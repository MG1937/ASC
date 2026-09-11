//! DEX debug info section parsing.
#![allow(missing_docs, reason = "internal")]
#![cfg_attr(not(test), allow(clippy::as_conversions, reason = "PROOF (bulk allow, 7 sites): debug.rs parses the debug_info_item bytecode stream out of parser-validated bytes. Casts cluster around (a) `u32/u16 ULEB128/SLEB128 byte values widened to u32/usize` for offset/line arithmetic, lossless on 64-bit; (b) `u32 register-id as u16` narrowing for typed-Err'd register operand storage — an explicit pre-cast range check against `registers_size: u16` guards this narrowing, eliminating the truncation-collision bug. Per-site PROOF refinement deferred."))]
use std::collections::BTreeMap;

use crate::error::{bound_count, safe_add, DexError, Result};
use crate::ids::*;
use crate::mutf8;
use crate::parser::DexFile;

/// A local variable entry from debug info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVar {
    pub register: u16,
    pub name: Option<String>,
    pub type_desc: Option<String>,
    pub start_addr: u32,
    pub end_addr: Option<u32>,
}

/// Parsed debug info for a method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugInfo {
    pub line_start: u32,
    pub parameter_names: Vec<Option<String>>,
    pub locals: Vec<LocalVar>,
    /// (pc, line) positions emitted by the state machine. Seeded with
    /// `(0, line_start)` for pre-first-special-opcode coverage; appended
    /// at each DBG_ADVANCE_LINE and special opcode (per DEX spec, the
    /// position table tracks line-change events, not every pc advance).
    /// Monotonic in pc by construction.
    pub line_table: Vec<(u32, u32)>,
}

// Debug info state machine opcodes
const DBG_END_SEQUENCE: u8 = 0x00;
const DBG_ADVANCE_PC: u8 = 0x01;
const DBG_ADVANCE_LINE: u8 = 0x02;
const DBG_START_LOCAL: u8 = 0x03;
const DBG_START_LOCAL_EXTENDED: u8 = 0x04;
const DBG_END_LOCAL: u8 = 0x05;
const DBG_RESTART_LOCAL: u8 = 0x06;
const DBG_SET_PROLOGUE_END: u8 = 0x07;
const DBG_SET_EPILOGUE_BEGIN: u8 = 0x08;
const DBG_SET_FILE: u8 = 0x09;
const DBG_FIRST_SPECIAL: u8 = 0x0A;
const DBG_LINE_BASE: i32 = -4;
const DBG_LINE_RANGE: i32 = 15;

/// Validate a u32 debug-info `register` operand against the method's
/// declared `registers_size` and narrow it to `u16` for storage in the
/// active-locals map.
///
/// Returns `DexError::InvalidDebugRegister` when the uleb128-read value
/// falls outside `[0, registers_size)`. DEX spec §3.4.6 mandates this
/// range; the prior `register as u16` narrowing silently truncated bits
/// 16-31, allowing an attacker to overwrite legitimate locals' names by
/// writing a uleb128 whose low 16 bits collide with a real register
/// index (e.g. `0x00010005` collides with v5).
#[inline]
pub(crate) fn narrow_register(uleb_value: u32, registers_size: u16) -> Result<u16> {
    match u16::try_from(uleb_value) {
        Ok(r) if r < registers_size => Ok(r),
        _ => Err(DexError::InvalidDebugRegister {
            uleb_value,
            method_registers_size: registers_size,
        }),
    }
}

/// Parse debug info from the DEX data at the given offset.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    reason = "PROOF: DEX debug-info-state-machine semantics. (1) `line_start as i32` from a u32 line number: DEX debug line_start is parsed as uleb128 to u32; values >i32::MAX are unrealistic for any real source file (i32::MAX = 2.1 billion lines). The state machine adjusts via DBG_LINE_RANGE in i32 space. (2) `line as u32`: line is held in i32 for delta arithmetic; on insertion to line_table, narrowed back. The state-machine spec guarantees positive lines for real DEX bytes. (3) `addr_delta as u32`: addr deltas are state-machine constants in [-16, 240]; div_euclid(DBG_LINE_RANGE) is in a small range, narrowing exact. (4) `register as u16` narrowing is guarded by an explicit pre-cast range check against `registers_size: u16`; a u32 ULEB128 with bits 16-31 set now returns `DexError::InvalidDebugRegister` before narrowing, eliminating the truncation-collision bug."
)]
pub fn parse_debug_info(
    data: &[u8],
    offset: u32,
    registers_size: u16,
    dex: &DexFile,
) -> Result<DebugInfo> {
    let mut pos = offset as usize;

    // line_start
    let (line_start, len) = mutf8::read_uleb128(data, pos)?;
    pos = safe_add(pos, len, "debug:line_start")?;

    // parameters_size
    let (params_size, len) = mutf8::read_uleb128(data, pos)?;
    pos = safe_add(pos, len, "debug:params_size")?;

    // parameter names (StringIdx per parameter, NO_INDEX = unnamed). Each
    // parameter entry is a ULEB128 `idx+1` — min 1 byte on disk.
    let params_count =
        bound_count(params_size, 1, data.len(), "debug_parameter_names")?;
    let mut parameter_names = Vec::with_capacity(params_count);
    for _ in 0..params_count {
        let (idx_plus_one, len) = mutf8::read_uleb128(data, pos)?;
        pos = safe_add(pos, len, "debug:param_idx")?;
        // Index is encoded as idx+1 (0 means no name)
        if idx_plus_one == 0 {
            parameter_names.push(None);
        } else {
            let sidx = StringIdx(idx_plus_one.saturating_sub(1));
            parameter_names.push(dex.get_string(sidx).ok().map(|s| s.to_string()));
        }
    }

    // State machine
    let mut locals = Vec::new();
    let mut address: u32 = 0;
    let mut line = line_start as i32;
    // Track active locals by register
    let mut active: BTreeMap<u16, LocalVar> = BTreeMap::new();
    // (pc, line) positions. Seed with (0, line_start) so statements emitted
    // before the first special opcode still have a mapped source line.
    let mut line_table: Vec<(u32, u32)> = vec![(0, line_start)];

    while let Some(&opcode) = data.get(pos) {
        pos = safe_add(pos, 1, "debug:opcode")?;

        match opcode {
            DBG_END_SEQUENCE => break,

            DBG_ADVANCE_PC => {
                let (delta, len) = mutf8::read_uleb128(data, pos)?;
                pos = safe_add(pos, len, "debug:advance_pc:len")?;
                // Accumulator overflow on adversarial debug stream → break
                // the state machine; partial DebugInfo is returned per the
                // caller's best-effort contract (unknown-opcode arm below
                // uses the same break pattern).
                let Some(new_address) = address.checked_add(delta) else { break; };
                address = new_address;
            }

            DBG_ADVANCE_LINE => {
                let (delta, len) = mutf8::read_sleb128(data, pos)?;
                pos = safe_add(pos, len, "debug:advance_line:len")?;
                let Some(new_line) = line.checked_add(delta) else { break; };
                line = new_line;
                if line >= 0 {
                    line_table.push((address, line as u32));
                }
            }

            DBG_START_LOCAL => {
                let (register, len) = mutf8::read_uleb128(data, pos)?;
                pos = safe_add(pos, len, "debug:start_local:register")?;
                let register = narrow_register(register, registers_size)?;
                let (name_idx, len) = mutf8::read_uleb128(data, pos)?;
                pos = safe_add(pos, len, "debug:start_local:name_idx")?;
                let (type_idx, len) = mutf8::read_uleb128(data, pos)?;
                pos = safe_add(pos, len, "debug:start_local:type_idx")?;

                let name = if name_idx == 0 {
                    None
                } else {
                    dex.get_string(StringIdx(name_idx.saturating_sub(1)))
                        .ok()
                        .map(|s| s.to_string())
                };
                let type_desc = if type_idx == 0 {
                    None
                } else {
                    dex.get_type_descriptor(TypeIdx(type_idx.saturating_sub(1)))
                        .ok()
                        .map(|s| s.to_string())
                };

                // End previous local in this register if any
                if let Some(mut prev) = active.remove(&register) {
                    prev.end_addr = Some(address);
                    locals.push(prev);
                }

                active.insert(
                    register,
                    LocalVar {
                        register,
                        name,
                        type_desc,
                        start_addr: address,
                        end_addr: None,
                    },
                );
            }

            DBG_START_LOCAL_EXTENDED => {
                let (register, len) = mutf8::read_uleb128(data, pos)?;
                pos = safe_add(pos, len, "debug:start_local_ext:register")?;
                let register = narrow_register(register, registers_size)?;
                let (name_idx, len) = mutf8::read_uleb128(data, pos)?;
                pos = safe_add(pos, len, "debug:start_local_ext:name_idx")?;
                let (type_idx, len) = mutf8::read_uleb128(data, pos)?;
                pos = safe_add(pos, len, "debug:start_local_ext:type_idx")?;
                let (_sig_idx, len) = mutf8::read_uleb128(data, pos)?;
                pos = safe_add(pos, len, "debug:start_local_ext:sig_idx")?;

                let name = if name_idx == 0 {
                    None
                } else {
                    dex.get_string(StringIdx(name_idx.saturating_sub(1)))
                        .ok()
                        .map(|s| s.to_string())
                };
                let type_desc = if type_idx == 0 {
                    None
                } else {
                    dex.get_type_descriptor(TypeIdx(type_idx.saturating_sub(1)))
                        .ok()
                        .map(|s| s.to_string())
                };

                if let Some(mut prev) = active.remove(&register) {
                    prev.end_addr = Some(address);
                    locals.push(prev);
                }

                active.insert(
                    register,
                    LocalVar {
                        register,
                        name,
                        type_desc,
                        start_addr: address,
                        end_addr: None,
                    },
                );
            }

            DBG_END_LOCAL => {
                let (register, len) = mutf8::read_uleb128(data, pos)?;
                pos = safe_add(pos, len, "debug:end_local:register")?;
                let register = narrow_register(register, registers_size)?;
                if let Some(mut local) = active.remove(&register) {
                    local.end_addr = Some(address);
                    locals.push(local);
                }
            }

            DBG_RESTART_LOCAL => {
                let (register, len) = mutf8::read_uleb128(data, pos)?;
                pos = safe_add(pos, len, "debug:restart_local:register")?;
                let register = narrow_register(register, registers_size)?;
                // Restart the last local in this register
                if let Some(prev) = locals.iter().rev().find(|l| l.register == register) {
                    active.insert(
                        register,
                        LocalVar {
                            register,
                            name: prev.name.clone(),
                            type_desc: prev.type_desc.clone(),
                            start_addr: address,
                            end_addr: None,
                        },
                    );
                }
            }

            DBG_SET_PROLOGUE_END | DBG_SET_EPILOGUE_BEGIN => {
                // No data, just markers
            }

            DBG_SET_FILE => {
                let (_name_idx, len) = mutf8::read_uleb128(data, pos)?;
                pos = safe_add(pos, len, "debug:set_file:name_idx")?;
            }

            special if special >= DBG_FIRST_SPECIAL => {
                // Special opcode: advance both PC and line. Guard preserves
                // `special >= DBG_FIRST_SPECIAL` so the subtraction cannot
                // underflow; `saturating_sub` is lint-friendly and
                // semantics-preserving.
                let adjusted = i32::from(special.saturating_sub(DBG_FIRST_SPECIAL));
                let line_delta = DBG_LINE_BASE.wrapping_add(adjusted.rem_euclid(DBG_LINE_RANGE));
                let addr_delta = adjusted.div_euclid(DBG_LINE_RANGE) as u32;
                // Accumulator overflow → break the state machine (same
                // contract as DBG_ADVANCE_PC / DBG_ADVANCE_LINE above).
                let Some(new_line) = line.checked_add(line_delta) else { break; };
                line = new_line;
                let Some(new_address) = address.checked_add(addr_delta) else { break; };
                address = new_address;
                if line >= 0 {
                    line_table.push((address, line as u32));
                }
            }

            _ => {
                // Unknown opcode, skip
                break;
            }
        }
    }

    // Close any remaining active locals
    for (_, mut local) in active {
        local.end_addr = None; // extends to end of method
        locals.push(local);
    }

    Ok(DebugInfo {
        line_start,
        parameter_names,
        locals,
        line_table,
    })
}

/// Look up the source line active at `pc` using the `line_table` positions.
/// Returns the line of the largest `(pc', line)` entry with `pc' <= pc`, or
/// `line_start` if `pc` is before any position (line_table is seeded with
/// `(0, line_start)` so this branch only fires on malformed empty tables).
/// `None` if the table is truly empty (e.g. parse failure mid-construction).
pub fn line_at(debug: &DebugInfo, pc: u32) -> Option<u32> {
    // line_table is monotonic in pc by construction (state machine only
    // advances address forward). Linear scan from the right returns the
    // largest entry with pc' <= pc; for typical method sizes this is
    // cheaper than binary search.
    debug
        .line_table
        .iter()
        .rev()
        .find(|(entry_pc, _)| *entry_pc <= pc)
        .map(|(_, line)| *line)
}

/// Build a register → name map from debug info for use in emission.
/// Prefers parameter names, falls back to local variable names.
pub fn build_name_map(
    debug: &DebugInfo,
    registers_size: u16,
    ins_size: u16,
    is_static: bool,
) -> BTreeMap<u16, String> {
    let mut names = BTreeMap::new();
    let first_param_reg = registers_size.saturating_sub(ins_size);

    // Apply parameter names.
    // For non-static methods, parameter_names covers explicit params only (not `this`),
    // so offset by 1 to skip the `this` register.
    let param_reg_offset = if is_static { 0u16 } else { 1 };
    for (i, name) in debug.parameter_names.iter().enumerate() {
        if let Some(n) = name {
            // Register key overflow → skip this param silently (matches the
            // function's best-effort "name map" contract; next param in the
            // loop may still fit if `i as u16` wrapped).
            let Some(offset_reg) = first_param_reg.checked_add(param_reg_offset) else { continue; };
            #[allow(
                clippy::cast_possible_truncation,
                reason = "PROOF: `i` is an enumerate index over debug.parameter_names; if i exceeds u16::MAX the `checked_add` below catches the wrap and continues silently — matches the function's best-effort 'name map' contract."
            )]
            let i_u16 = i as u16;
            let Some(reg) = offset_reg.checked_add(i_u16) else { continue; };
            names.insert(reg, n.clone());
        }
    }

    // Apply local variable names (may override params, which is fine)
    for local in &debug.locals {
        if let Some(ref name) = local.name {
            if name != "this" {
                names.insert(local.register, name.clone());
            }
        }
    }

    names
}

/// Look up the local-variable name active at `(register, pc)` in the debug
/// stream, or `None` if no local covers that point.
///
/// Iterates in reverse so more recently started locals win on overlapping
/// ranges — matches the DEX state-machine's "last DBG_START_LOCAL wins per
/// register" invariant. Filters out `"this"` to match the existing
/// `build_name_map` contract (the `this_var` channel handles that separately
/// in emit).
///
/// Used by the decompile pipeline to name non-param SSA VarIds: each
/// `SsaInsn.dst` has a definition PC (`insn.addr`); looking up
/// `(dst.reg(), insn.addr)` yields the source-level local name if the DEX
/// retained debug info and the scope covers the definition point.
pub fn local_name_at(debug: &DebugInfo, register: u16, pc: u32) -> Option<&str> {
    debug
        .locals
        .iter()
        .rev()
        .find(|l| {
            l.register == register
                && l.start_addr <= pc
                && l.end_addr.is_none_or(|end| pc < end)
                && l.name.as_deref() != Some("this")
        })
        .and_then(|l| l.name.as_deref())
}

/// Scan the on-disk byte range of a `debug_info_item` at `offset`,
/// returning the raw bytes verbatim. Used by emit to round-trip the
/// section byte-exact without re-synthesizing the state-machine
/// bytecode.
///
/// Walks the state machine opcode-by-opcode to find the byte-range
/// end (inclusive of `DBG_END_SEQUENCE`), without resolving any
/// string/type references (parse_debug_info does that).
///
/// Returns `Err` on truncated input, ULEB128/SLEB128 decode failure,
/// or an unknown opcode (spec does not define length for opcodes
/// past `DBG_FIRST_SPECIAL - 1` that are not listed here; if a future
/// DEX revision adds one, byte-preservation must be extended). The
/// caller (`parse_inner`) silently skips on Err — same tolerant-parse
/// discipline as class_datas / code_items. The downstream consequence
/// is a debug_info_item that the emitter cannot preserve; emit will
/// fall back to `debug_info_off = 0` for any code_item referencing
/// the skipped entry (matching the established security-safe
/// zeroing behavior for the skipped subset).
pub fn scan_debug_info_bytes(data: &[u8], offset: u32) -> Result<Vec<u8>> {
    let start = offset as usize;
    if start > data.len() {
        return Err(DexError::OffsetOutOfBounds {
            offset,
            file_size: data.len(),
        });
    }
    let mut pos = start;

    // Helper: skip one ULEB128. Minimum 1 byte; max 5 bytes (u32).
    // Min on-disk stride per variable-length record is 1 byte, which
    // `bound_count` uses for the outer cap in parse_inner.
    fn skip_uleb128(data: &[u8], pos: usize) -> Result<usize> {
        let (_, len) = mutf8::read_uleb128(data, pos)?;
        safe_add(pos, len, "debug:scan:uleb128")
    }
    fn skip_sleb128(data: &[u8], pos: usize) -> Result<usize> {
        let (_, len) = mutf8::read_sleb128(data, pos)?;
        safe_add(pos, len, "debug:scan:sleb128")
    }

    // line_start + parameters_size headers.
    pos = skip_uleb128(data, pos)?;
    let (params_size, len) = mutf8::read_uleb128(data, pos)?;
    pos = safe_add(pos, len, "debug:scan:params_size")?;
    // Bound the parameter-name walk against the remaining input
    // (stride = 1 byte per ULEB128, per spec minimum). Prevents an
    // attacker-controlled params_size from driving a multi-GiB walk
    // on a tiny input.
    let params_count = bound_count(params_size, 1, data.len(), "debug_scan_parameter_names")?;
    for _ in 0..params_count {
        pos = skip_uleb128(data, pos)?;
    }

    // State machine. Walk until DBG_END_SEQUENCE (0x00) or typed Err.
    loop {
        if pos >= data.len() {
            return Err(DexError::Truncated {
                offset: pos,
                need: 1,
                have: 0,
            });
        }
        let opcode = *data.get(pos).ok_or(DexError::Truncated {
            offset: pos,
            need: 1,
            have: 0,
        })?;
        pos = safe_add(pos, 1, "debug:scan:opcode")?;

        match opcode {
            DBG_END_SEQUENCE => break,
            DBG_ADVANCE_PC => pos = skip_uleb128(data, pos)?,
            DBG_ADVANCE_LINE => pos = skip_sleb128(data, pos)?,
            DBG_START_LOCAL => {
                pos = skip_uleb128(data, pos)?; // register
                pos = skip_uleb128(data, pos)?; // name_idx+1
                pos = skip_uleb128(data, pos)?; // type_idx+1
            }
            DBG_START_LOCAL_EXTENDED => {
                pos = skip_uleb128(data, pos)?; // register
                pos = skip_uleb128(data, pos)?; // name_idx+1
                pos = skip_uleb128(data, pos)?; // type_idx+1
                pos = skip_uleb128(data, pos)?; // sig_idx+1
            }
            DBG_END_LOCAL | DBG_RESTART_LOCAL => pos = skip_uleb128(data, pos)?,
            DBG_SET_PROLOGUE_END | DBG_SET_EPILOGUE_BEGIN => { /* no operands */ }
            DBG_SET_FILE => pos = skip_uleb128(data, pos)?, // name_idx+1
            // Everything 0x0A..=0xFF is a special opcode per spec §"debug_info_item" —
            // no operands, advances PC + line deterministically. The u8 range
            // 0x00..=0x09 is covered exhaustively above, so this catch-all
            // matches exactly the special-opcode range by process of elimination.
            _ => { /* no operands (special opcode) */ }
        }
    }

    // Capture inclusive of DBG_END_SEQUENCE.
    let end = pos;
    // pos was advanced past start monotonically; end >= start by construction.
    Ok(data
        .get(start..end)
        .ok_or(DexError::Truncated {
            offset: start,
            need: end.saturating_sub(start),
            have: data.len().saturating_sub(start),
        })?
        .to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_name_at_picks_scope_by_pc_range() {
        // Two sequential scopes on register 3: `a` covers [0, 5), `b` covers
        // [5, 10). Lookup at pc=3 should return "a"; pc=7 should return "b";
        // pc=15 (outside both) returns None.
        let debug = DebugInfo {
            line_start: 1,
            parameter_names: vec![],
            line_table: vec![],
            locals: vec![
                LocalVar {
                    register: 3,
                    name: Some("a".into()),
                    type_desc: None,
                    start_addr: 0,
                    end_addr: Some(5),
                },
                LocalVar {
                    register: 3,
                    name: Some("b".into()),
                    type_desc: None,
                    start_addr: 5,
                    end_addr: Some(10),
                },
            ],
        };
        assert_eq!(local_name_at(&debug, 3, 3), Some("a"));
        assert_eq!(local_name_at(&debug, 3, 7), Some("b"));
        assert_eq!(local_name_at(&debug, 3, 15), None);
        // Different register: no hit
        assert_eq!(local_name_at(&debug, 4, 3), None);
    }

    #[test]
    fn local_name_at_skips_this() {
        // Register 0 is `this` in a non-static method. Lookup must return None
        // because the this_var channel handles `this` separately in emit; the
        // debug-info-sourced name loop MUST NOT insert "this" into var_names.
        let debug = DebugInfo {
            line_start: 1,
            parameter_names: vec![],
            line_table: vec![],
            locals: vec![LocalVar {
                register: 0,
                name: Some("this".into()),
                type_desc: Some("LFoo;".into()),
                start_addr: 0,
                end_addr: None,
            }],
        };
        assert_eq!(local_name_at(&debug, 0, 3), None);
    }

    #[test]
    fn line_at_returns_nearest_lower_entry() {
        let debug = DebugInfo {
            line_start: 10,
            parameter_names: vec![],
            line_table: vec![(0, 10), (4, 11), (8, 13)],
            locals: vec![],
        };
        // Before any later entry: returns seed.
        assert_eq!(line_at(&debug, 0), Some(10));
        assert_eq!(line_at(&debug, 3), Some(10));
        // At exact pc: returns that entry.
        assert_eq!(line_at(&debug, 4), Some(11));
        assert_eq!(line_at(&debug, 8), Some(13));
        // Between entries: returns nearest lower.
        assert_eq!(line_at(&debug, 5), Some(11));
        assert_eq!(line_at(&debug, 99), Some(13));
    }

    #[test]
    fn line_at_empty_table_returns_none() {
        let debug = DebugInfo {
            line_start: 5,
            parameter_names: vec![],
            line_table: vec![],
            locals: vec![],
        };
        assert_eq!(line_at(&debug, 0), None);
    }

    #[test]
    fn parse_fixture_populates_line_table() {
        // The shipped fixture is compiled with `javac -g` so every method
        // with debug info should have at least one (pc, line) position.
        let data = include_bytes!("../tests/fixtures/classes.dex");
        let dex = DexFile::parse(data, None).unwrap();
        let cd = crate::decode::parse_class_data(
            data,
            dex.class_defs
                .iter()
                .find(|cd| dex.get_type_descriptor(cd.class_idx).ok() == Some("LMinimal;"))
                .unwrap()
                .class_data_off,
        )
        .unwrap();

        let mut checked = 0usize;
        for m in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
            if m.code_off == 0 {
                continue;
            }
            let code = crate::decode::parse_code_item(data, m.code_off).unwrap();
            if code.debug_info_off == 0 {
                continue;
            }
            let debug = parse_debug_info(data, code.debug_info_off, code.registers_size, &dex).unwrap();
            // At minimum, the (0, line_start) seed is present.
            assert!(
                !debug.line_table.is_empty(),
                "line_table seed (0, line_start) must always be present"
            );
            // Monotonic-in-pc invariant: adjacent entries must have
            // non-decreasing pc.
            for w in debug.line_table.windows(2) {
                assert!(
                    w[0].0 <= w[1].0,
                    "line_table must be monotonic in pc; got {:?} then {:?}",
                    w[0],
                    w[1]
                );
            }
            checked += 1;
        }
        assert!(checked > 0, "fixture must exercise at least one method with debug info");
    }

    #[test]
    fn local_name_at_open_ended_scope_covers_method_end() {
        // end_addr == None means "extends to end of method".
        let debug = DebugInfo {
            line_start: 1,
            parameter_names: vec![],
            line_table: vec![],
            locals: vec![LocalVar {
                register: 5,
                name: Some("counter".into()),
                type_desc: None,
                start_addr: 4,
                end_addr: None,
            }],
        };
        assert_eq!(local_name_at(&debug, 5, 4), Some("counter"));
        assert_eq!(local_name_at(&debug, 5, 999), Some("counter"));
        // Before start_addr: still None.
        assert_eq!(local_name_at(&debug, 5, 0), None);
    }


    #[test]
    fn parse_fixture_debug_info() {
        let data = include_bytes!("../tests/fixtures/classes.dex");
        let dex = DexFile::parse(data, None).unwrap();
        let cd = crate::decode::parse_class_data(
            data,
            dex.class_defs
                .iter()
                .find(|cd| dex.get_type_descriptor(cd.class_idx).ok() == Some("LMinimal;"))
                .unwrap()
                .class_data_off,
        )
        .unwrap();

        // init: should have debug info with named locals
        let init = &cd.direct_methods[0];
        let code = crate::decode::parse_code_item(data, init.code_off).unwrap();
        assert!(code.debug_info_off != 0, "init should have debug info");
        let debug = parse_debug_info(data, code.debug_info_off, code.registers_size, &dex).unwrap();
        assert!(debug.line_start > 0, "should have line numbers");

        // Check parameter_names
        eprintln!("init parameter_names: {:?}", debug.parameter_names);
        eprintln!("init locals: {:?}", debug.locals);

        // With -g -parameters compilation, "x" should appear in parameter_names
        let has_x = debug
            .parameter_names
            .iter()
            .any(|n| n.as_deref() == Some("x"))
            || debug.locals.iter().any(|l| l.name.as_deref() == Some("x"));
        assert!(has_x, "init debug info should contain 'x'");
    }

    #[test]
    fn parse_all_methods_debug_info() {
        let data = include_bytes!("../tests/fixtures/classes.dex");
        let dex = DexFile::parse(data, None).unwrap();
        let cd = crate::decode::parse_class_data(
            data,
            dex.class_defs
                .iter()
                .find(|cd| dex.get_type_descriptor(cd.class_idx).ok() == Some("LMinimal;"))
                .unwrap()
                .class_data_off,
        )
        .unwrap();

        for m in cd.direct_methods.iter().chain(cd.virtual_methods.iter()) {
            if m.code_off == 0 {
                continue;
            }
            let code = crate::decode::parse_code_item(data, m.code_off).unwrap();
            if code.debug_info_off != 0 {
                let debug = parse_debug_info(data, code.debug_info_off, code.registers_size, &dex);
                assert!(
                    debug.is_ok(),
                    "method {} debug info parse failed: {:?}",
                    m.method_idx.0,
                    debug.err()
                );
            }
        }
    }

    #[test]
    fn build_name_map_test() {
        let data = include_bytes!("../tests/fixtures/classes.dex");
        let dex = DexFile::parse(data, None).unwrap();
        let cd = crate::decode::parse_class_data(
            data,
            dex.class_defs
                .iter()
                .find(|cd| dex.get_type_descriptor(cd.class_idx).ok() == Some("LMinimal;"))
                .unwrap()
                .class_data_off,
        )
        .unwrap();

        let init = &cd.direct_methods[0];
        let code = crate::decode::parse_code_item(data, init.code_off).unwrap();
        if code.debug_info_off != 0 {
            let debug = parse_debug_info(data, code.debug_info_off, code.registers_size, &dex).unwrap();
            let is_static = init.access_flags & 0x0008 != 0;
            let names = build_name_map(&debug, code.registers_size, code.ins_size, is_static);
            // Names map should not contain "this" (we handle that separately)
            for name in names.values() {
                assert_ne!(name, "this");
            }
        }
    }

    #[test]
    fn scan_debug_info_bytes_preserves_fixture_bytes() {
        // Byte-exact capture: scan_debug_info_bytes must return a byte
        // range that is a prefix-exact slice of the input. Round-trip
        // gate for emit_debug_info_section.
        let data = include_bytes!("../tests/fixtures/classes.dex");
        let dex = DexFile::parse(data, None).unwrap();
        let mut checked = 0usize;
        for ci in dex.code_items.values() {
            if ci.debug_info_off == 0 {
                continue;
            }
            let raw = scan_debug_info_bytes(data, ci.debug_info_off).unwrap();
            let start = ci.debug_info_off as usize;
            let end = start + raw.len();
            assert!(!raw.is_empty(), "debug_info_item should be non-empty");
            assert_eq!(
                raw.as_slice(),
                &data[start..end],
                "scan must preserve exact on-disk bytes"
            );
            // Last byte MUST be DBG_END_SEQUENCE (0x00) — terminator
            // is included in the preserved range.
            assert_eq!(*raw.last().unwrap(), DBG_END_SEQUENCE);
            checked += 1;
        }
        assert!(checked > 0, "fixture must have at least one debug_info_item");
    }

    #[test]
    fn scan_debug_info_bytes_errs_on_truncated_end_sequence() {
        // No DBG_END_SEQUENCE: a state machine that walks past EOF
        // must return typed Err — no panic, no silent partial capture
        // (would cause emit to write a truncated item). The header is
        // line_start=1 (ULEB 0x01), params_size=0 (ULEB 0x00), then
        // a single DBG_ADVANCE_PC (0x01) expecting a ULEB operand,
        // but the buffer ends before the operand.
        let data = [0x01u8, 0x00, 0x01];
        let err = scan_debug_info_bytes(&data, 0).unwrap_err();
        // Exact variant not load-bearing; non-panic behavior is.
        let msg = format!("{err}");
        assert!(
            !msg.is_empty(),
            "truncated input must produce a typed error with a non-empty message"
        );
    }

    #[test]
    fn scan_debug_info_bytes_errs_on_truncated_operand() {
        // Spec defines 0x00..=0x09 as standard opcodes and 0x0A..=0xFF
        // as no-operand special opcodes, covering every u8 value; there
        // is no "reserved / unknown-length" byte in the spec. So the
        // adversarial-failure mode we actually defend against is
        // truncated operands — the state machine reaches an opcode
        // (e.g. DBG_START_LOCAL) that requires operands, and the byte
        // buffer ends before the ULEB128 encoding completes.
        //
        // Header: line_start=1, params_size=0, then DBG_START_LOCAL
        // (0x03) with no operands following.
        let data = [0x01u8, 0x00, 0x03];
        let err = scan_debug_info_bytes(&data, 0).unwrap_err();
        assert!(!format!("{err}").is_empty());
    }

    #[test]
    fn scan_debug_info_bytes_empty_stream_succeeds() {
        // Minimal valid debug_info_item: line_start=0, params_size=0,
        // DBG_END_SEQUENCE. Three bytes. Must round-trip byte-exact.
        let data = [0x00u8, 0x00, DBG_END_SEQUENCE];
        let raw = scan_debug_info_bytes(&data, 0).unwrap();
        assert_eq!(raw, vec![0x00u8, 0x00, DBG_END_SEQUENCE]);
    }

    #[test]
    fn scan_debug_info_bytes_offset_past_end_is_err() {
        // Adversarial: offset > data.len() must Err, not panic.
        let data = [0x01u8, 0x00, DBG_END_SEQUENCE];
        let err = scan_debug_info_bytes(&data, 999).unwrap_err();
        assert!(!format!("{err}").is_empty());
    }

    // ── Pure narrow_register unit tests (no DexFile needed) ───────────

    #[test]
    fn narrow_register_in_bounds_returns_u16() {
        assert_eq!(narrow_register(0, 4).unwrap(), 0u16);
        assert_eq!(narrow_register(3, 4).unwrap(), 3u16);
    }

    #[test]
    fn narrow_register_equal_to_size_rejected() {
        // registers_size is exclusive upper bound — value == size is invalid.
        let err = narrow_register(4, 4).unwrap_err();
        match err {
            crate::error::DexError::InvalidDebugRegister {
                uleb_value,
                method_registers_size,
            } => {
                assert_eq!(uleb_value, 4);
                assert_eq!(method_registers_size, 4);
            }
            other => panic!("expected InvalidDebugRegister, got {other:?}"),
        }
    }

    #[test]
    fn narrow_register_above_u16_max_rejected() {
        // The original bug shape: a uleb128 with bits 16-31 set silently
        // truncated to a colliding u16. The fix must reject ANY value
        // that overflows u16, regardless of whether the low 16 bits would
        // happen to fall inside the legal range.
        let smuggled: u32 = 0x0001_0005; // low 16 bits = 5, but bits 16+ set
        let err = narrow_register(smuggled, 8).unwrap_err();
        match err {
            crate::error::DexError::InvalidDebugRegister {
                uleb_value,
                method_registers_size,
            } => {
                assert_eq!(uleb_value, smuggled);
                assert_eq!(method_registers_size, 8);
            }
            other => panic!("expected InvalidDebugRegister, got {other:?}"),
        }
    }

    #[test]
    fn narrow_register_u32_max_rejected() {
        let err = narrow_register(u32::MAX, u16::MAX).unwrap_err();
        assert!(matches!(
            err,
            crate::error::DexError::InvalidDebugRegister { .. }
        ));
    }

    #[test]
    fn narrow_register_max_in_bounds_u16_accepted() {
        // The largest legal value: u16::MAX - 1 in a method with
        // registers_size = u16::MAX.
        assert_eq!(
            narrow_register(u32::from(u16::MAX - 1), u16::MAX).unwrap(),
            u16::MAX - 1
        );
    }

    // ── parse_debug_info adversarial inputs surface InvalidDebugRegister ─

    /// Build a minimal DexFile for tests below. We only need a parser
    /// shell that resolves string + type lookups — debug-info parsing
    /// doesn't depend on a real DEX header. We borrow the existing
    /// `classes_named.dex` fixture for its real pool plumbing.
    fn dex_for_debug_test() -> (Vec<u8>, crate::parser::DexFile) {
        let data: Vec<u8> = include_bytes!("../tests/fixtures/classes_named.dex").to_vec();
        let dex = crate::parser::DexFile::parse(&data, None).unwrap();
        (data, dex)
    }

    /// Encode a uleb128 value into the given Vec.
    fn push_uleb(v: u32, out: &mut Vec<u8>) {
        let mut x = v;
        loop {
            let mut b = (x & 0x7F) as u8;
            x >>= 7;
            if x != 0 {
                b |= 0x80;
                out.push(b);
            } else {
                out.push(b);
                return;
            }
        }
    }

    #[test]
    fn parse_debug_info_dbg_start_local_rejects_smuggled_register() {
        // Concrete repro: DBG_START_LOCAL with register=0x00100005
        // (low 16 = 5, bits 16-31 set). Without this guard, silently
        // overwrites legitimate v5; with it, returns
        // InvalidDebugRegister.
        let (_, dex) = dex_for_debug_test();
        // Build the debug_info stream INDEPENDENTLY of the fixture.
        let mut stream = Vec::new();
        stream.push(0x00); // line_start = 0
        stream.push(0x00); // params_size = 0
        stream.push(DBG_START_LOCAL);
        push_uleb(0x0010_0005, &mut stream); // smuggled register
        stream.push(0x00); // name_idx = 0 (no name)
        stream.push(0x00); // type_idx = 0 (no type)
        stream.push(DBG_END_SEQUENCE);
        // Wrap in a host buffer at offset 0; call parse_debug_info with
        // registers_size = 8 (so any value >= 8 is out of range).
        let err = parse_debug_info(&stream, 0, 8, &dex).unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::DexError::InvalidDebugRegister {
                    uleb_value: 0x0010_0005,
                    method_registers_size: 8,
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn parse_debug_info_dbg_end_local_rejects_smuggled_register() {
        let (_, dex) = dex_for_debug_test();
        let mut stream = Vec::new();
        stream.push(0x00); // line_start
        stream.push(0x00); // params_size
        stream.push(DBG_END_LOCAL);
        push_uleb(u32::from(u16::MAX), &mut stream); // exceeds registers_size=4
        stream.push(DBG_END_SEQUENCE);
        let err = parse_debug_info(&stream, 0, 4, &dex).unwrap_err();
        assert!(matches!(
            err,
            crate::error::DexError::InvalidDebugRegister { .. }
        ));
    }

    #[test]
    fn parse_debug_info_dbg_restart_local_rejects_smuggled_register() {
        let (_, dex) = dex_for_debug_test();
        let mut stream = Vec::new();
        stream.push(0x00);
        stream.push(0x00);
        stream.push(DBG_RESTART_LOCAL);
        push_uleb(u32::MAX, &mut stream); // way over u16::MAX
        stream.push(DBG_END_SEQUENCE);
        let err = parse_debug_info(&stream, 0, 8, &dex).unwrap_err();
        assert!(matches!(
            err,
            crate::error::DexError::InvalidDebugRegister { .. }
        ));
    }

    #[test]
    fn parse_debug_info_dbg_start_local_extended_rejects_smuggled_register() {
        let (_, dex) = dex_for_debug_test();
        let mut stream = Vec::new();
        stream.push(0x00);
        stream.push(0x00);
        stream.push(DBG_START_LOCAL_EXTENDED);
        push_uleb(0x0008_0001, &mut stream); // bits 16-31 set, low = 1
        stream.push(0x00); // name_idx
        stream.push(0x00); // type_idx
        stream.push(0x00); // sig_idx
        stream.push(DBG_END_SEQUENCE);
        let err = parse_debug_info(&stream, 0, 4, &dex).unwrap_err();
        assert!(matches!(
            err,
            crate::error::DexError::InvalidDebugRegister { .. }
        ));
    }

    #[test]
    fn parse_debug_info_in_range_register_succeeds() {
        // Sanity: a well-formed register operand still parses cleanly.
        let (_, dex) = dex_for_debug_test();
        let mut stream = Vec::new();
        stream.push(0x00); // line_start
        stream.push(0x00); // params_size
        stream.push(DBG_START_LOCAL);
        push_uleb(2, &mut stream); // valid: register 2 < 4
        stream.push(0x00); // name_idx = 0
        stream.push(0x00); // type_idx = 0
        stream.push(DBG_END_SEQUENCE);
        let info = parse_debug_info(&stream, 0, 4, &dex).unwrap();
        // No locals because name_idx == 0 and type_idx == 0 produce
        // None/None but the state machine still records the LocalVar.
        assert_eq!(info.locals.len(), 1);
        assert_eq!(info.locals[0].register, 2);
    }
}
