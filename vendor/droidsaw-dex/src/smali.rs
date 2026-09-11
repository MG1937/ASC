//! Smali text disassembly output.
#![allow(missing_docs, reason = "internal")]
#![allow(clippy::let_underscore_must_use, reason = "every `let _ = writeln!(out, ...)` in smali code writes to an in-memory `String` whose `Display`/`Write` impl is infallible. The unit-Result is structurally dead.")]
#![cfg_attr(not(test), allow(clippy::as_conversions, reason = "PROOF (bulk allow, 9 sites): smali.rs emits the textual disassembly of parser-validated Dalvik instructions. Casts cluster around (a) `i64 literal as u64/i32/u16` for the various smali literal-form helpers (negative-literal-positive-display etc.), which match the baksmali canonical rendering convention; (b) `u32 pool-index .0 as usize` for `.get()` on pool arrays, lossless on 64-bit (`.get()` handles OOB). Per-site PROOF refinement deferred."))]

//! Smali-format disassembly emitter for Dalvik instructions.
//!
//! Smali is the textual representation used by smali/baksmali. Each opcode
//! has a fixed mnemonic and an operand syntax determined by its instruction
//! format. The mnemonic table here is the canonical baksmali mapping; do
//! not invent variants.
//!
//! Two public entry points:
//!
//!   * [`fmt_instruction`] — render a single decoded instruction. Pure;
//!     useful for unit tests and ad-hoc disassembly.
//!   * [`DexFile::emit_smali`] — render the body of one method, with
//!     branch labels and packed/sparse-switch / fill-array-data payloads
//!     expanded inline. Returns the body only — the method directive
//!     header is the caller's responsibility.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use crate::decode::{parse_code_item, CodeItem, Instruction, PayloadData, PoolIndex, RegList};
use crate::error::Result;
use crate::opcodes::Opcode;
use crate::DexFile;

// ── Public entry points ─────────────────────────────────────────────

/// Format a single instruction in smali syntax.
///
/// Examples:
///   `const/4 v0, 0x0`
///   `invoke-virtual {v0, v1}, Lcom/foo/Bar;->method(Ljava/lang/String;)V`
///   `iget v0, v1, Lcom/foo/Bar;->field:I`
pub fn fmt_instruction(insn: &Instruction, dex: &DexFile) -> String {
    let m = mnemonic(insn.op);
    let body = render_operands(insn, dex);
    if body.is_empty() {
        m.to_string()
    } else {
        format!("{m} {body}")
    }
}

impl DexFile {
    /// Emit the smali body of one method.
    ///
    /// `code_off` comes from `MethodSummary::code_off` (or directly from
    /// `EncodedMethod::code_off`). Returns `Ok(None)` for abstract/native
    /// methods (`code_off == 0`).
    ///
    /// The output is the instructions only — labels, payload directives,
    /// and one instruction per line. Method-level directives like
    /// `.method`, `.registers`, parameter annotations are NOT emitted;
    /// see [`Self::emit_smali_method`] for the full wrapper.
    pub fn emit_smali(&self, data: &[u8], code_off: u32) -> Result<Option<String>> {
        if code_off == 0 {
            return Ok(None);
        }
        let code = parse_code_item(data, code_off)?;
        Ok(Some(emit_method_body(&code, self)))
    }

    /// Emit a complete smali `.method … .end method` block for one method.
    ///
    /// Includes the access-flag list, signature, `.registers N` directive
    /// (when the method has code), the instruction body from [`Self::emit_smali`],
    /// and the closing `.end method`. For abstract/native methods the body
    /// and `.registers` are omitted.
    ///
    /// `method_idx` is the global method-id index; `access_flags` comes
    /// from [`crate::api::MethodSummary::access_flags`]; `code_off` from
    /// [`crate::api::MethodSummary::code_off`] (or 0 for abstract/native).
    pub fn emit_smali_method(
        &self,
        data: &[u8],
        method_idx: u32,
        access_flags: u32,
        code_off: u32,
    ) -> Result<String> {
        let mut out = String::new();
        let sig = method_signature(self, method_idx);
        let flags = method_access_flags(access_flags);
        if flags.is_empty() {
            let _ = writeln!(out, ".method {sig}");
        } else {
            let _ = writeln!(out, ".method {flags} {sig}");
        }
        if code_off != 0 {
            let code = parse_code_item(data, code_off)?;
            let _ = writeln!(out, "    .registers {}", code.registers_size);
            let _ = writeln!(out);
            out.push_str(&emit_method_body(&code, self));
        }
        out.push_str(".end method\n");
        Ok(out)
    }
}

/// Render the method signature portion of a `.method` directive.
/// Example: `getX()I` or `parseInt(Ljava/lang/String;)I`.
fn method_signature(dex: &DexFile, method_idx: u32) -> String {
    let Some(method) = dex.methods.get(method_idx as usize) else {
        return "?()?".to_string();
    };
    let name = dex.get_string(method.name_idx).unwrap_or("?");
    let Some(proto) = dex.protos.get(method.proto_idx.0 as usize) else {
        return format!("{name}()?");
    };
    let ret = dex
        .get_type_descriptor(proto.return_type_idx)
        .unwrap_or("?");
    let params: String = if proto.parameters_off == 0 {
        String::new()
    } else if let Some(tl) = dex.type_lists.get(&proto.parameters_off) {
        tl.iter()
            .map(|t| dex.get_type_descriptor(*t).unwrap_or("?").to_string())
            .collect::<Vec<_>>()
            .join("")
    } else {
        String::new()
    };
    format!("{name}({params}){ret}")
}

/// Space-joined smali access flags for a method. Order follows baksmali's
/// canonical rendering so outputs round-trip cleanly through smali.
fn method_access_flags(flags: u32) -> String {
    // (bit, name) — ordered as baksmali prints them.
    const TABLE: &[(u32, &str)] = &[
        (0x0001, "public"),
        (0x0002, "private"),
        (0x0004, "protected"),
        (0x0008, "static"),
        (0x0010, "final"),
        (0x0020, "synchronized"),
        (0x0040, "bridge"),
        (0x0080, "varargs"),
        (0x0100, "native"),
        (0x0400, "abstract"),
        (0x0800, "strictfp"),
        (0x1000, "synthetic"),
        (0x10000, "constructor"),
        (0x20000, "declared-synchronized"),
    ];
    TABLE
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(" ")
}

// ── Method body emission ────────────────────────────────────────────

#[allow(clippy::arithmetic_side_effects, reason = "addr + size (insn) / start_addr + insn_count (try) on parser-validated CodeItem fields; spec caps insn_count to u16, insn.size as u32 to u8::MAX. u32 sums cannot overflow on well-formed input.")]
fn emit_method_body(code: &CodeItem, dex: &DexFile) -> String {
    // Collect every address that needs a label: branch targets, switch payload
    // targets, try-start / try-end addresses, and catch handler addresses.
    // All labels share the :addr_NN namespace so .catch directives can reference
    // them without a separate try-index scheme.
    let mut label_addrs: BTreeSet<u32> = BTreeSet::new();
    for insn in &code.instructions {
        if let Some(t) = insn.target {
            label_addrs.insert(t);
        }
    }
    for payload in code.payloads.values() {
        match payload {
            PayloadData::PackedSwitch { targets, .. }
            | PayloadData::SparseSwitch { targets, .. } => label_addrs.extend(targets),
            PayloadData::FillArrayData { .. } => {}
        }
    }
    for t in &code.tries {
        label_addrs.insert(t.start_addr);
        label_addrs.insert(t.start_addr + u32::from(t.insn_count));
        if let Some(h) = code.catch_handlers.get(t.handler_idx) {
            for c in &h.catches {
                label_addrs.insert(c.handler_addr);
            }
            if let Some(a) = h.catch_all_addr {
                label_addrs.insert(a);
            }
        }
    }

    // Build per-end-address `.catch` / `.catchall` directives. These render
    // immediately after the matching `:try_end` label (i.e. at the address
    // that is the exclusive end of the protected range).
    let mut catch_directives: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for t in &code.tries {
        let start = t.start_addr;
        let end = start + u32::from(t.insn_count);
        let Some(h) = code.catch_handlers.get(t.handler_idx) else {
            continue;
        };
        for c in &h.catches {
            let ty = dex.get_type_descriptor(c.exception_type).unwrap_or("?");
            let dir = format!(
                ".catch {ty} {{:{} .. :{}}} :{}",
                label(start),
                label(end),
                label(c.handler_addr),
            );
            catch_directives.entry(end).or_default().push(dir);
        }
        if let Some(all) = h.catch_all_addr {
            let dir = format!(
                ".catchall {{:{} .. :{}}} :{}",
                label(start),
                label(end),
                label(all),
            );
            catch_directives.entry(end).or_default().push(dir);
        }
    }

    let mut out = String::new();

    // Pre-pass: addresses that hold a payload (packed-switch / sparse-switch /
    // fill-array-data table). Those are NOT real instructions in baksmali —
    // they are .packed-switch / .sparse-switch / .array-data directives,
    // emitted at the end of the method.
    let payload_addrs: BTreeSet<u32> = code.payloads.keys().copied().collect();

    // Track one-past-the-last-instruction address so we can flush any trailing
    // try_end labels / .catch directives that point past the method body.
    let mut last_addr: u32 = 0;

    for insn in &code.instructions {
        if payload_addrs.contains(&insn.addr) {
            // Skip the nop-shaped payload marker; we render the payload
            // directive separately below.
            continue;
        }
        if label_addrs.contains(&insn.addr) {
            let _ = writeln!(out, "    :{}", label(insn.addr));
        }
        if let Some(dirs) = catch_directives.get(&insn.addr) {
            for d in dirs {
                let _ = writeln!(out, "    {d}");
            }
        }
        let _ = writeln!(out, "    {}", fmt_instruction(insn, dex));
        last_addr = insn.addr + u32::from(insn.size);
    }

    // Flush any labels / directives whose address lies past the last
    // instruction — this happens when a try range covers through end-of-method.
    for &addr in label_addrs.iter().filter(|&&a| a >= last_addr) {
        let _ = writeln!(out, "    :{}", label(addr));
        if let Some(dirs) = catch_directives.get(&addr) {
            for d in dirs {
                let _ = writeln!(out, "    {d}");
            }
        }
    }

    // Render payload directives at the end. Order by address for determinism.
    for (&addr, payload) in &code.payloads {
        let _ = writeln!(out);
        let _ = writeln!(out, "    :{}", label(addr));
        match payload {
            PayloadData::PackedSwitch { first_key, targets } => {
                let _ = writeln!(out, "    .packed-switch {first_key:#x}");
                for t in targets {
                    let _ = writeln!(out, "        :{}", label(*t));
                }
                let _ = writeln!(out, "    .end packed-switch");
            }
            PayloadData::SparseSwitch { keys, targets } => {
                let _ = writeln!(out, "    .sparse-switch");
                for (k, t) in keys.iter().zip(targets.iter()) {
                    let _ = writeln!(out, "        {k:#x} -> :{}", label(*t));
                }
                let _ = writeln!(out, "    .end sparse-switch");
            }
            PayloadData::FillArrayData {
                element_width,
                data,
            } => {
                let _ = writeln!(out, "    .array-data {element_width}");
                for chunk in data.chunks(*element_width as usize) {
                    let mut hex = String::from("        0x");
                    // Little-endian within element
                    for b in chunk.iter().rev() {
                        let _ = write!(hex, "{b:02x}");
                    }
                    hex.push('t');
                    let _ = writeln!(out, "{hex}");
                }
                let _ = writeln!(out, "    .end array-data");
            }
        }
    }

    out
}

fn label(addr: u32) -> String {
    format!("addr_{addr:x}")
}

// ── Per-instruction operand rendering ───────────────────────────────

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "PROOF: `insn.literal as u16` for InvokeXxxRange / FilledNewArrayRange — these are F3rc/F4rcc opcodes whose literal stores the range count (a u8 in the wire format). Narrowing i64 → u16 is exact, and the count is non-negative."
)]
fn render_operands(insn: &Instruction, dex: &DexFile) -> String {
    use Opcode::*;

    // Helper closures
    let regs = &insn.src;
    let dst = insn.dst;

    // Many opcodes have one of a small number of operand shapes.
    // The match below dispatches by opcode rather than format because some
    // opcodes share a format but render differently (e.g. const-string vs
    // new-instance both F21c).
    match insn.op {
        // No operands
        Nop | ReturnVoid => String::new(),

        // vAA (single register)
        MoveResult | MoveResultWide | MoveResultObject | MoveException | Return | ReturnWide
        | ReturnObject | MonitorEnter | MonitorExit | Throw => fmt_v(dst.unwrap_or(0)),

        // vA, vB (two registers)
        Move | MoveWide | MoveObject | MoveFrom16 | MoveWideFrom16 | MoveObjectFrom16 | Move16
        | MoveWide16 | MoveObject16 | NegInt | NotInt | NegLong | NotLong | NegFloat
        | NegDouble | IntToLong | IntToFloat | IntToDouble | LongToInt | LongToFloat
        | LongToDouble | FloatToInt | FloatToLong | FloatToDouble | DoubleToInt | DoubleToLong
        | DoubleToFloat | IntToByte | IntToChar | IntToShort | ArrayLength => {
            format!("{}, {}", fmt_v(dst.unwrap_or(0)), fmt_reg0(regs))
        }

        // vA, vB (2addr)
        AddInt2Addr | SubInt2Addr | MulInt2Addr | DivInt2Addr | RemInt2Addr | AndInt2Addr
        | OrInt2Addr | XorInt2Addr | ShlInt2Addr | ShrInt2Addr | UshrInt2Addr | AddLong2Addr
        | SubLong2Addr | MulLong2Addr | DivLong2Addr | RemLong2Addr | AndLong2Addr
        | OrLong2Addr | XorLong2Addr | ShlLong2Addr | ShrLong2Addr | UshrLong2Addr
        | AddFloat2Addr | SubFloat2Addr | MulFloat2Addr | DivFloat2Addr | RemFloat2Addr
        | AddDouble2Addr | SubDouble2Addr | MulDouble2Addr | DivDouble2Addr | RemDouble2Addr => {
            format!("{}, {}", fmt_v(dst.unwrap_or(0)), fmt_reg0(regs))
        }

        // const/4 vA, #+B   (signed 4-bit)
        Const4 => format!(
            "{}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_lit_signed(insn.literal)
        ),

        // const/16 vAA, #+BBBB
        Const16 | ConstWide16 => format!(
            "{}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_lit_signed(insn.literal)
        ),

        // const vAA, #+BBBBBBBB
        Const | ConstWide32 => format!(
            "{}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_lit_signed(insn.literal)
        ),

        // const-wide vAA, #+BBBBBBBBBBBBBBBB
        ConstWide => format!(
            "{}, {}L",
            fmt_v(dst.unwrap_or(0)),
            fmt_lit_signed(insn.literal)
        ),

        // const/high16 vAA, #+BBBB0000
        ConstHigh16 | ConstWideHigh16 => format!(
            "{}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_lit_signed(insn.literal)
        ),

        // const-string vAA, "..."
        ConstString | ConstStringJumbo => format!(
            "{}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_string_ref(&insn.pool_idx, dex)
        ),

        // const-class vAA, Lfoo;
        ConstClass | NewInstance | CheckCast => format!(
            "{}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_type_ref(&insn.pool_idx, dex)
        ),

        // new-array vA, vB, [Lfoo;
        NewArray => format!(
            "{}, {}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_reg0(regs),
            fmt_type_ref(&insn.pool_idx, dex),
        ),

        // instance-of vA, vB, Lfoo;
        InstanceOf => format!(
            "{}, {}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_reg0(regs),
            fmt_type_ref(&insn.pool_idx, dex),
        ),

        // iget* / iput* vA, vB, Lfoo;->name:type
        Iget | IgetWide | IgetObject | IgetBoolean | IgetByte | IgetChar | IgetShort => format!(
            "{}, {}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_reg0(regs),
            fmt_field_ref(&insn.pool_idx, dex),
        ),
        Iput | IputWide | IputObject | IputBoolean | IputByte | IputChar | IputShort => format!(
            "{}, {}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_reg0(regs),
            fmt_field_ref(&insn.pool_idx, dex),
        ),

        // sget* / sput* vAA, Lfoo;->name:type
        Sget | SgetWide | SgetObject | SgetBoolean | SgetByte | SgetChar | SgetShort | Sput
        | SputWide | SputObject | SputBoolean | SputByte | SputChar | SputShort => format!(
            "{}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_field_ref(&insn.pool_idx, dex),
        ),

        // aget* / aput* vAA, vBB, vCC
        Aget | AgetWide | AgetObject | AgetBoolean | AgetByte | AgetChar | AgetShort | Aput
        | AputWide | AputObject | AputBoolean | AputByte | AputChar | AputShort => format!(
            "{}, {}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_reg0(regs),
            fmt_reg1(regs),
        ),

        // 23x: cmp* vAA, vBB, vCC
        CmplFloat | CmpgFloat | CmplDouble | CmpgDouble | CmpLong => format!(
            "{}, {}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_reg0(regs),
            fmt_reg1(regs),
        ),

        // 23x: binop* vAA, vBB, vCC
        AddInt | SubInt | MulInt | DivInt | RemInt | AndInt | OrInt | XorInt | ShlInt | ShrInt
        | UshrInt | AddLong | SubLong | MulLong | DivLong | RemLong | AndLong | OrLong
        | XorLong | ShlLong | ShrLong | UshrLong | AddFloat | SubFloat | MulFloat | DivFloat
        | RemFloat | AddDouble | SubDouble | MulDouble | DivDouble | RemDouble => format!(
            "{}, {}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_reg0(regs),
            fmt_reg1(regs),
        ),

        // if-eq vA, vB, :label  (22t)
        IfEq | IfNe | IfLt | IfGe | IfGt | IfLe => format!(
            "{}, {}, :{}",
            fmt_reg0(regs),
            fmt_reg1(regs),
            label(insn.target.unwrap_or(0)),
        ),

        // if-eqz vAA, :label  (21t)
        IfEqz | IfNez | IfLtz | IfGez | IfGtz | IfLez => format!(
            "{}, :{}",
            fmt_v(dst.unwrap_or(0)),
            label(insn.target.unwrap_or(0)),
        ),

        // goto :label
        Goto | Goto16 | Goto32 => format!(":{}", label(insn.target.unwrap_or(0))),

        // packed-switch vAA, :payload   /  sparse-switch vAA, :payload
        // fill-array-data vAA, :payload
        PackedSwitch | SparseSwitch | FillArrayData => format!(
            "{}, :{}",
            fmt_v(dst.unwrap_or(0)),
            label(insn.target.unwrap_or(0)),
        ),

        // 22b: binop/lit8 vAA, vBB, #+CC
        AddIntLit8 | RsubIntLit8 | MulIntLit8 | DivIntLit8 | RemIntLit8 | AndIntLit8
        | OrIntLit8 | XorIntLit8 | ShlIntLit8 | ShrIntLit8 | UshrIntLit8 => format!(
            "{}, {}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_reg0(regs),
            fmt_lit_signed(insn.literal),
        ),

        // 22s: binop/lit16 vA, vB, #+CCCC
        AddIntLit16 | RsubInt | MulIntLit16 | DivIntLit16 | RemIntLit16 | AndIntLit16
        | OrIntLit16 | XorIntLit16 => format!(
            "{}, {}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_reg0(regs),
            fmt_lit_signed(insn.literal),
        ),

        // 35c invokes / filled-new-array
        InvokeVirtual | InvokeSuper | InvokeDirect | InvokeStatic | InvokeInterface
        | InvokePolymorphic | InvokeCustom => format!(
            "{}, {}",
            fmt_reg_set(regs),
            fmt_method_ref(&insn.pool_idx, dex)
        ),

        FilledNewArray => format!(
            "{}, {}",
            fmt_reg_set(regs),
            fmt_type_ref(&insn.pool_idx, dex)
        ),

        // 3rc range invokes / filled-new-array/range
        InvokeVirtualRange
        | InvokeSuperRange
        | InvokeDirectRange
        | InvokeStaticRange
        | InvokeInterfaceRange
        | InvokePolymorphicRange
        | InvokeCustomRange => format!(
            "{}, {}",
            fmt_reg_range(regs, insn.literal as u16),
            fmt_method_ref(&insn.pool_idx, dex),
        ),

        FilledNewArrayRange => format!(
            "{}, {}",
            fmt_reg_range(regs, insn.literal as u16),
            fmt_type_ref(&insn.pool_idx, dex),
        ),

        // const-method-handle / const-method-type — pool ref via 21c.
        // We don't fully classify these (decode treats them as Method); render
        // the raw method ref so the smali at least round-trips for inspection.
        ConstMethodHandle | ConstMethodType => format!(
            "{}, {}",
            fmt_v(dst.unwrap_or(0)),
            fmt_method_ref(&insn.pool_idx, dex)
        ),
    }
}

// ── Operand helpers ─────────────────────────────────────────────────

fn fmt_v(reg: u16) -> String {
    format!("v{reg}")
}

fn fmt_reg0(regs: &RegList) -> String {
    fmt_v(regs.as_slice().first().copied().unwrap_or(0))
}

fn fmt_reg1(regs: &RegList) -> String {
    fmt_v(regs.as_slice().get(1).copied().unwrap_or(0))
}

fn fmt_reg_set(regs: &RegList) -> String {
    let inner: Vec<String> = regs.as_slice().iter().map(|r| fmt_v(*r)).collect();
    format!("{{{}}}", inner.join(", "))
}

#[allow(clippy::arithmetic_side_effects, reason = "`first + count - 1` where first/count are u16 register coordinates from parser-validated RegList; count > 0 already verified above; first + count ≤ registers_size (u16 spec cap).")]
fn fmt_reg_range(regs: &RegList, count: u16) -> String {
    let s = regs.as_slice();
    let Some(&first) = s.first() else {
        return "{}".to_string();
    };
    if count == 0 {
        return "{}".to_string();
    }
    let last = first + count - 1;
    format!("{{{} .. {}}}", fmt_v(first), fmt_v(last))
}

#[allow(clippy::arithmetic_side_effects, reason = "`-(lit as i128)` — i64 widened to i128 before negation; i128 range covers i64::MIN negation, no overflow possible.")]
fn fmt_lit_signed(lit: i64) -> String {
    if lit < 0 {
        format!("-{:#x}", -i128::from(lit))
    } else {
        format!("{lit:#x}")
    }
}

fn fmt_string_ref(pool: &Option<PoolIndex>, dex: &DexFile) -> String {
    if let Some(PoolIndex::String(sidx)) = pool {
        match dex.get_string(*sidx) {
            Ok(s) => format!("\"{}\"", escape_smali_string(s)),
            Err(_) => "\"<invalid>\"".to_string(),
        }
    } else {
        "\"<invalid>\"".to_string()
    }
}

fn fmt_type_ref(pool: &Option<PoolIndex>, dex: &DexFile) -> String {
    if let Some(PoolIndex::Type(tidx)) = pool {
        dex.get_type_descriptor(*tidx).unwrap_or("?").to_string()
    } else {
        "?".to_string()
    }
}

fn fmt_field_ref(pool: &Option<PoolIndex>, dex: &DexFile) -> String {
    if let Some(PoolIndex::Field(fidx)) = pool {
        if let Some(field) = dex.fields.get(fidx.0 as usize) {
            let class = dex.get_type_descriptor(field.class_idx).unwrap_or("?");
            let name = dex.get_string(field.name_idx).unwrap_or("?");
            let ty = dex.get_type_descriptor(field.type_idx).unwrap_or("?");
            return format!("{class}->{name}:{ty}");
        }
    }
    "?->?:?".to_string()
}

fn fmt_method_ref(pool: &Option<PoolIndex>, dex: &DexFile) -> String {
    let midx = match pool {
        Some(PoolIndex::Method(m)) => *m,
        Some(PoolIndex::MethodAndProto(m, _)) => *m,
        _ => return "?->?(?)?".to_string(),
    };
    let Some(method) = dex.methods.get(midx.0 as usize) else {
        return "?->?(?)?".to_string();
    };
    let class = dex.get_type_descriptor(method.class_idx).unwrap_or("?");
    let name = dex.get_string(method.name_idx).unwrap_or("?");
    let proto = match dex.protos.get(method.proto_idx.0 as usize) {
        Some(p) => p,
        None => return format!("{class}->{name}(?)?"),
    };
    let ret = dex
        .get_type_descriptor(proto.return_type_idx)
        .unwrap_or("?");
    let params: String = if proto.parameters_off == 0 {
        String::new()
    } else if let Some(tl) = dex.type_lists.get(&proto.parameters_off) {
        tl.iter()
            .map(|t| dex.get_type_descriptor(*t).unwrap_or("?").to_string())
            .collect::<Vec<_>>()
            .join("")
    } else {
        String::new()
    };
    format!("{class}->{name}({params}){ret}")
}

fn escape_smali_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

// ── Mnemonic table ──────────────────────────────────────────────────

/// Canonical baksmali mnemonic for a Dalvik opcode.
fn mnemonic(op: Opcode) -> &'static str {
    use Opcode::*;
    match op {
        Nop => "nop",

        Move => "move",
        MoveFrom16 => "move/from16",
        Move16 => "move/16",
        MoveWide => "move-wide",
        MoveWideFrom16 => "move-wide/from16",
        MoveWide16 => "move-wide/16",
        MoveObject => "move-object",
        MoveObjectFrom16 => "move-object/from16",
        MoveObject16 => "move-object/16",

        MoveResult => "move-result",
        MoveResultWide => "move-result-wide",
        MoveResultObject => "move-result-object",
        MoveException => "move-exception",

        ReturnVoid => "return-void",
        Return => "return",
        ReturnWide => "return-wide",
        ReturnObject => "return-object",

        Const4 => "const/4",
        Const16 => "const/16",
        Const => "const",
        ConstHigh16 => "const/high16",
        ConstWide16 => "const-wide/16",
        ConstWide32 => "const-wide/32",
        ConstWide => "const-wide",
        ConstWideHigh16 => "const-wide/high16",
        ConstString => "const-string",
        ConstStringJumbo => "const-string/jumbo",
        ConstClass => "const-class",
        ConstMethodHandle => "const-method-handle",
        ConstMethodType => "const-method-type",

        MonitorEnter => "monitor-enter",
        MonitorExit => "monitor-exit",

        CheckCast => "check-cast",
        InstanceOf => "instance-of",
        ArrayLength => "array-length",
        NewInstance => "new-instance",
        NewArray => "new-array",

        FilledNewArray => "filled-new-array",
        FilledNewArrayRange => "filled-new-array/range",
        FillArrayData => "fill-array-data",

        Throw => "throw",
        Goto => "goto",
        Goto16 => "goto/16",
        Goto32 => "goto/32",

        PackedSwitch => "packed-switch",
        SparseSwitch => "sparse-switch",

        CmplFloat => "cmpl-float",
        CmpgFloat => "cmpg-float",
        CmplDouble => "cmpl-double",
        CmpgDouble => "cmpg-double",
        CmpLong => "cmp-long",

        IfEq => "if-eq",
        IfNe => "if-ne",
        IfLt => "if-lt",
        IfGe => "if-ge",
        IfGt => "if-gt",
        IfLe => "if-le",
        IfEqz => "if-eqz",
        IfNez => "if-nez",
        IfLtz => "if-ltz",
        IfGez => "if-gez",
        IfGtz => "if-gtz",
        IfLez => "if-lez",

        Aget => "aget",
        AgetWide => "aget-wide",
        AgetObject => "aget-object",
        AgetBoolean => "aget-boolean",
        AgetByte => "aget-byte",
        AgetChar => "aget-char",
        AgetShort => "aget-short",
        Aput => "aput",
        AputWide => "aput-wide",
        AputObject => "aput-object",
        AputBoolean => "aput-boolean",
        AputByte => "aput-byte",
        AputChar => "aput-char",
        AputShort => "aput-short",

        Iget => "iget",
        IgetWide => "iget-wide",
        IgetObject => "iget-object",
        IgetBoolean => "iget-boolean",
        IgetByte => "iget-byte",
        IgetChar => "iget-char",
        IgetShort => "iget-short",
        Iput => "iput",
        IputWide => "iput-wide",
        IputObject => "iput-object",
        IputBoolean => "iput-boolean",
        IputByte => "iput-byte",
        IputChar => "iput-char",
        IputShort => "iput-short",

        Sget => "sget",
        SgetWide => "sget-wide",
        SgetObject => "sget-object",
        SgetBoolean => "sget-boolean",
        SgetByte => "sget-byte",
        SgetChar => "sget-char",
        SgetShort => "sget-short",
        Sput => "sput",
        SputWide => "sput-wide",
        SputObject => "sput-object",
        SputBoolean => "sput-boolean",
        SputByte => "sput-byte",
        SputChar => "sput-char",
        SputShort => "sput-short",

        InvokeVirtual => "invoke-virtual",
        InvokeSuper => "invoke-super",
        InvokeDirect => "invoke-direct",
        InvokeStatic => "invoke-static",
        InvokeInterface => "invoke-interface",
        InvokeVirtualRange => "invoke-virtual/range",
        InvokeSuperRange => "invoke-super/range",
        InvokeDirectRange => "invoke-direct/range",
        InvokeStaticRange => "invoke-static/range",
        InvokeInterfaceRange => "invoke-interface/range",
        InvokePolymorphic => "invoke-polymorphic",
        InvokePolymorphicRange => "invoke-polymorphic/range",
        InvokeCustom => "invoke-custom",
        InvokeCustomRange => "invoke-custom/range",

        NegInt => "neg-int",
        NotInt => "not-int",
        NegLong => "neg-long",
        NotLong => "not-long",
        NegFloat => "neg-float",
        NegDouble => "neg-double",
        IntToLong => "int-to-long",
        IntToFloat => "int-to-float",
        IntToDouble => "int-to-double",
        LongToInt => "long-to-int",
        LongToFloat => "long-to-float",
        LongToDouble => "long-to-double",
        FloatToInt => "float-to-int",
        FloatToLong => "float-to-long",
        FloatToDouble => "float-to-double",
        DoubleToInt => "double-to-int",
        DoubleToLong => "double-to-long",
        DoubleToFloat => "double-to-float",
        IntToByte => "int-to-byte",
        IntToChar => "int-to-char",
        IntToShort => "int-to-short",

        AddInt => "add-int",
        SubInt => "sub-int",
        MulInt => "mul-int",
        DivInt => "div-int",
        RemInt => "rem-int",
        AndInt => "and-int",
        OrInt => "or-int",
        XorInt => "xor-int",
        ShlInt => "shl-int",
        ShrInt => "shr-int",
        UshrInt => "ushr-int",

        AddLong => "add-long",
        SubLong => "sub-long",
        MulLong => "mul-long",
        DivLong => "div-long",
        RemLong => "rem-long",
        AndLong => "and-long",
        OrLong => "or-long",
        XorLong => "xor-long",
        ShlLong => "shl-long",
        ShrLong => "shr-long",
        UshrLong => "ushr-long",

        AddFloat => "add-float",
        SubFloat => "sub-float",
        MulFloat => "mul-float",
        DivFloat => "div-float",
        RemFloat => "rem-float",

        AddDouble => "add-double",
        SubDouble => "sub-double",
        MulDouble => "mul-double",
        DivDouble => "div-double",
        RemDouble => "rem-double",

        AddInt2Addr => "add-int/2addr",
        SubInt2Addr => "sub-int/2addr",
        MulInt2Addr => "mul-int/2addr",
        DivInt2Addr => "div-int/2addr",
        RemInt2Addr => "rem-int/2addr",
        AndInt2Addr => "and-int/2addr",
        OrInt2Addr => "or-int/2addr",
        XorInt2Addr => "xor-int/2addr",
        ShlInt2Addr => "shl-int/2addr",
        ShrInt2Addr => "shr-int/2addr",
        UshrInt2Addr => "ushr-int/2addr",

        AddLong2Addr => "add-long/2addr",
        SubLong2Addr => "sub-long/2addr",
        MulLong2Addr => "mul-long/2addr",
        DivLong2Addr => "div-long/2addr",
        RemLong2Addr => "rem-long/2addr",
        AndLong2Addr => "and-long/2addr",
        OrLong2Addr => "or-long/2addr",
        XorLong2Addr => "xor-long/2addr",
        ShlLong2Addr => "shl-long/2addr",
        ShrLong2Addr => "shr-long/2addr",
        UshrLong2Addr => "ushr-long/2addr",

        AddFloat2Addr => "add-float/2addr",
        SubFloat2Addr => "sub-float/2addr",
        MulFloat2Addr => "mul-float/2addr",
        DivFloat2Addr => "div-float/2addr",
        RemFloat2Addr => "rem-float/2addr",

        AddDouble2Addr => "add-double/2addr",
        SubDouble2Addr => "sub-double/2addr",
        MulDouble2Addr => "mul-double/2addr",
        DivDouble2Addr => "div-double/2addr",
        RemDouble2Addr => "rem-double/2addr",

        AddIntLit16 => "add-int/lit16",
        RsubInt => "rsub-int",
        MulIntLit16 => "mul-int/lit16",
        DivIntLit16 => "div-int/lit16",
        RemIntLit16 => "rem-int/lit16",
        AndIntLit16 => "and-int/lit16",
        OrIntLit16 => "or-int/lit16",
        XorIntLit16 => "xor-int/lit16",

        AddIntLit8 => "add-int/lit8",
        RsubIntLit8 => "rsub-int/lit8",
        MulIntLit8 => "mul-int/lit8",
        DivIntLit8 => "div-int/lit8",
        RemIntLit8 => "rem-int/lit8",
        AndIntLit8 => "and-int/lit8",
        OrIntLit8 => "or-int/lit8",
        XorIntLit8 => "xor-int/lit8",
        ShlIntLit8 => "shl-int/lit8",
        ShrIntLit8 => "shr-int/lit8",
        UshrIntLit8 => "ushr-int/lit8",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mnemonic_round_trip_spot_check() {
        // Spot-check a representative slice of opcodes against the canonical
        // baksmali names. If any of these regress, the table is wrong.
        assert_eq!(mnemonic(Opcode::Nop), "nop");
        assert_eq!(mnemonic(Opcode::Move), "move");
        assert_eq!(mnemonic(Opcode::MoveFrom16), "move/from16");
        assert_eq!(mnemonic(Opcode::Const4), "const/4");
        assert_eq!(mnemonic(Opcode::ConstHigh16), "const/high16");
        assert_eq!(mnemonic(Opcode::ConstWideHigh16), "const-wide/high16");
        assert_eq!(mnemonic(Opcode::ConstStringJumbo), "const-string/jumbo");
        assert_eq!(mnemonic(Opcode::IfEqz), "if-eqz");
        assert_eq!(mnemonic(Opcode::Goto16), "goto/16");
        assert_eq!(mnemonic(Opcode::InvokeVirtualRange), "invoke-virtual/range");
        assert_eq!(mnemonic(Opcode::AddInt2Addr), "add-int/2addr");
        assert_eq!(mnemonic(Opcode::AddIntLit8), "add-int/lit8");
        assert_eq!(mnemonic(Opcode::ReturnVoid), "return-void");
        assert_eq!(mnemonic(Opcode::IntToByte), "int-to-byte");
        assert_eq!(mnemonic(Opcode::AgetObject), "aget-object");
    }

    #[test]
    fn fmt_lit_signed_basic() {
        assert_eq!(fmt_lit_signed(0), "0x0");
        assert_eq!(fmt_lit_signed(15), "0xf");
        assert_eq!(fmt_lit_signed(-1), "-0x1");
        assert_eq!(fmt_lit_signed(-256), "-0x100");
    }

    #[test]
    fn label_format() {
        assert_eq!(label(0), "addr_0");
        assert_eq!(label(0x1f), "addr_1f");
    }

    #[test]
    fn method_access_flags_order() {
        // Canonical baksmali order: public static final constructor
        assert_eq!(method_access_flags(0x0001), "public");
        assert_eq!(method_access_flags(0x0009), "public static");
        assert_eq!(method_access_flags(0x0019), "public static final");
        // <init> tag → constructor; public constructor
        assert_eq!(method_access_flags(0x10001), "public constructor");
        // Abstract native won't co-exist in practice, but the table still
        // renders them in declared order.
        assert_eq!(method_access_flags(0x0500), "native abstract");
        // Synthetic bridge
        assert_eq!(method_access_flags(0x1041), "public bridge synthetic");
    }
}
