//! Opcode encoding tables for the reference scan.
//!
//! Widths and reference kinds are two 256-entry tables generated from the range
//! lists below. The tests keep independently written transcriptions of both lists,
//! so editing a table cannot silently change how instructions decode.

use super::RefKind;
use crate::bytes::{read_u16, read_u32};
use anyhow::{Context, Result, bail};

/// Instruction width in code units, or 0 for the opcodes that need the runtime
/// path: `0x00` payloads and unsupported opcodes.
const fn opcode_units(opcode: u8) -> u8 {
    match opcode {
        0x00 => 0,
        0x01
        | 0x04
        | 0x07
        | 0x0a..=0x12
        | 0x1d
        | 0x1e
        | 0x21
        | 0x27
        | 0x28
        | 0x7b..=0x8f
        | 0xb0..=0xcf => 1,
        0x02
        | 0x05
        | 0x08
        | 0x13
        | 0x15
        | 0x16
        | 0x19
        | 0x1a
        | 0x1c
        | 0x1f
        | 0x20
        | 0x22
        | 0x23
        | 0x29
        | 0x2d..=0x3d
        | 0x44..=0x6d
        | 0x90..=0xaf
        | 0xd0..=0xe2
        | 0xfe
        | 0xff => 2,
        0x03
        | 0x06
        | 0x09
        | 0x14
        | 0x17
        | 0x1b
        | 0x24..=0x26
        | 0x2a..=0x2c
        | 0x6e..=0x72
        | 0x74..=0x78
        | 0xfc
        | 0xfd => 3,
        0xfa | 0xfb => 4,
        0x18 => 5,
        _ => 0,
    }
}

/// Bitmask of `RefKind::bit` values whose references this opcode can carry.
const fn opcode_kinds(opcode: u8) -> u8 {
    let mut mask = 0;
    if matches!(opcode, 0x1a | 0x1b) {
        mask |= RefKind::String.bit();
    }
    if matches!(opcode, 0x1c | 0x1f | 0x20 | 0x22..=0x25) {
        mask |= RefKind::Type.bit();
    }
    if matches!(opcode, 0x52..=0x6d) {
        mask |= RefKind::Field.bit();
    }
    if matches!(opcode, 0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb) {
        mask |= RefKind::Method.bit();
    }
    mask
}

/// Width and kind tables, so the instruction loop does two loads instead of two
/// function calls per instruction.
pub(super) const OPCODE_UNITS: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut opcode = 0;
    while opcode < 256 {
        table[opcode] = opcode_units(opcode as u8);
        opcode += 1;
    }
    table
};

pub(super) const OPCODE_KINDS: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut opcode = 0;
    while opcode < 256 {
        table[opcode] = opcode_kinds(opcode as u8);
        opcode += 1;
    }
    table
};

pub(super) fn instruction_units(code: &[u8], pc: usize) -> Result<usize> {
    let opcode = *code.get(pc).context("missing opcode")?;
    if opcode == 0 {
        let ident = read_u16(code, pc)?;
        return match ident {
            0x0100 => Ok(4 + read_u16(code, pc + 2)? as usize * 2),
            0x0200 => Ok(2 + read_u16(code, pc + 2)? as usize * 4),
            0x0300 => {
                let width = read_u16(code, pc + 2)? as usize;
                let size = read_u32(code, pc + 4)? as usize;
                Ok(4 + width
                    .checked_mul(size)
                    .context("array payload overflow")?
                    .div_ceil(2))
            }
            _ => Ok(1),
        };
    }
    match OPCODE_UNITS[opcode as usize] {
        0 => bail!("unsupported opcode 0x{opcode:02x}"),
        units => Ok(units as usize),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim transcription of the width match that `OPCODE_UNITS` replaced.
    fn instruction_units_reference(opcode: u8) -> Result<usize> {
        Ok(match opcode {
            0x01
            | 0x04
            | 0x07
            | 0x0a..=0x12
            | 0x1d
            | 0x1e
            | 0x21
            | 0x27
            | 0x28
            | 0x7b..=0x8f
            | 0xb0..=0xcf => 1,
            0x02
            | 0x05
            | 0x08
            | 0x13
            | 0x15
            | 0x16
            | 0x19
            | 0x1a
            | 0x1c
            | 0x1f
            | 0x20
            | 0x22
            | 0x23
            | 0x29
            | 0x2d..=0x3d
            | 0x44..=0x6d
            | 0x90..=0xaf
            | 0xd0..=0xe2
            | 0xfe
            | 0xff => 2,
            0x03
            | 0x06
            | 0x09
            | 0x14
            | 0x17
            | 0x1b
            | 0x24..=0x26
            | 0x2a..=0x2c
            | 0x6e..=0x72
            | 0x74..=0x78
            | 0xfc
            | 0xfd => 3,
            0xfa | 0xfb => 4,
            0x18 => 5,
            _ => bail!("unsupported opcode 0x{opcode:02x}"),
        })
    }

    #[test]
    fn opcode_width_table_agrees_with_the_original_match() {
        for opcode in 1..=u8::MAX {
            match instruction_units_reference(opcode) {
                Ok(width) => assert_eq!(
                    OPCODE_UNITS[opcode as usize] as usize, width,
                    "0x{opcode:02x}"
                ),
                Err(_) => assert_eq!(OPCODE_UNITS[opcode as usize], 0, "0x{opcode:02x}"),
            }
        }
    }

    #[test]
    fn opcode_width_table_agrees_with_the_runtime_path() {
        for opcode in 0..=u8::MAX {
            let code = [opcode, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            let width = OPCODE_UNITS[opcode as usize] as usize;
            if opcode == 0 {
                assert_eq!(width, 0, "payloads must use the runtime path");
            } else if width == 0 {
                assert!(
                    instruction_units(&code, 0).is_err(),
                    "0x{opcode:02x} should be rejected"
                );
            } else {
                assert_eq!(
                    instruction_units(&code, 0).unwrap(),
                    width,
                    "0x{opcode:02x}"
                );
            }
        }
    }

    #[test]
    fn opcode_widths_cover_reference_instructions() {
        for (opcode, width) in [(0x1a, 2), (0x1b, 3), (0x52, 2), (0x6e, 3), (0xfa, 4)] {
            let code = [opcode, 0, 0, 0, 0, 0, 0, 0];
            assert_eq!(instruction_units(&code, 0).unwrap(), width);
        }
    }

    #[test]
    fn payload_widths_are_computed() {
        assert_eq!(
            instruction_units(&[0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 0).unwrap(),
            8
        );
        assert_eq!(
            instruction_units(&[0, 3, 1, 0, 3, 0, 0, 0, 1, 2, 3, 0], 0).unwrap(),
            6
        );
    }

    /// Reference transcription of the filter the table replaced.
    fn opcode_matches_reference(kind: RefKind, opcode: u8) -> bool {
        match kind {
            RefKind::String => matches!(opcode, 0x1a | 0x1b),
            RefKind::Type => matches!(opcode, 0x1c | 0x1f | 0x20 | 0x22..=0x25),
            RefKind::Field => matches!(opcode, 0x52..=0x6d),
            RefKind::Method => matches!(opcode, 0x6e..=0x72 | 0x74..=0x78 | 0xfa | 0xfb),
        }
    }

    #[test]
    fn opcode_kind_table_agrees_with_the_old_filter() {
        for opcode in 0..=u8::MAX {
            for kind in [
                RefKind::String,
                RefKind::Type,
                RefKind::Method,
                RefKind::Field,
            ] {
                assert_eq!(
                    OPCODE_KINDS[opcode as usize] & kind.bit() != 0,
                    opcode_matches_reference(kind, opcode),
                    "0x{opcode:02x} {kind:?}"
                );
            }
        }
    }
}
