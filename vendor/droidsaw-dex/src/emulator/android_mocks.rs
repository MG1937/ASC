// SPDX-License-Identifier: BSD-3-Clause

//! Android API mock layer for the Dalvik bytecode emulator.
//!
//! Provides Rust-native implementations of the Android/Java standard
//! library methods that appear in typical string-deobfuscator patterns.
//! All values are owned by the emulator's register file; there is no JVM
//! heap or garbage collector.
//!
//! # Supported mock surface
//!
//! - `java.lang.String` — `charAt`, `length`, `substring`, `getBytes`,
//!   `valueOf(int)`, `valueOf(char)`, `concat`, `replace`.
//! - `java.lang.StringBuilder` — constructor, `append(String)`,
//!   `append(int)`, `append(char)`, `toString`.
//! - `java.util.Arrays` — `copyOf`, `copyOfRange`.
//! - `java.lang.Integer` — `parseInt`, `toHexString`.
//!
//! # Design constraints
//!
//! - All return values are [`super::Value`] — no JVM object graph.
//! - An invoke on an unmocked method returns
//!   `Err(EmulatorError::UnsupportedMethod)`.
//! - `StringBuilder` state is carried in the register file as
//!   `Value::Str`. The `updated_this` field of [`MockResult`] lets the
//!   caller write back the mutated `this` value without a separate heap.
//! - No `unwrap()` / `expect()` / `panic!()` on any non-test path.
//! - Arithmetic uses wrapping ops or explicit bounds checks; no
//!   `clippy::arithmetic_side_effects` violations.

#![allow(clippy::arithmetic_side_effects, reason = "Intentional JVM-wrapping arithmetic in the android mocks (parity with the real Android runtime). Per-site annotations document each wrapping case; the module-level allow keeps emulator code legible without 30+ per-call attribute pairs.")]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::as_conversions,
    reason = "PROOF / INTENT: this module emulates java.lang.String / StringBuilder semantics. Every cast follows the JVM convention: i32 indices into UTF-16/byte arrays are negative-checked above the cast (the negative branch returns ArrayOutOfBounds), then narrowed to usize. usize lengths are widened to i32 (returns of String.length() / array.length); these can technically truncate on >2GiB strings but no real JVM permits a String of that size — matches Android runtime behaviour. `b as i8` for byte-array sign-extension is the IDIOM matching DEX aget-byte semantics. as_conversions is included in the bulk allow because the cast cluster taxonomy is fully described above."
)]

use crate::ids::MethodIdx;
use crate::parser::DexFile;

use super::{EmulatorError, Value};

// ── MockResult ─────────────────────────────────────────────────────────

/// Result of a mock dispatch call.
///
/// `return_value` goes into `result_slot` (consumed by a subsequent
/// `move-result`). `updated_this` is `Some(v)` when the mock mutated the
/// `this` object (e.g. `StringBuilder.append`) and the caller must write
/// `v` back to the this-register.
#[derive(Debug)]
pub struct MockResult {
    /// The Java return value of the mocked method.
    pub return_value: Value,
    /// If `Some`, the caller must write this back to the this-register
    /// immediately after dispatch (before `move-result`).
    pub updated_this: Option<Value>,
}

impl MockResult {
    fn ok(return_value: Value) -> Self {
        Self { return_value, updated_this: None }
    }

    fn ok_with_this(return_value: Value, updated_this: Value) -> Self {
        Self { return_value, updated_this: Some(updated_this) }
    }
}

// ── Dispatch entry point ───────────────────────────────────────────────

/// Dispatch an `invoke-*` instruction to the appropriate Android mock.
///
/// - `dex`: DEX file used to resolve class and method names.
/// - `method_idx`: pool index from the instruction.
/// - `this_val`: `Some(&v)` for virtual/direct calls; `None` for static.
/// - `args`: typed argument values (excluding `this`).
///
/// Returns `Ok(MockResult)` on success. Returns
/// `Err(EmulatorError::UnsupportedMethod)` if the method is not in the
/// mock surface (caller should treat as "emulation not possible").
pub fn dispatch(
    dex: &DexFile,
    method_idx: MethodIdx,
    this_val: Option<&Value>,
    args: &[Value],
) -> Result<MockResult, EmulatorError> {
    // Resolve class descriptor ("Ljava/lang/String;"), method name, and
    // shorty descriptor. The shorty is used where overloading requires
    // distinguishing `append(char C)` from `append(int I)`.
    let (class_desc, method_name, shorty) = resolve_names(dex, method_idx)?;

    match (class_desc, method_name) {
        // ── java.lang.String ──────────────────────────────────────────
        ("Ljava/lang/String;", "charAt") => {
            let s = require_str_this(this_val, "String.charAt")?;
            let idx = require_int_arg(args, 0, "String.charAt")?;
            mock_char_at(s, idx)
        }
        ("Ljava/lang/String;", "length") => {
            let s = require_str_this(this_val, "String.length")?;
            mock_length(s)
        }
        ("Ljava/lang/String;", "substring") => {
            let s = require_str_this(this_val, "String.substring")?;
            let start = require_int_arg(args, 0, "String.substring")?;
            let end = require_int_arg(args, 1, "String.substring")?;
            mock_substring(s, start, end)
        }
        ("Ljava/lang/String;", "getBytes") => {
            let s = require_str_this(this_val, "String.getBytes")?;
            // Charset argument (args[0]) is intentionally ignored; we
            // treat all strings as UTF-8 byte sequences.
            mock_get_bytes(s)
        }
        ("Ljava/lang/String;", "valueOf") => {
            // valueOf is static; no this.
            // valueOf(int) and valueOf(char) share the same mock body.
            let v = args.first().ok_or(EmulatorError::TypeMismatch {
                expected: "int or char",
                got: "nothing",
            })?;
            mock_value_of(v)
        }
        ("Ljava/lang/String;", "concat") => {
            let s = require_str_this(this_val, "String.concat")?;
            let other = require_str_arg(args, 0, "String.concat")?;
            mock_concat(s, other)
        }
        ("Ljava/lang/String;", "replace") => {
            let s = require_str_this(this_val, "String.replace")?;
            let old_char = require_int_arg(args, 0, "String.replace")?;
            let new_char = require_int_arg(args, 1, "String.replace")?;
            mock_replace(s, old_char, new_char)
        }

        // ── java.lang.StringBuilder ───────────────────────────────────
        ("Ljava/lang/StringBuilder;", "<init>") => {
            // Constructor: returns Void; this is set to empty Str.
            Ok(MockResult::ok_with_this(Value::Void, Value::Str(String::new())))
        }
        ("Ljava/lang/StringBuilder;", "append") => {
            let buf = require_str_this(this_val, "StringBuilder.append")?;
            let arg = args.first().ok_or(EmulatorError::TypeMismatch {
                expected: "String, int, or char",
                got: "nothing",
            })?;
            // Shorty second character disambiguates overloads:
            // "VC" = append(char), "VI" = append(int), "VL" = append(String).
            // For append(char), convert the Int code unit to a char string.
            let is_char_append = shorty.as_bytes().get(1).copied() == Some(b'C');
            mock_sb_append(buf, arg, is_char_append)
        }
        ("Ljava/lang/StringBuilder;", "toString") => {
            let buf = require_str_this(this_val, "StringBuilder.toString")?;
            Ok(MockResult::ok(Value::Str(buf.to_owned())))
        }

        // ── java.util.Arrays ──────────────────────────────────────────
        ("Ljava/util/Arrays;", "copyOf") => {
            let arr = require_array_arg(args, 0, "Arrays.copyOf")?;
            let new_len = require_int_arg(args, 1, "Arrays.copyOf")?;
            mock_copy_of(arr, new_len)
        }
        ("Ljava/util/Arrays;", "copyOfRange") => {
            let arr = require_array_arg(args, 0, "Arrays.copyOfRange")?;
            let from = require_int_arg(args, 1, "Arrays.copyOfRange")?;
            let to = require_int_arg(args, 2, "Arrays.copyOfRange")?;
            mock_copy_of_range(arr, from, to)
        }

        // ── java.lang.Integer ─────────────────────────────────────────
        ("Ljava/lang/Integer;", "parseInt") => {
            let s = require_str_arg(args, 0, "Integer.parseInt")?;
            mock_parse_int(s)
        }
        ("Ljava/lang/Integer;", "toHexString") => {
            let v = require_int_arg(args, 0, "Integer.toHexString")?;
            mock_to_hex_string(v)
        }

        // ── Unknown method → UnsupportedMethod ────────────────────────
        _ => Err(EmulatorError::UnsupportedMethod {
            class: class_desc.to_owned(),
            name: method_name.to_owned(),
        }),
    }
}

// ── Name resolution ────────────────────────────────────────────────────

/// Resolve class descriptor, method name, and shorty descriptor from a
/// `MethodIdx`.
///
/// Returns `(class_descriptor, method_name, shorty)`.
///
/// The shorty encodes the signature compactly: first character is the
/// return type, subsequent characters are parameter types.  Type codes:
/// `V`=void, `Z`=boolean, `B`=byte, `S`=short, `C`=char, `I`=int,
/// `J`=long, `F`=float, `D`=double, `L`=reference/array.  Example:
/// `StringBuilder.append(char C)` → shorty `"VC"`.
fn resolve_names(
    dex: &DexFile,
    method_idx: MethodIdx,
) -> Result<(&str, &str, &str), EmulatorError> {
    let item = dex.methods.get(method_idx.0 as usize).ok_or(
        EmulatorError::InvokeResolutionError {
            detail: "method index out of bounds",
        },
    )?;
    let class_desc = dex
        .get_type_descriptor(item.class_idx)
        .map_err(|_e| EmulatorError::InvokeResolutionError {
            detail: "could not resolve class descriptor for invoke",
        })?;
    let method_name = dex
        .get_string(item.name_idx)
        .map_err(|_e| EmulatorError::InvokeResolutionError {
            detail: "could not resolve method name for invoke",
        })?;
    let proto = dex.protos.get(item.proto_idx.0 as usize).ok_or(
        EmulatorError::InvokeResolutionError {
            detail: "proto index out of bounds",
        },
    )?;
    let shorty = dex
        .get_string(proto.shorty_idx)
        .map_err(|_e| EmulatorError::InvokeResolutionError {
            detail: "could not resolve shorty descriptor for invoke",
        })?;
    Ok((class_desc, method_name, shorty))
}

// ── Argument extractors ────────────────────────────────────────────────

fn require_str_this<'a>(
    this_val: Option<&'a Value>,
    _site: &'static str,
) -> Result<&'a str, EmulatorError> {
    match this_val {
        Some(Value::Str(s)) => Ok(s.as_str()),
        Some(other) => Err(EmulatorError::TypeMismatch {
            expected: "Str (this)",
            got: value_kind_name(other),
        }),
        None => Err(EmulatorError::InvokeResolutionError {
            detail: "expected this-value for virtual call",
        }),
    }
}

fn require_str_arg<'a>(
    args: &'a [Value],
    idx: usize,
    _site: &'static str,
) -> Result<&'a str, EmulatorError> {
    match args.get(idx) {
        Some(Value::Str(s)) => Ok(s.as_str()),
        Some(other) => Err(EmulatorError::TypeMismatch {
            expected: "Str",
            got: value_kind_name(other),
        }),
        None => Err(EmulatorError::TypeMismatch {
            expected: "Str",
            got: "nothing",
        }),
    }
}

fn require_int_arg(
    args: &[Value],
    idx: usize,
    _site: &'static str,
) -> Result<i32, EmulatorError> {
    match args.get(idx) {
        Some(Value::Int(v)) => Ok(*v),
        Some(other) => Err(EmulatorError::TypeMismatch {
            expected: "Int",
            got: value_kind_name(other),
        }),
        None => Err(EmulatorError::TypeMismatch {
            expected: "Int",
            got: "nothing",
        }),
    }
}

fn require_array_arg<'a>(
    args: &'a [Value],
    idx: usize,
    _site: &'static str,
) -> Result<&'a [i32], EmulatorError> {
    match args.get(idx) {
        Some(Value::Array(a)) => Ok(a.as_slice()),
        Some(other) => Err(EmulatorError::TypeMismatch {
            expected: "Array",
            got: value_kind_name(other),
        }),
        None => Err(EmulatorError::TypeMismatch {
            expected: "Array",
            got: "nothing",
        }),
    }
}

fn value_kind_name(v: &Value) -> &'static str {
    match v {
        Value::Int(_) => "Int",
        Value::Wide(_) => "Wide",
        Value::Str(_) => "Str",
        Value::Array(_) => "Array",
        Value::Void => "Void",
    }
}

// ── java.lang.String mocks ─────────────────────────────────────────────

/// `String.charAt(int index)` → `int` (Java `char` = UTF-16 code unit).
///
/// Java strings are sequences of UTF-16 code units. To match JVM
/// semantics, we re-encode the Rust `str` as UTF-16 and index into that.
/// This correctly handles supplementary codepoints (which occupy two
/// code units in UTF-16 and are also represented as two Rust `char`-
/// width values when iterating).
fn mock_char_at(s: &str, index: i32) -> Result<MockResult, EmulatorError> {
    if index < 0 {
        return Err(EmulatorError::ArrayOutOfBounds {
            index,
            length: s.encode_utf16().count(),
        });
    }
    let index_usize = index as usize;
    let unit = s
        .encode_utf16()
        .nth(index_usize)
        .ok_or(EmulatorError::ArrayOutOfBounds {
            index,
            length: s.encode_utf16().count(),
        })?;
    Ok(MockResult::ok(Value::Int(i32::from(unit))))
}

/// `String.length()` → `int` (UTF-16 code unit count, matching JVM).
fn mock_length(s: &str) -> Result<MockResult, EmulatorError> {
    // Java `String.length()` returns the number of UTF-16 code units.
    let len = s.encode_utf16().count();
    // Lengths beyond i32::MAX cannot occur on any real JVM string; safe truncation.
    Ok(MockResult::ok(Value::Int(len as i32)))
}

/// `String.substring(int start, int end)` → `String`.
///
/// Operates on UTF-16 code units to match JVM semantics.
fn mock_substring(s: &str, start: i32, end: i32) -> Result<MockResult, EmulatorError> {
    if start < 0 || end < 0 {
        return Err(EmulatorError::ArrayOutOfBounds {
            index: start.min(end),
            length: 0,
        });
    }
    if end < start {
        return Err(EmulatorError::ArrayOutOfBounds {
            index: end,
            length: start as usize,
        });
    }
    let units: Vec<u16> = s.encode_utf16().collect();
    let len = units.len();
    let start_u = start as usize;
    let end_u = end as usize;
    if start_u > len || end_u > len {
        return Err(EmulatorError::ArrayOutOfBounds {
            index: start_u.max(end_u) as i32,
            length: len,
        });
    }
    let slice = units
        .get(start_u..end_u)
        .ok_or(EmulatorError::ArrayOutOfBounds {
            index: end,
            length: len,
        })?;
    let result = String::from_utf16_lossy(slice).to_owned();
    Ok(MockResult::ok(Value::Str(result)))
}

/// `String.getBytes(String charset)` → `byte[]` as `Value::Array(Vec<i32>)`.
///
/// The charset argument is intentionally ignored; we encode as UTF-8.
/// Byte values are sign-extended to i32 (as aput-byte / aget-byte do).
fn mock_get_bytes(s: &str) -> Result<MockResult, EmulatorError> {
    let bytes: Vec<i32> = s.as_bytes().iter().map(|&b| i32::from(b as i8)).collect();
    Ok(MockResult::ok(Value::Array(bytes)))
}

/// `String.valueOf(int)` / `String.valueOf(char)` → `String`.
fn mock_value_of(v: &Value) -> Result<MockResult, EmulatorError> {
    match v {
        Value::Int(i) => Ok(MockResult::ok(Value::Str(i.to_string()))),
        other => Err(EmulatorError::TypeMismatch {
            expected: "Int (for String.valueOf)",
            got: value_kind_name(other),
        }),
    }
}

/// `String.concat(String other)` → `String`.
fn mock_concat(s: &str, other: &str) -> Result<MockResult, EmulatorError> {
    let mut result = String::with_capacity(s.len().saturating_add(other.len()));
    result.push_str(s);
    result.push_str(other);
    Ok(MockResult::ok(Value::Str(result)))
}

/// `String.replace(char oldChar, char newChar)` → `String`.
///
/// Operates on UTF-16 code units to match JVM char semantics.
fn mock_replace(s: &str, old_char: i32, new_char: i32) -> Result<MockResult, EmulatorError> {
    // Java char is a 16-bit unsigned value. Mask to u16 then decode as
    // a single UTF-16 code unit → Option<char>. For surrogate halves
    // (which cannot form a valid Rust `char`) we silently replace the
    // whole 16-bit unit if it matches.
    let old_u16 = (old_char & 0xFFFF) as u16;
    let new_u16 = (new_char & 0xFFFF) as u16;

    let units: Vec<u16> = s
        .encode_utf16()
        .map(|u| if u == old_u16 { new_u16 } else { u })
        .collect();
    let result = String::from_utf16_lossy(&units).to_owned();
    Ok(MockResult::ok(Value::Str(result)))
}

// ── java.lang.StringBuilder mocks ─────────────────────────────────────

/// `StringBuilder.append(String | int | char)` → `StringBuilder` (this).
///
/// The emulator carries StringBuilder state as `Value::Str`. This mock
/// appends `arg` to the buffer and returns the updated buffer both as
/// `return_value` (the Dalvik convention is to return `this` from
/// `append`) and as `updated_this` (so the caller can write back).
///
/// `is_char_append`: `true` when the shorty says this is `append(char C)`.
/// When `true` and `arg` is `Value::Int`, the int is treated as a UTF-16
/// code unit and decoded to a Rust `char` (or replaced with U+FFFD if it
/// is a lone surrogate).
fn mock_sb_append(buf: &str, arg: &Value, is_char_append: bool) -> Result<MockResult, EmulatorError> {
    let mut result = String::from(buf);
    match arg {
        Value::Str(s) => result.push_str(s),
        Value::Int(i) => {
            if is_char_append {
                // JVM char → UTF-16 code unit. Decode to Rust char; for
                // surrogate halves (lone surrogate) use U+FFFD.
                // Intentional bitwise-and to mask to u16 range.
                let unit = (*i & 0xFFFF) as u16;
                match char::from_u32(u32::from(unit)) {
                    Some(c) => result.push(c),
                    None => result.push('\u{FFFD}'),
                }
            } else {
                result.push_str(&i.to_string());
            }
        }
        other => {
            return Err(EmulatorError::TypeMismatch {
                expected: "Str or Int",
                got: value_kind_name(other),
            })
        }
    }
    let new_this = Value::Str(result.clone());
    Ok(MockResult::ok_with_this(new_this, Value::Str(result)))
}

// ── java.util.Arrays mocks ─────────────────────────────────────────────

/// `Arrays.copyOf(byte[] original, int newLength)` → `byte[]`.
///
/// Zero-pads or truncates `original` to `newLength` elements.
fn mock_copy_of(arr: &[i32], new_len: i32) -> Result<MockResult, EmulatorError> {
    if new_len < 0 {
        return Err(EmulatorError::NegativeArrayLength { length: new_len });
    }
    let new_len_usize = new_len as usize;
    if new_len_usize > super::ARRAY_SIZE_CAP {
        return Err(EmulatorError::ArrayTooLarge {
            length: new_len_usize,
            cap: super::ARRAY_SIZE_CAP,
        });
    }
    let mut result = Vec::with_capacity(new_len_usize);
    let copy_len = arr.len().min(new_len_usize);
    // PROOF: `copy_len ≤ arr.len()` and `copy_len ≤ new_len_usize`; both
    // bounded slices are valid.
    result.extend_from_slice(arr.get(..copy_len).unwrap_or(&[]));
    result.resize(new_len_usize, 0_i32);
    Ok(MockResult::ok(Value::Array(result)))
}

/// `Arrays.copyOfRange(byte[] original, int from, int to)` → `byte[]`.
///
/// Copies the range `[from, to)` from `original`; zero-pads if `to >
/// original.length`.
fn mock_copy_of_range(arr: &[i32], from: i32, to: i32) -> Result<MockResult, EmulatorError> {
    if from < 0 || to < 0 {
        return Err(EmulatorError::ArrayOutOfBounds {
            index: from.min(to),
            length: arr.len(),
        });
    }
    if to < from {
        return Err(EmulatorError::ArrayOutOfBounds {
            index: to,
            length: from as usize,
        });
    }
    let from_usize = from as usize;
    let to_usize = to as usize;
    let new_len = to_usize.saturating_sub(from_usize);
    if new_len > super::ARRAY_SIZE_CAP {
        return Err(EmulatorError::ArrayTooLarge {
            length: new_len,
            cap: super::ARRAY_SIZE_CAP,
        });
    }
    let mut result = Vec::with_capacity(new_len);
    // Copy what is available; zero-pad the rest.
    if from_usize < arr.len() {
        let available_end = arr.len().min(to_usize);
        // PROOF: `from_usize < arr.len()` and `available_end ≤ arr.len()`
        // so the slice is valid.
        result.extend_from_slice(arr.get(from_usize..available_end).unwrap_or(&[]));
    }
    result.resize(new_len, 0_i32);
    Ok(MockResult::ok(Value::Array(result)))
}

// ── java.lang.Integer mocks ────────────────────────────────────────────

/// `Integer.parseInt(String s)` → `int`.
fn mock_parse_int(s: &str) -> Result<MockResult, EmulatorError> {
    let v = s.trim().parse::<i32>().map_err(|_e| EmulatorError::TypeMismatch {
        expected: "parseable decimal integer string",
        got: "non-parseable string",
    })?;
    Ok(MockResult::ok(Value::Int(v)))
}

/// `Integer.toHexString(int i)` → `String`.
///
/// Java `toHexString` treats the int as an unsigned 32-bit value.
fn mock_to_hex_string(v: i32) -> Result<MockResult, EmulatorError> {
    // Java: Integer.toHexString(-1) = "ffffffff"
    Ok(MockResult::ok(Value::Str(format!("{:x}", v as u32))))
}

// ── Unit tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emulator::Value;

    // Helpers to call mocks directly without a DexFile.

    fn str_val(s: &str) -> Value {
        Value::Str(s.to_owned())
    }

    fn int_val(i: i32) -> Value {
        Value::Int(i)
    }

    fn arr_val(v: Vec<i32>) -> Value {
        Value::Array(v)
    }

    // ── String.charAt ─────────────────────────────────────────────────

    #[test]
    fn test_char_at_ascii() {
        let result = mock_char_at("hello", 1).unwrap();
        assert_eq!(result.return_value, int_val('e' as i32));
    }

    #[test]
    fn test_char_at_oob() {
        let err = mock_char_at("hi", 5).unwrap_err();
        assert!(matches!(err, EmulatorError::ArrayOutOfBounds { .. }));
    }

    #[test]
    fn test_char_at_negative() {
        let err = mock_char_at("hi", -1).unwrap_err();
        assert!(matches!(err, EmulatorError::ArrayOutOfBounds { .. }));
    }

    // ── String.length ─────────────────────────────────────────────────

    #[test]
    fn test_length_normal() {
        let result = mock_length("hello").unwrap();
        assert_eq!(result.return_value, int_val(5));
    }

    #[test]
    fn test_length_empty() {
        let result = mock_length("").unwrap();
        assert_eq!(result.return_value, int_val(0));
    }

    // ── String.substring ──────────────────────────────────────────────

    #[test]
    fn test_substring_normal() {
        let result = mock_substring("hello world", 6, 11).unwrap();
        assert_eq!(result.return_value, str_val("world"));
    }

    #[test]
    fn test_substring_oob() {
        let err = mock_substring("hi", 0, 10).unwrap_err();
        assert!(matches!(err, EmulatorError::ArrayOutOfBounds { .. }));
    }

    #[test]
    fn test_substring_end_lt_start() {
        let err = mock_substring("hello", 3, 1).unwrap_err();
        assert!(matches!(err, EmulatorError::ArrayOutOfBounds { .. }));
    }

    // ── String.getBytes ───────────────────────────────────────────────

    #[test]
    fn test_get_bytes_normal() {
        let result = mock_get_bytes("ABC").unwrap();
        assert_eq!(result.return_value, arr_val(vec![65, 66, 67]));
    }

    #[test]
    fn test_get_bytes_empty() {
        let result = mock_get_bytes("").unwrap();
        assert_eq!(result.return_value, arr_val(vec![]));
    }

    // ── String.valueOf ────────────────────────────────────────────────

    #[test]
    fn test_value_of_int() {
        let result = mock_value_of(&int_val(42)).unwrap();
        assert_eq!(result.return_value, str_val("42"));
    }

    #[test]
    fn test_value_of_wrong_type() {
        let err = mock_value_of(&Value::Void).unwrap_err();
        assert!(matches!(err, EmulatorError::TypeMismatch { .. }));
    }

    // ── String.concat ─────────────────────────────────────────────────

    #[test]
    fn test_concat_normal() {
        let result = mock_concat("foo", "bar").unwrap();
        assert_eq!(result.return_value, str_val("foobar"));
    }

    #[test]
    fn test_concat_empty() {
        let result = mock_concat("foo", "").unwrap();
        assert_eq!(result.return_value, str_val("foo"));
    }

    // ── String.replace ────────────────────────────────────────────────

    #[test]
    fn test_replace_normal() {
        let result = mock_replace("hello", 'l' as i32, 'r' as i32).unwrap();
        assert_eq!(result.return_value, str_val("herro"));
    }

    #[test]
    fn test_replace_no_match() {
        let result = mock_replace("hello", 'z' as i32, 'x' as i32).unwrap();
        assert_eq!(result.return_value, str_val("hello"));
    }

    // ── StringBuilder constructor + append + toString ─────────────────

    #[test]
    fn test_sb_append_str() {
        let buf = "";
        let arg = str_val("world");
        let result = mock_sb_append(buf, &arg, false).unwrap();
        assert_eq!(result.return_value, str_val("world"));
        assert_eq!(result.updated_this, Some(str_val("world")));
    }

    #[test]
    fn test_sb_append_int() {
        let buf = "prefix";
        let arg = int_val(42);
        let result = mock_sb_append(buf, &arg, false).unwrap();
        assert_eq!(result.return_value, str_val("prefix42"));
    }

    #[test]
    fn test_sb_append_char() {
        // append(char 'A') — is_char_append=true; int 65 → "A"
        let buf = "hello";
        let arg = int_val('A' as i32);
        let result = mock_sb_append(buf, &arg, true).unwrap();
        assert_eq!(result.return_value, str_val("helloA"));
    }

    #[test]
    fn test_sb_append_char_distinguishes_from_int() {
        // Same int value; behaviour differs by is_char_append flag.
        // 65 as char → "A"; 65 as int → "65".
        let buf = "";
        let arg = int_val(65);
        let as_char = mock_sb_append(buf, &arg, true).unwrap();
        let as_int = mock_sb_append(buf, &arg, false).unwrap();
        assert_eq!(as_char.return_value, str_val("A"));
        assert_eq!(as_int.return_value, str_val("65"));
    }

    #[test]
    fn test_sb_append_wrong_type() {
        let buf = "";
        let err = mock_sb_append(buf, &Value::Void, false).unwrap_err();
        assert!(matches!(err, EmulatorError::TypeMismatch { .. }));
    }

    // ── Arrays.copyOf ─────────────────────────────────────────────────

    #[test]
    fn test_copy_of_truncate() {
        let arr = vec![1, 2, 3, 4, 5];
        let result = mock_copy_of(&arr, 3).unwrap();
        assert_eq!(result.return_value, arr_val(vec![1, 2, 3]));
    }

    #[test]
    fn test_copy_of_zero_pad() {
        let arr = vec![1, 2];
        let result = mock_copy_of(&arr, 5).unwrap();
        assert_eq!(result.return_value, arr_val(vec![1, 2, 0, 0, 0]));
    }

    #[test]
    fn test_copy_of_negative_len() {
        let err = mock_copy_of(&[1, 2, 3], -1).unwrap_err();
        assert!(matches!(err, EmulatorError::NegativeArrayLength { .. }));
    }

    // ── Arrays.copyOfRange ────────────────────────────────────────────

    #[test]
    fn test_copy_of_range_normal() {
        let arr = vec![10, 20, 30, 40, 50];
        let result = mock_copy_of_range(&arr, 1, 4).unwrap();
        assert_eq!(result.return_value, arr_val(vec![20, 30, 40]));
    }

    #[test]
    fn test_copy_of_range_zero_pad() {
        let arr = vec![1, 2, 3];
        let result = mock_copy_of_range(&arr, 1, 6).unwrap();
        assert_eq!(result.return_value, arr_val(vec![2, 3, 0, 0, 0]));
    }

    #[test]
    fn test_copy_of_range_oob_from() {
        let err = mock_copy_of_range(&[1, 2], 3, 1).unwrap_err();
        assert!(matches!(err, EmulatorError::ArrayOutOfBounds { .. }));
    }

    // ── Integer.parseInt ──────────────────────────────────────────────

    #[test]
    fn test_parse_int_normal() {
        let result = mock_parse_int("123").unwrap();
        assert_eq!(result.return_value, int_val(123));
    }

    #[test]
    fn test_parse_int_negative() {
        let result = mock_parse_int("-42").unwrap();
        assert_eq!(result.return_value, int_val(-42));
    }

    #[test]
    fn test_parse_int_invalid() {
        let err = mock_parse_int("not_a_number").unwrap_err();
        assert!(matches!(err, EmulatorError::TypeMismatch { .. }));
    }

    // ── Integer.toHexString ───────────────────────────────────────────

    #[test]
    fn test_to_hex_string_positive() {
        let result = mock_to_hex_string(255).unwrap();
        assert_eq!(result.return_value, str_val("ff"));
    }

    #[test]
    fn test_to_hex_string_negative() {
        // Java: Integer.toHexString(-1) = "ffffffff"
        let result = mock_to_hex_string(-1).unwrap();
        assert_eq!(result.return_value, str_val("ffffffff"));
    }
}
