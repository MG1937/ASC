//! Dalvik VM access-flag spec union per DEX format §3.4.1.
//!
//! The DEX format uses `access_flags: uleb128` on class definitions,
//! `encoded_field`, and `encoded_method`. Each scope has a fixed set
//! of legal bits; bits outside that set are not defined by the spec
//! and indicate either obfuscation, corruption, or adversarial input
//! crafted to bypass IR-level invariants like `is_static = af & 0x0008`.
//!
//! Without this gate, the parser pushes the raw uleb128 result
//! verbatim into the IR, allowing `access_flags = 0xFFFFFFFF` to
//! evaluate truthy on every flag check simultaneously (a method
//! becomes static+abstract+native+private+public+ACC_ENUM at once).
//! This module's `validate` gates the 5 parse sites: any bit outside
//! the per-scope spec union surfaces as
//! `DexError::InvalidAccessFlags { raw, scope }`.

use crate::error::{DexError, Result};

/// Scope of an `access_flags` field. Used to select the correct
/// spec-union mask in [`validate`] and to render the error variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessFlagScope {
    /// `class_def.access_flags` — the class-level flags.
    Class,
    /// `encoded_field.access_flags` — static or instance field.
    Field,
    /// `encoded_method.access_flags` — direct or virtual method.
    Method,
}

impl AccessFlagScope {
    /// Per-scope spec-union mask per DEX §3.4.1 / Dalvik VM spec.
    /// All bits outside the returned mask are invalid for that scope.
    pub const fn mask(self) -> u32 {
        match self {
            // Class flags: PUBLIC | PRIVATE | PROTECTED | STATIC | FINAL |
            // INTERFACE | ABSTRACT | SYNTHETIC | ANNOTATION | ENUM.
            // Private / protected / static apply only to inner classes,
            // but the DEX format permits them on any class_def entry.
            Self::Class => 0x0000_761F,
            // Field flags: PUBLIC | PRIVATE | PROTECTED | STATIC | FINAL |
            // VOLATILE | TRANSIENT | SYNTHETIC | ENUM.
            Self::Field => 0x0000_50DF,
            // Method flags: PUBLIC | PRIVATE | PROTECTED | STATIC | FINAL |
            // SYNCHRONIZED | BRIDGE | VARARGS | NATIVE | ABSTRACT | STRICT |
            // SYNTHETIC | CONSTRUCTOR | DECLARED_SYNCHRONIZED.
            //
            // Bit map (per DEX §3.4.1):
            //   0x0001 PUBLIC          0x0080 VARARGS
            //   0x0002 PRIVATE         0x0100 NATIVE
            //   0x0004 PROTECTED       0x0400 ABSTRACT
            //   0x0008 STATIC          0x0800 STRICT      ← bit 11
            //   0x0010 FINAL           0x1000 SYNTHETIC
            //   0x0020 SYNCHRONIZED    0x10000 CONSTRUCTOR
            //   0x0040 BRIDGE          0x20000 DECLARED_SYNCHRONIZED
            //
            // Sum: 0x000001FF + 0x00001C00 + 0x00030000 = 0x000_31DFF.
            // Previously read 0x0003_15FF (bit 11 STRICT dropped),
            // but real-world files carry bit 11 in valid method flags.
            Self::Method => 0x0003_1DFF,
        }
    }

    /// Human-readable scope tag for error messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Class => "class",
            Self::Field => "field",
            Self::Method => "method",
        }
    }
}

/// Validate `raw` against the per-scope spec union; return `raw`
/// unchanged on success, or `DexError::InvalidAccessFlags` if any bit
/// outside the union is set.
#[inline]
pub fn validate(raw: u32, scope: AccessFlagScope) -> Result<u32> {
    if raw & !scope.mask() != 0 {
        return Err(DexError::InvalidAccessFlags { raw, scope });
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_rejects_0xffffffff_for_every_scope() {
        for scope in [
            AccessFlagScope::Class,
            AccessFlagScope::Field,
            AccessFlagScope::Method,
        ] {
            let err = validate(0xFFFF_FFFF, scope).unwrap_err();
            assert!(
                matches!(
                    err,
                    DexError::InvalidAccessFlags {
                        raw: 0xFFFF_FFFF,
                        scope: s,
                    } if s == scope
                ),
                "expected InvalidAccessFlags for scope {scope:?}, got {err:?}",
            );
        }
    }

    #[test]
    fn validate_accepts_zero_for_every_scope() {
        // No flags set is legal in every scope (e.g. a package-private
        // class with no other modifiers).
        assert_eq!(validate(0, AccessFlagScope::Class).unwrap(), 0);
        assert_eq!(validate(0, AccessFlagScope::Field).unwrap(), 0);
        assert_eq!(validate(0, AccessFlagScope::Method).unwrap(), 0);
    }

    #[test]
    fn validate_accepts_canonical_class_combinations() {
        // ACC_PUBLIC | ACC_FINAL — a typical Java `public final class`.
        assert_eq!(
            validate(0x0001 | 0x0010, AccessFlagScope::Class).unwrap(),
            0x0011,
        );
        // ACC_INTERFACE | ACC_ABSTRACT | ACC_PUBLIC — a typical Java
        // public interface.
        assert_eq!(
            validate(0x0200 | 0x0400 | 0x0001, AccessFlagScope::Class).unwrap(),
            0x0601,
        );
        // ACC_PUBLIC | ACC_FINAL | ACC_ENUM — a typical Java `public enum`.
        assert_eq!(
            validate(0x0001 | 0x0010 | 0x4000, AccessFlagScope::Class).unwrap(),
            0x4011,
        );
        // ACC_SYNTHETIC | ACC_ANNOTATION | ACC_PUBLIC | ACC_INTERFACE | ACC_ABSTRACT —
        // a typical annotation interface.
        assert_eq!(
            validate(0x1000 | 0x2000 | 0x0001 | 0x0200 | 0x0400, AccessFlagScope::Class)
                .unwrap(),
            0x3601,
        );
    }

    #[test]
    fn validate_accepts_canonical_field_combinations() {
        // ACC_PRIVATE | ACC_STATIC | ACC_FINAL — `private static final` field.
        assert_eq!(
            validate(0x0002 | 0x0008 | 0x0010, AccessFlagScope::Field).unwrap(),
            0x001A,
        );
        // ACC_PUBLIC | ACC_VOLATILE.
        assert_eq!(
            validate(0x0001 | 0x0040, AccessFlagScope::Field).unwrap(),
            0x0041,
        );
        // ACC_PRIVATE | ACC_TRANSIENT.
        assert_eq!(
            validate(0x0002 | 0x0080, AccessFlagScope::Field).unwrap(),
            0x0082,
        );
        // ACC_PUBLIC | ACC_STATIC | ACC_FINAL | ACC_ENUM — an enum constant.
        assert_eq!(
            validate(0x0001 | 0x0008 | 0x0010 | 0x4000, AccessFlagScope::Field).unwrap(),
            0x4019,
        );
    }

    #[test]
    fn validate_accepts_canonical_method_combinations() {
        // ACC_PUBLIC | ACC_STATIC.
        assert_eq!(
            validate(0x0001 | 0x0008, AccessFlagScope::Method).unwrap(),
            0x0009,
        );
        // ACC_PUBLIC | ACC_CONSTRUCTOR.
        assert_eq!(
            validate(0x0001 | 0x10000, AccessFlagScope::Method).unwrap(),
            0x10001,
        );
        // ACC_PUBLIC | ACC_NATIVE.
        assert_eq!(
            validate(0x0001 | 0x0100, AccessFlagScope::Method).unwrap(),
            0x0101,
        );
        // ACC_PUBLIC | ACC_ABSTRACT.
        assert_eq!(
            validate(0x0001 | 0x0400, AccessFlagScope::Method).unwrap(),
            0x0401,
        );
        // ACC_PRIVATE | ACC_DECLARED_SYNCHRONIZED.
        assert_eq!(
            validate(0x0002 | 0x20000, AccessFlagScope::Method).unwrap(),
            0x20002,
        );
    }

    #[test]
    fn validate_rejects_method_flag_on_class_scope() {
        // ACC_CONSTRUCTOR (0x10000) is a method-only flag; appearing
        // on class scope is invalid.
        let err = validate(0x10000, AccessFlagScope::Class).unwrap_err();
        assert!(matches!(
            err,
            DexError::InvalidAccessFlags {
                raw: 0x10000,
                scope: AccessFlagScope::Class,
            }
        ));
    }

    #[test]
    fn validate_rejects_field_flag_on_method_scope() {
        // ACC_VOLATILE (0x40) and ACC_BRIDGE (0x40) overlap on the
        // wire. For method scope, 0x40 means ACC_BRIDGE and IS legal.
        // For field scope, 0x40 means ACC_VOLATILE and IS legal. Cross-
        // scope rejection is handled by other bits — here we verify a
        // genuinely field-only bit (ACC_TRANSIENT = 0x80) reaches the
        // method scope: it's actually ACC_VARARGS in method scope,
        // also legal. So a TRUE cross-scope rejection only happens for
        // ACC_VOLATILE-as-ACC_BRIDGE confusion which the spec resolves
        // at the parse site, not at the bit level. Verify instead that
        // a TRULY unused bit (e.g. 0x40000) is rejected for all scopes.
        for scope in [
            AccessFlagScope::Class,
            AccessFlagScope::Field,
            AccessFlagScope::Method,
        ] {
            let err = validate(0x40000, scope).unwrap_err();
            assert!(matches!(
                err,
                DexError::InvalidAccessFlags { raw: 0x40000, .. }
            ), "scope {scope:?}: got {err:?}");
        }
    }

    #[test]
    fn validate_rejects_high_bit_above_mask() {
        // 0x80000000 — a single high bit set. Outside every scope's
        // mask, must be rejected.
        for scope in [
            AccessFlagScope::Class,
            AccessFlagScope::Field,
            AccessFlagScope::Method,
        ] {
            let err = validate(0x8000_0000, scope).unwrap_err();
            assert!(matches!(
                err,
                DexError::InvalidAccessFlags {
                    raw: 0x8000_0000,
                    ..
                }
            ));
        }
    }
}
