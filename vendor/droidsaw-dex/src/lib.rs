// SPDX-License-Identifier: BSD-3-Clause

//! droidsaw-dex — DEX (Dalvik Executable) bytecode parser and decompiler.
//!
//! Parses the DEX file format, provides cross-reference analysis,
//! class/method enumeration, SSA-based decompilation, and Smali disassembly.

// Kani 0.67.0 uses a modified rustc 1.93.0-nightly (2025-11-20) that has not
// yet picked up the `if_let_guard` stabilization from Rust 1.95.0 (April 2026).
// `parser.rs` uses `if let` guards in match arms (match-arm `if let` guards —
// not `if let` chains — stabilized in 1.95.0, NOT 1.88.0). Gate this feature
// explicitly for Kani builds only — it has no effect on stable/nightly host
// builds where the feature is unconditionally available. Retained even though
// no `proofs/` modules currently exist in this crate, so that workspace-wide
// `cargo kani` invocations don't fail to compile `droidsaw-dex` during the
// Kani-build pass.
#![cfg_attr(kani, feature(if_let_guard))]

#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::disallowed_types)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::todo,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::let_underscore_future,
        clippy::await_holding_lock,
        clippy::await_holding_refcell_ref,
        clippy::if_let_mutex,
        clippy::large_futures,
        clippy::as_underscore,
        clippy::unused_result_ok,
        clippy::let_underscore_must_use,
        clippy::map_err_ignore,
        clippy::allow_attributes_without_reason,
        clippy::cast_lossless,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        clippy::cast_precision_loss,
        clippy::cast_possible_wrap,
        // as_conversions promoted to deny at crate root (matches hermes
        // discipline). 519 non-test sites across 28 src/ files. Landing
        // pattern:
        //   - ≤5-site files (12 files, 20 sites total): per-site
        //     `#[allow(clippy::as_conversions, reason = "PROOF: ...")]`.
        //   - 5-30-site files (11 files, 165 sites): file-level
        //     `#![cfg_attr(not(test), allow(clippy::as_conversions,
        //     reason = "PROOF (bulk allow, N sites): ..."))]` with
        //     cluster-signal PROOF text identifying the cast taxonomy
        //     for the file. Per-site refinement deferred.
        //   - >30-site files (5 files, 334 sites): same as 5-30 bucket;
        //     bulk allow with PROOF, per-site refinement deferred.
        // Structural gauge: crate-root deny catches new `as` casts in
        // files that don't yet have a file-level allow; existing files
        // are covered by per-site or bulk PROOF.
        clippy::as_conversions,
    )
)]
#![warn(missing_docs)]
#![warn(unreachable_pub)]

pub mod access_flags;
pub mod annotation;
pub mod api;
pub mod cfg;
pub mod dex_string;
#[cfg(any(test, kani, fuzzing))]
pub mod cfg_oracle;
#[cfg(any(test, kani, fuzzing))]
pub mod parser_oracle;
pub mod emulator;
pub mod classes;
pub mod debug;
pub mod decode;
pub mod diag;
pub mod emit;
pub mod emit_dex;
pub mod error;
pub mod header;
pub mod ids;
pub mod mutf8;
pub mod obfuscation_features;
pub mod opcodes;
pub mod optimize;
pub mod parser;
pub mod r8_identity;
pub mod r8_inversion;
pub mod sdk_inventory;
pub mod signatures;
pub mod smali;
pub mod spr;
pub mod ssa;
pub mod static_field_lookup;
pub mod structure;
pub mod sugar;
pub mod types;
pub mod xrefs;

pub use api::{ClassSummary, DetectorVerdict, MethodSummary};
pub use dex_string::DexString;
pub use error::DexError;
pub use parser::DexFile;
pub use xrefs::{method_key_for_idx, CallSite, FieldKey, InvokeKind, MethodKey, Xrefs};

// Kani proofs for MUTF-8 decode identity are not yet added: the String-returning
// outer API causes CBMC heap explosion; the inner decode_one_codepoint function
// would need to be exposed first. The header cross-validation proof (data_off +
// data_size <= file_len) has no production site to anchor to yet.

// Debug-info register-bound proofs (4 sub-proofs over `narrow_register`).
// Anti-smuggling regression for the `register as u16` truncation closed
// by `parse_debug_info(.., registers_size, ..)`. Module is `cfg(kani)`-
// gated and invisible to normal builds / tests / clippy.
#[cfg(kani)]
#[path = "../proofs/debug_register_bound.rs"]
mod proof_debug_register_bound;

// Canonical-header gauge proofs (2 sub-proofs over `DexHeader::parse`).
// Anti-audit-mute regression for the missing `header_size == 0x70` check
// at parse-time. Module is `cfg(kani)`-gated and invisible to normal
// builds / tests / clippy.
#[cfg(kani)]
#[path = "../proofs/header_size_gauge.rs"]
mod proof_header_size_gauge;

// Access-flag spec-union proofs (6 sub-proofs × 3 scopes over
// `access_flags::validate`). Anti-IR-incoherence + roundtrip-break
// regression for the out-of-mask access_flags bits the ungated parser
// would accept. Module is `cfg(kani)`-gated and invisible to normal
// builds / tests / clippy.
#[cfg(kani)]
#[path = "../proofs/access_flags_spec_union.rs"]
mod proof_access_flags_spec_union;

// Encoded-value value_arg size-bound proofs (12 sub-proofs over
// `annotation::check_value_arg_size`, covering 11 affected primitive
// tags plus the previously-correct VALUE_FLOAT migrated to the shared
// helper). Anti-silent-truncation regression guard
// for `as i8` / `as u16` / `as u32` narrowing casts at 11 match arms
// in `decode_primitive_encoded_value` that broke parser→emit
// roundtrip-byte-equality. Module is `cfg(kani)`-gated and invisible
// to normal builds / tests / clippy.
#[cfg(kani)]
#[path = "../proofs/encoded_value_value_arg_bound.rs"]
mod proof_encoded_value_value_arg_bound;

// AnnotationDirectoryItem sum-of-counts allocation-cap proofs (3 sub-
// proofs over `AnnotationDirectoryItem::parse`). Anti-OOM regression
// for the unchecked sum `fields_size + methods_size + parameters_size`
// that could drive ~3× the input length in `Vec::with_capacity`
// allocator pressure without this cap. Module is `cfg(kani)`-gated and
// invisible to normal builds / tests / clippy.
#[cfg(kani)]
#[path = "../proofs/annotation_directory_cap.rs"]
mod proof_annotation_directory_cap;

// class_def offset parse-time bound proofs (4 sub-proofs over
// `parser::validate_class_def_off`). Anti-deferred-Err regression
// for the 4 class_def offset fields (interfaces_off / annotations_off
// / class_data_off / static_values_off) that the ungated parser
// would accept as raw u32; downstream consumers bounds-check on read,
// which defers audit attribution. Module is `cfg(kani)`-gated and
// invisible to normal
// builds / tests / clippy.
#[cfg(kani)]
#[path = "../proofs/class_def_off_bound.rs"]
mod proof_class_def_off_bound;

// Empty-try-region structural-invariant proofs (2 sub-proofs over
// `CodeItemInvariantViolation::EmptyTryRegion`). Anti-audit-spoof
// regression for `try_item.insn_count == 0` that the ungated parser
// would accept — inflating audit try-region counters without covering
// any control flow. Module is `cfg(kani)`-gated and invisible to
// normal builds /
// tests / clippy.
#[cfg(kani)]
#[path = "../proofs/try_item_start_addr.rs"]
mod proof_try_item_start_addr;

// Companion to header_size_gauge.rs: fences off the byte-swapped
// `0x78563412` REVERSE_ENDIAN_CONSTANT (rejected by ART itself) and
// every other non-canonical endian-tag value. Asserts the typed
// DexError::BadEndianTag variant (split off from UnsupportedVersion
// in this arc to escape the format!/std::fmt::write CBMC pathology).
#[cfg(kani)]
#[path = "../proofs/endian_tag_gauge.rs"]
mod proof_endian_tag_gauge;

// F11n 4-bit signed-literal sign-extension correctness via
// subtraction-form arithmetic oracle. Closes a class-of-typo that the
// lint floor's `allow(cast_possible_wrap)` admits but cannot prove.
#[cfg(kani)]
#[path = "../proofs/sign_extend_4bit.rs"]
mod proof_sign_extend_4bit;
