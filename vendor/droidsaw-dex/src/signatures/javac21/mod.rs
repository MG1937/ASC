//! javac 21 lowering recognizers.
//!
//! Each submodule holds one [`Signature`](droidsaw_common::signature::Signature)
//! impl matching one canonical lowering produced by `javac 21`. Submodules
//! are added as #4 (`dex-signatures-javac21`) lands per-construct
//! recognizers.
//!
//! Currently:
//!
//! - [`switch_string`] — `switch (String) { case "lit": ... }` lowered by
//!   javac to a two-pass `hashCode + equals + dense-index switch` shape.
//! - [`switch_int`] — `switch (int)` covering both `tableswitch`
//!   (dense) and `lookupswitch` (sparse) bytecode shapes; lifts to
//!   `Stmt::MultiArm` with `Discriminant::Int`. Supersedes the
//!   pre-consolidation `switch_int_dense` + `switch_int_sparse`
//!   (one signature where two would do).
//! - [`string_concat_indy`] — `"a" + x + "b"` lowered by javac 9+ to
//!   `invokedynamic StringConcatFactory.makeConcatWithConstants`;
//!   lifts to existing `Stmt::StringConcat`.

pub mod string_concat_indy;
pub mod switch_int;
pub mod switch_string;
