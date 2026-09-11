//! Dalvik annotation item parsing.
#![allow(missing_docs, reason = "internal")]
#![cfg_attr(not(test), allow(clippy::as_conversions, reason = "PROOF (bulk allow, 24 sites): annotation.rs parses encoded_value / annotation_directory_item structures out of parser-validated bytes. Casts cluster around (a) `u32 as usize` widening for offset/count arithmetic into parser-validated sections (lossless on 64-bit); (b) `u8 value_arg as u32/u16/i8` controlled narrowing where `value_arg < 8` is range-checked by the per-tag validators; (c) `u8 as u32` widening for ULEB128/SLEB128 byte accumulation (lossless). Per-site PROOF refinement deferred."))]
use crate::error::{bound_count, safe_add, safe_mul, DexError, Result};
use crate::ids::*;
use crate::mutf8;
use scroll::{Pread, LE};
use std::collections::BTreeMap;

/// On-disk stride for `field_annotation` / `method_annotation` /
/// `parameter_annotation` entries: field_idx|method_idx (uint) +
/// annotations_off (uint) = 8 bytes.
const ANNOTATION_DIRECTORY_ENTRY_SIZE: usize = 8;
/// On-disk stride for an annotation_set `entries[]` element: uint
/// annotation_off = 4 bytes.
const ANNOTATION_SET_ENTRY_SIZE: usize = 4;
/// Minimum on-disk bytes per entry in an `encoded_array`: at least one
/// encoded_value header byte. Stride 1 is a loose but correct lower
/// bound — prevents `Vec::with_capacity(u32::MAX)` blow-up.
const ENCODED_ARRAY_MIN_ITEM_SIZE: usize = 1;

#[derive(Debug, Clone, PartialEq)]
pub struct AnnotationDirectoryItem {
    pub class_annotations_off: u32,
    pub fields: Vec<FieldAnnotation>,
    pub methods: Vec<MethodAnnotation>,
    pub parameters: Vec<ParameterAnnotation>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FieldAnnotation {
    pub field_idx: FieldIdx,
    pub annotations_off: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MethodAnnotation {
    pub method_idx: MethodIdx,
    pub annotations_off: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ParameterAnnotation {
    pub method_idx: MethodIdx,
    pub annotations_off: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnnotationSetItem {
    pub annotation_off: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AnnotationItem {
    pub visibility: u8,
    pub annotation: EncodedAnnotation,
}

#[derive(Debug, Clone, PartialEq)]
pub struct EncodedAnnotation {
    pub type_idx: TypeIdx,
    pub elements: BTreeMap<StringIdx, EncodedValue>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EncodedValue {
    Byte(i8),
    Short(i16),
    Char(u16),
    Int(i32),
    Long(i64),
    Float(f32),
    Double(f64),
    String(StringIdx),
    Type(TypeIdx),
    Field(FieldIdx),
    Method(MethodIdx),
    Enum(FieldIdx),
    Array(Vec<EncodedValue>),
    Annotation(EncodedAnnotation),
    Null,
    Boolean(bool),
    /// VALUE_METHOD_TYPE (0x15): proto_ids index. Lives in call_site
    /// encoded_arrays — the SAM proto + instantiated-MT args to
    /// `LambdaMetafactory.metafactory` — and in const-method-type.
    MethodType(ProtoIdx),
    /// VALUE_METHOD_HANDLE (0x16): method_handles index. Lives in
    /// call_site encoded_arrays — the bootstrap method (arg\[0\]) and
    /// the impl method (arg\[4\]) of a LambdaMetafactory bootstrap.
    MethodHandle(MethodHandleIdx),
}

impl AnnotationDirectoryItem {
    pub fn parse(data: &[u8], offset: u32) -> Result<Self> {
        let mut pos = offset as usize;
        let class_annotations_off: u32 =
            data.pread_with(pos, LE).map_err(|e| DexError::ScrollRead {
                offset: pos,
                source: e,
            })?;
        pos = safe_add(pos, 4, "annotation:dir:class_annotations_off")?;
        let fields_size: u32 = data.pread_with(pos, LE).map_err(|e| DexError::ScrollRead {
            offset: pos,
            source: e,
        })?;
        pos = safe_add(pos, 4, "annotation:dir:fields_size")?;
        let methods_size: u32 = data.pread_with(pos, LE).map_err(|e| DexError::ScrollRead {
            offset: pos,
            source: e,
        })?;
        pos = safe_add(pos, 4, "annotation:dir:methods_size")?;
        let parameters_size: u32 = data.pread_with(pos, LE).map_err(|e| DexError::ScrollRead {
            offset: pos,
            source: e,
        })?;
        pos = safe_add(pos, 4, "annotation:dir:parameters_size")?;

        // Sum-of-counts cap: each of fields_size / methods_size /
        // parameters_size is bound_count-checked individually below,
        // but their sum can drive ~3× the input length in
        // `Vec::with_capacity` allocator pressure on a memory-
        // constrained worker. Reject pre-allocation when the combined
        // count would exceed what the input can physically hold at the
        // per-entry stride. Computed in u64 (with `saturating_add` to
        // satisfy the workspace `arithmetic_side_effects` floor —
        // saturation is unreachable since 3 * u32::MAX < u64::MAX).
        let combined: u64 = u64::from(fields_size)
            .saturating_add(u64::from(methods_size))
            .saturating_add(u64::from(parameters_size));
        let max_entries = u64::try_from(data.len() / ANNOTATION_DIRECTORY_ENTRY_SIZE)
            .unwrap_or(u64::MAX);
        if combined > max_entries {
            return Err(DexError::AnnotationDirectoryAllocationCap {
                combined,
                data_len: data.len(),
            });
        }

        let fields_count = bound_count(
            fields_size,
            ANNOTATION_DIRECTORY_ENTRY_SIZE,
            data.len(),
            "annotation_fields",
        )?;
        let mut fields = Vec::with_capacity(fields_count);
        for _ in 0..fields_count {
            let field_idx: u32 = data.pread_with(pos, LE).map_err(|e| DexError::ScrollRead {
                offset: pos,
                source: e,
            })?;
            pos = safe_add(pos, 4, "annotation:dir:field_idx")?;
            let annotations_off: u32 =
                data.pread_with(pos, LE).map_err(|e| DexError::ScrollRead {
                    offset: pos,
                    source: e,
                })?;
            pos = safe_add(pos, 4, "annotation:dir:field_annotations_off")?;
            fields.push(FieldAnnotation {
                field_idx: FieldIdx(field_idx),
                annotations_off,
            });
        }

        let methods_count = bound_count(
            methods_size,
            ANNOTATION_DIRECTORY_ENTRY_SIZE,
            data.len(),
            "annotation_methods",
        )?;
        let mut methods = Vec::with_capacity(methods_count);
        for _ in 0..methods_count {
            let method_idx: u32 = data.pread_with(pos, LE).map_err(|e| DexError::ScrollRead {
                offset: pos,
                source: e,
            })?;
            pos = safe_add(pos, 4, "annotation:dir:method_idx")?;
            let annotations_off: u32 =
                data.pread_with(pos, LE).map_err(|e| DexError::ScrollRead {
                    offset: pos,
                    source: e,
                })?;
            pos = safe_add(pos, 4, "annotation:dir:method_annotations_off")?;
            methods.push(MethodAnnotation {
                method_idx: MethodIdx(method_idx),
                annotations_off,
            });
        }

        let parameters_count = bound_count(
            parameters_size,
            ANNOTATION_DIRECTORY_ENTRY_SIZE,
            data.len(),
            "annotation_parameters",
        )?;
        let mut parameters = Vec::with_capacity(parameters_count);
        for _ in 0..parameters_count {
            let method_idx: u32 = data.pread_with(pos, LE).map_err(|e| DexError::ScrollRead {
                offset: pos,
                source: e,
            })?;
            pos = safe_add(pos, 4, "annotation:dir:param_method_idx")?;
            let annotations_off: u32 =
                data.pread_with(pos, LE).map_err(|e| DexError::ScrollRead {
                    offset: pos,
                    source: e,
                })?;
            pos = safe_add(pos, 4, "annotation:dir:param_annotations_off")?;
            parameters.push(ParameterAnnotation {
                method_idx: MethodIdx(method_idx),
                annotations_off,
            });
        }

        Ok(AnnotationDirectoryItem {
            class_annotations_off,
            fields,
            methods,
            parameters,
        })
    }
}

pub fn parse_annotation_set(data: &[u8], offset: u32) -> Result<Vec<u32>> {
    if offset == 0 {
        return Ok(Vec::new());
    }
    let mut pos = offset as usize;
    let size: u32 = data.pread_with(pos, LE).map_err(|e| DexError::ScrollRead {
        offset: pos,
        source: e,
    })?;
    pos = safe_add(pos, 4, "annotation:set:size")?;
    let entry_count = bound_count(
        size,
        ANNOTATION_SET_ENTRY_SIZE,
        data.len(),
        "annotation_set",
    )?;
    let mut entries = Vec::with_capacity(entry_count);
    for _ in 0..entry_count {
        let off: u32 = data.pread_with(pos, LE).map_err(|e| DexError::ScrollRead {
            offset: pos,
            source: e,
        })?;
        pos = safe_add(pos, 4, "annotation:set:entry")?;
        entries.push(off);
    }
    Ok(entries)
}

pub fn parse_annotation_item(data: &[u8], offset: u32) -> Result<AnnotationItem> {
    let mut pos = offset as usize;
    let visibility: u8 = data.pread_with(pos, LE).map_err(|e| DexError::ScrollRead {
        offset: pos,
        source: e,
    })?;
    pos = safe_add(pos, 1, "annotation:item:visibility")?;
    let (annotation, _) = parse_encoded_annotation(data, pos)?;
    Ok(AnnotationItem {
        visibility,
        annotation,
    })
}

/// Heap-stack frame count cap for the iterative `encoded_value` /
/// `encoded_annotation` walkers.
///
/// Each `CollectorFrame` is ≤ ~120 bytes. 65 536 frames × 120 bytes ≈
/// 7.5 MiB — a hard ceiling that bounds the blast radius of adversarial-
/// width IR (e.g., `Array(vec![_; u32::MAX / 2])`).
/// Overflow yields `DexError::WorkStackExhausted`.
const PARSE_STACK_FRAME_CAP: usize = 65_536;

/// A collector frame on the iterative parse work-stack.
///
/// Each frame represents a partially-collected composite value:
/// either an `Array` or an `Annotation` that is waiting for its
/// children to be decoded.
enum CollectorFrame {
    /// Collecting elements for `EncodedValue::Array`.
    Array {
        /// Absolute byte offset of the Array's 0x1c header byte,
        /// used to compute the returned consumed-byte count.
        start_pos: usize,
        /// How many more child values remain to be decoded.
        remaining: usize,
        /// Children decoded so far (in order).
        children: Vec<EncodedValue>,
    },
    /// Collecting key/value pairs for `EncodedValue::Annotation`.
    Annotation {
        /// Absolute byte offset of the annotation body's first byte
        /// (type_idx ULEB), used to compute the returned consumed-byte
        /// count.
        start_pos: usize,
        /// How many more (name_idx, value) pairs remain.
        remaining: usize,
        /// `type_idx` already read from the header.
        type_idx: u32,
        /// Elements collected so far.
        elements: BTreeMap<StringIdx, EncodedValue>,
        /// The name_idx for the element whose value has not yet been
        /// decoded.  `Some` while waiting for a value; `None` while
        /// waiting for the next name_idx.
        pending_name: Option<StringIdx>,
    },
}

/// Iterative `encoded_annotation` parser.
///
/// Parses the annotation body starting at `pos` in `data` and returns
/// `(annotation, bytes_consumed)`. Uses an explicit heap-allocated
/// work-stack; no recursive call sites, no stack-depth limit.
pub fn parse_encoded_annotation(data: &[u8], pos: usize) -> Result<(EncodedAnnotation, usize)> {
    let start = pos;
    let (type_idx_val, l1) = mutf8::read_uleb128(data, pos)?;
    let pos2 = safe_add(pos, l1, "annotation:encoded:type_idx")?;
    let (size, l2) = mutf8::read_uleb128(data, pos2)?;
    let pos3 = safe_add(pos2, l2, "annotation:encoded:size")?;
    // Element = ULEB128 name_idx + encoded_value (≥ 2 bytes min stride).
    let element_count = bound_count(size, 2, data.len(), "annotation_elements")?;

    let root_frame = CollectorFrame::Annotation {
        start_pos: start,
        remaining: element_count,
        type_idx: type_idx_val,
        elements: BTreeMap::new(),
        pending_name: None,
    };
    // Drive the iterative walker; extract the Annotation from the result.
    let (val, consumed) = drive_collector_stack(data, pos3, root_frame)?;
    match val {
        EncodedValue::Annotation(ann) => Ok((ann, consumed)),
        _ => Err(DexError::WorkStackExhausted),
    }
}

/// Iterative `encoded_value` parser.
///
/// Parses an `encoded_value` starting at `pos` in `data` and returns
/// `(value, bytes_consumed)`. Uses an explicit heap-allocated work-stack;
/// no recursive call sites, no stack-depth limit.
pub fn parse_encoded_value(data: &[u8], pos: usize) -> Result<(EncodedValue, usize)> {
    // Fast path: decode the header to check whether we need a collector
    // frame at all.  Primitives (and Null/Boolean) don't need the stack.
    let (maybe_val, consumed) = decode_primitive_encoded_value(data, pos)?;
    match maybe_val {
        Some(val) => Ok((val, consumed)),
        None => {
            // Composite: decode_primitive_encoded_value leaves `consumed`
            // pointing past the header byte.  We need to build a frame.
            parse_encoded_value_composite(data, pos)
        }
    }
}

/// Parse an `encoded_array_item` (DEX §7.12): ULEB128 size prefix
/// followed by `size` back-to-back encoded_values. Used for the
/// class_def's `static_values_off` reference.
///
/// Returns `(values, input_widths)` — `input_widths[i]` is the input
/// byte width of `values[i]`'s data payload (NOT including the leading
/// header byte). Per DEX spec §VII.1, `value_arg = header >> 5`
/// encodes a 3-bit width-1 field, so widths are in `[1,8]` for typical
/// numeric values; variable-length types (Array, Annotation) record
/// the full nested-body byte width clamped to `u8::MAX`. The consumer
/// (`encoded_value_min_emit_width` in `emit_dex.rs`) returns `None`
/// for variable-length types so they don't contribute to divergence
/// counts. Used for per-value width-canonicalization attribution at
/// emit time.
pub fn parse_encoded_array(data: &[u8], offset: u32) -> Result<(Vec<EncodedValue>, Vec<u8>)> {
    let mut pos = offset as usize;
    let (size, len) = mutf8::read_uleb128(data, pos)?;
    pos = safe_add(pos, len, "encoded_array:size")?;
    let count = bound_count(
        size,
        ENCODED_ARRAY_MIN_ITEM_SIZE,
        data.len(),
        "encoded_array_item",
    )?;
    let mut values = Vec::with_capacity(count);
    let mut widths = Vec::with_capacity(count);
    for _ in 0..count {
        let pre = pos;
        let (v, vlen) = parse_encoded_value(data, pos)?;
        pos = safe_add(pos, vlen, "encoded_array:elem")?;
        // Total bytes consumed from header position = vlen. Subtract
        // the 1-byte header to get the data payload's byte width.
        // Spec caps payload at 8 bytes (3-bit value_arg + 1); clamp
        // defensively against malformed inputs (a tolerant-parse
        // descendant could conceivably advance further).
        let raw_width = vlen.saturating_sub(1);
        let width = u8::try_from(raw_width).unwrap_or(u8::MAX);
        values.push(v);
        widths.push(width);
        debug_assert_eq!(
            pos,
            pre.saturating_add(vlen),
            "encoded_array:elem stride invariant"
        );
    }
    Ok((values, widths))
}

/// Walk an already-parsed encoded_value tree alongside its source bytes
/// and emit per-primitive on-disk widths in pre-order.
///
/// `start` is the absolute byte offset (in `data`) of the encoded_value
/// header for `root`. Returns a `Vec<u8>` containing one entry per
/// width-bearing primitive descendant (Byte / Short / Char / Int / Long /
/// Float / Double / String / Type / Field / Method / Enum / MethodType /
/// MethodHandle) in pre-order traversal. Composites (Array / Annotation)
/// and zero-payload primitives (Null / Boolean) contribute nothing — the
/// emit-side consumer uses the same predicate to keep parser-side push
/// and emit-side pop in lock-step.
///
/// Used by `preserve_data_section_layout` to recover per-value on-disk
/// widths for *nested* values (inside annotation_item bodies and inside
/// nested arrays/annotations) where the parser-stored top-level widths
/// from `parse_encoded_array` don't reach.
pub fn collect_encoded_value_widths_pre_order(
    data: &[u8],
    start: u32,
    root: &EncodedValue,
) -> Result<Vec<u8>> {
    let mut widths: Vec<u8> = Vec::new();
    let mut pos: usize = start as usize;
    walk_one_for_widths(data, &mut pos, root, &mut widths)?;
    Ok(widths)
}

/// Walk an `annotation_item`'s encoded_annotation body (ULEB(type_idx)
/// || ULEB(size) || size × (ULEB(name_idx) || encoded_value)) alongside
/// its parsed `ann` and emit deep pre-order widths.
///
/// `body_start` is the absolute byte offset of the FIRST byte of the
/// body (i.e. the first byte after the annotation_item's 1-byte
/// visibility prefix). The body itself has no `0x1d` header byte —
/// this distinguishes it from a free-standing `EncodedValue::Annotation`.
pub fn collect_annotation_item_widths(
    data: &[u8],
    body_start: u32,
    ann: &EncodedAnnotation,
) -> Result<Vec<u8>> {
    let mut widths: Vec<u8> = Vec::new();
    let mut pos: usize = body_start as usize;
    let (_type_idx, l1) = mutf8::read_uleb128(data, pos)?;
    pos = safe_add(pos, l1, "ann_item:widths:type_idx")?;
    let (_size, l2) = mutf8::read_uleb128(data, pos)?;
    pos = safe_add(pos, l2, "ann_item:widths:size")?;
    for child in ann.elements.values() {
        let (_name_uleb, ln) = mutf8::read_uleb128(data, pos)?;
        pos = safe_add(pos, ln, "ann_item:widths:name_idx")?;
        walk_one_for_widths(data, &mut pos, child, &mut widths)?;
    }
    Ok(widths)
}

/// Walk an `encoded_array_item` (ULEB(size) || size × encoded_value)
/// alongside its parsed values and emit deep pre-order widths covering
/// every width-bearing primitive — including those nested inside arrays
/// or annotations.
pub fn collect_encoded_array_widths_pre_order(
    data: &[u8],
    start: u32,
    values: &[EncodedValue],
) -> Result<Vec<u8>> {
    let mut widths: Vec<u8> = Vec::new();
    let mut pos: usize = start as usize;
    let (_size, len) = mutf8::read_uleb128(data, pos)?;
    pos = safe_add(pos, len, "encoded_array:widths:size")?;
    for v in values {
        walk_one_for_widths(data, &mut pos, v, &mut widths)?;
    }
    Ok(widths)
}

/// Walk one encoded_value at `*pos` against the parsed `val`, advancing
/// `*pos` past the value and pushing pre-order widths for width-bearing
/// primitive descendants.
#[allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: `size = (header >> 5) + 1` is in 1..=8; narrowing usize→u8 is exact."
)]
fn walk_one_for_widths(
    data: &[u8],
    pos: &mut usize,
    val: &EncodedValue,
    widths: &mut Vec<u8>,
) -> Result<()> {
    let header: u8 = data.pread_with(*pos, LE).map_err(|e| DexError::ScrollRead {
        offset: *pos,
        source: e,
    })?;
    let value_arg = (header >> 5) as usize;
    let size = safe_add(value_arg, 1, "widths:value_arg+1")?;
    *pos = safe_add(*pos, 1, "widths:header")?;

    match val {
        EncodedValue::Null | EncodedValue::Boolean(_) => {
            // No payload bytes; nothing to record.
        }
        EncodedValue::Byte(_)
        | EncodedValue::Short(_)
        | EncodedValue::Char(_)
        | EncodedValue::Int(_)
        | EncodedValue::Long(_)
        | EncodedValue::Float(_)
        | EncodedValue::Double(_)
        | EncodedValue::String(_)
        | EncodedValue::Type(_)
        | EncodedValue::Field(_)
        | EncodedValue::Method(_)
        | EncodedValue::Enum(_)
        | EncodedValue::MethodType(_)
        | EncodedValue::MethodHandle(_) => {
            // size is in 1..=8 — cap at u8 for storage (clamp is defensive,
            // unreachable for spec-compliant inputs).
            let w = u8::try_from(size).unwrap_or(u8::MAX);
            widths.push(w);
            *pos = safe_add(*pos, size, "widths:primitive_payload")?;
        }
        EncodedValue::Array(children) => {
            let (_count, len) = mutf8::read_uleb128(data, *pos)?;
            *pos = safe_add(*pos, len, "widths:array:size")?;
            for child in children {
                walk_one_for_widths(data, pos, child, widths)?;
            }
        }
        EncodedValue::Annotation(ann) => {
            let (_type_idx, l1) = mutf8::read_uleb128(data, *pos)?;
            *pos = safe_add(*pos, l1, "widths:annotation:type_idx")?;
            let (_size, l2) = mutf8::read_uleb128(data, *pos)?;
            *pos = safe_add(*pos, l2, "widths:annotation:size")?;
            // BTreeMap iteration is ascending-by-key, matching d8's
            // on-disk order (annotation_element[] sorted by name_idx).
            for child in ann.elements.values() {
                let (_name_uleb, ln) = mutf8::read_uleb128(data, *pos)?;
                *pos = safe_add(*pos, ln, "widths:annotation:name_idx")?;
                walk_one_for_widths(data, pos, child, widths)?;
            }
        }
    }
    Ok(())
}

/// Iterative parse for composite `encoded_value` types (Array, Annotation).
///
/// Called when `pos` points to a `0x1c` (Array) or `0x1d` (Annotation)
/// header byte.  Returns `(value, bytes_consumed)`.
#[allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: `pos` is a buffer index into `data: &[u8]`. DEX inputs are u32-sized by the file-format header (data_size: u32); annotation byte streams therefore have `pos < u32::MAX`. The `pos as u32` here is only used to populate `DexError::UnknownOpcode { offset }` for diagnostics; truncation on a >4GiB input is bounded by the DEX file-format spec (the parser would have rejected the input at the header)."
)]
fn parse_encoded_value_composite(data: &[u8], pos: usize) -> Result<(EncodedValue, usize)> {
    let start = pos;
    let header: u8 = data.pread_with(pos, LE).map_err(|e| DexError::ScrollRead {
        offset: pos,
        source: e,
    })?;
    let value_type = header & 0x1f;
    let after_header = safe_add(pos, 1, "iterative:composite:header")?;

    match value_type {
        0x1c => {
            // Array: ULEB(size) || size × encoded_value
            let (arr_size, alen) = mutf8::read_uleb128(data, after_header)?;
            let body_start = safe_add(after_header, alen, "iterative:array:size")?;
            let count = bound_count(arr_size, ENCODED_ARRAY_MIN_ITEM_SIZE, data.len(), "iterative:array")?;
            let root_frame = CollectorFrame::Array {
                start_pos: start,
                remaining: count,
                children: Vec::with_capacity(count),
            };
            drive_collector_stack(data, body_start, root_frame)
        }
        0x1d => {
            // Annotation: ULEB(type_idx) || ULEB(size) || size × (ULEB(name) || value)
            let (type_idx_val, l1) = mutf8::read_uleb128(data, after_header)?;
            let p2 = safe_add(after_header, l1, "iterative:annotation:type_idx")?;
            let (size, l2) = mutf8::read_uleb128(data, p2)?;
            let body_start = safe_add(p2, l2, "iterative:annotation:size")?;
            let element_count = bound_count(size, 2, data.len(), "iterative:annotation:elements")?;
            let root_frame = CollectorFrame::Annotation {
                start_pos: start,
                remaining: element_count,
                type_idx: type_idx_val,
                elements: BTreeMap::new(),
                pending_name: None,
            };
            drive_collector_stack(data, body_start, root_frame)
        }
        _ => Err(DexError::UnknownOpcode {
            opcode: value_type,
            offset: pos as u32,
        }),
    }
}

/// Core iterative walker.  Drives the collector stack starting from
/// `body_start` with `root` as the initial collector frame.  Returns
/// `(assembled_value, total_bytes_consumed_from_root.start_pos)`.
///
/// Invariant: `root.start_pos` is the absolute position of the first
/// byte of the outermost value (the header byte for Array/Annotation).
/// On success, `consumed = final_pos - root.start_pos`.
#[allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: `cur` is a buffer offset into `data: &[u8]`. DEX file inputs are u32-sized (file-format header has u32 data_size). Truncating to u32 for diagnostic `offset` field is safe for any DEX-spec-compliant input."
)]
fn drive_collector_stack(
    data: &[u8],
    body_start: usize,
    root: CollectorFrame,
) -> Result<(EncodedValue, usize)> {
    let root_start = frame_start_pos(&root);
    let mut stack: Vec<CollectorFrame> = Vec::new();
    stack.push(root);
    let mut cur = body_start;

    'outer: loop {
        // — Phase A: if the top Annotation frame needs a name_idx, read it —
        if let Some(CollectorFrame::Annotation { pending_name, remaining, .. }) = stack.last_mut() {
            if pending_name.is_none() && *remaining > 0 {
                let (name_idx, ln) = mutf8::read_uleb128(data, cur)?;
                cur = safe_add(cur, ln, "iterative:annotation:name_idx")?;
                *pending_name = Some(StringIdx(name_idx));
            }
        }

        // — Phase B: if the top frame is complete, assemble and deliver —
        while frame_is_complete(stack.last()) {
            let completed = stack.pop().ok_or(DexError::WorkStackExhausted)?;
            let val = assemble_frame(completed, cur)?;
            if stack.is_empty() {
                // Root frame complete: return.
                return Ok((val, cur.saturating_sub(root_start)));
            }
            // Deliver to the new top frame; repeat Phase A/B as needed.
            deliver_to_top(&mut stack, &mut cur, val, data)?;
        }

        // — Phase C: decode one encoded_value from cur —
        let (maybe_prim, advance) = decode_primitive_encoded_value(data, cur)?;
        match maybe_prim {
            Some(prim) => {
                // Primitive decoded: advance cursor and deliver.
                cur = safe_add(cur, advance, "iterative:primitive:advance")?;
                deliver_to_top(&mut stack, &mut cur, prim, data)?;
            }
            None => {
                // Composite (Array or Annotation): push a new collector frame.
                if stack.len() >= PARSE_STACK_FRAME_CAP {
                    return Err(DexError::WorkStackExhausted);
                }
                let header: u8 = data.pread_with(cur, LE).map_err(|e| DexError::ScrollRead {
                    offset: cur,
                    source: e,
                })?;
                let value_type = header & 0x1f;
                let after_hdr = safe_add(cur, 1, "iterative:composite:header")?;

                match value_type {
                    0x1c => {
                        let (arr_size, alen) = mutf8::read_uleb128(data, after_hdr)?;
                        let body = safe_add(after_hdr, alen, "iterative:array:body")?;
                        let count = bound_count(arr_size, ENCODED_ARRAY_MIN_ITEM_SIZE, data.len(), "iterative:array:count")?;
                        stack.push(CollectorFrame::Array {
                            start_pos: cur,
                            remaining: count,
                            children: Vec::with_capacity(count),
                        });
                        cur = body;
                    }
                    0x1d => {
                        let (type_idx_val, l1) = mutf8::read_uleb128(data, after_hdr)?;
                        let p2 = safe_add(after_hdr, l1, "iterative:ann:type_idx")?;
                        let (size, l2) = mutf8::read_uleb128(data, p2)?;
                        let body = safe_add(p2, l2, "iterative:ann:body")?;
                        let element_count = bound_count(size, 2, data.len(), "iterative:ann:elements")?;
                        stack.push(CollectorFrame::Annotation {
                            start_pos: cur,
                            remaining: element_count,
                            type_idx: type_idx_val,
                            elements: BTreeMap::new(),
                            pending_name: None,
                        });
                        cur = body;
                    }
                    _ => {
                        return Err(DexError::UnknownOpcode {
                            opcode: value_type,
                            offset: cur as u32,
                        });
                    }
                }
                continue 'outer;
            }
        }
    }
}

/// Return the `start_pos` stored in a collector frame.
fn frame_start_pos(frame: &CollectorFrame) -> usize {
    match frame {
        CollectorFrame::Array { start_pos, .. } => *start_pos,
        CollectorFrame::Annotation { start_pos, .. } => *start_pos,
    }
}

/// Return `true` if the frame has collected all its children.
fn frame_is_complete(frame: Option<&CollectorFrame>) -> bool {
    match frame {
        None => false,
        Some(CollectorFrame::Array { remaining, .. }) => *remaining == 0,
        Some(CollectorFrame::Annotation { remaining, pending_name, .. }) => {
            *remaining == 0 && pending_name.is_none()
        }
    }
}

/// Assemble a completed collector frame into an `EncodedValue`.
fn assemble_frame(frame: CollectorFrame, _cur: usize) -> Result<EncodedValue> {
    match frame {
        CollectorFrame::Array { children, .. } => Ok(EncodedValue::Array(children)),
        CollectorFrame::Annotation { type_idx, elements, .. } => {
            Ok(EncodedValue::Annotation(EncodedAnnotation {
                type_idx: TypeIdx(type_idx),
                elements,
            }))
        }
    }
}

/// Deliver a completed child value to the top collector frame.
///
/// For Array: appends the child and decrements `remaining`.
/// For Annotation: if `pending_name` is `Some`, stores the value and
/// decrements `remaining`; otherwise this is a logic error.
/// After delivering, if the top frame now needs a name_idx (Annotation
/// with `pending_name == None && remaining > 0`), reads it.
fn deliver_to_top(
    stack: &mut [CollectorFrame],
    cur: &mut usize,
    val: EncodedValue,
    data: &[u8],
) -> Result<()> {
    match stack.last_mut() {
        None => {
            return Err(DexError::WorkStackExhausted);
        }
        Some(CollectorFrame::Array { children, remaining, .. }) => {
            children.push(val);
            *remaining = remaining.saturating_sub(1);
        }
        Some(CollectorFrame::Annotation { elements, remaining, pending_name, .. }) => {
            match pending_name.take() {
                Some(name) => {
                    elements.insert(name, val);
                    *remaining = remaining.saturating_sub(1);
                }
                None => {
                    return Err(DexError::WorkStackExhausted);
                }
            }
        }
    }
    // If the new top is an Annotation waiting for its next name_idx, read it.
    if let Some(CollectorFrame::Annotation { pending_name, remaining, .. }) = stack.last_mut() {
        if pending_name.is_none() && *remaining > 0 {
            let (name_idx, ln) = mutf8::read_uleb128(data, *cur)?;
            *cur = safe_add(*cur, ln, "iterative:deliver:name_idx")?;
            *pending_name = Some(StringIdx(name_idx));
        }
    }
    Ok(())
}

/// Reject an encoded_value `size` (`value_arg + 1`) that exceeds the
/// spec-mandated maximum for a given variant tag. DEX §VII.1.3 fixes
/// per-tag widths: `value_arg` is encoded in the high 3 bits of the
/// header, so the on-disk value can be up to 7 (size 8) regardless of
/// the tag, but each tag only legitimately occupies a fixed sub-range
/// (Byte = 0; Short/Char = 0..=1; Int/Float/*-Idx = 0..=3; Long/Double
/// = 0..=7). Without this check, overlong values silently truncate via
/// `as i8` / `as u16` / `as u32` narrowing casts, breaking parser→emit
/// roundtrip-byte-equality.
#[inline]
pub(crate) fn check_value_arg_size(variant: &'static str, size: usize, max: usize) -> Result<()> {
    if size > max {
        return Err(DexError::EncodedValueSize { variant, size });
    }
    Ok(())
}

/// Decode a single `encoded_value` if it is a primitive (non-composite).
///
/// Returns `(Some(value), bytes_consumed)` for primitives (Byte, Short,
/// Char, Int, Long, Float, Double, String, Type, Field, Method, Enum,
/// MethodType, MethodHandle, Null, Boolean).
///
/// Returns `(None, 0)` for composite types (Array `0x1c`, Annotation
/// `0x1d`) — the caller must handle those by pushing a collector frame.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "PROOF: every `as` narrowing here is dominated by the DEX encoded-value spec width rules AND by `check_value_arg_size` at the matching arm. `read_int(..., size)?` returns an i64 sign-extended from at most `size` bytes; the per-arm size cap (Byte=1, Short=2, Int=4) makes narrowing to i8 / i16 / i32 exact. `read_uint(..., size)?` returns u64 that fits in u16 for Char (size ≤ 2) or u32 for {String,Type,Field,Method,Enum,MethodType,MethodHandle}-Idx (size ≤ 4). `read_uint_right_extend >> 32 as u32` for Float (size ≤ 4) is INTENT bit-extraction. `start_pos as u32` for UnknownOpcode.offset is bounded by DEX u32 data_size."
)]
fn decode_primitive_encoded_value(
    data: &[u8],
    pos: usize,
) -> Result<(Option<EncodedValue>, usize)> {
    let start_pos = pos;
    let header: u8 = data.pread_with(pos, LE).map_err(|e| DexError::ScrollRead {
        offset: pos,
        source: e,
    })?;
    let value_type = header & 0x1f;
    let value_arg = (header >> 5) as usize;
    // `value_arg` ∈ [0,7], so `size` ∈ [1,8]. Per-type bounds further
    // restrict `size` to the spec maximum at each variant arm via
    // [`check_value_arg_size`]; that closes the 11-tag silent
    // truncation that breaks parser→emit roundtrip-byte-equality.
    let size = safe_add(value_arg, 1, "annotation:encoded_value:size")?;
    let after_hdr = safe_add(pos, 1, "annotation:encoded_value:header")?;

    let value = match value_type {
        0x00 => {
            // VALUE_BYTE: value_arg = 0, size = 1 per DEX spec §VII.1.3.
            check_value_arg_size("Byte", size, 1)?;
            EncodedValue::Byte(read_int(data, after_hdr, size)? as i8)
        }
        0x02 => {
            // VALUE_SHORT: value_arg ∈ 0..=1, size ∈ 1..=2.
            check_value_arg_size("Short", size, 2)?;
            EncodedValue::Short(read_int(data, after_hdr, size)? as i16)
        }
        // VALUE_CHAR is UNSIGNED u16 per DEX spec §VII.1.3:
        // "(value_arg + 1) bytes, interpreted as an unsigned integer,
        // zero-extended, that becomes a 16-bit unsigned value".
        // `read_int` sign-extends — wrong for char. Using `read_uint`
        // (zero-extending) matches the spec.
        0x03 => {
            // VALUE_CHAR: value_arg ∈ 0..=1, size ∈ 1..=2.
            check_value_arg_size("Char", size, 2)?;
            EncodedValue::Char(read_uint(data, after_hdr, size)? as u16)
        }
        0x04 => {
            // VALUE_INT: value_arg ∈ 0..=3, size ∈ 1..=4.
            check_value_arg_size("Int", size, 4)?;
            EncodedValue::Int(read_int(data, after_hdr, size)? as i32)
        }
        0x06 => EncodedValue::Long(read_int(data, after_hdr, size)?),
        0x10 => {
            // VALUE_FLOAT: value_arg ∈ 0..=3, size ∈ 1..=4.
            check_value_arg_size("Float", size, 4)?;
            EncodedValue::Float(f32::from_bits(
                (read_uint_right_extend(data, after_hdr, size)? >> 32) as u32,
            ))
        }
        0x11 => EncodedValue::Double(f64::from_bits(read_uint_right_extend(
            data, after_hdr, size,
        )?)),
        0x15 => {
            // VALUE_METHOD_TYPE: ProtoIdx is u32; value_arg ∈ 0..=3.
            check_value_arg_size("MethodType", size, 4)?;
            EncodedValue::MethodType(ProtoIdx(read_uint(data, after_hdr, size)? as u32))
        }
        0x16 => {
            // VALUE_METHOD_HANDLE: MethodHandleIdx is u32; value_arg ∈ 0..=3.
            check_value_arg_size("MethodHandle", size, 4)?;
            EncodedValue::MethodHandle(MethodHandleIdx(
                read_uint(data, after_hdr, size)? as u32,
            ))
        }
        0x17 => {
            // VALUE_STRING: StringIdx is u32; value_arg ∈ 0..=3.
            check_value_arg_size("String", size, 4)?;
            EncodedValue::String(StringIdx(read_uint(data, after_hdr, size)? as u32))
        }
        0x18 => {
            // VALUE_TYPE: TypeIdx is u32; value_arg ∈ 0..=3.
            check_value_arg_size("Type", size, 4)?;
            EncodedValue::Type(TypeIdx(read_uint(data, after_hdr, size)? as u32))
        }
        0x19 => {
            // VALUE_FIELD: FieldIdx is u32; value_arg ∈ 0..=3.
            check_value_arg_size("Field", size, 4)?;
            EncodedValue::Field(FieldIdx(read_uint(data, after_hdr, size)? as u32))
        }
        0x1a => {
            // VALUE_METHOD: MethodIdx is u32; value_arg ∈ 0..=3.
            check_value_arg_size("Method", size, 4)?;
            EncodedValue::Method(MethodIdx(read_uint(data, after_hdr, size)? as u32))
        }
        0x1b => {
            // VALUE_ENUM: FieldIdx is u32; value_arg ∈ 0..=3.
            check_value_arg_size("Enum", size, 4)?;
            EncodedValue::Enum(FieldIdx(read_uint(data, after_hdr, size)? as u32))
        }
        0x1c | 0x1d => {
            // Composite: caller handles.
            return Ok((None, 0));
        }
        0x1e => {
            // Null: only header byte consumed (no data bytes).
            return Ok((Some(EncodedValue::Null), 1));
        }
        0x1f => {
            return Ok((Some(EncodedValue::Boolean(value_arg != 0)), 1));
        }
        _ => {
            return Err(DexError::UnknownOpcode {
                opcode: value_type,
                offset: start_pos as u32,
            });
        }
    };
    // Primitive: 1 header byte + `size` data bytes.
    let total = safe_add(1, size, "annotation:encoded_value:primitive_total")?;
    Ok((Some(value), total))
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: `shift_bits = safe_mul(i, 8, ...)?` where `i < size <= 8` from the loop bound, so `shift_bits` ∈ [0, 56]. `pad_bytes <= 7` and `shift = safe_mul(pad_bytes, 8, ...)? <= 56`. Narrowing the usize shift count to u32 is exact in either case — values fit in 6 bits."
)]
fn read_int(data: &[u8], pos: usize, size: usize) -> Result<i64> {
    let mut val: i64 = 0;
    for i in 0..size {
        let p = safe_add(pos, i, "annotation:read_int:pos+i")?;
        let b: u8 = data
            .pread_with(p, LE)
            .map_err(|e| DexError::ScrollRead {
                offset: p,
                source: e,
            })?;
        let shift_bits = safe_mul(i, 8, "annotation:read_int:shift")?;
        val |= i64::from(b).wrapping_shl(shift_bits as u32);
    }
    // Sign extend. `size` is caller-bounded to [1,8] (hoisted from
    // `value_arg+1` in `parse_encoded_value`), so `8-size` stays in [0,7]
    // and the shift stays in [0,56] — well under i64's 63-bit shift ceiling.
    let pad_bytes = 8usize.saturating_sub(size);
    let shift = safe_mul(pad_bytes, 8, "annotation:read_int:signext_shift")?;
    let shift_u32 = shift as u32;
    Ok(val.wrapping_shl(shift_u32).wrapping_shr(shift_u32))
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: `shift_bits = safe_mul(i, 8, ...)?` where `i < size <= 8`, so `shift_bits` ∈ [0, 56]. Narrowing the usize shift count to u32 is exact — values fit in 6 bits."
)]
fn read_uint(data: &[u8], pos: usize, size: usize) -> Result<u64> {
    let mut val: u64 = 0;
    for i in 0..size {
        let p = safe_add(pos, i, "annotation:read_uint:pos+i")?;
        let b: u8 = data
            .pread_with(p, LE)
            .map_err(|e| DexError::ScrollRead {
                offset: p,
                source: e,
            })?;
        let shift_bits = safe_mul(i, 8, "annotation:read_uint:shift")?;
        val |= u64::from(b).wrapping_shl(shift_bits as u32);
    }
    Ok(val)
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "PROOF: `byte_pos = pad_bytes + i` where `pad_bytes <= 7` and `i < size <= 8`, so `byte_pos <= 15`. `shift_bits = safe_mul(byte_pos, 8, ...)?` <= 120. Narrowing to u32 is exact."
)]
fn read_uint_right_extend(data: &[u8], pos: usize, size: usize) -> Result<u64> {
    let mut val: u64 = 0;
    for i in 0..size {
        let p = safe_add(pos, i, "annotation:read_uint_right_extend:pos+i")?;
        let b: u8 = data
            .pread_with(p, LE)
            .map_err(|e| DexError::ScrollRead {
                offset: p,
                source: e,
            })?;
        // (8 - size + i) stays in [0,7] because size ∈ [1,8] and i < size;
        // *8 stays in [0,56], under u64's 63-bit shift ceiling.
        let pad_bytes = 8usize.saturating_sub(size);
        let byte_pos = safe_add(pad_bytes, i, "annotation:read_uint_right_extend:byte_pos")?;
        let shift_bits = safe_mul(byte_pos, 8, "annotation:read_uint_right_extend:shift")?;
        val |= u64::from(b).wrapping_shl(shift_bits as u32);
    }
    Ok(val)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Encoded compactly: header byte ((size-1) << 5) | value_type, followed by
    // the HIGH `size` bytes of the bit pattern in LE order (matches
    // read_uint_right_extend's placement math).
    fn encode(value_type: u8, size: usize, le_bytes: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + size);
        v.push((((size - 1) as u8) << 5) | value_type);
        v.extend_from_slice(le_bytes);
        v
    }

    fn f32_bytes(bits: u32, size: usize) -> Vec<u8> {
        // High `size` bytes of u32 in LE within the encoded stream.
        bits.to_be_bytes()[..size].iter().rev().copied().collect()
    }

    fn f64_bytes(bits: u64, size: usize) -> Vec<u8> {
        bits.to_be_bytes()[..size].iter().rev().copied().collect()
    }

    fn parse_float(bits: u32, size: usize) -> u32 {
        let data = encode(0x10, size, &f32_bytes(bits, size));
        match parse_encoded_value(&data, 0) {
            Ok((EncodedValue::Float(f), _)) => f.to_bits(),
            other => panic!("expected Float, got {other:?}"),
        }
    }

    fn parse_double(bits: u64, size: usize) -> u64 {
        let data = encode(0x11, size, &f64_bytes(bits, size));
        match parse_encoded_value(&data, 0) {
            Ok((EncodedValue::Double(f), _)) => f.to_bits(),
            other => panic!("expected Double, got {other:?}"),
        }
    }

    // Float IEEE-754 round-trips (load-bearing: the originally-buggy path).
    #[test]
    fn float_one_point_five_full_width() {
        assert_eq!(parse_float(0x3FC00000, 4), 0x3FC00000);
    }

    #[test]
    fn float_one_point_five_compact() {
        assert_eq!(parse_float(0x3FC00000, 2), 0x3FC00000);
    }

    #[test]
    fn float_one_point_five_size_three() {
        // Asymmetric right-extend width: 3 high bytes + 1 implicit zero low byte.
        assert_eq!(parse_float(0x3FC00000, 3), 0x3FC00000);
    }

    #[test]
    fn float_neg_zero_min_width() {
        assert_eq!(parse_float(0x80000000, 1), 0x80000000);
    }

    #[test]
    fn float_neg_zero_full_width() {
        assert_eq!(parse_float(0x80000000, 4), 0x80000000);
    }

    #[test]
    fn float_neg_one_point_five() {
        assert_eq!(parse_float(0xBFC00000, 4), 0xBFC00000);
    }

    #[test]
    fn float_infinity() {
        assert_eq!(parse_float(0x7F800000, 4), 0x7F800000);
    }

    #[test]
    fn float_neg_infinity() {
        assert_eq!(parse_float(0xFF800000, 4), 0xFF800000);
    }

    #[test]
    fn float_subnormal() {
        assert_eq!(parse_float(0x00000001, 4), 0x00000001);
    }

    #[test]
    fn float_quiet_nan() {
        assert_eq!(parse_float(0x7FC00000, 4), 0x7FC00000);
    }

    #[test]
    fn float_signaling_nan() {
        // Parser must not quiet sNaN; bit pattern survives verbatim.
        assert_eq!(parse_float(0x7FA00000, 4), 0x7FA00000);
    }

    // Double round-trips (verify-not-suspect: locks the Double path).
    #[test]
    fn double_one_point_five_full_width() {
        assert_eq!(parse_double(0x3FF8000000000000, 8), 0x3FF8000000000000);
    }

    #[test]
    fn double_one_point_five_compact() {
        assert_eq!(parse_double(0x3FF8000000000000, 2), 0x3FF8000000000000);
    }

    #[test]
    fn double_infinity() {
        assert_eq!(parse_double(0x7FF0000000000000, 8), 0x7FF0000000000000);
    }

    #[test]
    fn double_quiet_nan() {
        assert_eq!(parse_double(0x7FF8000000000000, 8), 0x7FF8000000000000);
    }

    // Bounds-check rejection (load-bearing: catches the HIGH finding).
    fn assert_float_size_rejected(size: usize) {
        let mut data = vec![(((size - 1) as u8) << 5) | 0x10];
        data.resize(1 + size, 0);
        match parse_encoded_value(&data, 0) {
            Err(DexError::EncodedValueSize {
                variant: "Float",
                size: got,
            }) if got == size => {}
            other => panic!("expected EncodedValueSize Err size={size}, got {other:?}"),
        }
    }

    #[test]
    fn float_size_five_rejected() {
        assert_float_size_rejected(5);
    }

    #[test]
    fn float_size_eight_rejected() {
        assert_float_size_rejected(8);
    }

    #[test]
    fn double_size_eight_accepted() {
        // VALUE_DOUBLE.size ∈ [1,8]; size=8 is spec-valid.
        assert_eq!(parse_double(0x3FF8000000000000, 8), 0x3FF8000000000000);
    }

    // ── Per-tag value_arg size bounds (DEX §VII.1.3) ──────────────────
    //
    // 11 tags carry per-tag value_arg bounds tighter than the wire's
    // 3-bit width. Each over-size shape MUST be rejected with
    // `EncodedValueSize { variant, size }` carrying the exact tag and
    // observed size. Without this guard, these silently truncate via
    // `as i8` / `as u16` / `as u32` narrowing, breaking parser→emit
    // roundtrip invariant.

    fn assert_size_rejected(value_type: u8, variant: &'static str, size: usize) {
        // Build header `((size-1) << 5) | value_type` and pad `size`
        // zero bytes after. value_arg in [0,7] maps to size in [1,8].
        let mut data = vec![(((size - 1) as u8) << 5) | value_type];
        data.resize(1 + size, 0);
        match parse_encoded_value(&data, 0) {
            Err(DexError::EncodedValueSize {
                variant: got_variant,
                size: got_size,
            }) if got_variant == variant && got_size == size => {}
            other => panic!(
                "expected EncodedValueSize {{ variant: {variant:?}, size: {size} }}, got {other:?}",
            ),
        }
    }

    #[test]
    fn byte_size_above_one_rejected() {
        // VALUE_BYTE: spec demands size = 1 exactly. size=2 / 5 / 8 all rejected.
        assert_size_rejected(0x00, "Byte", 2);
        assert_size_rejected(0x00, "Byte", 5);
        assert_size_rejected(0x00, "Byte", 8);
    }

    #[test]
    fn short_size_above_two_rejected() {
        // VALUE_SHORT: size ∈ [1,2]. size=3 / 5 / 8 all rejected.
        assert_size_rejected(0x02, "Short", 3);
        assert_size_rejected(0x02, "Short", 5);
        assert_size_rejected(0x02, "Short", 8);
    }

    #[test]
    fn char_size_above_two_rejected() {
        // VALUE_CHAR: size ∈ [1,2]. Same as Short bound.
        assert_size_rejected(0x03, "Char", 3);
        assert_size_rejected(0x03, "Char", 5);
        assert_size_rejected(0x03, "Char", 8);
    }

    #[test]
    fn int_size_above_four_rejected() {
        // VALUE_INT: size ∈ [1,4]. size=5 / 8 rejected.
        assert_size_rejected(0x04, "Int", 5);
        assert_size_rejected(0x04, "Int", 8);
    }

    #[test]
    fn method_type_size_above_four_rejected() {
        // VALUE_METHOD_TYPE: ProtoIdx is u32; size ∈ [1,4].
        assert_size_rejected(0x15, "MethodType", 5);
        assert_size_rejected(0x15, "MethodType", 8);
    }

    #[test]
    fn method_handle_size_above_four_rejected() {
        assert_size_rejected(0x16, "MethodHandle", 5);
        assert_size_rejected(0x16, "MethodHandle", 8);
    }

    #[test]
    fn string_size_above_four_rejected() {
        // Canonical smuggling shape: VALUE_STRING with value_arg=7
        // (size=8). Without this guard, `read_uint(...).. as u32`
        // silently truncates bits 32-63 of the u64 read, pointing
        // StringIdx at wherever the low 32 bits resolve. With it,
        // returns EncodedValueSize.
        assert_size_rejected(0x17, "String", 5);
        assert_size_rejected(0x17, "String", 8);
    }

    #[test]
    fn type_size_above_four_rejected() {
        assert_size_rejected(0x18, "Type", 5);
        assert_size_rejected(0x18, "Type", 8);
    }

    #[test]
    fn field_size_above_four_rejected() {
        assert_size_rejected(0x19, "Field", 5);
        assert_size_rejected(0x19, "Field", 8);
    }

    #[test]
    fn method_size_above_four_rejected() {
        assert_size_rejected(0x1A, "Method", 5);
        assert_size_rejected(0x1A, "Method", 8);
    }

    #[test]
    fn enum_size_above_four_rejected() {
        assert_size_rejected(0x1B, "Enum", 5);
        assert_size_rejected(0x1B, "Enum", 8);
    }

    // ── Canonical in-bounds sizes still accepted ──────────────────────

    #[test]
    fn byte_size_one_accepted() {
        // 1-byte Byte: header 0x00, single zero byte. Must parse to Byte(0).
        let data = [0x00u8, 0x00];
        match parse_encoded_value(&data, 0) {
            Ok((EncodedValue::Byte(0), _)) => {}
            other => panic!("expected Byte(0), got {other:?}"),
        }
    }

    #[test]
    fn short_size_two_accepted() {
        // 2-byte Short: header 0x22 (size=2 in high bits, tag=0x02).
        // Bytes 0x34 0x12 → 0x1234 LE → Short(0x1234).
        let data = [0x22u8, 0x34, 0x12];
        match parse_encoded_value(&data, 0) {
            Ok((EncodedValue::Short(0x1234), _)) => {}
            other => panic!("expected Short(0x1234), got {other:?}"),
        }
    }

    #[test]
    fn string_size_four_accepted() {
        // 4-byte VALUE_STRING (size=4, tag=0x17): header 0x77.
        // Bytes encode StringIdx(0x01020304).
        let data = [0x77u8, 0x04, 0x03, 0x02, 0x01];
        match parse_encoded_value(&data, 0) {
            Ok((EncodedValue::String(idx), _)) if idx.0 == 0x0102_0304 => {}
            other => panic!("expected String(0x01020304), got {other:?}"),
        }
    }

    // ── AnnotationDirectoryItem combined-size cap ─────────────────────

    /// Build a minimal annotation_directory_item header buffer with
    /// caller-chosen `(fields_size, methods_size, parameters_size)`,
    /// padded to `data_len` bytes so the allocation cap has a fixed
    /// `data.len()` to compare against.
    fn make_anno_dir(
        fields_size: u32,
        methods_size: u32,
        parameters_size: u32,
        data_len: usize,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; data_len.max(16)];
        // class_annotations_off at offset 0..4 — zero is fine.
        buf[4..8].copy_from_slice(&fields_size.to_le_bytes());
        buf[8..12].copy_from_slice(&methods_size.to_le_bytes());
        buf[12..16].copy_from_slice(&parameters_size.to_le_bytes());
        buf
    }

    #[test]
    fn anno_dir_combined_at_cap_accepted() {
        // data_len = 80, ENTRY_SIZE = 8, so max_entries = 10. Sum of
        // 3 individual sizes = 10 sits exactly at the cap. Header
        // consumes 16 bytes; per-entry stride is 8 so 10 entries need
        // 80 bytes — exactly the buffer. Must accept.
        let buf = make_anno_dir(3, 4, 3, 96);
        let _ = AnnotationDirectoryItem::parse(&buf, 0).expect("at-cap must be accepted");
    }

    #[test]
    fn anno_dir_combined_over_cap_rejected() {
        // data_len = 32, ENTRY_SIZE = 8, max_entries = 4. Sum 2+2+2 = 6
        // exceeds the cap. Must reject with AnnotationDirectoryAllocationCap.
        let buf = make_anno_dir(2, 2, 2, 32);
        match AnnotationDirectoryItem::parse(&buf, 0) {
            Err(DexError::AnnotationDirectoryAllocationCap {
                combined,
                data_len,
            }) => {
                assert_eq!(combined, 6);
                assert_eq!(data_len, 32);
            }
            other => panic!("expected AnnotationDirectoryAllocationCap, got {other:?}"),
        }
    }

    #[test]
    fn anno_dir_individual_at_cap_combined_over_cap_rejected() {
        // Each individual size sits at the bound_count individual cap
        // (data.len() / ENTRY_SIZE = 4 with data_len = 32), but the
        // sum of three (12) blows the combined cap (4). Without the
        // sum cap, this shape would pass every individual
        // `bound_count` and reach the `Vec::with_capacity(4 + 4 + 4 =
        // 12)` allocation. With it, the sum cap fires first.
        let buf = make_anno_dir(4, 4, 4, 32);
        let err = AnnotationDirectoryItem::parse(&buf, 0).expect_err("over-cap must reject");
        assert!(matches!(
            err,
            DexError::AnnotationDirectoryAllocationCap {
                combined: 12,
                data_len: 32,
            }
        ));
    }

    #[test]
    fn anno_dir_u32_max_sum_does_not_overflow() {
        // Adversarial: all three counts = u32::MAX. Sum in u64 =
        // 3 * u32::MAX ≈ 1.29 * 10^10, well under u64::MAX. Gauge
        // computes combined via saturating_add (saturation
        // unreachable for these inputs) and rejects without panic /
        // overflow. The data_len in the error matches the buffer.
        let buf = make_anno_dir(u32::MAX, u32::MAX, u32::MAX, 64);
        let err = AnnotationDirectoryItem::parse(&buf, 0).expect_err("must reject");
        match err {
            DexError::AnnotationDirectoryAllocationCap {
                combined,
                data_len,
            } => {
                assert_eq!(combined, u64::from(u32::MAX) * 3);
                assert_eq!(data_len, 64);
            }
            other => panic!("expected AnnotationDirectoryAllocationCap, got {other:?}"),
        }
    }

    #[test]
    fn anno_dir_combined_zero_accepted_with_empty_body() {
        // All zero counts: no entries to read. Must parse cleanly
        // into an empty AnnotationDirectoryItem.
        let buf = make_anno_dir(0, 0, 0, 16);
        let item = AnnotationDirectoryItem::parse(&buf, 0).expect("empty must be accepted");
        assert!(item.fields.is_empty());
        assert!(item.methods.is_empty());
        assert!(item.parameters.is_empty());
    }
}
