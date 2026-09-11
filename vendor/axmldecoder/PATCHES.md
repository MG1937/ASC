# rasc patches to axmldecoder 0.5.0

This is a vendored copy of `axmldecoder 0.5.0` (MIT OR Apache-2.0) with the changes below,
all marked `PATCHED (rasc)` in the source:

1. `src/stringpool.rs` - `parse_utf16_string` implemented the extended two-byte length
   form instead of `unimplemented!()`, which panicked on strings of 32768 units or more.
2. `src/stringpool.rs` - `parse_utf8_string` implemented the two-byte length forms for
   both the UTF-16 length and the byte length instead of `unimplemented!()`, which
   panicked on any string whose byte length is 128 or more. A real APK in the test
   corpus (a repacked Douyin build) has such a manifest, and the original Python
   implementation decodes it, so rasc could not report that manifest at all.
3. `src/xml.rs` - an end element without a matching start element returns a parse error
   instead of unwrapping an empty stack.
4. `src/xml.rs` - character data (CDATA) outside any element returns a parse error
   instead of unwrapping an empty element stack; a crafted manifest whose only node
   is a CDATA reached that unwrap and aborted the process.
5. `src/binaryxml.rs` - `ResourceValue::get_value` formats typed values the way Android
   tooling and the original Python implementation do (resource references as `@…`,
   framework ids with the `android:` prefix, signed integers, `0x%08X` hex, `%f` floats,
   dimensions and fractions through the packed mantissa/radix/unit fields, colours as
   `#AARRGGBB`, booleans, and Androguard's `<0x.., type 0x..>` fallback) instead of
   stringifying the raw data. `ResourceValueType` gained `Clone, Copy` so the type can be
   passed by value.

Everything else is upstream. `rasc` still validates the chunk skeleton before calling
the decoder (see `src/manifest.rs`), so the remaining `unwrap`s are unreachable for
input rasc accepts.

6. `src/binaryxml.rs` - `ResourceValue` keeps the raw type byte and `format_value` dispatches
   through `ResourceValueType::from_raw`, so typed values whose type is not one of the named
   ones (0x07/0x08 dynamic references and attributes, anything >= 0x20) render with the
   `<0x.., type 0x..>` fallback instead of failing the whole document. Before this, a single
   unlisted type byte made `rasc manifest` fail on that APK.
7. `src/binaryxml.rs` - `RADIX_MULTS` keeps the exact powers of two (2^-8, 2^-15, 2^-23,
   2^-31). Androguard rounds them to seven digits, which shifts a large mantissa in the
   sixth decimal (fraction mantissa 16384, radix 1: `50.000003%` there, `50.000000%` here).
   The exact value is the correct one, so the divergence is deliberate.
8. `src/binaryxml.rs` - the four AOSP colour types 0x1C-0x1F share one `Color` variant, while
   the reserved types 0x13-0x1B deliberately stay on the fallback (Androguard prints them as
   decimals because its integer branch spans 0x10-0x1F, but AOSP reserves them).
