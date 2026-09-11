# axmldecoder

[![Crates.io](https://img.shields.io/crates/v/axmldecoder?style=flat-square)](https://crates.io/crates/axmldecoder)

Decoder for the binary XML format used by Android.

This library implements the minimal amount of parsing required obtain
useful information from a binary `AndroidManifest.xml`. It does not
support parsing generic binary XML documents and does not have
support for decoding resource identifiers. In return, the compiled
footprint of the library is _much_ lighter as it does not have to
link in Android's `resources.arsc` file.

For a full-featured Rust binary XML parser,
[abxml-rs](https://github.com/SUPERAndroidAnalyzer/abxml-rs)
is highly recommended if it is acceptable to link a 30MB `resources.arsc`
file into your compiled binary.

Please file an issue with the relevant binary `AndroidManifest.xml` if
if any issues are encountered.
