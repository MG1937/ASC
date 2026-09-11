//!Decoder for the binary XML format used by Android.
//!
//!This library implements the minimal amount of parsing required obtain
//!useful information from a binary `AndroidManifest.xml`. It does not
//!support parsing generic binary XML documents and does not have
//!support for decoding resource identifiers. In return, the compiled
//!footprint of the library is _much_ lighter as it does not have to
//!link in Android's `resources.arsc` file.
//!
//!For a full-featured Rust binary XML parser,
//![abxml-rs](https://github.com/SUPERAndroidAnalyzer/abxml-rs)
//!is highly recommended if it is acceptable to link a 30MB `resources.arsc`
//!file into your compiled binary.
//!
//!Please file an issue with the relevant binary `AndroidManifest.xml` if
//!if any issues are encountered.

mod binaryxml;
mod stringpool;
mod xml;

use thiserror::Error;

use crate::binaryxml::BinaryXmlDocument;
pub use crate::xml::{Cdata, Element, Node, XmlDocument};

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("parse error: {0}")]
    DekuError(deku::DekuError),

    #[error("StringPool missing index: {0}")]
    StringNotFound(u32),

    #[error("ResourceMap missing index: {0}")]
    ResourceIdNotFound(u32),

    #[error("Unknown resource string: {0}")]
    UnknownResourceString(u32),

    #[error(transparent)]
    Utf8StringParseError(std::string::FromUtf8Error),

    #[error(transparent)]
    Utf16StringParseError(std::string::FromUtf16Error),
}

///Parses an Android binary XML and returns a [`XmlDocument`] object.
///
/// # Errors
///
/// Will return `ParseError` if `input` cannot be parsed
///```rust
///use axmldecoder::parse;
///# use axmldecoder::ParseError;
///let data= include_bytes!("../examples/AndroidManifest.xml");
///parse(data)?;
///# Ok::<(), ParseError>(())
///```
pub fn parse(input: &[u8]) -> Result<XmlDocument, ParseError> {
    let binaryxml = BinaryXmlDocument::try_from(input).map_err(ParseError::DekuError)?;
    XmlDocument::new(binaryxml)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn test_parse() {
        let mut examples = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        examples.push("examples");

        for entry in std::fs::read_dir(examples).unwrap() {
            let entry = entry.unwrap();
            let mut f = File::open(entry.path()).unwrap();
            let mut buf = Vec::new();
            f.read_to_end(&mut buf).unwrap();
            parse(&buf).unwrap_or_else(|_| panic!("{} failed to parse", entry.path().display()));
        }
    }
}
