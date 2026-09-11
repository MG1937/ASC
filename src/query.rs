//! The search query model shared by the CLI and the scanners.
//!
//! `cli` builds these values from command-line arguments; `apk` and `dex` consume
//! them. Keeping the model in its own module means the analysis layers never have
//! to depend on the argument-parsing layer.

use anyhow::{Result, bail};

/// What a `findrefs` invocation looks for.
#[derive(Clone, Debug)]
pub enum Query {
    String(String),
    Type(String),
    Method(MemberQuery),
    Field(MemberQuery),
}

/// A member query: at least one of a member name or a class constraint.
#[derive(Clone, Debug)]
pub struct MemberQuery {
    pub name: Option<String>,
    pub class: Option<ClassQuery>,
}

/// How a member query constrains the defining class.
#[derive(Clone, Debug)]
pub enum ClassQuery {
    /// A full `Lpkg/Name;` descriptor.
    Exact(String),
    /// A literal substring of the descriptor, in `pkg/Name` form.
    Fuzzy(String),
}

/// Normalizes a class name to the `Lpkg/Name;` descriptor form that `findrefs`
/// and `getclass` compare against the DEX tables.
///
/// Accepts dotted Java names, descriptors with or without their `L`/`;`
/// delimiters, and rejects the empty name.
pub fn format_class_name(name: &str) -> Result<String> {
    if name.is_empty() {
        bail!("Class name cannot be empty");
    }
    // A name that already looks like a descriptor is used as written, but only when
    // its slashes are there too: `Lcom.foo.Main;` still needs its dots normalised.
    // This mirrors the reference implementation exactly.
    if name.starts_with('L') && name.ends_with(';') && name.contains('/') {
        return Ok(name.to_owned());
    }
    let mut name = name.replace('.', "/");
    if !name.starts_with('L') {
        name.insert(0, 'L');
    }
    if !name.ends_with(';') {
        name.push(';');
    }
    Ok(name)
}

/// Normalizes a fuzzy class pattern by treating dots as package separators.
///
/// The reference implementation only replaces dots when the pattern has no slashes,
/// but that rule exists for its regex matcher, where a dot is a wildcard and
/// `com.example/Main` therefore matches `com/example/Main` by accident. rasc matches
/// literally, so leaving such a pattern alone would match nothing; replacing the dots
/// gives the same rows the reference reports for those inputs.
pub fn fuzzy_class_pattern(pattern: &str) -> String {
    pattern.replace('.', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every case here was read off the reference implementation's
    /// `_format_class_name` / `_normalize_class_query`.
    #[test]
    fn normalizes_class_names_like_the_reference() {
        for (input, expected) in [
            ("com.foo.Main", "Lcom/foo/Main;"),
            ("Lcom/foo/Main;", "Lcom/foo/Main;"),
            ("Lcom.foo.Main;", "Lcom/foo/Main;"),
            ("LMain;", "LMain;"),
            ("com/foo/Main", "Lcom/foo/Main;"),
            ("Main", "LMain;"),
            ("Lcom/foo/Main", "Lcom/foo/Main;"),
            ("com.foo.Main$Inner", "Lcom/foo/Main$Inner;"),
            ("Lcom/foo/Main$Inner;", "Lcom/foo/Main$Inner;"),
            ("I", "LI;"),
            ("[Lcom/foo/Main;", "L[Lcom/foo/Main;"),
            ("java.lang.String", "Ljava/lang/String;"),
            ("Lfoo.bar", "Lfoo/bar;"),
            ("foo.bar;", "Lfoo/bar;"),
        ] {
            assert_eq!(format_class_name(input).unwrap(), expected, "{input:?}");
        }
        assert!(format_class_name("").is_err());
    }

    #[test]
    fn normalizes_fuzzy_class_patterns_like_the_reference() {
        for (input, expected) in [
            ("com.foo", "com/foo"),
            ("com/foo", "com/foo"),
            ("com.foo/bar", "com/foo/bar"),
            ("com/foo.bar", "com/foo/bar"),
            ("Main", "Main"),
            ("", ""),
            ("Lcom/foo/Main;", "Lcom/foo/Main;"),
        ] {
            assert_eq!(fuzzy_class_pattern(input), expected, "{input:?}");
        }
    }
}
