//! Decompiler output language definitions for Ghidra Rust.
//!
//! Direct translation of `ghidra.program.model.lang.DecompilerLanguage`.
//!
//! Provides the [`DecompilerLanguage`] enum representing the source languages
//! that can be output by the decompiler.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Source languages that can be output by the decompiler.
///
/// Corresponds to `ghidra.program.model.lang.DecompilerLanguage`.
///
/// The decompiler can produce output in C-like syntax or Java-like syntax.
/// This enum identifies which output format is in use.
///
/// # Examples
///
/// ```
/// use ghidra_core::program::decompiler_lang::DecompilerLanguage;
///
/// let lang = DecompilerLanguage::C;
/// assert_eq!(lang.to_option_string(), "c-language");
/// assert_eq!(lang.to_string(), "C");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecompilerLanguage {
    /// C-like decompiler output (the default and most common).
    C,
    /// Java-like decompiler output.
    Java,
}

impl DecompilerLanguage {
    /// Returns the option string used in Ghidra configuration.
    ///
    /// Corresponds to `DecompilerLanguage.toString()` in Java.
    pub fn to_option_string(&self) -> &'static str {
        match self {
            DecompilerLanguage::C => "c-language",
            DecompilerLanguage::Java => "java-language",
        }
    }

    /// Parse a decompiler language from its option string.
    ///
    /// Returns `None` for unrecognized strings.
    pub fn from_option_string(s: &str) -> Option<Self> {
        match s {
            "c-language" => Some(DecompilerLanguage::C),
            "java-language" => Some(DecompilerLanguage::Java),
            _ => None,
        }
    }

    /// Returns the file extension typically associated with this language.
    pub fn file_extension(&self) -> &'static str {
        match self {
            DecompilerLanguage::C => "c",
            DecompilerLanguage::Java => "java",
        }
    }

    /// Returns all available decompiler languages.
    pub fn all() -> &'static [DecompilerLanguage] {
        &[DecompilerLanguage::C, DecompilerLanguage::Java]
    }
}

impl fmt::Display for DecompilerLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecompilerLanguage::C => write!(f, "C"),
            DecompilerLanguage::Java => write!(f, "Java"),
        }
    }
}

impl Default for DecompilerLanguage {
    /// The default decompiler language is C.
    fn default() -> Self {
        DecompilerLanguage::C
    }
}

impl From<&str> for DecompilerLanguage {
    /// Parse from an option string. Defaults to C for unrecognized values.
    fn from(s: &str) -> Self {
        Self::from_option_string(s).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_option_string() {
        assert_eq!(DecompilerLanguage::C.to_option_string(), "c-language");
        assert_eq!(DecompilerLanguage::Java.to_option_string(), "java-language");
    }

    #[test]
    fn test_from_option_string() {
        assert_eq!(
            DecompilerLanguage::from_option_string("c-language"),
            Some(DecompilerLanguage::C)
        );
        assert_eq!(
            DecompilerLanguage::from_option_string("java-language"),
            Some(DecompilerLanguage::Java)
        );
        assert_eq!(DecompilerLanguage::from_option_string("unknown"), None);
    }

    #[test]
    fn test_file_extension() {
        assert_eq!(DecompilerLanguage::C.file_extension(), "c");
        assert_eq!(DecompilerLanguage::Java.file_extension(), "java");
    }

    #[test]
    fn test_all() {
        assert_eq!(DecompilerLanguage::all().len(), 2);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", DecompilerLanguage::C), "C");
        assert_eq!(format!("{}", DecompilerLanguage::Java), "Java");
    }

    #[test]
    fn test_default() {
        assert_eq!(DecompilerLanguage::default(), DecompilerLanguage::C);
    }

    #[test]
    fn test_from_str() {
        let c: DecompilerLanguage = "c-language".into();
        assert_eq!(c, DecompilerLanguage::C);

        let j: DecompilerLanguage = "java-language".into();
        assert_eq!(j, DecompilerLanguage::Java);

        let d: DecompilerLanguage = "unknown".into();
        assert_eq!(d, DecompilerLanguage::C); // defaults to C
    }

    #[test]
    fn test_roundtrip() {
        for lang in DecompilerLanguage::all() {
            let s = lang.to_option_string();
            let parsed = DecompilerLanguage::from_option_string(s).unwrap();
            assert_eq!(*lang, parsed);
        }
    }
}
