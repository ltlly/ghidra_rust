//! Unicode script identifiers.
//!
//! Ported from `java.lang.Character.UnicodeScript` -- enumerates the writing
//! systems that a charset can represent. Used by [`CharsetDisplayInfo`] to
//! describe which scripts a given encoding supports.

use std::fmt;

/// Unicode script identifiers.
///
/// Mirrors `java.lang.Character.UnicodeScript`. Each variant represents a
/// distinct writing system or script category recognized by the Unicode standard.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnicodeScript {
    /// Latin script.
    Latin,
    /// Greek script.
    Greek,
    /// Cyrillic script.
    Cyrillic,
    /// Armenian script.
    Armenian,
    /// Hebrew script.
    Hebrew,
    /// Arabic script.
    Arabic,
    /// Devanagari script.
    Devanagari,
    /// Bengali script.
    Bengali,
    /// Thai script.
    Thai,
    /// Han (CJK Unified Ideographs) script.
    Han,
    /// Hiragana script.
    Hiragana,
    /// Katakana script.
    Katakana,
    /// Hangul script.
    Hangul,
    /// CJK ideographs.
    CJK,
    /// Common script (shared across many writing systems).
    Common,
    /// Inherited script.
    Inherited,
    /// Unknown or unrecognized script.
    Unknown,
}

impl fmt::Display for UnicodeScript {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Latin => "LATIN",
            Self::Greek => "GREEK",
            Self::Cyrillic => "CYRILLIC",
            Self::Armenian => "ARMENIAN",
            Self::Hebrew => "HEBREW",
            Self::Arabic => "ARABIC",
            Self::Devanagari => "DEVANAGARI",
            Self::Bengali => "BENGALI",
            Self::Thai => "THAI",
            Self::Han => "HAN",
            Self::Hiragana => "HIRAGANA",
            Self::Katakana => "KATAKANA",
            Self::Hangul => "HANGUL",
            Self::CJK => "CJK",
            Self::Common => "COMMON",
            Self::Inherited => "INHERITED",
            Self::Unknown => "UNKNOWN",
        };
        write!(f, "{}", name)
    }
}

impl UnicodeScript {
    /// Parse a script name string (case-insensitive) into a `UnicodeScript`.
    pub fn from_name(name: &str) -> Self {
        match name.to_uppercase().as_str() {
            "LATIN" => Self::Latin,
            "GREEK" => Self::Greek,
            "CYRILLIC" => Self::Cyrillic,
            "ARMENIAN" => Self::Armenian,
            "HEBREW" => Self::Hebrew,
            "ARABIC" => Self::Arabic,
            "DEVANAGARI" => Self::Devanagari,
            "BENGALI" => Self::Bengali,
            "THAI" => Self::Thai,
            "HAN" => Self::Han,
            "HIRAGANA" => Self::Hiragana,
            "KATAKANA" => Self::Katakana,
            "HANGUL" => Self::Hangul,
            "CJK" => Self::CJK,
            "COMMON" => Self::Common,
            "INHERITED" => Self::Inherited,
            _ => Self::Unknown,
        }
    }

    /// Return all known script variants (excluding `Unknown`).
    pub fn all_known() -> &'static [UnicodeScript] {
        &[
            Self::Latin,
            Self::Greek,
            Self::Cyrillic,
            Self::Armenian,
            Self::Hebrew,
            Self::Arabic,
            Self::Devanagari,
            Self::Bengali,
            Self::Thai,
            Self::Han,
            Self::Hiragana,
            Self::Katakana,
            Self::Hangul,
            Self::CJK,
            Self::Common,
            Self::Inherited,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display() {
        assert_eq!(UnicodeScript::Latin.to_string(), "LATIN");
        assert_eq!(UnicodeScript::Han.to_string(), "HAN");
        assert_eq!(UnicodeScript::Unknown.to_string(), "UNKNOWN");
        assert_eq!(UnicodeScript::Cyrillic.to_string(), "CYRILLIC");
    }

    #[test]
    fn test_from_name() {
        assert_eq!(UnicodeScript::from_name("latin"), UnicodeScript::Latin);
        assert_eq!(UnicodeScript::from_name("LATIN"), UnicodeScript::Latin);
        assert_eq!(UnicodeScript::from_name("Latin"), UnicodeScript::Latin);
        assert_eq!(UnicodeScript::from_name("bogus"), UnicodeScript::Unknown);
    }

    #[test]
    fn test_all_known() {
        let known = UnicodeScript::all_known();
        assert_eq!(known.len(), 16);
        assert!(!known.contains(&UnicodeScript::Unknown));
    }

    #[test]
    fn test_equality() {
        assert_eq!(UnicodeScript::Latin, UnicodeScript::Latin);
        assert_ne!(UnicodeScript::Latin, UnicodeScript::Greek);
    }

    #[test]
    fn test_copy_clone() {
        let a = UnicodeScript::Arabic;
        let b = a;
        assert_eq!(a, b);
    }
}
