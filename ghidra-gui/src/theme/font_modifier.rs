//! Port of `generic.theme.FontModifier`.
//!
//! Modifiers that can be applied to fonts (bold, italic, size adjustments).

/// A font modifier that can be applied to a base font.
///
/// Mirrors `generic.theme.FontModifier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum FontModifier {
    /// Make the font bold.
    Bold,
    /// Make the font italic.
    Italic,
    /// Make the font bold and italic.
    BoldItalic,
    /// Make the font underlined.
    Underline,
    /// Make the font strikethrough.
    Strikethrough,
    /// Increase the font size by a delta.
    SizeDelta(i32),
}

impl FontModifier {
    /// Parse from a string.
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "bold" => Some(Self::Bold),
            "italic" => Some(Self::Italic),
            "bolditalic" | "bold_italic" => Some(Self::BoldItalic),
            "underline" => Some(Self::Underline),
            "strikethrough" | "strike" => Some(Self::Strikethrough),
            _ => {
                if let Some(delta_str) = s.strip_prefix("size+") {
                    delta_str.parse::<i32>().ok().map(Self::SizeDelta)
                } else if let Some(delta_str) = s.strip_prefix("size-") {
                    delta_str.parse::<i32>().ok().map(|d| Self::SizeDelta(-d))
                } else {
                    None
                }
            }
        }
    }

    /// Returns true if this modifier makes the font bold.
    pub fn is_bold(&self) -> bool {
        matches!(self, Self::Bold | Self::BoldItalic)
    }

    /// Returns true if this modifier makes the font italic.
    pub fn is_italic(&self) -> bool {
        matches!(self, Self::Italic | Self::BoldItalic)
    }

    /// Returns true if this is a size modification.
    pub fn is_size_delta(&self) -> bool {
        matches!(self, Self::SizeDelta(_))
    }
}

impl std::fmt::Display for FontModifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bold => write!(f, "Bold"),
            Self::Italic => write!(f, "Italic"),
            Self::BoldItalic => write!(f, "BoldItalic"),
            Self::Underline => write!(f, "Underline"),
            Self::Strikethrough => write!(f, "Strikethrough"),
            Self::SizeDelta(d) => {
                if *d >= 0 {
                    write!(f, "size+{}", d)
                } else {
                    write!(f, "size{}", d) // negative sign included
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_font_modifier_parse() {
        assert_eq!(FontModifier::from_str("bold"), Some(FontModifier::Bold));
        assert_eq!(FontModifier::from_str("Italic"), Some(FontModifier::Italic));
        assert_eq!(FontModifier::from_str("BoldItalic"), Some(FontModifier::BoldItalic));
        assert_eq!(FontModifier::from_str("size+2"), Some(FontModifier::SizeDelta(2)));
        assert_eq!(FontModifier::from_str("size-1"), Some(FontModifier::SizeDelta(-1)));
        assert_eq!(FontModifier::from_str("unknown"), None);
    }

    #[test]
    fn test_font_modifier_helpers() {
        assert!(FontModifier::Bold.is_bold());
        assert!(!FontModifier::Bold.is_italic());
        assert!(FontModifier::Italic.is_italic());
        assert!(!FontModifier::Italic.is_bold());
        assert!(FontModifier::BoldItalic.is_bold());
        assert!(FontModifier::BoldItalic.is_italic());
    }

    #[test]
    fn test_font_modifier_display() {
        assert_eq!(FontModifier::Bold.to_string(), "Bold");
        assert_eq!(FontModifier::SizeDelta(3).to_string(), "size+3");
        assert_eq!(FontModifier::SizeDelta(-2).to_string(), "size-2");
    }
}
