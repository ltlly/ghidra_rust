//! Font that is not a UI resource.
//!
//! Port of Ghidra's `generic.theme.laf.FontNonUiResource`. In Java/Swing,
//! fonts can be wrapped in `FontUIResource` to be managed by the L&F, or
//! kept as plain `Font`. This module provides the non-UI-resource variant.

/// A font specification that is not managed by the L&F system.
///
/// In Ghidra's Java code, `FontNonUiResource` extends `java.awt.Font`
/// to prevent the L&F from overriding a programmatically-set font.
/// In the Rust port this is simply a font descriptor struct.
#[derive(Debug, Clone, PartialEq)]
pub struct FontNonUiResource {
    /// Font family name.
    pub family: String,
    /// Font style (e.g., "plain", "bold", "italic", "bolditalic").
    pub style: FontStyle,
    /// Font size in points.
    pub size: f32,
}

/// Font style variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FontStyle {
    /// Regular (plain) text.
    Plain,
    /// Bold text.
    Bold,
    /// Italic text.
    Italic,
    /// Bold and italic text.
    BoldItalic,
}

impl FontNonUiResource {
    /// Create a new non-UI-resource font.
    pub fn new(family: impl Into<String>, style: FontStyle, size: f32) -> Self {
        Self {
            family: family.into(),
            style,
            size,
        }
    }

    /// Create a plain font.
    pub fn plain(family: impl Into<String>, size: f32) -> Self {
        Self::new(family, FontStyle::Plain, size)
    }

    /// Create a bold font.
    pub fn bold(family: impl Into<String>, size: f32) -> Self {
        Self::new(family, FontStyle::Bold, size)
    }

    /// Create an italic font.
    pub fn italic(family: impl Into<String>, size: f32) -> Self {
        Self::new(family, FontStyle::Italic, size)
    }

    /// Whether this font is bold.
    pub fn is_bold(&self) -> bool {
        matches!(self.style, FontStyle::Bold | FontStyle::BoldItalic)
    }

    /// Whether this font is italic.
    pub fn is_italic(&self) -> bool {
        matches!(self.style, FontStyle::Italic | FontStyle::BoldItalic)
    }

    /// Derive a new font with a different size.
    pub fn with_size(&self, size: f32) -> Self {
        Self {
            family: self.family.clone(),
            style: self.style,
            size,
        }
    }

    /// Derive a new font with a different style.
    pub fn with_style(&self, style: FontStyle) -> Self {
        Self {
            family: self.family.clone(),
            style,
            size: self.size,
        }
    }
}

impl std::fmt::Display for FontNonUiResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let style_str = match self.style {
            FontStyle::Plain => "plain",
            FontStyle::Bold => "bold",
            FontStyle::Italic => "italic",
            FontStyle::BoldItalic => "bolditalic",
        };
        write!(f, "{} {} {}", self.family, style_str, self.size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_font_new() {
        let font = FontNonUiResource::new("Arial", FontStyle::Bold, 14.0);
        assert_eq!(font.family, "Arial");
        assert!(font.is_bold());
        assert!(!font.is_italic());
    }

    #[test]
    fn test_font_plain() {
        let font = FontNonUiResource::plain("Courier", 12.0);
        assert!(!font.is_bold());
        assert!(!font.is_italic());
    }

    #[test]
    fn test_font_bold_italic() {
        let font = FontNonUiResource::new("Helvetica", FontStyle::BoldItalic, 16.0);
        assert!(font.is_bold());
        assert!(font.is_italic());
    }

    #[test]
    fn test_font_with_size() {
        let font = FontNonUiResource::plain("Arial", 12.0);
        let bigger = font.with_size(24.0);
        assert_eq!(bigger.size, 24.0);
        assert_eq!(bigger.family, "Arial");
    }

    #[test]
    fn test_font_with_style() {
        let font = FontNonUiResource::plain("Arial", 12.0);
        let bold = font.with_style(FontStyle::Bold);
        assert!(bold.is_bold());
    }

    #[test]
    fn test_font_display() {
        let font = FontNonUiResource::new("Monospace", FontStyle::Italic, 10.0);
        let s = font.to_string();
        assert!(s.contains("Monospace"));
        assert!(s.contains("italic"));
    }

    #[test]
    fn test_font_derive() {
        let base = FontNonUiResource::bold("Serif", 14.0);
        let derived = base.with_size(20.0).with_style(FontStyle::Plain);
        assert!(!derived.is_bold());
        assert_eq!(derived.size, 20.0);
    }
}
