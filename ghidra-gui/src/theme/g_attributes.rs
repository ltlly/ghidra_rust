//! Graphic attributes for rendering theme-styled elements.
//!
//! Ports `generic.theme.GAttributes` which stores font, color,
//! and icon modifiers for a given UI element.

use super::font_modifier::FontModifier;
use super::icon_modifier::IconModifier;

/// Attributes that describe how to render a themed element.
///
/// This bundles color, font modifications, and icon modifications
/// for a single UI element.
#[derive(Debug, Clone, Default)]
pub struct GAttributes {
    /// The background color (CSS hex string).
    pub background: Option<String>,
    /// The foreground color (CSS hex string).
    pub foreground: Option<String>,
    /// Font modifier (bold, italic, etc.).
    pub font_modifier: Option<FontModifier>,
    /// Icon modifier (size, rotation, etc.).
    pub icon_modifier: Option<IconModifier>,
}

impl GAttributes {
    /// Create empty attributes.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set background color.
    pub fn with_background(mut self, bg: impl Into<String>) -> Self {
        self.background = Some(bg.into());
        self
    }

    /// Set foreground color.
    pub fn with_foreground(mut self, fg: impl Into<String>) -> Self {
        self.foreground = Some(fg.into());
        self
    }

    /// Set font modifier.
    pub fn with_font_modifier(mut self, fm: FontModifier) -> Self {
        self.font_modifier = Some(fm);
        self
    }

    /// Set icon modifier.
    pub fn with_icon_modifier(mut self, im: IconModifier) -> Self {
        self.icon_modifier = Some(im);
        self
    }

    /// Check if any attributes are set.
    pub fn is_empty(&self) -> bool {
        self.background.is_none()
            && self.foreground.is_none()
            && self.font_modifier.is_none()
            && self.icon_modifier.is_none()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g_attributes_default() {
        let attrs = GAttributes::new();
        assert!(attrs.is_empty());
    }

    #[test]
    fn test_g_attributes_builder() {
        let attrs = GAttributes::new()
            .with_background("#FFF")
            .with_foreground("#000");
        assert!(!attrs.is_empty());
        assert_eq!(attrs.background.as_deref(), Some("#FFF"));
        assert_eq!(attrs.foreground.as_deref(), Some("#000"));
    }
}
