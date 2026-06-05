//! Theme-aware option types.
//!
//! Ports `ghidra.framework.options.ThemeFontOption` and
//! `ghidra.framework.options.ThemeColorOption`.

use super::option_type::OptionType;

/// A theme font option that stores a font theme ID and the
/// current font specification.
///
/// Ports `ghidra.framework.options.ThemeFontOption`.
#[derive(Debug, Clone)]
pub struct ThemeFontOption {
    /// The option name.
    pub name: String,
    /// The theme font ID (e.g. "font.listing").
    pub theme_id: String,
    /// The font family name.
    pub family: String,
    /// The font size in points.
    pub size: f32,
    /// Whether the font is bold.
    pub bold: bool,
    /// Whether the font is italic.
    pub italic: bool,
}

impl ThemeFontOption {
    /// Create a new ThemeFontOption.
    pub fn new(name: impl Into<String>, theme_id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            theme_id: theme_id.into(),
            family: "SansSerif".to_string(),
            size: 12.0,
            bold: false,
            italic: false,
        }
    }

    /// Get the option type.
    pub fn option_type(&self) -> OptionType {
        OptionType::FontType
    }

    /// Get a CSS-like font specification string.
    pub fn to_font_spec(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.italic {
            parts.push("italic".to_string());
        }
        if self.bold {
            parts.push("bold".to_string());
        }
        parts.push(self.family.clone());
        parts.push(format!("{}pt", self.size));
        parts.join(" ")
    }
}

/// A theme color option that stores a color theme ID and the
/// current color value.
///
/// Ports `ghidra.framework.options.ThemeColorOption`.
#[derive(Debug, Clone)]
pub struct ThemeColorOption {
    /// The option name.
    pub name: String,
    /// The theme color ID (e.g. "color.bg.listing").
    pub theme_id: String,
    /// The current color as (r, g, b).
    pub color: (u8, u8, u8),
    /// The default color.
    pub default_color: (u8, u8, u8),
}

impl ThemeColorOption {
    /// Create a new ThemeColorOption.
    pub fn new(
        name: impl Into<String>,
        theme_id: impl Into<String>,
        r: u8,
        g: u8,
        b: u8,
    ) -> Self {
        Self {
            name: name.into(),
            theme_id: theme_id.into(),
            color: (r, g, b),
            default_color: (r, g, b),
        }
    }

    /// Get the option type.
    pub fn option_type(&self) -> OptionType {
        OptionType::ColorType
    }

    /// Get the color as a CSS hex string.
    pub fn to_hex(&self) -> String {
        format!("#{:02X}{:02X}{:02X}", self.color.0, self.color.1, self.color.2)
    }

    /// Set color from RGB.
    pub fn set_color(&mut self, r: u8, g: u8, b: u8) {
        self.color = (r, g, b);
    }

    /// Restore the default color.
    pub fn restore_default(&mut self) {
        self.color = self.default_color;
    }

    /// Check if the color differs from the default.
    pub fn is_changed(&self) -> bool {
        self.color != self.default_color
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_theme_font_option() {
        let opt = ThemeFontOption::new("Listing Font", "font.listing");
        assert_eq!(opt.family, "SansSerif");
        assert_eq!(opt.size, 12.0);
        assert!(!opt.bold);
        let spec = opt.to_font_spec();
        assert!(spec.contains("SansSerif"));
        assert!(spec.contains("12pt"));
    }

    #[test]
    fn test_theme_font_option_bold_italic() {
        let mut opt = ThemeFontOption::new("Code Font", "font.code");
        opt.family = "Courier".to_string();
        opt.bold = true;
        opt.italic = true;
        opt.size = 14.0;
        let spec = opt.to_font_spec();
        assert!(spec.contains("italic"));
        assert!(spec.contains("bold"));
        assert!(spec.contains("Courier"));
    }

    #[test]
    fn test_theme_color_option() {
        let opt = ThemeColorOption::new("BG Color", "color.bg", 255, 255, 255);
        assert_eq!(opt.to_hex(), "#FFFFFF");
        assert!(!opt.is_changed());
    }

    #[test]
    fn test_theme_color_option_change_and_restore() {
        let mut opt = ThemeColorOption::new("FG Color", "color.fg", 0, 0, 0);
        opt.set_color(255, 0, 0);
        assert_eq!(opt.to_hex(), "#FF0000");
        assert!(opt.is_changed());
        opt.restore_default();
        assert_eq!(opt.to_hex(), "#000000");
        assert!(!opt.is_changed());
    }
}
