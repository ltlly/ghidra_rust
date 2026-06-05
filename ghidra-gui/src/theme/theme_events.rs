//! Concrete theme change event types.
//!
//! Ports the specific event subclasses from `generic.theme`:
//! - `ColorChangedThemeEvent`
//! - `FontChangedThemeEvent`
//! - `IconChangedThemeEvent`
//! - `AllValuesChangedThemeEvent`

use super::theme_event::ThemeEvent;

/// A theme event that indicates a single color value changed.
#[derive(Debug, Clone)]
pub struct ColorChangedThemeEvent {
    /// The color id that changed.
    pub color_id: String,
}

impl ColorChangedThemeEvent {
    /// Create a new ColorChangedThemeEvent.
    pub fn new(color_id: impl Into<String>) -> Self {
        Self {
            color_id: color_id.into(),
        }
    }

    /// Convert to a generic ThemeEvent.
    pub fn to_theme_event(&self) -> ThemeEvent {
        ThemeEvent::color_changed(&self.color_id)
    }

    /// Check if a specific color id was affected.
    pub fn is_color_changed(&self, id: &str) -> bool {
        self.color_id == id
    }
}

/// A theme event that indicates a single font value changed.
#[derive(Debug, Clone)]
pub struct FontChangedThemeEvent {
    /// The font id that changed.
    pub font_id: String,
}

impl FontChangedThemeEvent {
    /// Create a new FontChangedThemeEvent.
    pub fn new(font_id: impl Into<String>) -> Self {
        Self {
            font_id: font_id.into(),
        }
    }

    /// Convert to a generic ThemeEvent.
    pub fn to_theme_event(&self) -> ThemeEvent {
        ThemeEvent::font_changed(&self.font_id)
    }

    /// Check if a specific font id was affected.
    pub fn is_font_changed(&self, id: &str) -> bool {
        self.font_id == id
    }
}

/// A theme event that indicates a single icon value changed.
#[derive(Debug, Clone)]
pub struct IconChangedThemeEvent {
    /// The icon id that changed.
    pub icon_id: String,
}

impl IconChangedThemeEvent {
    /// Create a new IconChangedThemeEvent.
    pub fn new(icon_id: impl Into<String>) -> Self {
        Self {
            icon_id: icon_id.into(),
        }
    }

    /// Convert to a generic ThemeEvent.
    pub fn to_theme_event(&self) -> ThemeEvent {
        ThemeEvent::icon_changed(&self.icon_id)
    }

    /// Check if a specific icon id was affected.
    pub fn is_icon_changed(&self, id: &str) -> bool {
        self.icon_id == id
    }
}

/// A theme event that indicates all values changed (theme switch, reset).
#[derive(Debug, Clone)]
pub struct AllValuesChangedThemeEvent {
    /// Changed color ids (if available).
    pub colors: Vec<String>,
    /// Changed font ids (if available).
    pub fonts: Vec<String>,
    /// Changed icon ids (if available).
    pub icons: Vec<String>,
}

impl AllValuesChangedThemeEvent {
    /// Create a new AllValuesChangedThemeEvent with no specific change info.
    pub fn new() -> Self {
        Self {
            colors: Vec::new(),
            fonts: Vec::new(),
            icons: Vec::new(),
        }
    }

    /// Create with specific change lists.
    pub fn with_changes(
        colors: Vec<String>,
        fonts: Vec<String>,
        icons: Vec<String>,
    ) -> Self {
        Self {
            colors,
            fonts,
            icons,
        }
    }

    /// Convert to a generic ThemeEvent.
    pub fn to_theme_event(&self) -> ThemeEvent {
        ThemeEvent::all_changed()
    }

    /// Check if any colors changed.
    pub fn has_any_color_changed(&self) -> bool {
        !self.colors.is_empty()
    }

    /// Check if any fonts changed.
    pub fn has_any_font_changed(&self) -> bool {
        !self.fonts.is_empty()
    }

    /// Check if any icons changed.
    pub fn has_any_icon_changed(&self) -> bool {
        !self.icons.is_empty()
    }

    /// Check if a specific color was affected.
    pub fn is_color_changed(&self, id: &str) -> bool {
        self.colors.iter().any(|c| c == id)
    }

    /// Check if a specific font was affected.
    pub fn is_font_changed(&self, id: &str) -> bool {
        self.fonts.iter().any(|f| f == id)
    }

    /// Check if a specific icon was affected.
    pub fn is_icon_changed(&self, id: &str) -> bool {
        self.icons.iter().any(|i| i == id)
    }
}

impl Default for AllValuesChangedThemeEvent {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_changed_event() {
        let event = ColorChangedThemeEvent::new("color.bg.listing");
        assert!(event.is_color_changed("color.bg.listing"));
        assert!(!event.is_color_changed("color.fg.listing"));
        let te = event.to_theme_event();
        assert!(te.is_color_changed("color.bg.listing"));
    }

    #[test]
    fn test_font_changed_event() {
        let event = FontChangedThemeEvent::new("font.listing");
        assert!(event.is_font_changed("font.listing"));
        assert!(!event.is_font_changed("font.mono"));
    }

    #[test]
    fn test_icon_changed_event() {
        let event = IconChangedThemeEvent::new("icon.open");
        assert!(event.is_icon_changed("icon.open"));
        assert!(!event.is_icon_changed("icon.close"));
    }

    #[test]
    fn test_all_values_changed() {
        let event = AllValuesChangedThemeEvent::with_changes(
            vec!["c1".to_string()],
            vec!["f1".to_string()],
            vec![],
        );
        assert!(event.has_any_color_changed());
        assert!(event.has_any_font_changed());
        assert!(!event.has_any_icon_changed());
        assert!(event.is_color_changed("c1"));
        assert!(!event.is_color_changed("c2"));
    }

    #[test]
    fn test_all_values_changed_default() {
        let event = AllValuesChangedThemeEvent::default();
        assert!(!event.has_any_color_changed());
        assert!(!event.has_any_font_changed());
        assert!(!event.has_any_icon_changed());
    }
}
