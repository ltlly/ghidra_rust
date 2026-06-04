//! Theme change event.
//!
//! Ports `generic.theme.ThemeEvent` and its subclasses.

/// Types of theme changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThemeChangeKind {
    /// A single color changed.
    ColorChanged(String),
    /// A single font changed.
    FontChanged(String),
    /// A single icon changed.
    IconChanged(String),
    /// The look-and-feel changed.
    LookAndFeelChanged,
    /// All values potentially changed (theme switch, reset).
    AllValuesChanged,
}

/// Event emitted when theme values change.
///
/// Ported from Ghidra's `generic.theme.ThemeEvent`.
#[derive(Debug, Clone)]
pub struct ThemeEvent {
    kind: ThemeChangeKind,
    /// Set of color ids that changed (for bulk changes).
    changed_colors: Vec<String>,
    /// Set of font ids that changed.
    changed_fonts: Vec<String>,
    /// Set of icon ids that changed.
    changed_icons: Vec<String>,
}

impl ThemeEvent {
    /// Create a color-changed event.
    pub fn color_changed(id: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            kind: ThemeChangeKind::ColorChanged(id.clone()),
            changed_colors: vec![id],
            changed_fonts: Vec::new(),
            changed_icons: Vec::new(),
        }
    }

    /// Create a font-changed event.
    pub fn font_changed(id: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            kind: ThemeChangeKind::FontChanged(id.clone()),
            changed_colors: Vec::new(),
            changed_fonts: vec![id],
            changed_icons: Vec::new(),
        }
    }

    /// Create an icon-changed event.
    pub fn icon_changed(id: impl Into<String>) -> Self {
        let id = id.into();
        Self {
            kind: ThemeChangeKind::IconChanged(id.clone()),
            changed_colors: Vec::new(),
            changed_fonts: Vec::new(),
            changed_icons: vec![id],
        }
    }

    /// Create a look-and-feel-changed event.
    pub fn laf_changed() -> Self {
        Self {
            kind: ThemeChangeKind::LookAndFeelChanged,
            changed_colors: Vec::new(),
            changed_fonts: Vec::new(),
            changed_icons: Vec::new(),
        }
    }

    /// Create an all-values-changed event.
    pub fn all_changed() -> Self {
        Self {
            kind: ThemeChangeKind::AllValuesChanged,
            changed_colors: Vec::new(),
            changed_fonts: Vec::new(),
            changed_icons: Vec::new(),
        }
    }

    /// Create an event with multiple changed ids.
    pub fn with_changes(
        kind: ThemeChangeKind,
        colors: Vec<String>,
        fonts: Vec<String>,
        icons: Vec<String>,
    ) -> Self {
        Self { kind, changed_colors: colors, changed_fonts: fonts, changed_icons: icons }
    }

    /// Whether a specific color id changed.
    pub fn is_color_changed(&self, id: &str) -> bool {
        match &self.kind {
            ThemeChangeKind::AllValuesChanged => true,
            ThemeChangeKind::LookAndFeelChanged => true,
            ThemeChangeKind::ColorChanged(_) => self.changed_colors.contains(&id.to_string()),
            _ => false,
        }
    }

    /// Whether a specific font id changed.
    pub fn is_font_changed(&self, id: &str) -> bool {
        match &self.kind {
            ThemeChangeKind::AllValuesChanged => true,
            ThemeChangeKind::LookAndFeelChanged => true,
            ThemeChangeKind::FontChanged(_) => self.changed_fonts.contains(&id.to_string()),
            _ => false,
        }
    }

    /// Whether a specific icon id changed.
    pub fn is_icon_changed(&self, id: &str) -> bool {
        match &self.kind {
            ThemeChangeKind::AllValuesChanged => true,
            ThemeChangeKind::LookAndFeelChanged => true,
            ThemeChangeKind::IconChanged(_) => self.changed_icons.contains(&id.to_string()),
            _ => false,
        }
    }

    /// Whether the look-and-feel changed.
    pub fn is_laf_changed(&self) -> bool {
        matches!(
            self.kind,
            ThemeChangeKind::LookAndFeelChanged | ThemeChangeKind::AllValuesChanged
        )
    }

    /// Whether any color changed.
    pub fn has_any_color_changed(&self) -> bool {
        !self.changed_colors.is_empty()
            || matches!(self.kind, ThemeChangeKind::AllValuesChanged | ThemeChangeKind::LookAndFeelChanged)
    }

    /// Whether any font changed.
    pub fn has_any_font_changed(&self) -> bool {
        !self.changed_fonts.is_empty()
            || matches!(self.kind, ThemeChangeKind::AllValuesChanged | ThemeChangeKind::LookAndFeelChanged)
    }

    /// Whether any icon changed.
    pub fn has_any_icon_changed(&self) -> bool {
        !self.changed_icons.is_empty()
            || matches!(self.kind, ThemeChangeKind::AllValuesChanged | ThemeChangeKind::LookAndFeelChanged)
    }

    /// Whether all values may have changed.
    pub fn have_all_values_changed(&self) -> bool {
        matches!(self.kind, ThemeChangeKind::AllValuesChanged | ThemeChangeKind::LookAndFeelChanged)
    }

    /// Get the change kind.
    pub fn kind(&self) -> &ThemeChangeKind {
        &self.kind
    }

    /// Get the list of changed color ids.
    pub fn changed_colors(&self) -> &[String] {
        &self.changed_colors
    }

    /// Get the list of changed font ids.
    pub fn changed_fonts(&self) -> &[String] {
        &self.changed_fonts
    }

    /// Get the list of changed icon ids.
    pub fn changed_icons(&self) -> &[String] {
        &self.changed_icons
    }
}

/// Trait for objects that listen to theme changes.
pub trait ThemeListener: Send + Sync {
    /// Called when the theme changes.
    fn theme_changed(&self, event: &ThemeEvent);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_changed_event() {
        let event = ThemeEvent::color_changed("color.bg");
        assert!(event.is_color_changed("color.bg"));
        assert!(!event.is_color_changed("color.fg"));
        assert!(event.has_any_color_changed());
        assert!(!event.has_any_font_changed());
    }

    #[test]
    fn test_font_changed_event() {
        let event = ThemeEvent::font_changed("font.mono");
        assert!(event.is_font_changed("font.mono"));
        assert!(!event.is_color_changed("anything"));
    }

    #[test]
    fn test_all_changed_event() {
        let event = ThemeEvent::all_changed();
        assert!(event.is_color_changed("anything"));
        assert!(event.is_font_changed("anything"));
        assert!(event.is_icon_changed("anything"));
        assert!(event.is_laf_changed());
        assert!(event.have_all_values_changed());
    }

    #[test]
    fn test_laf_changed_event() {
        let event = ThemeEvent::laf_changed();
        assert!(event.is_laf_changed());
        assert!(event.have_all_values_changed());
        assert!(event.is_color_changed("any.color"));
    }

    #[test]
    fn test_with_changes() {
        let event = ThemeEvent::with_changes(
            ThemeChangeKind::ColorChanged("color.x".into()),
            vec!["color.x".into(), "color.y".into()],
            vec![],
            vec![],
        );
        assert!(event.is_color_changed("color.x"));
        assert!(event.is_color_changed("color.y"));
        assert_eq!(event.changed_colors().len(), 2);
    }
}
