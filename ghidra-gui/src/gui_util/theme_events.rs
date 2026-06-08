//! Theme event types.
//!
//! Ports Ghidra's `generic.theme` event classes:
//! - `ThemeEvent` (base)
//! - `ColorChangedThemeEvent`
//! - `FontChangedThemeEvent`
//! - `IconChangedThemeEvent`
//! - `AllValuesChangedThemeEvent`

use serde::{Deserialize, Serialize};

/// The type of change that occurred in a theme.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemeChangeType {
    /// A color value was changed.
    ColorChanged,
    /// A font value was changed.
    FontChanged,
    /// An icon value was changed.
    IconChanged,
    /// All values were changed (e.g., theme switch).
    AllChanged,
}

/// Base event for theme changes.
///
/// Port of Ghidra's `generic.theme.ThemeEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThemeEvent {
    /// The type of change.
    pub change_type: ThemeChangeType,
    /// The ID of the changed value (if applicable).
    pub value_id: Option<String>,
    /// The old value identifier (for undo/redo).
    pub old_value_id: Option<String>,
    /// Whether this event should trigger a full repaint.
    pub needs_repaint: bool,
}

impl ThemeEvent {
    /// Create a color-changed event.
    pub fn color_changed(color_id: impl Into<String>) -> Self {
        Self {
            change_type: ThemeChangeType::ColorChanged,
            value_id: Some(color_id.into()),
            old_value_id: None,
            needs_repaint: true,
        }
    }

    /// Create a font-changed event.
    pub fn font_changed(font_id: impl Into<String>) -> Self {
        Self {
            change_type: ThemeChangeType::FontChanged,
            value_id: Some(font_id.into()),
            old_value_id: None,
            needs_repaint: true,
        }
    }

    /// Create an icon-changed event.
    pub fn icon_changed(icon_id: impl Into<String>) -> Self {
        Self {
            change_type: ThemeChangeType::IconChanged,
            value_id: Some(icon_id.into()),
            old_value_id: None,
            needs_repaint: false,
        }
    }

    /// Create an all-values-changed event (typically on theme switch).
    pub fn all_changed() -> Self {
        Self {
            change_type: ThemeChangeType::AllChanged,
            value_id: None,
            old_value_id: None,
            needs_repaint: true,
        }
    }
}

/// Event fired when a color value changes in the theme.
///
/// Port of Ghidra's `generic.theme.ColorChangedThemeEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorChangedThemeEvent {
    /// The color ID that changed.
    pub color_id: String,
    /// The old color value identifier.
    pub old_color_id: Option<String>,
}

impl ColorChangedThemeEvent {
    /// Create a new color changed event.
    pub fn new(color_id: impl Into<String>) -> Self {
        Self {
            color_id: color_id.into(),
            old_color_id: None,
        }
    }

    /// Create with old color id for tracking.
    pub fn with_old(color_id: impl Into<String>, old_color_id: impl Into<String>) -> Self {
        Self {
            color_id: color_id.into(),
            old_color_id: Some(old_color_id.into()),
        }
    }
}

/// Event fired when a font value changes in the theme.
///
/// Port of Ghidra's `generic.theme.FontChangedThemeEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontChangedThemeEvent {
    /// The font ID that changed.
    pub font_id: String,
    /// The old font value identifier.
    pub old_font_id: Option<String>,
}

impl FontChangedThemeEvent {
    /// Create a new font changed event.
    pub fn new(font_id: impl Into<String>) -> Self {
        Self {
            font_id: font_id.into(),
            old_font_id: None,
        }
    }
}

/// Event fired when an icon value changes in the theme.
///
/// Port of Ghidra's `generic.theme.IconChangedThemeEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IconChangedThemeEvent {
    /// The icon ID that changed.
    pub icon_id: String,
    /// The old icon value identifier.
    pub old_icon_id: Option<String>,
}

impl IconChangedThemeEvent {
    /// Create a new icon changed event.
    pub fn new(icon_id: impl Into<String>) -> Self {
        Self {
            icon_id: icon_id.into(),
            old_icon_id: None,
        }
    }
}

/// Event fired when all theme values change (e.g., during a theme switch).
///
/// Port of Ghidra's `generic.theme.AllValuesChangedThemeEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllValuesChangedThemeEvent {
    /// The name of the new theme.
    pub theme_name: String,
}

impl AllValuesChangedThemeEvent {
    /// Create a new all-values-changed event.
    pub fn new(theme_name: impl Into<String>) -> Self {
        Self {
            theme_name: theme_name.into(),
        }
    }
}

/// Trait for objects that listen to theme changes.
///
/// Port of Ghidra's `generic.theme.ThemeListener`.
pub trait ThemeListener: std::fmt::Debug {
    /// Called when a theme color changes.
    fn color_changed(&mut self, _event: &ColorChangedThemeEvent) {}

    /// Called when a theme font changes.
    fn font_changed(&mut self, _event: &FontChangedThemeEvent) {}

    /// Called when a theme icon changes.
    fn icon_changed(&mut self, _event: &IconChangedThemeEvent) {}

    /// Called when all theme values change.
    fn all_values_changed(&mut self, _event: &AllValuesChangedThemeEvent) {}
}

/// A collection of theme listeners.
#[derive(Debug, Default)]
pub struct ThemeListenerList {
    listeners: Vec<Box<dyn ThemeListener>>,
}

impl ThemeListenerList {
    /// Create a new empty listener list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a listener.
    pub fn add(&mut self, listener: Box<dyn ThemeListener>) {
        self.listeners.push(listener);
    }

    /// Fire a color changed event to all listeners.
    pub fn fire_color_changed(&mut self, event: &ColorChangedThemeEvent) {
        for listener in &mut self.listeners {
            listener.color_changed(event);
        }
    }

    /// Fire a font changed event to all listeners.
    pub fn fire_font_changed(&mut self, event: &FontChangedThemeEvent) {
        for listener in &mut self.listeners {
            listener.font_changed(event);
        }
    }

    /// Fire an icon changed event to all listeners.
    pub fn fire_icon_changed(&mut self, event: &IconChangedThemeEvent) {
        for listener in &mut self.listeners {
            listener.icon_changed(event);
        }
    }

    /// Fire an all-values-changed event to all listeners.
    pub fn fire_all_values_changed(&mut self, event: &AllValuesChangedThemeEvent) {
        for listener in &mut self.listeners {
            listener.all_values_changed(event);
        }
    }

    /// Number of registered listeners.
    pub fn len(&self) -> usize {
        self.listeners.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.listeners.is_empty()
    }

    /// Remove all listeners.
    pub fn clear(&mut self) {
        self.listeners.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Default)]
    struct TestListener {
        color_count: u32,
        font_count: u32,
        all_count: u32,
    }

    impl ThemeListener for TestListener {
        fn color_changed(&mut self, _event: &ColorChangedThemeEvent) {
            self.color_count += 1;
        }
        fn font_changed(&mut self, _event: &FontChangedThemeEvent) {
            self.font_count += 1;
        }
        fn all_values_changed(&mut self, _event: &AllValuesChangedThemeEvent) {
            self.all_count += 1;
        }
    }

    #[test]
    fn theme_event_creation() {
        let e = ThemeEvent::color_changed("fg.color");
        assert_eq!(e.change_type, ThemeChangeType::ColorChanged);
        assert_eq!(e.value_id.as_deref(), Some("fg.color"));
        assert!(e.needs_repaint);

        let e = ThemeEvent::all_changed();
        assert_eq!(e.change_type, ThemeChangeType::AllChanged);
    }

    #[test]
    fn color_changed_event() {
        let e = ColorChangedThemeEvent::with_old("new_color", "old_color");
        assert_eq!(e.color_id, "new_color");
        assert_eq!(e.old_color_id.as_deref(), Some("old_color"));
    }

    #[test]
    fn font_changed_event() {
        let e = FontChangedThemeEvent::new("monospace.font");
        assert_eq!(e.font_id, "monospace.font");
        assert!(e.old_font_id.is_none());
    }

    #[test]
    fn icon_changed_event() {
        let e = IconChangedThemeEvent::new("folder.icon");
        assert_eq!(e.icon_id, "folder.icon");
    }

    #[test]
    fn all_values_changed_event() {
        let e = AllValuesChangedThemeEvent::new("Dark Theme");
        assert_eq!(e.theme_name, "Dark Theme");
    }

    #[test]
    fn theme_listener_list_operations() {
        let mut list = ThemeListenerList::new();
        assert!(list.is_empty());

        list.add(Box::new(TestListener::default()));
        list.add(Box::new(TestListener::default()));
        assert_eq!(list.len(), 2);

        list.fire_color_changed(&ColorChangedThemeEvent::new("test"));
        list.fire_font_changed(&FontChangedThemeEvent::new("test"));
        list.fire_all_values_changed(&AllValuesChangedThemeEvent::new("test"));

        // We can't easily check individual listener counts without interior
        // mutability, but we verify no panics occur.
        list.clear();
        assert!(list.is_empty());
    }

    #[test]
    fn theme_change_type_variants() {
        assert_ne!(ThemeChangeType::ColorChanged, ThemeChangeType::FontChanged);
        assert_ne!(ThemeChangeType::AllChanged, ThemeChangeType::IconChanged);
    }
}
