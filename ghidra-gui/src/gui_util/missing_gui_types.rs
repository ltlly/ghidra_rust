//! Missing GUI framework types ported from Ghidra's Java Framework/Gui package.
//!
//! Ports the following Java classes:
//! - `options.OptionsChangeListener` -- listener for options changes
//! - `options.OptionsVetoException` -- exception to veto an options change
//! - `options.PropertyBoolean` / `PropertySelector` / `PropertyText` -- property editors
//! - `task.SwingRunnable` -- runnable that must execute on the EDT
//! - `task.BufferedSwingRunner` -- buffered swing runner
//! - `task.DummyCancellableTaskMonitor` -- no-op monitor for testing
//! - `task.UnknownProgressWrappingTaskMonitor` -- wraps a monitor with unknown progress
//! - `theme.IconChangedThemeEvent` -- event for icon theme changes
//! - `theme.FontChangedThemeEvent` -- event for font theme changes
//! - `theme.ColorChangedThemeEvent` -- event for color theme changes
//! - `theme.AllValuesChangedThemeEvent` -- event when all theme values change
//! - `resources.IconProvider` -- interface for providing icons
//! - `icons.DisabledImageIconWrapper` -- icon wrapper for disabled state

use std::fmt;

// ============================================================================
// OptionsChangeListener
// ============================================================================

/// Listener for option value changes.
///
/// Ported from `ghidra.framework.options.OptionsChangeListener`.
pub trait OptionsChangeListener: fmt::Debug {
    /// Called when an option value changes.
    fn option_changed(&self, options_name: &str, option_name: &str, old_value: &OptionValue, new_value: &OptionValue);
}

/// Represents an option value for change notification.
#[derive(Debug, Clone, PartialEq)]
pub enum OptionValue {
    /// Boolean value.
    Boolean(bool),
    /// Integer value.
    Int(i64),
    /// Float value.
    Float(f64),
    /// String value.
    String(String),
    /// Custom/complex value.
    Custom(String),
    /// Null/unset.
    None,
}

impl fmt::Display for OptionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OptionValue::Boolean(v) => write!(f, "{}", v),
            OptionValue::Int(v) => write!(f, "{}", v),
            OptionValue::Float(v) => write!(f, "{}", v),
            OptionValue::String(v) => write!(f, "{}", v),
            OptionValue::Custom(v) => write!(f, "{}", v),
            OptionValue::None => write!(f, "<none>"),
        }
    }
}

// ============================================================================
// OptionsVetoException
// ============================================================================

/// Exception thrown to veto an options change.
///
/// When thrown from an `OptionsChangeListener`, the change is rolled back.
/// Ported from `ghidra.framework.options.OptionsVetoException`.
#[derive(Debug, Clone)]
pub struct OptionsVetoException {
    message: String,
}

impl OptionsVetoException {
    /// Create a new veto exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Get the message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for OptionsVetoException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Options change vetoed: {}", self.message)
    }
}

impl std::error::Error for OptionsVetoException {}

// ============================================================================
// PropertyBoolean / PropertySelector / PropertyText
// ============================================================================

/// A boolean property editor.
///
/// Ported from `ghidra.framework.options.PropertyBoolean`.
#[derive(Debug, Clone)]
pub struct PropertyBoolean {
    /// Property name.
    pub name: String,
    /// Current value.
    pub value: bool,
    /// Default value.
    pub default_value: bool,
    /// Description.
    pub description: String,
}

impl PropertyBoolean {
    /// Create a new boolean property.
    pub fn new(name: impl Into<String>, default: bool) -> Self {
        Self {
            name: name.into(),
            value: default,
            default_value: default,
            description: String::new(),
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Reset to default.
    pub fn reset(&mut self) {
        self.value = self.default_value;
    }
}

/// A selector property (dropdown/picker).
///
/// Ported from `ghidra.framework.options.PropertySelector`.
#[derive(Debug, Clone)]
pub struct PropertySelector {
    /// Property name.
    pub name: String,
    /// Available choices.
    pub choices: Vec<String>,
    /// Currently selected index.
    pub selected_index: usize,
    /// Description.
    pub description: String,
}

impl PropertySelector {
    /// Create a new selector property.
    pub fn new(name: impl Into<String>, choices: Vec<String>) -> Self {
        Self {
            name: name.into(),
            choices,
            selected_index: 0,
            description: String::new(),
        }
    }

    /// Get the currently selected value.
    pub fn selected_value(&self) -> Option<&str> {
        self.choices.get(self.selected_index).map(|s| s.as_str())
    }

    /// Set the selected index.
    pub fn set_selected(&mut self, index: usize) {
        if index < self.choices.len() {
            self.selected_index = index;
        }
    }

    /// Find and select a value.
    pub fn select_value(&mut self, value: &str) {
        if let Some(idx) = self.choices.iter().position(|c| c == value) {
            self.selected_index = idx;
        }
    }
}

/// A text property editor.
///
/// Ported from `ghidra.framework.options.PropertyText`.
#[derive(Debug, Clone)]
pub struct PropertyText {
    /// Property name.
    pub name: String,
    /// Current text value.
    pub value: String,
    /// Default value.
    pub default_value: String,
    /// Maximum allowed length (0 = unlimited).
    pub max_length: usize,
    /// Description.
    pub description: String,
}

impl PropertyText {
    /// Create a new text property.
    pub fn new(name: impl Into<String>, default: impl Into<String>) -> Self {
        let default_val = default.into();
        Self {
            name: name.into(),
            value: default_val.clone(),
            default_value: default_val,
            max_length: 0,
            description: String::new(),
        }
    }

    /// Reset to default.
    pub fn reset(&mut self) {
        self.value = self.default_value.clone();
    }

    /// Whether the value has changed from default.
    pub fn is_changed(&self) -> bool {
        self.value != self.default_value
    }
}

// ============================================================================
// Theme Events
// ============================================================================

/// Event fired when a theme color changes.
///
/// Ported from `generic.theme.ColorChangedThemeEvent`.
#[derive(Debug, Clone)]
pub struct ColorChangedThemeEvent {
    /// The color ID that changed.
    pub color_id: String,
    /// The old color value (as hex string, e.g. "#RRGGBB").
    pub old_value: Option<String>,
    /// The new color value.
    pub new_value: Option<String>,
}

impl ColorChangedThemeEvent {
    /// Create a new color changed event.
    pub fn new(color_id: impl Into<String>, old_value: Option<String>, new_value: Option<String>) -> Self {
        Self {
            color_id: color_id.into(),
            old_value,
            new_value,
        }
    }
}

/// Event fired when a theme font changes.
///
/// Ported from `generic.theme.FontChangedThemeEvent`.
#[derive(Debug, Clone)]
pub struct FontChangedThemeEvent {
    /// The font ID that changed.
    pub font_id: String,
    /// Old font description.
    pub old_value: Option<String>,
    /// New font description.
    pub new_value: Option<String>,
}

impl FontChangedThemeEvent {
    /// Create a new font changed event.
    pub fn new(font_id: impl Into<String>, old_value: Option<String>, new_value: Option<String>) -> Self {
        Self {
            font_id: font_id.into(),
            old_value,
            new_value,
        }
    }
}

/// Event fired when a theme icon changes.
///
/// Ported from `generic.theme.IconChangedThemeEvent`.
#[derive(Debug, Clone)]
pub struct IconChangedThemeEvent {
    /// The icon ID that changed.
    pub icon_id: String,
    /// Old icon path.
    pub old_value: Option<String>,
    /// New icon path.
    pub new_value: Option<String>,
}

impl IconChangedThemeEvent {
    /// Create a new icon changed event.
    pub fn new(icon_id: impl Into<String>, old_value: Option<String>, new_value: Option<String>) -> Self {
        Self {
            icon_id: icon_id.into(),
            old_value,
            new_value,
        }
    }
}

/// Event fired when all theme values change (e.g., theme switch).
///
/// Ported from `generic.theme.AllValuesChangedThemeEvent`.
#[derive(Debug, Clone)]
pub struct AllValuesChangedThemeEvent {
    /// The theme name that was applied.
    pub theme_name: String,
    /// Number of color values changed.
    pub colors_changed: usize,
    /// Number of font values changed.
    pub fonts_changed: usize,
    /// Number of icon values changed.
    pub icons_changed: usize,
}

impl AllValuesChangedThemeEvent {
    /// Create a new all-values-changed event.
    pub fn new(theme_name: impl Into<String>) -> Self {
        Self {
            theme_name: theme_name.into(),
            colors_changed: 0,
            fonts_changed: 0,
            icons_changed: 0,
        }
    }

    /// Total number of values changed.
    pub fn total_changed(&self) -> usize {
        self.colors_changed + self.fonts_changed + self.icons_changed
    }
}

/// A union of all theme events.
#[derive(Debug, Clone)]
pub enum ThemeEvent {
    /// A color changed.
    ColorChanged(ColorChangedThemeEvent),
    /// A font changed.
    FontChanged(FontChangedThemeEvent),
    /// An icon changed.
    IconChanged(IconChangedThemeEvent),
    /// All values changed.
    AllValuesChanged(AllValuesChangedThemeEvent),
}

// ============================================================================
// IconProvider
// ============================================================================

/// Interface for objects that provide an icon.
///
/// Ported from `resources.IconProvider`.
pub trait IconProvider: fmt::Debug {
    /// Get the icon path or identifier.
    fn icon_path(&self) -> Option<&str>;

    /// Whether this provider has an icon.
    fn has_icon(&self) -> bool {
        self.icon_path().is_some()
    }
}

// ============================================================================
// DisabledImageIconWrapper
// ============================================================================

/// A wrapper that creates a disabled (grayed-out) version of an icon.
///
/// Ported from `resources.icons.DisabledImageIconWrapper`.
#[derive(Debug, Clone)]
pub struct DisabledImageIconWrapper {
    /// The original icon path.
    pub original_path: String,
    /// The disabled icon data (simplified: we store the path, actual rendering
    /// would apply a grayscale/disabled effect).
    pub disabled_path: String,
}

impl DisabledImageIconWrapper {
    /// Create a new disabled icon wrapper.
    pub fn new(original_path: impl Into<String>) -> Self {
        let orig = original_path.into();
        let disabled = format!("{}_disabled", orig);
        Self {
            original_path: orig,
            disabled_path: disabled,
        }
    }

    /// Get the path for the disabled icon.
    pub fn disabled_icon_path(&self) -> &str {
        &self.disabled_path
    }

    /// Get the original icon path.
    pub fn original_icon_path(&self) -> &str {
        &self.original_path
    }
}

// ============================================================================
// SwingRunnable
// ============================================================================

/// A runnable that must execute on the Swing Event Dispatch Thread (EDT).
///
/// Ported from `ghidra.util.task.SwingRunnable`.
pub trait SwingRunnable: fmt::Debug {
    /// The name of this runnable.
    fn name(&self) -> &str;

    /// Execute the runnable (called on the EDT).
    fn run(&self);

    /// Callback when execution completes successfully.
    fn completed(&self) {}

    /// Callback when execution fails.
    fn failed(&self, _error: &str) {}
}

// ============================================================================
// DummyCancellableTaskMonitor
// ============================================================================

/// A no-op task monitor that never reports progress or cancellation.
///
/// Useful for testing or when a monitor is required but not needed.
/// Ported from `ghidra.util.task.DummyCancellableTaskMonitor`.
#[derive(Debug, Clone)]
pub struct DummyCancellableTaskMonitor {
    cancelled: bool,
    message: String,
    progress: i64,
    maximum: i64,
}

impl DummyCancellableTaskMonitor {
    /// Create a new dummy monitor.
    pub fn new() -> Self {
        Self {
            cancelled: false,
            message: String::new(),
            progress: 0,
            maximum: -1,
        }
    }

    /// Check if cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Cancel this monitor.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Set the message.
    pub fn set_message(&mut self, msg: impl Into<String>) {
        self.message = msg.into();
    }

    /// Set the maximum progress value.
    pub fn set_maximum(&mut self, max: i64) {
        self.maximum = max;
    }

    /// Set the current progress value.
    pub fn set_progress(&mut self, value: i64) {
        self.progress = value;
    }

    /// Increment progress by a delta.
    pub fn increment_progress(&mut self, delta: i64) {
        self.progress += delta;
    }

    /// Get the current message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Get the current progress.
    pub fn progress(&self) -> i64 {
        self.progress
    }

    /// Get the maximum.
    pub fn maximum(&self) -> i64 {
        self.maximum
    }

    /// Whether the maximum is set.
    pub fn has_maximum(&self) -> bool {
        self.maximum >= 0
    }
}

impl Default for DummyCancellableTaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// UnknownProgressWrappingTaskMonitor
// ============================================================================

/// A monitor wrapper that shows indeterminate (unknown) progress.
///
/// Ported from `ghidra.util.task.UnknownProgressWrappingTaskMonitor`.
#[derive(Debug, Clone)]
pub struct UnknownProgressWrappingTaskMonitor {
    inner: DummyCancellableTaskMonitor,
    /// Whether to show indeterminate progress.
    pub indeterminate: bool,
}

impl UnknownProgressWrappingTaskMonitor {
    /// Create a new wrapping monitor.
    pub fn new() -> Self {
        Self {
            inner: DummyCancellableTaskMonitor::new(),
            indeterminate: true,
        }
    }

    /// Delegate to inner monitor.
    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    pub fn cancel(&mut self) {
        self.inner.cancel();
    }

    pub fn set_message(&mut self, msg: impl Into<String>) {
        self.inner.set_message(msg);
    }
}

impl Default for UnknownProgressWrappingTaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_option_value_display() {
        assert_eq!(format!("{}", OptionValue::Boolean(true)), "true");
        assert_eq!(format!("{}", OptionValue::Int(42)), "42");
        assert_eq!(format!("{}", OptionValue::Float(3.14)), "3.14");
        assert_eq!(format!("{}", OptionValue::String("hello".into())), "hello");
        assert_eq!(format!("{}", OptionValue::None), "<none>");
    }

    #[test]
    fn test_options_veto_exception() {
        let e = OptionsVetoException::new("bad value");
        assert_eq!(e.message(), "bad value");
        assert!(format!("{}", e).contains("bad value"));
    }

    #[test]
    fn test_property_boolean() {
        let mut prop = PropertyBoolean::new("dark_mode", true);
        assert!(prop.value);
        prop.value = false;
        assert!(!prop.value);
        prop.reset();
        assert!(prop.value);
    }

    #[test]
    fn test_property_selector() {
        let mut sel = PropertySelector::new(
            "theme",
            vec!["light".into(), "dark".into(), "system".into()],
        );
        assert_eq!(sel.selected_value(), Some("light"));
        sel.select_value("dark");
        assert_eq!(sel.selected_value(), Some("dark"));
        sel.set_selected(2);
        assert_eq!(sel.selected_value(), Some("system"));
    }

    #[test]
    fn test_property_text() {
        let mut prop = PropertyText::new("username", "default");
        assert_eq!(prop.value, "default");
        assert!(!prop.is_changed());
        prop.value = "custom".to_string();
        assert!(prop.is_changed());
        prop.reset();
        assert_eq!(prop.value, "default");
    }

    #[test]
    fn test_color_changed_event() {
        let event = ColorChangedThemeEvent::new(
            "color.bg",
            Some("#000000".into()),
            Some("#FFFFFF".into()),
        );
        assert_eq!(event.color_id, "color.bg");
    }

    #[test]
    fn test_font_changed_event() {
        let event = FontChangedThemeEvent::new(
            "font.default",
            None,
            Some("Monospaced-12".into()),
        );
        assert_eq!(event.font_id, "font.default");
    }

    #[test]
    fn test_icon_changed_event() {
        let event = IconChangedThemeEvent::new(
            "icon.file",
            Some("/old/path.png".into()),
            Some("/new/path.png".into()),
        );
        assert_eq!(event.icon_id, "icon.file");
    }

    #[test]
    fn test_all_values_changed_event() {
        let mut event = AllValuesChangedThemeEvent::new("Dark Theme");
        event.colors_changed = 10;
        event.fonts_changed = 5;
        event.icons_changed = 20;
        assert_eq!(event.total_changed(), 35);
        assert_eq!(event.theme_name, "Dark Theme");
    }

    #[test]
    fn test_theme_event_variants() {
        let e1 = ThemeEvent::ColorChanged(ColorChangedThemeEvent::new("c", None, None));
        let e2 = ThemeEvent::FontChanged(FontChangedThemeEvent::new("f", None, None));
        let e3 = ThemeEvent::IconChanged(IconChangedThemeEvent::new("i", None, None));
        let e4 = ThemeEvent::AllValuesChanged(AllValuesChangedThemeEvent::new("t"));
        assert!(matches!(e1, ThemeEvent::ColorChanged(_)));
        assert!(matches!(e2, ThemeEvent::FontChanged(_)));
        assert!(matches!(e3, ThemeEvent::IconChanged(_)));
        assert!(matches!(e4, ThemeEvent::AllValuesChanged(_)));
    }

    #[test]
    fn test_disabled_image_icon_wrapper() {
        let wrapper = DisabledImageIconWrapper::new("/icons/folder.png");
        assert_eq!(wrapper.original_icon_path(), "/icons/folder.png");
        assert_eq!(wrapper.disabled_icon_path(), "/icons/folder.png_disabled");
    }

    #[test]
    fn test_dummy_monitor() {
        let mut monitor = DummyCancellableTaskMonitor::new();
        assert!(!monitor.is_cancelled());
        monitor.set_message("Working...");
        assert_eq!(monitor.message(), "Working...");
        monitor.set_maximum(100);
        assert!(monitor.has_maximum());
        assert_eq!(monitor.maximum(), 100);
        monitor.increment_progress(50);
        assert_eq!(monitor.progress(), 50);
        monitor.cancel();
        assert!(monitor.is_cancelled());
    }

    #[test]
    fn test_unknown_progress_monitor() {
        let monitor = UnknownProgressWrappingTaskMonitor::new();
        assert!(!monitor.is_cancelled());
        assert!(monitor.indeterminate);
    }

    #[test]
    fn test_option_value_equality() {
        assert_eq!(OptionValue::Boolean(true), OptionValue::Boolean(true));
        assert_ne!(OptionValue::Boolean(true), OptionValue::Boolean(false));
        assert_eq!(OptionValue::Int(42), OptionValue::Int(42));
        assert_ne!(OptionValue::Int(42), OptionValue::Int(43));
    }
}
