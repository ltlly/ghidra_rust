//! User-input dialog types for Ghidra scripts.
//!
//! Ported from `ghidra.app.script.AskDialog` and
//! `ghidra.app.script.MultipleOptionsDialog`.
//!
//! Provides the backing models for script prompts (askString, askInt,
//! askChoice, askChoices, etc.) and the language-selection dialog.

use std::fmt;

// ---------------------------------------------------------------------------
// AskDialogType -- the type of value requested
// ---------------------------------------------------------------------------

/// The type of value a script is asking for.
///
/// Corresponds to the type constants in `AskDialog`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AskDialogType {
    /// Free-text string input.
    String,
    /// Integer input.
    Int,
    /// Long integer input.
    Long,
    /// Floating-point input.
    Double,
    /// Hex-encoded byte sequence.
    Bytes,
}

impl AskDialogType {
    /// Return the human-readable label for this input type.
    pub fn label(&self) -> &str {
        match self {
            Self::String => "String",
            Self::Int => "Int",
            Self::Long => "Long",
            Self::Double => "Double",
            Self::Bytes => "Bytes",
        }
    }
}

impl fmt::Display for AskDialogType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Result of an AskDialog interaction.
#[derive(Debug, Clone)]
pub enum AskDialogResult<T> {
    /// The user provided a value.
    Value(T),
    /// The user cancelled the dialog.
    Cancelled,
}

impl<T> AskDialogResult<T> {
    /// Returns `true` if the user provided a value.
    pub fn is_value(&self) -> bool {
        matches!(self, Self::Value(_))
    }

    /// Returns `true` if the user cancelled.
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled)
    }

    /// Extract the inner value, panicking if cancelled.
    pub fn unwrap(self) -> T {
        match self {
            Self::Value(v) => v,
            Self::Cancelled => panic!("AskDialogResult is Cancelled"),
        }
    }

    /// Extract the inner value or return the default.
    pub fn unwrap_or(self, default: T) -> T {
        match self {
            Self::Value(v) => v,
            Self::Cancelled => default,
        }
    }
}

// ---------------------------------------------------------------------------
// AskDialogModel -- backing model for the ask dialog
// ---------------------------------------------------------------------------

/// Model for the `AskDialog`.
///
/// Ported from `ghidra.app.script.AskDialog`.
#[derive(Debug, Clone)]
pub struct AskDialogModel<T: Clone + fmt::Debug> {
    /// Dialog title.
    pub title: String,
    /// Prompt message shown to the user.
    pub message: String,
    /// The type of value being requested.
    pub dialog_type: AskDialogType,
    /// Pre-populated choices (for choice-style dialogs).
    pub choices: Vec<T>,
    /// Default value.
    pub default_value: Option<T>,
    /// Whether the dialog was cancelled.
    pub cancelled: bool,
    /// The entered value (if any).
    pub value: Option<T>,
}

impl<T: Clone + fmt::Debug> AskDialogModel<T> {
    /// Create a new ask dialog model.
    pub fn new(
        title: impl Into<String>,
        message: impl Into<String>,
        dialog_type: AskDialogType,
    ) -> Self {
        Self {
            title: title.into(),
            message: message.into(),
            dialog_type,
            choices: Vec::new(),
            default_value: None,
            cancelled: false,
            value: None,
        }
    }

    /// Set the pre-populated choices.
    pub fn with_choices(mut self, choices: Vec<T>) -> Self {
        self.choices = choices;
        self
    }

    /// Set the default value.
    pub fn with_default(mut self, default: T) -> Self {
        self.default_value = Some(default);
        self
    }

    /// Submit the dialog with a value.
    pub fn submit(&mut self, value: T) {
        self.value = Some(value);
        self.cancelled = false;
    }

    /// Cancel the dialog.
    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.value = None;
    }

    /// Get the result.
    pub fn result(&self) -> AskDialogResult<&T> {
        if self.cancelled {
            AskDialogResult::Cancelled
        } else {
            match &self.value {
                Some(v) => AskDialogResult::Value(v),
                None => AskDialogResult::Cancelled,
            }
        }
    }

    /// Whether the dialog has choices.
    pub fn has_choices(&self) -> bool {
        !self.choices.is_empty()
    }
}

// ---------------------------------------------------------------------------
// MultipleOptionsDialog
// ---------------------------------------------------------------------------

/// A dialog that presents multiple options for the user to choose from.
///
/// Ported from `ghidra.app.script.MultipleOptionsDialog`.
#[derive(Debug, Clone)]
pub struct MultipleOptionsDialog<T: Clone + fmt::Debug> {
    /// Dialog title.
    pub title: String,
    /// Prompt message.
    pub message: String,
    /// Available options.
    pub options: Vec<T>,
    /// Selected index (None = nothing selected).
    pub selected: Option<usize>,
    /// Whether the dialog was cancelled.
    pub cancelled: bool,
}

impl<T: Clone + fmt::Debug + PartialEq> MultipleOptionsDialog<T> {
    /// Create a new multiple options dialog.
    pub fn new(
        title: impl Into<String>,
        message: impl Into<String>,
        options: Vec<T>,
    ) -> Self {
        Self {
            title: title.into(),
            message: message.into(),
            options,
            selected: None,
            cancelled: false,
        }
    }

    /// Select an option by index.
    pub fn select(&mut self, index: usize) {
        if index < self.options.len() {
            self.selected = Some(index);
        }
    }

    /// Select an option by value.
    pub fn select_by_value(&mut self, value: &T) {
        self.selected = self.options.iter().position(|o| o == value);
    }

    /// Get the selected option.
    pub fn selected_option(&self) -> Option<&T> {
        self.selected.and_then(|i| self.options.get(i))
    }

    /// Submit the selection.
    pub fn submit(&mut self) {
        self.cancelled = false;
    }

    /// Cancel the dialog.
    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.selected = None;
    }

    /// Get the result.
    pub fn result(&self) -> AskDialogResult<&T> {
        if self.cancelled {
            AskDialogResult::Cancelled
        } else {
            match self.selected_option() {
                Some(v) => AskDialogResult::Value(v),
                None => AskDialogResult::Cancelled,
            }
        }
    }

    /// Number of available options.
    pub fn option_count(&self) -> usize {
        self.options.len()
    }
}

// ---------------------------------------------------------------------------
// SelectLanguageDialog
// ---------------------------------------------------------------------------

/// A dialog for selecting a Ghidra language/compiler specification.
///
/// Ported from `ghidra.app.script.SelectLanguageDialog`.
#[derive(Debug, Clone)]
pub struct SelectLanguageDialog {
    /// Dialog title.
    pub title: String,
    /// Available languages as (language_id, description) pairs.
    pub languages: Vec<(String, String)>,
    /// Selected language ID.
    pub selected: Option<String>,
    /// Whether the dialog was cancelled.
    pub cancelled: bool,
    /// Show deprecated languages.
    pub show_deprecated: bool,
}

impl SelectLanguageDialog {
    /// Create a new language selection dialog.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            languages: Vec::new(),
            selected: None,
            cancelled: false,
            show_deprecated: false,
        }
    }

    /// Add a language option.
    pub fn add_language(&mut self, id: impl Into<String>, description: impl Into<String>) {
        self.languages.push((id.into(), description.into()));
    }

    /// Select a language by ID.
    pub fn select(&mut self, id: &str) {
        self.selected = Some(id.to_string());
    }

    /// Get the selected language ID.
    pub fn selected_language_id(&self) -> Option<&str> {
        self.selected.as_deref()
    }

    /// Get the selected language description.
    pub fn selected_language_description(&self) -> Option<&str> {
        let id = self.selected.as_deref()?;
        self.languages
            .iter()
            .find(|(lid, _)| lid == id)
            .map(|(_, desc)| desc.as_str())
    }

    /// Submit the dialog.
    pub fn submit(&mut self) {
        self.cancelled = false;
    }

    /// Cancel the dialog.
    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.selected = None;
    }

    /// Number of available languages.
    pub fn language_count(&self) -> usize {
        self.languages.len()
    }
}

// ---------------------------------------------------------------------------
// Preferences helper
// ---------------------------------------------------------------------------

/// Simple key-value preference store for script dialogs.
///
/// Ported from `ghidra.framework.preferences.Preferences` (simplified).
#[derive(Debug, Default)]
pub struct ScriptPreferences {
    store: std::collections::HashMap<String, String>,
}

impl ScriptPreferences {
    /// Create a new preferences store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a preference value.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.store.get(key).map(|s| s.as_str())
    }

    /// Set a preference value.
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.store.insert(key.into(), value.into());
    }

    /// Remove a preference.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.store.remove(key)
    }

    /// Check if a preference exists.
    pub fn has(&self, key: &str) -> bool {
        self.store.contains_key(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ask_dialog_type() {
        assert_eq!(AskDialogType::String.label(), "String");
        assert_eq!(format!("{}", AskDialogType::Int), "Int");
    }

    #[test]
    fn test_ask_dialog_result() {
        let val: AskDialogResult<i32> = AskDialogResult::Value(42);
        assert!(val.is_value());
        assert!(!val.is_cancelled());
        assert_eq!(val.unwrap(), 42);

        let cancelled: AskDialogResult<i32> = AskDialogResult::Cancelled;
        assert!(cancelled.is_cancelled());
        assert_eq!(cancelled.unwrap_or(0), 0);
    }

    #[test]
    fn test_ask_dialog_model_string() {
        let mut model = AskDialogModel::<String>::new(
            "Enter Name",
            "Please enter your name:",
            AskDialogType::String,
        );
        assert!(model.result().is_cancelled());

        model.submit("Alice".to_string());
        assert!(model.result().is_value());
        assert_eq!(model.result().unwrap().as_str(), "Alice");
    }

    #[test]
    fn test_ask_dialog_model_with_choices() {
        let model = AskDialogModel::<String>::new(
            "Choose Color",
            "Select a color:",
            AskDialogType::String,
        )
        .with_choices(vec!["Red".into(), "Green".into(), "Blue".into()])
        .with_default("Green".into());

        assert!(model.has_choices());
        assert_eq!(model.choices.len(), 3);
        assert_eq!(model.default_value.as_deref(), Some("Green"));
    }

    #[test]
    fn test_ask_dialog_cancel() {
        let mut model = AskDialogModel::<String>::new(
            "T", "M", AskDialogType::String,
        );
        model.submit("test".to_string());
        assert!(model.result().is_value());

        model.cancel();
        assert!(model.result().is_cancelled());
    }

    #[test]
    fn test_multiple_options_dialog() {
        let mut dialog = MultipleOptionsDialog::new(
            "Choose",
            "Select one:",
            vec!["Option A".to_string(), "Option B".to_string(), "Option C".to_string()],
        );
        assert_eq!(dialog.option_count(), 3);
        assert!(dialog.result().is_cancelled());

        dialog.select(1);
        assert_eq!(dialog.selected_option().unwrap().as_str(), "Option B");

        dialog.submit();
        assert!(dialog.result().is_value());
        assert_eq!(dialog.result().unwrap().as_str(), "Option B");
    }

    #[test]
    fn test_multiple_options_select_by_value() {
        let mut dialog = MultipleOptionsDialog::new(
            "Choose", "Select:",
            vec!["A".to_string(), "B".to_string()],
        );
        dialog.select_by_value(&"B".to_string());
        assert_eq!(dialog.selected, Some(1));
    }

    #[test]
    fn test_select_language_dialog() {
        let mut dialog = SelectLanguageDialog::new("Select Language");
        dialog.add_language("x86:LE:64:default", "x86-64 little-endian");
        dialog.add_language("ARM:LE:32:v8", "ARM 32-bit");

        assert_eq!(dialog.language_count(), 2);

        dialog.select("ARM:LE:32:v8");
        assert_eq!(dialog.selected_language_id(), Some("ARM:LE:32:v8"));
        assert_eq!(
            dialog.selected_language_description(),
            Some("ARM 32-bit")
        );

        dialog.submit();
        assert!(!dialog.cancelled);
    }

    #[test]
    fn test_select_language_dialog_cancel() {
        let mut dialog = SelectLanguageDialog::new("Select");
        dialog.add_language("x86:LE:64:default", "desc");
        dialog.select("x86:LE:64:default");
        dialog.cancel();
        assert!(dialog.cancelled);
        assert!(dialog.selected.is_none());
    }

    #[test]
    fn test_script_preferences() {
        let mut prefs = ScriptPreferences::new();
        assert!(prefs.get("key").is_none());

        prefs.set("key", "value");
        assert_eq!(prefs.get("key"), Some("value"));
        assert!(prefs.has("key"));

        prefs.remove("key");
        assert!(!prefs.has("key"));
    }

    #[test]
    fn test_ask_dialog_type_display() {
        for t in [
            AskDialogType::String,
            AskDialogType::Int,
            AskDialogType::Long,
            AskDialogType::Double,
            AskDialogType::Bytes,
        ] {
            assert!(!t.label().is_empty());
        }
    }
}
