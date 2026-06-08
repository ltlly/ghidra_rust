//! Decompiler options listener -- Rust port of the `OptionsChangeListener`
//! interface from `ghidra.app.plugin.core.decompile.DecompilerProvider`.
//!
//! In Ghidra, the `DecompilerProvider` implements `OptionsChangeListener` to
//! respond to changes in decompiler options and browser field options.  When
//! an option changes, the provider refreshes the decompiler display with
//! the updated settings.
//!
//! # Option Categories
//!
//! The provider listens to two option categories:
//!
//! 1. **`"Decompiler"`** (`DecompilePlugin.OPTIONS_TITLE`) -- the
//!    decompiler-specific options (display format, comment style, brace
//!    style, etc.).
//!
//! 2. **`"Browser Fields"`** (`GhidraOptions.CATEGORY_BROWSER_FIELDS`) --
//!    general browser field options that affect the decompiler display
//!    (font, colours, etc.).
//!
//! # Refresh Logic
//!
//! When options change, the `doRefresh(true)` path is taken, which:
//!
//! 1. Grabs the latest options from the tool and program.
//! 2. Refreshes the toggle button states (unreachable code, read-only).
//! 3. Updates the controller options.
//! 4. Triggers a re-decompile (unless display is locked).
//!
//! When the program changes (but options haven't), `doRefresh(false)` is
//! called, which preserves the current toggle button states.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// OptionCategory -- the option categories listened to
// ---------------------------------------------------------------------------

/// The option categories that the decompiler provider monitors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OptionCategory {
    /// The "Decompiler" option category.
    Decompiler,
    /// The "Browser Fields" option category.
    BrowserFields,
}

impl OptionCategory {
    /// The string name used by the Ghidra tool infrastructure.
    pub fn name(&self) -> &'static str {
        match self {
            OptionCategory::Decompiler => "Decompiler",
            OptionCategory::BrowserFields => "Browser Fields",
        }
    }

    /// Parse a category name string.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Decompiler" => Some(OptionCategory::Decompiler),
            "Browser Fields" => Some(OptionCategory::BrowserFields),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// DecompilerOption -- individual decompiler options
// ---------------------------------------------------------------------------

/// A decompiler option that can be changed by the user.
///
/// This models the subset of `DecompileOptions` that can be toggled
/// from the provider's toolbar or options dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecompilerOption {
    /// Whether to eliminate unreachable code.
    EliminateUnreachable,
    /// Whether to respect read-only flags on memory.
    RespectReadOnly,
    /// Whether to disable type cast display.
    NoCast,
    /// The decompiler output language (e.g., "c-language").
    Language,
    /// The integer display format (hex, dec, oct, etc.).
    IntegerFormat,
    /// The comment style (C, C++, end-of-line).
    CommentStyle,
    /// The brace style (same line, next line).
    BraceStyle,
}

// ---------------------------------------------------------------------------
// OptionChangeEvent -- a change notification
// ---------------------------------------------------------------------------

/// An event describing an option change.
#[derive(Debug, Clone)]
pub struct OptionChangeEvent {
    /// The category that changed.
    pub category: OptionCategory,
    /// The specific option name (if known).
    pub option_name: Option<String>,
    /// The previous value (as a string representation).
    pub old_value: Option<String>,
    /// The new value (as a string representation).
    pub new_value: Option<String>,
}

// ---------------------------------------------------------------------------
// RefreshMode -- how to refresh after options change
// ---------------------------------------------------------------------------

/// How the decompiler should refresh after an options change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshMode {
    /// Full refresh: grab new options, update toggles, re-decompile.
    Full,
    /// Preserve toggles: grab new options but keep current toggle states.
    PreserveToggles,
    /// No refresh (e.g., display is locked).
    None,
}

// ---------------------------------------------------------------------------
// OptionsSyncResult -- result of an options synchronization
// ---------------------------------------------------------------------------

/// The result of synchronising options from the tool and program.
#[derive(Debug, Clone)]
pub struct OptionsSyncResult {
    /// Whether the eliminate-unreachable option changed.
    pub eliminate_unreachable_changed: bool,
    /// Whether the respect-read-only option changed.
    pub respect_read_only_changed: bool,
    /// Whether any option changed at all.
    pub any_changed: bool,
    /// The current eliminate-unreachable value after sync.
    pub eliminate_unreachable: bool,
    /// The current respect-read-only value after sync.
    pub respect_read_only: bool,
}

// ---------------------------------------------------------------------------
// DecompilerOptionsState -- tracks the current options state
// ---------------------------------------------------------------------------

/// Tracks the current decompiler options state.
///
/// This is the Rust equivalent of the option values stored in the Java
/// `DecompileOptions` object that the provider maintains.
#[derive(Debug, Clone)]
pub struct DecompilerOptionsState {
    /// Whether to eliminate unreachable code.
    pub eliminate_unreachable: bool,
    /// Whether to respect read-only flags.
    pub respect_read_only: bool,
    /// Whether type casts are disabled.
    pub no_cast: bool,
    /// The integer display format.
    pub integer_format: IntegerFormat,
    /// The brace style.
    pub brace_style: BraceStyle,
    /// The comment style.
    pub comment_style: CommentStyle,
    /// Option change history (most recent first).
    change_history: Vec<OptionChangeEvent>,
    /// Maximum history size.
    max_history: usize,
}

/// Integer display format options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntegerFormat {
    /// Hexadecimal (0x prefix).
    Hex,
    /// Decimal.
    Decimal,
    /// Octal (0 prefix).
    Octal,
    /// Binary (0b prefix).
    Binary,
}

/// Brace style options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BraceStyle {
    /// Opening brace on the same line as the control statement.
    SameLine,
    /// Opening brace on the next line.
    NextLine,
}

/// Comment style options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommentStyle {
    /// C-style comments (/* ... */).
    CStyle,
    /// C++ style comments (// ...).
    CppStyle,
    /// End-of-line comments.
    EndOfLine,
}

impl DecompilerOptionsState {
    /// Create a new options state with default values.
    pub fn new() -> Self {
        Self {
            eliminate_unreachable: true,
            respect_read_only: false,
            no_cast: false,
            integer_format: IntegerFormat::Hex,
            brace_style: BraceStyle::SameLine,
            comment_style: CommentStyle::CStyle,
            change_history: Vec::new(),
            max_history: 50,
        }
    }

    /// Record an option change.
    pub fn record_change(&mut self, event: OptionChangeEvent) {
        if self.change_history.len() >= self.max_history {
            self.change_history.pop();
        }
        self.change_history.insert(0, event);
    }

    /// Get the change history.
    pub fn change_history(&self) -> &[OptionChangeEvent] {
        &self.change_history
    }

    /// Clear the change history.
    pub fn clear_history(&mut self) {
        self.change_history.clear();
    }

    /// Apply a toggle for eliminate-unreachable.
    ///
    /// Returns `true` if the value actually changed.
    pub fn set_eliminate_unreachable(&mut self, value: bool) -> bool {
        if self.eliminate_unreachable != value {
            self.eliminate_unreachable = value;
            self.record_change(OptionChangeEvent {
                category: OptionCategory::Decompiler,
                option_name: Some("EliminateUnreachable".into()),
                old_value: Some((!value).to_string()),
                new_value: Some(value.to_string()),
            });
            true
        } else {
            false
        }
    }

    /// Apply a toggle for respect-read-only.
    ///
    /// Returns `true` if the value actually changed.
    pub fn set_respect_read_only(&mut self, value: bool) -> bool {
        if self.respect_read_only != value {
            self.respect_read_only = value;
            self.record_change(OptionChangeEvent {
                category: OptionCategory::Decompiler,
                option_name: Some("RespectReadOnly".into()),
                old_value: Some((!value).to_string()),
                new_value: Some(value.to_string()),
            });
            true
        } else {
            false
        }
    }

    /// Apply a toggle for no-cast.
    ///
    /// Returns `true` if the value actually changed.
    pub fn set_no_cast(&mut self, value: bool) -> bool {
        if self.no_cast != value {
            self.no_cast = value;
            self.record_change(OptionChangeEvent {
                category: OptionCategory::Decompiler,
                option_name: Some("NoCast".into()),
                old_value: Some((!value).to_string()),
                new_value: Some(value.to_string()),
            });
            true
        } else {
            false
        }
    }

    /// Sync options from external state (tool + program).
    ///
    /// This models `DecompileOptions.grabFromToolAndProgram()`.  In the
    /// full implementation, this reads option values from the tool's
    /// options panels and the program's properties.
    pub fn sync_from_external(
        &mut self,
        new_eliminate_unreachable: bool,
        new_respect_read_only: bool,
    ) -> OptionsSyncResult {
        let eliminate_changed = self.eliminate_unreachable != new_eliminate_unreachable;
        let respect_changed = self.respect_read_only != new_respect_read_only;

        if eliminate_changed {
            self.set_eliminate_unreachable(new_eliminate_unreachable);
        }
        if respect_changed {
            self.set_respect_read_only(new_respect_read_only);
        }

        OptionsSyncResult {
            eliminate_unreachable_changed: eliminate_changed,
            respect_read_only_changed: respect_changed,
            any_changed: eliminate_changed || respect_changed,
            eliminate_unreachable: self.eliminate_unreachable,
            respect_read_only: self.respect_read_only,
        }
    }
}

impl Default for DecompilerOptionsState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DecompilerOptionsListener -- manages option change handling
// ---------------------------------------------------------------------------

/// Manages the decompiler provider's response to option changes.
///
/// This models the `OptionsChangeListener.optionsChanged()` method from
/// the Java `DecompilerProvider`.  It determines when a refresh is
/// needed and what kind of refresh to perform.
///
/// # Refresh Decision Logic
///
/// ```text
/// optionsChanged(options, name, oldValue, newValue):
///   if options not in [Decompiler, BrowserFields]:
///     return NoRefresh
///   if display is locked:
///     return OverlayMessage
///   if options are Decompiler category:
///     return FullRefresh
///   return PreserveTogglesRefresh
/// ```
#[derive(Debug)]
pub struct DecompilerOptionsListener {
    /// The current options state.
    options: DecompilerOptionsState,
    /// Whether the display is currently locked.
    display_locked: bool,
    /// The categories this listener monitors.
    monitored_categories: Vec<OptionCategory>,
    /// Count of options changes received.
    change_count: usize,
    /// The last option name that changed.
    last_changed_option: Option<String>,
}

impl DecompilerOptionsListener {
    /// Create a new options listener.
    pub fn new() -> Self {
        Self {
            options: DecompilerOptionsState::new(),
            display_locked: false,
            monitored_categories: vec![
                OptionCategory::Decompiler,
                OptionCategory::BrowserFields,
            ],
            change_count: 0,
            last_changed_option: None,
        }
    }

    /// Get the current options state.
    pub fn options(&self) -> &DecompilerOptionsState {
        &self.options
    }

    /// Get a mutable reference to the options state.
    pub fn options_mut(&mut self) -> &mut DecompilerOptionsState {
        &mut self.options
    }

    /// Set whether the display is locked.
    pub fn set_display_locked(&mut self, locked: bool) {
        self.display_locked = locked;
    }

    /// Whether the display is currently locked.
    pub fn is_display_locked(&self) -> bool {
        self.display_locked
    }

    /// The number of option changes received.
    pub fn change_count(&self) -> usize {
        self.change_count
    }

    /// The last option name that changed.
    pub fn last_changed_option(&self) -> Option<&str> {
        self.last_changed_option.as_deref()
    }

    /// Handle an options change notification.
    ///
    /// This is the Rust equivalent of
    /// `DecompilerProvider.optionsChanged(ToolOptions, String, Object, Object)`.
    ///
    /// Returns the appropriate refresh mode.
    pub fn options_changed(
        &mut self,
        category_name: &str,
        option_name: &str,
        _old_value: Option<&str>,
        _new_value: Option<&str>,
    ) -> RefreshMode {
        // Check if the category is one we monitor.
        let category = match OptionCategory::from_name(category_name) {
            Some(cat) if self.monitored_categories.contains(&cat) => cat,
            _ => return RefreshMode::None,
        };

        self.change_count += 1;
        self.last_changed_option = Some(option_name.to_string());

        self.options.record_change(OptionChangeEvent {
            category,
            option_name: Some(option_name.to_string()),
            old_value: _old_value.map(|s| s.to_string()),
            new_value: _new_value.map(|s| s.to_string()),
        });

        // If the display is locked, we don't refresh -- just update the overlay.
        if self.display_locked {
            return RefreshMode::None;
        }

        // For Decompiler category changes, do a full refresh.
        // For BrowserFields, preserve the toggle states.
        match category {
            OptionCategory::Decompiler => RefreshMode::Full,
            OptionCategory::BrowserFields => RefreshMode::PreserveToggles,
        }
    }

    /// Perform a doRefresh with the given mode.
    ///
    /// This models the `doRefresh(boolean optionsChanged)` method.
    pub fn do_refresh(
        &mut self,
        options_changed: bool,
        new_eliminate_unreachable: Option<bool>,
        new_respect_read_only: Option<bool>,
    ) -> (RefreshMode, OptionsSyncResult) {
        // Sync from external options.
        let result = self.options.sync_from_external(
            new_eliminate_unreachable.unwrap_or(self.options.eliminate_unreachable),
            new_respect_read_only.unwrap_or(self.options.respect_read_only),
        );

        let mode = if self.display_locked {
            RefreshMode::None
        } else if options_changed {
            RefreshMode::Full
        } else {
            RefreshMode::PreserveToggles
        };

        (mode, result)
    }

    /// Compute the toggle button states after a refresh.
    ///
    /// In Ghidra, `refreshToggleButtons()` sets the toggle buttons based
    /// on the current option values.  The toggle states are the *inverse*
    /// of the option values: when `eliminateUnreachable` is true, the
    /// "show unreachable code" toggle is NOT selected.
    pub fn compute_toggle_states(&self) -> (bool, bool) {
        (
            !self.options.eliminate_unreachable, // show_unreachable selected
            !self.options.respect_read_only,      // ignore_read_only selected
        )
    }
}

impl Default for DecompilerOptionsListener {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- OptionCategory --

    #[test]
    fn test_option_category_names() {
        assert_eq!(OptionCategory::Decompiler.name(), "Decompiler");
        assert_eq!(OptionCategory::BrowserFields.name(), "Browser Fields");
    }

    #[test]
    fn test_option_category_from_name() {
        assert_eq!(
            OptionCategory::from_name("Decompiler"),
            Some(OptionCategory::Decompiler)
        );
        assert_eq!(
            OptionCategory::from_name("Browser Fields"),
            Some(OptionCategory::BrowserFields)
        );
        assert_eq!(OptionCategory::from_name("Unknown"), None);
    }

    // -- DecompilerOptionsState --

    #[test]
    fn test_options_state_defaults() {
        let opts = DecompilerOptionsState::new();
        assert!(opts.eliminate_unreachable);
        assert!(!opts.respect_read_only);
        assert!(!opts.no_cast);
        assert_eq!(opts.integer_format, IntegerFormat::Hex);
        assert_eq!(opts.brace_style, BraceStyle::SameLine);
        assert_eq!(opts.comment_style, CommentStyle::CStyle);
    }

    #[test]
    fn test_options_state_set_eliminate_unreachable() {
        let mut opts = DecompilerOptionsState::new();
        assert!(opts.eliminate_unreachable);

        let changed = opts.set_eliminate_unreachable(false);
        assert!(changed);
        assert!(!opts.eliminate_unreachable);
        assert_eq!(opts.change_history().len(), 1);

        // Setting the same value should not change.
        let changed = opts.set_eliminate_unreachable(false);
        assert!(!changed);
        assert_eq!(opts.change_history().len(), 1);
    }

    #[test]
    fn test_options_state_set_respect_read_only() {
        let mut opts = DecompilerOptionsState::new();
        let changed = opts.set_respect_read_only(true);
        assert!(changed);
        assert!(opts.respect_read_only);
    }

    #[test]
    fn test_options_state_set_no_cast() {
        let mut opts = DecompilerOptionsState::new();
        let changed = opts.set_no_cast(true);
        assert!(changed);
        assert!(opts.no_cast);
    }

    #[test]
    fn test_options_state_change_history() {
        let mut opts = DecompilerOptionsState::new();
        opts.set_eliminate_unreachable(false);
        opts.set_respect_read_only(true);
        opts.set_no_cast(true);

        assert_eq!(opts.change_history().len(), 3);
        // Most recent first.
        assert_eq!(
            opts.change_history()[0].option_name.as_deref(),
            Some("NoCast")
        );
    }

    #[test]
    fn test_options_state_history_ring_eviction() {
        let mut opts = DecompilerOptionsState::new();
        opts.max_history = 3;

        opts.set_eliminate_unreachable(false);
        opts.set_respect_read_only(true);
        opts.set_no_cast(true);
        assert_eq!(opts.change_history().len(), 3);

        // This should evict the oldest.
        opts.set_eliminate_unreachable(true);
        assert_eq!(opts.change_history().len(), 3);
        assert_eq!(
            opts.change_history()[0].option_name.as_deref(),
            Some("EliminateUnreachable")
        );
    }

    #[test]
    fn test_options_state_clear_history() {
        let mut opts = DecompilerOptionsState::new();
        opts.set_eliminate_unreachable(false);
        opts.clear_history();
        assert!(opts.change_history().is_empty());
    }

    #[test]
    fn test_options_state_sync_from_external() {
        let mut opts = DecompilerOptionsState::new();
        assert!(opts.eliminate_unreachable);
        assert!(!opts.respect_read_only);

        let result = opts.sync_from_external(false, true);
        assert!(result.eliminate_unreachable_changed);
        assert!(result.respect_read_only_changed);
        assert!(result.any_changed);
        assert!(!result.eliminate_unreachable);
        assert!(result.respect_read_only);
    }

    #[test]
    fn test_options_state_sync_no_change() {
        let mut opts = DecompilerOptionsState::new();
        let result = opts.sync_from_external(true, false);
        assert!(!result.eliminate_unreachable_changed);
        assert!(!result.respect_read_only_changed);
        assert!(!result.any_changed);
    }

    // -- DecompilerOptionsListener --

    #[test]
    fn test_options_listener_new() {
        let listener = DecompilerOptionsListener::new();
        assert!(!listener.is_display_locked());
        assert_eq!(listener.change_count(), 0);
        assert!(listener.last_changed_option().is_none());
    }

    #[test]
    fn test_options_listener_handles_decompiler_category() {
        let mut listener = DecompilerOptionsListener::new();
        let mode = listener.options_changed("Decompiler", "NoCast", Some("false"), Some("true"));
        assert_eq!(mode, RefreshMode::Full);
        assert_eq!(listener.change_count(), 1);
        assert_eq!(listener.last_changed_option(), Some("NoCast"));
    }

    #[test]
    fn test_options_listener_handles_browser_fields() {
        let mut listener = DecompilerOptionsListener::new();
        let mode = listener.options_changed("Browser Fields", "Font", Some("Arial"), Some("Mono"));
        assert_eq!(mode, RefreshMode::PreserveToggles);
        assert_eq!(listener.change_count(), 1);
    }

    #[test]
    fn test_options_listener_ignores_unknown_category() {
        let mut listener = DecompilerOptionsListener::new();
        let mode = listener.options_changed("Unknown", "Foo", None, None);
        assert_eq!(mode, RefreshMode::None);
        assert_eq!(listener.change_count(), 0);
    }

    #[test]
    fn test_options_listener_display_locked() {
        let mut listener = DecompilerOptionsListener::new();
        listener.set_display_locked(true);

        let mode = listener.options_changed("Decompiler", "NoCast", Some("false"), Some("true"));
        assert_eq!(mode, RefreshMode::None);
        // Change count still increments even when locked.
        assert_eq!(listener.change_count(), 1);
    }

    #[test]
    fn test_options_listener_do_refresh_full() {
        let mut listener = DecompilerOptionsListener::new();
        let (mode, result) = listener.do_refresh(true, Some(false), Some(true));
        assert_eq!(mode, RefreshMode::Full);
        assert!(result.eliminate_unreachable_changed);
        assert!(result.respect_read_only_changed);
    }

    #[test]
    fn test_options_listener_do_refresh_preserve_toggles() {
        let mut listener = DecompilerOptionsListener::new();
        let (mode, _) = listener.do_refresh(false, None, None);
        assert_eq!(mode, RefreshMode::PreserveToggles);
    }

    #[test]
    fn test_options_listener_do_refresh_locked() {
        let mut listener = DecompilerOptionsListener::new();
        listener.set_display_locked(true);
        let (mode, _) = listener.do_refresh(true, Some(false), Some(true));
        assert_eq!(mode, RefreshMode::None);
    }

    #[test]
    fn test_options_listener_toggle_states() {
        let mut listener = DecompilerOptionsListener::new();
        // Default: eliminate_unreachable=true, respect_read_only=false
        // Toggle states: show_unreachable=false, ignore_read_only=true
        let (show_unreachable, ignore_read_only) = listener.compute_toggle_states();
        assert!(!show_unreachable);
        assert!(ignore_read_only);

        // After changing options.
        listener.options_mut().set_eliminate_unreachable(false);
        listener.options_mut().set_respect_read_only(true);
        let (show_unreachable, ignore_read_only) = listener.compute_toggle_states();
        assert!(show_unreachable);
        assert!(!ignore_read_only);
    }

    #[test]
    fn test_options_listener_multiple_changes() {
        let mut listener = DecompilerOptionsListener::new();
        listener.options_changed("Decompiler", "NoCast", Some("false"), Some("true"));
        listener.options_changed("Browser Fields", "Font", Some("A"), Some("B"));
        listener.options_changed("Decompiler", "BraceStyle", Some("SameLine"), Some("NextLine"));

        assert_eq!(listener.change_count(), 3);
        assert_eq!(
            listener.last_changed_option(),
            Some("BraceStyle")
        );
    }

    // -- OptionsSyncResult --

    #[test]
    fn test_options_sync_result_clone() {
        let result = OptionsSyncResult {
            eliminate_unreachable_changed: true,
            respect_read_only_changed: false,
            any_changed: true,
            eliminate_unreachable: false,
            respect_read_only: false,
        };
        let cloned = result.clone();
        assert!(cloned.eliminate_unreachable_changed);
        assert!(!cloned.respect_read_only_changed);
    }

    // -- OptionChangeEvent --

    #[test]
    fn test_option_change_event_clone() {
        let event = OptionChangeEvent {
            category: OptionCategory::Decompiler,
            option_name: Some("NoCast".into()),
            old_value: Some("false".into()),
            new_value: Some("true".into()),
        };
        let cloned = event.clone();
        assert_eq!(cloned.category, OptionCategory::Decompiler);
        assert_eq!(cloned.option_name.as_deref(), Some("NoCast"));
    }

    // -- Integration tests --

    #[test]
    fn test_full_options_workflow() {
        let mut listener = DecompilerOptionsListener::new();

        // Initial state.
        assert!(listener.options().eliminate_unreachable);
        assert!(!listener.options().respect_read_only);

        // User clicks the "toggle unreachable code" button.
        let mode = listener.options_changed(
            "Decompiler",
            "EliminateUnreachable",
            Some("true"),
            Some("false"),
        );
        assert_eq!(mode, RefreshMode::Full);

        // doRefresh is called.
        let (refresh_mode, result) = listener.do_refresh(true, Some(false), None);
        assert_eq!(refresh_mode, RefreshMode::Full);
        assert!(result.eliminate_unreachable_changed);
        assert!(!listener.options().eliminate_unreachable);

        // Toggle button states are updated.
        let (show_unreachable, _) = listener.compute_toggle_states();
        assert!(show_unreachable);
    }

    #[test]
    fn test_display_locked_defers_refresh() {
        let mut listener = DecompilerOptionsListener::new();

        // Lock the display.
        listener.set_display_locked(true);

        // Option change arrives but display is locked.
        let mode = listener.options_changed("Decompiler", "NoCast", Some("false"), Some("true"));
        assert_eq!(mode, RefreshMode::None);

        // Unlocking the display.
        listener.set_display_locked(false);

        // Now a refresh should work.
        let (mode, _) = listener.do_refresh(true, None, None);
        assert_eq!(mode, RefreshMode::Full);
    }

    #[test]
    fn test_options_default() {
        let listener = DecompilerOptionsListener::default();
        assert!(!listener.is_display_locked());
        assert_eq!(listener.change_count(), 0);
    }

    #[test]
    fn test_options_state_default() {
        let opts = DecompilerOptionsState::default();
        assert!(opts.eliminate_unreachable);
        assert!(opts.change_history().is_empty());
    }
}
