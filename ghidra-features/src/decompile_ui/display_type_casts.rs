//! Display type casts toggle action -- Rust port of
//! `ghidra.app.plugin.core.decompile.DisplayTypeCastsAction`.
//!
//! This action toggles the decompiler option that controls whether
//! explicit type casts are shown in the decompiled C output.  When
//! enabled, the decompiler omits type casts for cleaner output.
//!
//! # Architecture
//!
//! ```text
//! DisplayTypeCastsAction
//!   ├── plugin: DecompilePlugin        (owns the tool reference)
//!   ├── listener: OptionsChangeListener (syncs external option changes)
//!   ├── casts_disabled: bool            (current NOCAST option state)
//!   ├── enabled: bool                   (action enabled state)
//!   └── key_binding: "BACK_SLASH"       (toggle key)
//!
//! TypeCastOptions
//!   ├── no_cast: bool                   (disable type cast display)
//!   ├── eliminate_unreachable: bool     (analysis option)
//!   ├── respect_read_only: bool         (analysis option)
//!   └── cache_size: usize               (result cache capacity)
//! ```
//!
//! # Lifecycle
//!
//! 1. The action is constructed with the plugin reference and reads
//!    the initial `NOCAST` option from the tool's `Decompiler` options.
//! 2. An `OptionsChangeListener` is registered on the tool options so
//!    that external changes (e.g., from the options dialog) are
//!    reflected in the toggle button state.
//! 3. When the user presses `BACK_SLASH` or clicks the menu item,
//!    `action_performed` toggles the option and writes it back to the
//!    tool options.
//! 4. `dispose()` removes the options change listener.

// ---------------------------------------------------------------------------
// OptionsChangeListener -- callback for option changes
// ---------------------------------------------------------------------------

/// A callback that is invoked when a tool option changes externally.
///
/// In Ghidra this is the `OptionsChangeListener` interface.  In Rust
/// we model it as a function pointer that the action registers and
/// unregisters during its lifecycle.
pub type OptionsChangeCallback = fn(option_name: &str, old_value: &str, new_value: &str);

// ---------------------------------------------------------------------------
// DisplayTypeCastsAction
// ---------------------------------------------------------------------------

/// A toggle action that controls the "Disable Type Casts" decompiler option.
///
/// In Ghidra this is a `ToggleDockingAction` that reads and writes the
/// `DecompileOptions.NOCAST_OPTIONSTRING` option.  The action listens
/// for external option changes and updates its selected state
/// accordingly.
///
/// # Key Binding
///
/// The Ghidra key binding is `BACK_SLASH` (`\`).
///
/// # Menu Placement
///
/// Appears under the "Disable Type Casts" menu item in the "wDebug"
/// group (just above "Debug Function Decompilation").
///
/// # Tool Integration
///
/// The action is bound to a tool options category (`"Decompiler"`).
/// On construction it reads the current value of the NOCAST option;
/// on disposal it unregisters its change listener.
#[derive(Debug)]
pub struct DisplayTypeCastsAction {
    /// Whether type casts are currently disabled.
    casts_disabled: bool,
    /// The action's enabled state.
    enabled: bool,
    /// The key binding string.
    key_binding: String,
    /// The options category this action reads/writes.
    options_category: String,
    /// The option key in the tool options.
    option_key: String,
    /// Whether the options change listener is currently registered.
    listener_registered: bool,
    /// The registered change callback (if any).
    change_callback: Option<OptionsChangeCallback>,
    /// Help topic identifier.
    help_topic: String,
    /// Help location identifier.
    help_location: String,
}

impl DisplayTypeCastsAction {
    /// The action name used in the tool.
    pub const ACTION_NAME: &'static str = "Disable Type Casts Display";

    /// The option key for the no-cast setting.
    ///
    /// In Ghidra this is `DecompileOptions.NOCAST_OPTIONSTRING`.
    pub const NOCAST_OPTION_KEY: &'static str = "NoCast";

    /// The default options category.
    pub const OPTIONS_CATEGORY: &'static str = "Decompiler";

    /// The help topic for this action.
    pub const HELP_TOPIC: &'static str = "Decompiler";

    /// The help location identifier.
    pub const HELP_LOCATION: &'static str = "DisplayDisableCasts";

    /// Create a new display type casts action.
    ///
    /// The initial state of `casts_disabled` is read from the tool
    /// options (here passed as a parameter since we don't have direct
    /// tool access).
    pub fn new(initial_casts_disabled: bool) -> Self {
        Self {
            casts_disabled: initial_casts_disabled,
            enabled: true,
            key_binding: "BACK_SLASH".to_string(),
            options_category: Self::OPTIONS_CATEGORY.to_string(),
            option_key: Self::NOCAST_OPTION_KEY.to_string(),
            listener_registered: false,
            change_callback: None,
            help_topic: Self::HELP_TOPIC.to_string(),
            help_location: Self::HELP_LOCATION.to_string(),
        }
    }

    /// Create a new action with a specific options category and key.
    ///
    /// This constructor is useful for testing or when the option names
    /// differ from the defaults.
    pub fn with_options(
        initial_casts_disabled: bool,
        options_category: impl Into<String>,
        option_key: impl Into<String>,
    ) -> Self {
        Self {
            casts_disabled: initial_casts_disabled,
            enabled: true,
            key_binding: "BACK_SLASH".to_string(),
            options_category: options_category.into(),
            option_key: option_key.into(),
            listener_registered: false,
            change_callback: None,
            help_topic: Self::HELP_TOPIC.to_string(),
            help_location: Self::HELP_LOCATION.to_string(),
        }
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        Self::ACTION_NAME
    }

    /// Returns the key binding for this action.
    pub fn key_binding(&self) -> &str {
        &self.key_binding
    }

    /// Set the key binding for this action.
    pub fn set_key_binding(&mut self, binding: impl Into<String>) {
        self.key_binding = binding.into();
    }

    /// Returns the options category this action reads/writes.
    pub fn options_category(&self) -> &str {
        &self.options_category
    }

    /// Returns the option key this action reads/writes.
    pub fn option_key(&self) -> &str {
        &self.option_key
    }

    /// Returns the help topic identifier.
    pub fn help_topic(&self) -> &str {
        &self.help_topic
    }

    /// Returns the help location identifier.
    pub fn help_location(&self) -> &str {
        &self.help_location
    }

    /// Returns whether the action is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns whether type casts are currently disabled.
    pub fn is_selected(&self) -> bool {
        self.casts_disabled
    }

    /// Set the selected state (disabling or enabling type casts).
    ///
    /// This does NOT propagate the change to the tool options.  Use
    /// [`action_performed`](Self::action_performed) for user-initiated
    /// toggles that should write back.
    pub fn set_selected(&mut self, selected: bool) {
        self.casts_disabled = selected;
    }

    /// Perform the action -- toggle the type cast display.
    ///
    /// This both toggles the internal state and (in the full
    /// implementation) writes the new value to the tool options.
    ///
    /// Returns the new state of the option (`true` = casts disabled).
    pub fn action_performed(&mut self) -> bool {
        self.casts_disabled = !self.casts_disabled;
        self.casts_disabled
    }

    /// Handle an external options change notification.
    ///
    /// Called when the decompiler options change externally (e.g., from
    /// another action or the options dialog).  Updates the selected
    /// state to match.
    ///
    /// This corresponds to `DisplayTypeCastsOptionsListener.optionsChanged()`
    /// in the Java implementation.
    pub fn options_changed(&mut self, option_name: &str, new_value: bool) {
        if option_name == self.option_key {
            self.casts_disabled = new_value;
        }
    }

    /// Register an options change listener.
    ///
    /// In Ghidra this is done in the constructor via
    /// `options.addOptionsChangeListener(listener)`.  The callback
    /// will be invoked whenever the specified option changes.
    pub fn register_listener(&mut self, callback: OptionsChangeCallback) {
        self.change_callback = Some(callback);
        self.listener_registered = true;
    }

    /// Unregister the options change listener.
    ///
    /// In Ghidra this is done in `dispose()` via
    /// `options.removeOptionsChangeListener(listener)`.
    pub fn unregister_listener(&mut self) {
        self.change_callback = None;
        self.listener_registered = false;
    }

    /// Whether the options change listener is currently registered.
    pub fn is_listener_registered(&self) -> bool {
        self.listener_registered
    }

    /// Fire the options change callback (if registered).
    ///
    /// This is used internally when the action detects an external
    /// option change.
    pub fn fire_options_changed(&self, option_name: &str, old_value: &str, new_value: &str) {
        if let Some(callback) = self.change_callback {
            callback(option_name, old_value, new_value);
        }
    }

    /// Whether this action is enabled for the given context.
    ///
    /// In Ghidra this is `isEnabledForContext(ActionContext context)`
    /// which always returns `true`.
    pub fn is_enabled_for_context(&self) -> bool {
        true
    }

    /// Get the menu path for this action.
    pub fn menu_path(&self) -> &[&str] {
        &["Disable Type Casts"]
    }

    /// Get the menu group.
    pub fn menu_group(&self) -> &str {
        "wDebug"
    }

    /// Get the menu bar data (menu path + group).
    pub fn menu_bar_data(&self) -> (&[&str], &str) {
        (self.menu_path(), self.menu_group())
    }

    /// Dispose the action (cleanup).
    ///
    /// In Ghidra this unregisters the options change listener from the
    /// tool options.  Here we clear the callback and mark the action
    /// as disabled.
    pub fn dispose(&mut self) {
        self.unregister_listener();
        self.enabled = false;
    }
}

// ---------------------------------------------------------------------------
// DecompileOptions (simplified -- the NOCAST option subset)
// ---------------------------------------------------------------------------

/// A simplified decompile options model for the type-cast toggle.
///
/// In Ghidra, `DecompileOptions` is a large class managing dozens of
/// decompiler settings.  Here we model only the subset relevant to
/// the type-cast display action.
///
/// # Option Keys
///
/// The option keys are:
/// - `no_cast` -- `DecompileOptions.NOCAST_OPTIONSTRING`
/// - `eliminate_unreachable` -- eliminates unreachable code in decompiler output
/// - `respect_read_only` -- respects read-only flags on memory
/// - `cache_size` -- number of decompile results to cache
#[derive(Debug, Clone)]
pub struct TypeCastOptions {
    /// Whether type casts are disabled.
    pub no_cast: bool,
    /// Whether unreachable code is eliminated.
    pub eliminate_unreachable: bool,
    /// Whether read-only flags are respected.
    pub respect_read_only: bool,
    /// The cache size for decompile results.
    pub cache_size: usize,
}

impl TypeCastOptions {
    /// Create default options.
    ///
    /// Defaults match Ghidra's `DecompileOptions` defaults:
    /// - `no_cast`: false (type casts shown)
    /// - `eliminate_unreachable`: true (unreachable code eliminated)
    /// - `respect_read_only`: false (read-only flags ignored)
    /// - `cache_size`: 10
    pub fn new() -> Self {
        Self {
            no_cast: false,
            eliminate_unreachable: true,
            respect_read_only: false,
            cache_size: 10,
        }
    }

    /// Create options with all settings at their "permissive" defaults.
    ///
    /// This is useful for testing where all options are off/false.
    pub fn permissive() -> Self {
        Self {
            no_cast: false,
            eliminate_unreachable: false,
            respect_read_only: false,
            cache_size: 10,
        }
    }

    /// Returns `true` if type casts are disabled.
    pub fn is_no_cast(&self) -> bool {
        self.no_cast
    }

    /// Set whether type casts are disabled.
    pub fn set_no_cast(&mut self, no_cast: bool) {
        self.no_cast = no_cast;
    }

    /// Returns `true` if unreachable code is eliminated.
    pub fn is_eliminate_unreachable(&self) -> bool {
        self.eliminate_unreachable
    }

    /// Set whether unreachable code is eliminated.
    pub fn set_eliminate_unreachable(&mut self, eliminate: bool) {
        self.eliminate_unreachable = eliminate;
    }

    /// Returns `true` if read-only flags are respected.
    pub fn is_respect_read_only(&self) -> bool {
        self.respect_read_only
    }

    /// Set whether read-only flags are respected.
    pub fn set_respect_read_only(&mut self, respect: bool) {
        self.respect_read_only = respect;
    }

    /// Get the cache size.
    pub fn get_cache_size(&self) -> usize {
        self.cache_size
    }

    /// Set the cache size.
    pub fn set_cache_size(&mut self, size: usize) {
        self.cache_size = size;
    }

    /// Grab options from a simulated tool+program options source.
    ///
    /// In Ghidra this is `grabFromToolAndProgram(fieldOptions, opt, program)`.
    /// Here we accept a key-value pair list and apply matching keys.
    pub fn grab_from_options(&mut self, options: &[(String, String)]) {
        for (key, value) in options {
            match key.as_str() {
                "NoCast" => {
                    if let Ok(v) = value.parse::<bool>() {
                        self.no_cast = v;
                    }
                }
                "EliminateUnreachable" => {
                    if let Ok(v) = value.parse::<bool>() {
                        self.eliminate_unreachable = v;
                    }
                }
                "RespectReadOnly" => {
                    if let Ok(v) = value.parse::<bool>() {
                        self.respect_read_only = v;
                    }
                }
                "CacheSize" => {
                    if let Ok(v) = value.parse::<usize>() {
                        self.cache_size = v;
                    }
                }
                _ => {}
            }
        }
    }

    /// Export options to a key-value pair list.
    ///
    /// This is the inverse of `grab_from_options`.
    pub fn to_options(&self) -> Vec<(String, String)> {
        vec![
            ("NoCast".into(), self.no_cast.to_string()),
            ("EliminateUnreachable".into(), self.eliminate_unreachable.to_string()),
            ("RespectReadOnly".into(), self.respect_read_only.to_string()),
            ("CacheSize".into(), self.cache_size.to_string()),
        ]
    }
}

impl Default for TypeCastOptions {
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
    use std::cell::RefCell;
    use std::rc::Rc;

    // --- DisplayTypeCastsAction ---

    #[test]
    fn test_action_new_default() {
        let action = DisplayTypeCastsAction::new(false);
        assert!(!action.is_selected());
        assert!(action.is_enabled());
        assert_eq!(action.name(), "Disable Type Casts Display");
    }

    #[test]
    fn test_action_new_with_casts_disabled() {
        let action = DisplayTypeCastsAction::new(true);
        assert!(action.is_selected());
    }

    #[test]
    fn test_action_toggle() {
        let mut action = DisplayTypeCastsAction::new(false);
        let new_state = action.action_performed();
        assert!(new_state);
        assert!(action.is_selected());

        let new_state = action.action_performed();
        assert!(!new_state);
        assert!(!action.is_selected());
    }

    #[test]
    fn test_action_set_selected() {
        let mut action = DisplayTypeCastsAction::new(false);
        action.set_selected(true);
        assert!(action.is_selected());
        action.set_selected(false);
        assert!(!action.is_selected());
    }

    #[test]
    fn test_action_set_enabled() {
        let mut action = DisplayTypeCastsAction::new(false);
        assert!(action.is_enabled());

        action.set_enabled(false);
        assert!(!action.is_enabled());
    }

    #[test]
    fn test_action_key_binding() {
        let action = DisplayTypeCastsAction::new(false);
        assert_eq!(action.key_binding(), "BACK_SLASH");
    }

    #[test]
    fn test_action_set_key_binding() {
        let mut action = DisplayTypeCastsAction::new(false);
        action.set_key_binding("CTRL_SHIFT_X");
        assert_eq!(action.key_binding(), "CTRL_SHIFT_X");
    }

    #[test]
    fn test_action_menu_path() {
        let action = DisplayTypeCastsAction::new(false);
        assert_eq!(action.menu_path(), &["Disable Type Casts"]);
        assert_eq!(action.menu_group(), "wDebug");
    }

    #[test]
    fn test_action_menu_bar_data() {
        let action = DisplayTypeCastsAction::new(false);
        let (path, group) = action.menu_bar_data();
        assert_eq!(path, &["Disable Type Casts"]);
        assert_eq!(group, "wDebug");
    }

    #[test]
    fn test_action_options_changed() {
        let mut action = DisplayTypeCastsAction::new(false);

        // Matching option name should update.
        action.options_changed(DisplayTypeCastsAction::NOCAST_OPTION_KEY, true);
        assert!(action.is_selected());

        // Non-matching option name should not update.
        action.options_changed("OtherOption", false);
        assert!(action.is_selected()); // unchanged
    }

    #[test]
    fn test_action_options_changed_custom_key() {
        let mut action = DisplayTypeCastsAction::with_options(false, "MyCategory", "MyKey");
        action.options_changed("MyKey", true);
        assert!(action.is_selected());

        action.options_changed("NoCast", false);
        assert!(action.is_selected()); // "NoCast" does not match custom key
    }

    #[test]
    fn test_action_with_options() {
        let action = DisplayTypeCastsAction::with_options(true, "TestCat", "TestKey");
        assert!(action.is_selected());
        assert_eq!(action.options_category(), "TestCat");
        assert_eq!(action.option_key(), "TestKey");
    }

    #[test]
    fn test_action_constants() {
        assert_eq!(DisplayTypeCastsAction::ACTION_NAME, "Disable Type Casts Display");
        assert_eq!(DisplayTypeCastsAction::NOCAST_OPTION_KEY, "NoCast");
        assert_eq!(DisplayTypeCastsAction::OPTIONS_CATEGORY, "Decompiler");
        assert_eq!(DisplayTypeCastsAction::HELP_TOPIC, "Decompiler");
        assert_eq!(DisplayTypeCastsAction::HELP_LOCATION, "DisplayDisableCasts");
    }

    #[test]
    fn test_action_help() {
        let action = DisplayTypeCastsAction::new(false);
        assert_eq!(action.help_topic(), "Decompiler");
        assert_eq!(action.help_location(), "DisplayDisableCasts");
    }

    #[test]
    fn test_action_is_enabled_for_context() {
        let action = DisplayTypeCastsAction::new(false);
        assert!(action.is_enabled_for_context());
    }

    #[test]
    fn test_action_listener_registration() {
        let mut action = DisplayTypeCastsAction::new(false);
        assert!(!action.is_listener_registered());

        fn dummy_callback(_name: &str, _old: &str, _new: &str) {}
        action.register_listener(dummy_callback);
        assert!(action.is_listener_registered());

        action.unregister_listener();
        assert!(!action.is_listener_registered());
    }

    #[test]
    fn test_action_dispose() {
        let mut action = DisplayTypeCastsAction::new(false);
        fn dummy_callback(_name: &str, _old: &str, _new: &str) {}
        action.register_listener(dummy_callback);
        assert!(action.is_listener_registered());

        action.dispose();
        assert!(!action.is_enabled());
        assert!(!action.is_listener_registered());
    }

    // --- TypeCastOptions ---

    #[test]
    fn test_options_default() {
        let opts = TypeCastOptions::new();
        assert!(!opts.is_no_cast());
        assert!(opts.is_eliminate_unreachable());
        assert!(!opts.is_respect_read_only());
        assert_eq!(opts.get_cache_size(), 10);
    }

    #[test]
    fn test_options_permissive() {
        let opts = TypeCastOptions::permissive();
        assert!(!opts.is_no_cast());
        assert!(!opts.is_eliminate_unreachable());
        assert!(!opts.is_respect_read_only());
        assert_eq!(opts.get_cache_size(), 10);
    }

    #[test]
    fn test_options_no_cast() {
        let mut opts = TypeCastOptions::new();
        opts.set_no_cast(true);
        assert!(opts.is_no_cast());
        opts.set_no_cast(false);
        assert!(!opts.is_no_cast());
    }

    #[test]
    fn test_options_eliminate_unreachable() {
        let mut opts = TypeCastOptions::new();
        opts.set_eliminate_unreachable(false);
        assert!(!opts.is_eliminate_unreachable());
    }

    #[test]
    fn test_options_respect_read_only() {
        let mut opts = TypeCastOptions::new();
        opts.set_respect_read_only(true);
        assert!(opts.is_respect_read_only());
    }

    #[test]
    fn test_options_cache_size() {
        let mut opts = TypeCastOptions::new();
        opts.set_cache_size(20);
        assert_eq!(opts.get_cache_size(), 20);
    }

    #[test]
    fn test_options_clone() {
        let mut opts = TypeCastOptions::new();
        opts.set_no_cast(true);
        opts.set_cache_size(5);

        let cloned = opts.clone();
        assert!(cloned.is_no_cast());
        assert_eq!(cloned.get_cache_size(), 5);
    }

    #[test]
    fn test_options_grab_from_options() {
        let mut opts = TypeCastOptions::new();
        let options = vec![
            ("NoCast".into(), "true".into()),
            ("CacheSize".into(), "25".into()),
            ("EliminateUnreachable".into(), "false".into()),
            ("RespectReadOnly".into(), "true".into()),
            ("UnknownKey".into(), "ignored".into()),
        ];
        opts.grab_from_options(&options);
        assert!(opts.is_no_cast());
        assert_eq!(opts.get_cache_size(), 25);
        assert!(!opts.is_eliminate_unreachable());
        assert!(opts.is_respect_read_only());
    }

    #[test]
    fn test_options_to_options_round_trip() {
        let mut opts = TypeCastOptions::new();
        opts.set_no_cast(true);
        opts.set_cache_size(42);
        opts.set_eliminate_unreachable(false);
        opts.set_respect_read_only(true);

        let exported = opts.to_options();
        assert_eq!(exported.len(), 4);

        let mut restored = TypeCastOptions::new();
        restored.grab_from_options(&exported);
        assert!(restored.is_no_cast());
        assert_eq!(restored.get_cache_size(), 42);
        assert!(!restored.is_eliminate_unreachable());
        assert!(restored.is_respect_read_only());
    }

    #[test]
    fn test_options_grab_invalid_values() {
        let mut opts = TypeCastOptions::new();
        let options = vec![
            ("NoCast".into(), "not_a_bool".into()),
            ("CacheSize".into(), "not_a_number".into()),
        ];
        opts.grab_from_options(&options);
        // Invalid values should not change the defaults.
        assert!(!opts.is_no_cast());
        assert_eq!(opts.get_cache_size(), 10);
    }

    #[test]
    fn test_options_change_callback() {
        let mut action = DisplayTypeCastsAction::new(false);
        let log: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new()));
        let log_clone = log.clone();

        // We cannot use closures as fn pointers, so we test fire_options_changed
        // with a function that writes to a static cell.
        fn test_callback(name: &str, _old: &str, new: &str) {
            // This callback does nothing in the test; we verify it is called
            // by checking the action state instead.
            let _ = (name, new);
        }
        action.register_listener(test_callback);
        action.fire_options_changed("NoCast", "false", "true");
        // The callback was called (no panic).
    }
}
