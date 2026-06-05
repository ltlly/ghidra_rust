//! Next/Previous navigation plugins.
//!
//! Ported from `ghidra.app.plugin.core.navigation.NextPrevAddressPlugin`,
//! `NextPrevCodeUnitPlugin`, `NextPreviousBookmarkAction`,
//! `NextPreviousFunctionAction`, `NextPreviousInstructionAction`,
//! `NextPreviousLabelAction`, `NextPreviousSameBytesAction`,
//! `NextPreviousUndefinedAction`, and related classes.
//!
//! These plugins provide back/forward navigation through the code browser,
//! including navigation to specific types of code units (instructions,
//! data, functions, labels, bookmarks, etc.).

use ghidra_core::Address;

use super::NextPreviousAction;

/// Direction of next/previous navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NavigationDirection {
    /// Navigate forward (next).
    Forward,
    /// Navigate backward (previous).
    Backward,
}

impl NavigationDirection {
    /// Returns the opposite direction.
    pub fn opposite(&self) -> Self {
        match self {
            NavigationDirection::Forward => NavigationDirection::Backward,
            NavigationDirection::Backward => NavigationDirection::Forward,
        }
    }

    /// Returns `true` if this is forward.
    pub fn is_forward(&self) -> bool {
        matches!(self, NavigationDirection::Forward)
    }

    /// Human-readable name.
    pub fn display_name(&self) -> &'static str {
        match self {
            NavigationDirection::Forward => "Forward",
            NavigationDirection::Backward => "Backward",
        }
    }
}

impl std::fmt::Display for NavigationDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

// ---------------------------------------------------------------------------
// NextPrevAddressPlugin
// ---------------------------------------------------------------------------

/// Plugin that provides back/forward navigation through history.
///
/// Ported from `ghidra.app.plugin.core.navigation.NextPrevAddressPlugin`.
/// Maintains actions for Previous/Next Location in History and
/// Previous/Next Function in History.
#[derive(Debug, Clone)]
pub struct NextPrevAddressPlugin {
    /// The menu group for history actions.
    history_menu_group: String,
    /// Whether the plugin is enabled.
    enabled: bool,
    /// Current navigation direction (for inversion).
    direction: NavigationDirection,
}

impl NextPrevAddressPlugin {
    /// The menu group name for history actions.
    pub const HISTORY_MENU_GROUP: &'static str = "1_Menu_History_Group";

    /// Create a new next/prev address plugin.
    pub fn new() -> Self {
        Self {
            history_menu_group: Self::HISTORY_MENU_GROUP.to_string(),
            enabled: true,
            direction: NavigationDirection::Backward, // "Previous" is the default
        }
    }

    /// Returns `true` if the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the plugin.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the current navigation direction.
    pub fn direction(&self) -> NavigationDirection {
        self.direction
    }

    /// Set the navigation direction.
    pub fn set_direction(&mut self, direction: NavigationDirection) {
        self.direction = direction;
    }

    /// Invert the current direction.
    pub fn invert_direction(&mut self) {
        self.direction = self.direction.opposite();
    }

    /// Get the menu group for history actions.
    pub fn history_menu_group(&self) -> &str {
        &self.history_menu_group
    }

    /// Get the action names for the previous/next location actions.
    pub fn action_names() -> (&'static str, &'static str) {
        ("Previous Location in History", "Next Location in History")
    }

    /// Get the action names for the previous/next function actions.
    pub fn function_action_names() -> (&'static str, &'static str) {
        (
            "Previous Function in History",
            "Next Function in History",
        )
    }

    /// The "Clear History" menu path.
    pub fn clear_menu_path() -> [&'static str; 2] {
        ["Navigation", "Clear History"]
    }
}

impl Default for NextPrevAddressPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// NextPrevCodeUnitPlugin
// ---------------------------------------------------------------------------

/// Plugin that provides next/previous navigation to specific code unit types.
///
/// Ported from `ghidra.app.plugin.core.navigation.NextPrevCodeUnitPlugin`.
/// Generates GoTo events based on the type of code unit (instruction,
/// defined data, undefined data, function, label, bookmark, etc.).
#[derive(Debug, Clone)]
pub struct NextPrevCodeUnitPlugin {
    /// The current direction for all next/prev actions.
    direction: NavigationDirection,
    /// Which types of navigation are enabled.
    enabled_actions: Vec<NextPreviousAction>,
    /// Whether the direction is inverted from the default.
    inverted: bool,
}

impl NextPrevCodeUnitPlugin {
    /// Create a new next/prev code unit plugin with all actions enabled.
    pub fn new() -> Self {
        Self {
            direction: NavigationDirection::Forward,
            enabled_actions: vec![
                NextPreviousAction::Instruction,
                NextPreviousAction::DefinedData,
                NextPreviousAction::Undefined,
                NextPreviousAction::Function,
                NextPreviousAction::Label,
                NextPreviousAction::Bookmark,
                NextPreviousAction::SameBytes,
                NextPreviousAction::HighlightedRange,
                NextPreviousAction::SelectedRange,
            ],
            inverted: false,
        }
    }

    /// Get the current direction.
    pub fn direction(&self) -> NavigationDirection {
        self.direction
    }

    /// Set the direction.
    pub fn set_direction(&mut self, direction: NavigationDirection) {
        self.direction = direction;
    }

    /// Toggle the direction.
    pub fn toggle_direction(&mut self) {
        self.direction = self.direction.opposite();
    }

    /// Whether the direction is inverted from the default.
    pub fn is_inverted(&self) -> bool {
        self.inverted
    }

    /// Set whether the direction is inverted.
    pub fn set_inverted(&mut self, inverted: bool) {
        self.inverted = inverted;
    }

    /// Check if a specific action type is enabled.
    pub fn is_action_enabled(&self, action: NextPreviousAction) -> bool {
        self.enabled_actions.contains(&action)
    }

    /// Enable or disable a specific action type.
    pub fn set_action_enabled(&mut self, action: NextPreviousAction, enabled: bool) {
        if enabled && !self.enabled_actions.contains(&action) {
            self.enabled_actions.push(action);
        } else if !enabled {
            self.enabled_actions.retain(|a| *a != action);
        }
    }

    /// Get all enabled action types.
    pub fn enabled_actions(&self) -> &[NextPreviousAction] {
        &self.enabled_actions
    }
}

impl Default for NextPrevCodeUnitPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// NextPreviousBookmarkAction
// ---------------------------------------------------------------------------

/// Action that navigates to the next/previous bookmark.
///
/// Ported from `ghidra.app.plugin.core.navigation.NextPreviousBookmarkAction`.
#[derive(Debug, Clone)]
pub struct NextPreviousBookmarkAction {
    /// Current direction.
    pub direction: NavigationDirection,
    /// Whether to use the current bookmark type filter.
    pub use_type_filter: bool,
    /// Bookmark type filter (None means all types).
    pub type_filter: Option<String>,
    /// Name for display purposes.
    pub name: String,
}

impl NextPreviousBookmarkAction {
    /// Create a new action with the given direction.
    pub fn new(direction: NavigationDirection) -> Self {
        let name = match direction {
            NavigationDirection::Forward => "Next Bookmark".to_string(),
            NavigationDirection::Backward => "Previous Bookmark".to_string(),
        };
        Self {
            direction,
            use_type_filter: false,
            type_filter: None,
            name,
        }
    }

    /// Set the bookmark type filter.
    pub fn set_type_filter(&mut self, filter: Option<String>) {
        self.use_type_filter = filter.is_some();
        self.type_filter = filter;
    }
}

// ---------------------------------------------------------------------------
// NextPreviousFunctionAction
// ---------------------------------------------------------------------------

/// Action that navigates to the next/previous function.
///
/// Ported from `ghidra.app.plugin.core.navigation.NextPreviousFunctionAction`.
#[derive(Debug, Clone)]
pub struct NextPreviousFunctionAction {
    /// Current direction.
    pub direction: NavigationDirection,
    /// Name for display purposes.
    pub name: String,
}

impl NextPreviousFunctionAction {
    /// Create a new action with the given direction.
    pub fn new(direction: NavigationDirection) -> Self {
        let name = match direction {
            NavigationDirection::Forward => "Next Function".to_string(),
            NavigationDirection::Backward => "Previous Function".to_string(),
        };
        Self { direction, name }
    }
}

// ---------------------------------------------------------------------------
// NextPreviousInstructionAction
// ---------------------------------------------------------------------------

/// Action that navigates to the next/previous instruction.
///
/// Ported from `ghidra.app.plugin.core.navigation.NextPreviousInstructionAction`.
#[derive(Debug, Clone)]
pub struct NextPreviousInstructionAction {
    /// Current direction.
    pub direction: NavigationDirection,
    /// Name for display purposes.
    pub name: String,
}

impl NextPreviousInstructionAction {
    /// Create a new action with the given direction.
    pub fn new(direction: NavigationDirection) -> Self {
        let name = match direction {
            NavigationDirection::Forward => "Next Instruction".to_string(),
            NavigationDirection::Backward => "Previous Instruction".to_string(),
        };
        Self { direction, name }
    }
}

// ---------------------------------------------------------------------------
// NextPreviousLabelAction
// ---------------------------------------------------------------------------

/// Action that navigates to the next/previous label (symbol).
///
/// Ported from `ghidra.app.plugin.core.navigation.NextPreviousLabelAction`.
#[derive(Debug, Clone)]
pub struct NextPreviousLabelAction {
    /// Current direction.
    pub direction: NavigationDirection,
    /// Name for display purposes.
    pub name: String,
}

impl NextPreviousLabelAction {
    /// Create a new action with the given direction.
    pub fn new(direction: NavigationDirection) -> Self {
        let name = match direction {
            NavigationDirection::Forward => "Next Label".to_string(),
            NavigationDirection::Backward => "Previous Label".to_string(),
        };
        Self { direction, name }
    }
}

// ---------------------------------------------------------------------------
// NextPreviousSameBytesAction
// ---------------------------------------------------------------------------

/// Action that navigates to the next/previous occurrence of the same bytes.
///
/// Ported from `ghidra.app.plugin.core.navigation.NextPreviousSameBytesAction`.
#[derive(Debug, Clone)]
pub struct NextPreviousSameBytesAction {
    /// Current direction.
    pub direction: NavigationDirection,
    /// The byte pattern to search for.
    pub byte_pattern: Vec<u8>,
    /// Name for display purposes.
    pub name: String,
}

impl NextPreviousSameBytesAction {
    /// Create a new action with the given direction.
    pub fn new(direction: NavigationDirection) -> Self {
        let name = match direction {
            NavigationDirection::Forward => "Next Same Bytes".to_string(),
            NavigationDirection::Backward => "Previous Same Bytes".to_string(),
        };
        Self {
            direction,
            byte_pattern: Vec::new(),
            name,
        }
    }

    /// Set the byte pattern to search for.
    pub fn set_byte_pattern(&mut self, pattern: Vec<u8>) {
        self.byte_pattern = pattern;
    }
}

// ---------------------------------------------------------------------------
// NextPreviousUndefinedAction
// ---------------------------------------------------------------------------

/// Action that navigates to the next/previous undefined data area.
///
/// Ported from `ghidra.app.plugin.core.navigation.NextPreviousUndefinedAction`.
#[derive(Debug, Clone)]
pub struct NextPreviousUndefinedAction {
    /// Current direction.
    pub direction: NavigationDirection,
    /// Name for display purposes.
    pub name: String,
}

impl NextPreviousUndefinedAction {
    /// Create a new action with the given direction.
    pub fn new(direction: NavigationDirection) -> Self {
        let name = match direction {
            NavigationDirection::Forward => "Next Undefined".to_string(),
            NavigationDirection::Backward => "Previous Undefined".to_string(),
        };
        Self { direction, name }
    }
}

// ---------------------------------------------------------------------------
// GoToAddressLabelPlugin
// ---------------------------------------------------------------------------

/// Plugin that provides the "Go To Address/Label" dialog functionality.
///
/// Ported from `ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin`.
/// Manages the address/label entry dialog and coordinates with the
/// GoToService to navigate to user-specified addresses.
#[derive(Debug, Clone)]
pub struct GoToAddressLabelPlugin {
    /// Whether the plugin is enabled.
    enabled: bool,
    /// Whether to show the dialog on activation.
    show_dialog: bool,
    /// The last entered address string.
    last_address_string: Option<String>,
    /// Whether to use label-based navigation.
    use_labels: bool,
}

impl GoToAddressLabelPlugin {
    /// Create a new GoTo address/label plugin.
    pub fn new() -> Self {
        Self {
            enabled: true,
            show_dialog: true,
            last_address_string: None,
            use_labels: true,
        }
    }

    /// Returns `true` if the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the plugin.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether to show the dialog on activation.
    pub fn show_dialog(&self) -> bool {
        self.show_dialog
    }

    /// Set whether to show the dialog on activation.
    pub fn set_show_dialog(&mut self, show: bool) {
        self.show_dialog = show;
    }

    /// Get the last entered address string.
    pub fn last_address_string(&self) -> Option<&str> {
        self.last_address_string.as_deref()
    }

    /// Set the last entered address string.
    pub fn set_last_address_string(&mut self, s: Option<String>) {
        self.last_address_string = s;
    }

    /// Whether label-based navigation is enabled.
    pub fn use_labels(&self) -> bool {
        self.use_labels
    }

    /// Set whether to use label-based navigation.
    pub fn set_use_labels(&mut self, use_labels: bool) {
        self.use_labels = use_labels;
    }

    /// Parse a user-entered address string.
    ///
    /// Returns `Some(address)` if the string can be parsed as a hex address,
    /// or `None` if it should be interpreted as a label name.
    pub fn parse_address(input: &str) -> Option<Address> {
        let trimmed = input.trim();
        let hex_str = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);

        u64::from_str_radix(hex_str, 16)
            .ok()
            .map(Address::new)
    }
}

impl Default for GoToAddressLabelPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ProgramStartingLocationOptions
// ---------------------------------------------------------------------------

/// Options for the program starting location plugin.
///
/// Ported from `ghidra.app.plugin.core.navigation.ProgramStartingLocationOptions`.
#[derive(Debug, Clone)]
pub struct ProgramStartingLocationOptions {
    /// Whether to always start at the entry point.
    pub always_start_at_entry: bool,
    /// Whether to remember the last location per program.
    pub remember_last_location: bool,
    /// Whether to restore the last view state.
    pub restore_view_state: bool,
}

impl Default for ProgramStartingLocationOptions {
    fn default() -> Self {
        Self {
            always_start_at_entry: false,
            remember_last_location: true,
            restore_view_state: true,
        }
    }
}

// ---------------------------------------------------------------------------
// FindAppliedDataTypesService
// ---------------------------------------------------------------------------

/// Service for finding where specific data types have been applied.
///
/// Ported from `ghidra.app.plugin.core.navigation.FindAppliedDataTypesService`.
#[derive(Debug, Clone)]
pub struct FindAppliedDataTypesService {
    /// The data type name to search for.
    pub data_type_name: Option<String>,
    /// Whether to search in the current selection only.
    pub current_selection_only: bool,
    /// Whether to include sub-types in the search.
    pub include_subtypes: bool,
}

impl FindAppliedDataTypesService {
    /// Create a new service.
    pub fn new() -> Self {
        Self {
            data_type_name: None,
            current_selection_only: false,
            include_subtypes: false,
        }
    }
}

impl Default for FindAppliedDataTypesService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_navigation_direction() {
        assert!(NavigationDirection::Forward.is_forward());
        assert!(!NavigationDirection::Backward.is_forward());
        assert_eq!(NavigationDirection::Forward.opposite(), NavigationDirection::Backward);
        assert_eq!(NavigationDirection::Backward.opposite(), NavigationDirection::Forward);
        assert_eq!(format!("{}", NavigationDirection::Forward), "Forward");
    }

    #[test]
    fn test_next_prev_address_plugin() {
        let mut plugin = NextPrevAddressPlugin::new();
        assert!(plugin.is_enabled());
        assert_eq!(plugin.direction(), NavigationDirection::Backward);

        plugin.set_direction(NavigationDirection::Forward);
        assert_eq!(plugin.direction(), NavigationDirection::Forward);

        plugin.invert_direction();
        assert_eq!(plugin.direction(), NavigationDirection::Backward);

        plugin.set_enabled(false);
        assert!(!plugin.is_enabled());

        let (prev_name, next_name) = NextPrevAddressPlugin::action_names();
        assert_eq!(prev_name, "Previous Location in History");
        assert_eq!(next_name, "Next Location in History");

        let clear_path = NextPrevAddressPlugin::clear_menu_path();
        assert_eq!(clear_path[0], "Navigation");
        assert_eq!(clear_path[1], "Clear History");
    }

    #[test]
    fn test_next_prev_code_unit_plugin() {
        let mut plugin = NextPrevCodeUnitPlugin::new();
        assert_eq!(plugin.direction(), NavigationDirection::Forward);
        assert!(plugin.is_action_enabled(NextPreviousAction::Instruction));
        assert!(plugin.is_action_enabled(NextPreviousAction::Function));

        plugin.toggle_direction();
        assert_eq!(plugin.direction(), NavigationDirection::Backward);

        plugin.set_action_enabled(NextPreviousAction::Instruction, false);
        assert!(!plugin.is_action_enabled(NextPreviousAction::Instruction));

        plugin.set_action_enabled(NextPreviousAction::Instruction, true);
        assert!(plugin.is_action_enabled(NextPreviousAction::Instruction));
    }

    #[test]
    fn test_bookmark_action() {
        let action = NextPreviousBookmarkAction::new(NavigationDirection::Forward);
        assert_eq!(action.direction, NavigationDirection::Forward);
        assert_eq!(action.name, "Next Bookmark");
        assert!(!action.use_type_filter);
    }

    #[test]
    fn test_function_action() {
        let action = NextPreviousFunctionAction::new(NavigationDirection::Backward);
        assert_eq!(action.direction, NavigationDirection::Backward);
        assert_eq!(action.name, "Previous Function");
    }

    #[test]
    fn test_instruction_action() {
        let action = NextPreviousInstructionAction::new(NavigationDirection::Forward);
        assert_eq!(action.name, "Next Instruction");
    }

    #[test]
    fn test_label_action() {
        let action = NextPreviousLabelAction::new(NavigationDirection::Backward);
        assert_eq!(action.name, "Previous Label");
    }

    #[test]
    fn test_same_bytes_action() {
        let mut action = NextPreviousSameBytesAction::new(NavigationDirection::Forward);
        assert_eq!(action.name, "Next Same Bytes");
        assert!(action.byte_pattern.is_empty());

        action.set_byte_pattern(vec![0x90, 0x90, 0x90]);
        assert_eq!(action.byte_pattern, vec![0x90, 0x90, 0x90]);
    }

    #[test]
    fn test_undefined_action() {
        let action = NextPreviousUndefinedAction::new(NavigationDirection::Backward);
        assert_eq!(action.name, "Previous Undefined");
    }

    #[test]
    fn test_goto_address_label_plugin() {
        let mut plugin = GoToAddressLabelPlugin::new();
        assert!(plugin.is_enabled());
        assert!(plugin.use_labels());
        assert!(plugin.last_address_string().is_none());

        plugin.set_last_address_string(Some("0x1000".into()));
        assert_eq!(plugin.last_address_string(), Some("0x1000"));

        plugin.set_use_labels(false);
        assert!(!plugin.use_labels());
    }

    #[test]
    fn test_parse_address() {
        assert_eq!(GoToAddressLabelPlugin::parse_address("0x1000"), Some(Address::new(0x1000)));
        assert_eq!(GoToAddressLabelPlugin::parse_address("0XDEAD"), Some(Address::new(0xDEAD)));
        assert_eq!(GoToAddressLabelPlugin::parse_address("FF"), Some(Address::new(0xFF)));
        assert_eq!(GoToAddressLabelPlugin::parse_address("  0xABC  "), Some(Address::new(0xABC)));
        // Non-hex strings should return None.
        assert_eq!(GoToAddressLabelPlugin::parse_address("main"), None);
        assert_eq!(GoToAddressLabelPlugin::parse_address(""), None);
    }

    #[test]
    fn test_starting_location_options() {
        let opts = ProgramStartingLocationOptions::default();
        assert!(!opts.always_start_at_entry);
        assert!(opts.remember_last_location);
        assert!(opts.restore_view_state);
    }

    #[test]
    fn test_find_applied_data_types_service() {
        let service = FindAppliedDataTypesService::new();
        assert!(service.data_type_name.is_none());
        assert!(!service.current_selection_only);
        assert!(!service.include_subtypes);
    }

    #[test]
    fn test_next_prev_address_plugin_menu_group() {
        let plugin = NextPrevAddressPlugin::new();
        assert_eq!(plugin.history_menu_group(), NextPrevAddressPlugin::HISTORY_MENU_GROUP);

        let func_names = NextPrevAddressPlugin::function_action_names();
        assert_eq!(func_names.0, "Previous Function in History");
        assert_eq!(func_names.1, "Next Function in History");
    }
}
