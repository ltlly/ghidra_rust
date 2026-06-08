//! Diff filter options for listing code comparison.
//!
//! Ported from Ghidra's `ListingDiffActionManager` Java class in
//! `ghidra.features.base.codecompare.listing`.
//!
//! This module provides configuration options for filtering which types
//! of differences are highlighted in the listing comparison view. The
//! original Java version uses docking actions (toggles) to control these
//! settings; here we capture the logical state.
//!
//! # Key types
//!
//! - [`ListingDiffFilterOptions`] -- filter settings for diff computation
//! - [`DiffFilterKind`] -- the kind of difference that can be filtered

use std::fmt;

/// The kind of difference that can be filtered in the listing diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DiffFilterKind {
    /// Byte-level differences.
    ByteDiffs,
    /// Constant operand differences.
    Constants,
    /// Register name differences.
    RegisterNames,
}

impl DiffFilterKind {
    /// A human-readable label for this filter kind.
    pub fn label(&self) -> &'static str {
        match self {
            Self::ByteDiffs => "Byte Diffs",
            Self::Constants => "Operand Constants",
            Self::RegisterNames => "Operand Registers",
        }
    }

    /// A description of what this filter does when enabled.
    pub fn description(&self) -> &'static str {
        match self {
            Self::ByteDiffs => "Ignore byte differences when computing highlights.",
            Self::Constants => "Ignore operand constant differences when computing highlights.",
            Self::RegisterNames => "Ignore operand register name differences when computing highlights.",
        }
    }
}

impl fmt::Display for DiffFilterKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

/// Filter options for listing diff computation.
///
/// Controls which types of differences are considered when computing
/// highlights between two listings. When a filter is enabled, that type
/// of difference is ignored (not highlighted).
///
/// Ported from the toggle actions in Ghidra's `ListingDiffActionManager` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::listing::listing_diff_options::*;
///
/// let mut opts = ListingDiffFilterOptions::default();
/// assert!(!opts.ignore_byte_diffs);
///
/// opts.ignore_byte_diffs = true;
/// assert!(opts.is_ignored(DiffFilterKind::ByteDiffs));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListingDiffFilterOptions {
    /// If true, byte-level differences are ignored.
    pub ignore_byte_diffs: bool,
    /// If true, operand constant differences are ignored.
    pub ignore_constants: bool,
    /// If true, operand register name differences are ignored.
    pub ignore_register_names: bool,
}

impl ListingDiffFilterOptions {
    /// Create new filter options with all filters disabled.
    pub fn new() -> Self {
        Self {
            ignore_byte_diffs: false,
            ignore_constants: false,
            ignore_register_names: false,
        }
    }

    /// Check if a specific filter kind is currently ignored.
    pub fn is_ignored(&self, kind: DiffFilterKind) -> bool {
        match kind {
            DiffFilterKind::ByteDiffs => self.ignore_byte_diffs,
            DiffFilterKind::Constants => self.ignore_constants,
            DiffFilterKind::RegisterNames => self.ignore_register_names,
        }
    }

    /// Toggle the ignore state for a specific filter kind.
    ///
    /// Returns the new state (true = ignored).
    pub fn toggle(&mut self, kind: DiffFilterKind) -> bool {
        match kind {
            DiffFilterKind::ByteDiffs => {
                self.ignore_byte_diffs = !self.ignore_byte_diffs;
                self.ignore_byte_diffs
            }
            DiffFilterKind::Constants => {
                self.ignore_constants = !self.ignore_constants;
                self.ignore_constants
            }
            DiffFilterKind::RegisterNames => {
                self.ignore_register_names = !self.ignore_register_names;
                self.ignore_register_names
            }
        }
    }

    /// Set the ignore state for a specific filter kind.
    pub fn set_ignored(&mut self, kind: DiffFilterKind, ignored: bool) {
        match kind {
            DiffFilterKind::ByteDiffs => self.ignore_byte_diffs = ignored,
            DiffFilterKind::Constants => self.ignore_constants = ignored,
            DiffFilterKind::RegisterNames => self.ignore_register_names = ignored,
        }
    }

    /// Check if any filter is currently active (any difference type is ignored).
    pub fn has_active_filter(&self) -> bool {
        self.ignore_byte_diffs || self.ignore_constants || self.ignore_register_names
    }

    /// Get a list of all currently active (enabled) filter kinds.
    pub fn active_filters(&self) -> Vec<DiffFilterKind> {
        let mut filters = Vec::new();
        if self.ignore_byte_diffs {
            filters.push(DiffFilterKind::ByteDiffs);
        }
        if self.ignore_constants {
            filters.push(DiffFilterKind::Constants);
        }
        if self.ignore_register_names {
            filters.push(DiffFilterKind::RegisterNames);
        }
        filters
    }

    /// Get a list of all available filter kinds.
    pub fn all_filter_kinds() -> &'static [DiffFilterKind] {
        &[
            DiffFilterKind::ByteDiffs,
            DiffFilterKind::Constants,
            DiffFilterKind::RegisterNames,
        ]
    }

    /// Reset all filters to disabled.
    pub fn reset(&mut self) {
        self.ignore_byte_diffs = false;
        self.ignore_constants = false;
        self.ignore_register_names = false;
    }

    /// Serialize the filter state to a compact string representation.
    pub fn to_string_repr(&self) -> String {
        format!(
            "bytes={},constants={},registers={}",
            self.ignore_byte_diffs, self.ignore_constants, self.ignore_register_names
        )
    }

    /// Restore filter state from a compact string representation.
    pub fn from_string_repr(s: &str) -> Self {
        let mut opts = Self::new();
        for part in s.split(',') {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "bytes" => opts.ignore_byte_diffs = value == "true",
                    "constants" => opts.ignore_constants = value == "true",
                    "registers" => opts.ignore_register_names = value == "true",
                    _ => {}
                }
            }
        }
        opts
    }
}

impl Default for ListingDiffFilterOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// State of a toggle action for diff filtering.
///
/// This represents the state of a single toggle action in the UI,
/// corresponding to one of the toggle actions in `ListingDiffActionManager`.
#[derive(Debug, Clone)]
pub struct DiffToggleActionState {
    /// The filter kind this action controls.
    pub filter_kind: DiffFilterKind,
    /// Whether the action is currently selected (filter enabled).
    pub selected: bool,
    /// Whether the action is currently enabled (can be toggled).
    pub enabled: bool,
    /// The display name of the action.
    pub name: String,
    /// The description of the action.
    pub description: String,
}

impl DiffToggleActionState {
    /// Create a new toggle action state.
    pub fn new(filter_kind: DiffFilterKind) -> Self {
        Self {
            name: format!("Toggle Ignore {}", filter_kind.label()),
            description: format!(
                "If selected, difference highlights should ignore {}.",
                filter_kind.label()
            ),
            filter_kind,
            selected: false,
            enabled: true,
        }
    }

    /// Toggle the selected state.
    pub fn toggle(&mut self) {
        self.selected = !self.selected;
    }
}

/// Manages the toggle actions for diff filtering.
///
/// This is the Rust equivalent of Ghidra's `ListingDiffActionManager` Java class,
/// capturing the action state management without the Swing/docking framework.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::listing::listing_diff_options::*;
///
/// let mut manager = DiffFilterActionManager::new();
/// assert_eq!(manager.actions().len(), 3);
///
/// // Toggle byte diffs
/// manager.toggle(DiffFilterKind::ByteDiffs);
/// assert!(manager.filter_options().ignore_byte_diffs);
/// ```
pub struct DiffFilterActionManager {
    actions: Vec<DiffToggleActionState>,
    filter_options: ListingDiffFilterOptions,
}

impl DiffFilterActionManager {
    /// Create a new action manager with default (all disabled) filters.
    pub fn new() -> Self {
        let actions = ListingDiffFilterOptions::all_filter_kinds()
            .iter()
            .map(|&kind| DiffToggleActionState::new(kind))
            .collect();

        Self {
            actions,
            filter_options: ListingDiffFilterOptions::default(),
        }
    }

    /// Get the list of toggle action states.
    pub fn actions(&self) -> &[DiffToggleActionState] {
        &self.actions
    }

    /// Get the current filter options.
    pub fn filter_options(&self) -> &ListingDiffFilterOptions {
        &self.filter_options
    }

    /// Toggle a specific filter kind.
    pub fn toggle(&mut self, kind: DiffFilterKind) {
        let new_state = self.filter_options.toggle(kind);
        for action in &mut self.actions {
            if action.filter_kind == kind {
                action.selected = new_state;
                break;
            }
        }
    }

    /// Update the enablement of all actions.
    pub fn update_enablement(&mut self, enabled: bool) {
        for action in &mut self.actions {
            action.enabled = enabled;
        }
    }

    /// Get the number of active filters.
    pub fn active_filter_count(&self) -> usize {
        self.filter_options.active_filters().len()
    }
}

impl Default for DiffFilterActionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_options_default() {
        let opts = ListingDiffFilterOptions::default();
        assert!(!opts.ignore_byte_diffs);
        assert!(!opts.ignore_constants);
        assert!(!opts.ignore_register_names);
        assert!(!opts.has_active_filter());
    }

    #[test]
    fn test_filter_options_toggle() {
        let mut opts = ListingDiffFilterOptions::new();
        assert!(!opts.is_ignored(DiffFilterKind::ByteDiffs));

        let new_state = opts.toggle(DiffFilterKind::ByteDiffs);
        assert!(new_state);
        assert!(opts.is_ignored(DiffFilterKind::ByteDiffs));

        let new_state = opts.toggle(DiffFilterKind::ByteDiffs);
        assert!(!new_state);
        assert!(!opts.is_ignored(DiffFilterKind::ByteDiffs));
    }

    #[test]
    fn test_filter_options_set_ignored() {
        let mut opts = ListingDiffFilterOptions::new();
        opts.set_ignored(DiffFilterKind::Constants, true);
        assert!(opts.is_ignored(DiffFilterKind::Constants));
        assert!(opts.has_active_filter());
    }

    #[test]
    fn test_filter_options_active_filters() {
        let mut opts = ListingDiffFilterOptions::new();
        opts.ignore_byte_diffs = true;
        opts.ignore_register_names = true;

        let active = opts.active_filters();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&DiffFilterKind::ByteDiffs));
        assert!(active.contains(&DiffFilterKind::RegisterNames));
    }

    #[test]
    fn test_filter_options_all_kinds() {
        let kinds = ListingDiffFilterOptions::all_filter_kinds();
        assert_eq!(kinds.len(), 3);
    }

    #[test]
    fn test_filter_options_reset() {
        let mut opts = ListingDiffFilterOptions::new();
        opts.ignore_byte_diffs = true;
        opts.ignore_constants = true;
        opts.reset();
        assert!(!opts.has_active_filter());
    }

    #[test]
    fn test_filter_options_serialization() {
        let mut opts = ListingDiffFilterOptions::new();
        opts.ignore_byte_diffs = true;
        opts.ignore_register_names = true;

        let serialized = opts.to_string_repr();
        let restored = ListingDiffFilterOptions::from_string_repr(&serialized);

        assert!(restored.ignore_byte_diffs);
        assert!(!restored.ignore_constants);
        assert!(restored.ignore_register_names);
    }

    #[test]
    fn test_diff_filter_kind_label() {
        assert_eq!(DiffFilterKind::ByteDiffs.label(), "Byte Diffs");
        assert_eq!(DiffFilterKind::Constants.label(), "Operand Constants");
        assert_eq!(DiffFilterKind::RegisterNames.label(), "Operand Registers");
    }

    #[test]
    fn test_diff_filter_kind_display() {
        assert_eq!(format!("{}", DiffFilterKind::ByteDiffs), "Byte Diffs");
    }

    #[test]
    fn test_toggle_action_state() {
        let mut action = DiffToggleActionState::new(DiffFilterKind::ByteDiffs);
        assert!(!action.selected);
        assert!(action.enabled);
        assert!(action.name.contains("Byte"));

        action.toggle();
        assert!(action.selected);
    }

    #[test]
    fn test_filter_action_manager() {
        let mut manager = DiffFilterActionManager::new();
        assert_eq!(manager.actions().len(), 3);
        assert!(!manager.filter_options().has_active_filter());

        manager.toggle(DiffFilterKind::ByteDiffs);
        assert!(manager.filter_options().ignore_byte_diffs);
        assert_eq!(manager.active_filter_count(), 1);
    }

    #[test]
    fn test_filter_action_manager_enablement() {
        let mut manager = DiffFilterActionManager::new();
        manager.update_enablement(false);
        for action in manager.actions() {
            assert!(!action.enabled);
        }
        manager.update_enablement(true);
        for action in manager.actions() {
            assert!(action.enabled);
        }
    }
}
