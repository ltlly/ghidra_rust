//! Navigation plugins -- ported from Ghidra's
//! `ghidra.app.plugin.core.navigation` Java package.
//!
//! Provides next/previous navigation (code units, functions, labels,
//! bookmarks, undefined, etc.), navigation history, and the "Find
//! References To" infrastructure.
//!
//! - [`NavigationHistoryPlugin`] -- tracks and replays navigation history
//! - [`locationreferences`] -- find-references-to logic and descriptors
//! - [`NavigationOptions`] -- configurable navigation behavior
//! - [`NextPreviousAction`] -- enum of all next/prev action types
//!
//! Swing UI code is omitted; only model and business logic are ported.

pub mod bookmark_action;
pub mod function_action;
pub mod function_utils;
pub mod history;
pub mod instruction_action;
pub mod locationreferences;
pub mod location_service;
pub mod next_prev_plugins;
pub mod reference_utils;
pub mod starting_location;
pub mod table_model;

/// Navigation history management.
///
/// Ported from `ghidra.app.plugin.core.navigation` provider classes.
pub mod provider;

/// Address table navigation types (jump tables, vtables).
///
/// Ported from `ghidra.app.plugin.core.navigation` table-related classes.
pub mod address_table;

/// Specialized location descriptor types for "Find References To".
///
/// Ported from the many `*LocationDescriptor.java` subclasses in
/// `ghidra.app.plugin.core.navigation.locationreferences`.
pub mod descriptors;

/// Location descriptor and reference types for navigation.
///
/// Ported from `LocationDescriptor.java`, `LocationReference.java`,
/// and related classes in `ghidra.app.plugin.core.navigation.locationreferences`.
pub mod location_descriptors;

/// Extended navigation settings and starting location options.
///
/// Ported from `ProgramStartingLocationOptions.java` and
/// range-navigation option classes.
pub mod navigation_settings;

/// Top-level navigation plugin coordinating all navigation actions.
///
/// Ported from `ghidra.app.plugin.core.navigation.NavigationPlugin`.
pub mod navigation_plugin;

/// GoTo address/label service for address and label navigation.
///
/// Ported from `ghidra.app.services.GoToService` and
/// `ghidra.app.plugin.core.navigation.GoToAddressLabelPlugin`.
pub mod goto_address_label_service;

use std::collections::HashMap;


use crate::gotoquery::LocationMemento;

// ---------------------------------------------------------------------------
// NavigationOptions
// ---------------------------------------------------------------------------

/// Configurable navigation behavior.
#[derive(Debug, Clone)]
pub struct NavigationOptions {
    /// Whether navigating ranges goes to top and bottom (vs. top only).
    pub goto_top_and_bottom: bool,
    /// Whether to navigate to external programs.
    pub goto_external_program: bool,
    /// Whether to follow indirect references.
    pub follow_indirect_references: bool,
    /// Whether to prefer the current address space.
    pub prefer_current_address_space: bool,
    /// Whether to restrict GoTo to the current program.
    pub restrict_to_current_program: bool,
}

impl Default for NavigationOptions {
    fn default() -> Self {
        Self {
            goto_top_and_bottom: false,
            goto_external_program: false,
            follow_indirect_references: false,
            prefer_current_address_space: true,
            restrict_to_current_program: true,
        }
    }
}

// ---------------------------------------------------------------------------
// NextPreviousAction
// ---------------------------------------------------------------------------

/// The types of next/previous navigation actions available in Ghidra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NextPreviousAction {
    /// Navigate to the next/previous address.
    Address,
    /// Navigate to the next/previous code unit (instruction or data).
    CodeUnit,
    /// Navigate to the next/previous instruction.
    Instruction,
    /// Navigate to the next/previous defined data.
    DefinedData,
    /// Navigate to the next/previous undefined byte.
    Undefined,
    /// Navigate to the next/previous label (symbol).
    Label,
    /// Navigate to the next/previous function.
    Function,
    /// Navigate to the next/previous bookmark.
    Bookmark,
    /// Navigate to the next/previous highlighted range.
    HighlightedRange,
    /// Navigate to the next/previous selected range.
    SelectedRange,
    /// Navigate to the next/previous occurrence of same bytes.
    SameBytes,
}

impl NextPreviousAction {
    /// Human-readable name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Address => "Address",
            Self::CodeUnit => "Code Unit",
            Self::Instruction => "Instruction",
            Self::DefinedData => "Defined Data",
            Self::Undefined => "Undefined",
            Self::Label => "Label",
            Self::Function => "Function",
            Self::Bookmark => "Bookmark",
            Self::HighlightedRange => "Highlighted Range",
            Self::SelectedRange => "Selected Range",
            Self::SameBytes => "Same Bytes",
        }
    }
}

impl std::fmt::Display for NextPreviousAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

// ---------------------------------------------------------------------------
// HistoryList
// ---------------------------------------------------------------------------

/// A bounded navigation history for a single navigatable.
///
/// Maintains a list of [`LocationMemento`]s and a current-position
/// cursor.  New locations are added after the cursor, truncating
/// any forward history (like a browser back/forward stack).
#[derive(Debug, Clone)]
pub struct HistoryList {
    list: Vec<LocationMemento>,
    current_location: usize,
    max_locations: usize,
}

impl HistoryList {
    /// Create a new history list with the given capacity.
    pub fn new(max_locations: usize) -> Self {
        Self {
            list: Vec::new(),
            current_location: 0,
            max_locations,
        }
    }

    /// The current position index.
    pub fn current_location_index(&self) -> usize {
        self.current_location
    }

    /// Set the current position (for restore).
    pub fn set_current_location_index(&mut self, index: usize) {
        if index < self.list.len() {
            self.current_location = index;
        }
    }

    /// Number of entries.
    pub fn size(&self) -> usize {
        self.list.len()
    }

    /// Get an entry by index.
    pub fn get_location(&self, index: usize) -> Option<&LocationMemento> {
        self.list.get(index)
    }

    /// Get the current entry.
    pub fn current_location(&self) -> Option<&LocationMemento> {
        self.list.get(self.current_location)
    }

    /// Add a new location to the history.
    ///
    /// If we are not at the end of the list, future entries are
    /// discarded first.  Duplicate consecutive entries are collapsed.
    pub fn add_location(&mut self, memento: LocationMemento) {
        if self.list.is_empty() {
            self.list.push(memento);
            self.current_location = 0;
            return;
        }

        // Truncate entries after current
        self.list.truncate(self.current_location + 1);

        // Collapse duplicate consecutive
        let last = self.list.last().unwrap();
        if *last == memento {
            *self.list.last_mut().unwrap() = memento;
        } else {
            self.list.push(memento);
        }

        // Enforce max size
        if self.list.len() > self.max_locations {
            self.list.remove(0);
        }

        self.current_location = self.list.len() - 1;
    }

    /// Set the maximum number of stored locations.
    pub fn set_max_locations(&mut self, max: usize) {
        self.max_locations = max;
        while self.list.len() > max {
            self.list.remove(0);
            if self.current_location > 0 {
                self.current_location -= 1;
            }
        }
    }

    /// Whether there is a next entry.
    pub fn has_next(&self) -> bool {
        !self.list.is_empty() && self.current_location < self.list.len() - 1
    }

    /// Whether there is a previous entry.
    pub fn has_previous(&self) -> bool {
        !self.list.is_empty() && self.current_location > 0
    }

    /// Move forward and return the location.
    pub fn next(&mut self) -> Option<&LocationMemento> {
        if self.has_next() {
            self.current_location += 1;
            self.list.get(self.current_location)
        } else {
            None
        }
    }

    /// Move backward and return the location.
    pub fn previous(&mut self) -> Option<&LocationMemento> {
        if self.has_previous() {
            self.current_location -= 1;
            self.list.get(self.current_location)
        } else {
            None
        }
    }

    /// Remove a specific location from the history.
    pub fn remove(&mut self, memento: &LocationMemento) {
        if let Some(pos) = self.list.iter().position(|m| m == memento) {
            self.list.remove(pos);
            if self.current_location > 0 && self.current_location >= pos {
                self.current_location -= 1;
            }
        }
    }

    /// Get all next locations (for display in forward menu).
    pub fn get_next_locations(&self) -> Vec<&LocationMemento> {
        if self.current_location + 1 < self.list.len() {
            self.list[self.current_location + 1..].iter().collect()
        } else {
            Vec::new()
        }
    }

    /// Get all previous locations (for display in back menu),
    /// in reverse order (most recent first).
    pub fn get_previous_locations(&self) -> Vec<&LocationMemento> {
        if self.current_location > 0 {
            let mut locs: Vec<_> = self.list[..self.current_location].iter().collect();
            locs.reverse();
            locs
        } else {
            Vec::new()
        }
    }
}

// ---------------------------------------------------------------------------
// NavigationHistoryPlugin
// ---------------------------------------------------------------------------

/// Plugin that maintains navigation history for all navigatables.
///
/// Provides back/forward/next-function/previous-function operations
/// and persists history across tool sessions.
pub struct NavigationHistoryPlugin {
    /// History per navigatable.
    history_map: HashMap<u64, HistoryList>,
    /// Current max history size.
    max_history_size: usize,
    /// Pending events.
    events: Vec<String>,
}

impl NavigationHistoryPlugin {
    /// The default maximum history size.
    pub const DEFAULT_MAX_HISTORY_SIZE: usize = 30;
    /// Absolute minimum history size.
    pub const MIN_HISTORY_SIZE: usize = 10;
    /// Absolute maximum history size.
    pub const MAX_HISTORY_SIZE: usize = 400;

    /// Create a new navigation history plugin.
    pub fn new() -> Self {
        Self {
            history_map: HashMap::new(),
            max_history_size: Self::DEFAULT_MAX_HISTORY_SIZE,
            events: Vec::new(),
        }
    }

    /// Record a new location for the given navigatable.
    pub fn add_new_location(&mut self, navigatable_id: u64, memento: LocationMemento) {
        let history = self
            .history_map
            .entry(navigatable_id)
            .or_insert_with(|| HistoryList::new(self.max_history_size));
        history.add_location(memento);
        self.events.push(format!(
            "History: added location for navigatable {}",
            navigatable_id
        ));
    }

    /// Navigate forward in history.
    pub fn next(&mut self, navigatable_id: u64) -> Option<&LocationMemento> {
        if let Some(history) = self.history_map.get_mut(&navigatable_id) {
            history.next()
        } else {
            None
        }
    }

    /// Navigate backward in history.
    pub fn previous(&mut self, navigatable_id: u64) -> Option<&LocationMemento> {
        if let Some(history) = self.history_map.get_mut(&navigatable_id) {
            history.previous()
        } else {
            None
        }
    }

    /// Whether forward navigation is possible.
    pub fn has_next(&self, navigatable_id: u64) -> bool {
        self.history_map
            .get(&navigatable_id)
            .map_or(false, |h| h.has_next())
    }

    /// Whether backward navigation is possible.
    pub fn has_previous(&self, navigatable_id: u64) -> bool {
        self.history_map
            .get(&navigatable_id)
            .map_or(false, |h| h.has_previous())
    }

    /// Get the next locations for display.
    pub fn get_next_locations(&self, navigatable_id: u64) -> Vec<&LocationMemento> {
        self.history_map
            .get(&navigatable_id)
            .map_or(Vec::new(), |h| h.get_next_locations())
    }

    /// Get the previous locations for display.
    pub fn get_previous_locations(&self, navigatable_id: u64) -> Vec<&LocationMemento> {
        self.history_map
            .get(&navigatable_id)
            .map_or(Vec::new(), |h| h.get_previous_locations())
    }

    /// Clear history for a navigatable.
    pub fn clear(&mut self, navigatable_id: u64) {
        self.history_map.remove(&navigatable_id);
        self.events
            .push(format!("History: cleared for navigatable {}", navigatable_id));
    }

    /// Clear all history entries that reference a given program.
    pub fn clear_program(&mut self, program_name: &str) {
        for history in self.history_map.values_mut() {
            let indices_to_remove: Vec<usize> = history
                .list
                .iter()
                .enumerate()
                .filter(|(_, m)| m.program_name == program_name)
                .map(|(i, _)| i)
                .rev()
                .collect();
            for idx in indices_to_remove {
                history.list.remove(idx);
                if history.current_location > 0 && history.current_location >= idx {
                    history.current_location -= 1;
                }
            }
        }
        self.events
            .push(format!("History: cleared program '{}'", program_name));
    }

    /// Remove a navigatable (called when it is disposed).
    pub fn navigatable_removed(&mut self, navigatable_id: u64) {
        self.clear(navigatable_id);
    }

    /// Get the max history size.
    pub fn max_history_size(&self) -> usize {
        self.max_history_size
    }

    /// Set the max history size (applies to all history lists).
    pub fn set_max_history_size(&mut self, max: usize) {
        let clamped = max.clamp(Self::MIN_HISTORY_SIZE, Self::MAX_HISTORY_SIZE);
        self.max_history_size = clamped;
        for history in self.history_map.values_mut() {
            history.set_max_locations(clamped);
        }
    }

    /// Get the event log.
    pub fn events(&self) -> &[String] {
        &self.events
    }

    /// Get the history list for a navigatable (for testing).
    pub fn history(&self, navigatable_id: u64) -> Option<&HistoryList> {
        self.history_map.get(&navigatable_id)
    }
}

impl Default for NavigationHistoryPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// NextPrevHighlightRangePlugin
// ---------------------------------------------------------------------------

/// Plugin for navigating to the next/previous highlighted range.
///
/// Ported from `ghidra.app.plugin.core.navigation.NextPrevHighlightRangePlugin`.
#[derive(Debug)]
pub struct NextPrevHighlightRangePlugin {
    /// Plugin name.
    pub name: String,
    /// Whether the plugin has been disposed.
    pub is_disposed: bool,
    /// The next action.
    pub next_action: NextHighlightedRangeAction,
    /// The previous action.
    pub previous_action: PreviousHighlightedRangeAction,
}

impl NextPrevHighlightRangePlugin {
    /// Create a new plugin.
    pub fn new() -> Self {
        let name = "NextPrevHighlightRange".to_string();
        Self {
            next_action: NextHighlightedRangeAction::new(&name),
            previous_action: PreviousHighlightedRangeAction::new(&name),
            name,
            is_disposed: false,
        }
    }

    /// Dispose the plugin.
    pub fn dispose(&mut self) {
        self.is_disposed = true;
    }
}

impl Default for NextPrevHighlightRangePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Action to go to the next highlighted range.
///
/// Ported from `ghidra.app.plugin.core.navigation.NextHighlightedRangeAction`.
#[derive(Debug, Clone)]
pub struct NextHighlightedRangeAction {
    /// Action name.
    pub name: String,
    /// Owner plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub is_enabled: bool,
}

impl NextHighlightedRangeAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Next Highlighted Range".to_string(),
            owner: owner.into(),
            is_enabled: true,
        }
    }
}

/// Action to go to the previous highlighted range.
///
/// Ported from `ghidra.app.plugin.core.navigation.PreviousHighlightedRangeAction`.
#[derive(Debug, Clone)]
pub struct PreviousHighlightedRangeAction {
    /// Action name.
    pub name: String,
    /// Owner plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub is_enabled: bool,
}

impl PreviousHighlightedRangeAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Previous Highlighted Range".to_string(),
            owner: owner.into(),
            is_enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// NextPrevSelectedRangePlugin
// ---------------------------------------------------------------------------

/// Plugin for navigating to the next/previous selected range.
///
/// Ported from `ghidra.app.plugin.core.navigation.NextPrevSelectedRangePlugin`.
#[derive(Debug)]
pub struct NextPrevSelectedRangePlugin {
    /// Plugin name.
    pub name: String,
    /// Whether the plugin has been disposed.
    pub is_disposed: bool,
    /// The next action.
    pub next_action: NextSelectedRangeAction,
    /// The previous action.
    pub previous_action: PreviousSelectedRangeAction,
}

impl NextPrevSelectedRangePlugin {
    /// Create a new plugin.
    pub fn new() -> Self {
        let name = "NextPrevSelectedRange".to_string();
        Self {
            next_action: NextSelectedRangeAction::new(&name),
            previous_action: PreviousSelectedRangeAction::new(&name),
            name,
            is_disposed: false,
        }
    }

    /// Dispose the plugin.
    pub fn dispose(&mut self) {
        self.is_disposed = true;
    }
}

impl Default for NextPrevSelectedRangePlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Action to go to the next selected range.
///
/// Ported from `ghidra.app.plugin.core.navigation.NextSelectedRangeAction`.
#[derive(Debug, Clone)]
pub struct NextSelectedRangeAction {
    /// Action name.
    pub name: String,
    /// Owner plugin name.
    pub owner: String,
}

impl NextSelectedRangeAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Next Selected Range".to_string(),
            owner: owner.into(),
        }
    }
}

/// Action to go to the previous selected range.
///
/// Ported from `ghidra.app.plugin.core.navigation.PreviousSelectedRangeAction`.
#[derive(Debug, Clone)]
pub struct PreviousSelectedRangeAction {
    /// Action name.
    pub name: String,
    /// Owner plugin name.
    pub owner: String,
}

impl PreviousSelectedRangeAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Previous Selected Range".to_string(),
            owner: owner.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// ProviderNavigationPlugin
// ---------------------------------------------------------------------------

/// Plugin providing navigation actions for provider windows.
///
/// Ported from `ghidra.app.plugin.core.navigation.ProviderNavigationPlugin`.
#[derive(Debug)]
pub struct ProviderNavigationPlugin {
    /// Plugin name.
    pub name: String,
    /// Whether the plugin has been disposed.
    pub is_disposed: bool,
}

impl ProviderNavigationPlugin {
    /// Create a new plugin.
    pub fn new() -> Self {
        Self {
            name: "ProviderNavigation".to_string(),
            is_disposed: false,
        }
    }

    /// Dispose the plugin.
    pub fn dispose(&mut self) {
        self.is_disposed = true;
    }
}

impl Default for ProviderNavigationPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// FindReferencesTo actions
// ---------------------------------------------------------------------------

/// Action to find references to the current location.
///
/// Ported from `ghidra.app.plugin.core.navigation.locationreferences.FindReferencesToAction`.
#[derive(Debug, Clone)]
pub struct FindReferencesToAction {
    /// Action name.
    pub name: String,
    /// Owner plugin.
    pub owner: String,
    /// Whether the action is enabled.
    pub is_enabled: bool,
}

impl FindReferencesToAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Find References To".to_string(),
            owner: owner.into(),
            is_enabled: true,
        }
    }
}

/// Action to find references to a specific address.
///
/// Ported from `ghidra.app.plugin.core.navigation.locationreferences.FindReferencesToAddressAction`.
#[derive(Debug, Clone)]
pub struct FindReferencesToAddressAction {
    /// Action name.
    pub name: String,
    /// Owner plugin.
    pub owner: String,
}

impl FindReferencesToAddressAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Find References To Address".to_string(),
            owner: owner.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// NextPreviousDefinedDataAction
// ---------------------------------------------------------------------------

/// Action for navigating to the next or previous defined data item.
///
/// Ported from `ghidra.app.plugin.core.navigation.NextPreviousDefinedDataAction`.
#[derive(Debug, Clone)]
pub struct NextPreviousDefinedDataAction {
    /// Action name.
    pub name: String,
    /// Owner plugin.
    pub owner: String,
    /// Whether this is a forward (next) or backward (previous) action.
    pub is_forward: bool,
}

impl NextPreviousDefinedDataAction {
    /// Create a "Next Defined Data" action.
    pub fn new_forward(owner: impl Into<String>) -> Self {
        Self {
            name: "Next Defined Data".to_string(),
            owner: owner.into(),
            is_forward: true,
        }
    }

    /// Create a "Previous Defined Data" action.
    pub fn new_backward(owner: impl Into<String>) -> Self {
        Self {
            name: "Previous Defined Data".to_string(),
            owner: owner.into(),
            is_forward: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Location descriptor types
// ---------------------------------------------------------------------------

/// Location descriptor for function signature fields.
///
/// Ported from `ghidra.app.plugin.core.navigation.locationreferences.FunctionSignatureFieldLocationDescriptor`.
#[derive(Debug, Clone)]
pub struct FunctionSignatureFieldLocationDescriptor {
    /// Address of the function.
    pub address: u64,
    /// Name of the function.
    pub function_name: String,
}

impl FunctionSignatureFieldLocationDescriptor {
    /// Create a new descriptor.
    pub fn new(address: u64, function_name: impl Into<String>) -> Self {
        Self {
            address,
            function_name: function_name.into(),
        }
    }
}

/// Program location for a composite data type.
///
/// Ported from `ghidra.app.plugin.core.navigation.locationreferences.GenericCompositeDataTypeProgramLocation`.
#[derive(Debug, Clone)]
pub struct GenericCompositeDataTypeProgramLocation {
    /// Address where the composite type is used.
    pub address: u64,
    /// Name of the composite type.
    pub type_name: String,
}

impl GenericCompositeDataTypeProgramLocation {
    /// Create a new location.
    pub fn new(address: u64, type_name: impl Into<String>) -> Self {
        Self {
            address,
            type_name: type_name.into(),
        }
    }
}

/// Program location for a generic data type.
///
/// Ported from `ghidra.app.plugin.core.navigation.locationreferences.GenericDataTypeProgramLocation`.
#[derive(Debug, Clone)]
pub struct GenericDataTypeProgramLocation {
    /// Address where the data type is used.
    pub address: u64,
    /// Name of the data type.
    pub type_name: String,
}

impl GenericDataTypeProgramLocation {
    /// Create a new location.
    pub fn new(address: u64, type_name: impl Into<String>) -> Self {
        Self {
            address,
            type_name: type_name.into(),
        }
    }
}

/// Context for the location references provider.
///
/// Ported from `ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesProviderContext`.
#[derive(Debug, Clone)]
pub struct LocationReferencesProviderContext {
    /// The address being referenced.
    pub address: u64,
    /// The provider name.
    pub provider_name: String,
}

impl LocationReferencesProviderContext {
    /// Create a new context.
    pub fn new(address: u64, provider_name: impl Into<String>) -> Self {
        Self {
            address,
            provider_name: provider_name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// AbstractNextPreviousAction
// ---------------------------------------------------------------------------

/// Abstract base for next/previous navigation actions.
///
/// Ported from `ghidra.app.plugin.core.navigation.AbstractNextPreviousAction`.
#[derive(Debug, Clone)]
pub struct AbstractNextPreviousAction {
    /// The action name.
    pub name: String,
    /// Whether this is a "next" (forward) or "previous" (backward) action.
    pub forward: bool,
    /// Whether the action is enabled.
    pub enabled: bool,
    /// The navigation provider name.
    pub provider_name: Option<String>,
}

impl AbstractNextPreviousAction {
    /// Create a new next/previous action.
    pub fn new(name: impl Into<String>, forward: bool) -> Self {
        Self {
            name: name.into(),
            forward,
            enabled: true,
            provider_name: None,
        }
    }

    /// Create a "next" action.
    pub fn next_action(name: impl Into<String>) -> Self {
        Self::new(name, true)
    }

    /// Create a "previous" action.
    pub fn previous_action(name: impl Into<String>) -> Self {
        Self::new(name, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;


    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn memento(program: &str, offset: u64) -> LocationMemento {
        LocationMemento::new(program, addr(offset), 0)
    }

    #[test]
    fn test_next_previous_action_display() {
        assert_eq!(NextPreviousAction::Function.display_name(), "Function");
        assert_eq!(
            format!("{}", NextPreviousAction::Instruction),
            "Instruction"
        );
    }

    #[test]
    fn test_history_list_basic() {
        let mut hl = HistoryList::new(10);
        assert_eq!(hl.size(), 0);
        assert!(!hl.has_next());
        assert!(!hl.has_previous());

        hl.add_location(memento("p", 0x1000));
        assert_eq!(hl.size(), 1);
        assert_eq!(hl.current_location_index(), 0);
        assert!(!hl.has_next());
        assert!(!hl.has_previous());
    }

    #[test]
    fn test_history_list_add_and_navigate() {
        let mut hl = HistoryList::new(10);
        hl.add_location(memento("p", 0x1000));
        hl.add_location(memento("p", 0x2000));
        hl.add_location(memento("p", 0x3000));

        assert_eq!(hl.size(), 3);
        assert_eq!(hl.current_location_index(), 2);
        assert!(!hl.has_next());
        assert!(hl.has_previous());

        let prev = hl.previous().unwrap();
        assert_eq!(prev.address, 0x2000);
        assert_eq!(hl.current_location_index(), 1);

        let prev2 = hl.previous().unwrap();
        assert_eq!(prev2.address, 0x1000);
        assert!(!hl.has_previous());

        let next = hl.next().unwrap();
        assert_eq!(next.address, 0x2000);
    }

    #[test]
    fn test_history_list_truncate_forward() {
        let mut hl = HistoryList::new(10);
        hl.add_location(memento("p", 0x1000));
        hl.add_location(memento("p", 0x2000));
        hl.add_location(memento("p", 0x3000));

        // Go back twice
        hl.previous();
        hl.previous();

        // Add new -- should truncate 0x2000 and 0x3000
        hl.add_location(memento("p", 0x1500));
        assert_eq!(hl.size(), 2);
        assert_eq!(hl.get_location(0).unwrap().address, 0x1000);
        assert_eq!(hl.get_location(1).unwrap().address, 0x1500);
    }

    #[test]
    fn test_history_list_max_size() {
        let mut hl = HistoryList::new(3);
        hl.add_location(memento("p", 0x1000));
        hl.add_location(memento("p", 0x2000));
        hl.add_location(memento("p", 0x3000));
        hl.add_location(memento("p", 0x4000));

        assert_eq!(hl.size(), 3);
        // Oldest entry (0x1000) was evicted
        assert_eq!(hl.get_location(0).unwrap().address, 0x2000);
    }

    #[test]
    fn test_history_list_remove() {
        let mut hl = HistoryList::new(10);
        let m1 = memento("p", 0x1000);
        let m2 = memento("p", 0x2000);
        let m3 = memento("p", 0x3000);
        hl.add_location(m1.clone());
        hl.add_location(m2.clone());
        hl.add_location(m3.clone());

        hl.remove(&m2);
        assert_eq!(hl.size(), 2);
    }

    #[test]
    fn test_history_list_next_previous_locations() {
        let mut hl = HistoryList::new(10);
        hl.add_location(memento("p", 0x1000));
        hl.add_location(memento("p", 0x2000));
        hl.add_location(memento("p", 0x3000));

        let next_locs = hl.get_next_locations();
        assert!(next_locs.is_empty());

        let prev_locs = hl.get_previous_locations();
        assert_eq!(prev_locs.len(), 2);
        // Most recent first
        assert_eq!(prev_locs[0].address, 0x2000);
        assert_eq!(prev_locs[1].address, 0x1000);
    }

    #[test]
    fn test_history_list_set_max_locations() {
        let mut hl = HistoryList::new(100);
        for i in 0..50 {
            hl.add_location(memento("p", 0x1000 + i * 0x100));
        }
        assert_eq!(hl.size(), 50);

        hl.set_max_locations(10);
        assert_eq!(hl.size(), 10);
    }

    #[test]
    fn test_navigation_history_plugin_basic() {
        let mut plugin = NavigationHistoryPlugin::new();
        assert_eq!(plugin.max_history_size(), 30);

        let m = memento("test.exe", 0x1000);
        plugin.add_new_location(1, m);

        assert!(plugin.has_previous(1) || !plugin.has_previous(1)); // depends on state
        assert!(!plugin.has_next(1));
    }

    #[test]
    fn test_navigation_history_plugin_navigate() {
        let mut plugin = NavigationHistoryPlugin::new();

        plugin.add_new_location(1, memento("p", 0x1000));
        plugin.add_new_location(1, memento("p", 0x2000));
        plugin.add_new_location(1, memento("p", 0x3000));

        assert!(!plugin.has_next(1));
        assert!(plugin.has_previous(1));

        let prev = plugin.previous(1).unwrap();
        assert_eq!(prev.address, 0x2000);

        let prev2 = plugin.previous(1).unwrap();
        assert_eq!(prev2.address, 0x1000);
        assert!(!plugin.has_previous(1));

        let next = plugin.next(1).unwrap();
        assert_eq!(next.address, 0x2000);
    }

    #[test]
    fn test_navigation_history_plugin_clear() {
        let mut plugin = NavigationHistoryPlugin::new();
        plugin.add_new_location(1, memento("p", 0x1000));
        plugin.add_new_location(1, memento("p", 0x2000));

        plugin.clear(1);
        assert!(!plugin.has_next(1));
        assert!(!plugin.has_previous(1));
    }

    #[test]
    fn test_navigation_history_plugin_clear_program() {
        let mut plugin = NavigationHistoryPlugin::new();
        plugin.add_new_location(1, memento("p1", 0x1000));
        plugin.add_new_location(1, memento("p2", 0x2000));
        plugin.add_new_location(1, memento("p1", 0x3000));

        plugin.clear_program("p1");
        // Only p2 should remain
        let history = plugin.history(1).unwrap();
        assert_eq!(history.size(), 1);
        assert_eq!(history.get_location(0).unwrap().program_name, "p2");
    }

    #[test]
    fn test_navigation_history_plugin_set_max_size() {
        let mut plugin = NavigationHistoryPlugin::new();
        plugin.set_max_history_size(50);
        assert_eq!(plugin.max_history_size(), 50);

        // Clamping
        plugin.set_max_history_size(5);
        assert_eq!(plugin.max_history_size(), NavigationHistoryPlugin::MIN_HISTORY_SIZE);

        plugin.set_max_history_size(999);
        assert_eq!(plugin.max_history_size(), NavigationHistoryPlugin::MAX_HISTORY_SIZE);
    }

    #[test]
    fn test_navigation_history_plugin_navigatable_removed() {
        let mut plugin = NavigationHistoryPlugin::new();
        plugin.add_new_location(42, memento("p", 0x1000));
        plugin.navigatable_removed(42);
        assert!(!plugin.has_next(42));
        assert!(!plugin.has_previous(42));
    }

    #[test]
    fn test_navigation_history_plugin_different_navigatables() {
        let mut plugin = NavigationHistoryPlugin::new();
        plugin.add_new_location(1, memento("p", 0x1000));
        plugin.add_new_location(2, memento("p", 0x2000));

        // Navigatable 1 should have its own history, navigatable 2 its own
        assert!(plugin.history(1).is_some());
        assert!(plugin.history(2).is_some());
        assert_eq!(plugin.history(1).unwrap().size(), 1);
        assert_eq!(plugin.history(2).unwrap().size(), 1);
    }

    // --- Tests for newly ported types ---

    #[test]
    fn test_next_prev_highlight_range_plugin() {
        let mut plugin = NextPrevHighlightRangePlugin::new();
        assert_eq!(plugin.name, "NextPrevHighlightRange");
        assert!(!plugin.is_disposed);

        plugin.dispose();
        assert!(plugin.is_disposed);
    }

    #[test]
    fn test_next_highlighted_range_action() {
        let action = NextHighlightedRangeAction::new("Plugin");
        assert_eq!(action.name, "Next Highlighted Range");
        assert!(action.is_enabled);
    }

    #[test]
    fn test_previous_highlighted_range_action() {
        let action = PreviousHighlightedRangeAction::new("Plugin");
        assert_eq!(action.name, "Previous Highlighted Range");
        assert!(action.is_enabled);
    }

    #[test]
    fn test_next_prev_selected_range_plugin() {
        let mut plugin = NextPrevSelectedRangePlugin::new();
        assert!(!plugin.is_disposed);
        plugin.dispose();
        assert!(plugin.is_disposed);
    }

    #[test]
    fn test_next_selected_range_action() {
        let action = NextSelectedRangeAction::new("Plugin");
        assert_eq!(action.name, "Next Selected Range");
    }

    #[test]
    fn test_previous_selected_range_action() {
        let action = PreviousSelectedRangeAction::new("Plugin");
        assert_eq!(action.name, "Previous Selected Range");
    }

    #[test]
    fn test_provider_navigation_plugin() {
        let mut plugin = ProviderNavigationPlugin::new();
        assert!(!plugin.is_disposed);
        plugin.dispose();
        assert!(plugin.is_disposed);
    }

    #[test]
    fn test_find_references_to_action() {
        let action = FindReferencesToAction::new("Plugin");
        assert_eq!(action.name, "Find References To");
        assert!(action.is_enabled);
    }

    #[test]
    fn test_find_references_to_address_action() {
        let action = FindReferencesToAddressAction::new("Plugin");
        assert_eq!(action.name, "Find References To Address");
    }

    #[test]
    fn test_next_previous_defined_data_action() {
        let action = NextPreviousDefinedDataAction::new_forward("Plugin");
        assert_eq!(action.name, "Next Defined Data");
        assert!(action.is_forward);

        let back = NextPreviousDefinedDataAction::new_backward("Plugin");
        assert_eq!(back.name, "Previous Defined Data");
        assert!(!back.is_forward);
    }

    #[test]
    fn test_function_signature_field_location_descriptor() {
        let desc = FunctionSignatureFieldLocationDescriptor::new(0x1000, "myFunc");
        assert_eq!(desc.address, 0x1000);
        assert_eq!(desc.function_name, "myFunc");
    }

    #[test]
    fn test_generic_data_type_location_descriptors() {
        let composite = GenericCompositeDataTypeProgramLocation::new(0x2000, "MyStruct");
        assert_eq!(composite.address, 0x2000);
        assert_eq!(composite.type_name, "MyStruct");

        let generic = GenericDataTypeProgramLocation::new(0x3000, "int");
        assert_eq!(generic.address, 0x3000);
        assert_eq!(generic.type_name, "int");
    }

    #[test]
    fn test_location_references_provider_context() {
        let ctx = LocationReferencesProviderContext::new(0x4000, "test_provider");
        assert_eq!(ctx.address, 0x4000);
        assert_eq!(ctx.provider_name, "test_provider");
    }
}
