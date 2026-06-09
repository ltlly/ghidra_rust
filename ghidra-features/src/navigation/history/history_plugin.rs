//! Navigation History Plugin -- full-featured history management.
//!
//! Ported from `ghidra.app.plugin.core.navigation.NavigationHistoryPlugin`.
//!
//! This plugin maintains navigation history for all navigatables, providing
//! back/forward/next-function/previous-function operations and persisting
//! history across tool sessions.
//!
//! # Key Types
//!
//! - [`NavigationHistoryPlugin`] -- Plugin that owns per-navigatable history lists
//! - [`HistoryList`] -- Bounded list of [`LocationMemento`]s with a cursor
//! - [`HistoryEntry`] -- A single entry in the history with function metadata
//!
//! # Java Original
//!
//! The Java `NavigationHistoryPlugin` extends `Plugin` and implements
//! `NavigationHistoryService`. It:
//! - Maintains a `Map<Navigatable, HistoryList>` of history stacks
//! - Provides next/previous/nextFunction/previousFunction operations
//! - Serializes history to/from `SaveState` for tool persistence
//! - Listens for `ProgramClosedPluginEvent` to purge stale entries
//! - Validates history size against configurable min/max bounds
//!
//! Swing UI code is omitted; only model and business logic are ported.

use std::collections::HashMap;

use crate::gotoquery::{LocationMemento, Navigatable, ProgramLocation};
use ghidra_core::Address;

use super::history_service::NavigationHistoryService;

// ---------------------------------------------------------------------------
// HistoryEntry
// ---------------------------------------------------------------------------

/// A single entry in the navigation history with optional function context.
///
/// Extends the basic [`LocationMemento`] with function containment
/// information used by next-function/previous-function navigation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    /// The location memento for this entry.
    pub memento: LocationMemento,
    /// The address of the function containing this location, if any.
    pub containing_function_address: Option<u64>,
    /// The name of the containing function, if any.
    pub containing_function_name: Option<String>,
}

impl HistoryEntry {
    /// Create a new history entry from a memento.
    pub fn new(memento: LocationMemento) -> Self {
        Self {
            memento,
            containing_function_address: None,
            containing_function_name: None,
        }
    }

    /// Create a history entry with function context.
    pub fn with_function(
        memento: LocationMemento,
        function_address: u64,
        function_name: impl Into<String>,
    ) -> Self {
        Self {
            memento,
            containing_function_address: Some(function_address),
            containing_function_name: Some(function_name.into()),
        }
    }

    /// Whether this entry has function context.
    pub fn has_function(&self) -> bool {
        self.containing_function_address.is_some()
    }
}

// ---------------------------------------------------------------------------
// HistoryList
// ---------------------------------------------------------------------------

/// A bounded navigation history for a single navigatable.
///
/// Maintains a list of [`HistoryEntry`]s and a current-position cursor.
/// New locations are added after the cursor, truncating any forward
/// history (like a browser back/forward stack).
///
/// Ported from the inner `HistoryList` class in `NavigationHistoryPlugin.java`.
#[derive(Debug, Clone)]
pub struct HistoryList {
    list: Vec<HistoryEntry>,
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

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Get an entry by index.
    pub fn get_entry(&self, index: usize) -> Option<&HistoryEntry> {
        self.list.get(index)
    }

    /// Get the current entry.
    pub fn current_entry(&self) -> Option<&HistoryEntry> {
        self.list.get(self.current_location)
    }

    /// Get the current [`LocationMemento`].
    pub fn current_location(&self) -> Option<&LocationMemento> {
        self.list.get(self.current_location).map(|e| &e.memento)
    }

    /// Add a new location to the history.
    ///
    /// If we are not at the end of the list, future entries are
    /// discarded first.  Duplicate consecutive entries are collapsed
    /// (the newer one replaces the older).
    pub fn add_location(&mut self, entry: HistoryEntry) {
        if self.list.is_empty() {
            self.list.push(entry);
            self.current_location = 0;
            return;
        }

        // Truncate entries after current
        self.list.truncate(self.current_location + 1);

        // Collapse duplicate consecutive mementos
        let last = self.list.last().unwrap();
        if last.memento == entry.memento {
            *self.list.last_mut().unwrap() = entry;
        } else {
            self.list.push(entry);
        }

        // Enforce max size
        if self.list.len() > self.max_locations {
            self.list.remove(0);
        }

        self.current_location = self.list.len() - 1;
    }

    /// Convenience: add a [`LocationMemento`] directly (without function context).
    pub fn add_memento(&mut self, memento: LocationMemento) {
        self.add_location(HistoryEntry::new(memento));
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
            self.list.get(self.current_location).map(|e| &e.memento)
        } else {
            None
        }
    }

    /// Move backward and return the location.
    pub fn previous(&mut self) -> Option<&LocationMemento> {
        if self.has_previous() {
            self.current_location -= 1;
            self.list.get(self.current_location).map(|e| &e.memento)
        } else {
            None
        }
    }

    /// Find the next entry that is in a different function from the current one.
    ///
    /// Returns `None` if no such entry exists. If `move_to` is true,
    /// the cursor is advanced to the found entry.
    pub fn next_function(
        &mut self,
        current_function_address: Option<u64>,
        move_to: bool,
    ) -> Option<&LocationMemento> {
        if self.list.is_empty() {
            return None;
        }

        for i in (self.current_location + 1)..self.list.len() {
            let entry = &self.list[i];
            // A non-function entry (external, etc.) always counts as a boundary
            if let Some(func_addr) = entry.containing_function_address {
                if Some(func_addr) != current_function_address {
                    if move_to {
                        self.current_location = i;
                    }
                    return self.list.get(i).map(|e| &e.memento);
                }
            } else {
                // Entry without function context -- treat as a boundary
                if move_to {
                    self.current_location = i;
                }
                return self.list.get(i).map(|e| &e.memento);
            }
        }

        None
    }

    /// Find the previous entry that is in a different function from the current one.
    ///
    /// Returns `None` if no such entry exists. If `move_to` is true,
    /// the cursor is moved to the found entry.
    pub fn previous_function(
        &mut self,
        current_function_address: Option<u64>,
        move_to: bool,
    ) -> Option<&LocationMemento> {
        if self.list.is_empty() {
            return None;
        }

        for i in (0..self.current_location).rev() {
            let entry = &self.list[i];
            if let Some(func_addr) = entry.containing_function_address {
                if Some(func_addr) != current_function_address {
                    if move_to {
                        self.current_location = i;
                    }
                    return self.list.get(i).map(|e| &e.memento);
                }
            } else {
                if move_to {
                    self.current_location = i;
                }
                return self.list.get(i).map(|e| &e.memento);
            }
        }

        None
    }

    /// Whether there is a next entry in a different function.
    pub fn has_next_function(&self, current_function_address: Option<u64>) -> bool {
        if self.list.is_empty() {
            return false;
        }
        for i in (self.current_location + 1)..self.list.len() {
            let entry = &self.list[i];
            match entry.containing_function_address {
                Some(func_addr) if Some(func_addr) == current_function_address => continue,
                _ => return true,
            }
        }
        false
    }

    /// Whether there is a previous entry in a different function.
    pub fn has_previous_function(&self, current_function_address: Option<u64>) -> bool {
        if self.list.is_empty() {
            return false;
        }
        for i in (0..self.current_location).rev() {
            let entry = &self.list[i];
            match entry.containing_function_address {
                Some(func_addr) if Some(func_addr) == current_function_address => continue,
                _ => return true,
            }
        }
        false
    }

    /// Remove a specific entry by memento equality.
    pub fn remove(&mut self, memento: &LocationMemento) {
        if let Some(pos) = self.list.iter().position(|e| e.memento == *memento) {
            self.list.remove(pos);
            if self.current_location > 0 && self.current_location >= pos {
                self.current_location -= 1;
            }
        }
    }

    /// Get all next locations (for display in forward menu).
    pub fn get_next_locations(&self) -> Vec<LocationMemento> {
        if self.current_location + 1 < self.list.len() {
            self.list[self.current_location + 1..]
                .iter()
                .map(|e| e.memento.clone())
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Get all previous locations (for display in back menu),
    /// in reverse order (most recent first).
    pub fn get_previous_locations(&self) -> Vec<LocationMemento> {
        if self.current_location > 0 {
            let mut locs: Vec<_> = self.list[..self.current_location]
                .iter()
                .map(|e| e.memento.clone())
                .collect();
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
///
/// Ported from `ghidra.app.plugin.core.navigation.NavigationHistoryPlugin`.
pub struct NavigationHistoryPlugin {
    /// History per navigatable id.
    history_map: HashMap<u64, HistoryList>,
    /// Current max history size.
    max_history_size: usize,
    /// Pending events (simulates plugin event dispatch).
    events: Vec<String>,
    /// Simulated function address map: memento address -> containing function address.
    ///
    /// In the real Ghidra this comes from `FunctionManager.getFunctionContaining()`.
    /// Here we allow callers to register function containment for testing.
    function_map: HashMap<u64, u64>,
    /// Function name map: function address -> function name.
    function_names: HashMap<u64, String>,
}

impl NavigationHistoryPlugin {
    /// The default maximum history size.
    pub const DEFAULT_MAX_HISTORY_SIZE: usize = 30;
    /// Absolute minimum history size.
    pub const MIN_HISTORY_SIZE: usize = 10;
    /// Absolute maximum history size.
    pub const MAX_HISTORY_SIZE: usize = 400;
    /// Option name for max history size (used by tool options).
    pub const MAX_NAVIGATION_HISTORY_SIZE_OPTION: &'static str = "Max Navigation History Size";

    /// Create a new navigation history plugin.
    pub fn new() -> Self {
        Self {
            history_map: HashMap::new(),
            max_history_size: Self::DEFAULT_MAX_HISTORY_SIZE,
            events: Vec::new(),
            function_map: HashMap::new(),
            function_names: HashMap::new(),
        }
    }

    // -- Function map management (simplified from Java's FunctionManager) --

    /// Register a function containment mapping.
    ///
    /// Maps a code address to its containing function address and name.
    /// This is a simplified version of what Ghidra gets from
    /// `FunctionManager.getFunctionContaining(address)`.
    pub fn register_function(
        &mut self,
        code_address: u64,
        function_address: u64,
        function_name: impl Into<String>,
    ) {
        self.function_map.insert(code_address, function_address);
        self.function_names
            .entry(function_address)
            .or_insert_with(|| function_name.into());
    }

    /// Look up the containing function address for a code address.
    pub fn get_containing_function(&self, code_address: u64) -> Option<u64> {
        self.function_map.get(&code_address).copied()
    }

    /// Look up the function name for a function address.
    pub fn get_function_name(&self, function_address: u64) -> Option<&str> {
        self.function_names.get(&function_address).map(|s| s.as_str())
    }

    // -- Core navigation operations --

    /// Record a new location for the given navigatable.
    pub fn add_new_location(&mut self, navigatable_id: u64, memento: LocationMemento) {
        let func_addr = self.get_containing_function(memento.address);
        let entry = match func_addr {
            Some(fa) => {
                let fname = self
                    .get_function_name(fa)
                    .unwrap_or("")
                    .to_string();
                HistoryEntry::with_function(memento, fa, fname)
            }
            None => HistoryEntry::new(memento),
        };

        let history = self
            .history_map
            .entry(navigatable_id)
            .or_insert_with(|| HistoryList::new(self.max_history_size));
        history.add_location(entry);
        self.events.push(format!(
            "History: added location for navigatable {}",
            navigatable_id
        ));
    }

    /// Navigate forward in history and return the location.
    pub fn next(&mut self, navigatable_id: u64) -> Option<LocationMemento> {
        self.history_map
            .get_mut(&navigatable_id)
            .and_then(|h| h.next().cloned())
    }

    /// Navigate backward in history and return the location.
    pub fn previous(&mut self, navigatable_id: u64) -> Option<LocationMemento> {
        self.history_map
            .get_mut(&navigatable_id)
            .and_then(|h| h.previous().cloned())
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

    /// Navigate to the next function boundary in history.
    pub fn next_function(&mut self, navigatable_id: u64) -> Option<LocationMemento> {
        let current_func = self.get_current_function_address(navigatable_id);
        self.history_map
            .get_mut(&navigatable_id)
            .and_then(|h| h.next_function(current_func, true).cloned())
    }

    /// Navigate to the previous function boundary in history.
    pub fn previous_function(&mut self, navigatable_id: u64) -> Option<LocationMemento> {
        let current_func = self.get_current_function_address(navigatable_id);
        self.history_map
            .get_mut(&navigatable_id)
            .and_then(|h| h.previous_function(current_func, true).cloned())
    }

    /// Whether there is a next function in history.
    pub fn has_next_function(&self, navigatable_id: u64) -> bool {
        let current_func = self.get_current_function_address(navigatable_id);
        self.history_map
            .get(&navigatable_id)
            .map_or(false, |h| h.has_next_function(current_func))
    }

    /// Whether there is a previous function in history.
    pub fn has_previous_function(&self, navigatable_id: u64) -> bool {
        let current_func = self.get_current_function_address(navigatable_id);
        self.history_map
            .get(&navigatable_id)
            .map_or(false, |h| h.has_previous_function(current_func))
    }

    /// Get the next locations for display (forward menu).
    pub fn get_next_locations(&self, navigatable_id: u64) -> Vec<LocationMemento> {
        self.history_map
            .get(&navigatable_id)
            .map_or(Vec::new(), |h| h.get_next_locations())
    }

    /// Get the previous locations for display (back menu).
    pub fn get_previous_locations(&self, navigatable_id: u64) -> Vec<LocationMemento> {
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
                .filter(|(_, e)| e.memento.program_name == program_name)
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

    /// Get the history list for a navigatable (for testing/debugging).
    pub fn history(&self, navigatable_id: u64) -> Option<&HistoryList> {
        self.history_map.get(&navigatable_id)
    }

    // -- Serialization (simplified from Java SaveState) --

    /// Serialize all history to a JSON-compatible structure.
    ///
    /// This is the Rust equivalent of the Java `writeDataState` method.
    pub fn to_save_state(&self) -> Vec<(u64, Vec<HistoryEntry>, usize)> {
        self.history_map
            .iter()
            .map(|(&nav_id, list)| {
                (
                    nav_id,
                    list.list.clone(),
                    list.current_location_index(),
                )
            })
            .collect()
    }

    /// Restore history from a serialized structure.
    ///
    /// This is the Rust equivalent of the Java `readDataState` method.
    pub fn from_save_state(
        data: Vec<(u64, Vec<HistoryEntry>, usize)>,
        max_history_size: usize,
    ) -> Self {
        let mut plugin = Self::new();
        plugin.max_history_size = max_history_size;
        for (nav_id, entries, current_idx) in data {
            let mut list = HistoryList::new(max_history_size);
            for entry in entries {
                list.add_location(entry);
            }
            list.set_current_location_index(current_idx);
            plugin.history_map.insert(nav_id, list);
        }
        plugin
    }

    // -- Private helpers --

    /// Get the function address for the current location of a navigatable.
    fn get_current_function_address(&self, navigatable_id: u64) -> Option<u64> {
        self.history_map
            .get(&navigatable_id)
            .and_then(|h| h.current_entry())
            .and_then(|e| e.containing_function_address)
    }
}

impl Default for NavigationHistoryPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// NavigationHistoryServiceImpl
// ---------------------------------------------------------------------------

/// Implementation of [`NavigationHistoryService`] backed by
/// [`NavigationHistoryPlugin`].
///
/// This struct adapts the plugin to the service trait, providing
/// the interface that other plugins consume via the tool's service
/// registry.
pub struct NavigationHistoryServiceImpl {
    plugin: NavigationHistoryPlugin,
}

impl NavigationHistoryServiceImpl {
    /// Create a new service wrapping the given plugin.
    pub fn new(plugin: NavigationHistoryPlugin) -> Self {
        Self { plugin }
    }

    /// Get a reference to the underlying plugin.
    pub fn plugin(&self) -> &NavigationHistoryPlugin {
        &self.plugin
    }

    /// Get a mutable reference to the underlying plugin.
    pub fn plugin_mut(&mut self) -> &mut NavigationHistoryPlugin {
        &mut self.plugin
    }
}

impl NavigationHistoryService for NavigationHistoryServiceImpl {
    fn next(&mut self, navigatable_id: u64) {
        self.plugin.next(navigatable_id);
    }

    fn previous(&mut self, navigatable_id: u64) {
        self.plugin.previous(navigatable_id);
    }

    fn next_to(&mut self, navigatable_id: u64, location: &LocationMemento) {
        // Navigate forward until we find the target location
        while self.plugin.has_next(navigatable_id) {
            let next_memento = self.plugin.next(navigatable_id);
            if let Some(m) = next_memento {
                if m == *location {
                    break;
                }
            }
        }
    }

    fn previous_to(&mut self, navigatable_id: u64, location: &LocationMemento) {
        // Navigate backward until we find the target location
        while self.plugin.has_previous(navigatable_id) {
            let prev_memento = self.plugin.previous(navigatable_id);
            if let Some(m) = prev_memento {
                if m == *location {
                    break;
                }
            }
        }
    }

    fn next_function(&mut self, navigatable_id: u64) {
        self.plugin.next_function(navigatable_id);
    }

    fn previous_function(&mut self, navigatable_id: u64) {
        self.plugin.previous_function(navigatable_id);
    }

    fn get_previous_locations(&self, navigatable_id: u64) -> Vec<LocationMemento> {
        self.plugin.get_previous_locations(navigatable_id)
    }

    fn get_next_locations(&self, navigatable_id: u64) -> Vec<LocationMemento> {
        self.plugin.get_next_locations(navigatable_id)
    }

    fn has_next(&self, navigatable_id: u64) -> bool {
        self.plugin.has_next(navigatable_id)
    }

    fn has_previous(&self, navigatable_id: u64) -> bool {
        self.plugin.has_previous(navigatable_id)
    }

    fn has_next_function(&self, navigatable_id: u64) -> bool {
        self.plugin.has_next_function(navigatable_id)
    }

    fn has_previous_function(&self, navigatable_id: u64) -> bool {
        self.plugin.has_previous_function(navigatable_id)
    }

    fn add_new_location(&mut self, navigatable_id: u64, memento: LocationMemento) {
        self.plugin.add_new_location(navigatable_id, memento);
    }

    fn clear(&mut self, navigatable_id: u64) {
        self.plugin.clear(navigatable_id);
    }

    fn clear_program(&mut self, program_name: &str) {
        self.plugin.clear_program(program_name);
    }

    fn navigatable_removed(&mut self, navigatable_id: u64) {
        self.plugin.navigatable_removed(navigatable_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn memento(program: &str, offset: u64) -> LocationMemento {
        LocationMemento::new(program, addr(offset), 0)
    }

    // -- HistoryEntry tests --

    #[test]
    fn test_history_entry_new() {
        let m = memento("prog", 0x1000);
        let entry = HistoryEntry::new(m.clone());
        assert_eq!(entry.memento, m);
        assert!(!entry.has_function());
        assert!(entry.containing_function_address.is_none());
    }

    #[test]
    fn test_history_entry_with_function() {
        let m = memento("prog", 0x1000);
        let entry = HistoryEntry::with_function(m.clone(), 0x1000, "main");
        assert!(entry.has_function());
        assert_eq!(entry.containing_function_address, Some(0x1000));
        assert_eq!(entry.containing_function_name.as_deref(), Some("main"));
    }

    // -- HistoryList tests --

    #[test]
    fn test_history_list_basic() {
        let mut hl = HistoryList::new(10);
        assert_eq!(hl.size(), 0);
        assert!(hl.is_empty());
        assert!(!hl.has_next());
        assert!(!hl.has_previous());

        hl.add_memento(memento("p", 0x1000));
        assert_eq!(hl.size(), 1);
        assert_eq!(hl.current_location_index(), 0);
        assert!(!hl.has_next());
        assert!(!hl.has_previous());
    }

    #[test]
    fn test_history_list_add_and_navigate() {
        let mut hl = HistoryList::new(10);
        hl.add_memento(memento("p", 0x1000));
        hl.add_memento(memento("p", 0x2000));
        hl.add_memento(memento("p", 0x3000));

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
        hl.add_memento(memento("p", 0x1000));
        hl.add_memento(memento("p", 0x2000));
        hl.add_memento(memento("p", 0x3000));

        hl.previous();
        hl.previous();

        hl.add_memento(memento("p", 0x1500));
        assert_eq!(hl.size(), 2);
        assert_eq!(hl.get_entry(0).unwrap().memento.address, 0x1000);
        assert_eq!(hl.get_entry(1).unwrap().memento.address, 0x1500);
    }

    #[test]
    fn test_history_list_max_size() {
        let mut hl = HistoryList::new(3);
        hl.add_memento(memento("p", 0x1000));
        hl.add_memento(memento("p", 0x2000));
        hl.add_memento(memento("p", 0x3000));
        hl.add_memento(memento("p", 0x4000));

        assert_eq!(hl.size(), 3);
        assert_eq!(hl.get_entry(0).unwrap().memento.address, 0x2000);
    }

    #[test]
    fn test_history_list_remove() {
        let mut hl = HistoryList::new(10);
        let m1 = memento("p", 0x1000);
        let m2 = memento("p", 0x2000);
        let m3 = memento("p", 0x3000);
        hl.add_memento(m1.clone());
        hl.add_memento(m2.clone());
        hl.add_memento(m3.clone());

        hl.remove(&m2);
        assert_eq!(hl.size(), 2);
    }

    #[test]
    fn test_history_list_next_previous_locations() {
        let mut hl = HistoryList::new(10);
        hl.add_memento(memento("p", 0x1000));
        hl.add_memento(memento("p", 0x2000));
        hl.add_memento(memento("p", 0x3000));

        let next_locs = hl.get_next_locations();
        assert!(next_locs.is_empty());

        let prev_locs = hl.get_previous_locations();
        assert_eq!(prev_locs.len(), 2);
        assert_eq!(prev_locs[0].address, 0x2000);
        assert_eq!(prev_locs[1].address, 0x1000);
    }

    #[test]
    fn test_history_list_set_max_locations() {
        let mut hl = HistoryList::new(100);
        for i in 0..50 {
            hl.add_memento(memento("p", 0x1000 + i * 0x100));
        }
        assert_eq!(hl.size(), 50);

        hl.set_max_locations(10);
        assert_eq!(hl.size(), 10);
    }

    #[test]
    fn test_history_list_next_function() {
        let mut hl = HistoryList::new(10);
        let e1 = HistoryEntry::with_function(memento("p", 0x1000), 0x1000, "funcA");
        let e2 = HistoryEntry::with_function(memento("p", 0x1010), 0x1000, "funcA");
        let e3 = HistoryEntry::with_function(memento("p", 0x2000), 0x2000, "funcB");
        let e4 = HistoryEntry::with_function(memento("p", 0x3000), 0x3000, "funcC");

        hl.add_location(e1);
        hl.add_location(e2);
        hl.add_location(e3);
        hl.add_location(e4);

        // Current is funcC (index 3). Looking for next function -- none beyond.
        assert!(!hl.has_next_function(Some(0x3000)));

        // Go back to funcA (index 1).
        hl.previous();
        hl.previous();

        // has_next_function from funcA should find funcB
        assert!(hl.has_next_function(Some(0x1000)));

        let next_fn = hl.next_function(Some(0x1000), true);
        assert!(next_fn.is_some());
        assert_eq!(next_fn.unwrap().address, 0x2000);
    }

    #[test]
    fn test_history_list_previous_function() {
        let mut hl = HistoryList::new(10);
        let e1 = HistoryEntry::with_function(memento("p", 0x1000), 0x1000, "funcA");
        let e2 = HistoryEntry::with_function(memento("p", 0x2000), 0x2000, "funcB");
        let e3 = HistoryEntry::with_function(memento("p", 0x3000), 0x3000, "funcC");

        hl.add_location(e1);
        hl.add_location(e2);
        hl.add_location(e3);

        // Current is funcC. Previous function should find funcB.
        assert!(hl.has_previous_function(Some(0x3000)));
        let prev_fn = hl.previous_function(Some(0x3000), true);
        assert!(prev_fn.is_some());
        assert_eq!(prev_fn.unwrap().address, 0x2000);

        // Now in funcB. Previous function should find funcA.
        assert!(hl.has_previous_function(Some(0x2000)));
        let prev_fn2 = hl.previous_function(Some(0x2000), true);
        assert!(prev_fn2.is_some());
        assert_eq!(prev_fn2.unwrap().address, 0x1000);

        // Now in funcA. No previous function.
        assert!(!hl.has_previous_function(Some(0x1000)));
    }

    #[test]
    fn test_history_list_no_function_boundary_without_function_context() {
        let mut hl = HistoryList::new(10);
        // Entries without function context
        hl.add_memento(memento("p", 0x1000));
        hl.add_memento(memento("p", 0x2000));

        // Without function context, any entry counts as a boundary
        assert!(hl.has_next_function(None));
        assert!(hl.has_previous_function(None));
    }

    // -- NavigationHistoryPlugin tests --

    #[test]
    fn test_plugin_basic() {
        let mut plugin = NavigationHistoryPlugin::new();
        assert_eq!(plugin.max_history_size(), 30);

        let m = memento("test.exe", 0x1000);
        plugin.add_new_location(1, m);

        assert!(!plugin.has_next(1));
    }

    #[test]
    fn test_plugin_navigate() {
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
    fn test_plugin_clear() {
        let mut plugin = NavigationHistoryPlugin::new();
        plugin.add_new_location(1, memento("p", 0x1000));
        plugin.add_new_location(1, memento("p", 0x2000));

        plugin.clear(1);
        assert!(!plugin.has_next(1));
        assert!(!plugin.has_previous(1));
    }

    #[test]
    fn test_plugin_clear_program() {
        let mut plugin = NavigationHistoryPlugin::new();
        plugin.add_new_location(1, memento("p1", 0x1000));
        plugin.add_new_location(1, memento("p2", 0x2000));
        plugin.add_new_location(1, memento("p1", 0x3000));

        plugin.clear_program("p1");
        let history = plugin.history(1).unwrap();
        assert_eq!(history.size(), 1);
        assert_eq!(history.get_entry(0).unwrap().memento.program_name, "p2");
    }

    #[test]
    fn test_plugin_set_max_size() {
        let mut plugin = NavigationHistoryPlugin::new();
        plugin.set_max_history_size(50);
        assert_eq!(plugin.max_history_size(), 50);

        plugin.set_max_history_size(5);
        assert_eq!(plugin.max_history_size(), NavigationHistoryPlugin::MIN_HISTORY_SIZE);

        plugin.set_max_history_size(999);
        assert_eq!(plugin.max_history_size(), NavigationHistoryPlugin::MAX_HISTORY_SIZE);
    }

    #[test]
    fn test_plugin_navigatable_removed() {
        let mut plugin = NavigationHistoryPlugin::new();
        plugin.add_new_location(42, memento("p", 0x1000));
        plugin.navigatable_removed(42);
        assert!(!plugin.has_next(42));
        assert!(!plugin.has_previous(42));
    }

    #[test]
    fn test_plugin_different_navigatables() {
        let mut plugin = NavigationHistoryPlugin::new();
        plugin.add_new_location(1, memento("p", 0x1000));
        plugin.add_new_location(2, memento("p", 0x2000));

        assert!(plugin.history(1).is_some());
        assert!(plugin.history(2).is_some());
        assert_eq!(plugin.history(1).unwrap().size(), 1);
        assert_eq!(plugin.history(2).unwrap().size(), 1);
    }

    #[test]
    fn test_plugin_function_navigation() {
        let mut plugin = NavigationHistoryPlugin::new();

        // Register function containment
        plugin.register_function(0x1000, 0x1000, "funcA");
        plugin.register_function(0x1010, 0x1000, "funcA");
        plugin.register_function(0x2000, 0x2000, "funcB");
        plugin.register_function(0x3000, 0x3000, "funcC");

        plugin.add_new_location(1, memento("p", 0x1000));
        plugin.add_new_location(1, memento("p", 0x1010));
        plugin.add_new_location(1, memento("p", 0x2000));
        plugin.add_new_location(1, memento("p", 0x3000));

        assert!(plugin.has_next_function(1));
        assert!(plugin.has_previous_function(1));

        let prev_fn = plugin.previous_function(1).unwrap();
        assert_eq!(prev_fn.address, 0x2000);
    }

    #[test]
    fn test_plugin_save_restore() {
        let mut plugin = NavigationHistoryPlugin::new();
        plugin.add_new_location(1, memento("p", 0x1000));
        plugin.add_new_location(1, memento("p", 0x2000));

        let state = plugin.to_save_state();
        assert_eq!(state.len(), 1);

        let restored = NavigationHistoryPlugin::from_save_state(state, 30);
        assert!(restored.history(1).is_some());
        assert_eq!(restored.history(1).unwrap().size(), 2);
    }

    #[test]
    fn test_plugin_events() {
        let mut plugin = NavigationHistoryPlugin::new();
        assert!(plugin.events().is_empty());

        plugin.add_new_location(1, memento("p", 0x1000));
        assert!(!plugin.events().is_empty());

        plugin.clear(1);
        assert!(plugin.events().len() >= 2);
    }

    #[test]
    fn test_plugin_default() {
        let plugin = NavigationHistoryPlugin::default();
        assert_eq!(plugin.max_history_size(), NavigationHistoryPlugin::DEFAULT_MAX_HISTORY_SIZE);
    }

    // -- NavigationHistoryServiceImpl tests --

    #[test]
    fn test_service_impl_basic() {
        let plugin = NavigationHistoryPlugin::new();
        let mut svc = NavigationHistoryServiceImpl::new(plugin);

        svc.add_new_location(1, memento("p", 0x1000));
        svc.add_new_location(1, memento("p", 0x2000));

        assert!(svc.has_previous(1));
        assert!(!svc.has_next(1));

        svc.previous(1);
        assert!(svc.has_next(1));

        svc.next(1);
        assert!(!svc.has_next(1));
    }

    #[test]
    fn test_service_impl_next_to() {
        let plugin = NavigationHistoryPlugin::new();
        let mut svc = NavigationHistoryServiceImpl::new(plugin);

        svc.add_new_location(1, memento("p", 0x1000));
        svc.add_new_location(1, memento("p", 0x2000));
        svc.add_new_location(1, memento("p", 0x3000));

        // Go back to 0x1000
        svc.previous(1);
        svc.previous(1);

        // Navigate forward to 0x3000 specifically
        let target = memento("p", 0x3000);
        svc.next_to(1, &target);

        assert!(!svc.has_next(1));
    }

    #[test]
    fn test_service_impl_previous_to() {
        let plugin = NavigationHistoryPlugin::new();
        let mut svc = NavigationHistoryServiceImpl::new(plugin);

        svc.add_new_location(1, memento("p", 0x1000));
        svc.add_new_location(1, memento("p", 0x2000));
        svc.add_new_location(1, memento("p", 0x3000));

        // Navigate backward to 0x1000 specifically
        let target = memento("p", 0x1000);
        svc.previous_to(1, &target);

        assert!(!svc.has_previous(1));
    }

    #[test]
    fn test_service_impl_clear_program() {
        let plugin = NavigationHistoryPlugin::new();
        let mut svc = NavigationHistoryServiceImpl::new(plugin);

        svc.add_new_location(1, memento("p1", 0x1000));
        svc.add_new_location(1, memento("p2", 0x2000));

        svc.clear_program("p1");
        let locs = svc.get_previous_locations(1);
        assert!(locs.iter().all(|m| m.program_name != "p1"));
    }

    #[test]
    fn test_service_impl_navigatable_removed() {
        let plugin = NavigationHistoryPlugin::new();
        let mut svc = NavigationHistoryServiceImpl::new(plugin);

        svc.add_new_location(10, memento("p", 0x1000));
        svc.navigatable_removed(10);
        assert!(!svc.has_next(10));
        assert!(!svc.has_previous(10));
    }

    #[test]
    fn test_service_impl_locations() {
        let plugin = NavigationHistoryPlugin::new();
        let mut svc = NavigationHistoryServiceImpl::new(plugin);

        svc.add_new_location(1, memento("p", 0x1000));
        svc.add_new_location(1, memento("p", 0x2000));
        svc.add_new_location(1, memento("p", 0x3000));

        let next_locs = svc.get_next_locations(1);
        assert!(next_locs.is_empty());

        let prev_locs = svc.get_previous_locations(1);
        assert_eq!(prev_locs.len(), 2);
        assert_eq!(prev_locs[0].address, 0x2000);
    }

    #[test]
    fn test_service_impl_function_ops() {
        let mut plugin = NavigationHistoryPlugin::new();
        plugin.register_function(0x1000, 0x1000, "funcA");
        plugin.register_function(0x2000, 0x2000, "funcB");

        let mut svc = NavigationHistoryServiceImpl::new(plugin);
        svc.add_new_location(1, memento("p", 0x1000));
        svc.add_new_location(1, memento("p", 0x2000));

        assert!(svc.has_previous_function(1));
        svc.previous_function(1);

        assert!(svc.has_next_function(1));
        svc.next_function(1);
    }
}
