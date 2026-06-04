//! MultiProgramManager -- tracks open programs and their state.
//!
//! Ported from `ghidra.app.plugin.core.progmgr.MultiProgramManager`.
//!
//! Maintains a map of open programs with their visibility, ordering,
//! and owner information.  Fires events when programs are opened,
//! closed, activated, or change visibility.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use super::ProgramLocator;

/// Program open state constants.
pub const OPEN_CURRENT: i32 = 0;
/// Program is visible but not the active tab.
pub const OPEN_VISIBLE: i32 = 1;
/// Program is opened but hidden.
pub const OPEN_HIDDEN: i32 = 2;

/// Events fired by the MultiProgramManager.
#[derive(Debug, Clone)]
pub enum ProgramEvent {
    /// A program was opened.
    Opened(String),
    /// A program was closed.
    Closed(String),
    /// A program was activated (became the current program).
    Activated(Option<String>),
    /// A program's visibility changed.
    VisibilityChanged { name: String, visible: bool },
}

/// Information about an open program.
#[derive(Debug, Clone)]
pub struct ProgramInfo {
    /// The program name.
    pub name: String,
    /// The locator for this program.
    pub locator: ProgramLocator,
    /// Whether this program is visible in the tool.
    pub visible: bool,
    /// The persistent owner (if any), preventing automatic close.
    pub owner: Option<String>,
    /// Instance ID for ordering.
    instance: u64,
    /// Whether this program has unsaved changes.
    pub is_changed: bool,
    /// Display name (cached).
    display_name: Option<String>,
}

static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);

impl ProgramInfo {
    /// Create a new ProgramInfo.
    pub fn new(name: impl Into<String>, locator: ProgramLocator, visible: bool) -> Self {
        Self {
            name: name.into(),
            locator,
            visible,
            owner: None,
            instance: NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed),
            is_changed: false,
            display_name: None,
        }
    }

    /// Returns the display name for this program.
    pub fn display_name(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.name)
    }

    /// Invalidate the cached display name.
    pub fn invalidate_display_name(&mut self) {
        self.display_name = None;
    }
}

/// Tracks all open programs in the tool.
///
/// Programs are stored in a map keyed by name.  The manager supports:
/// - opening/closing programs
/// - switching the current (active) program
/// - visibility management
/// - persistent ownership
/// - ordering by open time
#[derive(Debug)]
pub struct MultiProgramManager {
    /// Map from program name to its info.
    programs: HashMap<String, ProgramInfo>,
    /// The name of the currently active program.
    current_program_name: Option<String>,
    /// Pending events.
    events: Vec<ProgramEvent>,
}

impl MultiProgramManager {
    /// Create a new MultiProgramManager.
    pub fn new() -> Self {
        Self {
            programs: HashMap::new(),
            current_program_name: None,
            events: Vec::new(),
        }
    }

    // ------------------------------------------------------------------
    // Program lifecycle
    // ------------------------------------------------------------------

    /// Add a program to the manager.
    ///
    /// If the program is already open, its visibility may be updated.
    /// If `state` is `OPEN_CURRENT`, it becomes the active program.
    pub fn add_program(
        &mut self,
        name: impl Into<String>,
        locator: ProgramLocator,
        state: i32,
    ) {
        let n = name.into();
        let visible = state != OPEN_HIDDEN;

        if let Some(info) = self.programs.get_mut(&n) {
            if !info.visible && visible {
                info.visible = true;
                self.events.push(ProgramEvent::VisibilityChanged {
                    name: n.clone(),
                    visible: true,
                });
            }
        } else {
            let info = ProgramInfo::new(&n, locator, visible);
            self.programs.insert(n.clone(), info);
            self.events.push(ProgramEvent::Opened(n.clone()));
        }

        if state == OPEN_CURRENT {
            self.set_current_program_inner(&n);
        }
    }

    /// Remove a program from the manager.
    pub fn remove_program(&mut self, name: &str) {
        if let Some(info) = self.programs.get(name) {
            if info.owner.is_some() {
                // Persist: just hide
                if let Some(info) = self.programs.get_mut(name) {
                    info.visible = false;
                    self.events.push(ProgramEvent::VisibilityChanged {
                        name: name.to_string(),
                        visible: false,
                    });
                }
                // If it was the current program, switch to another
                if self.current_program_name.as_deref() == Some(name) {
                    let next = self.find_next_current();
                    self.set_current_program_inner(&next.unwrap_or_default());
                }
            } else {
                self.programs.remove(name);
                self.events.push(ProgramEvent::Closed(name.to_string()));
                if self.current_program_name.as_deref() == Some(name) {
                    let next = self.find_next_current();
                    self.set_current_program_inner(&next.unwrap_or_default());
                }
            }
        }
    }

    /// Returns the name of the currently active program.
    pub fn current_program_name(&self) -> Option<&str> {
        self.current_program_name.as_deref()
    }

    /// Set the current (active) program.
    pub fn set_current_program(&mut self, name: &str) {
        self.set_current_program_inner(name);
    }

    fn set_current_program_inner(&mut self, name: &str) {
        if self.current_program_name.as_deref() == Some(name) {
            return;
        }
        if name.is_empty() {
            self.current_program_name = None;
            self.events.push(ProgramEvent::Activated(None));
            return;
        }
        if self.programs.contains_key(name) {
            self.current_program_name = Some(name.to_string());
            self.events.push(ProgramEvent::Activated(Some(name.to_string())));
        }
    }

    fn find_next_current(&self) -> Option<String> {
        // Find the first visible program by instance order
        let mut visible: Vec<(&String, &ProgramInfo)> = self
            .programs
            .iter()
            .filter(|(_, info)| info.visible)
            .collect();
        visible.sort_by_key(|(_, info)| info.instance);
        visible.first().map(|(name, _)| (*name).clone())
    }

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    /// Returns `true` if the manager has no programs.
    pub fn is_empty(&self) -> bool {
        self.programs.is_empty()
    }

    /// Returns the number of open programs.
    pub fn program_count(&self) -> usize {
        self.programs.len()
    }

    /// Check if a program is open.
    pub fn contains(&self, name: &str) -> bool {
        self.programs.contains_key(name)
    }

    /// Check if a program is visible.
    pub fn is_visible(&self, name: &str) -> bool {
        self.programs
            .get(name)
            .map(|info| info.visible)
            .unwrap_or(false)
    }

    /// Returns all program names, sorted by open order.
    pub fn all_program_names(&self) -> Vec<String> {
        let mut names: Vec<(&String, &ProgramInfo)> = self.programs.iter().collect();
        names.sort_by_key(|(_, info)| info.instance);
        names.into_iter().map(|(name, _)| name.clone()).collect()
    }

    /// Returns all visible program names, sorted by open order.
    pub fn visible_program_names(&self) -> Vec<String> {
        let mut names: Vec<(&String, &ProgramInfo)> = self
            .programs
            .iter()
            .filter(|(_, info)| info.visible)
            .collect();
        names.sort_by_key(|(_, info)| info.instance);
        names.into_iter().map(|(name, _)| name.clone()).collect()
    }

    /// Returns all program names except the current one.
    pub fn other_program_names(&self) -> Vec<String> {
        self.all_program_names()
            .into_iter()
            .filter(|n| Some(n.as_str()) != self.current_program_name())
            .collect()
    }

    /// Returns a reference to the info for a program.
    pub fn get_info(&self, name: &str) -> Option<&ProgramInfo> {
        self.programs.get(name)
    }

    /// Returns a mutable reference to the info for a program.
    pub fn get_info_mut(&mut self, name: &str) -> Option<&mut ProgramInfo> {
        self.programs.get_mut(name)
    }

    /// Check if there are any unsaved programs.
    pub fn has_unsaved_programs(&self) -> bool {
        self.programs.values().any(|info| info.is_changed)
    }

    /// Find a program by its locator.
    pub fn find_by_locator(&self, locator: &ProgramLocator) -> Option<&str> {
        self.programs
            .iter()
            .find(|(_, info)| &info.locator == locator)
            .map(|(name, _)| name.as_str())
    }

    // ------------------------------------------------------------------
    // Ownership
    // ------------------------------------------------------------------

    /// Set a persistent owner on a program, preventing it from being
    /// automatically closed.
    pub fn set_persistent_owner(&mut self, name: &str, owner: impl Into<String>) -> bool {
        if let Some(info) = self.programs.get_mut(name) {
            if info.owner.is_none() {
                info.owner = Some(owner.into());
                return true;
            }
        }
        false
    }

    /// Release the persistent owner on a program.
    pub fn release_program(&mut self, name: &str, owner: &str) {
        if let Some(info) = self.programs.get_mut(name) {
            if info.owner.as_deref() == Some(owner) {
                info.owner = None;
            }
        }
    }

    /// Check if a program has a persistent owner.
    pub fn is_persistent(&self, name: &str) -> bool {
        self.programs
            .get(name)
            .map(|info| info.owner.is_some())
            .unwrap_or(false)
    }

    // ------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------

    /// Drain and return all pending events.
    pub fn drain_events(&mut self) -> Vec<ProgramEvent> {
        std::mem::take(&mut self.events)
    }

    /// Clear all programs (for disposal).
    pub fn dispose(&mut self) {
        self.programs.clear();
        self.current_program_name = None;
        self.events.clear();
    }
}

impl Default for MultiProgramManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loc(name: &str) -> ProgramLocator {
        ProgramLocator::from_path(format!("/test/{}", name))
    }

    #[test]
    fn test_add_and_query() {
        let mut mgr = MultiProgramManager::new();
        mgr.add_program("prog1", loc("prog1"), OPEN_CURRENT);

        assert!(mgr.contains("prog1"));
        assert_eq!(mgr.program_count(), 1);
        assert_eq!(mgr.current_program_name(), Some("prog1"));
        assert!(!mgr.is_empty());
    }

    #[test]
    fn test_multiple_programs() {
        let mut mgr = MultiProgramManager::new();
        mgr.add_program("a", loc("a"), OPEN_CURRENT);
        mgr.add_program("b", loc("b"), OPEN_VISIBLE);
        mgr.add_program("c", loc("c"), OPEN_HIDDEN);

        assert_eq!(mgr.program_count(), 3);
        assert_eq!(mgr.current_program_name(), Some("a"));

        let visible = mgr.visible_program_names();
        assert_eq!(visible.len(), 2); // a and b
        assert!(!mgr.is_visible("c"));
    }

    #[test]
    fn test_remove_program() {
        let mut mgr = MultiProgramManager::new();
        mgr.add_program("a", loc("a"), OPEN_CURRENT);
        mgr.add_program("b", loc("b"), OPEN_VISIBLE);

        mgr.remove_program("a");
        assert!(!mgr.contains("a"));
        assert_eq!(mgr.current_program_name(), Some("b"));

        let events = mgr.drain_events();
        assert!(events
            .iter()
            .any(|e| matches!(e, ProgramEvent::Closed(n) if n == "a")));
    }

    #[test]
    fn test_set_current() {
        let mut mgr = MultiProgramManager::new();
        mgr.add_program("a", loc("a"), OPEN_VISIBLE);
        mgr.add_program("b", loc("b"), OPEN_VISIBLE);

        mgr.set_current_program("b");
        assert_eq!(mgr.current_program_name(), Some("b"));
    }

    #[test]
    fn test_persistent_owner() {
        let mut mgr = MultiProgramManager::new();
        mgr.add_program("a", loc("a"), OPEN_CURRENT);

        assert!(mgr.set_persistent_owner("a", "analysis"));
        assert!(mgr.is_persistent("a"));

        // Removing a persistent program just hides it
        mgr.remove_program("a");
        assert!(mgr.contains("a"));
        assert!(!mgr.is_visible("a"));

        mgr.release_program("a", "analysis");
        assert!(!mgr.is_persistent("a"));
    }

    #[test]
    fn test_find_by_locator() {
        let mut mgr = MultiProgramManager::new();
        mgr.add_program("prog", loc("prog"), OPEN_CURRENT);

        let found = mgr.find_by_locator(&loc("prog"));
        assert_eq!(found, Some("prog"));

        let not_found = mgr.find_by_locator(&ProgramLocator::from_path("/other"));
        assert!(not_found.is_none());
    }

    #[test]
    fn test_unsaved_programs() {
        let mut mgr = MultiProgramManager::new();
        mgr.add_program("a", loc("a"), OPEN_CURRENT);
        assert!(!mgr.has_unsaved_programs());

        mgr.get_info_mut("a").unwrap().is_changed = true;
        assert!(mgr.has_unsaved_programs());
    }

    #[test]
    fn test_other_programs() {
        let mut mgr = MultiProgramManager::new();
        mgr.add_program("a", loc("a"), OPEN_CURRENT);
        mgr.add_program("b", loc("b"), OPEN_VISIBLE);

        let others = mgr.other_program_names();
        assert_eq!(others, vec!["b"]);
    }

    #[test]
    fn test_events() {
        let mut mgr = MultiProgramManager::new();
        mgr.add_program("a", loc("a"), OPEN_CURRENT);
        let events = mgr.drain_events();
        assert!(events
            .iter()
            .any(|e| matches!(e, ProgramEvent::Opened(n) if n == "a")));
        assert!(events
            .iter()
            .any(|e| matches!(e, ProgramEvent::Activated(Some(n)) if n == "a")));
    }
}
