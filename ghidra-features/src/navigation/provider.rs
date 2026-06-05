//! Navigation provider model.
//!
//! Ported from `ghidra.app.plugin.core.navigation` provider classes.
//!
//! Manages navigation history, bookmarks, and go-to-address functionality.

use std::collections::VecDeque;

/// A single entry in the navigation history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NavigationEntry {
    /// Address of the navigation target.
    pub address: u64,
    /// The address space name (e.g., "ram", "register").
    pub space: String,
    /// Description of what's at this address.
    pub description: String,
    /// The program name.
    pub program_name: String,
}

impl NavigationEntry {
    /// Create a new navigation entry.
    pub fn new(address: u64, space: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            address,
            space: space.into(),
            description: description.into(),
            program_name: String::new(),
        }
    }
}

/// Provides navigation history management.
///
/// Ported from navigation-related classes in Ghidra's navigation plugin.
#[derive(Debug)]
pub struct NavigationHistoryManager {
    /// Backward history.
    back_history: VecDeque<NavigationEntry>,
    /// Forward history.
    forward_history: VecDeque<NavigationEntry>,
    /// Current location.
    current: Option<NavigationEntry>,
    /// Maximum history size.
    max_size: usize,
}

impl NavigationHistoryManager {
    /// Create a new navigation history manager.
    pub fn new() -> Self {
        Self {
            back_history: VecDeque::new(),
            forward_history: VecDeque::new(),
            current: None,
            max_size: 1000,
        }
    }

    /// Navigate to a new location.
    pub fn navigate(&mut self, entry: NavigationEntry) {
        if let Some(prev) = self.current.take() {
            self.back_history.push_back(prev);
            if self.back_history.len() > self.max_size {
                self.back_history.pop_front();
            }
        }
        self.forward_history.clear();
        self.current = Some(entry);
    }

    /// Go back in history.
    pub fn go_back(&mut self) -> Option<&NavigationEntry> {
        if let Some(prev) = self.back_history.pop_back() {
            if let Some(cur) = self.current.take() {
                self.forward_history.push_front(cur);
            }
            self.current = Some(prev);
        }
        self.current.as_ref()
    }

    /// Go forward in history.
    pub fn go_forward(&mut self) -> Option<&NavigationEntry> {
        if let Some(next) = self.forward_history.pop_front() {
            if let Some(cur) = self.current.take() {
                self.back_history.push_back(cur);
            }
            self.current = Some(next);
        }
        self.current.as_ref()
    }

    /// Whether back navigation is available.
    pub fn can_go_back(&self) -> bool {
        !self.back_history.is_empty()
    }

    /// Whether forward navigation is available.
    pub fn can_go_forward(&self) -> bool {
        !self.forward_history.is_empty()
    }

    /// Get the current entry.
    pub fn current(&self) -> Option<&NavigationEntry> {
        self.current.as_ref()
    }

    /// Get the back history length.
    pub fn back_count(&self) -> usize {
        self.back_history.len()
    }

    /// Get the forward history length.
    pub fn forward_count(&self) -> usize {
        self.forward_history.len()
    }

    /// Clear all history.
    pub fn clear(&mut self) {
        self.back_history.clear();
        self.forward_history.clear();
        self.current = None;
    }

    /// Get the back history as a slice.
    pub fn back_history(&self) -> &VecDeque<NavigationEntry> {
        &self.back_history
    }

    /// Get the forward history as a slice.
    pub fn forward_history(&self) -> &VecDeque<NavigationEntry> {
        &self.forward_history
    }
}

impl Default for NavigationHistoryManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Type of navigation destination.
///
/// Ported from navigation action types in Ghidra.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavigationDestinationType {
    /// Go to an address.
    Address,
    /// Go to a function.
    Function,
    /// Go to a label.
    Label,
    /// Go to the next/previous code unit.
    NextCode,
    /// Go to the next/previous function.
    NextFunction,
    /// Go to the next/previous data item.
    NextData,
    /// Go to the next/previous undefined byte.
    NextUndefined,
    /// Go to a bookmark.
    Bookmark,
    /// Go to a reference.
    Reference,
    /// Go to the entry point.
    EntryPoint,
    /// Go to the start of the program.
    ProgramStart,
    /// Go to the end of the program.
    ProgramEnd,
    /// Go to a specific line number.
    LineNumber,
}

/// A navigation target.
#[derive(Debug, Clone)]
pub struct NavigationTarget {
    /// The type of target.
    pub target_type: NavigationDestinationType,
    /// The address.
    pub address: u64,
    /// The address space.
    pub space: String,
    /// A label or description.
    pub label: String,
}

impl NavigationTarget {
    /// Create a new navigation target.
    pub fn new(
        target_type: NavigationDestinationType,
        address: u64,
        space: impl Into<String>,
    ) -> Self {
        Self {
            target_type,
            address,
            space: space.into(),
            label: String::new(),
        }
    }

    /// Convert to a navigation entry for history.
    pub fn to_entry(&self, program_name: &str) -> NavigationEntry {
        NavigationEntry {
            address: self.address,
            space: self.space.clone(),
            description: self.label.clone(),
            program_name: program_name.to_string(),
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_navigation_entry() {
        let entry = NavigationEntry::new(0x401000, "ram", "main function");
        assert_eq!(entry.address, 0x401000);
        assert_eq!(entry.space, "ram");
    }

    #[test]
    fn test_navigation_history_lifecycle() {
        let mut mgr = NavigationHistoryManager::new();
        assert!(!mgr.can_go_back());
        assert!(!mgr.can_go_forward());
        assert!(mgr.current().is_none());

        mgr.navigate(NavigationEntry::new(0x1000, "ram", "start"));
        assert!(mgr.current().is_some());
        assert_eq!(mgr.current().unwrap().address, 0x1000);

        mgr.navigate(NavigationEntry::new(0x2000, "ram", "second"));
        assert!(mgr.can_go_back());
        assert_eq!(mgr.current().unwrap().address, 0x2000);

        mgr.navigate(NavigationEntry::new(0x3000, "ram", "third"));
        assert_eq!(mgr.back_count(), 2);
    }

    #[test]
    fn test_navigation_history_go_back_forward() {
        let mut mgr = NavigationHistoryManager::new();
        mgr.navigate(NavigationEntry::new(0x1000, "ram", "a"));
        mgr.navigate(NavigationEntry::new(0x2000, "ram", "b"));
        mgr.navigate(NavigationEntry::new(0x3000, "ram", "c"));

        mgr.go_back();
        assert_eq!(mgr.current().unwrap().address, 0x2000);
        assert!(mgr.can_go_forward());
        assert_eq!(mgr.forward_count(), 1);

        mgr.go_back();
        assert_eq!(mgr.current().unwrap().address, 0x1000);

        mgr.go_forward();
        assert_eq!(mgr.current().unwrap().address, 0x2000);
    }

    #[test]
    fn test_navigation_history_navigate_clears_forward() {
        let mut mgr = NavigationHistoryManager::new();
        mgr.navigate(NavigationEntry::new(0x1000, "ram", "a"));
        mgr.navigate(NavigationEntry::new(0x2000, "ram", "b"));
        mgr.go_back(); // back to 0x1000
        assert!(mgr.can_go_forward());

        mgr.navigate(NavigationEntry::new(0x4000, "ram", "new"));
        assert!(!mgr.can_go_forward());
        assert!(mgr.can_go_back());
    }

    #[test]
    fn test_navigation_history_clear() {
        let mut mgr = NavigationHistoryManager::new();
        mgr.navigate(NavigationEntry::new(0x1000, "ram", "a"));
        mgr.navigate(NavigationEntry::new(0x2000, "ram", "b"));
        mgr.clear();
        assert!(mgr.current().is_none());
        assert!(!mgr.can_go_back());
        assert!(!mgr.can_go_forward());
    }

    #[test]
    fn test_navigation_destination_type_variants() {
        let targets = vec![
            NavigationDestinationType::Address,
            NavigationDestinationType::Function,
            NavigationDestinationType::Label,
            NavigationDestinationType::NextCode,
            NavigationDestinationType::Bookmark,
        ];
        assert_eq!(targets.len(), 5);
    }

    #[test]
    fn test_navigation_target() {
        let target = NavigationTarget::new(
            NavigationDestinationType::Function,
            0x401000,
            "ram",
        );
        let entry = target.to_entry("my_program");
        assert_eq!(entry.address, 0x401000);
        assert_eq!(entry.program_name, "my_program");
    }

    #[test]
    fn test_navigation_history_max_size() {
        let mut mgr = NavigationHistoryManager::new();
        // Override max_size for test
        mgr.max_size = 3;
        for i in 0..10 {
            mgr.navigate(NavigationEntry::new(i * 0x1000, "ram", format!("entry_{}", i)));
        }
        // Should be limited to max_size
        assert!(mgr.back_count() <= 3);
    }
}
