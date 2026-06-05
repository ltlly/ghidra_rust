//! Navigation types for program viewers and navigatables.
//!
//! Ported from Ghidra's `ghidra.app.nav` Java package. Provides the
//! [`Navigatable`] trait, [`LocationMemento`] for save/restore,
//! and navigation utility types.

use std::sync::Arc;

// ---------------------------------------------------------------------------
// Placeholder types
// ---------------------------------------------------------------------------

/// Placeholder for a Ghidra Program.
#[derive(Debug, Clone)]
pub struct Program {
    pub name: String,
}

/// Placeholder for a program address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub u64);

/// Placeholder for a program location.
#[derive(Debug, Clone)]
pub struct ProgramLocation {
    pub address: Address,
}

/// Placeholder for a program selection.
#[derive(Debug, Clone, Default)]
pub struct ProgramSelection {
    pub ranges: Vec<(Address, Address)>,
}

// ---------------------------------------------------------------------------
// LocationMemento
// ---------------------------------------------------------------------------

/// Serializable snapshot of a navigatable's view state (program, location,
/// selection, highlight). Used to save and restore view state.
#[derive(Debug, Clone)]
pub struct LocationMemento {
    program_name: String,
    location: ProgramLocation,
    selection: ProgramSelection,
    highlight: ProgramSelection,
}

impl LocationMemento {
    pub fn new(
        program_name: impl Into<String>,
        location: ProgramLocation,
        selection: ProgramSelection,
        highlight: ProgramSelection,
    ) -> Self {
        Self {
            program_name: program_name.into(),
            location,
            selection,
            highlight,
        }
    }

    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    pub fn location(&self) -> &ProgramLocation {
        &self.location
    }

    pub fn selection(&self) -> &ProgramSelection {
        &self.selection
    }

    pub fn highlight(&self) -> &ProgramSelection {
        &self.highlight
    }
}

// ---------------------------------------------------------------------------
// Navigatable trait
// ---------------------------------------------------------------------------

/// Interface for component providers that support navigation and selection.
///
/// Implementing this interface gives a provider navigation history and
/// actions that require navigation or selection (search text, search
/// memory, select bytes, select instructions, etc.).
pub trait Navigatable: std::fmt::Debug + Send + Sync {
    /// Unique instance ID for this navigatable.
    fn get_instance_id(&self) -> u64;

    /// Navigate to the given program and location.
    fn go_to(&self, program: &Program, location: &ProgramLocation) -> bool;

    /// Navigate to a location (using the program in the location).
    fn go_to_location(&self, location: &ProgramLocation) -> bool {
        // Default: delegate to go_to with a stub program
        let program = Program {
            name: String::new(),
        };
        self.go_to(&program, location)
    }

    /// Get the current location of this navigatable.
    fn get_location(&self) -> Option<ProgramLocation>;

    /// Get the current program.
    fn get_program(&self) -> Option<Arc<Program>>;

    /// Get a memento to save the current view state.
    fn get_memento(&self) -> Option<LocationMemento>;

    /// Restore a previously saved view state.
    fn set_memento(&self, memento: &LocationMemento);

    /// Returns true if this navigatable is connected (produces and
    /// consumes location/selection events).
    fn is_connected(&self) -> bool;

    /// Returns true if this navigatable is part of the debugger UI.
    fn is_dynamic(&self) -> bool {
        false
    }

    /// Returns true if this navigatable supports markers.
    fn supports_markers(&self) -> bool;

    /// Request keyboard focus.
    fn request_focus(&self);

    /// Returns true if the navigatable is visible.
    fn is_visible(&self) -> bool;

    /// Set the selection.
    fn set_selection(&self, selection: &ProgramSelection);

    /// Set the highlight.
    fn set_highlight(&self, highlight: &ProgramSelection);

    /// Get the current selection.
    fn get_selection(&self) -> ProgramSelection;

    /// Get the current highlight.
    fn get_highlight(&self) -> ProgramSelection;

    /// Get the current text selection.
    fn get_text_selection(&self) -> Option<String>;

    /// Returns true if this navigatable supports highlighting.
    fn supports_highlight(&self) -> bool;

    /// Returns true if this navigatable is no longer valid.
    fn is_disposed(&self) -> bool;
}

// ---------------------------------------------------------------------------
// NavigatableRemovalListener
// ---------------------------------------------------------------------------

/// Trait for listeners that are notified when a navigatable is closed/removed.
pub trait NavigatableRemovalListener: Send + Sync {
    fn navigatable_removed(&self, navigatable_id: u64);
}

// ---------------------------------------------------------------------------
// NavigatableRegistry
// ---------------------------------------------------------------------------

/// Global registry of all active navigatables.
///
/// Plugins register their navigatables so that other components can
/// enumerate available navigation targets.
#[derive(Debug, Default)]
pub struct NavigatableRegistry {
    navigatables: Vec<RegisteredNavigatable>,
}

#[derive(Debug)]
struct RegisteredNavigatable {
    id: u64,
    name: String,
}

impl NavigatableRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a navigatable with a human-readable name.
    pub fn register(&mut self, id: u64, name: impl Into<String>) {
        self.navigatables.push(RegisteredNavigatable {
            id,
            name: name.into(),
        });
    }

    /// Unregister a navigatable by ID.
    pub fn unregister(&mut self, id: u64) {
        self.navigatables.retain(|n| n.id != id);
    }

    /// Get the number of registered navigatables.
    pub fn count(&self) -> usize {
        self.navigatables.len()
    }

    /// List all registered navigatable names.
    pub fn list_names(&self) -> Vec<&str> {
        self.navigatables.iter().map(|n| n.name.as_str()).collect()
    }
}

// ---------------------------------------------------------------------------
// NavigationUtils
// ---------------------------------------------------------------------------

/// Utility functions for navigation.
pub struct NavigationUtils;

impl NavigationUtils {
    /// Default navigatable instance ID.
    pub const DEFAULT_NAVIGATABLE_ID: u64 = u64::MAX;

    /// Check if an address is within a set of ranges.
    pub fn is_in_ranges(addr: Address, ranges: &[(Address, Address)]) -> bool {
        ranges
            .iter()
            .any(|(start, end)| addr.0 >= start.0 && addr.0 <= end.0)
    }
}

// ---------------------------------------------------------------------------
// NextRangeAction / PreviousRangeAction
// ---------------------------------------------------------------------------

/// Action to navigate to the next range in a selection.
#[derive(Debug, Clone)]
pub struct NextRangeAction {
    name: String,
    owner: String,
}

impl NextRangeAction {
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Compute the next range address given current address and ranges.
    pub fn next_range(&self, current: Address, ranges: &[(Address, Address)]) -> Option<Address> {
        ranges
            .iter()
            .find(|(start, _)| start.0 > current.0)
            .map(|(start, _)| *start)
    }
}

/// Action to navigate to the previous range in a selection.
#[derive(Debug, Clone)]
pub struct PreviousRangeAction {
    name: String,
    owner: String,
}

impl PreviousRangeAction {
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Compute the previous range address given current address and ranges.
    pub fn previous_range(
        &self,
        current: Address,
        ranges: &[(Address, Address)],
    ) -> Option<Address> {
        ranges
            .iter()
            .rev()
            .find(|(_, end)| end.0 < current.0)
            .map(|(start, _)| *start)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_location_memento() {
        let memento = LocationMemento::new(
            "test.exe",
            ProgramLocation {
                address: Address(0x1000),
            },
            ProgramSelection::default(),
            ProgramSelection::default(),
        );
        assert_eq!(memento.program_name(), "test.exe");
        assert_eq!(memento.location().address, Address(0x1000));
    }

    #[test]
    fn test_navigatable_registry() {
        let mut registry = NavigatableRegistry::new();
        registry.register(1, "CodeBrowser");
        registry.register(2, "Listing");
        assert_eq!(registry.count(), 2);
        assert_eq!(registry.list_names(), vec!["CodeBrowser", "Listing"]);
        registry.unregister(1);
        assert_eq!(registry.count(), 1);
    }

    #[test]
    fn test_navigation_utils_is_in_ranges() {
        let ranges = vec![(Address(0x1000), Address(0x2000))];
        assert!(NavigationUtils::is_in_ranges(Address(0x1500), &ranges));
        assert!(!NavigationUtils::is_in_ranges(Address(0x3000), &ranges));
    }

    #[test]
    fn test_next_range_action() {
        let action = NextRangeAction::new("Next", "Test");
        let ranges = vec![
            (Address(0x1000), Address(0x2000)),
            (Address(0x5000), Address(0x6000)),
        ];
        assert_eq!(
            action.next_range(Address(0x1500), &ranges),
            Some(Address(0x5000))
        );
        assert_eq!(action.next_range(Address(0x6000), &ranges), None);
    }

    #[test]
    fn test_previous_range_action() {
        let action = PreviousRangeAction::new("Prev", "Test");
        let ranges = vec![
            (Address(0x1000), Address(0x2000)),
            (Address(0x5000), Address(0x6000)),
        ];
        assert_eq!(
            action.previous_range(Address(0x5500), &ranges),
            Some(Address(0x1000))
        );
        assert_eq!(
            action.previous_range(Address(0x1500), &ranges),
            None
        );
    }

    #[test]
    fn test_default_navigatable_id() {
        assert_eq!(NavigationUtils::DEFAULT_NAVIGATABLE_ID, u64::MAX);
    }
}
