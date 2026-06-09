//! Navigation History Service -- trait interface.
//!
//! Ported from `ghidra.app.services.NavigationHistoryService`.
//!
//! This service maintains a stack of locations that the user has visited
//! via a navigation plugin. It provides methods for querying and
//! manipulating this list.
//!
//! # Java Original
//!
//! The Java interface defines the contract that [`NavigationHistoryPlugin`]
//! implements. Consumers obtain the service via the tool's service
//! registry and call methods like [`next`](NavigationHistoryService::next),
//! [`previous`](NavigationHistoryService::previous),
//! [`add_new_location`](NavigationHistoryService::add_new_location), etc.

use crate::gotoquery::{LocationMemento, Navigatable};

/// Service interface for navigation history management.
///
/// Ported from `ghidra.app.services.NavigationHistoryService`.
///
/// The navigation history service maintains a per-navigatable stack of
/// [`LocationMemento`] entries. Other plugins use this service to
/// support back/forward/next-function/previous-function navigation.
pub trait NavigationHistoryService: Send + Sync {
    /// Navigate forward one step in the history.
    ///
    /// If there is no "next" location, the history list remains unchanged.
    fn next(&mut self, navigatable_id: u64);

    /// Navigate backward one step in the history.
    ///
    /// If there is no "previous" location, the history list remains unchanged.
    fn previous(&mut self, navigatable_id: u64);

    /// Navigate forward to a specific location in the "next" list.
    ///
    /// If the location is not in the next list, nothing happens.
    fn next_to(&mut self, navigatable_id: u64, location: &LocationMemento);

    /// Navigate backward to a specific location in the "previous" list.
    ///
    /// If the location is not in the previous list, nothing happens.
    fn previous_to(&mut self, navigatable_id: u64, location: &LocationMemento);

    /// Navigate to the next location that is in a different function.
    ///
    /// If we are not inside any function, behaves like [`next`](Self::next).
    fn next_function(&mut self, navigatable_id: u64);

    /// Navigate to the previous location that is in a different function.
    ///
    /// If we are not inside any function, behaves like [`previous`](Self::previous).
    fn previous_function(&mut self, navigatable_id: u64);

    /// Get the list of "previous" locations for display (most recent first).
    fn get_previous_locations(&self, navigatable_id: u64) -> Vec<LocationMemento>;

    /// Get the list of "next" locations for display.
    fn get_next_locations(&self, navigatable_id: u64) -> Vec<LocationMemento>;

    /// Whether there is a valid "next" location in the history.
    fn has_next(&self, navigatable_id: u64) -> bool;

    /// Whether there is a valid "previous" location in the history.
    fn has_previous(&self, navigatable_id: u64) -> bool;

    /// Whether there is a valid "next function" location in the history.
    fn has_next_function(&self, navigatable_id: u64) -> bool;

    /// Whether there is a valid "previous function" location in the history.
    fn has_previous_function(&self, navigatable_id: u64) -> bool;

    /// Record the current location of a navigatable in the history.
    ///
    /// Clears any forward history beyond the current position.
    fn add_new_location(&mut self, navigatable_id: u64, memento: LocationMemento);

    /// Clear all history entries for the given navigatable.
    fn clear(&mut self, navigatable_id: u64);

    /// Clear all entries that reference a given program from all histories.
    fn clear_program(&mut self, program_name: &str);

    /// Called when a navigatable is disposed; remove its history.
    fn navigatable_removed(&mut self, navigatable_id: u64);
}
