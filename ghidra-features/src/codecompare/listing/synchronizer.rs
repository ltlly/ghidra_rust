//! Listing display synchronization for code comparison.
//!
//! Ported from Ghidra's `ListingDisplaySynchronizer` Java class in
//! `ghidra.features.base.codecompare.listing`.
//!
//! This module keeps two listing displays synchronized, both in terms of
//! scroll position (view) and cursor location. When the user scrolls or
//! moves the cursor on one side, the other side is updated to show the
//! correlated position.
//!
//! # Key types
//!
//! - [`ScrollPosition`] -- a scroll position in a listing panel
//! - [`ViewCoordinator`] -- coordinates the scroll positions of two listing displays
//! - [`ListingSynchronizer`] -- the main synchronization engine

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use super::ListingSide;
use super::LinearAddressCorrelation;
use crate::codecompare::panel::AddressSet;

/// A scroll position in a listing panel.
///
/// Represents the viewer position (top visible line index and offsets)
/// that can be saved and restored for synchronization purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrollPosition {
    /// The index of the top visible line.
    pub top_index: u64,
    /// The horizontal offset.
    pub x_offset: i32,
    /// The vertical offset within the top line.
    pub y_offset: i32,
}

impl ScrollPosition {
    /// Create a new scroll position.
    pub fn new(top_index: u64, x_offset: i32, y_offset: i32) -> Self {
        Self {
            top_index,
            x_offset,
            y_offset,
        }
    }

    /// Create a zero scroll position.
    pub fn zero() -> Self {
        Self {
            top_index: 0,
            x_offset: 0,
            y_offset: 0,
        }
    }
}

/// A locked line pair for synchronized scrolling.
///
/// When two listing displays are synchronized, specific line indices
/// on each side are "locked" together so that scrolling one side
/// adjusts the other to keep the locked lines aligned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockedLinePair {
    /// The line index on the left side.
    pub left_index: u64,
    /// The line index on the right side.
    pub right_index: u64,
}

impl LockedLinePair {
    /// Create a new locked line pair.
    pub fn new(left_index: u64, right_index: u64) -> Self {
        Self {
            left_index,
            right_index,
        }
    }
}

/// Coordinates the scroll positions of two listing displays.
///
/// This is the Rust equivalent of the view coordination logic in
/// Ghidra's `ListingDisplaySynchronizer` Java class. It tracks
/// the locked line pair and computes the scroll offset needed to
/// keep the two displays aligned.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::listing::synchronizer::*;
///
/// let mut coordinator = ViewCoordinator::new();
/// coordinator.lock_lines(10, 20);
///
/// let pos = ScrollPosition::new(5, 0, 0);
/// let other_pos = coordinator.compute_other_position(pos, 100);
/// // The other side should scroll to keep line 20 aligned with line 10
/// ```
pub struct ViewCoordinator {
    /// The currently locked line pair.
    locked_pair: Option<LockedLinePair>,
    /// The scroll position of the left side.
    left_position: ScrollPosition,
    /// The scroll position of the right side.
    right_position: ScrollPosition,
}

impl ViewCoordinator {
    /// Create a new view coordinator.
    pub fn new() -> Self {
        Self {
            locked_pair: None,
            left_position: ScrollPosition::zero(),
            right_position: ScrollPosition::zero(),
        }
    }

    /// Lock specific line indices on each side together.
    ///
    /// When locked, scrolling one side will adjust the other to keep
    /// these lines at the same vertical position.
    pub fn lock_lines(&mut self, left_index: u64, right_index: u64) {
        self.locked_pair = Some(LockedLinePair::new(left_index, right_index));
    }

    /// Unlock the line pair (disable synchronized scrolling).
    pub fn unlock_lines(&mut self) {
        self.locked_pair = None;
    }

    /// Check if lines are currently locked.
    pub fn is_locked(&self) -> bool {
        self.locked_pair.is_some()
    }

    /// Get the currently locked line pair.
    pub fn locked_pair(&self) -> Option<&LockedLinePair> {
        self.locked_pair.as_ref()
    }

    /// Update the scroll position for one side and compute the position
    /// for the other side.
    ///
    /// Returns the scroll position the other side should adopt, or None
    /// if lines are not locked.
    pub fn update_position(
        &mut self,
        side: ListingSide,
        position: ScrollPosition,
    ) -> Option<ScrollPosition> {
        match side {
            ListingSide::Left => {
                self.left_position = position;
            }
            ListingSide::Right => {
                self.right_position = position;
            }
        }

        let pair = self.locked_pair?;
        let (src_pos, src_locked, dst_locked) = match side {
            ListingSide::Left => (position, pair.left_index, pair.right_index),
            ListingSide::Right => (position, pair.right_index, pair.left_index),
        };

        // Compute the offset: the source's top_index relative to the locked line
        let offset = src_pos.top_index as i64 - src_locked as i64;
        let dst_top_index = (dst_locked as i64 + offset).max(0) as u64;

        let other_pos = ScrollPosition::new(dst_top_index, src_pos.x_offset, src_pos.y_offset);

        match side {
            ListingSide::Left => self.right_position = other_pos,
            ListingSide::Right => self.left_position = other_pos,
        }

        Some(other_pos)
    }

    /// Get the current scroll position for the given side.
    pub fn get_position(&self, side: ListingSide) -> &ScrollPosition {
        match side {
            ListingSide::Left => &self.left_position,
            ListingSide::Right => &self.right_position,
        }
    }

    /// Compute the other side's position without updating state.
    ///
    /// This is useful for previewing where the other side would scroll to.
    pub fn compute_other_position(
        &self,
        source_position: ScrollPosition,
        source_locked_line: u64,
    ) -> ScrollPosition {
        let pair = match self.locked_pair {
            Some(p) => p,
            None => return source_position,
        };

        let offset = source_position.top_index as i64 - source_locked_line as i64;
        let dst_top_index = (pair.right_index as i64 + offset).max(0) as u64;

        ScrollPosition::new(
            dst_top_index,
            source_position.x_offset,
            source_position.y_offset,
        )
    }

    /// Reset the coordinator state.
    pub fn reset(&mut self) {
        self.locked_pair = None;
        self.left_position = ScrollPosition::zero();
        self.right_position = ScrollPosition::zero();
    }
}

impl Default for ViewCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

/// Events emitted by the listing synchronizer.
#[derive(Debug, Clone)]
pub enum SynchronizerEvent {
    /// The cursor was synchronized to the other side.
    CursorSynced {
        source_side: ListingSide,
        source_address: u64,
        target_address: Option<u64>,
    },
    /// The scroll position was synchronized.
    ScrollSynced {
        source_side: ListingSide,
        target_position: ScrollPosition,
    },
    /// The synchronization was enabled or disabled.
    SyncStateChanged { enabled: bool },
}

/// Trait for receiving synchronizer events.
pub trait SynchronizerListener: Send + Sync {
    /// Called when an event occurs.
    fn on_event(&self, event: &SynchronizerEvent);
}

/// The main listing synchronizer engine.
///
/// Manages the synchronization between two listing displays, keeping
/// both the cursor location and scroll position in sync. Uses an
/// address correlation to map positions between the two sides.
///
/// Ported from Ghidra's `ListingDisplaySynchronizer` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::listing::synchronizer::*;
/// use ghidra_features::codecompare::listing::{LinearAddressCorrelation, ListingSide};
/// use ghidra_features::codecompare::panel::AddressSet;
///
/// let left_addrs = AddressSet::single(0x1000, 0x100f);
/// let right_addrs = AddressSet::single(0x2000, 0x200f);
/// let correlation = LinearAddressCorrelation::new(left_addrs, right_addrs);
///
/// let mut sync = ListingSynchronizer::new(correlation);
/// sync.set_enabled(true);
///
/// // Sync cursor from left side
/// let target = sync.sync_cursor(ListingSide::Left, 0x1005);
/// assert_eq!(target, Some(0x2005));
/// ```
pub struct ListingSynchronizer {
    /// The address correlation between the two sides.
    correlation: LinearAddressCorrelation,
    /// The view coordinator for scroll synchronization.
    coordinator: ViewCoordinator,
    /// Whether synchronization is enabled.
    enabled: bool,
    /// The current cursor address on each side.
    cursor_addresses: (Option<u64>, Option<u64>),
    /// Listeners for synchronizer events.
    listeners: Vec<Arc<dyn SynchronizerListener>>,
}

impl ListingSynchronizer {
    /// Create a new listing synchronizer.
    pub fn new(correlation: LinearAddressCorrelation) -> Self {
        Self {
            correlation,
            coordinator: ViewCoordinator::new(),
            enabled: false,
            cursor_addresses: (None, None),
            listeners: Vec::new(),
        }
    }

    /// Add a listener for synchronizer events.
    pub fn add_listener(&mut self, listener: Arc<dyn SynchronizerListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Fire an event to all listeners.
    fn fire_event(&self, event: SynchronizerEvent) {
        for listener in &self.listeners {
            listener.on_event(&event);
        }
    }

    /// Enable or disable synchronization.
    pub fn set_enabled(&mut self, enabled: bool) {
        if self.enabled == enabled {
            return;
        }
        self.enabled = enabled;
        if !enabled {
            self.coordinator.unlock_lines();
        }
        self.fire_event(SynchronizerEvent::SyncStateChanged { enabled });
    }

    /// Check if synchronization is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the address correlation.
    pub fn correlation(&self) -> &LinearAddressCorrelation {
        &self.correlation
    }

    /// Get the view coordinator.
    pub fn coordinator(&self) -> &ViewCoordinator {
        &self.coordinator
    }

    /// Get a mutable reference to the view coordinator.
    pub fn coordinator_mut(&mut self) -> &mut ViewCoordinator {
        &mut self.coordinator
    }

    /// Synchronize the cursor from one side to the other.
    ///
    /// Given a cursor address on the source side, computes the correlated
    /// address on the target side and returns it. Also updates the locked
    /// line pair for scroll synchronization.
    ///
    /// Returns the correlated address on the other side, or None if no
    /// correlation exists.
    pub fn sync_cursor(
        &mut self,
        source_side: ListingSide,
        source_address: u64,
    ) -> Option<u64> {
        if !self.enabled {
            return None;
        }

        // Update the cursor address for the source side
        match source_side {
            ListingSide::Left => self.cursor_addresses.0 = Some(source_address),
            ListingSide::Right => self.cursor_addresses.1 = Some(source_address),
        }

        // Get the correlated address on the other side
        let target_address = self
            .correlation
            .get_correlated_address(source_side, source_address);

        // Update the cursor address for the target side
        match source_side {
            ListingSide::Left => self.cursor_addresses.1 = target_address,
            ListingSide::Right => self.cursor_addresses.0 = target_address,
        }

        // Update the locked line pair based on the cursor addresses
        if let (Some(left_addr), Some(right_addr)) = self.cursor_addresses {
            // Use the address as a proxy for line index
            self.coordinator.lock_lines(left_addr, right_addr);
        }

        self.fire_event(SynchronizerEvent::CursorSynced {
            source_side,
            source_address,
            target_address,
        });

        target_address
    }

    /// Synchronize the scroll position from one side to the other.
    ///
    /// Given a scroll position on the source side, computes the position
    /// the other side should adopt.
    ///
    /// Returns the target scroll position, or None if synchronization
    /// is not enabled or lines are not locked.
    pub fn sync_scroll(
        &mut self,
        source_side: ListingSide,
        source_position: ScrollPosition,
    ) -> Option<ScrollPosition> {
        if !self.enabled {
            return None;
        }

        let target_position = self.coordinator.update_position(source_side, source_position)?;

        self.fire_event(SynchronizerEvent::ScrollSynced {
            source_side,
            target_position,
        });

        Some(target_position)
    }

    /// Get the current cursor address for the given side.
    pub fn cursor_address(&self, side: ListingSide) -> Option<u64> {
        match side {
            ListingSide::Left => self.cursor_addresses.0,
            ListingSide::Right => self.cursor_addresses.1,
        }
    }

    /// Reset the synchronizer state.
    pub fn reset(&mut self) {
        self.coordinator.reset();
        self.cursor_addresses = (None, None);
    }

    /// Dispose of the synchronizer.
    pub fn dispose(&mut self) {
        self.enabled = false;
        self.coordinator.reset();
        self.cursor_addresses = (None, None);
        self.listeners.clear();
    }
}

/// A simple listener that tracks synchronizer events.
#[derive(Debug, Default)]
pub struct TrackingSynchronizerListener {
    /// Recorded events.
    pub events: Mutex<Vec<SynchronizerEvent>>,
}

impl TrackingSynchronizerListener {
    /// Create a new tracking listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of events received.
    pub fn event_count(&self) -> usize {
        self.events.lock().unwrap().len()
    }
}

impl SynchronizerListener for TrackingSynchronizerListener {
    fn on_event(&self, event: &SynchronizerEvent) {
        self.events.lock().unwrap().push(event.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_correlation() -> LinearAddressCorrelation {
        let left = AddressSet::single(0x1000, 0x100f);
        let right = AddressSet::single(0x2000, 0x200f);
        LinearAddressCorrelation::new(left, right)
    }

    // --- ScrollPosition tests ---

    #[test]
    fn test_scroll_position() {
        let pos = ScrollPosition::new(10, 5, 3);
        assert_eq!(pos.top_index, 10);
        assert_eq!(pos.x_offset, 5);
        assert_eq!(pos.y_offset, 3);
    }

    #[test]
    fn test_scroll_position_zero() {
        let pos = ScrollPosition::zero();
        assert_eq!(pos.top_index, 0);
        assert_eq!(pos.x_offset, 0);
        assert_eq!(pos.y_offset, 0);
    }

    // --- ViewCoordinator tests ---

    #[test]
    fn test_view_coordinator_new() {
        let coordinator = ViewCoordinator::new();
        assert!(!coordinator.is_locked());
        assert!(coordinator.locked_pair().is_none());
    }

    #[test]
    fn test_view_coordinator_lock() {
        let mut coordinator = ViewCoordinator::new();
        coordinator.lock_lines(10, 20);
        assert!(coordinator.is_locked());
        let pair = coordinator.locked_pair().unwrap();
        assert_eq!(pair.left_index, 10);
        assert_eq!(pair.right_index, 20);
    }

    #[test]
    fn test_view_coordinator_unlock() {
        let mut coordinator = ViewCoordinator::new();
        coordinator.lock_lines(10, 20);
        coordinator.unlock_lines();
        assert!(!coordinator.is_locked());
    }

    #[test]
    fn test_view_coordinator_update_position() {
        let mut coordinator = ViewCoordinator::new();
        coordinator.lock_lines(10, 20);

        // Left side scrolls to index 15 (5 lines above locked line 10)
        let pos = ScrollPosition::new(15, 0, 0);
        let other_pos = coordinator.update_position(ListingSide::Left, pos);

        assert!(other_pos.is_some());
        let other = other_pos.unwrap();
        // Right side should be at 20 + 5 = 25
        assert_eq!(other.top_index, 25);
    }

    #[test]
    fn test_view_coordinator_update_position_no_lock() {
        let mut coordinator = ViewCoordinator::new();
        let pos = ScrollPosition::new(15, 0, 0);
        let other_pos = coordinator.update_position(ListingSide::Left, pos);
        assert!(other_pos.is_none());
    }

    #[test]
    fn test_view_coordinator_get_position() {
        let mut coordinator = ViewCoordinator::new();
        let pos = ScrollPosition::new(10, 5, 3);
        coordinator.update_position(ListingSide::Left, pos);

        let left_pos = coordinator.get_position(ListingSide::Left);
        assert_eq!(left_pos.top_index, 10);
    }

    #[test]
    fn test_view_coordinator_reset() {
        let mut coordinator = ViewCoordinator::new();
        coordinator.lock_lines(10, 20);
        coordinator.reset();
        assert!(!coordinator.is_locked());
    }

    // --- ListingSynchronizer tests ---

    #[test]
    fn test_synchronizer_new() {
        let corr = make_correlation();
        let sync = ListingSynchronizer::new(corr);
        assert!(!sync.is_enabled());
        assert_eq!(sync.cursor_address(ListingSide::Left), None);
    }

    #[test]
    fn test_synchronizer_enable() {
        let corr = make_correlation();
        let mut sync = ListingSynchronizer::new(corr);
        sync.set_enabled(true);
        assert!(sync.is_enabled());
    }

    #[test]
    fn test_synchronizer_disable() {
        let corr = make_correlation();
        let mut sync = ListingSynchronizer::new(corr);
        sync.set_enabled(true);
        sync.set_enabled(false);
        assert!(!sync.is_enabled());
    }

    #[test]
    fn test_synchronizer_sync_cursor() {
        let corr = make_correlation();
        let mut sync = ListingSynchronizer::new(corr);
        sync.set_enabled(true);

        let target = sync.sync_cursor(ListingSide::Left, 0x1005);
        assert_eq!(target, Some(0x2005));
        assert_eq!(sync.cursor_address(ListingSide::Left), Some(0x1005));
        assert_eq!(sync.cursor_address(ListingSide::Right), Some(0x2005));
    }

    #[test]
    fn test_synchronizer_sync_cursor_reverse() {
        let corr = make_correlation();
        let mut sync = ListingSynchronizer::new(corr);
        sync.set_enabled(true);

        let target = sync.sync_cursor(ListingSide::Right, 0x2003);
        assert_eq!(target, Some(0x1003));
    }

    #[test]
    fn test_synchronizer_sync_cursor_out_of_range() {
        let corr = make_correlation();
        let mut sync = ListingSynchronizer::new(corr);
        sync.set_enabled(true);

        let target = sync.sync_cursor(ListingSide::Left, 0x5000);
        assert_eq!(target, None);
    }

    #[test]
    fn test_synchronizer_sync_cursor_disabled() {
        let corr = make_correlation();
        let mut sync = ListingSynchronizer::new(corr);

        let target = sync.sync_cursor(ListingSide::Left, 0x1005);
        assert_eq!(target, None);
    }

    #[test]
    fn test_synchronizer_sync_scroll() {
        let corr = make_correlation();
        let mut sync = ListingSynchronizer::new(corr);
        sync.set_enabled(true);

        // First sync cursor to establish locked lines
        sync.sync_cursor(ListingSide::Left, 0x1005);

        // Now sync scroll
        let pos = ScrollPosition::new(10, 0, 0);
        let target_pos = sync.sync_scroll(ListingSide::Left, pos);
        assert!(target_pos.is_some());
    }

    #[test]
    fn test_synchronizer_sync_scroll_disabled() {
        let corr = make_correlation();
        let mut sync = ListingSynchronizer::new(corr);

        let pos = ScrollPosition::new(10, 0, 0);
        let target_pos = sync.sync_scroll(ListingSide::Left, pos);
        assert!(target_pos.is_none());
    }

    #[test]
    fn test_synchronizer_listener() {
        let corr = make_correlation();
        let mut sync = ListingSynchronizer::new(corr);
        let listener = Arc::new(TrackingSynchronizerListener::new());
        sync.add_listener(listener.clone());

        sync.set_enabled(true);
        assert_eq!(listener.event_count(), 1);

        sync.sync_cursor(ListingSide::Left, 0x1005);
        assert_eq!(listener.event_count(), 2);
    }

    #[test]
    fn test_synchronizer_reset() {
        let corr = make_correlation();
        let mut sync = ListingSynchronizer::new(corr);
        sync.set_enabled(true);
        sync.sync_cursor(ListingSide::Left, 0x1005);

        sync.reset();
        assert_eq!(sync.cursor_address(ListingSide::Left), None);
        assert_eq!(sync.cursor_address(ListingSide::Right), None);
    }

    #[test]
    fn test_synchronizer_dispose() {
        let corr = make_correlation();
        let mut sync = ListingSynchronizer::new(corr);
        let listener = Arc::new(TrackingSynchronizerListener::new());
        sync.add_listener(listener.clone());
        sync.set_enabled(true);

        sync.dispose();
        assert!(!sync.is_enabled());
        assert_eq!(sync.cursor_address(ListingSide::Left), None);
    }

    #[test]
    fn test_tracking_listener() {
        let listener = TrackingSynchronizerListener::new();
        assert_eq!(listener.event_count(), 0);
    }
}
