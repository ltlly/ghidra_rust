//! Selection Service -- the service interface for program selection.
//!
//! Ported from Ghidra's `ghidra.app.services.SelectionService` Java interface
//! and the associated `ProgramSelection` type from `ghidra.framework.model`.
//!
//! The [`SelectionService`] trait defines the contract that a selection plugin
//! exposes to other plugins. Any plugin that needs to query or modify the
//! current program selection can request a reference to this service from
//! the tool's service registry.
//!
//! # Key Types
//!
//! - [`ProgramSelection`] -- A set of address ranges representing the user's
//!   current selection in a program.
//! - [`SelectionService`] -- The service trait for querying and modifying the
//!   current selection.
//! - [`SelectionServiceListener`] -- Callback trait for selection change
//!   notifications.

use std::collections::BTreeSet;
use std::fmt;

// ---------------------------------------------------------------------------
// ProgramSelection
// ---------------------------------------------------------------------------

/// A set of contiguous address ranges representing a program selection.
///
/// Ported from `ghidra.framework.model.ProgramSelection`.
///
/// Internally stores sorted, non-overlapping `(start, end)` range pairs
/// where both `start` and `end` are inclusive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProgramSelection {
    /// Sorted, non-overlapping inclusive ranges: `(start, end)`.
    ranges: Vec<(u64, u64)>,
}

impl ProgramSelection {
    /// Create an empty selection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a selection from a single range.
    pub fn from_range(start: u64, end: u64) -> Self {
        let mut sel = Self::new();
        sel.add_range(start, end);
        sel
    }

    /// Create a selection from a set of individual addresses.
    pub fn from_addresses(addresses: &BTreeSet<u64>) -> Self {
        let mut sel = Self::new();
        for &addr in addresses {
            sel.add_address(addr);
        }
        sel
    }

    /// Create a selection from raw range pairs (not necessarily sorted/merged).
    pub fn from_raw_ranges(ranges: &[(u64, u64)]) -> Self {
        let mut sel = Self::new();
        for &(start, end) in ranges {
            sel.add_range(start, end);
        }
        sel
    }

    // -- Queries -------------------------------------------------------------

    /// Whether the selection is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The number of individual addresses in the selection.
    pub fn num_addresses(&self) -> u64 {
        self.ranges.iter().map(|(s, e)| e - s + 1).sum()
    }

    /// The number of contiguous ranges.
    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }

    /// Whether the selection contains the given address.
    pub fn contains(&self, address: u64) -> bool {
        self.ranges
            .binary_search_by(|(start, end)| {
                if address < *start {
                    std::cmp::Ordering::Greater
                } else if address > *end {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    /// Get the minimum selected address, if any.
    pub fn min_address(&self) -> Option<u64> {
        self.ranges.first().map(|(s, _)| *s)
    }

    /// Get the maximum selected address, if any.
    pub fn max_address(&self) -> Option<u64> {
        self.ranges.last().map(|(_, e)| *e)
    }

    /// Get the ranges as a slice.
    pub fn ranges(&self) -> &[(u64, u64)] {
        &self.ranges
    }

    /// Iterate over all individual addresses.
    pub fn addresses(&self) -> impl Iterator<Item = u64> + '_ {
        self.ranges.iter().flat_map(|(s, e)| *s..=*e)
    }

    /// Collect all addresses into a `BTreeSet`.
    pub fn to_address_set(&self) -> BTreeSet<u64> {
        self.addresses().collect()
    }

    // -- Mutations ------------------------------------------------------------

    /// Add a single address to the selection, merging with adjacent ranges.
    pub fn add_address(&mut self, address: u64) {
        self.add_range(address, address);
    }

    /// Add a contiguous range to the selection, merging overlapping ranges.
    pub fn add_range(&mut self, start: u64, end: u64) {
        if start > end {
            return;
        }
        self.ranges.push((start, end));
        self.normalize();
    }

    /// Remove a single address from the selection.
    pub fn remove_address(&mut self, address: u64) {
        self.remove_range(address, address);
    }

    /// Remove a contiguous range from the selection.
    pub fn remove_range(&mut self, start: u64, end: u64) {
        if start > end {
            return;
        }
        let mut new_ranges = Vec::new();
        for &(rs, re) in &self.ranges {
            if re < start || rs > end {
                // No overlap -- keep as-is.
                new_ranges.push((rs, re));
            } else {
                // Overlap exists -- keep the non-overlapping portions.
                if rs < start {
                    new_ranges.push((rs, start - 1));
                }
                if re > end {
                    new_ranges.push((end + 1, re));
                }
            }
        }
        self.ranges = new_ranges;
    }

    /// Clear the selection.
    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    /// Invert the selection within the given bounds.
    pub fn invert(&mut self, min: u64, max: u64) {
        let mut new_ranges = Vec::new();
        let mut cursor = min;
        for &(rs, re) in &self.ranges {
            if rs > cursor {
                new_ranges.push((cursor, rs - 1));
            }
            cursor = re + 1;
        }
        if cursor <= max {
            new_ranges.push((cursor, max));
        }
        self.ranges = new_ranges;
    }

    /// Set the selection to the union of `self` and `other` in-place.
    pub fn union_with(&mut self, other: &ProgramSelection) {
        for &(s, e) in &other.ranges {
            self.add_range(s, e);
        }
    }

    /// Set the selection to the intersection of `self` and `other` in-place.
    pub fn intersect_with(&mut self, other: &ProgramSelection) {
        let mut result = Vec::new();
        let mut i = 0;
        let mut j = 0;
        while i < self.ranges.len() && j < other.ranges.len() {
            let (as_, ae) = self.ranges[i];
            let (bs, be) = other.ranges[j];
            let lo = as_.max(bs);
            let hi = ae.min(be);
            if lo <= hi {
                result.push((lo, hi));
            }
            if ae < be {
                i += 1;
            } else {
                j += 1;
            }
        }
        self.ranges = result;
    }

    /// Set the selection to `self` minus `other` in-place.
    pub fn subtract_with(&mut self, other: &ProgramSelection) {
        for &(s, e) in &other.ranges {
            self.remove_range(s, e);
        }
    }

    // -- Internal ------------------------------------------------------------

    /// Normalize ranges: sort and merge overlapping/adjacent ranges.
    fn normalize(&mut self) {
        if self.ranges.len() <= 1 {
            return;
        }
        self.ranges.sort_by_key(|&(s, _)| s);
        let mut merged = Vec::with_capacity(self.ranges.len());
        let (mut cur_start, mut cur_end) = self.ranges[0];
        for &(s, e) in &self.ranges[1..] {
            if s <= cur_end + 1 {
                cur_end = cur_end.max(e);
            } else {
                merged.push((cur_start, cur_end));
                cur_start = s;
                cur_end = e;
            }
        }
        merged.push((cur_start, cur_end));
        self.ranges = merged;
    }
}

impl fmt::Display for ProgramSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ProgramSelection(ranges={}, addresses={})",
            self.num_ranges(),
            self.num_addresses()
        )
    }
}

// ---------------------------------------------------------------------------
// SelectionService
// ---------------------------------------------------------------------------

/// The service interface for program selection.
///
/// Ported from `ghidra.app.services.SelectionService`.
///
/// Plugins that control the code browser or need to operate on the user's
/// current selection obtain this service from the tool. The service provides
/// both read access (query the current selection) and write access
/// (modify or clear the selection).
pub trait SelectionService: fmt::Debug + Send + Sync {
    /// Get the current program selection.
    fn get_selection(&self) -> ProgramSelection;

    /// Set the current program selection.
    ///
    /// Implementations should notify all registered
    /// [`SelectionServiceListener`]s after applying the change.
    fn set_selection(&self, selection: ProgramSelection);

    /// Clear the current program selection.
    fn clear_selection(&self);

    /// Whether there is a non-empty selection.
    fn has_selection(&self) -> bool;

    /// Add a listener that will be called when the selection changes.
    fn add_selection_listener(&self, listener: Arc<dyn SelectionServiceListener>);

    /// Remove a previously registered listener.
    fn remove_selection_listener(&self, listener: &Arc<dyn SelectionServiceListener>);

    /// Get the number of currently registered listeners.
    fn listener_count(&self) -> usize;
}

use std::sync::Arc;

// ---------------------------------------------------------------------------
// SelectionServiceListener
// ---------------------------------------------------------------------------

/// Listener for program selection change events.
///
/// Ported from `ghidra.app.services.SelectionServiceListener`.
///
/// Implementations are called by the [`SelectionService`] whenever the
/// user or a plugin modifies the program selection.
pub trait SelectionServiceListener: fmt::Debug + Send + Sync {
    /// Called when the program selection has changed.
    ///
    /// The `selection` parameter contains the new selection.
    fn selection_changed(&self, selection: &ProgramSelection);
}

// ---------------------------------------------------------------------------
// DefaultSelectionService
// ---------------------------------------------------------------------------

/// A default, in-process implementation of [`SelectionService`].
///
/// This is suitable for single-threaded tool setups or testing.
#[derive(Debug)]
pub struct DefaultSelectionService {
    inner: std::sync::RwLock<DefaultSelectionServiceInner>,
}

#[derive(Debug)]
struct DefaultSelectionServiceInner {
    selection: ProgramSelection,
    listeners: Vec<Arc<dyn SelectionServiceListener>>,
}

impl DefaultSelectionService {
    /// Create a new default selection service.
    pub fn new() -> Self {
        Self {
            inner: std::sync::RwLock::new(DefaultSelectionServiceInner {
                selection: ProgramSelection::default(),
                listeners: Vec::new(),
            }),
        }
    }

    /// Notify all listeners of a selection change.
    fn notify_listeners(&self, selection: &ProgramSelection) {
        let inner = self.inner.read().unwrap();
        for listener in &inner.listeners {
            listener.selection_changed(selection);
        }
    }
}

impl Default for DefaultSelectionService {
    fn default() -> Self {
        Self::new()
    }
}

impl SelectionService for DefaultSelectionService {
    fn get_selection(&self) -> ProgramSelection {
        let inner = self.inner.read().unwrap();
        inner.selection.clone()
    }

    fn set_selection(&self, selection: ProgramSelection) {
        {
            let mut inner = self.inner.write().unwrap();
            inner.selection = selection.clone();
        }
        self.notify_listeners(&selection);
    }

    fn clear_selection(&self) {
        self.set_selection(ProgramSelection::default());
    }

    fn has_selection(&self) -> bool {
        let inner = self.inner.read().unwrap();
        !inner.selection.is_empty()
    }

    fn add_selection_listener(&self, listener: Arc<dyn SelectionServiceListener>) {
        let mut inner = self.inner.write().unwrap();
        inner.listeners.push(listener);
    }

    fn remove_selection_listener(&self, listener: &Arc<dyn SelectionServiceListener>) {
        let mut inner = self.inner.write().unwrap();
        // Compare Arc data pointers for identity (cast fat pointer to thin pointer).
        let ptr = Arc::as_ptr(listener) as *const () as usize;
        inner
            .listeners
            .retain(|l| Arc::as_ptr(l) as *const () as usize != ptr);
    }

    fn listener_count(&self) -> usize {
        let inner = self.inner.read().unwrap();
        inner.listeners.len()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- ProgramSelection tests -----------------------------------------------

    #[test]
    fn test_program_selection_empty() {
        let sel = ProgramSelection::new();
        assert!(sel.is_empty());
        assert_eq!(sel.num_addresses(), 0);
        assert_eq!(sel.num_ranges(), 0);
        assert_eq!(sel.min_address(), None);
        assert_eq!(sel.max_address(), None);
    }

    #[test]
    fn test_program_selection_from_range() {
        let sel = ProgramSelection::from_range(0x1000, 0x100F);
        assert_eq!(sel.num_addresses(), 16);
        assert_eq!(sel.num_ranges(), 1);
        assert_eq!(sel.min_address(), Some(0x1000));
        assert_eq!(sel.max_address(), Some(0x100F));
    }

    #[test]
    fn test_program_selection_contains() {
        let sel = ProgramSelection::from_range(0x1000, 0x100F);
        assert!(sel.contains(0x1000));
        assert!(sel.contains(0x1005));
        assert!(sel.contains(0x100F));
        assert!(!sel.contains(0x0FFF));
        assert!(!sel.contains(0x1010));
    }

    #[test]
    fn test_program_selection_add_range_merge() {
        let mut sel = ProgramSelection::new();
        sel.add_range(0x1000, 0x100F);
        sel.add_range(0x1010, 0x101F);
        // Adjacent ranges should be merged.
        assert_eq!(sel.num_ranges(), 1);
        assert_eq!(sel.num_addresses(), 32);
    }

    #[test]
    fn test_program_selection_add_range_overlap() {
        let mut sel = ProgramSelection::new();
        sel.add_range(0x1000, 0x100F);
        sel.add_range(0x1005, 0x1014);
        assert_eq!(sel.num_ranges(), 1);
        assert_eq!(sel.num_addresses(), 21); // 0x1000..=0x1014
    }

    #[test]
    fn test_program_selection_add_range_disjoint() {
        let mut sel = ProgramSelection::new();
        sel.add_range(0x1000, 0x100F);
        sel.add_range(0x2000, 0x200F);
        assert_eq!(sel.num_ranges(), 2);
        assert_eq!(sel.num_addresses(), 32);
    }

    #[test]
    fn test_program_selection_remove_range() {
        let mut sel = ProgramSelection::from_range(0x1000, 0x100F);
        sel.remove_range(0x1005, 0x100A);
        assert_eq!(sel.num_addresses(), 10);
        assert!(sel.contains(0x1004));
        assert!(!sel.contains(0x1005));
        assert!(!sel.contains(0x100A));
        assert!(sel.contains(0x100B));
        assert_eq!(sel.num_ranges(), 2);
    }

    #[test]
    fn test_program_selection_remove_full_range() {
        let mut sel = ProgramSelection::from_range(0x1000, 0x100F);
        sel.remove_range(0x1000, 0x100F);
        assert!(sel.is_empty());
    }

    #[test]
    fn test_program_selection_invert() {
        let mut sel = ProgramSelection::new();
        sel.add_address(0x1005);
        sel.invert(0x1000, 0x1009);
        assert!(!sel.contains(0x1005));
        assert!(sel.contains(0x1000));
        assert!(sel.contains(0x1004));
        assert!(sel.contains(0x1006));
        assert!(sel.contains(0x1009));
        assert_eq!(sel.num_addresses(), 9);
    }

    #[test]
    fn test_program_selection_union() {
        let mut a = ProgramSelection::from_range(0x1000, 0x100F);
        let b = ProgramSelection::from_range(0x1008, 0x1017);
        a.union_with(&b);
        assert_eq!(a.num_ranges(), 1);
        assert_eq!(a.num_addresses(), 24); // 0x1000..=0x1017
    }

    #[test]
    fn test_program_selection_intersect() {
        let mut a = ProgramSelection::from_range(0x1000, 0x100F);
        let b = ProgramSelection::from_range(0x1008, 0x1017);
        a.intersect_with(&b);
        assert_eq!(a.num_ranges(), 1);
        assert_eq!(a.num_addresses(), 8); // 0x1008..=0x100F
    }

    #[test]
    fn test_program_selection_subtract() {
        let mut a = ProgramSelection::from_range(0x1000, 0x100F);
        let b = ProgramSelection::from_range(0x1005, 0x100A);
        a.subtract_with(&b);
        assert_eq!(a.num_ranges(), 2);
        assert_eq!(a.num_addresses(), 10);
    }

    #[test]
    fn test_program_selection_from_addresses() {
        let mut addrs = BTreeSet::new();
        addrs.insert(0x1000);
        addrs.insert(0x1001);
        addrs.insert(0x1002);
        addrs.insert(0x2000);
        let sel = ProgramSelection::from_addresses(&addrs);
        assert_eq!(sel.num_ranges(), 2);
        assert_eq!(sel.num_addresses(), 4);
    }

    #[test]
    fn test_program_selection_to_address_set() {
        let sel = ProgramSelection::from_range(0x1000, 0x1002);
        let set = sel.to_address_set();
        assert_eq!(set.len(), 3);
        assert!(set.contains(&0x1000));
        assert!(set.contains(&0x1001));
        assert!(set.contains(&0x1002));
    }

    #[test]
    fn test_program_selection_from_raw_ranges() {
        let sel = ProgramSelection::from_raw_ranges(&[(0x2000, 0x200F), (0x1000, 0x100F)]);
        assert_eq!(sel.num_ranges(), 2);
        assert_eq!(sel.min_address(), Some(0x1000));
        assert_eq!(sel.max_address(), Some(0x200F));
    }

    #[test]
    fn test_program_selection_display() {
        let sel = ProgramSelection::from_range(0x1000, 0x100F);
        let display = format!("{}", sel);
        assert!(display.contains("ranges=1"));
        assert!(display.contains("addresses=16"));
    }

    #[test]
    fn test_program_selection_clear() {
        let mut sel = ProgramSelection::from_range(0x1000, 0x100F);
        sel.clear();
        assert!(sel.is_empty());
    }

    #[test]
    fn test_program_selection_add_address() {
        let mut sel = ProgramSelection::new();
        sel.add_address(0x1000);
        sel.add_address(0x1001);
        sel.add_address(0x1003);
        assert_eq!(sel.num_ranges(), 2); // {0x1000..0x1001, 0x1003}
        assert_eq!(sel.num_addresses(), 3);
    }

    #[test]
    fn test_program_selection_remove_address() {
        let mut sel = ProgramSelection::from_range(0x1000, 0x100F);
        sel.remove_address(0x1005);
        assert_eq!(sel.num_addresses(), 15);
        assert!(!sel.contains(0x1005));
        assert_eq!(sel.num_ranges(), 2);
    }

    #[test]
    fn test_program_selection_invert_empty() {
        let mut sel = ProgramSelection::new();
        sel.invert(0x1000, 0x100F);
        assert_eq!(sel.num_addresses(), 16);
        assert_eq!(sel.num_ranges(), 1);
    }

    // -- DefaultSelectionService tests ----------------------------------------

    #[test]
    fn test_default_service_creation() {
        let service = DefaultSelectionService::new();
        assert!(!service.has_selection());
        assert_eq!(service.listener_count(), 0);
    }

    #[test]
    fn test_default_service_set_and_get() {
        let service = DefaultSelectionService::new();
        let sel = ProgramSelection::from_range(0x1000, 0x100F);
        service.set_selection(sel.clone());
        assert!(service.has_selection());
        let got = service.get_selection();
        assert_eq!(got.num_addresses(), 16);
    }

    #[test]
    fn test_default_service_clear() {
        let service = DefaultSelectionService::new();
        service.set_selection(ProgramSelection::from_range(0x1000, 0x100F));
        assert!(service.has_selection());
        service.clear_selection();
        assert!(!service.has_selection());
    }

    #[test]
    fn test_default_service_listener_notification() {
        let service = DefaultSelectionService::new();
        let listener = Arc::new(TestServiceListener::new());
        service.add_selection_listener(listener.clone());
        assert_eq!(service.listener_count(), 1);

        let sel = ProgramSelection::from_range(0x1000, 0x100F);
        service.set_selection(sel);
        assert_eq!(listener.call_count(), 1);

        service.clear_selection();
        assert_eq!(listener.call_count(), 2);
    }

    #[test]
    fn test_default_service_remove_listener() {
        let service = DefaultSelectionService::new();
        let listener = Arc::new(TestServiceListener::new());
        service.add_selection_listener(listener.clone());
        assert_eq!(service.listener_count(), 1);

        service.remove_selection_listener(&listener);
        assert_eq!(service.listener_count(), 0);
    }

    // -- Test helper ----------------------------------------------------------

    #[derive(Debug)]
    struct TestServiceListener {
        count: std::sync::atomic::AtomicUsize,
    }

    impl TestServiceListener {
        fn new() -> Self {
            Self {
                count: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn call_count(&self) -> usize {
            self.count.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl SelectionServiceListener for TestServiceListener {
        fn selection_changed(&self, _selection: &ProgramSelection) {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}
