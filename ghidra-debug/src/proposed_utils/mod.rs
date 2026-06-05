//! Proposed utility types used by the debug framework.
//!
//! Ported from Ghidra's `ProposedUtils` module.
//!
//! Provides utility types including:
//! - **Spatial data structures**: R*-tree, hyper-box queries, 2D rectangles.
//! - **Database utilities**: Key spans, field spans, cached object stores,
//!   directed iterators, and annotated object frameworks.
//! - **General utilities**: Observable collections, lock holds, pairing iterators,
//!   merging spliterators, and dependent service resolution.

pub mod database;
pub mod spatial;

// ---------------------------------------------------------------------------
// General Utilities
// ---------------------------------------------------------------------------

use serde::{Deserialize, Serialize};

/// A lock hold guard that tracks whether a lock is currently held.
///
/// Ported from Ghidra's `LockHold`.
#[derive(Debug, Clone, Default)]
pub struct LockHold {
    held: bool,
}

impl LockHold {
    /// Create a new lock hold (not held).
    pub fn new() -> Self {
        Self { held: false }
    }

    /// Acquire the lock.
    pub fn acquire(&mut self) {
        self.held = true;
    }

    /// Release the lock.
    pub fn release(&mut self) {
        self.held = false;
    }

    /// Whether the lock is currently held.
    pub fn is_held(&self) -> bool {
        self.held
    }
}

/// An iterator that merges two sorted iterators.
///
/// Ported from Ghidra's `MergeSortingSpliterator`.
#[derive(Debug, Clone)]
pub struct MergingIterator<T: Ord> {
    a: Vec<T>,
    b: Vec<T>,
    pos_a: usize,
    pos_b: usize,
}

impl<T: Ord + Clone> MergingIterator<T> {
    /// Create a new merging iterator from two sorted vectors.
    pub fn new(a: Vec<T>, b: Vec<T>) -> Self {
        Self {
            a,
            b,
            pos_a: 0,
            pos_b: 0,
        }
    }

    /// Collect all remaining items into a sorted vector.
    pub fn merge_collect(&mut self) -> Vec<T> {
        let mut result = Vec::with_capacity(self.a.len() + self.b.len());
        while self.pos_a < self.a.len() && self.pos_b < self.b.len() {
            if self.a[self.pos_a] <= self.b[self.pos_b] {
                result.push(self.a[self.pos_a].clone());
                self.pos_a += 1;
            } else {
                result.push(self.b[self.pos_b].clone());
                self.pos_b += 1;
            }
        }
        while self.pos_a < self.a.len() {
            result.push(self.a[self.pos_a].clone());
            self.pos_a += 1;
        }
        while self.pos_b < self.b.len() {
            result.push(self.b[self.pos_b].clone());
            self.pos_b += 1;
        }
        result
    }
}

/// An observable collection that notifies listeners of changes.
///
/// Ported from Ghidra's `ObservableCollection`.
#[derive(Debug, Clone)]
pub struct ObservableCollection<T: Clone> {
    items: Vec<T>,
    /// Number of times the collection has been modified.
    pub modification_count: u64,
}

impl<T: Clone> ObservableCollection<T> {
    /// Create a new observable collection.
    pub fn new() -> Self {
        Self {
            items: Vec::new(),
            modification_count: 0,
        }
    }

    /// Add an item.
    pub fn push(&mut self, item: T) {
        self.items.push(item);
        self.modification_count += 1;
    }

    /// Remove an item at the given index.
    pub fn remove(&mut self, index: usize) -> T {
        self.modification_count += 1;
        self.items.remove(index)
    }

    /// Get the number of items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Get an item by index.
    pub fn get(&self, index: usize) -> Option<&T> {
        self.items.get(index)
    }

    /// Iterate over items.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }
}

impl<T: Clone> Default for ObservableCollection<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// A lazy collection that materializes elements on demand.
///
/// Ported from Ghidra's `LazyCollection`.
#[derive(Debug, Clone)]
pub struct LazyCollection<T> {
    materialized: Vec<T>,
    remaining: usize,
}

impl<T> LazyCollection<T> {
    /// Create a new lazy collection.
    pub fn new(remaining: usize) -> Self {
        Self {
            materialized: Vec::new(),
            remaining,
        }
    }

    /// Add an already-materialized item.
    pub fn push(&mut self, item: T) {
        self.materialized.push(item);
        if self.remaining > 0 {
            self.remaining -= 1;
        }
    }

    /// Get the number of materialized items.
    pub fn materialized_len(&self) -> usize {
        self.materialized.len()
    }

    /// How many items remain to be materialized.
    pub fn remaining(&self) -> usize {
        self.remaining
    }

    /// Whether all items have been materialized.
    pub fn is_fully_materialized(&self) -> bool {
        self.remaining == 0
    }

    /// Get a reference to the materialized items.
    pub fn as_slice(&self) -> &[T] {
        &self.materialized
    }
}

/// An iterator that pairs items from two iterators.
///
/// Ported from Ghidra's `PairingIteratorMerger`.
#[derive(Debug, Clone)]
pub struct PairingIterator<A, B> {
    a: Vec<A>,
    b: Vec<B>,
    pos: usize,
}

impl<A: Clone, B: Clone> PairingIterator<A, B> {
    /// Create a new pairing iterator.
    pub fn new(a: Vec<A>, b: Vec<B>) -> Self {
        Self { a, b, pos: 0 }
    }

    /// Collect all pairs.
    pub fn collect_pairs(&mut self) -> Vec<(A, B)> {
        let mut result = Vec::new();
        while self.pos < self.a.len() && self.pos < self.b.len() {
            result.push((self.a[self.pos].clone(), self.b[self.pos].clone()));
            self.pos += 1;
        }
        result
    }
}

/// A cached address set view.
///
/// Ported from Ghidra's `CachedAddressSetView`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CachedAddressSetView {
    /// Address ranges: (min, max) pairs, sorted.
    ranges: Vec<(u64, u64)>,
}

impl CachedAddressSetView {
    /// Create a new empty address set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a range.
    pub fn add_range(&mut self, min: u64, max: u64) {
        self.ranges.push((min, max));
        self.ranges.sort_by_key(|r| r.0);
    }

    /// Whether the set contains an address.
    pub fn contains(&self, addr: u64) -> bool {
        self.ranges.iter().any(|(min, max)| addr >= *min && addr <= *max)
    }

    /// The number of ranges.
    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }

    /// The total number of addresses.
    pub fn num_addresses(&self) -> u64 {
        self.ranges.iter().map(|(min, max)| max - min + 1).sum()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Iterate over ranges.
    pub fn ranges(&self) -> &[(u64, u64)] {
        &self.ranges
    }
}

/// An iterator direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// Forward iteration.
    Forward,
    /// Backward iteration.
    Backward,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lock_hold() {
        let mut lh = LockHold::new();
        assert!(!lh.is_held());
        lh.acquire();
        assert!(lh.is_held());
        lh.release();
        assert!(!lh.is_held());
    }

    #[test]
    fn test_merging_iterator() {
        let mut mi = MergingIterator::new(vec![1, 3, 5], vec![2, 4, 6]);
        let result = mi.merge_collect();
        assert_eq!(result, vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn test_merging_iterator_empty() {
        let mut mi = MergingIterator::<i32>::new(vec![], vec![]);
        assert!(mi.merge_collect().is_empty());
    }

    #[test]
    fn test_merging_iterator_one_empty() {
        let mut mi = MergingIterator::new(vec![1, 2], vec![]);
        assert_eq!(mi.merge_collect(), vec![1, 2]);
    }

    #[test]
    fn test_observable_collection() {
        let mut col = ObservableCollection::new();
        assert!(col.is_empty());

        col.push(10);
        col.push(20);
        assert_eq!(col.len(), 2);
        assert_eq!(col.modification_count, 2);

        let removed = col.remove(0);
        assert_eq!(removed, 10);
        assert_eq!(col.modification_count, 3);
    }

    #[test]
    fn test_lazy_collection() {
        let mut lc = LazyCollection::new(5);
        assert_eq!(lc.remaining(), 5);
        assert!(!lc.is_fully_materialized());

        lc.push(1);
        lc.push(2);
        assert_eq!(lc.materialized_len(), 2);
        assert_eq!(lc.remaining(), 3);
    }

    #[test]
    fn test_pairing_iterator() {
        let mut pi = PairingIterator::new(vec!["a", "b", "c"], vec![1, 2, 3]);
        let pairs = pi.collect_pairs();
        assert_eq!(pairs, vec![("a", 1), ("b", 2), ("c", 3)]);
    }

    #[test]
    fn test_pairing_iterator_mismatched() {
        let mut pi = PairingIterator::new(vec!["a", "b"], vec![1]);
        let pairs = pi.collect_pairs();
        assert_eq!(pairs, vec![("a", 1)]);
    }

    #[test]
    fn test_cached_address_set_view() {
        let mut set = CachedAddressSetView::new();
        set.add_range(0x1000, 0x1FFF);
        set.add_range(0x400000, 0x400FFF);

        assert!(set.contains(0x1500));
        assert!(set.contains(0x400000));
        assert!(!set.contains(0x2000));
        assert_eq!(set.num_ranges(), 2);
        assert_eq!(set.num_addresses(), 0x1000 + 0x1000);
    }

    #[test]
    fn test_cached_address_set_empty() {
        let set = CachedAddressSetView::new();
        assert!(set.is_empty());
        assert!(!set.contains(0));
    }

    #[test]
    fn test_direction() {
        assert_ne!(Direction::Forward, Direction::Backward);
    }

    #[test]
    fn test_observable_collection_default() {
        let col: ObservableCollection<i32> = ObservableCollection::default();
        assert!(col.is_empty());
    }
}
