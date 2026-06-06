//! Data structure utilities.
//!
//! Ported from `ghidra.util.data`.
//!
//! Provides common data structures used across Ghidra including
//! accumulators and collection utilities.

// ---------------------------------------------------------------------------
// Accumulator
// ---------------------------------------------------------------------------

/// A thread-safe accumulator for collecting results from search operations.
///
/// Used by search tasks and handlers to collect results asynchronously.
#[derive(Debug)]
pub struct Accumulator<T> {
    items: Vec<T>,
}

impl<T> Accumulator<T> {
    /// Create a new empty accumulator.
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Add an item to the accumulator.
    pub fn add(&mut self, item: T) {
        self.items.push(item);
    }

    /// Add multiple items.
    pub fn add_all(&mut self, items: impl IntoIterator<Item = T>) {
        self.items.extend(items);
    }

    /// Get all accumulated items.
    pub fn get(&self) -> &[T] {
        &self.items
    }

    /// Drain all items out of the accumulator.
    pub fn drain(&mut self) -> Vec<T> {
        std::mem::take(&mut self.items)
    }

    /// Number of accumulated items.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the accumulator is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Clear all accumulated items.
    pub fn clear(&mut self) {
        self.items.clear();
    }
}

impl<T> Default for Accumulator<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> IntoIterator for Accumulator<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.items.into_iter()
    }
}

// ---------------------------------------------------------------------------
// Selection
// ---------------------------------------------------------------------------

/// Represents a selection of addresses in a program.
///
/// Internally stores address ranges as (start, end) pairs, sorted by start address.
#[derive(Debug, Clone, Default)]
pub struct AddressSelection {
    ranges: Vec<(u64, u64)>,
}

impl AddressSelection {
    /// Create a new empty selection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a range to the selection.
    pub fn add_range(&mut self, start: u64, end: u64) {
        self.ranges.push((start, end));
        self.ranges.sort_by_key(|r| r.0);
    }

    /// Add a single address.
    pub fn add_address(&mut self, addr: u64) {
        self.add_range(addr, addr);
    }

    /// Whether the selection contains an address.
    pub fn contains(&self, addr: u64) -> bool {
        self.ranges.iter().any(|&(s, e)| addr >= s && addr <= e)
    }

    /// Number of ranges.
    pub fn range_count(&self) -> usize {
        self.ranges.len()
    }

    /// Whether the selection is empty.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Total number of addresses covered.
    pub fn num_addresses(&self) -> u64 {
        self.ranges
            .iter()
            .map(|&(s, e)| e - s + 1)
            .sum()
    }

    /// All ranges as a slice.
    pub fn ranges(&self) -> &[(u64, u64)] {
        &self.ranges
    }

    /// Clear the selection.
    pub fn clear(&mut self) {
        self.ranges.clear();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_accumulator_basic() {
        let mut acc = Accumulator::new();
        assert!(acc.is_empty());
        acc.add(1);
        acc.add(2);
        acc.add(3);
        assert_eq!(acc.len(), 3);
        assert_eq!(acc.get(), &[1, 2, 3]);
    }

    #[test]
    fn test_accumulator_add_all() {
        let mut acc = Accumulator::new();
        acc.add_all(vec![10, 20, 30]);
        assert_eq!(acc.len(), 3);
    }

    #[test]
    fn test_accumulator_drain() {
        let mut acc = Accumulator::new();
        acc.add("a");
        acc.add("b");
        let items = acc.drain();
        assert_eq!(items, vec!["a", "b"]);
        assert!(acc.is_empty());
    }

    #[test]
    fn test_accumulator_into_iter() {
        let mut acc = Accumulator::new();
        acc.add(1);
        acc.add(2);
        let sum: i32 = acc.into_iter().sum();
        assert_eq!(sum, 3);
    }

    #[test]
    fn test_address_selection() {
        let mut sel = AddressSelection::new();
        sel.add_range(0x1000, 0x1FFF);
        sel.add_address(0x3000);
        assert!(sel.contains(0x1500));
        assert!(sel.contains(0x3000));
        assert!(!sel.contains(0x2000));
        assert_eq!(sel.range_count(), 2);
        assert_eq!(sel.num_addresses(), 0x1000 + 1);
    }

    #[test]
    fn test_address_selection_clear() {
        let mut sel = AddressSelection::new();
        sel.add_address(0x1000);
        assert!(!sel.is_empty());
        sel.clear();
        assert!(sel.is_empty());
    }
}
