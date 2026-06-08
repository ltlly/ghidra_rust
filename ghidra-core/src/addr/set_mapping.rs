//! Random-access mapping for address sets.
//!
//! Direct translation of `ghidra.program.model.address.AddressSetMapping`.
//!
//! Provides [`AddressSetMapping`] which maps a contiguous index `[0..N)` to
//! the N addresses in an `AddressSet`, collapsing any holes. This is useful
//! for UI components (e.g., scrollbars) that need to map a linear position
//! to an address in a sparse set.

use crate::addr::{Address, AddressRange};
use crate::addr::set_view::AddressSetView;

/// Provides random access to addresses in an address set by index.
///
/// Corresponds to `ghidra.program.model.address.AddressSetMapping`.
///
/// Given an `AddressSet` containing addresses `[0,1,2,3,4,90,91,92,93,94]`,
/// `get_address(5)` returns the address at offset 90, not 5. This class
/// collapses a sparse address space with holes into a contiguous list.
///
/// # Examples
///
/// ```
/// use ghidra_core::addr::{Address, AddressSet};
/// use ghidra_core::addr::set_mapping::AddressSetMapping;
///
/// let mut set = AddressSet::new();
/// set.add_range(Address::new(0), Address::new(4));
/// set.add_range(Address::new(90), Address::new(94));
///
/// let mut mapping = AddressSetMapping::new(&set);
/// assert_eq!(mapping.get_address(0).unwrap().offset, 0);
/// assert_eq!(mapping.get_address(5).unwrap().offset, 90);
/// assert_eq!(mapping.num_addresses(), 10);
/// ```
pub struct AddressSetMapping {
    /// Flattened list of ranges from the set.
    ranges: Vec<AddressRange>,
    /// Prefix sum: `indexes[i]` is the start index of range `i`.
    indexes: Vec<u64>,
    /// Total number of addresses.
    max_index: u64,
    /// Cache: index into `ranges` for the current range.
    current_range_index: usize,
    /// Cache: start index of the current range.
    current_range_start: i64,
    /// Cache: end index of the current range.
    current_range_end: i64,
}

impl AddressSetMapping {
    /// Create a new mapping for the given address set view.
    ///
    /// # Panics
    ///
    /// Panics if the set has more than `i64::MAX` addresses.
    pub fn new(set: &dyn AddressSetView) -> Self {
        let num_addrs = set.num_addresses();
        assert!(
            num_addrs <= i64::MAX as u64,
            "AddressSetMapping does not support sets with >= i64::MAX addresses"
        );

        let ranges: Vec<AddressRange> = set.iter_ranges().collect();
        let mut indexes = Vec::with_capacity(ranges.len() + 1);
        indexes.push(0);
        for r in &ranges {
            let prev = *indexes.last().unwrap();
            indexes.push(prev + r.len());
        }

        Self {
            ranges,
            indexes,
            max_index: num_addrs,
            current_range_index: 0,
            current_range_start: -1,
            current_range_end: -1,
        }
    }

    /// Returns the total number of addresses in the mapping.
    pub fn num_addresses(&self) -> u64 {
        self.max_index
    }

    /// Returns the number of address ranges.
    pub fn num_ranges(&self) -> usize {
        self.ranges.len()
    }

    /// Get the address at the given index position.
    ///
    /// Returns `None` if the index is out of bounds.
    pub fn get_address(&mut self, index: u64) -> Option<Address> {
        if index >= self.max_index {
            return None;
        }

        let idx = index as i64;
        if !self.index_in_current_range(idx) {
            self.set_current_range(idx);
        }

        let offset_in_range = (idx - self.current_range_start) as u64;
        let range = &self.ranges[self.current_range_index];
        Some(range.get_min_address().add(offset_in_range))
    }

    /// Find the index of the given address in the mapping.
    ///
    /// Returns `None` if the address is not in the set.
    pub fn get_index(&self, addr: Address) -> Option<u64> {
        for (i, range) in self.ranges.iter().enumerate() {
            if addr.offset >= range.get_min_address().offset
                && addr.offset <= range.get_max_address().offset
            {
                let base = self.indexes[i];
                return Some(base + (addr.offset - range.get_min_address().offset));
            }
        }
        None
    }

    fn index_in_current_range(&self, index: i64) -> bool {
        index >= self.current_range_start && index <= self.current_range_end
    }

    fn set_current_range(&mut self, index: i64) {
        // Optimized: check if index is one past the current range end
        if self.current_range_end >= 0
            && index == self.current_range_end + 1
            && self.current_range_index + 1 < self.ranges.len()
        {
            self.current_range_index += 1;
        } else {
            // Binary search for the correct range.
            // `indexes` is a prefix-sum: [0, len(r0), len(r0)+len(r1), ...]
            // We want the largest i such that indexes[i] <= index.
            // binary_search returns Ok(i) if indexes[i] == index, or Err(i)
            // where i is the insertion point (first index > target).
            let idx = index as u64;
            let pos = self.indexes[..self.indexes.len() - 1]
                .binary_search(&idx);
            self.current_range_index = match pos {
                Ok(i) => i,
                Err(i) => {
                    // i is the first index whose value > target,
                    // so i-1 is the last index whose value <= target
                    if i == 0 { 0 } else { i - 1 }
                }
            };
        }

        let range = &self.ranges[self.current_range_index];
        self.current_range_start = self.indexes[self.current_range_index] as i64;
        self.current_range_end = self.current_range_start + range.len() as i64 - 1;
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::AddressSet;

    #[test]
    fn test_basic_mapping() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0), Address::new(4));
        set.add_range(Address::new(90), Address::new(94));

        let mut mapping = AddressSetMapping::new(&set);
        assert_eq!(mapping.num_addresses(), 10);
        assert_eq!(mapping.num_ranges(), 2);

        assert_eq!(mapping.get_address(0).unwrap().offset, 0);
        assert_eq!(mapping.get_address(1).unwrap().offset, 1);
        assert_eq!(mapping.get_address(4).unwrap().offset, 4);
        assert_eq!(mapping.get_address(5).unwrap().offset, 90);
        assert_eq!(mapping.get_address(9).unwrap().offset, 94);
    }

    #[test]
    fn test_out_of_bounds() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0), Address::new(4));
        let mut mapping = AddressSetMapping::new(&set);
        assert!(mapping.get_address(5).is_none());
        assert!(mapping.get_address(u64::MAX).is_none());
    }

    #[test]
    fn test_sequential_access() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0), Address::new(4));
        set.add_range(Address::new(100), Address::new(104));
        set.add_range(Address::new(200), Address::new(204));

        let mut mapping = AddressSetMapping::new(&set);
        for i in 0..15 {
            let addr = mapping.get_address(i).unwrap();
            match i {
                0..=4 => assert_eq!(addr.offset, i),
                5..=9 => assert_eq!(addr.offset, 100 + (i - 5)),
                10..=14 => assert_eq!(addr.offset, 200 + (i - 10)),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn test_random_access() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0), Address::new(4));
        set.add_range(Address::new(100), Address::new(104));

        let mut mapping = AddressSetMapping::new(&set);
        // Jump from range 0 to range 1
        assert_eq!(mapping.get_address(7).unwrap().offset, 102);
        // Back to range 0
        assert_eq!(mapping.get_address(2).unwrap().offset, 2);
    }

    #[test]
    fn test_get_index() {
        let mut set = AddressSet::new();
        set.add_range(Address::new(0), Address::new(4));
        set.add_range(Address::new(90), Address::new(94));

        let mapping = AddressSetMapping::new(&set);
        assert_eq!(mapping.get_index(Address::new(0)), Some(0));
        assert_eq!(mapping.get_index(Address::new(4)), Some(4));
        assert_eq!(mapping.get_index(Address::new(90)), Some(5));
        assert_eq!(mapping.get_index(Address::new(94)), Some(9));
        assert_eq!(mapping.get_index(Address::new(50)), None);
    }

    #[test]
    fn test_empty_set() {
        let set = AddressSet::new();
        let mut mapping = AddressSetMapping::new(&set);
        assert_eq!(mapping.num_addresses(), 0);
        assert!(mapping.get_address(0).is_none());
    }

    #[test]
    fn test_singleton_set() {
        let mut set = AddressSet::new();
        set.add(Address::new(42));
        let mut mapping = AddressSetMapping::new(&set);
        assert_eq!(mapping.num_addresses(), 1);
        assert_eq!(mapping.get_address(0).unwrap().offset, 42);
    }
}
