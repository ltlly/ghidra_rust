//! Address iterators for search -- ported from Ghidra's
//! `ghidra.app.plugin.core.searchtext.iterators` package.
//!
//! Provides iterators that yield addresses of specific field types
//! (comments, instructions, data, labels, functions) for use by the
//! search subsystem.

use ghidra_core::Address;

// ---------------------------------------------------------------------------
// SearchAddressIterator trait
// ---------------------------------------------------------------------------

/// Trait for iterators that yield addresses of interest for searching.
///
/// Each implementation focuses on a specific field type (comments,
/// labels, instructions, data, functions) and yields addresses in
/// the specified direction.
pub trait SearchAddressIterator {
    /// Get the next address in the iteration.
    fn next_address(&mut self) -> Option<Address>;

    /// Reset the iterator to the beginning.
    fn reset(&mut self);
}

// ---------------------------------------------------------------------------
// CommentSearchAddressIterator
// ---------------------------------------------------------------------------

/// Yields addresses that have comments.
///
/// The addresses are sorted in the iteration direction (forward or backward).
pub struct CommentSearchAddressIterator {
    /// Sorted addresses with comments.
    addresses: Vec<Address>,
    /// Current position.
    position: usize,
}

impl CommentSearchAddressIterator {
    /// Create a new comment address iterator.
    pub fn new(mut addresses: Vec<Address>, forward: bool) -> Self {
        addresses.sort();
        if !forward {
            addresses.reverse();
        }
        Self {
            addresses,
            position: 0,
        }
    }
}

impl SearchAddressIterator for CommentSearchAddressIterator {
    fn next_address(&mut self) -> Option<Address> {
        if self.position < self.addresses.len() {
            let addr = self.addresses[self.position];
            self.position += 1;
            Some(addr)
        } else {
            None
        }
    }

    fn reset(&mut self) {
        self.position = 0;
    }
}

// ---------------------------------------------------------------------------
// InstructionSearchAddressIterator
// ---------------------------------------------------------------------------

/// Yields addresses of instructions.
pub struct InstructionSearchAddressIterator {
    addresses: Vec<Address>,
    position: usize,
}

impl InstructionSearchAddressIterator {
    /// Create a new instruction address iterator.
    pub fn new(mut addresses: Vec<Address>, forward: bool) -> Self {
        addresses.sort();
        if !forward {
            addresses.reverse();
        }
        Self {
            addresses,
            position: 0,
        }
    }
}

impl SearchAddressIterator for InstructionSearchAddressIterator {
    fn next_address(&mut self) -> Option<Address> {
        if self.position < self.addresses.len() {
            let addr = self.addresses[self.position];
            self.position += 1;
            Some(addr)
        } else {
            None
        }
    }

    fn reset(&mut self) {
        self.position = 0;
    }
}

// ---------------------------------------------------------------------------
// DataSearchAddressIterator
// ---------------------------------------------------------------------------

/// Yields addresses of defined data.
pub struct DataSearchAddressIterator {
    addresses: Vec<Address>,
    position: usize,
}

impl DataSearchAddressIterator {
    /// Create a new data address iterator.
    pub fn new(mut addresses: Vec<Address>, forward: bool) -> Self {
        addresses.sort();
        if !forward {
            addresses.reverse();
        }
        Self {
            addresses,
            position: 0,
        }
    }
}

impl SearchAddressIterator for DataSearchAddressIterator {
    fn next_address(&mut self) -> Option<Address> {
        if self.position < self.addresses.len() {
            let addr = self.addresses[self.position];
            self.position += 1;
            Some(addr)
        } else {
            None
        }
    }

    fn reset(&mut self) {
        self.position = 0;
    }
}

// ---------------------------------------------------------------------------
// LabelSearchAddressIterator
// ---------------------------------------------------------------------------

/// Yields addresses that have symbol labels.
pub struct LabelSearchAddressIterator {
    addresses: Vec<Address>,
    position: usize,
}

impl LabelSearchAddressIterator {
    /// Create a new label address iterator.
    pub fn new(mut addresses: Vec<Address>, forward: bool) -> Self {
        addresses.sort();
        if !forward {
            addresses.reverse();
        }
        Self {
            addresses,
            position: 0,
        }
    }
}

impl SearchAddressIterator for LabelSearchAddressIterator {
    fn next_address(&mut self) -> Option<Address> {
        if self.position < self.addresses.len() {
            let addr = self.addresses[self.position];
            self.position += 1;
            Some(addr)
        } else {
            None
        }
    }

    fn reset(&mut self) {
        self.position = 0;
    }
}

// ---------------------------------------------------------------------------
// FunctionSearchAddressIterator
// ---------------------------------------------------------------------------

/// Yields addresses of function entry points.
pub struct FunctionSearchAddressIterator {
    addresses: Vec<Address>,
    position: usize,
}

impl FunctionSearchAddressIterator {
    /// Create a new function address iterator.
    pub fn new(mut addresses: Vec<Address>, forward: bool) -> Self {
        addresses.sort();
        if !forward {
            addresses.reverse();
        }
        Self {
            addresses,
            position: 0,
        }
    }
}

impl SearchAddressIterator for FunctionSearchAddressIterator {
    fn next_address(&mut self) -> Option<Address> {
        if self.position < self.addresses.len() {
            let addr = self.addresses[self.position];
            self.position += 1;
            Some(addr)
        } else {
            None
        }
    }

    fn reset(&mut self) {
        self.position = 0;
    }
}

// ---------------------------------------------------------------------------
// CompositeSearchAddressIterator
// ---------------------------------------------------------------------------

/// Combines multiple search address iterators into one, yielding
/// addresses in sorted order (merging all sources).
pub struct CompositeSearchAddressIterator {
    /// All addresses from all sources, sorted and deduplicated.
    addresses: Vec<Address>,
    position: usize,
}

impl CompositeSearchAddressIterator {
    /// Create from multiple address vectors.
    pub fn new(sources: Vec<Vec<Address>>, forward: bool) -> Self {
        let mut all: Vec<Address> = sources.into_iter().flatten().collect();
        all.sort();
        all.dedup();
        if !forward {
            all.reverse();
        }
        Self {
            addresses: all,
            position: 0,
        }
    }
}

impl SearchAddressIterator for CompositeSearchAddressIterator {
    fn next_address(&mut self) -> Option<Address> {
        if self.position < self.addresses.len() {
            let addr = self.addresses[self.position];
            self.position += 1;
            Some(addr)
        } else {
            None
        }
    }

    fn reset(&mut self) {
        self.position = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;


    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_comment_iterator_forward() {
        let mut iter = CommentSearchAddressIterator::new(
            vec![addr(0x3000), addr(0x1000), addr(0x2000)],
            true,
        );
        let addrs: Vec<_> = std::iter::from_fn(|| iter.next_address()).collect();
        assert_eq!(addrs, vec![addr(0x1000), addr(0x2000), addr(0x3000)]);
    }

    #[test]
    fn test_comment_iterator_backward() {
        let mut iter = CommentSearchAddressIterator::new(
            vec![addr(0x3000), addr(0x1000), addr(0x2000)],
            false,
        );
        let addrs: Vec<_> = std::iter::from_fn(|| iter.next_address()).collect();
        assert_eq!(addrs, vec![addr(0x3000), addr(0x2000), addr(0x1000)]);
    }

    #[test]
    fn test_instruction_iterator() {
        let mut iter =
            InstructionSearchAddressIterator::new(vec![addr(0x1000), addr(0x2000)], true);
        assert_eq!(iter.next_address(), Some(addr(0x1000)));
        assert_eq!(iter.next_address(), Some(addr(0x2000)));
        assert_eq!(iter.next_address(), None);
    }

    #[test]
    fn test_data_iterator_reset() {
        let mut iter = DataSearchAddressIterator::new(vec![addr(0x1000)], true);
        assert_eq!(iter.next_address(), Some(addr(0x1000)));
        assert_eq!(iter.next_address(), None);
        iter.reset();
        assert_eq!(iter.next_address(), Some(addr(0x1000)));
    }

    #[test]
    fn test_label_iterator_empty() {
        let mut iter = LabelSearchAddressIterator::new(Vec::new(), true);
        assert_eq!(iter.next_address(), None);
    }

    #[test]
    fn test_function_iterator() {
        let mut iter = FunctionSearchAddressIterator::new(
            vec![addr(0x5000), addr(0x1000)],
            true,
        );
        assert_eq!(iter.next_address(), Some(addr(0x1000)));
        assert_eq!(iter.next_address(), Some(addr(0x5000)));
    }

    #[test]
    fn test_composite_iterator_dedup() {
        let sources = vec![
            vec![addr(0x1000), addr(0x2000)],
            vec![addr(0x2000), addr(0x3000)],
        ];
        let mut iter = CompositeSearchAddressIterator::new(sources, true);
        assert_eq!(iter.next_address(), Some(addr(0x1000)));
        assert_eq!(iter.next_address(), Some(addr(0x2000)));
        assert_eq!(iter.next_address(), Some(addr(0x3000)));
        assert_eq!(iter.next_address(), None);
    }

    #[test]
    fn test_composite_iterator_backward() {
        let sources = vec![vec![addr(0x1000), addr(0x3000), addr(0x2000)]];
        let mut iter = CompositeSearchAddressIterator::new(sources, false);
        let addrs: Vec<_> = std::iter::from_fn(|| iter.next_address()).collect();
        assert_eq!(addrs, vec![addr(0x3000), addr(0x2000), addr(0x1000)]);
    }
}
