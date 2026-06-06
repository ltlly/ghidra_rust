//! Wrapping iterator adapters for trace data, code units, functions, and instructions.
//!
//! Ported from Ghidra's `ghidra.trace.util`:
//! - `WrappingDataIterator`
//! - `WrappingCodeUnitIterator`
//! - `WrappingFunctionIterator`
//! - `WrappingInstructionIterator`
//!
//! These adapters wrap a raw address-based iterator and resolve each
//! address against a snapshot of the trace listing to produce
//! high-level `TraceCodeUnit` / `TraceData` / `TraceInstruction` /
//! function entries.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

/// An entry representing a resolved code unit from a wrapping iterator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResolvedListingEntry {
    /// A data unit at the given address.
    Data {
        /// The address.
        address: u64,
        /// Address space name.
        space: String,
        /// The snap at which this data is valid.
        snap: i64,
        /// Length in bytes.
        length: usize,
        /// The data type name (if known).
        data_type: Option<String>,
        /// Whether the data is defined.
        defined: bool,
    },
    /// An instruction at the given address.
    Instruction {
        /// The address.
        address: u64,
        /// Address space name.
        space: String,
        /// The snap at which this instruction is valid.
        snap: i64,
        /// Length in bytes.
        length: usize,
        /// The mnemonic (e.g., "MOV", "ADD").
        mnemonic: String,
    },
    /// A function entry.
    Function {
        /// The entry point address.
        entry_point: u64,
        /// Address space name.
        space: String,
        /// The snap at which this function is valid.
        snap: i64,
        /// Function name.
        name: String,
        /// The body address set (start, end) pairs.
        body_ranges: Vec<(u64, u64)>,
    },
}

impl ResolvedListingEntry {
    /// Get the address of this entry.
    pub fn address(&self) -> u64 {
        match self {
            ResolvedListingEntry::Data { address, .. } => *address,
            ResolvedListingEntry::Instruction { address, .. } => *address,
            ResolvedListingEntry::Function { entry_point, .. } => *entry_point,
        }
    }

    /// Get the snap of this entry.
    pub fn snap(&self) -> i64 {
        match self {
            ResolvedListingEntry::Data { snap, .. } => *snap,
            ResolvedListingEntry::Instruction { snap, .. } => *snap,
            ResolvedListingEntry::Function { snap, .. } => *snap,
        }
    }

    /// Whether this entry is an instruction.
    pub fn is_instruction(&self) -> bool {
        matches!(self, ResolvedListingEntry::Instruction { .. })
    }

    /// Whether this entry is data.
    pub fn is_data(&self) -> bool {
        matches!(self, ResolvedListingEntry::Data { .. })
    }

    /// Whether this entry is a function.
    pub fn is_function(&self) -> bool {
        matches!(self, ResolvedListingEntry::Function { .. })
    }
}

/// Trait for listing queries that resolve addresses to listing entries.
///
/// This represents the listing snapshot that wrapping iterators query
/// against.
pub trait ListingQuery {
    /// Get the code unit at the given address and snap.
    fn get_code_unit(&self, address: u64, snap: i64) -> Option<ResolvedListingEntry>;

    /// Get the next defined address after the given one at the specified snap.
    fn get_next_defined_address(&self, after: u64, snap: i64) -> Option<u64>;

    /// Get the minimum defined address at the given snap.
    fn get_min_address(&self, snap: i64) -> Option<u64>;

    /// Get the maximum defined address at the given snap.
    fn get_max_address(&self, snap: i64) -> Option<u64>;
}

/// Wraps a data iterator to resolve addresses to data entries.
///
/// Ported from Ghidra's `WrappingDataIterator`.
pub struct WrappingDataIterator<I> {
    inner: I,
    listing: Box<dyn ListingQuery>,
    snap: i64,
    space: String,
    buffer: VecDeque<ResolvedListingEntry>,
}

impl<I: Iterator<Item = u64>> WrappingDataIterator<I> {
    /// Create a new wrapping data iterator.
    pub fn new(inner: I, listing: Box<dyn ListingQuery>, snap: i64, space: String) -> Self {
        Self {
            inner,
            listing,
            snap,
            space,
            buffer: VecDeque::new(),
        }
    }

    /// Advance the inner iterator and resolve the next data entry.
    fn advance_inner(&mut self) -> Option<ResolvedListingEntry> {
        for addr in self.inner.by_ref() {
            if let Some(entry) = self.listing.get_code_unit(addr, self.snap) {
                if entry.is_data() {
                    return Some(entry);
                }
            }
            // If no code unit found at this address, return an undefined data entry
            return Some(ResolvedListingEntry::Data {
                address: addr,
                space: self.space.clone(),
                snap: self.snap,
                length: 1,
                data_type: None,
                defined: false,
            });
        }
        None
    }
}

impl<I: Iterator<Item = u64>> Iterator for WrappingDataIterator<I> {
    type Item = ResolvedListingEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(entry) = self.buffer.pop_front() {
            return Some(entry);
        }
        self.advance_inner()
    }
}

/// Wraps a code unit iterator to resolve addresses to code unit entries.
///
/// Ported from Ghidra's `WrappingCodeUnitIterator`.
pub struct WrappingCodeUnitIterator<I> {
    inner: I,
    listing: Box<dyn ListingQuery>,
    snap: i64,
    #[allow(dead_code)]
    space: String,
}

impl<I: Iterator<Item = u64>> WrappingCodeUnitIterator<I> {
    /// Create a new wrapping code unit iterator.
    pub fn new(inner: I, listing: Box<dyn ListingQuery>, snap: i64, space: String) -> Self {
        Self {
            inner,
            listing,
            snap,
            space,
        }
    }
}

impl<I: Iterator<Item = u64>> Iterator for WrappingCodeUnitIterator<I> {
    type Item = ResolvedListingEntry;

    fn next(&mut self) -> Option<Self::Item> {
        for addr in self.inner.by_ref() {
            if let Some(entry) = self.listing.get_code_unit(addr, self.snap) {
                return Some(entry);
            }
        }
        None
    }
}

/// Wraps a function iterator to resolve addresses to function entries.
///
/// Ported from Ghidra's `WrappingFunctionIterator`.
pub struct WrappingFunctionIterator<I> {
    inner: I,
    listing: Box<dyn ListingQuery>,
    snap: i64,
    #[allow(dead_code)]
    space: String,
}

impl<I: Iterator<Item = u64>> WrappingFunctionIterator<I> {
    /// Create a new wrapping function iterator.
    pub fn new(inner: I, listing: Box<dyn ListingQuery>, snap: i64, space: String) -> Self {
        Self {
            inner,
            listing,
            snap,
            space,
        }
    }
}

impl<I: Iterator<Item = u64>> Iterator for WrappingFunctionIterator<I> {
    type Item = ResolvedListingEntry;

    fn next(&mut self) -> Option<Self::Item> {
        for addr in self.inner.by_ref() {
            if let Some(entry) = self.listing.get_code_unit(addr, self.snap) {
                if entry.is_function() {
                    return Some(entry);
                }
            }
        }
        None
    }
}

/// Wraps an instruction iterator to resolve addresses to instruction entries.
///
/// Ported from Ghidra's `WrappingInstructionIterator`.
pub struct WrappingInstructionIterator<I> {
    inner: I,
    listing: Box<dyn ListingQuery>,
    snap: i64,
    #[allow(dead_code)]
    space: String,
}

impl<I: Iterator<Item = u64>> WrappingInstructionIterator<I> {
    /// Create a new wrapping instruction iterator.
    pub fn new(inner: I, listing: Box<dyn ListingQuery>, snap: i64, space: String) -> Self {
        Self {
            inner,
            listing,
            snap,
            space,
        }
    }
}

impl<I: Iterator<Item = u64>> Iterator for WrappingInstructionIterator<I> {
    type Item = ResolvedListingEntry;

    fn next(&mut self) -> Option<Self::Item> {
        for addr in self.inner.by_ref() {
            if let Some(entry) = self.listing.get_code_unit(addr, self.snap) {
                if entry.is_instruction() {
                    return Some(entry);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockListingQuery {
        units: Vec<(u64, i64, ResolvedListingEntry)>,
    }

    impl MockListingQuery {
        fn new() -> Self {
            Self { units: Vec::new() }
        }

        fn add_data(&mut self, address: u64, snap: i64, length: usize) {
            self.units.push((
                address,
                snap,
                ResolvedListingEntry::Data {
                    address,
                    space: "ram".into(),
                    snap,
                    length,
                    data_type: Some("dword".into()),
                    defined: true,
                },
            ));
        }

        fn add_instruction(&mut self, address: u64, snap: i64, mnemonic: &str) {
            self.units.push((
                address,
                snap,
                ResolvedListingEntry::Instruction {
                    address,
                    space: "ram".into(),
                    snap,
                    length: 4,
                    mnemonic: mnemonic.into(),
                },
            ));
        }

        fn add_function(&mut self, entry_point: u64, snap: i64, name: &str) {
            self.units.push((
                entry_point,
                snap,
                ResolvedListingEntry::Function {
                    entry_point,
                    space: "ram".into(),
                    snap,
                    name: name.into(),
                    body_ranges: vec![(entry_point, entry_point + 0x40)],
                },
            ));
        }
    }

    impl ListingQuery for MockListingQuery {
        fn get_code_unit(&self, address: u64, snap: i64) -> Option<ResolvedListingEntry> {
            self.units
                .iter()
                .find(|(a, s, _)| *a == address && *s == snap)
                .map(|(_, _, entry)| entry.clone())
        }

        fn get_next_defined_address(&self, after: u64, snap: i64) -> Option<u64> {
            self.units
                .iter()
                .filter(|(a, s, _)| *a > after && *s == snap)
                .map(|(a, _, _)| *a)
                .min()
        }

        fn get_min_address(&self, snap: i64) -> Option<u64> {
            self.units
                .iter()
                .filter(|(_, s, _)| *s == snap)
                .map(|(a, _, _)| *a)
                .min()
        }

        fn get_max_address(&self, snap: i64) -> Option<u64> {
            self.units
                .iter()
                .filter(|(_, s, _)| *s == snap)
                .map(|(a, _, _)| *a)
                .max()
        }
    }

    #[test]
    fn test_wrapping_data_iterator() {
        let mut listing = MockListingQuery::new();
        listing.add_data(0x1000, 0, 4);
        listing.add_data(0x1004, 0, 4);

        let addrs = vec![0x1000, 0x1004, 0x1008];
        let mut iter = WrappingDataIterator::new(
            addrs.into_iter(),
            Box::new(listing),
            0,
            "ram".into(),
        );

        let entry = iter.next().unwrap();
        assert!(entry.is_data());
        assert_eq!(entry.address(), 0x1000);

        let entry = iter.next().unwrap();
        assert!(entry.is_data());
        assert_eq!(entry.address(), 0x1004);

        // 0x1008 not in listing, should return undefined data
        let entry = iter.next().unwrap();
        assert!(entry.is_data());

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_wrapping_instruction_iterator() {
        let mut listing = MockListingQuery::new();
        listing.add_instruction(0x2000, 0, "MOV");
        listing.add_data(0x2004, 0, 4);
        listing.add_instruction(0x2008, 0, "ADD");

        let addrs = vec![0x2000, 0x2004, 0x2008];
        let mut iter = WrappingInstructionIterator::new(
            addrs.into_iter(),
            Box::new(listing),
            0,
            "ram".into(),
        );

        // Should skip the data entry
        let entry = iter.next().unwrap();
        assert!(entry.is_instruction());
        assert_eq!(entry.address(), 0x2000);

        let entry = iter.next().unwrap();
        assert!(entry.is_instruction());
        assert_eq!(entry.address(), 0x2008);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_wrapping_code_unit_iterator() {
        let mut listing = MockListingQuery::new();
        listing.add_instruction(0x3000, 0, "NOP");
        listing.add_data(0x3004, 0, 2);
        listing.add_function(0x3008, 0, "main");

        let addrs = vec![0x3000, 0x3004, 0x3008];
        let mut iter = WrappingCodeUnitIterator::new(
            addrs.into_iter(),
            Box::new(listing),
            0,
            "ram".into(),
        );

        let entry = iter.next().unwrap();
        assert!(entry.is_instruction());

        let entry = iter.next().unwrap();
        assert!(entry.is_data());

        let entry = iter.next().unwrap();
        assert!(entry.is_function());

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_wrapping_function_iterator() {
        let mut listing = MockListingQuery::new();
        listing.add_instruction(0x4000, 0, "PUSH");
        listing.add_function(0x4004, 0, "helper");
        listing.add_instruction(0x4008, 0, "POP");

        let addrs = vec![0x4000, 0x4004, 0x4008];
        let mut iter = WrappingFunctionIterator::new(
            addrs.into_iter(),
            Box::new(listing),
            0,
            "ram".into(),
        );

        // Should skip instructions
        let entry = iter.next().unwrap();
        assert!(entry.is_function());
        assert_eq!(entry.address(), 0x4004);

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_resolved_listing_entry_properties() {
        let data = ResolvedListingEntry::Data {
            address: 0x1000,
            space: "ram".into(),
            snap: 0,
            length: 4,
            data_type: Some("dword".into()),
            defined: true,
        };
        assert_eq!(data.address(), 0x1000);
        assert_eq!(data.snap(), 0);
        assert!(data.is_data());
        assert!(!data.is_instruction());
        assert!(!data.is_function());

        let instr = ResolvedListingEntry::Instruction {
            address: 0x2000,
            space: "ram".into(),
            snap: 1,
            length: 4,
            mnemonic: "MOV".into(),
        };
        assert!(instr.is_instruction());

        let func = ResolvedListingEntry::Function {
            entry_point: 0x3000,
            space: "ram".into(),
            snap: 0,
            name: "main".into(),
            body_ranges: vec![(0x3000, 0x3100)],
        };
        assert!(func.is_function());
    }

    #[test]
    fn test_empty_iterator() {
        let listing = MockListingQuery::new();
        let addrs: Vec<u64> = vec![];
        let mut iter = WrappingDataIterator::new(
            addrs.into_iter(),
            Box::new(listing),
            0,
            "ram".into(),
        );
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_listing_query_mock() {
        let mut listing = MockListingQuery::new();
        listing.add_data(0x1000, 0, 4);
        listing.add_instruction(0x2000, 0, "MOV");
        listing.add_data(0x3000, 0, 8);

        assert_eq!(listing.get_min_address(0), Some(0x1000));
        assert_eq!(listing.get_max_address(0), Some(0x3000));
        assert_eq!(listing.get_next_defined_address(0x1000, 0), Some(0x2000));
        assert_eq!(listing.get_next_defined_address(0x3000, 0), None);
    }
}
