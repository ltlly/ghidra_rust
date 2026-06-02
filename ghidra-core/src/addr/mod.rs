//! Address types for Ghidra Rust.
//!
//! Models Ghidra's address space + offset model. An [`Address`] represents
//! a location in a program, which may span multiple address spaces (RAM, ROM,
//! register space, etc.).

use serde::{Deserialize, Serialize};
use std::fmt;

/// An address space identifier (e.g., "ram", "register", "const").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AddressSpace {
    /// Unique name of the address space.
    pub name: String,
    /// Size of addresses in this space in bytes (e.g., 4 for 32-bit, 8 for 64-bit).
    pub pointer_size: usize,
    /// Whether this space represents a big-endian layout.
    pub big_endian: bool,
}

impl AddressSpace {
    /// Create a new address space with the given name and properties.
    pub fn new(name: impl Into<String>, pointer_size: usize, big_endian: bool) -> Self {
        Self {
            name: name.into(),
            pointer_size,
            big_endian,
        }
    }

    /// The default "ram" address space.
    pub fn ram() -> Self {
        Self::new("ram", 8, false)
    }

    /// Returns the address space name.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns the pointer size for this space in bytes.
    pub fn get_pointer_size(&self) -> usize {
        self.pointer_size
    }

    /// Returns true if this space is big-endian.
    pub fn is_big_endian(&self) -> bool {
        self.big_endian
    }
}

impl fmt::Display for AddressSpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// A memory address consisting of an address space and an offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Address {
    /// The raw offset within the address space.
    pub offset: u64,
}

impl Address {
    /// An invalid/null address (offset = u64::MAX).
    pub const NULL: Address = Address { offset: u64::MAX };

    /// Create a new address from an offset.
    pub const fn new(offset: u64) -> Self {
        Self { offset }
    }

    /// Returns true if this is the NULL address.
    pub fn is_null(&self) -> bool {
        self.offset == u64::MAX
    }

    /// Returns true if this is a stack address.
    pub fn is_stack_address(&self) -> bool {
        false
    }

    /// Returns true if this is an external (imported) address.
    pub fn is_external_address(&self) -> bool {
        false
    }

    /// Returns true if this is a register address.
    pub fn is_register_address(&self) -> bool {
        false
    }

    /// Returns true if this is a constant address.
    pub fn is_constant_address(&self) -> bool {
        false
    }

    /// Returns true if this is a memory address.
    pub fn is_memory_address(&self) -> bool {
        !self.is_null()
    }

    /// Returns true if this is the NO_ADDRESS (null) address.
    pub fn is_no_address(&self) -> bool {
        self.offset == u64::MAX
    }

    /// Returns true if this is a variable (stack/register) address.
    pub fn is_variable_address(&self) -> bool {
        false
    }

    /// Add an offset to this address.
    pub fn add(&self, delta: u64) -> Self {
        Self {
            offset: self.offset.wrapping_add(delta),
        }
    }

    /// Subtract an offset from this address.
    pub fn sub(&self, delta: u64) -> Self {
        Self {
            offset: self.offset.wrapping_sub(delta),
        }
    }

    /// Compute the difference between two addresses in the same space.
    pub fn subtract(&self, other: &Address) -> i64 {
        (self.offset as i64).wrapping_sub(other.offset as i64)
    }

    /// Return the next address after this one.
    pub fn next(&self) -> Self {
        self.add(1)
    }

    /// Return the previous address before this one.
    pub fn prev(&self) -> Self {
        self.sub(1)
    }

    /// Returns the unsigned offset of this address.
    pub fn get_offset(&self) -> u64 {
        self.offset
    }

    /// Returns the word offset using the given addressable unit size.
    pub fn get_addressable_word_offset(&self, unit_size: u64) -> u64 {
        if unit_size == 0 {
            self.offset
        } else {
            self.offset / unit_size
        }
    }

    /// Returns true if `other` is the next address after this one.
    pub fn is_successor(&self, other: &Address) -> bool {
        self.offset.wrapping_add(1) == other.offset
    }

    /// Returns true if `other` is the previous address before this one.
    pub fn is_predecessor(&self, other: &Address) -> bool {
        self.offset.wrapping_sub(1) == other.offset
    }
}

impl std::ops::Add<u64> for Address {
    type Output = Address;

    fn add(self, rhs: u64) -> Self::Output {
        Address::new(self.offset.wrapping_add(rhs))
    }
}

impl std::ops::Sub<u64> for Address {
    type Output = Address;

    fn sub(self, rhs: u64) -> Self::Output {
        Address::new(self.offset.wrapping_sub(rhs))
    }
}

impl std::ops::Sub<Address> for Address {
    type Output = i64;

    fn sub(self, rhs: Address) -> Self::Output {
        self.subtract(&rhs)
    }
}

impl std::ops::AddAssign<u64> for Address {
    fn add_assign(&mut self, rhs: u64) {
        self.offset = self.offset.wrapping_add(rhs);
    }
}

impl std::ops::SubAssign<u64> for Address {
    fn sub_assign(&mut self, rhs: u64) {
        self.offset = self.offset.wrapping_sub(rhs);
    }
}

impl std::str::FromStr for Address {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let trimmed = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        u64::from_str_radix(trimmed, 16).map(Address::new)
    }
}

impl From<usize> for Address {
    fn from(offset: usize) -> Self {
        Address::new(offset as u64)
    }
}

impl From<Address> for usize {
    fn from(addr: Address) -> Self {
        addr.offset as usize
    }
}

impl From<i64> for Address {
    fn from(offset: i64) -> Self {
        Address::new(offset as u64)
    }
}

impl From<Address> for i64 {
    fn from(addr: Address) -> Self {
        addr.offset as i64
    }
}

impl PartialEq<u64> for Address {
    fn eq(&self, other: &u64) -> bool {
        self.offset == *other
    }
}

impl PartialEq<Address> for u64 {
    fn eq(&self, other: &Address) -> bool {
        *self == other.offset
    }
}

impl PartialOrd<u64> for Address {
    fn partial_cmp(&self, other: &u64) -> Option<std::cmp::Ordering> {
        self.offset.partial_cmp(other)
    }
}

impl PartialOrd<Address> for u64 {
    fn partial_cmp(&self, other: &Address) -> Option<std::cmp::Ordering> {
        self.partial_cmp(&other.offset)
    }
}

impl From<std::ops::RangeInclusive<u64>> for AddressRange {
    fn from(range: std::ops::RangeInclusive<u64>) -> Self {
        AddressRange::new(Address::new(*range.start()), Address::new(*range.end()))
    }
}

impl IntoIterator for AddressRange {
    type Item = Address;
    type IntoIter = AddressRangeIterator;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a AddressRange {
    type Item = Address;
    type IntoIter = AddressRangeIterator;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl ExactSizeIterator for AddressRangeIterator {
    fn len(&self) -> usize {
        if self.current > self.end {
            0
        } else {
            (self.end - self.current + 1) as usize
        }
    }
}

impl std::iter::FusedIterator for AddressRangeIterator {}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", self.offset)
    }
}

impl fmt::LowerHex for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", self.offset)
    }
}

impl Default for Address {
    fn default() -> Self {
        Address::NULL
    }
}

impl From<u64> for Address {
    fn from(offset: u64) -> Self {
        Self { offset }
    }
}

impl From<Address> for u64 {
    fn from(addr: Address) -> Self {
        addr.offset
    }
}

/// A contiguous range of addresses in the same address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AddressRange {
    /// The start (inclusive) address.
    pub start: Address,
    /// The end (inclusive) address.
    pub end: Address,
}

impl AddressRange {
    /// Create a new address range.
    pub fn new(start: Address, end: Address) -> Self {
        Self { start, end }
    }

    /// The size (number of addresses) in the range.
    pub fn len(&self) -> u64 {
        if self.end.offset >= self.start.offset {
            self.end.offset - self.start.offset + 1
        } else {
            0
        }
    }

    /// Returns true if the range is empty.
    pub fn is_empty(&self) -> bool {
        self.end.offset < self.start.offset
    }

    /// Returns the minimum (inclusive) address of the range.
    pub fn get_min_address(&self) -> Address {
        self.start
    }

    /// Returns the maximum (inclusive) address of the range.
    pub fn get_max_address(&self) -> Address {
        self.end
    }

    /// Returns true if the range consists of exactly one address.
    pub fn is_singleton(&self) -> bool {
        !self.is_empty() && self.start == self.end
    }

    /// Check if an address is within this range.
    pub fn contains(&self, addr: &Address) -> bool {
        addr.offset >= self.start.offset && addr.offset <= self.end.offset
    }

    /// Returns true if this range fully contains another range.
    pub fn contains_range(&self, other: &AddressRange) -> bool {
        !other.is_empty()
            && !self.is_empty()
            && self.start.offset <= other.start.offset
            && self.end.offset >= other.end.offset
    }

    /// Returns true if this range overlaps another range.
    pub fn intersects(&self, other: &AddressRange) -> bool {
        !self.is_empty()
            && !other.is_empty()
            && self.start.offset <= other.end.offset
            && other.start.offset <= self.end.offset
    }

    /// Returns the overlapping portion of two ranges, if any.
    pub fn intersection(&self, other: &AddressRange) -> Option<AddressRange> {
        if !self.intersects(other) {
            return None;
        }
        Some(AddressRange::new(
            Address::new(self.start.offset.max(other.start.offset)),
            Address::new(self.end.offset.min(other.end.offset)),
        ))
    }

    /// Iterate over all addresses in the range.
    pub fn iter(&self) -> AddressRangeIterator {
        AddressRangeIterator {
            current: self.start.offset,
            end: self.end.offset,
        }
    }
}

impl fmt::Display for AddressRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} - {}", self.start, self.end)
    }
}

/// Iterator over addresses in an [`AddressRange`].
pub struct AddressRangeIterator {
    current: u64,
    end: u64,
}

impl Iterator for AddressRangeIterator {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current > self.end {
            None
        } else {
            let addr = Address::new(self.current);
            self.current += 1;
            Some(addr)
        }
    }
}
use std::collections::HashMap;

/// Factory for creating addresses in different spaces.
#[derive(Debug, Clone, Default)]
pub struct AddressFactory {
    spaces: HashMap<String, AddressSpace>,
}

impl AddressFactory {
    pub fn new() -> Self {
        let mut factory = Self::default();
        factory.add_space(AddressSpace::ram());
        factory
    }

    pub fn add_space(&mut self, space: AddressSpace) {
        self.spaces.insert(space.name.clone(), space);
    }

    pub fn get_space(&self, name: &str) -> Option<&AddressSpace> {
        self.spaces.get(name)
    }

    pub fn default_space(&self) -> &AddressSpace {
        self.spaces.get("ram").unwrap_or_else(|| {
            // Should not happen if initialized with new()
            panic!("No default address space");
        })
    }

    pub fn new_address(&self, offset: u64) -> Address {
        Address::new(offset)
    }
}
