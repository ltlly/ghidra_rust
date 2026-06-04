//! Address types for Ghidra Rust.
//!
//! Models Ghidra's address space + offset model. An [`Address`] represents
//! a location in a program, which may span multiple address spaces (RAM, ROM,
//! register space, etc.).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;

/// Address space type — mirrors Ghidra's `AddressSpace.TYPE_*` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum AddrSpaceType {
    Constant = 0,
    Ram = 1,
    Unique = 3,
    Register = 4,
    Stack = 5,
    Join = 6,
    Other = 7,
    Symbol = 9,
    External = 10,
    Variable = 11,
}

impl AddrSpaceType {
    /// True for spaces that represent real loaded memory (RAM + code).
    pub fn is_memory(&self) -> bool {
        matches!(self, AddrSpaceType::Ram)
    }

    /// True for spaces that use signed offsets.
    pub fn has_signed_offset(&self) -> bool {
        matches!(self, AddrSpaceType::Constant | AddrSpaceType::Stack)
    }
}

/// An address space identifier (e.g., "ram", "register", "const").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AddressSpace {
    /// Unique name of the address space.
    pub name: String,
    /// Size of addresses in this space in bytes (e.g., 4 for 32-bit, 8 for 64-bit).
    pub pointer_size: usize,
    /// Whether this space represents a big-endian layout.
    pub big_endian: bool,
    /// The type of this address space.
    pub space_type: AddrSpaceType,
    /// Unique numeric ID for this space (used for encoding/decoding).
    pub space_id: u32,
    /// Whether this is an overlay address space.
    pub is_overlay: bool,
}

impl AddressSpace {
    /// Create a new address space with the given name, properties, type, and ID.
    pub fn new(
        name: impl Into<String>,
        pointer_size: usize,
        big_endian: bool,
        space_type: AddrSpaceType,
        space_id: u32,
    ) -> Self {
        Self {
            name: name.into(),
            pointer_size,
            big_endian,
            space_type,
            space_id,
            is_overlay: false,
        }
    }

    /// Create an overlay address space backed by the given underlying space.
    pub fn new_overlay(name: impl Into<String>, base: &AddressSpace) -> Self {
        let mut s = Self::new(name, base.pointer_size, base.big_endian, base.space_type, 0);
        s.is_overlay = true;
        s
    }

    /// The default "ram" address space.
    pub fn ram() -> Self {
        Self::new("ram", 8, false, AddrSpaceType::Ram, 1)
    }

    /// The built-in "register" address space.
    pub fn register() -> Self {
        Self::new("register", 8, false, AddrSpaceType::Register, 2)
    }

    /// The built-in "const" (constant) address space.
    pub fn constant() -> Self {
        Self::new("const", 8, false, AddrSpaceType::Constant, 3)
    }

    /// The built-in "unique" address space.
    pub fn unique() -> Self {
        Self::new("unique", 8, false, AddrSpaceType::Unique, 4)
    }

    /// The built-in "stack" address space.
    pub fn stack() -> Self {
        Self::new("stack", 8, false, AddrSpaceType::Stack, 5)
    }

    /// The built-in "external" address space.
    pub fn external() -> Self {
        Self::new("external", 8, false, AddrSpaceType::External, 6)
    }

    /// The built-in "join" address space.
    pub fn join() -> Self {
        Self::new("join", 8, false, AddrSpaceType::Join, 7)
    }

    // -- Accessors --

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

    /// Returns the space type.
    pub fn get_type(&self) -> AddrSpaceType {
        self.space_type
    }

    /// Returns the unique space ID.
    pub fn get_space_id(&self) -> u32 {
        self.space_id
    }

    // -- Type query methods (mirror Java AddressSpace) --

    /// True for RAM and overlay-on-RAM spaces.
    pub fn is_memory_space(&self) -> bool {
        self.space_type.is_memory() || (self.is_overlay && self.space_type.is_memory())
    }

    pub fn is_register_space(&self) -> bool {
        self.space_type == AddrSpaceType::Register
    }

    pub fn is_constant_space(&self) -> bool {
        self.space_type == AddrSpaceType::Constant
    }

    pub fn is_unique_space(&self) -> bool {
        self.space_type == AddrSpaceType::Unique
    }

    pub fn is_stack_space(&self) -> bool {
        self.space_type == AddrSpaceType::Stack
    }

    pub fn is_external_space(&self) -> bool {
        self.space_type == AddrSpaceType::External
    }

    pub fn is_overlay_space(&self) -> bool {
        self.is_overlay
    }

    pub fn is_variable_space(&self) -> bool {
        self.space_type == AddrSpaceType::Variable
    }

    /// True for spaces that use signed offsets.
    pub fn has_signed_offset(&self) -> bool {
        self.space_type.has_signed_offset()
    }

    /// Returns true if the name is a valid address space name (no colon or control chars).
    pub fn is_valid_name(name: &str) -> bool {
        !name.is_empty() && !name.chars().any(|c| c == ':' || c <= '\x20')
    }

    /// Maximum address offset for this space (based on pointer size).
    pub fn get_max_address(&self) -> Address {
        match self.pointer_size {
            1 => Address::new(0xFF),
            2 => Address::new(0xFFFF),
            4 => Address::new(0xFFFF_FFFF),
            _ => Address::new(u64::MAX),
        }
    }

    /// Minimum address offset for this space (0, unless signed).
    pub fn get_min_address(&self) -> Address {
        Address::new(0)
    }

    /// Parse an address string in this space (hex with optional "0x" prefix).
    pub fn get_address(&self, addr_str: &str) -> Option<Address> {
        let s = addr_str.trim();
        let s = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")).unwrap_or(s);
        u64::from_str_radix(s, 16).ok().map(Address::new)
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
/// Factory for creating addresses in different spaces.
///
/// Manages all known address spaces and provides lookup by name, ID, and type.
#[derive(Debug, Clone)]
pub struct AddressFactory {
    /// All registered spaces, keyed by name.
    by_name: HashMap<String, AddressSpace>,
    /// All registered spaces, keyed by space_id.
    by_id: HashMap<u32, AddressSpace>,
    /// Name of the default space.
    default_name: String,
}

impl Default for AddressFactory {
    fn default() -> Self {
        Self {
            by_name: HashMap::new(),
            by_id: HashMap::new(),
            default_name: String::new(),
        }
    }
}

impl AddressFactory {
    /// Create a factory with the default "ram" space.
    pub fn new() -> Self {
        Self::with_spaces(vec![AddressSpace::ram()], "ram")
    }

    /// Create a factory from a list of spaces, specifying the default by name.
    pub fn with_spaces(spaces: Vec<AddressSpace>, default: &str) -> Self {
        let mut factory = Self::default();
        factory.default_name = default.to_string();
        for space in spaces {
            factory.add_space(space);
        }
        factory
    }

    /// Register an additional address space.
    pub fn add_space(&mut self, space: AddressSpace) {
        self.by_id.insert(space.space_id, space.clone());
        self.by_name.insert(space.name.clone(), space);
    }

    // -- Lookup by name / ID --

    /// Look up a space by name.
    pub fn get_space(&self, name: &str) -> Option<&AddressSpace> {
        self.by_name.get(name)
    }

    /// Look up a space by numeric ID.
    pub fn get_space_by_id(&self, id: u32) -> Option<&AddressSpace> {
        self.by_id.get(&id)
    }

    /// The default address space.
    pub fn default_space(&self) -> &AddressSpace {
        self.by_name
            .get(&self.default_name)
            .or_else(|| self.by_name.values().next())
            .expect("AddressFactory has no spaces")
    }

    /// All registered spaces (unspecified order).
    pub fn get_address_spaces(&self) -> Vec<&AddressSpace> {
        self.by_name.values().collect()
    }

    /// Number of registered spaces.
    pub fn num_address_spaces(&self) -> usize {
        self.by_name.len()
    }

    // -- Special space accessors --

    /// The "constant" space, if registered.
    pub fn get_constant_space(&self) -> Option<&AddressSpace> {
        self.by_name.values().find(|s| s.space_type == AddrSpaceType::Constant)
    }

    /// The "unique" space, if registered.
    pub fn get_unique_space(&self) -> Option<&AddressSpace> {
        self.by_name.values().find(|s| s.space_type == AddrSpaceType::Unique)
    }

    /// The "register" space, if registered.
    pub fn get_register_space(&self) -> Option<&AddressSpace> {
        self.by_name.values().find(|s| s.space_type == AddrSpaceType::Register)
    }

    /// The "stack" space, if registered.
    pub fn get_stack_space(&self) -> Option<&AddressSpace> {
        self.by_name.values().find(|s| s.space_type == AddrSpaceType::Stack)
    }

    /// The "external" space, if registered.
    pub fn get_external_space(&self) -> Option<&AddressSpace> {
        self.by_name.values().find(|s| s.space_type == AddrSpaceType::External)
    }

    // -- Address creation --

    /// Create an address in the default space.
    pub fn new_address(&self, offset: u64) -> Address {
        Address::new(offset)
    }

    /// Create an address in the space with the given ID.
    pub fn get_address(&self, space_id: u32, offset: u64) -> Address {
        // Currently Address is space-agnostic (offset only); validate space exists.
        debug_assert!(self.by_id.contains_key(&space_id), "Unknown space ID {space_id}");
        Address::new(offset)
    }

    /// Parse an address string. Tries the default space first, then all others.
    pub fn get_address_from_string(&self, addr_str: &str) -> Option<Address> {
        if let Some(addr) = self.default_space().get_address(addr_str) {
            return Some(addr);
        }
        for space in self.by_name.values() {
            if space.name == self.default_name {
                continue;
            }
            if let Some(addr) = space.get_address(addr_str) {
                return Some(addr);
            }
        }
        None
    }

    /// All physical (memory) spaces.
    pub fn get_physical_spaces(&self) -> Vec<&AddressSpace> {
        self.by_name.values().filter(|s| s.is_memory_space()).collect()
    }

    /// True if there is more than one memory address space.
    pub fn has_multiple_memory_spaces(&self) -> bool {
        self.by_name.values().filter(|s| s.is_memory_space()).count() > 1
    }

    /// Build an AddressSet spanning start..end (same space only).
    pub fn get_address_set(&self, start: Address, end: Address) -> AddressSet {
        let mut set = AddressSet::new();
        set.add_range(start, end);
        set
    }

    /// A constant address in the "const" space.
    pub fn get_constant_address(&self, offset: u64) -> Address {
        Address::new(offset)
    }
}

// ---------------------------------------------------------------------------
// AddressSet — set of non-contiguous address ranges
// ---------------------------------------------------------------------------

/// A mutable set of addresses, stored as sorted, non-overlapping ranges.
///
/// This is the Rust equivalent of Ghidra's `AddressSet` (mutable) /
/// `AddressSetView` (read-only). All ranges must use the same address space
/// (enforced by using plain `Address` offsets).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddressSet {
    /// Sorted map: start offset -> end offset (both inclusive).
    ranges: BTreeMap<u64, u64>,
}

impl AddressSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a set containing a single range.
    pub fn from_range(start: Address, end: Address) -> Self {
        let mut s = Self::new();
        s.add_range(start, end);
        s
    }

    // -- Size queries --

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    pub fn num_address_ranges(&self) -> usize {
        self.ranges.len()
    }

    pub fn num_addresses(&self) -> u64 {
        self.ranges.values().zip(self.ranges.keys()).map(|(&e, &s)| e - s + 1).sum()
    }

    // -- Boundary accessors --

    pub fn get_min_address(&self) -> Option<Address> {
        self.ranges.keys().next().map(|&o| Address::new(o))
    }

    pub fn get_max_address(&self) -> Option<Address> {
        self.ranges.values().next_back().map(|&o| Address::new(o))
    }

    pub fn get_first_range(&self) -> Option<AddressRange> {
        self.ranges.iter().next().map(|(&s, &e)| AddressRange::new(Address::new(s), Address::new(e)))
    }

    pub fn get_last_range(&self) -> Option<AddressRange> {
        self.ranges.iter().next_back().map(|(&s, &e)| AddressRange::new(Address::new(s), Address::new(e)))
    }

    /// Returns the range that contains the given address, if any.
    pub fn get_range_containing(&self, addr: Address) -> Option<AddressRange> {
        // Find the last range whose start <= addr.offset
        self.ranges
            .range(..=addr.offset)
            .next_back()
            .filter(|(_, &end)| addr.offset <= end)
            .map(|(&s, &e)| AddressRange::new(Address::new(s), Address::new(e)))
    }

    // -- Containment --

    pub fn contains(&self, addr: &Address) -> bool {
        self.get_range_containing(*addr).is_some()
    }

    /// True if the entire [start, end] range is in the set.
    pub fn contains_range(&self, start: Address, end: Address) -> bool {
        self.get_range_containing(start)
            .map_or(false, |r| r.end.offset >= end.offset)
    }

    /// True if `other` is a subset of `self`.
    pub fn contains_set(&self, other: &AddressSet) -> bool {
        for (&s, &e) in &other.ranges {
            if !self.contains_range(Address::new(s), Address::new(e)) {
                return false;
            }
        }
        true
    }

    // -- Mutation --

    /// Add a single address.
    pub fn add(&mut self, addr: Address) {
        self.add_range(addr, addr);
    }

    /// Add an inclusive range [start, end].
    pub fn add_range(&mut self, start: Address, end: Address) {
        if start.offset > end.offset {
            return;
        }
        let (mut lo, mut hi) = (start.offset, end.offset);
        // Merge with any overlapping/adjacent existing ranges.
        let overlaps: Vec<u64> = self
            .ranges
            .range(..=hi + 1)
            .rev()
            .take_while(|(&s, _)| s >= lo.saturating_sub(1))
            .map(|(&s, _)| s)
            .collect();
        for k in overlaps {
            let e = self.ranges.remove(&k).unwrap();
            lo = lo.min(k);
            hi = hi.max(e);
        }
        self.ranges.insert(lo, hi);
    }

    /// Add all ranges from another set.
    pub fn add_set(&mut self, other: &AddressSet) {
        for (&s, &e) in &other.ranges {
            self.add_range(Address::new(s), Address::new(e));
        }
    }

    /// Add all addresses from an iterator of AddressRange.
    pub fn add_all(&mut self, ranges: impl IntoIterator<Item = AddressRange>) {
        for r in ranges {
            self.add_range(r.start, r.end);
        }
    }

    /// Delete a single address.
    pub fn delete(&mut self, addr: Address) {
        self.delete_range(addr, addr);
    }

    /// Delete an inclusive range [start, end].
    pub fn delete_range(&mut self, start: Address, end: Address) {
        if start.offset > end.offset {
            return;
        }
        let (lo, hi) = (start.offset, end.offset);
        let keys: Vec<u64> = self
            .ranges
            .range(..=hi)
            .rev()
            .take_while(|(&s, _)| s >= lo.saturating_sub(1))
            .map(|(&s, _)| s)
            .collect();
        for k in keys {
            let e = self.ranges.remove(&k).unwrap();
            if k < lo {
                self.ranges.insert(k, lo - 1);
            }
            if e > hi {
                self.ranges.insert(hi + 1, e);
            }
        }
    }

    /// Delete all ranges from another set.
    pub fn delete_set(&mut self, other: &AddressSet) {
        for (&s, &e) in &other.ranges {
            self.delete_range(Address::new(s), Address::new(e));
        }
    }

    // -- Set operations (return new sets) --

    /// Intersection with another set.
    pub fn intersect(&self, other: &AddressSet) -> AddressSet {
        let mut result = AddressSet::new();
        let mut b_iter = other.ranges.iter();
        let mut b_cur = b_iter.next();
        for (&a_s, &a_e) in &self.ranges {
            while let Some((&b_s, &b_e)) = b_cur {
                if b_e < a_s {
                    b_cur = b_iter.next();
                    continue;
                }
                if b_s > a_e {
                    break;
                }
                let lo = a_s.max(b_s);
                let hi = a_e.min(b_e);
                result.ranges.insert(lo, hi);
                if b_e <= a_e {
                    b_cur = b_iter.next();
                } else {
                    break;
                }
            }
        }
        result
    }

    /// Union with another set.
    pub fn union(&self, other: &AddressSet) -> AddressSet {
        let mut result = self.clone();
        result.add_set(other);
        result
    }

    /// Difference (self - other).
    pub fn difference(&self, other: &AddressSet) -> AddressSet {
        let mut result = self.clone();
        result.delete_set(other);
        result
    }

    /// True if this set intersects with the given range.
    pub fn intersects_range(&self, start: Address, end: Address) -> bool {
        if start.offset > end.offset {
            return false;
        }
        // Any range that overlaps [start, end]
        self.ranges
            .range(..=end.offset)
            .next_back()
            .map_or(false, |(_, &e)| e >= start.offset)
    }

    /// True if this set intersects with another set.
    pub fn intersects_set(&self, other: &AddressSet) -> bool {
        for (&s, &e) in &other.ranges {
            if self.intersects_range(Address::new(s), Address::new(e)) {
                return true;
            }
        }
        false
    }

    /// First address common to both sets.
    pub fn find_first_in_common(&self, other: &AddressSet) -> Option<Address> {
        // Walk both in parallel
        let mut a_iter = self.ranges.iter();
        let mut b_iter = other.ranges.iter();
        let mut a_cur = a_iter.next();
        let mut b_cur = b_iter.next();
        loop {
            match (a_cur, b_cur) {
                (Some((&a_s, &a_e)), Some((&b_s, &b_e))) => {
                    if a_e < b_s {
                        a_cur = a_iter.next();
                    } else if b_e < a_s {
                        b_cur = b_iter.next();
                    } else {
                        return Some(Address::new(a_s.max(b_s)));
                    }
                }
                _ => return None,
            }
        }
    }

    // -- Iteration --

    /// Iterate over ranges in this set.
    pub fn iter(&self) -> AddressSetRangeIter<'_> {
        AddressSetRangeIter {
            inner: self.ranges.iter(),
        }
    }

    /// Iterate over all individual addresses (potentially very large).
    pub fn addresses(&self) -> AddressSetAddrIter<'_> {
        AddressSetAddrIter {
            range_iter: self.ranges.iter(),
            current: 0,
            end: 0,
        }
    }
}

impl IntoIterator for AddressSet {
    type Item = AddressRange;
    type IntoIter = AddressSetIntoRangeIter;

    fn into_iter(self) -> Self::IntoIter {
        AddressSetIntoRangeIter {
            inner: self.ranges.into_iter(),
        }
    }
}

/// Iterator over borrowed address ranges in an AddressSet.
pub struct AddressSetRangeIter<'a> {
    inner: std::collections::btree_map::Iter<'a, u64, u64>,
}

impl<'a> Iterator for AddressSetRangeIter<'a> {
    type Item = AddressRange;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(&s, &e)| AddressRange::new(Address::new(s), Address::new(e)))
    }
}

/// Iterator over owned address ranges (consumes the set).
pub struct AddressSetIntoRangeIter {
    inner: std::collections::btree_map::IntoIter<u64, u64>,
}

impl Iterator for AddressSetIntoRangeIter {
    type Item = AddressRange;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(s, e)| AddressRange::new(Address::new(s), Address::new(e)))
    }
}

/// Iterator over individual addresses in an AddressSet.
pub struct AddressSetAddrIter<'a> {
    range_iter: std::collections::btree_map::Iter<'a, u64, u64>,
    current: u64,
    end: u64,
}

impl<'a> Iterator for AddressSetAddrIter<'a> {
    type Item = Address;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.current <= self.end {
                let addr = Address::new(self.current);
                self.current += 1;
                return Some(addr);
            }
            let (&s, &e) = self.range_iter.next()?;
            self.current = s;
            self.end = e;
        }
    }
}

impl fmt::Display for AddressSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, range) in self.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "{}", range)?;
        }
        Ok(())
    }
}
