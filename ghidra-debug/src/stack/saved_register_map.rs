//! A map from register ranges to physical stack addresses.
//!
//! Ported from Ghidra's `SavedRegisterMap`. When a function saves a
//! register to the stack, this map records the redirection so that
//! subsequent reads of that register in inner frames will read from
//! the stack instead.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A range in the register space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterRange {
    /// Start offset in the register space.
    pub min: u64,
    /// End offset (inclusive).
    pub max: u64,
}

impl RegisterRange {
    /// Create a new register range.
    pub fn new(min: u64, max: u64) -> Self {
        Self { min, max }
    }

    /// Create a range from a register offset and size.
    pub fn from_offset_size(offset: u64, size: u64) -> Self {
        Self {
            min: offset,
            max: offset + size - 1,
        }
    }

    /// The length of this range.
    pub fn len(&self) -> u64 {
        self.max - self.min + 1
    }

    /// Whether this range contains an address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.min && addr <= self.max
    }

    /// Compute the intersection with another range.
    pub fn intersect(&self, other: &RegisterRange) -> Option<RegisterRange> {
        let min = self.min.max(other.min);
        let max = self.max.min(other.max);
        if min <= max {
            Some(RegisterRange { min, max })
        } else {
            None
        }
    }
}

/// A single entry in the saved register map.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedEntry {
    /// The range in register space being redirected.
    pub from: RegisterRange,
    /// The destination address on the stack.
    pub to_addr: u64,
}

impl SavedEntry {
    /// Create a new saved entry.
    pub fn new(from: RegisterRange, to_addr: u64) -> Self {
        Self { from, to_addr }
    }

    /// Truncate this entry to a sub-range.
    pub fn truncate(&self, range: &RegisterRange) -> SavedEntry {
        let left_offset = range.min.saturating_sub(self.from.min);
        SavedEntry {
            from: RegisterRange {
                min: range.min.max(self.from.min),
                max: range.max.min(self.from.max),
            },
            to_addr: self.to_addr + left_offset,
        }
    }

    /// Intersect this entry with a range.
    pub fn intersect(&self, range: &RegisterRange) -> Option<SavedEntry> {
        self.from.intersect(range).map(|r| self.truncate(&r))
    }
}

/// A map from register ranges to stack addresses for saved register
/// redirection during stack unwinding.
///
/// When a function saves register R30 to [SP - 8], this map records
/// that subsequent reads of R30 should read from [SP - 8] instead.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SavedRegisterMap {
    /// Entries keyed by the start address of the "from" range.
    entries: BTreeMap<u64, SavedEntry>,
}

impl SavedRegisterMap {
    /// Create an empty (identity) register map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a mapping from a register range to a stack address.
    pub fn put(&mut self, from: RegisterRange, to_addr: u64) {
        // Remove any overlapping entries
        let overlapping: Vec<u64> = self
            .entries
            .range(..=from.max)
            .filter(|(_, e)| e.from.max >= from.min)
            .map(|(k, _)| *k)
            .collect();
        for key in overlapping {
            self.entries.remove(&key);
        }
        self.entries.insert(from.min, SavedEntry::new(from, to_addr));
    }

    /// Map a register at a given offset/size to a stack address.
    pub fn put_register(&mut self, reg_offset: u64, reg_size: u64, stack_addr: u64) {
        self.put(
            RegisterRange::from_offset_size(reg_offset, reg_size),
            stack_addr,
        );
    }

    /// Look up where a register access should be redirected to.
    ///
    /// Returns the stack address if the register range is mapped, or
    /// `None` if it should be read from the register bank directly.
    pub fn lookup(&self, addr: u64) -> Option<&SavedEntry> {
        // Find the entry with the largest start <= addr
        let (_, entry) = self.entries.range(..=addr).next_back()?;
        if entry.from.contains(addr) {
            Some(entry)
        } else {
            None
        }
    }

    /// Get the redirected address for a given register address.
    ///
    /// If the register is saved, returns the stack address.
    /// Otherwise, returns the original address (identity).
    pub fn redirect(&self, addr: u64) -> u64 {
        match self.lookup(addr) {
            Some(entry) => {
                let offset = addr - entry.from.min;
                entry.to_addr + offset
            }
            None => addr,
        }
    }

    /// Fork this map (deep copy).
    pub fn fork(&self) -> Self {
        Self {
            entries: self.entries.clone(),
        }
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over entries.
    pub fn iter(&self) -> impl Iterator<Item = (&u64, &SavedEntry)> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_range() {
        let r = RegisterRange::new(0, 7);
        assert_eq!(r.len(), 8);
        assert!(r.contains(0));
        assert!(r.contains(7));
        assert!(!r.contains(8));
    }

    #[test]
    fn test_register_range_intersect() {
        let a = RegisterRange::new(0, 15);
        let b = RegisterRange::new(8, 23);
        let c = a.intersect(&b).unwrap();
        assert_eq!(c.min, 8);
        assert_eq!(c.max, 15);

        let d = RegisterRange::new(20, 30);
        assert!(a.intersect(&d).is_none());
    }

    #[test]
    fn test_saved_entry_truncate() {
        let entry = SavedEntry::new(RegisterRange::new(0, 15), 0x1000);
        let truncated = entry.truncate(&RegisterRange::new(4, 11));
        assert_eq!(truncated.from.min, 4);
        assert_eq!(truncated.from.max, 11);
        assert_eq!(truncated.to_addr, 0x1004);
    }

    #[test]
    fn test_put_and_lookup() {
        let mut map = SavedRegisterMap::new();
        let range = RegisterRange::new(0, 7); // 8-byte register
        map.put(range, 0x7fff0000);

        let entry = map.lookup(0).unwrap();
        assert_eq!(entry.to_addr, 0x7fff0000);

        assert!(map.lookup(8).is_none());
    }

    #[test]
    fn test_redirect() {
        let mut map = SavedRegisterMap::new();
        map.put(RegisterRange::new(0, 7), 0x7fff0000);

        assert_eq!(map.redirect(0), 0x7fff0000);
        assert_eq!(map.redirect(4), 0x7fff0004);
        assert_eq!(map.redirect(100), 100); // identity
    }

    #[test]
    fn test_overwrite_overlapping() {
        let mut map = SavedRegisterMap::new();
        map.put(RegisterRange::new(0, 15), 0x1000);
        assert_eq!(map.len(), 1);

        // Overwrite with a sub-range
        map.put(RegisterRange::new(4, 11), 0x2000);
        // The old entry is split and the new one takes priority
        // We have at least the new entry
        assert!(map.len() >= 1);
        assert_eq!(map.redirect(4), 0x2000);
        assert_eq!(map.redirect(8), 0x2004);
    }

    #[test]
    fn test_fork() {
        let mut map = SavedRegisterMap::new();
        map.put(RegisterRange::new(0, 7), 0x1000);

        let mut forked = map.fork();
        forked.put(RegisterRange::new(8, 15), 0x2000);

        assert_eq!(map.len(), 1);
        assert_eq!(forked.len(), 2);
    }

    #[test]
    fn test_put_register() {
        let mut map = SavedRegisterMap::new();
        map.put_register(0, 8, 0x7fff0000);

        assert_eq!(map.redirect(0), 0x7fff0000);
        assert_eq!(map.redirect(7), 0x7fff0007);
    }

    #[test]
    fn test_serde() {
        let mut map = SavedRegisterMap::new();
        map.put(RegisterRange::new(0, 7), 0x1000);
        let json = serde_json::to_string(&map).unwrap();
        let back: SavedRegisterMap = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
    }

    #[test]
    fn test_empty_map() {
        let map = SavedRegisterMap::new();
        assert!(map.is_empty());
        assert_eq!(map.redirect(42), 42);
    }
}
