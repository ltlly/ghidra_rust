//! Symbolic state pieces -- maps varnodes to symbolic values.
//!
//! Ported from `SymZ3PcodeExecutorStatePiece.java` and related state
//! classes in the SymbolicSummaryZ3 extension.
//!
//! The state pieces maintain a mapping from address spaces (register,
//! memory, unique) to symbolic values (`SymValueZ3`).

use super::model::SymValueZ3;
use std::collections::HashMap;

/// Identifies a symbolic address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpaceKind {
    /// Register space (e.g., RAX, RIP).
    Register,
    /// Memory/RAM space.
    Memory,
    /// Unique (temporary) space used by p-code internals.
    Unique,
}

/// A symbolic space that maps offsets to symbolic values.
///
/// Each space type (register, memory, unique) maintains its own mapping.
#[derive(Debug)]
pub struct SymZ3Space {
    /// The kind of address space.
    pub kind: SpaceKind,
    /// Maps offset -> (size -> symbolic value).
    values: HashMap<u64, HashMap<u32, SymValueZ3>>,
}

impl SymZ3Space {
    /// Create a new symbolic space.
    pub fn new(kind: SpaceKind) -> Self {
        Self {
            kind,
            values: HashMap::new(),
        }
    }

    /// Get the symbolic value at the given offset and size.
    pub fn get(&self, offset: u64, size: u32) -> Option<&SymValueZ3> {
        self.values.get(&offset).and_then(|m| m.get(&size))
    }

    /// Set the symbolic value at the given offset and size.
    pub fn set(&mut self, offset: u64, size: u32, value: SymValueZ3) {
        self.values
            .entry(offset)
            .or_default()
            .insert(size, value);
    }

    /// Check if a value exists at the given offset and size.
    pub fn contains(&self, offset: u64, size: u32) -> bool {
        self.values
            .get(&offset)
            .map_or(false, |m| m.contains_key(&size))
    }

    /// Remove all values.
    pub fn clear(&mut self) {
        self.values.clear();
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.values.values().map(|m| m.len()).sum()
    }

    /// Whether the space is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Iterate over all entries: (offset, size, value).
    pub fn iter(&self) -> impl Iterator<Item = (u64, u32, &SymValueZ3)> {
        self.values
            .iter()
            .flat_map(|(&offset, sizes)| {
                sizes
                    .iter()
                    .map(move |(&size, value)| (offset, size, value))
            })
    }
}

/// Register-space symbolic state.
pub type SymZ3RegisterSpace = SymZ3Space;

/// Memory-space symbolic state.
pub type SymZ3MemorySpace = SymZ3Space;

/// The combined symbolic p-code executor state.
///
/// Maintains separate symbolic spaces for registers, memory, and unique
/// (temporary) addresses. Each space maps `(offset, size)` pairs to
/// `SymValueZ3` symbolic values.
#[derive(Debug)]
pub struct SymZ3State {
    /// Register space.
    pub register: SymZ3Space,
    /// Memory space.
    pub memory: SymZ3Space,
    /// Unique (temporary) space.
    pub unique: SymZ3Space,
}

impl SymZ3State {
    /// Create a new empty symbolic state.
    pub fn new() -> Self {
        Self {
            register: SymZ3Space::new(SpaceKind::Register),
            memory: SymZ3Space::new(SpaceKind::Memory),
            unique: SymZ3Space::new(SpaceKind::Unique),
        }
    }

    /// Get the space for the given kind.
    pub fn space(&self, kind: SpaceKind) -> &SymZ3Space {
        match kind {
            SpaceKind::Register => &self.register,
            SpaceKind::Memory => &self.memory,
            SpaceKind::Unique => &self.unique,
        }
    }

    /// Get a mutable reference to the space for the given kind.
    pub fn space_mut(&mut self, kind: SpaceKind) -> &mut SymZ3Space {
        match kind {
            SpaceKind::Register => &mut self.register,
            SpaceKind::Memory => &mut self.memory,
            SpaceKind::Unique => &mut self.unique,
        }
    }

    /// Get a symbolic value from the specified space.
    pub fn get_value(
        &self,
        kind: SpaceKind,
        offset: u64,
        size: u32,
    ) -> Option<&SymValueZ3> {
        self.space(kind).get(offset, size)
    }

    /// Set a symbolic value in the specified space.
    pub fn set_value(
        &mut self,
        kind: SpaceKind,
        offset: u64,
        size: u32,
        value: SymValueZ3,
    ) {
        self.space_mut(kind).set(offset, size, value);
    }

    /// Clear all symbolic values.
    pub fn clear(&mut self) {
        self.register.clear();
        self.memory.clear();
        self.unique.clear();
    }

    /// Total number of symbolic values across all spaces.
    pub fn total_entries(&self) -> usize {
        self.register.len() + self.memory.len() + self.unique.len()
    }
}

impl Default for SymZ3State {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_space_set_and_get() {
        let mut space = SymZ3Space::new(SpaceKind::Register);
        let val = SymValueZ3::from_bitvec("bv42");
        space.set(0x10, 8, val.clone());
        assert_eq!(space.get(0x10, 8), Some(&val));
        assert!(space.get(0x10, 4).is_none());
        assert!(space.get(0x20, 8).is_none());
    }

    #[test]
    fn test_space_contains() {
        let mut space = SymZ3Space::new(SpaceKind::Memory);
        space.set(0x100, 4, SymValueZ3::from_bitvec("x"));
        assert!(space.contains(0x100, 4));
        assert!(!space.contains(0x100, 8));
    }

    #[test]
    fn test_space_len() {
        let mut space = SymZ3Space::new(SpaceKind::Register);
        assert!(space.is_empty());
        space.set(0, 8, SymValueZ3::from_bitvec("a"));
        space.set(8, 8, SymValueZ3::from_bitvec("b"));
        assert_eq!(space.len(), 2);
    }

    #[test]
    fn test_space_clear() {
        let mut space = SymZ3Space::new(SpaceKind::Register);
        space.set(0, 8, SymValueZ3::from_bitvec("a"));
        space.clear();
        assert!(space.is_empty());
    }

    #[test]
    fn test_space_iter() {
        let mut space = SymZ3Space::new(SpaceKind::Register);
        space.set(0, 8, SymValueZ3::from_bitvec("a"));
        space.set(8, 4, SymValueZ3::from_bitvec("b"));
        let entries: Vec<_> = space.iter().collect();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_state_new() {
        let state = SymZ3State::new();
        assert_eq!(state.total_entries(), 0);
    }

    #[test]
    fn test_state_set_and_get() {
        let mut state = SymZ3State::new();
        let val = SymValueZ3::from_bitvec("RAX_value");
        state.set_value(SpaceKind::Register, 0, 8, val.clone());
        assert_eq!(
            state.get_value(SpaceKind::Register, 0, 8),
            Some(&val)
        );
        assert_eq!(state.total_entries(), 1);
    }

    #[test]
    fn test_state_multiple_spaces() {
        let mut state = SymZ3State::new();
        state.set_value(
            SpaceKind::Register,
            0,
            8,
            SymValueZ3::from_bitvec("reg"),
        );
        state.set_value(
            SpaceKind::Memory,
            0x1000,
            4,
            SymValueZ3::from_bitvec("mem"),
        );
        state.set_value(
            SpaceKind::Unique,
            0,
            8,
            SymValueZ3::from_bitvec("tmp"),
        );
        assert_eq!(state.total_entries(), 3);
    }

    #[test]
    fn test_state_clear() {
        let mut state = SymZ3State::new();
        state.set_value(
            SpaceKind::Register,
            0,
            8,
            SymValueZ3::from_bitvec("x"),
        );
        state.clear();
        assert_eq!(state.total_entries(), 0);
    }

    #[test]
    fn test_state_different_sizes_same_offset() {
        let mut state = SymZ3State::new();
        state.set_value(
            SpaceKind::Register,
            0,
            4,
            SymValueZ3::from_bitvec("eax"),
        );
        state.set_value(
            SpaceKind::Register,
            0,
            8,
            SymValueZ3::from_bitvec("rax"),
        );
        assert_eq!(
            state.get_value(SpaceKind::Register, 0, 4).unwrap(),
            &SymValueZ3::from_bitvec("eax")
        );
        assert_eq!(
            state.get_value(SpaceKind::Register, 0, 8).unwrap(),
            &SymValueZ3::from_bitvec("rax")
        );
    }

    #[test]
    fn test_space_kind_equality() {
        assert_eq!(SpaceKind::Register, SpaceKind::Register);
        assert_ne!(SpaceKind::Register, SpaceKind::Memory);
        assert_ne!(SpaceKind::Memory, SpaceKind::Unique);
    }
}
