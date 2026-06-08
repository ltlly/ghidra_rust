//! Symbolic preconditions.
//!
//! Ported from `SymZ3Preconditions.java` and `SymZ3RecordsPreconditions.java`
//! in the SymbolicSummaryZ3 extension.
//!
//! Preconditions define symbolic assumptions about the initial state
//! before execution. They allow specifying constraints on register
//! values, memory contents, and other state.

use super::model::SymValueZ3;
use super::state::SpaceKind;


/// A precondition for the symbolic emulator.
///
/// Defines a constraint that must hold in the initial state.
#[derive(Debug, Clone)]
pub struct SymZ3Precondition {
    /// The space kind (register, memory, unique).
    pub space: SpaceKind,
    /// The offset within the space.
    pub offset: u64,
    /// The size in bytes.
    pub size: u32,
    /// The symbolic value constraint.
    pub value: SymValueZ3,
}

impl SymZ3Precondition {
    /// Create a new precondition.
    pub fn new(
        space: SpaceKind,
        offset: u64,
        size: u32,
        value: SymValueZ3,
    ) -> Self {
        Self {
            space,
            offset,
            size,
            value,
        }
    }

    /// Create a register precondition (e.g., "RAX = some_expr").
    pub fn register(offset: u64, size: u32, value: SymValueZ3) -> Self {
        Self::new(SpaceKind::Register, offset, size, value)
    }

    /// Create a memory precondition.
    pub fn memory(address: u64, size: u32, value: SymValueZ3) -> Self {
        Self::new(SpaceKind::Memory, address, size, value)
    }
}

/// Container for symbolic preconditions.
///
/// Manages a collection of preconditions that define the initial
/// symbolic state before execution begins.
#[derive(Debug, Clone, Default)]
pub struct SymZ3Preconditions {
    /// The preconditions, keyed by (space, offset, size).
    preconditions: Vec<SymZ3Precondition>,
}

impl SymZ3Preconditions {
    /// Create an empty preconditions set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a precondition.
    pub fn add(&mut self, precondition: SymZ3Precondition) {
        self.preconditions.push(precondition);
    }

    /// Add a register constraint.
    pub fn add_register(&mut self, offset: u64, size: u32, value: SymValueZ3) {
        self.add(SymZ3Precondition::register(offset, size, value));
    }

    /// Add a memory constraint.
    pub fn add_memory(&mut self, address: u64, size: u32, value: SymValueZ3) {
        self.add(SymZ3Precondition::memory(address, size, value));
    }

    /// Get all preconditions.
    pub fn all(&self) -> &[SymZ3Precondition] {
        &self.preconditions
    }

    /// Number of preconditions.
    pub fn len(&self) -> usize {
        self.preconditions.len()
    }

    /// Whether there are no preconditions.
    pub fn is_empty(&self) -> bool {
        self.preconditions.is_empty()
    }

    /// Apply all preconditions to a state.
    pub fn apply_to_state(
        &self,
        state: &mut super::state::SymZ3State,
    ) {
        for pre in &self.preconditions {
            state.set_value(pre.space, pre.offset, pre.size, pre.value.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_preconditions_add() {
        let mut pre = SymZ3Preconditions::new();
        pre.add_register(0, 8, SymValueZ3::from_bitvec("RAX_init"));
        pre.add_memory(0x1000, 4, SymValueZ3::from_bitvec("mem_init"));
        assert_eq!(pre.len(), 2);
    }

    #[test]
    fn test_preconditions_apply() {
        let mut pre = SymZ3Preconditions::new();
        pre.add_register(0, 8, SymValueZ3::from_bitvec("init_rax"));

        let mut state = crate::symz3::SymZ3State::new();
        pre.apply_to_state(&mut state);

        let val = state.get_value(SpaceKind::Register, 0, 8).unwrap();
        assert_eq!(val.bitvec_expr_string.as_deref(), Some("init_rax"));
    }

    #[test]
    fn test_preconditions_empty() {
        let pre = SymZ3Preconditions::new();
        assert!(pre.is_empty());
    }
}
