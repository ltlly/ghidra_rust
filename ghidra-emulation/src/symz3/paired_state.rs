//! Paired p-code executor state.
//!
//! Ported from `SymZ3PairedPcodeExecutorState.java` and
//! `SymZ3ThreadPcodeExecutorState.java` in the SymbolicSummaryZ3
//! extension.
//!
//! A paired state wraps both a concrete state and a symbolic state,
//! dispatching reads and writes to both simultaneously.

use super::model::SymValueZ3;
use super::state::{SpaceKind, SymZ3State};

/// A paired (concrete + symbolic) p-code executor state.
///
/// Reads from the concrete state produce concrete values, while
/// the symbolic state tracks the corresponding symbolic expressions.
#[derive(Debug)]
pub struct SymZ3PairedPcodeExecutorState {
    /// The concrete state (offset -> byte values).
    concrete_register: std::collections::HashMap<u64, Vec<u8>>,
    concrete_memory: std::collections::HashMap<u64, Vec<u8>>,
    /// The symbolic state.
    symbolic: SymZ3State,
}

impl SymZ3PairedPcodeExecutorState {
    /// Create a new paired state.
    pub fn new() -> Self {
        Self {
            concrete_register: std::collections::HashMap::new(),
            concrete_memory: std::collections::HashMap::new(),
            symbolic: SymZ3State::new(),
        }
    }

    /// Get the symbolic state.
    pub fn symbolic(&self) -> &SymZ3State {
        &self.symbolic
    }

    /// Get a mutable reference to the symbolic state.
    pub fn symbolic_mut(&mut self) -> &mut SymZ3State {
        &mut self.symbolic
    }

    /// Write both concrete and symbolic values.
    pub fn write_register(&mut self, offset: u64, concrete: Vec<u8>, symbolic: SymValueZ3) {
        let size = concrete.len() as u32;
        self.concrete_register.insert(offset, concrete);
        self.symbolic
            .set_value(SpaceKind::Register, offset, size, symbolic);
    }

    /// Write both concrete and symbolic values to memory.
    pub fn write_memory(&mut self, address: u64, concrete: Vec<u8>, symbolic: SymValueZ3) {
        let size = concrete.len() as u32;
        self.concrete_memory.insert(address, concrete);
        self.symbolic
            .set_value(SpaceKind::Memory, address, size, symbolic);
    }

    /// Read concrete bytes from a register.
    pub fn read_concrete_register(&self, offset: u64) -> Option<&[u8]> {
        self.concrete_register.get(&offset).map(|v| v.as_slice())
    }

    /// Read concrete bytes from memory.
    pub fn read_concrete_memory(&self, address: u64) -> Option<&[u8]> {
        self.concrete_memory.get(&address).map(|v| v.as_slice())
    }

    /// Read the symbolic value of a register.
    pub fn read_symbolic_register(&self, offset: u64, size: u32) -> Option<&SymValueZ3> {
        self.symbolic.get_value(SpaceKind::Register, offset, size)
    }

    /// Read the symbolic value from memory.
    pub fn read_symbolic_memory(&self, address: u64, size: u32) -> Option<&SymValueZ3> {
        self.symbolic.get_value(SpaceKind::Memory, address, size)
    }

    /// Clear all state.
    pub fn clear(&mut self) {
        self.concrete_register.clear();
        self.concrete_memory.clear();
        self.symbolic.clear();
    }
}

impl Default for SymZ3PairedPcodeExecutorState {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-thread p-code executor state.
#[derive(Debug)]
pub struct SymZ3ThreadPcodeExecutorState {
    /// Thread ID.
    pub thread_id: u32,
    /// The paired state for this thread.
    state: SymZ3PairedPcodeExecutorState,
}

impl SymZ3ThreadPcodeExecutorState {
    /// Create new per-thread state.
    pub fn new(thread_id: u32) -> Self {
        Self {
            thread_id,
            state: SymZ3PairedPcodeExecutorState::new(),
        }
    }

    /// Get the paired state.
    pub fn state(&self) -> &SymZ3PairedPcodeExecutorState {
        &self.state
    }

    /// Get a mutable reference to the paired state.
    pub fn state_mut(&mut self) -> &mut SymZ3PairedPcodeExecutorState {
        &mut self.state
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paired_state_write_register() {
        let mut ps = SymZ3PairedPcodeExecutorState::new();
        ps.write_register(
            0,
            vec![42, 0, 0, 0, 0, 0, 0, 0],
            SymValueZ3::from_bitvec("RAX_sym"),
        );

        let concrete = ps.read_concrete_register(0).unwrap();
        assert_eq!(concrete[0], 42);

        let sym = ps.read_symbolic_register(0, 8).unwrap();
        assert_eq!(sym.bitvec_expr_string.as_deref(), Some("RAX_sym"));
    }

    #[test]
    fn test_paired_state_write_memory() {
        let mut ps = SymZ3PairedPcodeExecutorState::new();
        ps.write_memory(0x1000, vec![0xFF], SymValueZ3::from_bitvec("m_sym"));

        let concrete = ps.read_concrete_memory(0x1000).unwrap();
        assert_eq!(concrete[0], 0xFF);
    }

    #[test]
    fn test_paired_state_clear() {
        let mut ps = SymZ3PairedPcodeExecutorState::new();
        ps.write_register(0, vec![0; 8], SymValueZ3::from_bitvec("x"));
        ps.clear();
        assert!(ps.read_concrete_register(0).is_none());
    }

    #[test]
    fn test_thread_state() {
        let mut ts = SymZ3ThreadPcodeExecutorState::new(42);
        assert_eq!(ts.thread_id, 42);
        ts.state_mut().write_register(
            0,
            vec![0; 8],
            SymValueZ3::from_bitvec("thread_reg"),
        );
        assert!(ts.state().read_symbolic_register(0, 8).is_some());
    }
}
