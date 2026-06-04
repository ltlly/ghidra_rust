//! Symbolic p-code emulator.
//!
//! Ported from `SymZ3PcodeEmulator.java` and related state classes
//! in the SymbolicSummaryZ3 extension.
//!
//! The symbolic emulator extends the concrete p-code emulator with
//! symbolic tracking using Z3 bit-vector expressions stored as strings.

use super::arithmetic::SymZ3PcodeArithmetic;
use super::model::SymValueZ3;
use super::state::SymZ3State;
use std::collections::HashMap;

/// The symbolic p-code emulator.
///
/// Maintains a symbolic state alongside concrete execution, tracking
/// Z3 expressions for each varnode that has been written.
pub struct SymZ3PcodeEmulator {
    /// The symbolic state (register, memory, unique spaces).
    state: SymZ3State,
    /// Arithmetic dispatch for symbolic operations.
    arithmetic: SymZ3PcodeArithmetic,
    /// User-defined operation library.
    userop_library: HashMap<String, Box<dyn Fn(&[SymValueZ3]) -> SymValueZ3>>,
    /// Instruction counter.
    instruction_count: u64,
}

impl SymZ3PcodeEmulator {
    /// Create a new symbolic emulator.
    pub fn new() -> Self {
        Self {
            state: SymZ3State::new(),
            arithmetic: SymZ3PcodeArithmetic,
            userop_library: HashMap::new(),
            instruction_count: 0,
        }
    }

    /// Get a reference to the symbolic state.
    pub fn state(&self) -> &SymZ3State {
        &self.state
    }

    /// Get a mutable reference to the symbolic state.
    pub fn state_mut(&mut self) -> &mut SymZ3State {
        &mut self.state
    }

    /// Register a user-defined operation.
    pub fn register_userop(
        &mut self,
        name: impl Into<String>,
        handler: Box<dyn Fn(&[SymValueZ3]) -> SymValueZ3>,
    ) {
        self.userop_library.insert(name.into(), handler);
    }

    /// Execute a unary symbolic operation.
    pub fn execute_unary(
        &mut self,
        opcode: &str,
        out_size: u32,
        input_size: u32,
        input: &SymValueZ3,
    ) -> SymValueZ3 {
        self.instruction_count += 1;
        SymZ3PcodeArithmetic::unary_op(opcode, out_size, input_size, input)
    }

    /// Execute a binary symbolic operation.
    pub fn execute_binary(
        &mut self,
        opcode: &str,
        out_size: u32,
        left: &SymValueZ3,
        right: &SymValueZ3,
    ) -> SymValueZ3 {
        self.instruction_count += 1;
        SymZ3PcodeArithmetic::binary_op(opcode, out_size, left, right)
    }

    /// Get the number of instructions executed.
    pub fn instruction_count(&self) -> u64 {
        self.instruction_count
    }

    /// Reset the emulator state.
    pub fn reset(&mut self) {
        self.state.clear();
        self.instruction_count = 0;
    }
}

impl Default for SymZ3PcodeEmulator {
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
    use crate::symz3::state::SpaceKind;

    #[test]
    fn test_emulator_creation() {
        let emu = SymZ3PcodeEmulator::new();
        assert_eq!(emu.instruction_count(), 0);
    }

    #[test]
    fn test_emulator_unary() {
        let mut emu = SymZ3PcodeEmulator::new();
        let input = SymValueZ3::from_bitvec("x");
        let result = emu.execute_unary("BOOL_NEGATE", 1, 1, &input);
        assert!(result.has_bitvec_expr());
        assert_eq!(emu.instruction_count(), 1);
    }

    #[test]
    fn test_emulator_binary() {
        let mut emu = SymZ3PcodeEmulator::new();
        let a = SymValueZ3::from_bitvec("a");
        let b = SymValueZ3::from_bitvec("b");
        let result = emu.execute_binary("INT_ADD", 8, &a, &b);
        assert!(result.bitvec_expr_string.unwrap().contains("bvadd"));
        assert_eq!(emu.instruction_count(), 1);
    }

    #[test]
    fn test_emulator_state() {
        let mut emu = SymZ3PcodeEmulator::new();
        emu.state_mut().set_value(
            SpaceKind::Register,
            0,
            8,
            SymValueZ3::from_bitvec("RAX"),
        );
        assert_eq!(emu.state().total_entries(), 1);
    }

    #[test]
    fn test_emulator_reset() {
        let mut emu = SymZ3PcodeEmulator::new();
        emu.execute_binary("INT_ADD", 8, &SymValueZ3::from_bitvec("a"), &SymValueZ3::from_bitvec("b"));
        emu.reset();
        assert_eq!(emu.instruction_count(), 0);
    }

    #[test]
    fn test_register_userop() {
        let mut emu = SymZ3PcodeEmulator::new();
        emu.register_userop(
            "my_op",
            Box::new(|args| {
                if let Some(first) = args.first() {
                    first.clone()
                } else {
                    SymValueZ3::from_bitvec("bv0")
                }
            }),
        );
        assert!(emu.userop_library.contains_key("my_op"));
    }
}
