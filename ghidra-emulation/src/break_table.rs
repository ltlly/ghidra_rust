//! BreakTable interface for the legacy emulation framework.
//!
//! Ported from Java: `ghidra.pcode.emulate.BreakTable`.
//!
//! A [`BreakTable`] keeps track of breakpoints for an emulator.
//! Breakpoints are either associated with a particular user-defined pcode op,
//! or with a specific machine address (as in a standard debugger).

use ghidra_core::addr::Address;
use ghidra_decompile::pcode::PcodeOperation;

/// A collection of breakpoints for the emulator.
///
/// Through the [`BreakTable`] trait, an emulator can invoke breakpoints via:
/// - [`do_pcode_op_break`] -- for user-defined pcode operation breakpoints
/// - [`do_address_break`] -- for machine address breakpoints
///
/// Ported from Java: `ghidra.pcode.emulate.BreakTable` (deprecated since 12.1).
pub trait BreakTable {
    /// Associate a particular emulator context with breakpoints in this table.
    ///
    /// Breakpoints may need access to the context in which they are invoked.
    /// This method provides that context for all breakpoints in the table.
    fn set_emulate(&mut self, emu_context: &dyn EmulateContext);

    /// Invoke any breakpoints associated with this particular pcode op.
    ///
    /// Within the table, the first breakpoint designed to work with this
    /// particular kind of pcode operation is invoked. If there was a
    /// breakpoint and it was designed to replace the action of the pcode op,
    /// then `true` is returned.
    fn do_pcode_op_break(&mut self, curop: &PcodeOperation) -> bool;

    /// Invoke any breakpoints associated with this machine address.
    ///
    /// Within the table, the first breakpoint designed to work at this address
    /// is invoked. If there was a breakpoint and it was designed to replace
    /// the action of the machine instruction, then `true` is returned.
    fn do_address_break(&mut self, addr: &Address) -> bool;
}

/// Minimal emulation context required by break table callbacks.
///
/// This trait provides the subset of emulator functionality that breakpoint
/// callbacks need to interact with the emulation state.
pub trait EmulateContext {
    /// Execute a pcode op, replacing the normal instruction behavior.
    fn execute_pcode_op(&mut self, op: &PcodeOperation);

    /// Get the current execution address.
    fn get_execution_address(&self) -> Address;

    /// Get a register value by name.
    fn get_register(&self, name: &str) -> Option<&[u8]>;

    /// Set a register value by name.
    fn set_register(&mut self, name: &str, value: &[u8]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{AddressSpace, AddrSpaceType};
    use ghidra_decompile::pcode::{OpCode, Varnode};

    /// A minimal mock implementation of EmulateContext for testing.
    struct MockEmulateContext {
        addr: Address,
        registers: std::collections::HashMap<String, Vec<u8>>,
    }

    impl MockEmulateContext {
        fn new() -> Self {
            Self {
                addr: Address::new(0),
                registers: std::collections::HashMap::new(),
            }
        }
    }

    impl EmulateContext for MockEmulateContext {
        fn execute_pcode_op(&mut self, _op: &PcodeOperation) {}
        fn get_execution_address(&self) -> Address {
            self.addr
        }
        fn get_register(&self, name: &str) -> Option<&[u8]> {
            self.registers.get(name).map(|v| v.as_slice())
        }
        fn set_register(&mut self, name: &str, value: &[u8]) {
            self.registers.insert(name.to_string(), value.to_vec());
        }
    }

    /// A simple break table for testing.
    struct TestBreakTable {
        emulate_set: bool,
        address_breaks: std::collections::HashMap<Address, bool>,
        pcode_breaks: std::collections::HashMap<u64, bool>,
    }

    impl TestBreakTable {
        fn new() -> Self {
            Self {
                emulate_set: false,
                address_breaks: std::collections::HashMap::new(),
                pcode_breaks: std::collections::HashMap::new(),
            }
        }
    }

    impl BreakTable for TestBreakTable {
        fn set_emulate(&mut self, _emu_context: &dyn EmulateContext) {
            self.emulate_set = true;
        }

        fn do_pcode_op_break(&mut self, curop: &PcodeOperation) -> bool {
            let val = curop.inputs.first().map(|vn| vn.offset).unwrap_or(0);
            self.pcode_breaks.get(&val).copied().unwrap_or(false)
        }

        fn do_address_break(&mut self, addr: &Address) -> bool {
            self.address_breaks.get(addr).copied().unwrap_or(false)
        }
    }

    #[test]
    fn test_break_table_set_emulate() {
        let mut table = TestBreakTable::new();
        let ctx = MockEmulateContext::new();
        assert!(!table.emulate_set);
        table.set_emulate(&ctx);
        assert!(table.emulate_set);
    }

    #[test]
    fn test_break_table_address_break() {
        let mut table = TestBreakTable::new();
        table.address_breaks.insert(Address::new(0x1000), true);

        assert!(table.do_address_break(&Address::new(0x1000)));
        assert!(!table.do_address_break(&Address::new(0x2000)));
    }

    #[test]
    fn test_break_table_pcode_break() {
        let mut table = TestBreakTable::new();
        table.pcode_breaks.insert(42, true);

        let space = AddressSpace::new("unique", 8, false, AddrSpaceType::Unique, 0);
        let op = PcodeOperation::new_unannotated(
            OpCode::CALLOTHER,
            None,
            vec![Varnode::new(space, 42, 8)],
        );

        assert!(table.do_pcode_op_break(&op));

        let op2 = PcodeOperation::new_unannotated(
            OpCode::CALLOTHER,
            None,
            vec![Varnode::new(
                AddressSpace::new("unique", 8, false, AddrSpaceType::Unique, 0),
                99,
                8,
            )],
        );

        assert!(!table.do_pcode_op_break(&op2));
    }
}
