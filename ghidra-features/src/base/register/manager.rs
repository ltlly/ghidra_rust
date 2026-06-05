//! Register manager — orchestrates register value display and editing.
//!
//! Ported from `RegisterManagerProvider` and `RegisterValuesPanel` in
//! Ghidra's `ghidra.app.plugin.core.register`.
//!
//! The register manager coordinates between the register tree (which
//! groups registers for selection) and the value range table (which
//! shows the address ranges where a register has a specific value).

use ghidra_core::addr::{Address, AddressRange, AddressSet};
use ghidra_core::program::lang::Register;
use ghidra_core::program::listing::ProgramContext;
use ghidra_core::program::program::Program;

use super::commands::{
    CompoundRegisterCmd, InMemoryRegisterContext, RegisterCommand, RegisterContext,
    SetRegisterValueCmd,
};
use super::tree::RegisterTree;
use super::value_range::{merge_adjacent_ranges, RegisterValueRange};

/// Manages register value display, selection, and modification.
///
/// Ported from `RegisterManagerProvider` + `RegisterValuesPanel` in Java.
/// This is a data-oriented manager (no GUI) that provides the same
/// logical operations as the Java version.
///
/// # Usage
///
/// ```ignore
/// let mut manager = RegisterManager::new();
/// manager.set_program(&program);
/// manager.select_register("EAX");
/// let ranges = manager.value_ranges();
/// // Edit ranges, set/clear values, etc.
/// ```
#[derive(Debug)]
pub struct RegisterManager {
    /// The register tree (grouped hierarchy).
    tree: RegisterTree,
    /// Currently selected register name.
    selected_register: Option<String>,
    /// Value ranges for the selected register.
    value_ranges: Vec<RegisterValueRange>,
    /// Whether to include default values in the display.
    include_default_values: bool,
    /// Whether the manager is currently showing (visible).
    is_showing: bool,
    /// Current address (for location tracking).
    current_address: Option<Address>,
    /// All non-hidden registers in the program.
    all_registers: Vec<Register>,
}

impl RegisterManager {
    /// Create a new register manager.
    pub fn new() -> Self {
        Self {
            tree: RegisterTree::default(),
            selected_register: None,
            value_ranges: Vec::new(),
            include_default_values: false,
            is_showing: true,
            current_address: None,
            all_registers: Vec::new(),
        }
    }

    /// Set the program and populate the register tree.
    pub fn set_program(&mut self, program: Option<&Program>) {
        match program {
            Some(prog) => {
                // In a full implementation, we'd get registers from ProgramContext.
                // Here we use a simplified approach: check if the program has
                // a language with registers.
                self.all_registers = Vec::new();
                // Note: In the real Ghidra, registers come from
                // program.getProgramContext().getRegisters().
                // We build an empty tree for now; actual registers would come
                // from the program's language specification.
                self.tree = RegisterTree::new(&self.all_registers);
            }
            None => {
                self.all_registers.clear();
                self.tree = RegisterTree::default();
            }
        }
        self.selected_register = None;
        self.value_ranges.clear();
    }

    /// Set the program using pre-built register and context data.
    ///
    /// This variant is used when the caller already has the register list
    /// and context data available.
    pub fn set_program_with_data(
        &mut self,
        registers: &[Register],
        context: Option<&ProgramContext>,
    ) {
        self.all_registers = registers.to_vec();
        self.tree = RegisterTree::new(registers);
        self.refresh_value_ranges(context);
    }

    /// Select a register by name.
    pub fn select_register(&mut self, name: &str) {
        self.selected_register = Some(name.to_string());
    }

    /// Get the currently selected register name.
    pub fn selected_register(&self) -> Option<&str> {
        self.selected_register.as_deref()
    }

    /// Get the register tree.
    pub fn tree(&self) -> &RegisterTree {
        &self.tree
    }

    /// Get the value ranges for the currently selected register.
    pub fn value_ranges(&self) -> &[RegisterValueRange] {
        &self.value_ranges
    }

    /// Set the value ranges directly (for testing and programmatic use).
    pub fn set_value_ranges(&mut self, ranges: Vec<RegisterValueRange>) {
        self.value_ranges = ranges;
    }

    /// Whether to include default values in the display.
    pub fn include_default_values(&self) -> bool {
        self.include_default_values
    }

    /// Set whether to include default values in the display.
    pub fn set_include_default_values(&mut self, include: bool, context: Option<&ProgramContext>) {
        self.include_default_values = include;
        self.refresh_value_ranges(context);
    }

    /// Set whether the manager is currently showing.
    pub fn set_is_showing(&mut self, showing: bool) {
        self.is_showing = showing;
    }

    /// Update the current address for location tracking.
    pub fn set_location(&mut self, register: Option<&str>, address: Address) {
        self.current_address = Some(address);
        if let Some(reg_name) = register {
            self.selected_register = Some(reg_name.to_string());
        }
    }

    /// Refresh the value ranges for the currently selected register.
    pub fn refresh_value_ranges(&mut self, context: Option<&ProgramContext>) {
        self.value_ranges.clear();

        let reg_name = match &self.selected_register {
            Some(name) => name.clone(),
            None => return,
        };

        let _ctx = match context {
            Some(c) => c,
            None => return,
        };

        // In a full implementation, we would iterate over the register value
        // address ranges from ProgramContext and build RegisterValueRange objects.
        // This is a simplified version that demonstrates the data flow.
        //
        // The full version would call:
        //   context.get_register_value_address_ranges(&register)
        // and for each range, get the value and create a RegisterValueRange.
    }

    /// Find the value range row that contains the given address.
    pub fn find_row_for_address(&self, address: &Address) -> Option<usize> {
        self.value_ranges
            .iter()
            .position(|range| range.contains(address))
    }

    /// Set the selected row by address (for navigation).
    pub fn set_address(&mut self, address: Address) -> Option<usize> {
        self.current_address = Some(address);
        self.find_row_for_address(&address)
    }

    /// Build a command to set register values over the selected address set.
    pub fn build_set_value_command(
        &self,
        register_name: &str,
        value: u64,
        address_set: &[(Address, Address)],
    ) -> CompoundRegisterCmd {
        let mut cmd = CompoundRegisterCmd::new("Set Register Values");
        for &(start, end) in address_set {
            cmd.add(SetRegisterValueCmd::new(
                register_name,
                start,
                end,
                Some(value),
            ));
        }
        cmd
    }

    /// Build a command to clear register values over the selected ranges.
    pub fn build_delete_ranges_command(
        &self,
        register_name: &str,
        rows: &[usize],
    ) -> CompoundRegisterCmd {
        let mut cmd = CompoundRegisterCmd::new("Delete Register Value Ranges");
        for &row in rows {
            if let Some(range) = self.value_ranges.get(row) {
                cmd.add(SetRegisterValueCmd::clear(
                    register_name,
                    range.start_address(),
                    range.end_address(),
                ));
            }
        }
        cmd
    }

    /// Build a command to update a register value range (edit in-place).
    ///
    /// This clears the old range and sets the new range.
    pub fn build_update_value_command(
        &self,
        register_name: &str,
        old_start: Address,
        old_end: Address,
        new_start: Address,
        new_end: Address,
        new_value: u64,
    ) -> CompoundRegisterCmd {
        let mut cmd = CompoundRegisterCmd::new("Update Register Range");
        cmd.add(SetRegisterValueCmd::clear(
            register_name,
            old_start,
            old_end,
        ));
        cmd.add(SetRegisterValueCmd::new(
            register_name,
            new_start,
            new_end,
            Some(new_value),
        ));
        cmd
    }

    /// Get the address set for the selected rows (for creating selections).
    pub fn get_address_set_for_rows(&self, rows: &[usize]) -> Vec<(Address, Address)> {
        rows.iter()
            .filter_map(|&row| self.value_ranges.get(row))
            .map(|r| (r.start_address(), r.end_address()))
            .collect()
    }
}

impl Default for RegisterManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::Address;
    use ghidra_core::program::lang::{Register, RegisterTypeFlags};
    use std::collections::HashSet;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn make_register(name: &str, group: Option<&str>) -> Register {
        Register {
            name: name.to_string(),
            description: String::new(),
            group: group.map(|s| s.to_string()),
            parent: None,
            bit_length: 32,
            address: addr(0),
            num_bytes: 4,
            least_significant_bit: 0,
            big_endian: false,
            type_flags: RegisterTypeFlags::default(),
            aliases: HashSet::new(),
            child_registers: Vec::new(),
            base_register: None,
            least_significant_bit_in_base: 0,
            lane_sizes: 0,
        }
    }

    #[test]
    fn test_new_manager() {
        let manager = RegisterManager::new();
        assert!(manager.selected_register().is_none());
        assert!(manager.value_ranges().is_empty());
    }

    #[test]
    fn test_set_program_with_data() {
        let regs = vec![
            make_register("EAX", Some("General")),
            make_register("EBX", Some("General")),
        ];
        let mut manager = RegisterManager::new();
        manager.set_program_with_data(&regs, None);
        assert_eq!(manager.tree().all_registers().len(), 2);
    }

    #[test]
    fn test_select_register() {
        let mut manager = RegisterManager::new();
        manager.select_register("EAX");
        assert_eq!(manager.selected_register(), Some("EAX"));
    }

    #[test]
    fn test_find_row_for_address() {
        let mut manager = RegisterManager::new();
        manager.value_ranges = vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5),
            RegisterValueRange::from_range(addr(0x2000), addr(0x2fff), 10),
        ];
        assert_eq!(manager.find_row_for_address(&addr(0x1500)), Some(0));
        assert_eq!(manager.find_row_for_address(&addr(0x2500)), Some(1));
        assert_eq!(manager.find_row_for_address(&addr(0x3000)), None);
    }

    #[test]
    fn test_set_address() {
        let mut manager = RegisterManager::new();
        manager.value_ranges = vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5),
        ];
        let row = manager.set_address(addr(0x1500));
        assert_eq!(row, Some(0));
    }

    #[test]
    fn test_build_set_value_command() {
        let manager = RegisterManager::new();
        let ranges = vec![(addr(0x1000), addr(0x1fff))];
        let cmd = manager.build_set_value_command("EAX", 42, &ranges);
        assert_eq!(cmd.len(), 1);
        assert_eq!(cmd.commands()[0].register_name(), "EAX");
        assert_eq!(cmd.commands()[0].value(), Some(42));
    }

    #[test]
    fn test_build_delete_ranges_command() {
        let mut manager = RegisterManager::new();
        manager.value_ranges = vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5),
            RegisterValueRange::from_range(addr(0x2000), addr(0x2fff), 10),
        ];
        let cmd = manager.build_delete_ranges_command("EAX", &[0, 1]);
        assert_eq!(cmd.len(), 2);
        // Both commands should be clear commands (value = None)
        assert_eq!(cmd.commands()[0].value(), None);
        assert_eq!(cmd.commands()[1].value(), None);
    }

    #[test]
    fn test_build_update_value_command() {
        let manager = RegisterManager::new();
        let cmd = manager.build_update_value_command(
            "EAX",
            addr(0x1000),
            addr(0x1fff),
            addr(0x1000),
            addr(0x1fff),
            99,
        );
        assert_eq!(cmd.len(), 2);
        assert_eq!(cmd.commands()[0].value(), None); // clear
        assert_eq!(cmd.commands()[1].value(), Some(99)); // set new
    }

    #[test]
    fn test_get_address_set_for_rows() {
        let mut manager = RegisterManager::new();
        manager.value_ranges = vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5),
            RegisterValueRange::from_range(addr(0x2000), addr(0x2fff), 10),
        ];
        let set = manager.get_address_set_for_rows(&[0, 1]);
        assert_eq!(set.len(), 2);
        assert_eq!(set[0].0, addr(0x1000));
        assert_eq!(set[1].0, addr(0x2000));
    }

    #[test]
    fn test_include_default_values() {
        let mut manager = RegisterManager::new();
        assert!(!manager.include_default_values());
        manager.set_include_default_values(true, None);
        assert!(manager.include_default_values());
    }

    #[test]
    fn test_set_location() {
        let mut manager = RegisterManager::new();
        manager.set_location(Some("EBX"), addr(0x5000));
        assert_eq!(manager.selected_register(), Some("EBX"));
        assert_eq!(manager.current_address, Some(addr(0x5000)));
    }

    #[test]
    fn test_set_program_none_clears() {
        let regs = vec![make_register("EAX", None)];
        let mut manager = RegisterManager::new();
        manager.set_program_with_data(&regs, None);
        assert_eq!(manager.tree().all_registers().len(), 1);
        manager.set_program(None);
        assert!(manager.tree().all_registers().is_empty());
    }
}
