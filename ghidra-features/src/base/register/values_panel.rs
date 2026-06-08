//! Register values panel — displays and edits register value ranges.
//!
//! Ported from `RegisterValuesPanel` in Ghidra's
//! `ghidra.app.plugin.core.register`.
//!
//! This module provides [`RegisterValuesPanel`], a data-oriented panel
//! that manages the display of register value address ranges for a
//! selected register. It supports:
//! - Populating value ranges from a [`ProgramContext`]
//! - Filtering by default/non-default values
//! - Selecting rows by address (for cursor navigation)
//! - Sorting by start address, end address, or value
//! - Building commands to set, clear, or update register values

use ghidra_core::addr::{Address, AddressSet};
use ghidra_core::program::lang::Register;

use super::commands::{CompoundRegisterCmd, SetRegisterValueCmd};
use super::value_range::{
    RegisterValueColumn, RegisterValueRange,
};

/// Sort direction for the register values table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    /// Sort ascending.
    Ascending,
    /// Sort descending.
    Descending,
}

/// A data-oriented register values panel.
///
/// Ported from `RegisterValuesPanel` in Java. Manages the list of
/// [`RegisterValueRange`]s for a selected register, providing sort,
/// filter, and command-building facilities.
#[derive(Debug)]
pub struct RegisterValuesPanel {
    /// The currently selected register.
    selected_register: Option<Register>,
    /// All value ranges (before filtering).
    all_ranges: Vec<RegisterValueRange>,
    /// Displayed value ranges (after filtering).
    display_ranges: Vec<RegisterValueRange>,
    /// Whether to show default values.
    show_defaults: bool,
    /// Currently selected row index (into `display_ranges`).
    selected_row: Option<usize>,
    /// Current sort column.
    sort_column: RegisterValueColumn,
    /// Current sort direction.
    sort_direction: SortDirection,
    /// Address set for the register's valid range.
    address_set: AddressSet,
}

impl RegisterValuesPanel {
    /// Create a new empty register values panel.
    pub fn new() -> Self {
        Self {
            selected_register: None,
            all_ranges: Vec::new(),
            display_ranges: Vec::new(),
            show_defaults: false,
            selected_row: None,
            sort_column: RegisterValueColumn::StartAddress,
            sort_direction: SortDirection::Ascending,
            address_set: AddressSet::new(),
        }
    }

    /// Set the selected register and populate value ranges.
    ///
    /// In a full implementation this queries the [`ProgramContext`] for
    /// the register's value address ranges. This version accepts
    /// pre-built ranges directly.
    pub fn set_register(
        &mut self,
        register: Register,
        ranges: Vec<RegisterValueRange>,
    ) {
        self.selected_register = Some(register);
        self.all_ranges = ranges;
        self.apply_filter_and_sort();
    }

    /// Clear the selection and all ranges.
    pub fn clear(&mut self) {
        self.selected_register = None;
        self.all_ranges.clear();
        self.display_ranges.clear();
        self.selected_row = None;
    }

    /// Get the selected register, if any.
    pub fn selected_register(&self) -> Option<&Register> {
        self.selected_register.as_ref()
    }

    /// Get the displayed (filtered/sorted) value ranges.
    pub fn display_ranges(&self) -> &[RegisterValueRange] {
        &self.display_ranges
    }

    /// Get the number of displayed rows.
    pub fn row_count(&self) -> usize {
        self.display_ranges.len()
    }

    /// Whether default values are currently shown.
    pub fn shows_defaults(&self) -> bool {
        self.show_defaults
    }

    /// Set whether to include default values in the display.
    pub fn set_show_defaults(&mut self, show: bool) {
        self.show_defaults = show;
        self.apply_filter_and_sort();
    }

    /// Get the currently selected row index.
    pub fn selected_row(&self) -> Option<usize> {
        self.selected_row
    }

    /// Select a row by index.
    pub fn select_row(&mut self, row: Option<usize>) {
        self.selected_row = row;
    }

    /// Select the row containing the given address.
    ///
    /// Returns the row index if found.
    pub fn select_by_address(&mut self, address: Address) -> Option<usize> {
        let row = self
            .display_ranges
            .iter()
            .position(|r| r.contains(&address));
        self.selected_row = row;
        row
    }

    /// Get the value at the currently selected row.
    pub fn selected_value(&self) -> Option<u64> {
        self.selected_row
            .and_then(|row| self.display_ranges.get(row))
            .map(|r| r.value())
    }

    /// Sort the display ranges by a given column.
    pub fn sort_by(&mut self, column: RegisterValueColumn) {
        if self.sort_column == column {
            self.sort_direction = match self.sort_direction {
                SortDirection::Ascending => SortDirection::Descending,
                SortDirection::Descending => SortDirection::Ascending,
            };
        } else {
            self.sort_column = column;
            self.sort_direction = SortDirection::Ascending;
        }
        self.apply_sort();
    }

    /// Get the current sort column.
    pub fn sort_column(&self) -> RegisterValueColumn {
        self.sort_column
    }

    /// Get the current sort direction.
    pub fn sort_direction(&self) -> SortDirection {
        self.sort_direction
    }

    /// Build a command to set a register value over the given address ranges.
    pub fn build_set_value_command(
        &self,
        value: u64,
        ranges: &[(Address, Address)],
    ) -> CompoundRegisterCmd {
        let reg_name = self
            .selected_register
            .as_ref()
            .map(|r| r.name.clone())
            .unwrap_or_default();
        let mut cmd = CompoundRegisterCmd::new(format!("Set {} Value", reg_name));
        for &(start, end) in ranges {
            cmd.add(SetRegisterValueCmd::new(&reg_name, start, end, Some(value)));
        }
        cmd
    }

    /// Build a command to clear (remove) the register values at the selected rows.
    pub fn build_clear_selected_command(&self) -> CompoundRegisterCmd {
        let reg_name = self
            .selected_register
            .as_ref()
            .map(|r| r.name.clone())
            .unwrap_or_default();
        let mut cmd = CompoundRegisterCmd::new(format!("Clear {} Values", reg_name));
        if let Some(row) = self.selected_row {
            if let Some(range) = self.display_ranges.get(row) {
                cmd.add(SetRegisterValueCmd::clear(
                    &reg_name,
                    range.start_address(),
                    range.end_address(),
                ));
            }
        }
        cmd
    }

    /// Build a command to update the value at the selected row.
    pub fn build_update_value_command(
        &self,
        new_value: u64,
    ) -> CompoundRegisterCmd {
        let reg_name = self
            .selected_register
            .as_ref()
            .map(|r| r.name.clone())
            .unwrap_or_default();
        let mut cmd = CompoundRegisterCmd::new(format!("Update {} Value", reg_name));
        if let Some(row) = self.selected_row {
            if let Some(range) = self.display_ranges.get(row) {
                // Clear old value
                cmd.add(SetRegisterValueCmd::clear(
                    &reg_name,
                    range.start_address(),
                    range.end_address(),
                ));
                // Set new value
                cmd.add(SetRegisterValueCmd::new(
                    &reg_name,
                    range.start_address(),
                    range.end_address(),
                    Some(new_value),
                ));
            }
        }
        cmd
    }

    /// Get the address set covering all displayed ranges.
    pub fn get_address_set(&self) -> AddressSet {
        let mut set = AddressSet::new();
        for range in &self.display_ranges {
            set.add_range(range.start_address(), range.end_address());
        }
        set
    }

    // ---- private helpers ----

    fn apply_filter_and_sort(&mut self) {
        self.display_ranges = if self.show_defaults {
            self.all_ranges.clone()
        } else {
            self.all_ranges.iter().filter(|r| !r.is_default()).cloned().collect()
        };
        self.apply_sort();
        // Clear selection if out of bounds
        if let Some(row) = self.selected_row {
            if row >= self.display_ranges.len() {
                self.selected_row = None;
            }
        }
    }

    fn apply_sort(&mut self) {
        let col = self.sort_column;
        let dir = self.sort_direction;
        self.display_ranges.sort_by(|a, b| {
            let ord = col.compare(a, b);
            match dir {
                SortDirection::Ascending => ord,
                SortDirection::Descending => ord.reverse(),
            }
        });
    }
}

impl Default for RegisterValuesPanel {
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
    use ghidra_core::program::lang::RegisterTypeFlags;
    use std::collections::HashSet;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn make_register(name: &str) -> Register {
        Register {
            name: name.to_string(),
            description: String::new(),
            group: None,
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
    fn test_new_panel_is_empty() {
        let panel = RegisterValuesPanel::new();
        assert_eq!(panel.row_count(), 0);
        assert!(panel.selected_register().is_none());
        assert!(panel.selected_row().is_none());
    }

    #[test]
    fn test_set_register_populates_ranges() {
        let mut panel = RegisterValuesPanel::new();
        let ranges = vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5),
            RegisterValueRange::from_range(addr(0x2000), addr(0x2fff), 10),
        ];
        panel.set_register(make_register("EAX"), ranges);
        assert_eq!(panel.row_count(), 2);
        assert!(panel.selected_register().is_some());
    }

    #[test]
    fn test_clear_resets_state() {
        let mut panel = RegisterValuesPanel::new();
        panel.set_register(
            make_register("EAX"),
            vec![RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5)],
        );
        panel.select_row(Some(0));
        panel.clear();
        assert_eq!(panel.row_count(), 0);
        assert!(panel.selected_register().is_none());
        assert!(panel.selected_row().is_none());
    }

    #[test]
    fn test_show_defaults_filter() {
        let mut panel = RegisterValuesPanel::new();
        let ranges = vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5),
            RegisterValueRange::default_range(addr(0x2000), addr(0x2fff), 0),
        ];
        panel.set_register(make_register("EAX"), ranges);
        assert_eq!(panel.row_count(), 1); // default filtered out
        panel.set_show_defaults(true);
        assert_eq!(panel.row_count(), 2);
    }

    #[test]
    fn test_select_by_address() {
        let mut panel = RegisterValuesPanel::new();
        let ranges = vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5),
            RegisterValueRange::from_range(addr(0x2000), addr(0x2fff), 10),
        ];
        panel.set_register(make_register("EAX"), ranges);
        // After sort by start ascending, range 0x1000..0x1fff is index 0
        assert_eq!(panel.display_ranges().len(), 2);
        assert_eq!(panel.display_ranges()[0].start_address(), addr(0x1000));
        assert_eq!(panel.display_ranges()[1].start_address(), addr(0x2000));
        assert_eq!(panel.select_by_address(addr(0x1500)), Some(0));
        assert_eq!(panel.selected_row(), Some(0));
        assert_eq!(panel.select_by_address(addr(0x2500)), Some(1));
        assert_eq!(panel.selected_row(), Some(1));
        assert_eq!(panel.select_by_address(addr(0x5000)), None);
        // When address not found, selected_row is cleared to None
        assert_eq!(panel.selected_row(), None);
    }

    #[test]
    fn test_selected_value() {
        let mut panel = RegisterValuesPanel::new();
        let ranges = vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 42),
        ];
        panel.set_register(make_register("EAX"), ranges);
        assert!(panel.selected_value().is_none()); // no row selected yet
        panel.select_row(Some(0));
        assert_eq!(panel.selected_value(), Some(42));
    }

    #[test]
    fn test_sort_by_column() {
        let mut panel = RegisterValuesPanel::new();
        let ranges = vec![
            RegisterValueRange::from_range(addr(0x2000), addr(0x2fff), 10),
            RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5),
        ];
        panel.set_register(make_register("EAX"), ranges);
        // Default sort is by start ascending
        assert_eq!(panel.display_ranges()[0].start_address(), addr(0x1000));

        // Toggle direction
        panel.sort_by(RegisterValueColumn::StartAddress);
        assert_eq!(panel.display_ranges()[0].start_address(), addr(0x2000));
    }

    #[test]
    fn test_sort_by_value() {
        let mut panel = RegisterValuesPanel::new();
        let ranges = vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 100),
            RegisterValueRange::from_range(addr(0x2000), addr(0x2fff), 5),
        ];
        panel.set_register(make_register("EAX"), ranges);
        panel.sort_by(RegisterValueColumn::Value);
        assert_eq!(panel.display_ranges()[0].value(), 5);
    }

    #[test]
    fn test_build_set_value_command() {
        let mut panel = RegisterValuesPanel::new();
        panel.set_register(
            make_register("EAX"),
            vec![RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 0)],
        );
        let cmd = panel.build_set_value_command(99, &[(addr(0x1000), addr(0x1fff))]);
        assert_eq!(cmd.len(), 1);
    }

    #[test]
    fn test_build_clear_selected_command() {
        let mut panel = RegisterValuesPanel::new();
        let ranges = vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5),
        ];
        panel.set_register(make_register("EAX"), ranges);
        panel.select_row(Some(0));
        let cmd = panel.build_clear_selected_command();
        assert_eq!(cmd.len(), 1);
        assert_eq!(cmd.commands()[0].value(), None); // clear
    }

    #[test]
    fn test_build_update_value_command() {
        let mut panel = RegisterValuesPanel::new();
        let ranges = vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5),
        ];
        panel.set_register(make_register("EAX"), ranges);
        panel.select_row(Some(0));
        let cmd = panel.build_update_value_command(99);
        assert_eq!(cmd.len(), 2);
        assert_eq!(cmd.commands()[0].value(), None); // clear
        assert_eq!(cmd.commands()[1].value(), Some(99)); // set
    }

    #[test]
    fn test_get_address_set() {
        let mut panel = RegisterValuesPanel::new();
        let ranges = vec![
            RegisterValueRange::from_range(addr(0x1000), addr(0x1fff), 5),
            RegisterValueRange::from_range(addr(0x3000), addr(0x3fff), 10),
        ];
        panel.set_register(make_register("EAX"), ranges);
        let set = panel.get_address_set();
        assert!(set.contains(&addr(0x1000)));
        assert!(set.contains(&addr(0x3000)));
        assert!(!set.contains(&addr(0x2000)));
    }

    #[test]
    fn test_default_panel() {
        let panel = RegisterValuesPanel::default();
        assert_eq!(panel.row_count(), 0);
        assert_eq!(panel.sort_column(), RegisterValueColumn::StartAddress);
        assert_eq!(panel.sort_direction(), SortDirection::Ascending);
    }
}
