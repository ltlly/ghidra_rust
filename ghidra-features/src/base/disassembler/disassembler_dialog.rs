//! Disassembler dialogs -- ported from Ghidra's
//! `ProcessorStateDialog.java`, `SetFlowOverrideDialog.java`, and
//! `AddressTableDialog.java`.
//!
//! This module provides dialog data models for the disassembler UI:
//!
//! - [`ProcessorStateDialog`] -- edit default disassembly context registers
//! - [`SetFlowOverrideDialog`] -- change instruction flow override
//! - [`AddressTableSearchDialog`] -- search for address tables and
//!   disassemble from them
//!
//! In a headless Rust implementation these are pure data models; a GUI
//! layer would render them into actual dialog windows.

use crate::base::analyzer::core::*;
use crate::base::disassembler::address_table::{AddressTable, AddressTableOptions};
use crate::base::disassembler::flow_override::FlowOverride;

// ---------------------------------------------------------------------------
// ProcessorStateDialog
// ---------------------------------------------------------------------------

/// Dialog for specifying processor disassembly options (context
/// registers).
///
/// Ported from Ghidra's `ProcessorStateDialog.java`.  In Ghidra this
/// dialog is shown when the user selects "Set Default Context" from the
/// disassembler menu.  It displays all context registers of the
/// current program and lets the user edit their default values.
///
/// In this Rust port the dialog is a data model that holds the
/// register state; rendering is left to the GUI layer.
#[derive(Debug, Clone)]
pub struct ProcessorStateDialog {
    /// Title of the dialog.
    pub title: String,
    /// The context registers available for editing.
    pub registers: Vec<ContextRegisterEntry>,
    /// Whether the dialog result has been accepted (OK).
    pub accepted: bool,
    /// The display radix for register values (10 or 16).
    pub radix: u32,
}

/// A single context register entry displayed in the dialog.
#[derive(Debug, Clone)]
pub struct ContextRegisterEntry {
    /// Register name.
    pub name: String,
    /// Register description.
    pub description: String,
    /// Bit width of the register.
    pub bit_length: u32,
    /// Current default value.
    pub value: u64,
    /// Whether this is a base register (excluded from the dialog).
    pub is_base_register: bool,
}

impl ProcessorStateDialog {
    /// Create a new processor state dialog from a list of context
    /// registers.
    pub fn new(registers: Vec<ContextRegisterEntry>) -> Self {
        Self {
            title: "Specify Processor Disassembly Options".to_string(),
            registers,
            accepted: false,
            radix: 16,
        }
    }

    /// Create a dialog from a program's language context registers.
    ///
    /// In Ghidra this iterates over
    /// `programContext.getContextRegisters()` and skips the base
    /// register.  Here we accept pre-filtered entries.
    pub fn from_program(program: &Program) -> Self {
        // In a full implementation, this would query the program's
        // language for context registers.  For now we create an
        // empty dialog.
        let _ = program;
        Self::new(Vec::new())
    }

    /// Get the number of editable registers.
    pub fn register_count(&self) -> usize {
        self.registers.iter().filter(|r| !r.is_base_register).count()
    }

    /// Set the display radix (10 for decimal, 16 for hex).
    pub fn set_radix(&mut self, radix: u32) {
        assert!(radix == 10 || radix == 16, "radix must be 10 or 16");
        self.radix = radix;
    }

    /// Update the value of a register by name.
    pub fn set_register_value(&mut self, name: &str, value: u64) {
        if let Some(reg) = self.registers.iter_mut().find(|r| r.name == name) {
            reg.value = value;
        }
    }

    /// Get the value of a register by name.
    pub fn get_register_value(&self, name: &str) -> Option<u64> {
        self.registers
            .iter()
            .find(|r| r.name == name)
            .map(|r| r.value)
    }

    /// Accept the dialog (OK button pressed).
    pub fn accept(&mut self) {
        self.accepted = true;
    }

    /// Cancel the dialog.
    pub fn cancel(&mut self) {
        self.accepted = false;
    }

    /// Check if the dialog was accepted.
    pub fn is_accepted(&self) -> bool {
        self.accepted
    }

    /// Get the edited register values as a vector of (name, value)
    /// pairs.  Only non-base registers are included.
    pub fn edited_values(&self) -> Vec<(&str, u64)> {
        self.registers
            .iter()
            .filter(|r| !r.is_base_register)
            .map(|r| (r.name.as_str(), r.value))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// SetFlowOverrideDialog
// ---------------------------------------------------------------------------

/// Dialog for modifying instruction flow override.
///
/// Ported from Ghidra's `SetFlowOverrideDialog.java`.  This dialog
/// lets the user change how an instruction's control flow is
/// interpreted (e.g., changing a call to a no-return).
///
/// Two modes are supported:
/// 1. Single-instruction mode: modify the flow of a specific instruction.
/// 2. Selection mode: modify the flow of all instructions in a
///    selection.
#[derive(Debug, Clone)]
pub struct SetFlowOverrideDialog {
    /// Title of the dialog.
    pub title: String,
    /// The current flow override selection.
    pub selected_override: FlowOverrideChoice,
    /// The current flow type of the instruction (for display).
    pub current_flow_name: Option<String>,
    /// Whether the current flow is conditional.
    pub current_flow_conditional: bool,
    /// The available override choices.
    pub choices: Vec<FlowOverrideChoice>,
    /// Whether the dialog result has been accepted (OK).
    pub accepted: bool,
    /// The address of the instruction being modified (single mode).
    pub instruction_address: Option<Address>,
    /// Whether this is a selection-based modification.
    pub is_selection_mode: bool,
}

/// A choice in the flow override combo box.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowOverrideChoice {
    /// Use the default flow (no override).
    Default,
    /// A specific flow override.
    Override(FlowOverride),
}

impl FlowOverrideChoice {
    /// Get the display name for this choice.
    pub fn display_name(&self) -> &'static str {
        match self {
            FlowOverrideChoice::Default => "-DEFAULT-",
            FlowOverrideChoice::Override(o) => o.display_name(),
        }
    }

    /// Convert this choice to a `FlowOverride`.
    pub fn to_flow_override(&self) -> FlowOverride {
        match self {
            FlowOverrideChoice::Default => FlowOverride::None,
            FlowOverrideChoice::Override(o) => *o,
        }
    }
}

impl SetFlowOverrideDialog {
    /// Create a dialog for a single instruction.
    pub fn for_instruction(
        addr: Address,
        current_flow_name: Option<String>,
        current_flow_conditional: bool,
        current_override: Option<FlowOverride>,
    ) -> Self {
        let choices = Self::build_choices();
        let selected_override = match current_override {
            None => FlowOverrideChoice::Default,
            Some(FlowOverride::None) => FlowOverrideChoice::Default,
            Some(o) => FlowOverrideChoice::Override(o),
        };
        Self {
            title: format!("Modify Instruction Flow: {:#x}", addr.offset),
            selected_override,
            current_flow_name,
            current_flow_conditional,
            choices,
            accepted: false,
            instruction_address: Some(addr),
            is_selection_mode: false,
        }
    }

    /// Create a dialog for a selection of instructions.
    pub fn for_selection() -> Self {
        let choices = Self::build_choices();
        Self {
            title: "Modify Instruction Flow on Selection".to_string(),
            selected_override: FlowOverrideChoice::Default,
            current_flow_name: None,
            current_flow_conditional: false,
            choices,
            accepted: false,
            instruction_address: None,
            is_selection_mode: true,
        }
    }

    /// Build the list of available override choices.
    fn build_choices() -> Vec<FlowOverrideChoice> {
        let mut choices = vec![FlowOverrideChoice::Default];
        for variant in &[
            FlowOverride::CallReturn,
            FlowOverride::CallNoReturn,
            FlowOverride::NoFlow,
            FlowOverride::Jump,
            FlowOverride::Fallthrough,
        ] {
            choices.push(FlowOverrideChoice::Override(*variant));
        }
        choices
    }

    /// Set the selected override choice.
    pub fn set_selected(&mut self, choice: FlowOverrideChoice) {
        self.selected_override = choice;
    }

    /// Get the resolved `FlowOverride` to apply.
    pub fn resolved_override(&self) -> FlowOverride {
        self.selected_override.to_flow_override()
    }

    /// Accept the dialog (OK button pressed).
    pub fn accept(&mut self) {
        self.accepted = true;
    }

    /// Cancel the dialog.
    pub fn cancel(&mut self) {
        self.accepted = false;
    }

    /// Check if the dialog was accepted.
    pub fn is_accepted(&self) -> bool {
        self.accepted
    }
}

// ---------------------------------------------------------------------------
// AddressTableSearchDialog
// ---------------------------------------------------------------------------

/// Dialog for searching address tables and disassembling from them.
///
/// Ported from Ghidra's `AddressTableDialog.java`.  Provides search
/// options (minimum table length, alignment, skip length, shifted
/// addresses) and action buttons (Search, Make Table, Disassemble).
#[derive(Debug, Clone)]
pub struct AddressTableSearchDialog {
    /// Title of the dialog.
    pub title: String,
    /// Search options.
    pub options: AddressTableSearchOptions,
    /// Whether to search only the current selection.
    pub search_selection: bool,
    /// Discovered address tables.
    pub results: Vec<AddressTable>,
    /// Indices of the currently selected result rows.
    pub selected_rows: Vec<usize>,
    /// Whether auto-labeling is enabled.
    pub auto_label: bool,
    /// Offset from the beginning of selected tables.
    pub offset: i32,
    /// Whether the dialog is currently showing.
    pub visible: bool,
    /// Status text displayed in the dialog.
    pub status_text: String,
}

/// Options for the address table search.
#[derive(Debug, Clone)]
pub struct AddressTableSearchOptions {
    /// Minimum number of consecutive addresses to form a table.
    pub min_length: usize,
    /// Alignment that tables and their targets must satisfy.
    pub alignment: usize,
    /// Number of bytes to skip between found addresses.
    pub skip_length: usize,
    /// Whether to search for shifted addresses.
    pub shifted_addresses: bool,
}

impl Default for AddressTableSearchOptions {
    fn default() -> Self {
        Self {
            min_length: 3,
            alignment: 1,
            skip_length: 0,
            shifted_addresses: false,
        }
    }
}

impl AddressTableSearchDialog {
    /// Create a new address table search dialog.
    pub fn new() -> Self {
        Self {
            title: "Search For Address Tables".to_string(),
            options: AddressTableSearchOptions::default(),
            search_selection: false,
            results: Vec::new(),
            selected_rows: Vec::new(),
            auto_label: true,
            offset: 0,
            visible: false,
            status_text: String::new(),
        }
    }

    /// Create a dialog with program-specific defaults (e.g.,
    /// alignment from the language).
    pub fn with_program(program: &Program) -> Self {
        let mut dialog = Self::new();
        dialog.options.alignment = 1; // default instruction alignment
        let _ = program;
        dialog
    }

    /// Show the dialog.
    pub fn show(&mut self) {
        self.visible = true;
        self.status_text.clear();
    }

    /// Close the dialog.
    pub fn close(&mut self) {
        self.visible = false;
        self.selected_rows.clear();
    }

    /// Check if the dialog is currently visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set the search results.
    pub fn set_results(&mut self, results: Vec<AddressTable>) {
        self.results = results;
        self.selected_rows.clear();
        if self.results.is_empty() {
            self.status_text = "No address tables found.".to_string();
        } else {
            self.status_text = format!("Found {} address tables.", self.results.len());
        }
    }

    /// Select rows in the results table.
    pub fn select_rows(&mut self, rows: Vec<usize>) {
        self.selected_rows = rows;
    }

    /// Get the selected address tables.
    pub fn selected_tables(&self) -> Vec<&AddressTable> {
        self.selected_rows
            .iter()
            .filter_map(|&i| self.results.get(i))
            .collect()
    }

    /// Clear the search results and reset the dialog state.
    pub fn clear_results(&mut self) {
        self.results.clear();
        self.selected_rows.clear();
        self.offset = 0;
        self.status_text.clear();
    }

    /// Update the status text.
    pub fn set_status_text(&mut self, text: impl Into<String>) {
        self.status_text = text.into();
    }

    /// Set whether the search is limited to the current selection.
    pub fn set_search_selection(&mut self, selection: bool) {
        self.search_selection = selection;
    }

    /// Get the minimum table length from the options.
    pub fn min_table_size(&self) -> usize {
        self.options.min_length
    }

    /// Get the alignment from the options.
    pub fn alignment(&self) -> usize {
        self.options.alignment
    }

    /// Get the skip length from the options.
    pub fn skip_length(&self) -> usize {
        self.options.skip_length
    }

    /// Whether shifted address search is enabled.
    pub fn shifted_addresses(&self) -> bool {
        self.options.shifted_addresses
    }

    /// Whether automatic labeling is enabled.
    pub fn automatic_label(&self) -> bool {
        self.auto_label
    }

    /// Get the current offset.
    pub fn get_offset(&self) -> i32 {
        self.offset
    }

    /// Set the offset.
    pub fn set_offset(&mut self, offset: i32) {
        self.offset = offset;
    }

    /// Whether to search only the current selection.
    pub fn is_search_selection(&self) -> bool {
        self.search_selection
    }
}

impl Default for AddressTableSearchDialog {
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
    fn test_processor_state_dialog_creation() {
        let registers = vec![
            ContextRegisterEntry {
                name: "TMode".to_string(),
                description: "Thumb mode".to_string(),
                bit_length: 1,
                value: 0,
                is_base_register: false,
            },
            ContextRegisterEntry {
                name: "ISAMode".to_string(),
                description: "ISA mode".to_string(),
                bit_length: 2,
                value: 1,
                is_base_register: false,
            },
        ];
        let dialog = ProcessorStateDialog::new(registers);
        assert_eq!(dialog.title, "Specify Processor Disassembly Options");
        assert_eq!(dialog.register_count(), 2);
        assert!(!dialog.is_accepted());
        assert_eq!(dialog.radix, 16);
    }

    #[test]
    fn test_processor_state_dialog_values() {
        let registers = vec![ContextRegisterEntry {
            name: "TMode".to_string(),
            description: "Thumb mode".to_string(),
            bit_length: 1,
            value: 0,
            is_base_register: false,
        }];
        let mut dialog = ProcessorStateDialog::new(registers);
        assert_eq!(dialog.get_register_value("TMode"), Some(0));
        dialog.set_register_value("TMode", 1);
        assert_eq!(dialog.get_register_value("TMode"), Some(1));
        assert_eq!(dialog.get_register_value("nonexistent"), None);
    }

    #[test]
    fn test_processor_state_dialog_accept_cancel() {
        let mut dialog = ProcessorStateDialog::new(Vec::new());
        dialog.accept();
        assert!(dialog.is_accepted());
        dialog.cancel();
        assert!(!dialog.is_accepted());
    }

    #[test]
    fn test_processor_state_dialog_radix() {
        let mut dialog = ProcessorStateDialog::new(Vec::new());
        dialog.set_radix(10);
        assert_eq!(dialog.radix, 10);
        dialog.set_radix(16);
        assert_eq!(dialog.radix, 16);
    }

    #[test]
    #[should_panic(expected = "radix must be 10 or 16")]
    fn test_processor_state_dialog_invalid_radix() {
        let mut dialog = ProcessorStateDialog::new(Vec::new());
        dialog.set_radix(8);
    }

    #[test]
    fn test_processor_state_dialog_edited_values() {
        let registers = vec![
            ContextRegisterEntry {
                name: "TMode".to_string(),
                description: "Thumb mode".to_string(),
                bit_length: 1,
                value: 0,
                is_base_register: false,
            },
            ContextRegisterEntry {
                name: "CPSR".to_string(),
                description: "Base register".to_string(),
                bit_length: 32,
                value: 0,
                is_base_register: true,
            },
        ];
        let dialog = ProcessorStateDialog::new(registers);
        let edited = dialog.edited_values();
        assert_eq!(edited.len(), 1);
        assert_eq!(edited[0].0, "TMode");
    }

    #[test]
    fn test_set_flow_override_dialog_instruction() {
        let dialog = SetFlowOverrideDialog::for_instruction(
            Address::new(0x400000),
            Some("CALL".to_string()),
            false,
            None,
        );
        assert!(dialog.title.contains("400000"));
        assert_eq!(dialog.selected_override, FlowOverrideChoice::Default);
        assert!(!dialog.is_selection_mode);
        assert_eq!(dialog.instruction_address, Some(Address::new(0x400000)));
        assert!(!dialog.is_accepted());
        assert_eq!(dialog.choices.len(), 6); // Default + 5 overrides
    }

    #[test]
    fn test_set_flow_override_dialog_selection() {
        let dialog = SetFlowOverrideDialog::for_selection();
        assert!(dialog.title.contains("Selection"));
        assert!(dialog.is_selection_mode);
        assert_eq!(dialog.instruction_address, None);
    }

    #[test]
    fn test_set_flow_override_dialog_accept() {
        let mut dialog = SetFlowOverrideDialog::for_selection();
        dialog.accept();
        assert!(dialog.is_accepted());
        dialog.cancel();
        assert!(!dialog.is_accepted());
    }

    #[test]
    fn test_set_flow_override_dialog_set_selected() {
        let mut dialog = SetFlowOverrideDialog::for_selection();
        dialog.set_selected(FlowOverrideChoice::Override(FlowOverride::CallNoReturn));
        assert_eq!(
            dialog.resolved_override(),
            FlowOverride::CallNoReturn
        );
    }

    #[test]
    fn test_flow_override_choice_display() {
        assert_eq!(FlowOverrideChoice::Default.display_name(), "-DEFAULT-");
        assert_eq!(
            FlowOverrideChoice::Override(FlowOverride::CallNoReturn).display_name(),
            "Call No Return"
        );
    }

    #[test]
    fn test_flow_override_choice_to_flow_override() {
        assert_eq!(
            FlowOverrideChoice::Default.to_flow_override(),
            FlowOverride::None
        );
        assert_eq!(
            FlowOverrideChoice::Override(FlowOverride::Jump).to_flow_override(),
            FlowOverride::Jump
        );
    }

    #[test]
    fn test_address_table_search_dialog_creation() {
        let dialog = AddressTableSearchDialog::new();
        assert_eq!(dialog.title, "Search For Address Tables");
        assert!(!dialog.is_visible());
        assert!(dialog.results.is_empty());
        assert!(dialog.selected_rows.is_empty());
        assert!(dialog.automatic_label());
        assert_eq!(dialog.min_table_size(), 3);
        assert_eq!(dialog.alignment(), 1);
        assert_eq!(dialog.skip_length(), 0);
        assert!(!dialog.shifted_addresses());
        assert!(!dialog.is_search_selection());
        assert_eq!(dialog.get_offset(), 0);
    }

    #[test]
    fn test_address_table_search_dialog_show_close() {
        let mut dialog = AddressTableSearchDialog::new();
        dialog.show();
        assert!(dialog.is_visible());
        dialog.close();
        assert!(!dialog.is_visible());
    }

    #[test]
    fn test_address_table_search_dialog_results() {
        let mut dialog = AddressTableSearchDialog::new();
        let elements: Vec<Address> = (0..10).map(|i| Address::new(0x2000 + i * 4)).collect();
        let table = AddressTable::new(Address::new(0x1000), elements, 4, 0, false);
        dialog.set_results(vec![table]);
        assert_eq!(dialog.results.len(), 1);
        assert!(dialog.status_text.contains("Found 1"));
    }

    #[test]
    fn test_address_table_search_dialog_selection() {
        let mut dialog = AddressTableSearchDialog::new();
        let e1: Vec<Address> = (0..10).map(|i| Address::new(0x3000 + i * 4)).collect();
        let e2: Vec<Address> = (0..5).map(|i| Address::new(0x4000 + i * 4)).collect();
        let t1 = AddressTable::new(Address::new(0x1000), e1, 4, 0, false);
        let t2 = AddressTable::new(Address::new(0x2000), e2, 4, 0, false);
        dialog.set_results(vec![t1, t2]);
        dialog.select_rows(vec![1]);
        let selected = dialog.selected_tables();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].top_address, Address::new(0x2000));
    }

    #[test]
    fn test_address_table_search_dialog_clear() {
        let mut dialog = AddressTableSearchDialog::new();
        let elements: Vec<Address> = (0..10).map(|i| Address::new(0x2000 + i * 4)).collect();
        let table = AddressTable::new(Address::new(0x1000), elements, 4, 0, false);
        dialog.set_results(vec![table]);
        dialog.set_offset(5);
        dialog.clear_results();
        assert!(dialog.results.is_empty());
        assert!(dialog.selected_rows.is_empty());
        assert_eq!(dialog.get_offset(), 0);
    }

    #[test]
    fn test_address_table_search_dialog_options() {
        let mut dialog = AddressTableSearchDialog::new();
        dialog.options.min_length = 5;
        dialog.options.alignment = 4;
        dialog.options.skip_length = 2;
        dialog.options.shifted_addresses = true;
        dialog.search_selection = true;
        dialog.auto_label = false;
        dialog.set_offset(10);

        assert_eq!(dialog.min_table_size(), 5);
        assert_eq!(dialog.alignment(), 4);
        assert_eq!(dialog.skip_length(), 2);
        assert!(dialog.shifted_addresses());
        assert!(dialog.is_search_selection());
        assert!(!dialog.automatic_label());
        assert_eq!(dialog.get_offset(), 10);
    }

    #[test]
    fn test_address_table_search_dialog_status_text() {
        let mut dialog = AddressTableSearchDialog::new();
        dialog.set_status_text("Searching...");
        assert_eq!(dialog.status_text, "Searching...");
    }

    #[test]
    fn test_address_table_search_dialog_empty_results() {
        let mut dialog = AddressTableSearchDialog::new();
        dialog.set_results(Vec::new());
        assert!(dialog.status_text.contains("No address tables"));
    }

    #[test]
    fn test_address_table_search_options_default() {
        let opts = AddressTableSearchOptions::default();
        assert_eq!(opts.min_length, 3);
        assert_eq!(opts.alignment, 1);
        assert_eq!(opts.skip_length, 0);
        assert!(!opts.shifted_addresses);
    }
}
