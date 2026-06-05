// ===========================================================================
// Flow Override -- ported from Ghidra's
// `ghidra.app.plugin.core.disassembler` package.
//
// Includes:
// - SetFlowOverrideAction    -- action to override control flow type
// - SetFlowOverrideDialog    -- dialog model for selecting overrides
// - SetLengthOverrideAction  -- action to override instruction length
// - FlowOverride             -- the override types
// - ContextAction            -- context register modification action
// ===========================================================================

use ghidra_core::Address;

/// The type of flow override applied to an instruction.
///
/// Ported from `ghidra.app.plugin.core.disassembler.FlowOverride` (Java enum).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowOverride {
    /// No override -- use the default flow.
    None,
    /// Override to always call (CALL).
    Call,
    /// Override to always return (RETURN).
    Return,
    /// Override to always jump (JUMP).
    Jump,
    /// Override to always fall through.
    FallThrough,
}

impl FlowOverride {
    /// Display name for the override.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::None => "Default",
            Self::Call => "Call Override",
            Self::Return => "Return Override",
            Self::Jump => "Jump Override",
            Self::FallThrough => "Fall Through Override",
        }
    }

    /// All available overrides (including None).
    pub fn all() -> &'static [FlowOverride] {
        &[
            Self::None,
            Self::Call,
            Self::Return,
            Self::Jump,
            Self::FallThrough,
        ]
    }
}

impl Default for FlowOverride {
    fn default() -> Self {
        Self::None
    }
}

// ---------------------------------------------------------------------------
// SetFlowOverrideAction
// ---------------------------------------------------------------------------

/// Action that sets a flow override on one or more instructions.
///
/// Ported from `ghidra.app.plugin.core.disassembler.SetFlowOverrideAction`.
#[derive(Debug, Clone)]
pub struct SetFlowOverrideAction {
    /// The name of this action.
    pub name: String,
    /// The flow override to apply.
    pub override_type: FlowOverride,
    /// Target addresses.
    pub targets: Vec<Address>,
    /// Popup menu description.
    pub popup_description: String,
}

impl SetFlowOverrideAction {
    /// Create a new action.
    pub fn new(override_type: FlowOverride) -> Self {
        Self {
            name: format!("Set Flow Override: {}", override_type.display_name()),
            override_type,
            targets: Vec::new(),
            popup_description: format!(
                "Override control flow to {}",
                override_type.display_name()
            ),
        }
    }

    /// Add a target address.
    pub fn add_target(&mut self, addr: Address) {
        self.targets.push(addr);
    }

    /// Set multiple target addresses.
    pub fn set_targets(&mut self, addrs: Vec<Address>) {
        self.targets = addrs;
    }

    /// Generate the set of override requests.
    pub fn generate_requests(&self) -> Vec<FlowOverrideRequest> {
        self.targets
            .iter()
            .map(|addr| FlowOverrideRequest {
                address: *addr,
                override_type: self.override_type,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// FlowOverrideRequest
// ---------------------------------------------------------------------------

/// A pending flow override request for an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowOverrideRequest {
    /// The address of the instruction.
    pub address: Address,
    /// The override to apply.
    pub override_type: FlowOverride,
}

// ---------------------------------------------------------------------------
// SetFlowOverrideDialog
// ---------------------------------------------------------------------------

/// Dialog model for selecting a flow override.
///
/// Ported from `ghidra.app.plugin.core.disassembler.SetFlowOverrideDialog`.
#[derive(Debug, Clone)]
pub struct SetFlowOverrideDialog {
    /// The currently selected override.
    pub selected: FlowOverride,
    /// The current flow override on the selected instruction(s), if any.
    pub current_override: FlowOverride,
    /// Whether the selection is valid.
    pub valid: bool,
}

impl SetFlowOverrideDialog {
    /// Create a new dialog model.
    pub fn new(current_override: FlowOverride) -> Self {
        Self {
            selected: current_override,
            current_override,
            valid: true,
        }
    }

    /// Set the selected override.
    pub fn set_selected(&mut self, override_type: FlowOverride) {
        self.selected = override_type;
    }

    /// Confirm the selection.
    pub fn confirm(&self) -> Option<FlowOverride> {
        if self.valid && self.selected != self.current_override {
            Some(self.selected)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// SetLengthOverrideAction
// ---------------------------------------------------------------------------

/// Action that overrides the length of an instruction.
///
/// Ported from `ghidra.app.plugin.core.disassembler.SetLengthOverrideAction`.
#[derive(Debug, Clone)]
pub struct SetLengthOverrideAction {
    /// The name of this action.
    pub name: String,
    /// Target address.
    pub target: Address,
    /// The new length (0 = remove override).
    pub new_length: u32,
}

impl SetLengthOverrideAction {
    /// Create a new action.
    pub fn new(target: Address, new_length: u32) -> Self {
        Self {
            name: "Set Instruction Length Override".into(),
            target,
            new_length,
        }
    }

    /// Generate a length override request.
    pub fn generate_request(&self) -> LengthOverrideRequest {
        LengthOverrideRequest {
            address: self.target,
            new_length: self.new_length,
        }
    }
}

/// A pending length override request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LengthOverrideRequest {
    /// The address of the instruction.
    pub address: Address,
    /// The new length (0 = remove override).
    pub new_length: u32,
}

// ---------------------------------------------------------------------------
// ContextAction
// ---------------------------------------------------------------------------

/// Action that modifies a context register value at a specific address.
///
/// Ported from `ghidra.app.plugin.core.disassembler.ContextAction`.
#[derive(Debug, Clone)]
pub struct ContextAction {
    /// The name of this action.
    pub name: String,
    /// The address where the context change applies.
    pub address: Address,
    /// The context register name.
    pub register: String,
    /// The new value.
    pub value: u32,
    /// The mask for which bits to change.
    pub mask: u32,
}

impl ContextAction {
    /// Create a new context action.
    pub fn new(
        address: Address,
        register: impl Into<String>,
        value: u32,
        mask: u32,
    ) -> Self {
        let reg = register.into();
        Self {
            name: format!("Set Context: {}", reg),
            address,
            register: reg,
            value,
            mask,
        }
    }

    /// Apply the context change to a current value.
    pub fn apply_to(&self, current: u32) -> u32 {
        (current & !self.mask) | (self.value & self.mask)
    }
}

// ---------------------------------------------------------------------------
// ProcessorStateDialog
// ---------------------------------------------------------------------------

/// Dialog model for viewing and editing processor state at an address.
///
/// Ported from `ghidra.app.plugin.core.disassembler.ProcessorStateDialog`.
#[derive(Debug, Clone)]
pub struct ProcessorStateDialog {
    /// The address being inspected.
    pub address: Address,
    /// Register name -> value.
    pub registers: Vec<(String, u32)>,
    /// Whether any register values have been modified.
    pub modified: bool,
}

impl ProcessorStateDialog {
    /// Create a new dialog.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            registers: Vec::new(),
            modified: false,
        }
    }

    /// Add a register value.
    pub fn add_register(&mut self, name: impl Into<String>, value: u32) {
        self.registers.push((name.into(), value));
    }

    /// Modify a register value.
    pub fn set_register(&mut self, name: &str, value: u32) {
        if let Some(entry) = self.registers.iter_mut().find(|(n, _)| n == name) {
            entry.1 = value;
            self.modified = true;
        }
    }

    /// Get a register value by name.
    pub fn get_register(&self, name: &str) -> Option<u32> {
        self.registers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| *v)
    }
}

// ---------------------------------------------------------------------------
// StaticDisassembleAction
// ---------------------------------------------------------------------------

/// Action for performing a static (non-modifying) disassembly of bytes.
///
/// Ported from `ghidra.app.plugin.core.disassembler.StaticDisassembleAction`.
#[derive(Debug, Clone)]
pub struct StaticDisassembleAction {
    /// The name of this action.
    pub name: String,
    /// Start address.
    pub start_address: Address,
    /// Number of bytes to disassemble.
    pub byte_count: usize,
    /// Disassembly results: address -> mnemonic + operands.
    pub results: Vec<(Address, String)>,
}

impl StaticDisassembleAction {
    /// Create a new action.
    pub fn new(start_address: Address, byte_count: usize) -> Self {
        Self {
            name: "Static Disassemble".into(),
            start_address,
            byte_count,
            results: Vec::new(),
        }
    }

    /// Add a disassembly result.
    pub fn add_result(&mut self, addr: Address, text: impl Into<String>) {
        self.results.push((addr, text.into()));
    }
}

// ---------------------------------------------------------------------------
// RestrictedDisassembleAction
// ---------------------------------------------------------------------------

/// Action that disassembles with restricted flow (only at the specified
/// address, without following branches).
///
/// Ported from `ghidra.app.plugin.core.disassembler.RestrictedDisassembleAction`.
#[derive(Debug, Clone)]
pub struct RestrictedDisassembleAction {
    /// The name of this action.
    pub name: String,
    /// The target address.
    pub address: Address,
    /// Whether to follow fall-throughs only (not branches).
    pub fall_through_only: bool,
    /// Maximum number of instructions to disassemble.
    pub max_instructions: usize,
}

impl RestrictedDisassembleAction {
    /// Create a new action.
    pub fn new(address: Address) -> Self {
        Self {
            name: "Restricted Disassemble".into(),
            address,
            fall_through_only: true,
            max_instructions: 1,
        }
    }

    /// Set maximum instructions to disassemble.
    pub fn set_max_instructions(&mut self, max: usize) {
        self.max_instructions = max;
    }
}

// ---------------------------------------------------------------------------
// DisassembledViewPlugin
// ---------------------------------------------------------------------------

/// Plugin for viewing disassembled output in a standalone window.
///
/// Ported from `ghidra.app.plugin.core.disassembler.DisassembledViewPlugin`.
#[derive(Debug, Clone)]
pub struct DisassembledViewPlugin {
    /// Whether the view is open.
    pub is_open: bool,
    /// The current address being viewed.
    pub current_address: Address,
    /// The disassembly text lines.
    pub lines: Vec<DisassemblyLine>,
}

/// A single line of disassembly output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisassemblyLine {
    /// The address.
    pub address: Address,
    /// The bytes.
    pub bytes: Vec<u8>,
    /// The mnemonic.
    pub mnemonic: String,
    /// The operands.
    pub operands: String,
    /// The full text representation.
    pub full_text: String,
}

impl DisassembledViewPlugin {
    /// Create a new plugin.
    pub fn new() -> Self {
        Self {
            is_open: false,
            current_address: Address::new(0),
            lines: Vec::new(),
        }
    }

    /// Open the view at a specific address.
    pub fn open(&mut self, addr: Address) {
        self.is_open = true;
        self.current_address = addr;
    }

    /// Close the view.
    pub fn close(&mut self) {
        self.is_open = false;
    }

    /// Add a disassembly line.
    pub fn add_line(&mut self, line: DisassemblyLine) {
        self.lines.push(line);
    }
}

impl Default for DisassembledViewPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AddressTableDialog
// ---------------------------------------------------------------------------

/// Dialog model for configuring address table disassembly.
///
/// Ported from `ghidra.app.plugin.core.disassembler.AddressTableDialog`.
#[derive(Debug, Clone)]
pub struct AddressTableDialog {
    /// The start address of the table.
    pub start_address: Address,
    /// Number of entries.
    pub entry_count: u32,
    /// Pointer size in bytes.
    pub pointer_size: u8,
    /// Whether entries are relative offsets.
    pub is_relative: bool,
    /// Whether to automatically follow table entries.
    pub auto_follow: bool,
    /// Whether to create labels at table targets.
    pub create_labels: bool,
    /// Whether to disassemble at table targets.
    pub disassemble_targets: bool,
}

impl AddressTableDialog {
    /// Create a new dialog with defaults.
    pub fn new(start_address: Address) -> Self {
        Self {
            start_address,
            entry_count: 0,
            pointer_size: 4,
            is_relative: false,
            auto_follow: true,
            create_labels: true,
            disassemble_targets: true,
        }
    }

    /// Set the table parameters.
    pub fn configure(
        &mut self,
        entry_count: u32,
        pointer_size: u8,
        is_relative: bool,
    ) {
        self.entry_count = entry_count;
        self.pointer_size = pointer_size;
        self.is_relative = is_relative;
    }

    /// Calculate the end address of the table.
    pub fn end_address(&self) -> u64 {
        self.start_address.offset
            + (self.entry_count as u64) * (self.pointer_size as u64)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_override_display() {
        assert_eq!(FlowOverride::None.display_name(), "Default");
        assert_eq!(FlowOverride::Call.display_name(), "Call Override");
        assert_eq!(FlowOverride::Return.display_name(), "Return Override");
        assert_eq!(FlowOverride::Jump.display_name(), "Jump Override");
        assert_eq!(
            FlowOverride::FallThrough.display_name(),
            "Fall Through Override"
        );
    }

    #[test]
    fn test_flow_override_all() {
        assert_eq!(FlowOverride::all().len(), 5);
    }

    #[test]
    fn test_set_flow_override_action() {
        let mut action = SetFlowOverrideAction::new(FlowOverride::Call);
        action.add_target(Address::new(0x400000));
        action.add_target(Address::new(0x400100));
        let requests = action.generate_requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].override_type, FlowOverride::Call);
    }

    #[test]
    fn test_set_flow_override_dialog() {
        let dialog = SetFlowOverrideDialog::new(FlowOverride::None);
        assert_eq!(dialog.selected, FlowOverride::None);
        assert!(dialog.confirm().is_none()); // no change

        let mut dialog = SetFlowOverrideDialog::new(FlowOverride::None);
        dialog.set_selected(FlowOverride::Jump);
        assert!(dialog.confirm().is_some());
    }

    #[test]
    fn test_set_length_override_action() {
        let action = SetLengthOverrideAction::new(Address::new(0x400000), 6);
        let req = action.generate_request();
        assert_eq!(req.address, Address::new(0x400000));
        assert_eq!(req.new_length, 6);
    }

    #[test]
    fn test_context_action_apply() {
        let action = ContextAction::new(Address::new(0x400000), "TMode", 1, 0x01);
        assert_eq!(action.apply_to(0x00), 0x01);
        assert_eq!(action.apply_to(0xFF), 0xFF);
        assert_eq!(action.apply_to(0xFE), 0xFF);
    }

    #[test]
    fn test_processor_state_dialog() {
        let mut dialog = ProcessorStateDialog::new(Address::new(0x400000));
        dialog.add_register("TMode", 0);
        dialog.add_register("CPSR", 0x60000010);
        assert_eq!(dialog.get_register("TMode"), Some(0));
        assert_eq!(dialog.get_register("CPSR"), Some(0x60000010));
        assert!(!dialog.modified);

        dialog.set_register("TMode", 1);
        assert_eq!(dialog.get_register("TMode"), Some(1));
        assert!(dialog.modified);
    }

    #[test]
    fn test_static_disassemble_action() {
        let mut action = StaticDisassembleAction::new(Address::new(0x400000), 16);
        action.add_result(Address::new(0x400000), "NOP");
        action.add_result(Address::new(0x400001), "RET");
        assert_eq!(action.results.len(), 2);
    }

    #[test]
    fn test_restricted_disassemble_action() {
        let mut action = RestrictedDisassembleAction::new(Address::new(0x400000));
        action.set_max_instructions(10);
        assert_eq!(action.max_instructions, 10);
        assert!(action.fall_through_only);
    }

    #[test]
    fn test_disassembled_view_plugin() {
        let mut plugin = DisassembledViewPlugin::new();
        assert!(!plugin.is_open);

        plugin.open(Address::new(0x400000));
        assert!(plugin.is_open);
        assert_eq!(plugin.current_address, Address::new(0x400000));

        plugin.add_line(DisassemblyLine {
            address: Address::new(0x400000),
            bytes: vec![0x90],
            mnemonic: "NOP".into(),
            operands: String::new(),
            full_text: "400000  90    NOP".into(),
        });
        assert_eq!(plugin.lines.len(), 1);

        plugin.close();
        assert!(!plugin.is_open);
    }

    #[test]
    fn test_address_table_dialog() {
        let mut dialog = AddressTableDialog::new(Address::new(0x400000));
        dialog.configure(100, 4, false);
        assert_eq!(dialog.end_address(), 0x400000 + 400);
    }
}
