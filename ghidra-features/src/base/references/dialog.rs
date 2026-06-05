//! Reference dialog and instruction panel types.
//!
//! Ported from Ghidra's:
//! - `EditReferenceDialog` -- dialog for editing a single reference
//! - `InstructionPanel` -- panel showing instruction bytes and operand info
//!
//! These types model the reference editing UI without Swing/AWT dependencies.

use ghidra_core::addr::Address;
use ghidra_core::symbol::{DataRefType, FlowType, RefType, Reference, SourceType};
use serde::{Deserialize, Serialize};

use super::instruction_info::InstructionOperandInfo;

// ---------------------------------------------------------------------------
// EditReferenceDialog
// ---------------------------------------------------------------------------

/// The type of reference editing panel.
///
/// Corresponds to the four concrete `EditReferencePanel` subclasses
/// in Ghidra (memory, stack, register, external).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditPanelType {
    /// Memory reference editing.
    Memory,
    /// Stack reference editing.
    Stack,
    /// Register reference editing.
    Register,
    /// External reference editing.
    External,
}

impl EditPanelType {
    /// Returns the panel name.
    pub fn name(&self) -> &'static str {
        match self {
            EditPanelType::Memory => "MEM",
            EditPanelType::Stack => "STACK",
            EditPanelType::Register => "REG",
            EditPanelType::External => "EXT",
        }
    }
}

/// Dialog for editing a single reference.
///
/// Ported from Ghidra's `EditReferenceDialog`. This dialog allows the
/// user to modify the type, destination, and properties of a reference.
/// In the Rust version, the dialog logic is modeled as a state machine.
///
/// # Example
///
/// ```
/// use ghidra_features::base::references::{EditReferenceDialog, EditPanelType};
/// use ghidra_core::addr::Address;
/// use ghidra_core::symbol::{RefType, DataRefType};
///
/// let mut dialog = EditReferenceDialog::new(
///     Address::new(0x1000),
///     Address::new(0x2000),
///     0, // operand index
/// );
/// assert_eq!(dialog.from_address().offset, 0x1000);
/// assert_eq!(dialog.to_address().offset, 0x2000);
/// assert!(!dialog.is_confirmed());
/// dialog.set_ref_type(RefType::Data(DataRefType::Read));
/// assert!(dialog.is_modified());
/// ```
#[derive(Debug, Clone)]
pub struct EditReferenceDialog {
    /// The source address of the reference.
    from_address: Address,
    /// The destination address of the reference.
    to_address: Address,
    /// The operand index.
    operand_index: i32,
    /// The currently selected reference type.
    ref_type: RefType,
    /// Whether this is the primary reference.
    is_primary: bool,
    /// The source type.
    source_type: SourceType,
    /// Which edit panel is active.
    active_panel: EditPanelType,
    /// Whether the dialog was confirmed.
    confirmed: bool,
    /// Whether the reference was modified.
    modified: bool,
}

impl EditReferenceDialog {
    /// Creates a new edit reference dialog.
    pub fn new(from_address: Address, to_address: Address, operand_index: i32) -> Self {
        Self {
            from_address,
            to_address,
            operand_index,
            ref_type: RefType::Data(DataRefType::Read),
            is_primary: false,
            source_type: SourceType::UserDefined,
            active_panel: EditPanelType::Memory,
            confirmed: false,
            modified: false,
        }
    }

    /// Creates a dialog to edit an existing reference.
    pub fn from_reference(ref_: &Reference) -> Self {
        Self {
            from_address: *ref_.get_from_address(),
            to_address: *ref_.get_to_address(),
            operand_index: ref_.get_operand_index(),
            ref_type: ref_.get_reference_type(),
            is_primary: ref_.is_primary(),
            source_type: ref_.get_source(),
            active_panel: EditPanelType::Memory,
            confirmed: false,
            modified: false,
        }
    }

    /// Returns the source address.
    pub fn from_address(&self) -> Address {
        self.from_address
    }

    /// Returns the destination address.
    pub fn to_address(&self) -> Address {
        self.to_address
    }

    /// Returns the operand index.
    pub fn operand_index(&self) -> i32 {
        self.operand_index
    }

    /// Returns the current reference type.
    pub fn ref_type(&self) -> RefType {
        self.ref_type
    }

    /// Sets the reference type.
    pub fn set_ref_type(&mut self, ref_type: RefType) {
        self.ref_type = ref_type;
        self.modified = true;
    }

    /// Returns whether this is a primary reference.
    pub fn is_primary(&self) -> bool {
        self.is_primary
    }

    /// Sets whether this is a primary reference.
    pub fn set_primary(&mut self, primary: bool) {
        self.is_primary = primary;
        self.modified = true;
    }

    /// Returns the source type.
    pub fn source_type(&self) -> SourceType {
        self.source_type
    }

    /// Sets the source type.
    pub fn set_source_type(&mut self, source: SourceType) {
        self.source_type = source;
        self.modified = true;
    }

    /// Returns the active edit panel type.
    pub fn active_panel(&self) -> EditPanelType {
        self.active_panel
    }

    /// Sets the active edit panel type.
    pub fn set_active_panel(&mut self, panel: EditPanelType) {
        self.active_panel = panel;
    }

    /// Returns whether the dialog was confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// Returns whether the reference was modified.
    pub fn is_modified(&self) -> bool {
        self.modified
    }

    /// Confirms the dialog (simulates pressing OK).
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Cancels the dialog.
    pub fn cancel(&mut self) {
        self.confirmed = false;
        self.modified = false;
    }
}

// ---------------------------------------------------------------------------
// InstructionPanel
// ---------------------------------------------------------------------------

/// Panel showing instruction bytes and operand information.
///
/// Ported from Ghidra's `InstructionPanel`. Displays the bytes of the
/// instruction at the current address and provides operand metadata
/// used by the reference editing panels.
///
/// # Example
///
/// ```
/// use ghidra_features::base::references::InstructionPanel;
/// use ghidra_core::addr::Address;
///
/// let mut panel = InstructionPanel::new();
/// panel.set_address(Address::new(0x1000));
/// assert_eq!(panel.address(), Some(Address::new(0x1000)));
/// ```
#[derive(Debug, Clone)]
pub struct InstructionPanel {
    /// The current address being displayed.
    address: Option<Address>,
    /// The instruction mnemonic.
    mnemonic: Option<String>,
    /// The instruction bytes.
    bytes: Vec<u8>,
    /// Operand info for each operand.
    operand_info: Vec<InstructionOperandInfo>,
    /// The selected operand index.
    selected_operand: Option<i32>,
    /// Registered listeners count.
    listener_count: usize,
}

impl InstructionPanel {
    /// Creates a new empty instruction panel.
    pub fn new() -> Self {
        Self {
            address: None,
            mnemonic: None,
            bytes: Vec::new(),
            operand_info: Vec::new(),
            selected_operand: None,
            listener_count: 0,
        }
    }

    /// Returns the current address.
    pub fn address(&self) -> Option<Address> {
        self.address
    }

    /// Sets the current address.
    pub fn set_address(&mut self, address: Address) {
        self.address = Some(address);
    }

    /// Returns the mnemonic.
    pub fn mnemonic(&self) -> Option<&str> {
        self.mnemonic.as_deref()
    }

    /// Sets the mnemonic.
    pub fn set_mnemonic(&mut self, mnemonic: impl Into<String>) {
        self.mnemonic = Some(mnemonic.into());
    }

    /// Returns the instruction bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Sets the instruction bytes.
    pub fn set_bytes(&mut self, bytes: Vec<u8>) {
        self.bytes = bytes;
    }

    /// Returns the operand info.
    pub fn operand_info(&self) -> &[InstructionOperandInfo] {
        &self.operand_info
    }

    /// Sets the operand info.
    pub fn set_operand_info(&mut self, info: Vec<InstructionOperandInfo>) {
        self.operand_info = info;
    }

    /// Returns the selected operand index.
    pub fn selected_operand(&self) -> Option<i32> {
        self.selected_operand
    }

    /// Selects an operand.
    pub fn select_operand(&mut self, index: Option<i32>) {
        self.selected_operand = index;
    }

    /// Returns the number of operands.
    pub fn num_operands(&self) -> usize {
        self.operand_info.len()
    }

    /// Registers a listener (increments counter).
    pub fn add_listener(&mut self) {
        self.listener_count += 1;
    }

    /// Unregisters a listener (decrements counter).
    pub fn remove_listener(&mut self) {
        if self.listener_count > 0 {
            self.listener_count -= 1;
        }
    }

    /// Returns the number of registered listeners.
    pub fn listener_count(&self) -> usize {
        self.listener_count
    }
}

impl Default for InstructionPanel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_edit_panel_type_names() {
        assert_eq!(EditPanelType::Memory.name(), "MEM");
        assert_eq!(EditPanelType::Stack.name(), "STACK");
        assert_eq!(EditPanelType::Register.name(), "REG");
        assert_eq!(EditPanelType::External.name(), "EXT");
    }

    #[test]
    fn test_edit_reference_dialog_new() {
        let dialog = EditReferenceDialog::new(addr(0x1000), addr(0x2000), 0);
        assert_eq!(dialog.from_address(), addr(0x1000));
        assert_eq!(dialog.to_address(), addr(0x2000));
        assert_eq!(dialog.operand_index(), 0);
        assert!(!dialog.is_confirmed());
        assert!(!dialog.is_modified());
    }

    #[test]
    fn test_edit_reference_dialog_set_ref_type() {
        let mut dialog = EditReferenceDialog::new(addr(0x1000), addr(0x2000), 0);
        dialog.set_ref_type(RefType::Data(DataRefType::Read));
        assert!(dialog.ref_type().is_data());
        assert!(dialog.is_modified());
    }

    #[test]
    fn test_edit_reference_dialog_flow_ref_type() {
        let mut dialog = EditReferenceDialog::new(addr(0x1000), addr(0x2000), 0);
        dialog.set_ref_type(RefType::Flow(FlowType::UnconditionalCall));
        assert!(dialog.ref_type().is_flow());
    }

    #[test]
    fn test_edit_reference_dialog_set_primary() {
        let mut dialog = EditReferenceDialog::new(addr(0x1000), addr(0x2000), 0);
        assert!(!dialog.is_primary());
        dialog.set_primary(true);
        assert!(dialog.is_primary());
        assert!(dialog.is_modified());
    }

    #[test]
    fn test_edit_reference_dialog_set_source_type() {
        let mut dialog = EditReferenceDialog::new(addr(0x1000), addr(0x2000), 0);
        dialog.set_source_type(SourceType::Analysis);
        assert!(dialog.is_modified());
        assert!(matches!(dialog.source_type(), SourceType::Analysis));
    }

    #[test]
    fn test_edit_reference_dialog_set_panel() {
        let mut dialog = EditReferenceDialog::new(addr(0x1000), addr(0x2000), 0);
        dialog.set_active_panel(EditPanelType::Stack);
        assert_eq!(dialog.active_panel(), EditPanelType::Stack);
    }

    #[test]
    fn test_edit_reference_dialog_confirm_cancel() {
        let mut dialog = EditReferenceDialog::new(addr(0x1000), addr(0x2000), 0);
        dialog.set_ref_type(RefType::Data(DataRefType::Write));
        assert!(dialog.is_modified());

        dialog.confirm();
        assert!(dialog.is_confirmed());

        dialog.cancel();
        assert!(!dialog.is_confirmed());
        assert!(!dialog.is_modified());
    }

    #[test]
    fn test_instruction_panel_new() {
        let panel = InstructionPanel::new();
        assert!(panel.address().is_none());
        assert!(panel.mnemonic().is_none());
        assert!(panel.bytes().is_empty());
        assert!(panel.operand_info().is_empty());
        assert!(panel.selected_operand().is_none());
        assert_eq!(panel.num_operands(), 0);
        assert_eq!(panel.listener_count(), 0);
    }

    #[test]
    fn test_instruction_panel_set_address() {
        let mut panel = InstructionPanel::new();
        panel.set_address(addr(0x1000));
        assert_eq!(panel.address(), Some(addr(0x1000)));
    }

    #[test]
    fn test_instruction_panel_set_mnemonic() {
        let mut panel = InstructionPanel::new();
        panel.set_mnemonic("mov");
        assert_eq!(panel.mnemonic(), Some("mov"));
    }

    #[test]
    fn test_instruction_panel_set_bytes() {
        let mut panel = InstructionPanel::new();
        panel.set_bytes(vec![0x48, 0x89, 0xE5]);
        assert_eq!(panel.bytes(), &[0x48, 0x89, 0xE5]);
    }

    #[test]
    fn test_instruction_panel_operand_info() {
        let mut panel = InstructionPanel::new();
        let info = InstructionOperandInfo::new(addr(0x1000), "MOV", 2);
        panel.set_operand_info(vec![info]);
        assert_eq!(panel.num_operands(), 1);
    }

    #[test]
    fn test_instruction_panel_select_operand() {
        let mut panel = InstructionPanel::new();
        panel.select_operand(Some(1));
        assert_eq!(panel.selected_operand(), Some(1));
        panel.select_operand(None);
        assert!(panel.selected_operand().is_none());
    }

    #[test]
    fn test_instruction_panel_listeners() {
        let mut panel = InstructionPanel::new();
        assert_eq!(panel.listener_count(), 0);
        panel.add_listener();
        assert_eq!(panel.listener_count(), 1);
        panel.add_listener();
        assert_eq!(panel.listener_count(), 2);
        panel.remove_listener();
        assert_eq!(panel.listener_count(), 1);
        panel.remove_listener();
        assert_eq!(panel.listener_count(), 0);
        panel.remove_listener();
        assert_eq!(panel.listener_count(), 0);
    }
}
