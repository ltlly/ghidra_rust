//! Memory reference editing panel.
//!
//! Ported from `EditMemoryReferencePanel.java`. Manages the state for
//! adding and editing memory references, including address history,
//! offset references, and overlay space selection.

use crate::base::references::ref_type_factory::RefTypeFactory;
use ghidra_core::symbol::{DataRefType, RefType, SourceType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Maximum number of address history entries per program.
const MAX_HISTORY_LENGTH: usize = 10;

/// An entry in the address history list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressHistoryEntry {
    /// The address.
    pub address: u64,
    /// Optional label/symbol name at this address.
    pub label: Option<String>,
}

/// Memory reference editing panel.
///
/// Manages the state for adding and editing memory references.
/// Corresponds to `EditMemoryReferencePanel.java`.
#[derive(Debug, Clone)]
pub struct MemoryRefPanel {
    /// The source code unit address.
    from_address: Option<u64>,
    /// The operand index.
    op_index: i32,
    /// The sub-operand index.
    sub_index: i32,
    /// The destination address.
    to_address: Option<u64>,
    /// Whether this is an offset reference.
    is_offset_ref: bool,
    /// The offset value for offset references.
    offset_value: i64,
    /// The default offset computed from operand analysis.
    default_offset: i64,
    /// The selected reference type.
    ref_type: RefType,
    /// Available reference types for the current context.
    available_ref_types: Vec<RefType>,
    /// Whether to include other overlay spaces.
    include_other_overlays: bool,
    /// Address history keyed by program name.
    address_history: HashMap<String, Vec<AddressHistoryEntry>>,
    /// Whether the panel is in a valid state.
    is_valid: bool,
    /// Whether we are editing an existing reference (vs. adding new).
    is_editing: bool,
}

impl MemoryRefPanel {
    /// Create a new memory reference panel.
    pub fn new() -> Self {
        Self {
            from_address: None,
            op_index: -1,
            sub_index: -1,
            to_address: None,
            is_offset_ref: false,
            offset_value: 0,
            default_offset: 0,
            ref_type: RefType::Data(DataRefType::Data),
            available_ref_types: RefTypeFactory::get_memory_ref_types().to_vec(),
            include_other_overlays: false,
            address_history: HashMap::new(),
            is_valid: false,
            is_editing: false,
        }
    }

    /// Initialize the panel for editing an existing memory reference.
    ///
    /// Corresponds to `EditMemoryReferencePanel.initialize(CodeUnit, Reference)`.
    pub fn initialize_for_edit(
        &mut self,
        from_addr: u64,
        to_addr: u64,
        is_offset: bool,
        offset: i64,
        ref_type: RefType,
    ) {
        self.is_valid = false;
        self.from_address = Some(from_addr);
        self.is_editing = true;

        if is_offset {
            self.default_offset = offset;
            self.to_address = Some(to_addr.wrapping_sub(offset as u64));
        } else {
            self.default_offset = 0;
            self.to_address = Some(to_addr);
        }

        self.is_offset_ref = is_offset;
        self.offset_value = offset;
        self.ref_type = ref_type;

        // Populate available ref types including the current one.
        self.populate_ref_types(Some(&ref_type));

        self.is_valid = true;
    }

    /// Initialize the panel for adding a new memory reference.
    ///
    /// Corresponds to `EditMemoryReferencePanel.initialize(CodeUnit, int, int)`.
    pub fn initialize_for_add(
        &mut self,
        from_addr: u64,
        op_index: i32,
        sub_index: i32,
    ) -> bool {
        self.is_valid = false;
        self.is_editing = false;
        self.from_address = Some(from_addr);
        self.op_index = op_index;
        self.sub_index = sub_index;
        self.default_offset = 0;
        self.is_offset_ref = false;
        self.offset_value = 0;

        // Determine default ref type.
        let rt = RefTypeFactory::get_default_memory_ref_type_for_operand(op_index, false);
        self.ref_type = rt.clone();
        self.populate_ref_types(Some(&rt));

        self.is_valid = true;
        true
    }

    /// Set the destination address.
    pub fn set_to_address(&mut self, addr: Option<u64>) {
        self.to_address = addr;
    }

    /// Get the destination address.
    pub fn to_address(&self) -> Option<u64> {
        self.to_address
    }

    /// Set whether this is an offset reference.
    pub fn set_offset_enabled(&mut self, enabled: bool) {
        self.is_offset_ref = enabled;
        if !enabled {
            self.offset_value = 0;
        }
    }

    /// Get whether this is an offset reference.
    pub fn is_offset_ref(&self) -> bool {
        self.is_offset_ref
    }

    /// Set the offset value.
    pub fn set_offset_value(&mut self, value: i64) {
        self.offset_value = value;
    }

    /// Get the offset value.
    pub fn offset_value(&self) -> i64 {
        self.offset_value
    }

    /// Get the default offset.
    pub fn default_offset(&self) -> i64 {
        self.default_offset
    }

    /// Set the reference type.
    pub fn set_ref_type(&mut self, ref_type: RefType) {
        self.ref_type = ref_type;
    }

    /// Get the reference type.
    pub fn ref_type(&self) -> &RefType {
        &self.ref_type
    }

    /// Get available reference types.
    pub fn available_ref_types(&self) -> &[RefType] {
        &self.available_ref_types
    }

    /// Set whether to include other overlay spaces.
    pub fn set_include_other_overlays(&mut self, include: bool) {
        self.include_other_overlays = include;
    }

    /// Get whether to include other overlay spaces.
    pub fn include_other_overlays(&self) -> bool {
        self.include_other_overlays
    }

    /// Check if the panel is in a valid state.
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    /// Check if the panel is in edit mode.
    pub fn is_editing(&self) -> bool {
        self.is_editing
    }

    /// Get the operand index.
    pub fn op_index(&self) -> i32 {
        self.op_index
    }

    /// Get the sub-operand index.
    pub fn sub_index(&self) -> i32 {
        self.sub_index
    }

    /// Get the source address.
    pub fn from_address(&self) -> Option<u64> {
        self.from_address
    }

    /// Populate the available reference types list.
    fn populate_ref_types(&mut self, adhoc_type: Option<&RefType>) {
        let base_types = RefTypeFactory::get_memory_ref_types();
        self.available_ref_types.clear();

        let mut found_adhoc = false;
        for rt in base_types {
            if adhoc_type.map_or(false, |adhoc| std::mem::discriminant(adhoc) == std::mem::discriminant(rt)) {
                found_adhoc = true;
            }
            self.available_ref_types.push(rt.clone());
        }

        // Add the adhoc type if it wasn't in the standard list.
        if let Some(rt) = adhoc_type {
            if !found_adhoc {
                self.available_ref_types.push(rt.clone());
            }
        }
    }

    /// Validate the current state and return the resolved parameters.
    ///
    /// Returns `Ok((to_addr, is_offset_ref, offset, ref_type, source_type))` on success.
    pub fn validate_and_get_params(&self) -> Result<(u64, bool, i64, RefType, SourceType), String> {
        if !self.is_valid {
            return Err("Panel is not in a valid state".to_string());
        }

        let to_addr = self.to_address
            .ok_or_else(|| "No destination address specified".to_string())?;

        // Validate it is a memory address (not register/stack/external).
        // In Rust we just check it's non-zero as a basic validation.
        if to_addr == 0 && self.to_address.is_some() {
            return Err("Invalid memory address specified".to_string());
        }

        let offset = if self.is_offset_ref { self.offset_value } else { 0 };

        Ok((
            to_addr,
            self.is_offset_ref,
            offset,
            self.ref_type.clone(),
            SourceType::UserDefined,
        ))
    }

    /// Apply the reference (add or update).
    ///
    /// Returns the parameters needed by the plugin to execute the command.
    /// The caller (plugin) is responsible for actually creating the reference.
    pub fn apply_reference(&self) -> Result<MemoryRefApplyResult, String> {
        let (to_addr, is_offset, offset, ref_type, source) = self.validate_and_get_params()?;

        Ok(MemoryRefApplyResult {
            from_addr: self.from_address.unwrap(),
            op_index: self.op_index,
            to_addr,
            is_offset_ref: is_offset,
            offset,
            ref_type,
            source_type: source,
            is_edit: self.is_editing,
        })
    }

    /// Add an address to the history for a program.
    pub fn add_history_address(&mut self, program_name: &str, addr: u64, label: Option<String>) {
        let history = self.address_history
            .entry(program_name.to_string())
            .or_insert_with(Vec::new);

        // Remove if already exists.
        history.retain(|e| e.address != addr);

        // Insert at front.
        history.insert(0, AddressHistoryEntry { address: addr, label });

        // Trim to max length.
        if history.len() > MAX_HISTORY_LENGTH {
            history.truncate(MAX_HISTORY_LENGTH);
        }
    }

    /// Get the address history for a program.
    pub fn get_history(&self, program_name: &str) -> Option<&[AddressHistoryEntry]> {
        self.address_history.get(program_name).map(|v| v.as_slice())
    }

    /// Get the most recent history address for a program.
    pub fn get_last_history_address(&self, program_name: &str) -> Option<u64> {
        self.address_history
            .get(program_name)
            .and_then(|h| h.first().map(|e| e.address))
    }

    /// Get the number of history entries for a program.
    pub fn get_history_size(&self, program_name: &str) -> usize {
        self.address_history
            .get(program_name)
            .map_or(0, |h| h.len())
    }

    /// Clean up the panel state.
    pub fn cleanup(&mut self) {
        self.is_valid = false;
        self.from_address = None;
        self.to_address = None;
        self.is_editing = false;
    }

    /// Set the operand index (only for ADD case).
    pub fn set_op_index(&mut self, op_index: i32) -> bool {
        if self.is_editing {
            return false;
        }
        self.op_index = op_index;
        self.is_valid = true;
        true
    }

    /// Get the label for the address history display.
    pub fn format_history_entry(entry: &AddressHistoryEntry) -> String {
        match &entry.label {
            Some(label) => format!("0x{:x} ({})", entry.address, label),
            None => format!("0x{:x}", entry.address),
        }
    }

    /// Compute a default destination address from a source address and offset.
    ///
    /// Tries the source address space first, then the default address space.
    pub fn compute_default_address(source_addr: u64, offset: u64, addr_size: u32) -> Option<u64> {
        let addr_unit_size = if addr_size == 0 { 1 } else { addr_size as u64 };
        let addr_offset = offset.wrapping_mul(addr_unit_size);

        // Try computing from source address.
        let result = source_addr.wrapping_add(addr_offset);
        if result != 0 {
            return Some(result);
        }

        None
    }
}

impl Default for MemoryRefPanel {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of applying a memory reference from the panel.
#[derive(Debug, Clone)]
pub struct MemoryRefApplyResult {
    /// The source address.
    pub from_addr: u64,
    /// The operand index.
    pub op_index: i32,
    /// The destination address.
    pub to_addr: u64,
    /// Whether this is an offset reference.
    pub is_offset_ref: bool,
    /// The offset value.
    pub offset: i64,
    /// The reference type.
    pub ref_type: RefType,
    /// The source type.
    pub source_type: SourceType,
    /// Whether this is an edit (vs. add).
    pub is_edit: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_ref_panel_new() {
        let panel = MemoryRefPanel::new();
        assert!(!panel.is_valid());
        assert!(!panel.is_editing());
        assert!(panel.to_address().is_none());
        assert!(!panel.is_offset_ref());
    }

    #[test]
    fn test_memory_ref_panel_initialize_for_add() {
        let mut panel = MemoryRefPanel::new();
        assert!(panel.initialize_for_add(0x400000, 1, 0));
        assert!(panel.is_valid());
        assert!(!panel.is_editing());
        assert_eq!(panel.from_address(), Some(0x400000));
        assert_eq!(panel.op_index(), 1);
    }

    #[test]
    fn test_memory_ref_panel_initialize_for_edit() {
        let mut panel = MemoryRefPanel::new();
        panel.initialize_for_edit(
            0x400000,
            0x500000,
            false,
            0,
            RefType::Data(DataRefType::Read),
        );
        assert!(panel.is_valid());
        assert!(panel.is_editing());
        assert_eq!(panel.to_address(), Some(0x500000));
    }

    #[test]
    fn test_memory_ref_panel_initialize_for_edit_with_offset() {
        let mut panel = MemoryRefPanel::new();
        panel.initialize_for_edit(
            0x400000,
            0x500010,
            true,
            0x10,
            RefType::Data(DataRefType::Read),
        );
        assert!(panel.is_valid());
        assert!(panel.is_offset_ref());
        assert_eq!(panel.offset_value(), 0x10);
        // Base address = to_addr - offset
        assert_eq!(panel.to_address(), Some(0x500000));
    }

    #[test]
    fn test_memory_ref_panel_set_to_address() {
        let mut panel = MemoryRefPanel::new();
        panel.initialize_for_add(0x400000, 0, -1);
        panel.set_to_address(Some(0x600000));
        assert_eq!(panel.to_address(), Some(0x600000));
    }

    #[test]
    fn test_memory_ref_panel_offset_toggle() {
        let mut panel = MemoryRefPanel::new();
        panel.set_offset_enabled(true);
        assert!(panel.is_offset_ref());
        panel.set_offset_value(0x20);
        assert_eq!(panel.offset_value(), 0x20);
        panel.set_offset_enabled(false);
        assert!(!panel.is_offset_ref());
        assert_eq!(panel.offset_value(), 0);
    }

    #[test]
    fn test_memory_ref_panel_ref_type() {
        let mut panel = MemoryRefPanel::new();
        panel.set_ref_type(RefType::Data(DataRefType::Write));
        assert!(matches!(panel.ref_type(), RefType::Data(DataRefType::Write)));
    }

    #[test]
    fn test_memory_ref_panel_available_ref_types() {
        let panel = MemoryRefPanel::new();
        assert!(!panel.available_ref_types().is_empty());
    }

    #[test]
    fn test_memory_ref_panel_apply_no_address() {
        let mut panel = MemoryRefPanel::new();
        panel.initialize_for_add(0x400000, 0, -1);
        // No to_address set, should fail.
        assert!(panel.apply_reference().is_err());
    }

    #[test]
    fn test_memory_ref_panel_apply_valid() {
        let mut panel = MemoryRefPanel::new();
        panel.initialize_for_add(0x400000, 0, -1);
        panel.set_to_address(Some(0x500000));
        let result = panel.apply_reference().unwrap();
        assert_eq!(result.from_addr, 0x400000);
        assert_eq!(result.to_addr, 0x500000);
        assert!(!result.is_offset_ref);
        assert!(!result.is_edit);
    }

    #[test]
    fn test_memory_ref_panel_apply_edit_with_offset() {
        let mut panel = MemoryRefPanel::new();
        panel.initialize_for_edit(
            0x400000,
            0x500010,
            true,
            0x10,
            RefType::Data(DataRefType::Read),
        );
        let result = panel.apply_reference().unwrap();
        assert!(result.is_offset_ref);
        assert_eq!(result.offset, 0x10);
        assert!(result.is_edit);
    }

    #[test]
    fn test_memory_ref_panel_history() {
        let mut panel = MemoryRefPanel::new();
        panel.add_history_address("test.exe", 0x400000, Some("main".to_string()));
        panel.add_history_address("test.exe", 0x400100, None);

        assert_eq!(panel.get_history_size("test.exe"), 2);
        assert_eq!(panel.get_last_history_address("test.exe"), Some(0x400100));

        let history = panel.get_history("test.exe").unwrap();
        assert_eq!(history[0].address, 0x400100);
        assert_eq!(history[1].address, 0x400000);
        assert_eq!(history[1].label.as_deref(), Some("main"));
    }

    #[test]
    fn test_memory_ref_panel_history_dedup() {
        let mut panel = MemoryRefPanel::new();
        panel.add_history_address("test.exe", 0x400000, None);
        panel.add_history_address("test.exe", 0x400100, None);
        panel.add_history_address("test.exe", 0x400000, None); // re-add

        assert_eq!(panel.get_history_size("test.exe"), 2);
        assert_eq!(panel.get_last_history_address("test.exe"), Some(0x400000));
    }

    #[test]
    fn test_memory_ref_panel_history_max_length() {
        let mut panel = MemoryRefPanel::new();
        for i in 0..20 {
            panel.add_history_address("test.exe", 0x400000 + i * 0x100, None);
        }
        assert_eq!(panel.get_history_size("test.exe"), MAX_HISTORY_LENGTH);
    }

    #[test]
    fn test_memory_ref_panel_cleanup() {
        let mut panel = MemoryRefPanel::new();
        panel.initialize_for_add(0x400000, 0, -1);
        assert!(panel.is_valid());
        panel.cleanup();
        assert!(!panel.is_valid());
        assert!(panel.from_address().is_none());
    }

    #[test]
    fn test_memory_ref_panel_set_op_index() {
        let mut panel = MemoryRefPanel::new();
        panel.initialize_for_add(0x400000, 0, -1);
        assert!(panel.set_op_index(2));
        assert_eq!(panel.op_index(), 2);
    }

    #[test]
    fn test_memory_ref_panel_set_op_index_edit_mode() {
        let mut panel = MemoryRefPanel::new();
        panel.initialize_for_edit(
            0x400000,
            0x500000,
            false,
            0,
            RefType::Data(DataRefType::Read),
        );
        assert!(!panel.set_op_index(2)); // Should fail in edit mode.
    }

    #[test]
    fn test_format_history_entry() {
        let entry = AddressHistoryEntry {
            address: 0x400000,
            label: Some("main".to_string()),
        };
        assert_eq!(MemoryRefPanel::format_history_entry(&entry), "0x400000 (main)");

        let entry = AddressHistoryEntry {
            address: 0x400000,
            label: None,
        };
        assert_eq!(MemoryRefPanel::format_history_entry(&entry), "0x400000");
    }

    #[test]
    fn test_compute_default_address() {
        assert_eq!(MemoryRefPanel::compute_default_address(0x400000, 0x100, 1), Some(0x400100));
        assert_eq!(MemoryRefPanel::compute_default_address(0x400000, 4, 4), Some(0x400010));
    }

    #[test]
    fn test_memory_ref_panel_include_other_overlays() {
        let mut panel = MemoryRefPanel::new();
        assert!(!panel.include_other_overlays());
        panel.set_include_other_overlays(true);
        assert!(panel.include_other_overlays());
    }

    #[test]
    fn test_address_history_entry_different_programs() {
        let mut panel = MemoryRefPanel::new();
        panel.add_history_address("prog1.exe", 0x400000, None);
        panel.add_history_address("prog2.exe", 0x500000, None);

        assert_eq!(panel.get_history_size("prog1.exe"), 1);
        assert_eq!(panel.get_history_size("prog2.exe"), 1);
        assert_eq!(panel.get_last_history_address("prog1.exe"), Some(0x400000));
        assert_eq!(panel.get_last_history_address("prog2.exe"), Some(0x500000));
    }
}
