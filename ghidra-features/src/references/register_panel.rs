//! Register reference editing panel.
//!
//! Ported from `EditRegisterReferencePanel.java`. Manages the state for
//! adding and editing register references within functions.

use crate::base::references::ref_type_factory::RefTypeFactory;
use ghidra_core::symbol::{DataRefType, RefType, SourceType};
use serde::{Deserialize, Serialize};

/// Represents a register that can be referenced.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegisterInfo {
    /// The register name (e.g., "eax", "x0").
    pub name: String,
    /// The register address in the register space.
    pub address: u64,
    /// The register size in bytes.
    pub size: u32,
    /// Whether this is a base (parent) register.
    pub is_base: bool,
    /// The parent register address (if this is a child register).
    pub parent_address: Option<u64>,
}

impl RegisterInfo {
    /// Create a new register info.
    pub fn new(name: &str, address: u64, size: u32) -> Self {
        Self {
            name: name.to_string(),
            address,
            size,
            is_base: true,
            parent_address: None,
        }
    }

    /// Create a child register info.
    pub fn child(name: &str, address: u64, size: u32, parent_address: u64) -> Self {
        Self {
            name: name.to_string(),
            address,
            size,
            is_base: false,
            parent_address: Some(parent_address),
        }
    }
}

impl std::fmt::Display for RegisterInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// Register reference editing panel.
///
/// Manages the state for adding and editing register references.
/// Corresponds to `EditRegisterReferencePanel.java`.
#[derive(Debug, Clone)]
pub struct RegisterRefPanel {
    /// The source code unit address.
    from_address: Option<u64>,
    /// The operand index.
    op_index: i32,
    /// The selected register.
    selected_register: Option<RegisterInfo>,
    /// Available registers for the current context.
    available_registers: Vec<RegisterInfo>,
    /// The selected reference type.
    ref_type: RefType,
    /// Available reference types for register references.
    available_ref_types: Vec<RefType>,
    /// Whether the panel is in a valid state.
    is_valid: bool,
    /// Whether we are editing an existing reference (vs. adding new).
    is_editing: bool,
}

impl RegisterRefPanel {
    /// Create a new register reference panel.
    pub fn new() -> Self {
        Self {
            from_address: None,
            op_index: -1,
            selected_register: None,
            available_registers: Vec::new(),
            ref_type: RefType::Data(DataRefType::Write),
            available_ref_types: RefTypeFactory::get_data_ref_types().to_vec(),
            is_valid: false,
            is_editing: false,
        }
    }

    /// Initialize the panel for editing an existing register reference.
    ///
    /// Corresponds to `EditRegisterReferencePanel.initialize(CodeUnit, Reference)`.
    pub fn initialize_for_edit(
        &mut self,
        from_addr: u64,
        to_reg: RegisterInfo,
        ref_type: RefType,
        allowed_registers: Vec<RegisterInfo>,
    ) {
        self.is_valid = false;
        self.from_address = Some(from_addr);
        self.is_editing = true;

        self.available_registers = allowed_registers;
        self.selected_register = Some(to_reg);

        self.ref_type = ref_type.clone();
        self.populate_ref_types(Some(&ref_type));

        self.is_valid = true;
    }

    /// Initialize the panel for adding a new register reference.
    ///
    /// Corresponds to `EditRegisterReferencePanel.initialize(CodeUnit, int, int)`.
    pub fn initialize_for_add(
        &mut self,
        from_addr: u64,
        op_index: i32,
    ) -> bool {
        self.is_valid = false;
        self.is_editing = false;
        self.from_address = Some(from_addr);
        self.op_index = op_index;
        self.selected_register = None;

        self.populate_ref_types(None);
        self.ref_type = RefType::Data(DataRefType::Write);

        self.is_valid = true;
        true
    }

    /// Set the selected register.
    pub fn set_selected_register(&mut self, reg: Option<RegisterInfo>) {
        self.selected_register = reg;
    }

    /// Get the selected register.
    pub fn selected_register(&self) -> Option<&RegisterInfo> {
        self.selected_register.as_ref()
    }

    /// Set the available registers.
    pub fn set_available_registers(&mut self, registers: Vec<RegisterInfo>) {
        self.available_registers = registers;
    }

    /// Get the available registers.
    pub fn available_registers(&self) -> &[RegisterInfo] {
        &self.available_registers
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

    /// Get the source address.
    pub fn from_address(&self) -> Option<u64> {
        self.from_address
    }

    /// Populate the available reference types list.
    fn populate_ref_types(&mut self, adhoc_type: Option<&RefType>) {
        let base_types = RefTypeFactory::get_data_ref_types();
        self.available_ref_types.clear();

        let mut found_adhoc = false;
        for rt in base_types {
            if adhoc_type.map_or(false, |adhoc| std::mem::discriminant(adhoc) == std::mem::discriminant(rt)) {
                found_adhoc = true;
            }
            self.available_ref_types.push(rt.clone());
        }

        if let Some(rt) = adhoc_type {
            if !found_adhoc {
                self.available_ref_types.push(rt.clone());
            }
        }
    }

    /// Validate the current state and return the resolved parameters.
    pub fn validate_and_get_params(&self) -> Result<(&RegisterInfo, RefType, SourceType), String> {
        if !self.is_valid {
            return Err("Panel is not in a valid state".to_string());
        }

        let reg = self.selected_register
            .as_ref()
            .ok_or_else(|| "No register selected".to_string())?;

        Ok((reg, self.ref_type.clone(), SourceType::UserDefined))
    }

    /// Apply the reference (add or update).
    ///
    /// Returns the parameters needed by the plugin to execute the command.
    pub fn apply_reference(&self) -> Result<RegisterRefApplyResult, String> {
        let (reg, ref_type, source) = self.validate_and_get_params()?;

        Ok(RegisterRefApplyResult {
            from_addr: self.from_address.unwrap(),
            op_index: self.op_index,
            register: reg.clone(),
            ref_type,
            source_type: source,
            is_edit: self.is_editing,
        })
    }

    /// Clean up the panel state.
    pub fn cleanup(&mut self) {
        self.is_valid = false;
        self.from_address = None;
        self.selected_register = None;
        self.is_editing = false;
    }

    /// Set the operand index (only for ADD case).
    ///
    /// Returns true if the operand supports register references.
    pub fn set_op_index(
        &mut self,
        op_index: i32,
        has_function: bool,
        allowed_registers: Vec<RegisterInfo>,
        preferred_register: Option<RegisterInfo>,
    ) -> bool {
        if self.is_editing {
            return false;
        }

        self.is_valid = false;
        self.op_index = op_index;

        // Register references require a function context.
        if !has_function {
            return false;
        }

        if allowed_registers.is_empty() {
            return false;
        }

        self.available_registers = allowed_registers;
        self.selected_register = preferred_register.or_else(|| {
            self.available_registers.first().cloned()
        });

        self.populate_ref_types(None);
        self.ref_type = RefType::Data(DataRefType::Write);

        self.is_valid = true;
        true
    }

    /// Filter allowed registers from instruction result objects.
    ///
    /// In the Java version this is `getAllowedRegisters`. Here we accept
    /// a pre-filtered list of result registers and a stack pointer name.
    pub fn filter_allowed_registers(
        result_registers: &[RegisterInfo],
        stack_pointer_name: Option<&str>,
        required_reg: Option<&RegisterInfo>,
    ) -> Vec<RegisterInfo> {
        let mut reg_set = Vec::new();

        for reg in result_registers {
            // Skip hidden, processor context, program counter, and stack pointer registers.
            if reg.name.starts_with('_') || reg.name == "pc" {
                continue;
            }
            if stack_pointer_name.map_or(false, |sp| sp == reg.name) {
                continue;
            }
            if reg.is_base {
                reg_set.push(reg.clone());
                // Add child registers.
                for child in result_registers {
                    if !child.is_base && child.parent_address == Some(reg.address) {
                        reg_set.push(child.clone());
                    }
                }
            }
        }

        // Ensure required register is included.
        if let Some(required) = required_reg {
            if !reg_set.iter().any(|r| r.address == required.address) {
                reg_set.push(required.clone());
            }
        }

        reg_set.sort();
        reg_set
    }

    /// Find the register operand for an instruction.
    ///
    /// Returns the register if the operand resolves to a single register.
    pub fn find_operand_register(
        op_objects: &[RegisterInfo],
    ) -> Option<RegisterInfo> {
        if op_objects.len() == 1 {
            Some(op_objects[0].clone())
        } else {
            None
        }
    }
}

impl Default for RegisterRefPanel {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of applying a register reference from the panel.
#[derive(Debug, Clone)]
pub struct RegisterRefApplyResult {
    /// The source address.
    pub from_addr: u64,
    /// The operand index.
    pub op_index: i32,
    /// The target register.
    pub register: RegisterInfo,
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
    fn test_register_ref_panel_new() {
        let panel = RegisterRefPanel::new();
        assert!(!panel.is_valid());
        assert!(!panel.is_editing());
        assert!(panel.selected_register().is_none());
        assert!(panel.available_registers().is_empty());
    }

    #[test]
    fn test_register_ref_panel_initialize_for_add() {
        let mut panel = RegisterRefPanel::new();
        assert!(panel.initialize_for_add(0x400000, 1));
        assert!(panel.is_valid());
        assert!(!panel.is_editing());
        assert_eq!(panel.from_address(), Some(0x400000));
        assert_eq!(panel.op_index(), 1);
    }

    #[test]
    fn test_register_ref_panel_initialize_for_edit() {
        let mut panel = RegisterRefPanel::new();
        let reg = RegisterInfo::new("eax", 0, 4);
        panel.initialize_for_edit(
            0x400000,
            reg,
            RefType::Data(DataRefType::Write),
            vec![RegisterInfo::new("eax", 0, 4), RegisterInfo::new("ebx", 4, 4)],
        );
        assert!(panel.is_valid());
        assert!(panel.is_editing());
        assert_eq!(panel.selected_register().unwrap().name, "eax");
    }

    #[test]
    fn test_register_ref_panel_set_selected_register() {
        let mut panel = RegisterRefPanel::new();
        panel.initialize_for_add(0x400000, 0);
        let reg = RegisterInfo::new("rax", 0, 8);
        panel.set_selected_register(Some(reg.clone()));
        assert_eq!(panel.selected_register().unwrap().name, "rax");
    }

    #[test]
    fn test_register_ref_panel_available_registers() {
        let mut panel = RegisterRefPanel::new();
        let regs = vec![
            RegisterInfo::new("eax", 0, 4),
            RegisterInfo::new("ebx", 4, 4),
        ];
        panel.set_available_registers(regs);
        assert_eq!(panel.available_registers().len(), 2);
    }

    #[test]
    fn test_register_ref_panel_ref_type() {
        let mut panel = RegisterRefPanel::new();
        panel.set_ref_type(RefType::Data(DataRefType::Read));
        assert!(matches!(panel.ref_type(), RefType::Data(DataRefType::Read)));
    }

    #[test]
    fn test_register_ref_panel_available_ref_types() {
        let panel = RegisterRefPanel::new();
        assert!(!panel.available_ref_types().is_empty());
    }

    #[test]
    fn test_register_ref_panel_validate_no_register() {
        let mut panel = RegisterRefPanel::new();
        panel.initialize_for_add(0x400000, 0);
        assert!(panel.validate_and_get_params().is_err());
    }

    #[test]
    fn test_register_ref_panel_validate_valid() {
        let mut panel = RegisterRefPanel::new();
        panel.initialize_for_add(0x400000, 0);
        panel.set_selected_register(Some(RegisterInfo::new("eax", 0, 4)));
        assert!(panel.validate_and_get_params().is_ok());
    }

    #[test]
    fn test_register_ref_panel_apply_valid() {
        let mut panel = RegisterRefPanel::new();
        panel.initialize_for_add(0x400000, 0);
        panel.set_selected_register(Some(RegisterInfo::new("eax", 0, 4)));
        let result = panel.apply_reference().unwrap();
        assert_eq!(result.from_addr, 0x400000);
        assert_eq!(result.register.name, "eax");
        assert!(!result.is_edit);
    }

    #[test]
    fn test_register_ref_panel_apply_edit() {
        let mut panel = RegisterRefPanel::new();
        let reg = RegisterInfo::new("eax", 0, 4);
        panel.initialize_for_edit(
            0x400000,
            reg,
            RefType::Data(DataRefType::Write),
            vec![RegisterInfo::new("eax", 0, 4)],
        );
        let result = panel.apply_reference().unwrap();
        assert!(result.is_edit);
        assert_eq!(result.register.name, "eax");
    }

    #[test]
    fn test_register_ref_panel_cleanup() {
        let mut panel = RegisterRefPanel::new();
        panel.initialize_for_add(0x400000, 0);
        assert!(panel.is_valid());
        panel.cleanup();
        assert!(!panel.is_valid());
        assert!(panel.from_address().is_none());
    }

    #[test]
    fn test_register_ref_panel_set_op_index() {
        let mut panel = RegisterRefPanel::new();
        panel.initialize_for_add(0x400000, 0);
        let regs = vec![
            RegisterInfo::new("eax", 0, 4),
            RegisterInfo::new("ebx", 4, 4),
        ];
        let preferred = RegisterInfo::new("eax", 0, 4);
        assert!(panel.set_op_index(2, true, regs, Some(preferred)));
        assert_eq!(panel.op_index(), 2);
        assert_eq!(panel.selected_register().unwrap().name, "eax");
    }

    #[test]
    fn test_register_ref_panel_set_op_index_no_function() {
        let mut panel = RegisterRefPanel::new();
        panel.initialize_for_add(0x400000, 0);
        assert!(!panel.set_op_index(2, false, vec![], None));
    }

    #[test]
    fn test_register_ref_panel_set_op_index_no_registers() {
        let mut panel = RegisterRefPanel::new();
        panel.initialize_for_add(0x400000, 0);
        assert!(!panel.set_op_index(2, true, vec![], None));
    }

    #[test]
    fn test_register_ref_panel_set_op_index_edit_mode() {
        let mut panel = RegisterRefPanel::new();
        let reg = RegisterInfo::new("eax", 0, 4);
        panel.initialize_for_edit(
            0x400000,
            reg,
            RefType::Data(DataRefType::Write),
            vec![RegisterInfo::new("eax", 0, 4)],
        );
        assert!(!panel.set_op_index(2, true, vec![], None));
    }

    #[test]
    fn test_filter_allowed_registers() {
        let regs = vec![
            RegisterInfo::new("eax", 0, 4),
            RegisterInfo::new("ebx", 4, 4),
            RegisterInfo::new("_hidden", 8, 4),
            RegisterInfo::new("pc", 12, 4),
            RegisterInfo::new("esp", 16, 4),
        ];
        let filtered = RegisterRefPanel::filter_allowed_registers(&regs, Some("esp"), None);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0].name, "eax");
        assert_eq!(filtered[1].name, "ebx");
    }

    #[test]
    fn test_filter_allowed_registers_with_required() {
        let regs = vec![
            RegisterInfo::new("eax", 0, 4),
        ];
        let required = RegisterInfo::new("ecx", 8, 4);
        let filtered = RegisterRefPanel::filter_allowed_registers(&regs, None, Some(&required));
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().any(|r| r.name == "ecx"));
    }

    #[test]
    fn test_filter_allowed_registers_required_already_present() {
        let regs = vec![
            RegisterInfo::new("eax", 0, 4),
            RegisterInfo::new("ecx", 8, 4),
        ];
        let required = RegisterInfo::new("ecx", 8, 4);
        let filtered = RegisterRefPanel::filter_allowed_registers(&regs, None, Some(&required));
        assert_eq!(filtered.len(), 2); // Should not duplicate.
    }

    #[test]
    fn test_find_operand_register() {
        let regs = vec![RegisterInfo::new("eax", 0, 4)];
        assert!(RegisterRefPanel::find_operand_register(&regs).is_some());

        let regs = vec![
            RegisterInfo::new("eax", 0, 4),
            RegisterInfo::new("ebx", 4, 4),
        ];
        assert!(RegisterRefPanel::find_operand_register(&regs).is_none());

        let regs: Vec<RegisterInfo> = vec![];
        assert!(RegisterRefPanel::find_operand_register(&regs).is_none());
    }

    #[test]
    fn test_register_info_display() {
        let reg = RegisterInfo::new("eax", 0, 4);
        assert_eq!(format!("{}", reg), "eax");
    }

    #[test]
    fn test_register_info_child() {
        let reg = RegisterInfo::child("al", 0, 1, 0);
        assert!(!reg.is_base);
        assert_eq!(reg.parent_address, Some(0));
    }

    #[test]
    fn test_register_info_ordering() {
        let mut regs = vec![
            RegisterInfo::new("ebx", 4, 4),
            RegisterInfo::new("eax", 0, 4),
            RegisterInfo::new("ecx", 8, 4),
        ];
        regs.sort();
        assert_eq!(regs[0].name, "eax");
        assert_eq!(regs[1].name, "ebx");
        assert_eq!(regs[2].name, "ecx");
    }

    #[test]
    fn test_register_ref_panel_default() {
        let panel = RegisterRefPanel::default();
        assert!(!panel.is_valid());
        assert!(panel.selected_register().is_none());
    }
}
