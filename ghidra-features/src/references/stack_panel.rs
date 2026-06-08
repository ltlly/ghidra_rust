//! Stack reference editing panel.
//!
//! Ported from `EditStackReferencePanel.java`. Manages the state for
//! adding and editing stack references within functions.

use crate::base::references::ref_type_factory::RefTypeFactory;
use ghidra_core::symbol::{DataRefType, RefType, SourceType};
use serde::{Deserialize, Serialize};

/// Stack reference editing panel.
///
/// Manages the state for adding and editing stack references.
/// Corresponds to `EditStackReferencePanel.java`.
#[derive(Debug, Clone)]
pub struct StackRefPanel {
    /// The source code unit address.
    from_address: Option<u64>,
    /// The operand index.
    op_index: i32,
    /// The stack offset value.
    stack_offset: i32,
    /// The selected reference type.
    ref_type: RefType,
    /// Available reference types for stack references.
    available_ref_types: Vec<RefType>,
    /// Whether the current operand resolves to a valid stack reference.
    is_valid_stack_ref: bool,
    /// Whether the panel is in a valid state.
    is_valid: bool,
    /// Whether we are editing an existing reference (vs. adding new).
    is_editing: bool,
    /// The minimum valid stack offset.
    min_stack_offset: i64,
    /// The maximum valid stack offset.
    max_stack_offset: i64,
}

impl StackRefPanel {
    /// Create a new stack reference panel.
    pub fn new() -> Self {
        Self {
            from_address: None,
            op_index: -1,
            stack_offset: 0,
            ref_type: RefType::Data(DataRefType::Read),
            available_ref_types: RefTypeFactory::get_stack_ref_types().to_vec(),
            is_valid_stack_ref: false,
            is_valid: false,
            is_editing: false,
            min_stack_offset: i32::MIN as i64,
            max_stack_offset: i32::MAX as i64,
        }
    }

    /// Initialize the panel for editing an existing stack reference.
    ///
    /// Corresponds to `EditStackReferencePanel.initialize(CodeUnit, Reference)`.
    pub fn initialize_for_edit(
        &mut self,
        from_addr: u64,
        stack_offset: i32,
        ref_type: RefType,
    ) {
        self.is_valid = false;
        self.from_address = Some(from_addr);
        self.is_editing = true;

        self.stack_offset = stack_offset;
        self.ref_type = ref_type.clone();
        self.populate_ref_types(Some(&ref_type));

        self.is_valid = true;
    }

    /// Initialize the panel for adding a new stack reference.
    ///
    /// Corresponds to `EditStackReferencePanel.initialize(CodeUnit, int, int)`.
    pub fn initialize_for_add(
        &mut self,
        from_addr: u64,
        op_index: i32,
    ) -> bool {
        self.is_valid = false;
        self.is_editing = false;
        self.from_address = Some(from_addr);
        self.op_index = op_index;
        self.stack_offset = 0;

        let rt = RefTypeFactory::get_default_stack_ref_type_for_operand(op_index);
        self.ref_type = rt.clone();
        self.populate_ref_types(Some(&rt));

        self.is_valid = true;
        true
    }

    /// Set the stack offset value.
    pub fn set_stack_offset(&mut self, offset: i32) {
        self.stack_offset = offset;
    }

    /// Get the stack offset value.
    pub fn stack_offset(&self) -> i32 {
        self.stack_offset
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

    /// Check if the current operand resolves to a valid stack reference.
    pub fn is_valid_stack_ref(&self) -> bool {
        self.is_valid_stack_ref
    }

    /// Set whether the current operand is a valid stack reference.
    pub fn set_valid_stack_ref(&mut self, valid: bool) {
        self.is_valid_stack_ref = valid;
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

    /// Set the stack space bounds.
    pub fn set_stack_bounds(&mut self, min: i64, max: i64) {
        self.min_stack_offset = min;
        self.max_stack_offset = max;
    }

    /// Get the minimum stack offset.
    pub fn min_stack_offset(&self) -> i64 {
        self.min_stack_offset
    }

    /// Get the maximum stack offset.
    pub fn max_stack_offset(&self) -> i64 {
        self.max_stack_offset
    }

    /// Populate the available reference types list.
    fn populate_ref_types(&mut self, adhoc_type: Option<&RefType>) {
        let base_types = RefTypeFactory::get_stack_ref_types();
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
    pub fn validate_and_get_params(&self) -> Result<(i32, RefType, SourceType), String> {
        if !self.is_valid {
            return Err("Panel is not in a valid state".to_string());
        }

        let offset = self.stack_offset;
        if (offset as i64) < self.min_stack_offset || (offset as i64) > self.max_stack_offset {
            let min_str = format_hex_signed(self.min_stack_offset);
            let max_str = format_hex_signed(self.max_stack_offset);
            return Err(format!(
                "'Stack Offset' value too {}\nMust be between {} and {}",
                if offset > 0 { "large" } else { "small" },
                min_str,
                max_str
            ));
        }

        Ok((offset, self.ref_type.clone(), SourceType::UserDefined))
    }

    /// Apply the reference (add or update).
    ///
    /// Returns the parameters needed by the plugin to execute the command.
    pub fn apply_reference(&self) -> Result<StackRefApplyResult, String> {
        let (offset, ref_type, source) = self.validate_and_get_params()?;

        Ok(StackRefApplyResult {
            from_addr: self.from_address.unwrap(),
            op_index: self.op_index,
            stack_offset: offset,
            ref_type,
            source_type: source,
            is_edit: self.is_editing,
        })
    }

    /// Clean up the panel state.
    pub fn cleanup(&mut self) {
        self.is_valid = false;
        self.from_address = None;
        self.is_editing = false;
    }

    /// Set the operand index (only for ADD case).
    ///
    /// Returns true if the operand supports stack references.
    pub fn set_op_index(&mut self, op_index: i32, has_function: bool, stack_offset: Option<i32>) -> bool {
        if self.is_editing {
            return false;
        }

        self.is_valid = false;
        self.op_index = op_index;

        // Stack references require a function context.
        if !has_function {
            return false;
        }

        // Compute stack offset from operand analysis.
        if let Some(offset) = stack_offset {
            self.stack_offset = offset;
            self.is_valid_stack_ref = true;
        } else {
            self.stack_offset = 0;
            self.is_valid_stack_ref = false;
        }

        let rt = RefTypeFactory::get_default_stack_ref_type_for_operand(op_index);
        self.ref_type = rt.clone();
        self.populate_ref_types(Some(&rt));

        self.is_valid = true;
        true
    }

    /// Format the stack offset as a hex string with sign.
    pub fn format_stack_offset(val: i32) -> String {
        format_hex_signed(val as i64)
    }
}

impl Default for StackRefPanel {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of applying a stack reference from the panel.
#[derive(Debug, Clone)]
pub struct StackRefApplyResult {
    /// The source address.
    pub from_addr: u64,
    /// The operand index.
    pub op_index: i32,
    /// The stack offset.
    pub stack_offset: i32,
    /// The reference type.
    pub ref_type: RefType,
    /// The source type.
    pub source_type: SourceType,
    /// Whether this is an edit (vs. add).
    pub is_edit: bool,
}

/// Format a signed value as a hex string with sign prefix.
fn format_hex_signed(val: i64) -> String {
    let neg = val < 0;
    let abs_val = if neg { -val } else { val };
    format!("{}0x{:x}", if neg { "-" } else { "+" }, abs_val)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_ref_panel_new() {
        let panel = StackRefPanel::new();
        assert!(!panel.is_valid());
        assert!(!panel.is_editing());
        assert_eq!(panel.stack_offset(), 0);
        assert!(!panel.is_valid_stack_ref());
    }

    #[test]
    fn test_stack_ref_panel_initialize_for_add() {
        let mut panel = StackRefPanel::new();
        assert!(panel.initialize_for_add(0x400000, 1));
        assert!(panel.is_valid());
        assert!(!panel.is_editing());
        assert_eq!(panel.from_address(), Some(0x400000));
        assert_eq!(panel.op_index(), 1);
    }

    #[test]
    fn test_stack_ref_panel_initialize_for_edit() {
        let mut panel = StackRefPanel::new();
        panel.initialize_for_edit(
            0x400000,
            -8,
            RefType::Data(DataRefType::Read),
        );
        assert!(panel.is_valid());
        assert!(panel.is_editing());
        assert_eq!(panel.stack_offset(), -8);
    }

    #[test]
    fn test_stack_ref_panel_set_stack_offset() {
        let mut panel = StackRefPanel::new();
        panel.initialize_for_add(0x400000, 0);
        panel.set_stack_offset(-16);
        assert_eq!(panel.stack_offset(), -16);
    }

    #[test]
    fn test_stack_ref_panel_ref_type() {
        let mut panel = StackRefPanel::new();
        panel.set_ref_type(RefType::Data(DataRefType::Write));
        assert!(matches!(panel.ref_type(), RefType::Data(DataRefType::Write)));
    }

    #[test]
    fn test_stack_ref_panel_available_ref_types() {
        let panel = StackRefPanel::new();
        assert!(!panel.available_ref_types().is_empty());
    }

    #[test]
    fn test_stack_ref_panel_validate_valid() {
        let mut panel = StackRefPanel::new();
        panel.initialize_for_add(0x400000, 0);
        panel.set_stack_offset(-8);
        assert!(panel.validate_and_get_params().is_ok());
    }

    #[test]
    fn test_stack_ref_panel_validate_out_of_bounds() {
        let mut panel = StackRefPanel::new();
        panel.initialize_for_add(0x400000, 0);
        panel.set_stack_bounds(-100, 100);
        panel.set_stack_offset(200);
        assert!(panel.validate_and_get_params().is_err());
    }

    #[test]
    fn test_stack_ref_panel_apply_valid() {
        let mut panel = StackRefPanel::new();
        panel.initialize_for_add(0x400000, 0);
        panel.set_stack_offset(-8);
        let result = panel.apply_reference().unwrap();
        assert_eq!(result.from_addr, 0x400000);
        assert_eq!(result.stack_offset, -8);
        assert!(!result.is_edit);
    }

    #[test]
    fn test_stack_ref_panel_apply_edit() {
        let mut panel = StackRefPanel::new();
        panel.initialize_for_edit(
            0x400000,
            -16,
            RefType::Data(DataRefType::Read),
        );
        let result = panel.apply_reference().unwrap();
        assert!(result.is_edit);
        assert_eq!(result.stack_offset, -16);
    }

    #[test]
    fn test_stack_ref_panel_cleanup() {
        let mut panel = StackRefPanel::new();
        panel.initialize_for_add(0x400000, 0);
        assert!(panel.is_valid());
        panel.cleanup();
        assert!(!panel.is_valid());
        assert!(panel.from_address().is_none());
    }

    #[test]
    fn test_stack_ref_panel_set_op_index() {
        let mut panel = StackRefPanel::new();
        panel.initialize_for_add(0x400000, 0);
        assert!(panel.set_op_index(2, true, Some(-8)));
        assert_eq!(panel.op_index(), 2);
        assert_eq!(panel.stack_offset(), -8);
        assert!(panel.is_valid_stack_ref());
    }

    #[test]
    fn test_stack_ref_panel_set_op_index_no_function() {
        let mut panel = StackRefPanel::new();
        panel.initialize_for_add(0x400000, 0);
        assert!(!panel.set_op_index(2, false, None));
    }

    #[test]
    fn test_stack_ref_panel_set_op_index_edit_mode() {
        let mut panel = StackRefPanel::new();
        panel.initialize_for_edit(
            0x400000,
            -8,
            RefType::Data(DataRefType::Read),
        );
        assert!(!panel.set_op_index(2, true, Some(-8)));
    }

    #[test]
    fn test_stack_ref_panel_valid_stack_ref() {
        let mut panel = StackRefPanel::new();
        panel.set_valid_stack_ref(true);
        assert!(panel.is_valid_stack_ref());
        panel.set_valid_stack_ref(false);
        assert!(!panel.is_valid_stack_ref());
    }

    #[test]
    fn test_format_hex_signed() {
        assert_eq!(format_hex_signed(0), "+0x0");
        assert_eq!(format_hex_signed(8), "+0x8");
        assert_eq!(format_hex_signed(-8), "-0x8");
        assert_eq!(format_hex_signed(255), "+0xff");
        assert_eq!(format_hex_signed(-255), "-0xff");
    }

    #[test]
    fn test_format_stack_offset() {
        assert_eq!(StackRefPanel::format_stack_offset(0), "+0x0");
        assert_eq!(StackRefPanel::format_stack_offset(-8), "-0x8");
        assert_eq!(StackRefPanel::format_stack_offset(16), "+0x10");
    }

    #[test]
    fn test_stack_ref_panel_stack_bounds() {
        let mut panel = StackRefPanel::new();
        panel.set_stack_bounds(-0x80000000, 0x7FFFFFFF);
        assert_eq!(panel.min_stack_offset(), -0x80000000);
        assert_eq!(panel.max_stack_offset(), 0x7FFFFFFF);
    }

    #[test]
    fn test_stack_ref_panel_default() {
        let panel = StackRefPanel::default();
        assert!(!panel.is_valid());
        assert_eq!(panel.stack_offset(), 0);
    }
}
