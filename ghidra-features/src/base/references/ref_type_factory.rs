//! Reference type factory -- provides allowed reference type arrays.
//!
//! Ported from `ghidra.program.model.symbol.RefTypeFactory` and usage in the
//! Java reference panels.

use ghidra_core::symbol::{DataRefType, FlowType, RefType};

/// Factory for obtaining the allowed [`RefType`] arrays for different kinds
/// of references.
///
/// In Ghidra the `RefTypeFactory` produces static arrays. Here we return
/// `&'static [RefType]` slices for each category.
pub struct RefTypeFactory;

impl RefTypeFactory {
    /// Allowed types for memory references (code flow or data).
    const MEMORY_REF_TYPES: &'static [RefType] = &[
        RefType::Flow(FlowType::UnconditionalJump),
        RefType::Flow(FlowType::ConditionalJump),
        RefType::Flow(FlowType::UnconditionalCall),
        RefType::Flow(FlowType::ConditionalCall),
        RefType::Flow(FlowType::ComputedJump),
        RefType::Flow(FlowType::ComputedCall),
        RefType::Data(DataRefType::Data),
        RefType::Data(DataRefType::Read),
        RefType::Data(DataRefType::Write),
        RefType::Data(DataRefType::ReadWrite),
        RefType::Data(DataRefType::ReadInd),
        RefType::Data(DataRefType::WriteInd),
        RefType::Data(DataRefType::ReadWriteInd),
        RefType::Data(DataRefType::Param),
    ];

    /// Allowed types for stack references.
    const STACK_REF_TYPES: &'static [RefType] = &[
        RefType::Data(DataRefType::Read),
        RefType::Data(DataRefType::Write),
        RefType::Data(DataRefType::ReadWrite),
    ];

    /// Allowed types for register references.
    const DATA_REF_TYPES: &'static [RefType] = &[
        RefType::Data(DataRefType::Data),
        RefType::Data(DataRefType::Read),
        RefType::Data(DataRefType::Write),
        RefType::Data(DataRefType::ReadWrite),
        RefType::Data(DataRefType::ReadInd),
        RefType::Data(DataRefType::WriteInd),
        RefType::Data(DataRefType::ReadWriteInd),
    ];

    /// Allowed types for external references.
    const EXTERNAL_REF_TYPES: &'static [RefType] = &[
        RefType::Data(DataRefType::Data),
        RefType::Flow(FlowType::UnconditionalCall),
        RefType::Flow(FlowType::ComputedCall),
        RefType::Flow(FlowType::UnconditionalJump),
        RefType::Flow(FlowType::ComputedJump),
    ];

    /// Returns the reference types allowed for memory references.
    pub fn get_memory_ref_types() -> &'static [RefType] {
        Self::MEMORY_REF_TYPES
    }

    /// Returns the reference types allowed for stack references.
    pub fn get_stack_ref_types() -> &'static [RefType] {
        Self::STACK_REF_TYPES
    }

    /// Returns the reference types allowed for data/register references.
    pub fn get_data_ref_types() -> &'static [RefType] {
        Self::DATA_REF_TYPES
    }

    /// Returns the reference types allowed for external references.
    pub fn get_external_ref_types() -> &'static [RefType] {
        Self::EXTERNAL_REF_TYPES
    }

    /// Returns the default memory reference type for a given from-address,
    /// operand, and optional destination.
    ///
    /// If the code unit at `from_addr` is an instruction, the flow type is
    /// inferred; otherwise `DATA` is used.
    pub fn get_default_memory_ref_type(
        is_instruction: bool,
        is_computed_flow: bool,
        is_call_flow: bool,
    ) -> RefType {
        if !is_instruction {
            return RefType::Data(DataRefType::Data);
        }
        if is_computed_flow {
            if is_call_flow {
                RefType::Flow(FlowType::ComputedCall)
            } else {
                RefType::Flow(FlowType::ComputedJump)
            }
        } else if is_call_flow {
            RefType::Flow(FlowType::UnconditionalCall)
        } else {
            RefType::Flow(FlowType::UnconditionalJump)
        }
    }

    /// Returns the default stack reference type.
    pub fn get_default_stack_ref_type() -> RefType {
        RefType::Data(DataRefType::Read)
    }

    /// Returns the default stack reference type for a given operand index.
    ///
    /// Currently ignores the operand index and returns the default stack
    /// reference type (Read).
    pub fn get_default_stack_ref_type_for_operand(_op_index: i32) -> RefType {
        Self::get_default_stack_ref_type()
    }

    /// Returns the default register reference type.
    ///
    /// Uses the provided register's default reference type (typically `WRITE`).
    pub fn get_default_register_ref_type() -> RefType {
        RefType::Data(DataRefType::Write)
    }

    /// Returns the default memory reference type for a given operand index.
    ///
    /// If `is_computed_flow` is true, returns a computed jump type; otherwise
    /// returns the data reference type.
    pub fn get_default_memory_ref_type_for_operand(
        _op_index: i32,
        is_computed_flow: bool,
    ) -> RefType {
        Self::get_default_memory_ref_type(false, is_computed_flow, false)
    }

    /// Determines the allowed reference types for a specific reference,
    /// based on the destination address kind.
    ///
    /// Mirrors `EditReferencesModel.getAllowedRefTypes()`.
    pub fn get_allowed_ref_types(
        to_addr_is_memory: bool,
        to_addr_is_stack: bool,
        to_addr_is_register: bool,
        to_addr_is_external: bool,
        is_computed_flow: bool,
    ) -> &'static [RefType] {
        if to_addr_is_stack {
            return Self::get_stack_ref_types();
        }
        if to_addr_is_register {
            return Self::get_data_ref_types();
        }
        if to_addr_is_memory {
            if is_computed_flow {
                return Self::get_memory_ref_types();
            }
            return Self::get_data_ref_types();
        }
        if to_addr_is_external {
            return Self::get_external_ref_types();
        }
        // Fallback: data ref types.
        Self::get_data_ref_types()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_ref_types_not_empty() {
        assert!(!RefTypeFactory::get_memory_ref_types().is_empty());
    }

    #[test]
    fn test_stack_ref_types_not_empty() {
        assert!(!RefTypeFactory::get_stack_ref_types().is_empty());
    }

    #[test]
    fn test_data_ref_types_not_empty() {
        assert!(!RefTypeFactory::get_data_ref_types().is_empty());
    }

    #[test]
    fn test_external_ref_types_not_empty() {
        assert!(!RefTypeFactory::get_external_ref_types().is_empty());
    }

    #[test]
    fn test_default_memory_ref_for_data() {
        let rt = RefTypeFactory::get_default_memory_ref_type(false, false, false);
        assert_eq!(rt, RefType::Data(DataRefType::Data));
    }

    #[test]
    fn test_default_memory_ref_for_instruction_call() {
        let rt = RefTypeFactory::get_default_memory_ref_type(true, false, true);
        assert_eq!(rt, RefType::Flow(FlowType::UnconditionalCall));
    }

    #[test]
    fn test_default_memory_ref_for_instruction_jump() {
        let rt = RefTypeFactory::get_default_memory_ref_type(true, false, false);
        assert_eq!(rt, RefType::Flow(FlowType::UnconditionalJump));
    }

    #[test]
    fn test_default_memory_ref_for_computed_call() {
        let rt = RefTypeFactory::get_default_memory_ref_type(true, true, true);
        assert_eq!(rt, RefType::Flow(FlowType::ComputedCall));
    }

    #[test]
    fn test_default_memory_ref_for_computed_jump() {
        let rt = RefTypeFactory::get_default_memory_ref_type(true, true, false);
        assert_eq!(rt, RefType::Flow(FlowType::ComputedJump));
    }

    #[test]
    fn test_allowed_ref_types_stack() {
        let types = RefTypeFactory::get_allowed_ref_types(false, true, false, false, false);
        assert_eq!(types, RefTypeFactory::get_stack_ref_types());
    }

    #[test]
    fn test_allowed_ref_types_register() {
        let types = RefTypeFactory::get_allowed_ref_types(false, false, true, false, false);
        assert_eq!(types, RefTypeFactory::get_data_ref_types());
    }

    #[test]
    fn test_allowed_ref_types_memory_computed() {
        let types = RefTypeFactory::get_allowed_ref_types(true, false, false, false, true);
        assert_eq!(types, RefTypeFactory::get_memory_ref_types());
    }

    #[test]
    fn test_allowed_ref_types_external() {
        let types = RefTypeFactory::get_allowed_ref_types(false, false, false, true, false);
        assert_eq!(types, RefTypeFactory::get_external_ref_types());
    }
}
