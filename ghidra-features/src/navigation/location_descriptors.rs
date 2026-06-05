//! Location descriptor types -- ported from the various
//! `*LocationDescriptor` classes in `ghidra.app.plugin.core.navigation`.
//!
//! Each descriptor encapsulates a "location" within a program that can
//! be searched for references or navigated to.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// LocationDescriptorKind -- discriminant for the descriptor enum
// ---------------------------------------------------------------------------

/// Kinds of location descriptors in the navigation system.
///
/// Ported from the abstract `LocationDescriptor` hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LocationDescriptorKind {
    /// An address in memory.
    Address,
    /// A label (symbol name) at an address.
    Label,
    /// A mnemonic (instruction opcode name).
    Mnemonic,
    /// An operand field value.
    Operand,
    /// A data-type location (from a structure/class field).
    DataType,
    /// A function signature field.
    FunctionSignature,
    /// A function return type.
    FunctionReturnType,
    /// A function parameter name.
    FunctionParameterName,
    /// A function parameter type.
    FunctionParameterType,
    /// A generic composite data-type (struct/union).
    GenericCompositeDataType,
    /// A generic data-type.
    GenericDataType,
    /// A structure member.
    StructureMember,
    /// A union member.
    Union,
    /// A variable name.
    VariableName,
    /// A variable type.
    VariableType,
    /// A cross-reference location.
    XRef,
    /// A function definition.
    FunctionDefinition,
    /// A variable cross-reference.
    VariableXRef,
}

// ---------------------------------------------------------------------------
// LocationDescriptor -- a navigable location in a program
// ---------------------------------------------------------------------------

/// A descriptor for a location within a program that can be the target
/// of navigation or reference-search operations.
///
/// Ported from the abstract `LocationDescriptor` class and its subclasses
/// in `ghidra.app.plugin.core.navigation.locationreferences`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationDescriptor {
    /// The kind of location.
    pub kind: LocationDescriptorKind,
    /// The address (if applicable).
    pub address: Option<u64>,
    /// The label/text at this location.
    pub label: String,
    /// The data-type name (if applicable).
    pub data_type_name: Option<String>,
    /// The namespace path (if applicable).
    pub namespace: Option<String>,
    /// The function entry point (if inside a function).
    pub function_entry: Option<u64>,
    /// The field name (for structure/union members).
    pub field_name: Option<String>,
    /// The operand index (for operand locations).
    pub operand_index: Option<usize>,
    /// Additional context information.
    pub context: String,
}

impl LocationDescriptor {
    /// Create a new address location descriptor.
    pub fn address(addr: u64) -> Self {
        Self {
            kind: LocationDescriptorKind::Address,
            address: Some(addr),
            label: format!("0x{:x}", addr),
            data_type_name: None,
            namespace: None,
            function_entry: None,
            field_name: None,
            operand_index: None,
            context: String::new(),
        }
    }

    /// Create a new label location descriptor.
    pub fn label(addr: u64, name: impl Into<String>) -> Self {
        let name = name.into();
        Self {
            kind: LocationDescriptorKind::Label,
            address: Some(addr),
            label: name,
            data_type_name: None,
            namespace: None,
            function_entry: None,
            field_name: None,
            operand_index: None,
            context: String::new(),
        }
    }

    /// Create a new mnemonic location descriptor.
    pub fn mnemonic(addr: u64, mnemonic: impl Into<String>) -> Self {
        Self {
            kind: LocationDescriptorKind::Mnemonic,
            address: Some(addr),
            label: mnemonic.into(),
            data_type_name: None,
            namespace: None,
            function_entry: None,
            field_name: None,
            operand_index: None,
            context: String::new(),
        }
    }

    /// Create a new operand location descriptor.
    pub fn operand(addr: u64, operand_text: impl Into<String>, op_index: usize) -> Self {
        Self {
            kind: LocationDescriptorKind::Operand,
            address: Some(addr),
            label: operand_text.into(),
            data_type_name: None,
            namespace: None,
            function_entry: None,
            field_name: None,
            operand_index: Some(op_index),
            context: String::new(),
        }
    }

    /// Create a new data-type location descriptor.
    pub fn data_type(addr: Option<u64>, type_name: impl Into<String>) -> Self {
        Self {
            kind: LocationDescriptorKind::DataType,
            address: addr,
            label: String::new(),
            data_type_name: Some(type_name.into()),
            namespace: None,
            function_entry: None,
            field_name: None,
            operand_index: None,
            context: String::new(),
        }
    }

    /// Create a function signature field descriptor.
    pub fn function_signature(func_addr: u64, field_text: impl Into<String>) -> Self {
        Self {
            kind: LocationDescriptorKind::FunctionSignature,
            address: Some(func_addr),
            label: field_text.into(),
            data_type_name: None,
            namespace: None,
            function_entry: Some(func_addr),
            field_name: None,
            operand_index: None,
            context: String::new(),
        }
    }

    /// Create a structure member descriptor.
    pub fn structure_member(
        struct_name: impl Into<String>,
        field_name: impl Into<String>,
    ) -> Self {
        let field = field_name.into();
        Self {
            kind: LocationDescriptorKind::StructureMember,
            address: None,
            label: format!("{}.{}", struct_name.into(), field),
            data_type_name: None,
            namespace: None,
            function_entry: None,
            field_name: Some(field),
            operand_index: None,
            context: String::new(),
        }
    }

    /// Create an XRef location descriptor.
    pub fn xref(from_addr: u64, to_addr: u64) -> Self {
        Self {
            kind: LocationDescriptorKind::XRef,
            address: Some(from_addr),
            label: format!("0x{:x} -> 0x{:x}", from_addr, to_addr),
            data_type_name: None,
            namespace: None,
            function_entry: None,
            field_name: None,
            operand_index: None,
            context: format!("to:0x{:x}", to_addr),
        }
    }

    /// Create a variable name descriptor.
    pub fn variable_name(
        func_addr: u64,
        var_name: impl Into<String>,
    ) -> Self {
        Self {
            kind: LocationDescriptorKind::VariableName,
            address: Some(func_addr),
            label: var_name.into(),
            data_type_name: None,
            namespace: None,
            function_entry: Some(func_addr),
            field_name: None,
            operand_index: None,
            context: String::new(),
        }
    }

    /// Whether this descriptor represents a data-type location.
    pub fn is_data_type(&self) -> bool {
        matches!(
            self.kind,
            LocationDescriptorKind::DataType
                | LocationDescriptorKind::GenericDataType
                | LocationDescriptorKind::GenericCompositeDataType
                | LocationDescriptorKind::FunctionReturnType
                | LocationDescriptorKind::FunctionParameterType
                | LocationDescriptorKind::VariableType
                | LocationDescriptorKind::StructureMember
                | LocationDescriptorKind::Union
        )
    }

    /// Whether this descriptor is inside a function.
    pub fn is_in_function(&self) -> bool {
        self.function_entry.is_some()
    }
}

// ---------------------------------------------------------------------------
// LocationReference -- a reference found for a LocationDescriptor
// ---------------------------------------------------------------------------

/// A reference to or from a location, used in the "Find References"
/// result set.
///
/// Ported from `LocationReference.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocationReference {
    /// The source address of the reference.
    pub from_address: u64,
    /// The target address.
    pub to_address: u64,
    /// The reference type description.
    pub ref_type: String,
    /// The label at the from address.
    pub from_label: String,
    /// The label at the to address.
    pub to_label: String,
    /// Whether this is a read reference.
    pub is_read: bool,
    /// Whether this is a write reference.
    pub is_write: bool,
    /// Whether this is a flow (call/jump) reference.
    pub is_flow: bool,
    /// The function entry containing the from address (if any).
    pub from_function: Option<u64>,
}

impl LocationReference {
    /// Create a new location reference.
    pub fn new(from_address: u64, to_address: u64, ref_type: impl Into<String>) -> Self {
        Self {
            from_address,
            to_address,
            ref_type: ref_type.into(),
            from_label: String::new(),
            to_label: String::new(),
            is_read: false,
            is_write: false,
            is_flow: false,
            from_function: None,
        }
    }

    /// Create a read reference.
    pub fn read(from: u64, to: u64) -> Self {
        let mut r = Self::new(from, to, "READ");
        r.is_read = true;
        r
    }

    /// Create a write reference.
    pub fn write(from: u64, to: u64) -> Self {
        let mut r = Self::new(from, to, "WRITE");
        r.is_write = true;
        r
    }

    /// Create a call reference.
    pub fn call(from: u64, to: u64) -> Self {
        let mut r = Self::new(from, to, "CALL");
        r.is_flow = true;
        r
    }

    /// Create a jump reference.
    pub fn jump(from: u64, to: u64) -> Self {
        let mut r = Self::new(from, to, "JUMP");
        r.is_flow = true;
        r
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_descriptor() {
        let d = LocationDescriptor::address(0x400000);
        assert_eq!(d.kind, LocationDescriptorKind::Address);
        assert_eq!(d.address, Some(0x400000));
        assert_eq!(d.label, "0x400000");
        assert!(!d.is_data_type());
    }

    #[test]
    fn test_label_descriptor() {
        let d = LocationDescriptor::label(0x400000, "main");
        assert_eq!(d.kind, LocationDescriptorKind::Label);
        assert_eq!(d.label, "main");
    }

    #[test]
    fn test_mnemonic_descriptor() {
        let d = LocationDescriptor::mnemonic(0x400000, "MOV");
        assert_eq!(d.kind, LocationDescriptorKind::Mnemonic);
        assert_eq!(d.label, "MOV");
    }

    #[test]
    fn test_operand_descriptor() {
        let d = LocationDescriptor::operand(0x400000, "RAX", 0);
        assert_eq!(d.kind, LocationDescriptorKind::Operand);
        assert_eq!(d.operand_index, Some(0));
    }

    #[test]
    fn test_data_type_descriptor() {
        let d = LocationDescriptor::data_type(Some(0x400000), "int");
        assert!(d.is_data_type());
        assert_eq!(d.data_type_name.as_deref(), Some("int"));
    }

    #[test]
    fn test_function_signature_descriptor() {
        let d = LocationDescriptor::function_signature(0x400000, "int main(int argc)");
        assert_eq!(d.kind, LocationDescriptorKind::FunctionSignature);
        assert!(d.is_in_function());
        assert_eq!(d.function_entry, Some(0x400000));
    }

    #[test]
    fn test_structure_member_descriptor() {
        let d = LocationDescriptor::structure_member("myStruct", "field1");
        assert_eq!(d.kind, LocationDescriptorKind::StructureMember);
        assert!(d.is_data_type());
        assert_eq!(d.field_name.as_deref(), Some("field1"));
    }

    #[test]
    fn test_xref_descriptor() {
        let d = LocationDescriptor::xref(0x400000, 0x401000);
        assert_eq!(d.kind, LocationDescriptorKind::XRef);
        assert_eq!(d.address, Some(0x400000));
    }

    #[test]
    fn test_variable_name_descriptor() {
        let d = LocationDescriptor::variable_name(0x400000, "local_var");
        assert_eq!(d.kind, LocationDescriptorKind::VariableName);
        assert!(d.is_in_function());
    }

    #[test]
    fn test_location_reference() {
        let r = LocationReference::new(0x400000, 0x401000, "CALL");
        assert_eq!(r.from_address, 0x400000);
        assert_eq!(r.to_address, 0x401000);
        assert_eq!(r.ref_type, "CALL");
    }

    #[test]
    fn test_location_reference_types() {
        let r = LocationReference::read(0x100, 0x200);
        assert!(r.is_read);
        assert!(!r.is_write);

        let r = LocationReference::write(0x100, 0x200);
        assert!(r.is_write);

        let r = LocationReference::call(0x100, 0x200);
        assert!(r.is_flow);
        assert_eq!(r.ref_type, "CALL");

        let r = LocationReference::jump(0x100, 0x200);
        assert!(r.is_flow);
        assert_eq!(r.ref_type, "JUMP");
    }

    #[test]
    fn test_is_data_type_variants() {
        assert!(LocationDescriptor::data_type(None, "int").is_data_type());
        let mut d = LocationDescriptor::address(0x100);
        d.kind = LocationDescriptorKind::VariableType;
        assert!(d.is_data_type());
        d.kind = LocationDescriptorKind::FunctionReturnType;
        assert!(d.is_data_type());
        d.kind = LocationDescriptorKind::Label;
        assert!(!d.is_data_type());
    }
}
