//! Specialized location descriptor types for "Find References To".
//!
//! Ported from the many `*LocationDescriptor.java` subclasses in
//! `ghidra.app.plugin.core.navigation.locationreferences`.
//!
//! Each descriptor type captures the specific context needed to find
//! references to a particular kind of program element:
//!
//! | Rust struct                           | Java class                             |
//! |---------------------------------------|----------------------------------------|
//! | [`AddressLocationDescriptor`]         | `AddressLocationDescriptor`            |
//! | [`DataTypeLocationDescriptor`]        | `DataTypeLocationDescriptor`           |
//! | [`GenericDataTypeLocationDescriptor`] | `GenericDataTypeLocationDescriptor`    |
//! | [`GenericCompositeDataTypeLocationDescriptor`] | `GenericCompositeDataTypeLocationDescriptor` |
//! | [`LabelLocationDescriptor`]           | `LabelLocationDescriptor`              |
//! | [`MnemonicLocationDescriptor`]        | `MnemonicLocationDescriptor`           |
//! | [`OperandLocationDescriptor`]         | `OperandLocationDescriptor`            |
//! | [`XRefLocationDescriptor`]            | `XRefLocationDescriptor`               |
//! | [`FunctionDefinitionLocationDescriptor`] | `FunctionDefinitionLocationDescriptor` |
//! | [`VariableNameLocationDescriptor`]    | `VariableNameLocationDescriptor`       |
//! | [`VariableTypeLocationDescriptor`]    | `VariableTypeLocationDescriptor`       |
//! | [`VariableXRefLocationDescriptor`]    | `VariableXRefLocationDescriptor`       |
//! | [`StructureMemberLocationDescriptor`] | `StructureMemberLocationDescriptor`    |
//! | [`UnionLocationDescriptor`]           | `UnionLocationDescriptor`              |

use super::locationreferences::{DescriptorKind, LocationDescriptor, LocationReference};
use ghidra_core::Address;

// ---------------------------------------------------------------------------
// Descriptor factory functions
// ---------------------------------------------------------------------------
// Rather than creating a deep type hierarchy, each descriptor type is a
// factory function that produces a `LocationDescriptor` with the correct
// `DescriptorKind` and pre-populated metadata.

/// Create an address location descriptor.
///
/// Used when the user selects "Find References To" on an address that
/// has no more specific descriptor (no label, data type, etc.).
pub fn address_descriptor(address: Address, program_name: &str) -> LocationDescriptor {
    LocationDescriptor::new(
        DescriptorKind::Address,
        address,
        format!("{}", address),
        program_name,
    )
}

/// Create a data-type location descriptor.
///
/// Finds all places where a given data type is applied in the program.
pub fn data_type_descriptor(
    type_name: &str,
    home_address: Address,
    program_name: &str,
) -> LocationDescriptor {
    LocationDescriptor::new(
        DescriptorKind::DataType,
        home_address,
        type_name,
        program_name,
    )
}

/// Create a generic data-type location descriptor.
///
/// Like the data-type descriptor but uses a broader matching strategy:
/// any usage of the type (parameters, local variables, data, etc.)
/// is considered a reference.
pub fn generic_data_type_descriptor(
    type_name: &str,
    home_address: Address,
    program_name: &str,
) -> LocationDescriptor {
    LocationDescriptor::new(
        DescriptorKind::DataType,
        home_address,
        type_name,
        program_name,
    )
}

/// Create a generic composite data-type location descriptor.
///
/// For structures and unions, this finds references to the composite
/// type and also to individual field types.
pub fn generic_composite_data_type_descriptor(
    type_name: &str,
    home_address: Address,
    program_name: &str,
    field_names: &[String],
) -> LocationDescriptor {
    let label = if field_names.is_empty() {
        type_name.to_string()
    } else {
        format!("{} [{} fields]", type_name, field_names.len())
    };
    let mut desc = LocationDescriptor::new(
        DescriptorKind::DataType,
        home_address,
        label,
        program_name,
    );
    desc.set_use_dynamic_searching(true);
    desc
}

/// Create a label location descriptor.
///
/// Finds all references to a label (symbol) at a given address.
pub fn label_descriptor(
    label_name: &str,
    address: Address,
    program_name: &str,
) -> LocationDescriptor {
    LocationDescriptor::new(
        DescriptorKind::Label,
        address,
        label_name,
        program_name,
    )
}

/// Create a mnemonic location descriptor.
///
/// Finds all occurrences of a specific mnemonic (e.g., "MOV", "CALL").
pub fn mnemonic_descriptor(
    mnemonic: &str,
    address: Address,
    program_name: &str,
) -> LocationDescriptor {
    LocationDescriptor::new(
        DescriptorKind::Mnemonic,
        address,
        mnemonic,
        program_name,
    )
}

/// Create an operand location descriptor.
///
/// Finds references to the value at a specific operand position.
pub fn operand_descriptor(
    operand_text: &str,
    address: Address,
    program_name: &str,
    operand_index: usize,
) -> LocationDescriptor {
    let label = format!("operand[{}]: {}", operand_index, operand_text);
    LocationDescriptor::new(
        DescriptorKind::Operand,
        address,
        label,
        program_name,
    )
}

/// Create an XRef (cross-reference) location descriptor.
///
/// Finds all cross-references to a given address.
pub fn xref_descriptor(
    address: Address,
    program_name: &str,
) -> LocationDescriptor {
    LocationDescriptor::new(
        DescriptorKind::Address,
        address,
        format!("xref: {}", address),
        program_name,
    )
}

/// Create a function-definition location descriptor.
///
/// Finds references to a function definition type.
pub fn function_definition_descriptor(
    func_name: &str,
    home_address: Address,
    program_name: &str,
) -> LocationDescriptor {
    LocationDescriptor::new(
        DescriptorKind::FunctionDefinition,
        home_address,
        func_name,
        program_name,
    )
}

/// Create a function-parameter-name location descriptor.
///
/// Finds all references where the parameter name appears.
pub fn function_parameter_name_descriptor(
    param_name: &str,
    func_address: Address,
    program_name: &str,
    param_index: usize,
) -> LocationDescriptor {
    let label = format!("{} (param {})", param_name, param_index);
    LocationDescriptor::new(
        DescriptorKind::FunctionParameterName,
        func_address,
        label,
        program_name,
    )
}

/// Create a function-parameter-type location descriptor.
///
/// Finds all places where the same data type is used as a parameter
/// type in function signatures.
pub fn function_parameter_type_descriptor(
    type_name: &str,
    func_address: Address,
    program_name: &str,
    param_index: usize,
) -> LocationDescriptor {
    let label = format!("{} (param {} type)", type_name, param_index);
    LocationDescriptor::new(
        DescriptorKind::FunctionParameterType,
        func_address,
        label,
        program_name,
    )
}

/// Create a function-return-type location descriptor.
///
/// Finds all functions that use the same return type.
pub fn function_return_type_descriptor(
    type_name: &str,
    func_address: Address,
    program_name: &str,
) -> LocationDescriptor {
    let label = format!("{} (return type)", type_name);
    LocationDescriptor::new(
        DescriptorKind::FunctionReturnType,
        func_address,
        label,
        program_name,
    )
}

/// Create a function-signature-field location descriptor.
///
/// Finds references to a specific field of a function signature.
pub fn function_signature_field_descriptor(
    field_name: &str,
    func_address: Address,
    program_name: &str,
) -> LocationDescriptor {
    LocationDescriptor::new(
        DescriptorKind::FunctionSignature,
        func_address,
        field_name,
        program_name,
    )
}

/// Create a variable-name location descriptor.
///
/// Finds all references where a local variable name appears.
pub fn variable_name_descriptor(
    var_name: &str,
    func_address: Address,
    program_name: &str,
) -> LocationDescriptor {
    LocationDescriptor::new(
        DescriptorKind::VariableName,
        func_address,
        var_name,
        program_name,
    )
}

/// Create a variable-type location descriptor.
///
/// Finds all variables (local or parameter) that use the same type.
pub fn variable_type_descriptor(
    type_name: &str,
    func_address: Address,
    program_name: &str,
) -> LocationDescriptor {
    let label = format!("{} (variable type)", type_name);
    LocationDescriptor::new(
        DescriptorKind::VariableType,
        func_address,
        label,
        program_name,
    )
}

/// Create a variable-xref location descriptor.
///
/// Finds all cross-references that touch a variable's storage location.
pub fn variable_xref_descriptor(
    var_name: &str,
    storage_address: Address,
    program_name: &str,
) -> LocationDescriptor {
    LocationDescriptor::new(
        DescriptorKind::VariableXRef,
        storage_address,
        var_name,
        program_name,
    )
}

/// Create a structure-member location descriptor.
///
/// Finds all references to a field within a structure type.
pub fn structure_member_descriptor(
    struct_name: &str,
    field_name: &str,
    field_offset: usize,
    home_address: Address,
    program_name: &str,
) -> LocationDescriptor {
    let label = format!("{}.{} (offset 0x{:x})", struct_name, field_name, field_offset);
    LocationDescriptor::new(
        DescriptorKind::StructureMember,
        home_address,
        label,
        program_name,
    )
}

/// Create a union-member location descriptor.
///
/// Finds all references to a field within a union type.
pub fn union_member_descriptor(
    union_name: &str,
    field_name: &str,
    home_address: Address,
    program_name: &str,
) -> LocationDescriptor {
    let label = format!("{}.{}", union_name, field_name);
    LocationDescriptor::new(
        DescriptorKind::UnionMember,
        home_address,
        label,
        program_name,
    )
}

// ---------------------------------------------------------------------------
// ReferenceUtils -- utility functions for finding references
// ---------------------------------------------------------------------------

/// Utilities for collecting references to program elements.
///
/// Ported from `ReferenceUtils.java` in the navigation locationreferences
/// package.
pub struct ReferenceUtils;

impl ReferenceUtils {
    /// Filter references to only include those within the given address set.
    pub fn filter_by_addresses(
        refs: &[LocationReference],
        addresses: &[Address],
    ) -> Vec<LocationReference> {
        let addr_set: std::collections::HashSet<Address> = addresses.iter().copied().collect();
        refs.iter()
            .filter(|r| addr_set.contains(&r.location_of_use()))
            .cloned()
            .collect()
    }

    /// Merge two lists of references, removing duplicates.
    pub fn merge_references(
        refs_a: &[LocationReference],
        refs_b: &[LocationReference],
    ) -> Vec<LocationReference> {
        let mut merged: Vec<LocationReference> = refs_a.to_vec();
        for r in refs_b {
            if !merged.iter().any(|m| m == r) {
                merged.push(r.clone());
            }
        }
        merged.sort();
        merged
    }

    /// Get the count of unique addresses in a reference list.
    pub fn unique_address_count(refs: &[LocationReference]) -> usize {
        let addrs: std::collections::HashSet<Address> =
            refs.iter().map(|r| r.location_of_use()).collect();
        addrs.len()
    }

    /// Check if any references are offcut (refer to interior of code units).
    pub fn has_offcut_references(refs: &[LocationReference]) -> bool {
        refs.iter().any(|r| r.is_offcut_reference())
    }

    /// Separate references into oncut and offcut groups.
    pub fn separate_by_offcut(
        refs: &[LocationReference],
    ) -> (Vec<&LocationReference>, Vec<&LocationReference>) {
        let mut oncut = Vec::new();
        let mut offcut = Vec::new();
        for r in refs {
            if r.is_offcut_reference() {
                offcut.push(r);
            } else {
                oncut.push(r);
            }
        }
        (oncut, offcut)
    }

    /// Group references by their reference type string.
    pub fn group_by_ref_type(
        refs: &[LocationReference],
    ) -> std::collections::HashMap<String, Vec<&LocationReference>> {
        let mut map: std::collections::HashMap<String, Vec<&LocationReference>> =
            std::collections::HashMap::new();
        for r in refs {
            map.entry(r.ref_type_string().to_string())
                .or_default()
                .push(r);
        }
        map
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    #[test]
    fn test_address_descriptor() {
        let desc = address_descriptor(addr(0x400000), "test.exe");
        assert_eq!(desc.kind(), &DescriptorKind::Address);
        assert_eq!(desc.home_address(), addr(0x400000));
    }

    #[test]
    fn test_data_type_descriptor() {
        let desc = data_type_descriptor("int", addr(0x1000), "prog");
        assert_eq!(desc.kind(), &DescriptorKind::DataType);
        assert_eq!(desc.label(), "int");
    }

    #[test]
    fn test_label_descriptor() {
        let desc = label_descriptor("main", addr(0x400000), "test.exe");
        assert_eq!(desc.kind(), &DescriptorKind::Label);
        assert_eq!(desc.label(), "main");
    }

    #[test]
    fn test_mnemonic_descriptor() {
        let desc = mnemonic_descriptor("CALL", addr(0x100), "prog");
        assert_eq!(desc.kind(), &DescriptorKind::Mnemonic);
        assert_eq!(desc.label(), "CALL");
    }

    #[test]
    fn test_operand_descriptor() {
        let desc = operand_descriptor("[RAX+0x10]", addr(0x200), "prog", 1);
        assert_eq!(desc.kind(), &DescriptorKind::Operand);
        assert!(desc.label().contains("operand[1]"));
    }

    #[test]
    fn test_xref_descriptor() {
        let desc = xref_descriptor(addr(0x400000), "prog");
        assert_eq!(desc.kind(), &DescriptorKind::Address);
    }

    #[test]
    fn test_function_definition_descriptor() {
        let desc = function_definition_descriptor("myFunc", addr(0x1000), "prog");
        assert_eq!(desc.kind(), &DescriptorKind::FunctionDefinition);
    }

    #[test]
    fn test_function_parameter_name_descriptor() {
        let desc = function_parameter_name_descriptor("argc", addr(0x1000), "prog", 0);
        assert_eq!(desc.kind(), &DescriptorKind::FunctionParameterName);
        assert!(desc.label().contains("param 0"));
    }

    #[test]
    fn test_function_parameter_type_descriptor() {
        let desc = function_parameter_type_descriptor("int", addr(0x1000), "prog", 0);
        assert_eq!(desc.kind(), &DescriptorKind::FunctionParameterType);
    }

    #[test]
    fn test_function_return_type_descriptor() {
        let desc = function_return_type_descriptor("void", addr(0x1000), "prog");
        assert_eq!(desc.kind(), &DescriptorKind::FunctionReturnType);
    }

    #[test]
    fn test_function_signature_field_descriptor() {
        let desc = function_signature_field_descriptor("name", addr(0x1000), "prog");
        assert_eq!(desc.kind(), &DescriptorKind::FunctionSignature);
    }

    #[test]
    fn test_variable_name_descriptor() {
        let desc = variable_name_descriptor("local_10", addr(0x1000), "prog");
        assert_eq!(desc.kind(), &DescriptorKind::VariableName);
    }

    #[test]
    fn test_variable_type_descriptor() {
        let desc = variable_type_descriptor("char*", addr(0x1000), "prog");
        assert_eq!(desc.kind(), &DescriptorKind::VariableType);
    }

    #[test]
    fn test_variable_xref_descriptor() {
        let desc = variable_xref_descriptor("local_10", addr(0x7fff0000), "prog");
        assert_eq!(desc.kind(), &DescriptorKind::VariableXRef);
    }

    #[test]
    fn test_structure_member_descriptor() {
        let desc =
            structure_member_descriptor("my_struct", "field_a", 0x10, addr(0x1000), "prog");
        assert_eq!(desc.kind(), &DescriptorKind::StructureMember);
        assert!(desc.label().contains("my_struct.field_a"));
        assert!(desc.label().contains("0x10"));
    }

    #[test]
    fn test_union_member_descriptor() {
        let desc = union_member_descriptor("my_union", "variant_a", addr(0x1000), "prog");
        assert_eq!(desc.kind(), &DescriptorKind::UnionMember);
        assert!(desc.label().contains("my_union.variant_a"));
    }

    #[test]
    fn test_generic_composite_descriptor() {
        let fields = vec!["x".to_string(), "y".to_string()];
        let desc =
            generic_composite_data_type_descriptor("Point", addr(0x1000), "prog", &fields);
        assert_eq!(desc.kind(), &DescriptorKind::DataType);
        assert!(desc.label().contains("2 fields"));
    }

    #[test]
    fn test_generic_composite_descriptor_no_fields() {
        let desc = generic_composite_data_type_descriptor("Point", addr(0x1000), "prog", &[]);
        assert_eq!(desc.label(), "Point");
    }

    #[test]
    fn test_reference_utils_filter() {
        let refs = vec![
            LocationReference::new(addr(0x1000)),
            LocationReference::new(addr(0x2000)),
            LocationReference::new(addr(0x3000)),
        ];
        let filtered = ReferenceUtils::filter_by_addresses(&refs, &[addr(0x1000), addr(0x3000)]);
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_reference_utils_merge() {
        let a = vec![
            LocationReference::new(addr(0x1000)),
            LocationReference::new(addr(0x2000)),
        ];
        let b = vec![
            LocationReference::new(addr(0x2000)),
            LocationReference::new(addr(0x3000)),
        ];
        let merged = ReferenceUtils::merge_references(&a, &b);
        assert_eq!(merged.len(), 3);
    }

    #[test]
    fn test_reference_utils_unique_count() {
        let refs = vec![
            LocationReference::new(addr(0x1000)),
            LocationReference::new(addr(0x1000)),
            LocationReference::new(addr(0x2000)),
        ];
        assert_eq!(ReferenceUtils::unique_address_count(&refs), 2);
    }

    #[test]
    fn test_reference_utils_offcut() {
        let refs = vec![
            LocationReference::new(addr(0x1000)),
            LocationReference::with_ref_type(addr(0x2000), "READ", true),
        ];
        assert!(ReferenceUtils::has_offcut_references(&refs));

        let (oncut, offcut) = ReferenceUtils::separate_by_offcut(&refs);
        assert_eq!(oncut.len(), 1);
        assert_eq!(offcut.len(), 1);
    }

    #[test]
    fn test_reference_utils_group_by_ref_type() {
        let refs = vec![
            LocationReference::with_ref_type(addr(0x1000), "READ", false),
            LocationReference::with_ref_type(addr(0x2000), "WRITE", false),
            LocationReference::with_ref_type(addr(0x3000), "READ", false),
        ];
        let groups = ReferenceUtils::group_by_ref_type(&refs);
        assert_eq!(groups.get("READ").unwrap().len(), 2);
        assert_eq!(groups.get("WRITE").unwrap().len(), 1);
    }

    #[test]
    fn test_descriptor_display() {
        let desc = data_type_descriptor("int", addr(0x1000), "prog");
        let s = format!("{}", desc);
        assert!(s.contains("Data Type"));
        assert!(s.contains("int"));
    }
}
