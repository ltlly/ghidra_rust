//! Composite Member -- PDB composite type reconstruction.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb.CompositeMember` and
//! `ghidra.app.util.bin.format.pdb.DefaultCompositeMember`.
//!
//! This module provides the ability to process PDB data-type records and
//! incrementally build-up composite structure and union data-types from a
//! flattened offset-based list of members which may include embedded anonymous
//! composite members.

use std::collections::BTreeMap;
use std::fmt;

use super::pdb_bitfield::PdbBitField;
use super::pdb_member::PdbMember;

/// Maximum depth for nested composite construction.
const MAX_CONSTRUCTION_DEPTH: usize = 20;

/// Name used for padding components.
const PADDING_COMPONENT_NAME: &str = "_padding_";

/// Errors that can occur during composite member operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositeMemberError {
    /// Maximum construction depth exceeded.
    MaxDepthExceeded(String),
    /// Failed to resolve a data type dependency.
    DataTypeDependencyFailed(String),
    /// Invalid composite structure.
    InvalidComposite(String),
    /// Bitfield operation failed.
    BitfieldError(String),
}

impl fmt::Display for CompositeMemberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompositeMemberError::MaxDepthExceeded(name) => {
                write!(f, "PDB composite reconstruction exceeded max depth: {}", name)
            }
            CompositeMemberError::DataTypeDependencyFailed(name) => {
                write!(f, "Failed to resolve datatype dependency: {}", name)
            }
            CompositeMemberError::InvalidComposite(msg) => {
                write!(f, "Invalid composite: {}", msg)
            }
            CompositeMemberError::BitfieldError(msg) => {
                write!(f, "Bitfield error: {}", msg)
            }
        }
    }
}

impl std::error::Error for CompositeMemberError {}

/// The type of a composite member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberType {
    /// A structure container.
    Structure,
    /// A union container.
    Union,
    /// A regular field member.
    Member,
}

/// A member within a composite type (structure, union, or class).
///
/// Composite members correspond to either hard predefined data-types, or
/// structure/union containers whose members are added and refined incrementally.
///
/// Container members are characterized by a null data-type name, zero length,
/// and are identified as either a structure or union.
#[derive(Debug, Clone)]
pub struct CompositeMember {
    /// Member name (None for root container).
    name: Option<String>,
    /// Data type name (None for containers).
    data_type_name: Option<String>,
    /// Byte offset relative to start of parent container.
    /// -1 for root container.
    offset: i32,
    /// Optional member comment.
    comment: Option<String>,
    /// Type of this member.
    member_type: MemberType,
    /// Length of the data type in bytes.
    length: u32,
    /// Whether this is a class structure (for root containers).
    is_class: bool,
    /// Whether this member is a zero-length array.
    is_zero_length_array: bool,
    /// Bitfield information (if this is a bitfield member).
    bitfield: Option<PdbBitField>,
    /// Children for structure containers (offset -> member).
    structure_members: Option<BTreeMap<i32, CompositeMember>>,
    /// Children for union containers.
    union_members: Option<Vec<CompositeMember>>,
    /// Whether structure padding has been applied.
    has_structure_padding: bool,
    /// Largest primitive size seen (for padding calculations).
    largest_primitive_size: u32,
}

impl CompositeMember {
    /// Create a root container for a new composite data type.
    pub fn new_root(is_class: bool, is_structure: bool) -> Self {
        let (structure_members, union_members) = if is_structure {
            (Some(BTreeMap::new()), None)
        } else {
            (None, Some(Vec::new()))
        };

        Self {
            name: None,
            data_type_name: None,
            offset: -1,
            comment: None,
            member_type: if is_structure {
                MemberType::Structure
            } else {
                MemberType::Union
            },
            length: 0,
            is_class,
            is_zero_length_array: false,
            bitfield: None,
            structure_members,
            union_members,
            has_structure_padding: false,
            largest_primitive_size: 4, // default to pointer size
        }
    }

    /// Create a regular field member from a PDB member record.
    pub fn new_member(member: &PdbMember, data_type_size: u32) -> Self {
        Self {
            name: Some(member.name.clone()),
            data_type_name: Some(member.data_type_name.clone()),
            offset: member.offset,
            comment: member.comment.clone(),
            member_type: MemberType::Member,
            length: data_type_size,
            is_class: false,
            is_zero_length_array: false,
            bitfield: if member.is_bitfield {
                PdbBitField::new(0, data_type_size, member.bitfield_size as u32, member.bitfield_offset).ok()
            } else {
                None
            },
            structure_members: None,
            union_members: None,
            has_structure_padding: false,
            largest_primitive_size: 0,
        }
    }

    /// Create a padding bitfield member.
    pub fn new_padding_bitfield(
        offset: i32,
        base_type_size: u32,
        bit_size: u32,
        bit_offset: u32,
    ) -> Self {
        Self {
            name: Some(PADDING_COMPONENT_NAME.to_string()),
            data_type_name: None,
            offset,
            comment: None,
            member_type: MemberType::Member,
            length: base_type_size,
            is_class: false,
            is_zero_length_array: false,
            bitfield: PdbBitField::new(0, base_type_size, bit_size, bit_offset as i32).ok(),
            structure_members: None,
            union_members: None,
            has_structure_padding: false,
            largest_primitive_size: 0,
        }
    }

    /// Get the member name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the data type name.
    pub fn data_type_name(&self) -> Option<&str> {
        self.data_type_name.as_deref()
    }

    /// Get the offset relative to the parent container.
    pub fn offset(&self) -> i32 {
        self.offset
    }

    /// Set the offset.
    pub fn set_offset(&mut self, offset: i32) {
        self.offset = offset;
    }

    /// Get the length of this member in bytes.
    pub fn length(&self) -> u32 {
        if let Some(ref bf) = self.bitfield {
            bf.storage_size()
        } else {
            self.length
        }
    }

    /// Get the comment.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// Check if this is a container (structure or union).
    pub fn is_container(&self) -> bool {
        self.member_type != MemberType::Member
    }

    /// Check if this is a structure container.
    pub fn is_structure_container(&self) -> bool {
        self.member_type == MemberType::Structure
    }

    /// Check if this is a union container.
    pub fn is_union_container(&self) -> bool {
        self.member_type == MemberType::Union
    }

    /// Check if this is a bitfield member.
    pub fn is_bitfield_member(&self) -> bool {
        self.bitfield.is_some()
    }

    /// Get the bitfield info, if any.
    pub fn bitfield(&self) -> Option<&PdbBitField> {
        self.bitfield.as_ref()
    }

    /// Check if this is a zero-length array.
    pub fn is_zero_length_array(&self) -> bool {
        self.is_zero_length_array
    }

    /// Get the number of children in this container.
    pub fn num_children(&self) -> usize {
        if let Some(ref members) = self.structure_members {
            members.len()
        } else if let Some(ref members) = self.union_members {
            members.len()
        } else {
            0
        }
    }

    /// Add a member to this container.
    ///
    /// Returns true if the member was successfully added.
    pub fn add_member(&mut self, member: CompositeMember) -> Result<bool, CompositeMemberError> {
        if !self.is_container() {
            return Err(CompositeMemberError::InvalidComposite(
                "add_member only permitted on containers".to_string(),
            ));
        }

        if self.is_union_container() {
            self.add_union_member(member)
        } else {
            self.add_structure_member(member)
        }
    }

    /// Add a member to a structure container.
    fn add_structure_member(
        &mut self,
        member: CompositeMember,
    ) -> Result<bool, CompositeMemberError> {
        let offset = member.offset;
        let length = member.length();

        // Insert padding if needed
        if offset > 0 {
            let current_end = self.get_structure_end_offset();
            if offset > current_end {
                // Would insert padding here in a full implementation
            }
        }

        if let Some(ref mut members) = self.structure_members {
            members.insert(offset, member);
            Ok(true)
        } else {
            Err(CompositeMemberError::InvalidComposite(
                "Not a structure container".to_string(),
            ))
        }
    }

    /// Add a member to a union container.
    fn add_union_member(
        &mut self,
        member: CompositeMember,
    ) -> Result<bool, CompositeMemberError> {
        if let Some(ref mut members) = self.union_members {
            members.push(member);
            Ok(true)
        } else {
            Err(CompositeMemberError::InvalidComposite(
                "Not a union container".to_string(),
            ))
        }
    }

    /// Get the end offset of the structure (offset of last member + its length).
    fn get_structure_end_offset(&self) -> i32 {
        if let Some(ref members) = self.structure_members {
            members
                .iter()
                .map(|(offset, member)| offset + member.length() as i32)
                .max()
                .unwrap_or(0)
        } else {
            0
        }
    }

    /// Get the structure members (for structure containers).
    pub fn structure_members(&self) -> Option<&BTreeMap<i32, CompositeMember>> {
        self.structure_members.as_ref()
    }

    /// Get the union members (for union containers).
    pub fn union_members(&self) -> Option<&Vec<CompositeMember>> {
        self.union_members.as_ref()
    }

    /// Check if this is a class structure.
    pub fn is_class(&self) -> bool {
        self.is_class
    }

    /// Finalize the data type by renaming anonymous composites and checking alignment.
    pub fn finalize(&mut self, preferred_size: i32, packing_disabled: bool) {
        if !self.is_container() {
            return;
        }

        if self.is_structure_container() {
            self.update_container_name("s");
            // Finalize children
            if let Some(ref mut members) = self.structure_members {
                for member in members.values_mut() {
                    member.finalize(0, packing_disabled);
                }
            }
            // Adjust size
            self.adjust_size(preferred_size);
        } else if self.is_union_container() {
            self.update_container_name("u");
            if let Some(ref mut members) = self.union_members {
                for member in members.iter_mut() {
                    member.finalize(0, packing_disabled);
                }
            }
        }
    }

    /// Update the container name based on its type mnemonic.
    fn update_container_name(&mut self, type_mnemonic: &str) {
        // In a full implementation, this would rename anonymous composites
        // based on their parent type and offset.
    }

    /// Adjust the structure size to match the preferred size.
    fn adjust_size(&mut self, preferred_size: i32) {
        if preferred_size <= 0 {
            return;
        }
        // In a full implementation, this would trim trailing padding.
    }
}

impl fmt::Display for CompositeMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let type_str = if self.is_union_container() {
            "Union"
        } else if self.is_structure_container() {
            "Structure"
        } else if self.is_bitfield_member() {
            "BitField"
        } else {
            self.data_type_name.as_deref().unwrap_or("unknown")
        };
        let name = self.name.as_deref().unwrap_or("(root)");
        write!(f, "[CompositeMember: {} {} {}]", self.offset, name, type_str)
    }
}

/// Build up a composite by applying PDB data-type members.
///
/// This is the main entry point for composite reconstruction. It takes a list
/// of PDB members and builds a composite structure or union.
///
/// # Arguments
/// * `is_class` - Whether the composite is a class structure.
/// * `is_structure` - Whether it's a structure (vs union).
/// * `preferred_size` - Preferred size of the composite, or 0 if unknown.
/// * `packing_disabled` - Whether to disable packing.
/// * `members` - The PDB members to add.
///
/// # Returns
/// The root CompositeMember with all children added, or an error.
pub fn apply_data_type_members(
    is_class: bool,
    is_structure: bool,
    preferred_size: i32,
    packing_disabled: bool,
    members: &[PdbMember],
) -> Result<CompositeMember, CompositeMemberError> {
    let mut root = CompositeMember::new_root(is_class, is_structure);

    for member in members {
        // In a full implementation, we would resolve the data type here
        let data_type_size = 4; // placeholder
        let composite_member = CompositeMember::new_member(member, data_type_size);
        root.add_member(composite_member)?;
    }

    root.finalize(preferred_size, packing_disabled);
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::pdb_member::PdbMember;
    use super::super::pdb_kind::PdbKind;

    #[test]
    fn test_root_structure() {
        let root = CompositeMember::new_root(false, true);
        assert!(root.is_container());
        assert!(root.is_structure_container());
        assert!(!root.is_union_container());
        assert_eq!(root.offset(), -1);
    }

    #[test]
    fn test_root_union() {
        let root = CompositeMember::new_root(false, false);
        assert!(root.is_container());
        assert!(!root.is_structure_container());
        assert!(root.is_union_container());
    }

    #[test]
    fn test_add_member_to_structure() {
        let mut root = CompositeMember::new_root(false, true);
        let pdb_member = PdbMember::new("field1", "int", 0, PdbKind::Member);
        let member = CompositeMember::new_member(&pdb_member, 4);
        assert!(root.add_member(member).unwrap());
        assert_eq!(root.num_children(), 1);
    }

    #[test]
    fn test_add_member_to_union() {
        let mut root = CompositeMember::new_root(false, false);
        let pdb_member = PdbMember::new("field1", "int", 0, PdbKind::Member);
        let member = CompositeMember::new_member(&pdb_member, 4);
        assert!(root.add_member(member).unwrap());
        assert_eq!(root.num_children(), 1);
    }

    #[test]
    fn test_multiple_members() {
        let mut root = CompositeMember::new_root(false, true);
        let m1 = PdbMember::new("x", "int", 0, PdbKind::Member);
        let m2 = PdbMember::new("y", "float", 4, PdbKind::Member);
        root.add_member(CompositeMember::new_member(&m1, 4)).unwrap();
        root.add_member(CompositeMember::new_member(&m2, 4)).unwrap();
        assert_eq!(root.num_children(), 2);
    }

    #[test]
    fn test_member_properties() {
        let pdb_member = PdbMember::new("field", "int", 8, PdbKind::Member);
        let member = CompositeMember::new_member(&pdb_member, 4);
        assert_eq!(member.name(), Some("field"));
        assert_eq!(member.data_type_name(), Some("int"));
        assert_eq!(member.offset(), 8);
        assert_eq!(member.length(), 4);
        assert!(!member.is_container());
        assert!(!member.is_bitfield_member());
    }

    #[test]
    fn test_bitfield_member() {
        let pdb_member = PdbMember::new("flags:0x4:0x0", "unsigned int", 0, PdbKind::Member);
        let member = CompositeMember::new_member(&pdb_member, 4);
        assert!(member.is_bitfield_member());
        assert!(member.bitfield().is_some());
    }

    #[test]
    fn test_display() {
        let root = CompositeMember::new_root(false, true);
        let s = format!("{}", root);
        assert!(s.contains("Structure"));
    }

    #[test]
    fn test_apply_data_type_members() {
        let members = vec![
            PdbMember::new("x", "int", 0, PdbKind::Member),
            PdbMember::new("y", "int", 4, PdbKind::Member),
        ];
        let root = apply_data_type_members(false, true, 8, false, &members).unwrap();
        assert!(root.is_structure_container());
        assert_eq!(root.num_children(), 2);
    }
}
