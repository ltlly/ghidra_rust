//! LF_FIELDLIST -- concrete Field List type record.
//!
//! Ports Ghidra's `FieldListMsType` (PDB_ID = 0x1203) Java class.
//!
//! Represents a field list in the PDB type stream. Wraps
//! [`AbstractFieldListMsType`] and provides the PDB ID for the MsType
//! variant (32-bit type indices, NT-format strings).
//!
//! A field list is a container that groups all sub-records (members,
//! base classes, methods, enumerates, nested types, etc.) belonging to
//! a composite (struct/class/union) or enum type.

use std::fmt;

use super::abstract_field_list_ms_type::{AbstractFieldListMsType, FieldListEntry};
use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

/// Concrete PDB field list type record (`LF_FIELDLIST`).
///
/// This is the Rust equivalent of Ghidra's `FieldListMsType`. It delegates
/// all field list fields and behaviour to the embedded
/// [`AbstractFieldListMsType`], overriding only the PDB ID to `0x1203`
/// for the MsType variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LfFieldlist {
    /// The underlying field list data.
    pub field_list: AbstractFieldListMsType,
}

impl LfFieldlist {
    /// Create a new empty field list type record.
    pub fn new() -> Self {
        Self {
            field_list: AbstractFieldListMsType::new(),
        }
    }

    /// Create from a parsed vector of field list entries.
    pub fn from_parsed(entries: Vec<FieldListEntry>) -> Self {
        Self {
            field_list: AbstractFieldListMsType::from_parsed(entries),
        }
    }

    /// Parse an `LF_FIELDLIST` record from raw bytes (payload after leaf ID).
    ///
    /// Mirrors the Java `AbstractFieldListMsType(AbstractPdb, PdbByteReader)`
    /// constructor. The `data` slice should start at the first sub-record
    /// (after the 2-byte leaf ID).
    ///
    /// Each sub-record begins with a 2-byte leaf ID followed by its own fields.
    /// The parser continues until all bytes are consumed.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        let entries = parse_field_entries(data);
        Ok(Self::from_parsed(entries))
    }

    /// Add a single entry to this field list.
    pub fn add_entry(&mut self, entry: FieldListEntry) {
        self.field_list.add_entry(entry);
    }

    /// Get the total number of entries.
    pub fn len(&self) -> usize {
        self.field_list.len()
    }

    /// Check if this field list is empty.
    pub fn is_empty(&self) -> bool {
        self.field_list.is_empty()
    }

    /// Get all entries as a slice.
    pub fn entries(&self) -> &[FieldListEntry] {
        self.field_list.entries()
    }

    /// Get an entry by index.
    pub fn get_entry(&self, index: usize) -> Option<&FieldListEntry> {
        self.field_list.entries().get(index)
    }

    /// Get the base class entries.
    pub fn base_classes(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.field_list.base_classes()
    }

    /// Get the non-static member entries.
    pub fn nonstatic_members(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.field_list.nonstatic_members()
    }

    /// Get the static member entries.
    pub fn static_members(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.field_list.static_members()
    }

    /// Get the method entries (overloaded + single).
    pub fn methods(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.field_list.methods()
    }

    /// Get the enumerate entries.
    pub fn enumerates(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.field_list.enumerates()
    }

    /// Get the nested type entries.
    pub fn nested_types(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.field_list.nested_types()
    }

    /// Get the vftable pointer entries.
    pub fn vftable_pointers(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.field_list.vftable_pointers()
    }

    /// Get the continuation index entries.
    pub fn continuation_indices(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.field_list.continuation_indices()
    }

    /// Count the number of non-static members.
    pub fn num_nonstatic_members(&self) -> usize {
        self.field_list.nonstatic_members().count()
    }

    /// Count the number of base classes.
    pub fn num_base_classes(&self) -> usize {
        self.field_list.base_classes().count()
    }

    /// Count the number of methods.
    pub fn num_methods(&self) -> usize {
        self.field_list.methods().count()
    }

    /// Get the friend function entries.
    pub fn friend_functions(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.field_list.entries().iter().filter(|e| {
            matches!(e, FieldListEntry::FriendFunction { .. })
        })
    }

    /// Get the friend class entries (LF_FRIENDCLS).
    pub fn friend_classes(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.field_list.entries().iter().filter(|e| {
            matches!(e, FieldListEntry::FriendClass { .. })
        })
    }

    /// Get the virtual base class entries (LF_VBCLASS).
    pub fn virtual_base_classes(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.field_list.entries().iter().filter(|e| {
            matches!(e, FieldListEntry::VirtualBaseClass { .. })
        })
    }

    /// Get the indirect virtual base class entries (LF_IVBCLASS).
    pub fn indirect_virtual_base_classes(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.field_list.entries().iter().filter(|e| {
            matches!(e, FieldListEntry::IndirectVirtualBaseClass { .. })
        })
    }

    /// Count the number of static members.
    pub fn num_static_members(&self) -> usize {
        self.field_list.static_members().count()
    }

    /// Count the number of nested types.
    pub fn num_nested_types(&self) -> usize {
        self.field_list.nested_types().count()
    }

    /// Count the number of enumerates.
    pub fn num_enumerates(&self) -> usize {
        self.field_list.enumerates().count()
    }

    /// Count the number of vftable pointers.
    pub fn num_vftable_pointers(&self) -> usize {
        self.field_list.vftable_pointers().count()
    }

    /// Count the number of continuation indices.
    pub fn num_continuation_indices(&self) -> usize {
        self.field_list.continuation_indices().count()
    }

    /// Count the number of friend functions.
    pub fn num_friend_functions(&self) -> usize {
        self.friend_functions().count()
    }

    /// Count the number of friend classes.
    pub fn num_friend_classes(&self) -> usize {
        self.friend_classes().count()
    }

    /// Count the number of virtual base classes (direct + indirect).
    pub fn num_virtual_base_classes(&self) -> usize {
        self.virtual_base_classes().count() + self.indirect_virtual_base_classes().count()
    }

    /// Get the name of this field list.
    ///
    /// Field lists do not have names in PDB; this always returns `""`.
    /// Provided for API symmetry with other type records.
    pub fn name(&self) -> &str {
        ""
    }

    /// Whether this field list has any entries at all.
    pub fn has_entries(&self) -> bool {
        !self.field_list.is_empty()
    }

    /// Whether this field list has any base class entries (direct or virtual).
    pub fn has_base_classes(&self) -> bool {
        self.num_base_classes() > 0
    }

    /// Whether this field list has any method entries.
    pub fn has_methods(&self) -> bool {
        self.num_methods() > 0
    }

    /// Whether this field list has any non-static member entries.
    pub fn has_nonstatic_members(&self) -> bool {
        self.num_nonstatic_members() > 0
    }

    /// Whether this field list has any static member entries.
    pub fn has_static_members(&self) -> bool {
        self.num_static_members() > 0
    }

    /// Whether this field list has any enumerate entries.
    pub fn has_enumerates(&self) -> bool {
        self.num_enumerates() > 0
    }

    /// Whether this field list has any nested type entries.
    pub fn has_nested_types(&self) -> bool {
        self.num_nested_types() > 0
    }

    /// Whether this field list has any continuation indices.
    ///
    /// Continuation indices link to additional field list records when
    /// a single field list cannot hold all entries.
    pub fn has_continuation(&self) -> bool {
        self.num_continuation_indices() > 0
    }

    /// Whether this field list has any vftable pointer entries.
    pub fn has_vftable_pointers(&self) -> bool {
        self.num_vftable_pointers() > 0
    }

    /// Whether this field list has any friend function entries.
    pub fn has_friend_functions(&self) -> bool {
        self.num_friend_functions() > 0
    }

    /// Whether this field list has any friend class entries.
    pub fn has_friend_classes(&self) -> bool {
        self.num_friend_classes() > 0
    }
}

impl Default for LfFieldlist {
    fn default() -> Self {
        Self::new()
    }
}

impl AbstractMsType for LfFieldlist {
    fn pdb_id(&self) -> u32 {
        0x1203 // LF_FIELDLIST (MsType variant)
    }

    fn record_number(&self) -> RecordNumber {
        self.field_list.record_number()
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.field_list.set_record_number(record_number);
    }

    fn emit(&self, bind: Bind) -> String {
        self.field_list.emit(bind)
    }
}

impl fmt::Display for LfFieldlist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

// =============================================================================
// Field list sub-record parsing
// =============================================================================

/// Leaf IDs for field list sub-records.
mod field_leaf_id {
    pub const LF_BCLASS: u16 = 0x0400;
    pub const LF_VBCLASS: u16 = 0x0401;
    pub const LF_IVBCLASS: u16 = 0x0402;
    pub const LF_ENUMERATE: u16 = 0x0403;
    pub const LF_FRIENDFCN: u16 = 0x0404;
    pub const LF_INDEX: u16 = 0x0405;
    pub const LF_MEMBER: u16 = 0x0406;
    pub const LF_STMEMBER: u16 = 0x0407;
    pub const LF_METHOD: u16 = 0x0408;
    pub const LF_NESTTYPE: u16 = 0x0409;
    pub const LF_VFUNCTAB: u16 = 0x040A;
    pub const LF_FRIENDCLS: u16 = 0x040B;
    pub const LF_ONEMETHOD: u16 = 0x040C;
    pub const LF_VFUNCOFF: u16 = 0x040D;
    pub const LF_BITFIELD: u16 = 0x1205;
}

/// Parse a numeric value from a byte slice (MSFT Numeric encoding).
fn parse_numeric_at(data: &[u8], offset: usize) -> (u64, usize) {
    crate::pdb::pdb_byte_reader::parse_numeric(data, offset)
}

/// Parse a null-terminated string from `data` starting at `offset`.
fn parse_nt_string(data: &[u8], offset: usize) -> String {
    crate::pdb::pdb_byte_reader::parse_null_terminated_string(&data[offset..])
}

/// Parse all field list entries from raw bytes.
fn parse_field_entries(data: &[u8]) -> Vec<FieldListEntry> {
    let mut entries = Vec::new();
    let mut pos = 0usize;

    while pos + 2 <= data.len() {
        let lid = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let p = &data[pos + 2..];
        let entry = parse_single_field_entry(lid, p);
        entries.push(entry);
        pos = advance_past_field_entry(lid, data, pos);
    }

    entries
}

/// Parse a single field entry from its payload (after the 2-byte leaf ID).
fn parse_single_field_entry(lid: u16, p: &[u8]) -> FieldListEntry {
    match lid {
        field_leaf_id::LF_BCLASS => {
            if p.len() < 10 {
                return FieldListEntry::Unknown { leaf_id: lid };
            }
            let access = u16::from_le_bytes([p[0], p[1]]);
            let ti = u32::from_le_bytes([p[2], p[3], p[4], p[5]]);
            let offset = if p.len() >= 14 {
                u32::from_le_bytes([p[10], p[11], p[12], p[13]])
            } else {
                u32::from_le_bytes([p[6], p[7], p[8], p[9]])
            };
            FieldListEntry::BaseClass { type_record: super::RecordNumber::type_record(ti), offset, access }
        }
        field_leaf_id::LF_VBCLASS => {
            if p.len() < 16 {
                return FieldListEntry::Unknown { leaf_id: lid };
            }
            let access = u16::from_le_bytes([p[0], p[1]]);
            let base_ti = u32::from_le_bytes([p[2], p[3], p[4], p[5]]);
            let vbptr_ti = u32::from_le_bytes([p[6], p[7], p[8], p[9]]);
            let vbptr_off = u32::from_le_bytes([p[10], p[11], p[12], p[13]]);
            let vbtbl_off = u32::from_le_bytes([p[14], p[15], p[16], p[17]]);
            FieldListEntry::VirtualBaseClass {
                base_type_record: super::RecordNumber::type_record(base_ti),
                vbptr_type_record: super::RecordNumber::type_record(vbptr_ti),
                vbptr_offset: vbptr_off,
                vbtable_offset: vbtbl_off,
                access,
            }
        }
        field_leaf_id::LF_IVBCLASS => {
            if p.len() < 18 {
                return FieldListEntry::Unknown { leaf_id: lid };
            }
            let access = u16::from_le_bytes([p[0], p[1]]);
            let base_ti = u32::from_le_bytes([p[2], p[3], p[4], p[5]]);
            let vbptr_ti = u32::from_le_bytes([p[6], p[7], p[8], p[9]]);
            let vbptr_off = u32::from_le_bytes([p[10], p[11], p[12], p[13]]);
            let vbtbl_off = u32::from_le_bytes([p[14], p[15], p[16], p[17]]);
            FieldListEntry::IndirectVirtualBaseClass {
                base_type_record: super::RecordNumber::type_record(base_ti),
                vbptr_type_record: super::RecordNumber::type_record(vbptr_ti),
                vbptr_offset: vbptr_off,
                vbtable_offset: vbtbl_off,
                access,
            }
        }
        field_leaf_id::LF_ENUMERATE => {
            let access = if p.len() >= 2 { u16::from_le_bytes([p[0], p[1]]) } else { 0 };
            let (value, after_num) = parse_numeric_at(p, 2);
            let name = parse_nt_string(p, after_num);
            FieldListEntry::Enumerate { value: value as i64, access, name }
        }
        field_leaf_id::LF_MEMBER => {
            let access = if p.len() >= 2 { u16::from_le_bytes([p[0], p[1]]) } else { 0 };
            let ti = u32::from_le_bytes([p[2], p[3], p[4], p[5]]);
            let (offset, after_num) = parse_numeric_at(p, 6);
            let name = parse_nt_string(p, after_num);
            FieldListEntry::Member {
                type_record: super::RecordNumber::type_record(ti),
                offset: offset as u32,
                access,
                name,
            }
        }
        field_leaf_id::LF_STMEMBER => {
            let access = if p.len() >= 2 { u16::from_le_bytes([p[0], p[1]]) } else { 0 };
            let ti = u32::from_le_bytes([p[2], p[3], p[4], p[5]]);
            let name = parse_nt_string(p, 6);
            FieldListEntry::StaticMember {
                type_record: super::RecordNumber::type_record(ti),
                access,
                name,
            }
        }
        field_leaf_id::LF_METHOD => {
            let count = if p.len() >= 2 { u16::from_le_bytes([p[0], p[1]]) } else { 0 };
            let ti = u32::from_le_bytes([p[2], p[3], p[4], p[5]]);
            let name = parse_nt_string(p, 6);
            FieldListEntry::OverloadedMethod {
                count,
                method_list_record: super::RecordNumber::type_record(ti),
                name,
            }
        }
        field_leaf_id::LF_ONEMETHOD => {
            let access = if p.len() >= 2 { u16::from_le_bytes([p[0], p[1]]) } else { 0 };
            let ti = u32::from_le_bytes([p[2], p[3], p[4], p[5]]);
            let vftable_offset = if p.len() >= 10 {
                i32::from_le_bytes([p[6], p[7], p[8], p[9]])
            } else {
                -1
            };
            let name = parse_nt_string(p, 10);
            FieldListEntry::OneMethod {
                type_record: super::RecordNumber::type_record(ti),
                vftable_offset,
                access,
                name,
            }
        }
        field_leaf_id::LF_NESTTYPE => {
            let _pad = if p.len() >= 2 { u16::from_le_bytes([p[0], p[1]]) } else { 0 };
            let ti = u32::from_le_bytes([p[2], p[3], p[4], p[5]]);
            let name = parse_nt_string(p, 6);
            FieldListEntry::NestedType {
                type_record: super::RecordNumber::type_record(ti),
                name,
            }
        }
        field_leaf_id::LF_INDEX => {
            let ti = if p.len() >= 4 { u32::from_le_bytes([p[0], p[1], p[2], p[3]]) } else { 0 };
            FieldListEntry::Index { type_record: super::RecordNumber::type_record(ti) }
        }
        field_leaf_id::LF_VFUNCTAB => {
            let _pad = if p.len() >= 2 { u16::from_le_bytes([p[0], p[1]]) } else { 0 };
            let ti = if p.len() >= 4 { u32::from_le_bytes([p[2], p[3], p[4], p[5]]) } else { 0 };
            FieldListEntry::VfTablePointer { type_record: super::RecordNumber::type_record(ti) }
        }
        field_leaf_id::LF_VFUNCOFF => {
            let ti = if p.len() >= 4 { u32::from_le_bytes([p[0], p[1], p[2], p[3]]) } else { 0 };
            let off = if p.len() >= 8 { u32::from_le_bytes([p[4], p[5], p[6], p[7]]) } else { 0 };
            FieldListEntry::VfFuncOffset {
                type_record: super::RecordNumber::type_record(ti),
                vftable_offset: off,
            }
        }
        field_leaf_id::LF_FRIENDFCN => {
            let ti = if p.len() >= 4 { u32::from_le_bytes([p[0], p[1], p[2], p[3]]) } else { 0 };
            let name = parse_nt_string(p, 4);
            FieldListEntry::FriendFunction {
                type_record: super::RecordNumber::type_record(ti),
                name,
            }
        }
        field_leaf_id::LF_FRIENDCLS => {
            // LF_FRIENDCLS: pad(2) + typeIndex(4)
            let ti = if p.len() >= 6 { u32::from_le_bytes([p[2], p[3], p[4], p[5]]) } else { 0 };
            FieldListEntry::FriendClass {
                type_record: super::RecordNumber::type_record(ti),
            }
        }
        field_leaf_id::LF_BITFIELD => {
            let ti = if p.len() >= 4 { u32::from_le_bytes([p[0], p[1], p[2], p[3]]) } else { 0 };
            let length = if p.len() >= 5 { p[4] } else { 0 };
            let position = if p.len() >= 6 { p[5] } else { 0 };
            FieldListEntry::Bitfield {
                type_record: super::RecordNumber::type_record(ti),
                bit_length: length,
                bit_position: position,
            }
        }
        _ => FieldListEntry::Unknown { leaf_id: lid },
    }
}

/// Advance past a field entry to the next one.
fn advance_past_field_entry(lid: u16, data: &[u8], pos: usize) -> usize {
    let p = &data[pos + 2..];
    match lid {
        field_leaf_id::LF_BCLASS | field_leaf_id::LF_VBCLASS => pos + 2 + 12,
        field_leaf_id::LF_IVBCLASS => pos + 2 + 20,
        field_leaf_id::LF_ENUMERATE => {
            if p.len() < 2 { return data.len(); }
            let (_, an) = parse_numeric_at(p, 2);
            let end = p[an..].iter().position(|&b| b == 0).unwrap_or(p.len() - an);
            pos + 2 + an + end + 1
        }
        field_leaf_id::LF_MEMBER | field_leaf_id::LF_STMEMBER => {
            if p.len() < 10 { return data.len(); }
            let (_, an) = parse_numeric_at(p, 6);
            if lid == field_leaf_id::LF_STMEMBER {
                // STMEMBER: access(2) + typeIndex(4) + name
                let end = p[6..].iter().position(|&b| b == 0).unwrap_or(p.len() - 6);
                pos + 2 + 6 + end + 1
            } else {
                let end = p[an..].iter().position(|&b| b == 0).unwrap_or(p.len() - an);
                pos + 2 + an + end + 1
            }
        }
        field_leaf_id::LF_METHOD => {
            if p.len() < 6 { return data.len(); }
            let end = p[6..].iter().position(|&b| b == 0).unwrap_or(p.len() - 6);
            pos + 2 + 6 + end + 1
        }
        field_leaf_id::LF_ONEMETHOD => {
            if p.len() < 10 { return data.len(); }
            let end = p[10..].iter().position(|&b| b == 0).unwrap_or(p.len() - 10);
            pos + 2 + 10 + end + 1
        }
        field_leaf_id::LF_NESTTYPE => {
            if p.len() < 6 { return data.len(); }
            let end = p[6..].iter().position(|&b| b == 0).unwrap_or(p.len() - 6);
            pos + 2 + 6 + end + 1
        }
        field_leaf_id::LF_INDEX => pos + 2 + 4,
        field_leaf_id::LF_VFUNCTAB => pos + 2 + 6,
        field_leaf_id::LF_VFUNCOFF => pos + 2 + 8,
        field_leaf_id::LF_FRIENDFCN => {
            if p.len() < 4 { return data.len(); }
            let end = p[4..].iter().position(|&b| b == 0).unwrap_or(p.len() - 4);
            pos + 2 + 4 + end + 1
        }
        field_leaf_id::LF_FRIENDCLS => pos + 2 + 6, // pad(2) + typeIndex(4)
        field_leaf_id::LF_BITFIELD => pos + 2 + 6,
        _ => data.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fieldlist_empty() {
        let fl = LfFieldlist::new();
        assert!(fl.is_empty());
        assert_eq!(fl.len(), 0);
        assert_eq!(fl.pdb_id(), 0x1203);
    }

    #[test]
    fn test_fieldlist_with_members() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 0,
            access: 3,
            name: "x".to_string(),
        });
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 4,
            access: 3,
            name: "y".to_string(),
        });

        assert_eq!(fl.len(), 2);
        assert_eq!(fl.field_list.nonstatic_members().count(), 2);
    }

    #[test]
    fn test_fieldlist_from_parsed() {
        let entries = vec![
            FieldListEntry::Member {
                type_record: RecordNumber::type_record(0x0074),
                offset: 0,
                access: 3,
                name: "a".to_string(),
            },
            FieldListEntry::StaticMember {
                type_record: RecordNumber::type_record(0x0074),
                access: 3,
                name: "count".to_string(),
            },
        ];

        let fl = LfFieldlist::from_parsed(entries);
        assert_eq!(fl.field_list.nonstatic_members().count(), 1);
        assert_eq!(fl.field_list.static_members().count(), 1);
    }

    #[test]
    fn test_fieldlist_with_base_class() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::BaseClass {
            type_record: RecordNumber::type_record(0x1000),
            offset: 0,
            access: 3,
        });
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 8,
            access: 3,
            name: "data".to_string(),
        });

        assert_eq!(fl.field_list.base_classes().count(), 1);
        assert_eq!(fl.field_list.nonstatic_members().count(), 1);
    }

    #[test]
    fn test_fieldlist_with_enumerate() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::Enumerate {
            value: 0,
            access: 3,
            name: "RED".to_string(),
        });
        fl.add_entry(FieldListEntry::Enumerate {
            value: 1,
            access: 3,
            name: "GREEN".to_string(),
        });

        assert_eq!(fl.field_list.enumerates().count(), 2);
    }

    #[test]
    fn test_fieldlist_emit() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::BaseClass {
            type_record: RecordNumber::type_record(0x1000),
            offset: 0,
            access: 3,
        });
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 8,
            access: 3,
            name: "data".to_string(),
        });

        let emitted = fl.emit(Bind::NONE);
        assert!(emitted.contains(" : "));
        assert!(emitted.contains("data"));
        assert!(emitted.contains('{'));
        assert!(emitted.contains('}'));
    }

    #[test]
    fn test_fieldlist_with_methods() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::OverloadedMethod {
            count: 3,
            method_list_record: RecordNumber::type_record(0x1010),
            name: "foo".to_string(),
        });

        assert_eq!(fl.field_list.methods().count(), 1);
        let emitted = fl.emit(Bind::NONE);
        assert!(emitted.contains("..."));
    }

    #[test]
    fn test_fieldlist_record_number() {
        let mut fl = LfFieldlist::new();
        assert!(fl.record_number().is_no_type());
        fl.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(fl.record_number().index(), 0x2000);
    }

    #[test]
    fn test_fieldlist_display() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 0,
            access: 3,
            name: "value".to_string(),
        });

        let display = format!("{}", fl);
        assert!(display.contains("value"));
    }

    #[test]
    fn test_fieldlist_default() {
        let fl = LfFieldlist::default();
        assert!(fl.is_empty());
        assert_eq!(fl.pdb_id(), 0x1203);
    }

    #[test]
    fn test_fieldlist_with_bitfield() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::Bitfield {
            type_record: RecordNumber::type_record(0x0074),
            bit_length: 4,
            bit_position: 0,
        });

        assert_eq!(fl.len(), 1);
        let emitted = fl.emit(Bind::NONE);
        assert!(emitted.contains("bitfield"));
    }

    #[test]
    fn test_fieldlist_with_index_continuation() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 0,
            access: 3,
            name: "a".to_string(),
        });
        fl.add_entry(FieldListEntry::Index {
            type_record: RecordNumber::type_record(0x1005),
        });

        assert_eq!(fl.len(), 2);
        assert_eq!(fl.continuation_indices().count(), 1);
    }

    #[test]
    fn test_fieldlist_entries_slice() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 0,
            access: 3,
            name: "x".to_string(),
        });
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 4,
            access: 3,
            name: "y".to_string(),
        });

        let entries = fl.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name(), Some("x"));
        assert_eq!(entries[1].name(), Some("y"));
    }

    #[test]
    fn test_fieldlist_get_entry() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 0,
            access: 3,
            name: "x".to_string(),
        });

        assert!(fl.get_entry(0).is_some());
        assert!(fl.get_entry(1).is_none());
        assert_eq!(fl.get_entry(0).unwrap().name(), Some("x"));
    }

    #[test]
    fn test_fieldlist_num_nonstatic_members() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 0,
            access: 3,
            name: "a".to_string(),
        });
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 4,
            access: 3,
            name: "b".to_string(),
        });
        fl.add_entry(FieldListEntry::StaticMember {
            type_record: RecordNumber::type_record(0x0074),
            access: 3,
            name: "count".to_string(),
        });

        assert_eq!(fl.num_nonstatic_members(), 2);
    }

    #[test]
    fn test_fieldlist_num_base_classes() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::BaseClass {
            type_record: RecordNumber::type_record(0x1000),
            offset: 0,
            access: 3,
        });
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 8,
            access: 3,
            name: "data".to_string(),
        });

        assert_eq!(fl.num_base_classes(), 1);
    }

    #[test]
    fn test_fieldlist_num_methods() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::OverloadedMethod {
            count: 2,
            method_list_record: RecordNumber::type_record(0x1010),
            name: "foo".to_string(),
        });
        fl.add_entry(FieldListEntry::OneMethod {
            type_record: RecordNumber::type_record(0x1011),
            vftable_offset: -1,
            access: 3,
            name: "bar".to_string(),
        });

        assert_eq!(fl.num_methods(), 2);
    }

    #[test]
    fn test_fieldlist_parse_empty() {
        let data = [];
        let fl = LfFieldlist::parse(&data).unwrap();
        assert!(fl.is_empty());
        assert_eq!(fl.pdb_id(), 0x1203);
    }

    #[test]
    fn test_fieldlist_parse_with_member() {
        // Build a field list with one LF_MEMBER entry.
        // LF_MEMBER: leafId(2) + access(2) + typeIndex(4) + numericOffset(2) + name(NT)
        let mut data = Vec::new();
        // LF_MEMBER leaf ID = 0x0406
        data.extend_from_slice(&0x0406u16.to_le_bytes());
        // access = 3 (public)
        data.extend_from_slice(&3u16.to_le_bytes());
        // type index = 0x0074 (int)
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        // offset = 0 (small numeric, 2 bytes)
        data.extend_from_slice(&0u16.to_le_bytes());
        // name = "x\0"
        data.push(b'x'); data.push(0);

        let fl = LfFieldlist::parse(&data).unwrap();
        assert_eq!(fl.len(), 1);
        assert_eq!(fl.num_nonstatic_members(), 1);
        assert_eq!(fl.entries()[0].name(), Some("x"));
    }

    #[test]
    fn test_fieldlist_parse_with_enumerate() {
        // LF_ENUMERATE: leafId(2) + access(2) + numericValue(2) + name(NT)
        let mut data = Vec::new();
        // LF_ENUMERATE leaf ID = 0x0403
        data.extend_from_slice(&0x0403u16.to_le_bytes());
        // access = 3 (public)
        data.extend_from_slice(&3u16.to_le_bytes());
        // value = 42 (small numeric)
        data.extend_from_slice(&42u16.to_le_bytes());
        // name = "ANSWER\0"
        data.extend_from_slice(b"ANSWER\0");

        let fl = LfFieldlist::parse(&data).unwrap();
        assert_eq!(fl.len(), 1);
        assert_eq!(fl.enumerates().count(), 1);
    }

    #[test]
    fn test_fieldlist_parse_with_index() {
        // LF_INDEX: leafId(2) + typeIndex(4)
        let mut data = Vec::new();
        data.extend_from_slice(&0x0405u16.to_le_bytes());
        data.extend_from_slice(&0x1005u32.to_le_bytes());

        let fl = LfFieldlist::parse(&data).unwrap();
        assert_eq!(fl.len(), 1);
        assert_eq!(fl.continuation_indices().count(), 1);
    }

    #[test]
    fn test_fieldlist_parse_with_base_class() {
        // LF_BCLASS: leafId(2) + access(2) + typeIndex(4) + offset(4)
        let mut data = Vec::new();
        data.extend_from_slice(&0x0400u16.to_le_bytes());
        data.extend_from_slice(&3u16.to_le_bytes());  // access
        data.extend_from_slice(&0x1000u32.to_le_bytes());  // type index
        data.extend_from_slice(&0u32.to_le_bytes());  // offset (numeric)

        let fl = LfFieldlist::parse(&data).unwrap();
        assert_eq!(fl.len(), 1);
        assert_eq!(fl.base_classes().count(), 1);
    }

    #[test]
    fn test_fieldlist_parse_with_vfunctab() {
        // LF_VFUNCTAB: leafId(2) + pad(2) + typeIndex(4)
        let mut data = Vec::new();
        data.extend_from_slice(&0x040Au16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());   // pad
        data.extend_from_slice(&0x2000u32.to_le_bytes());  // type index

        let fl = LfFieldlist::parse(&data).unwrap();
        assert_eq!(fl.len(), 1);
        assert_eq!(fl.vftable_pointers().count(), 1);
    }

    #[test]
    fn test_fieldlist_parse_with_nested_type() {
        // LF_NESTTYPE: leafId(2) + pad(2) + typeIndex(4) + name(NT)
        let mut data = Vec::new();
        data.extend_from_slice(&0x0409u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());   // pad
        data.extend_from_slice(&0x3000u32.to_le_bytes());  // type index
        data.extend_from_slice(b"Inner\0");

        let fl = LfFieldlist::parse(&data).unwrap();
        assert_eq!(fl.len(), 1);
        assert_eq!(fl.nested_types().count(), 1);
    }

    #[test]
    fn test_fieldlist_parse_with_method() {
        // LF_METHOD: leafId(2) + count(2) + methodListIndex(4) + name(NT)
        let mut data = Vec::new();
        data.extend_from_slice(&0x0408u16.to_le_bytes());
        data.extend_from_slice(&3u16.to_le_bytes());   // count
        data.extend_from_slice(&0x1010u32.to_le_bytes());  // method list index
        data.extend_from_slice(b"foo\0");

        let fl = LfFieldlist::parse(&data).unwrap();
        assert_eq!(fl.len(), 1);
        assert_eq!(fl.methods().count(), 1);
    }

    #[test]
    fn test_fieldlist_parse_with_stmember() {
        // LF_STMEMBER: leafId(2) + access(2) + typeIndex(4) + name(NT)
        let mut data = Vec::new();
        data.extend_from_slice(&0x0407u16.to_le_bytes());
        data.extend_from_slice(&3u16.to_le_bytes());   // access
        data.extend_from_slice(&0x0074u32.to_le_bytes());  // type index
        data.extend_from_slice(b"count\0");

        let fl = LfFieldlist::parse(&data).unwrap();
        assert_eq!(fl.len(), 1);
        assert_eq!(fl.static_members().count(), 1);
    }

    #[test]
    fn test_fieldlist_parse_multiple_entries() {
        let mut data = Vec::new();

        // LF_MEMBER: x at offset 0
        data.extend_from_slice(&0x0406u16.to_le_bytes());
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.push(b'x'); data.push(0);

        // LF_MEMBER: y at offset 4
        data.extend_from_slice(&0x0406u16.to_le_bytes());
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.extend_from_slice(&4u16.to_le_bytes());
        data.push(b'y'); data.push(0);

        let fl = LfFieldlist::parse(&data).unwrap();
        assert_eq!(fl.len(), 2);
        assert_eq!(fl.num_nonstatic_members(), 2);
    }

    #[test]
    fn test_fieldlist_parse_with_static_member() {
        // LF_STMEMBER: leafId(2) + access(2) + typeIndex(4) + name(NT)
        let mut data = Vec::new();
        data.extend_from_slice(&0x0407u16.to_le_bytes());
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&0x0074u32.to_le_bytes());
        data.extend_from_slice(b"count\0");

        let fl = LfFieldlist::parse(&data).unwrap();
        assert_eq!(fl.num_nonstatic_members(), 0);
        assert_eq!(fl.static_members().count(), 1);
    }

    #[test]
    fn test_fieldlist_parse_with_onemethod() {
        // LF_ONEMETHOD: leafId(2) + access(2) + typeIndex(4) + vftableOffset(4) + name(NT)
        let mut data = Vec::new();
        data.extend_from_slice(&0x040Cu16.to_le_bytes());
        data.extend_from_slice(&3u16.to_le_bytes());   // access
        data.extend_from_slice(&0x1011u32.to_le_bytes());  // type index
        data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());  // vftable offset (-1)
        data.extend_from_slice(b"bar\0");

        let fl = LfFieldlist::parse(&data).unwrap();
        assert_eq!(fl.len(), 1);
        assert_eq!(fl.methods().count(), 1);
    }

    #[test]
    fn test_fieldlist_friend_functions() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::FriendFunction {
            type_record: RecordNumber::type_record(0x1010),
            name: "operator+".to_string(),
        });
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 0,
            access: 3,
            name: "x".to_string(),
        });

        assert_eq!(fl.num_friend_functions(), 1);
        assert_eq!(fl.friend_functions().count(), 1);
    }

    #[test]
    fn test_fieldlist_friend_classes() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::FriendClass {
            type_record: RecordNumber::type_record(0x1020),
        });
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 0,
            access: 3,
            name: "x".to_string(),
        });

        assert_eq!(fl.num_friend_classes(), 1);
        assert_eq!(fl.friend_classes().count(), 1);
        assert!(fl.has_friend_classes());
    }

    #[test]
    fn test_fieldlist_parse_with_friendcls() {
        // LF_FRIENDCLS: leafId(2) + pad(2) + typeIndex(4)
        let mut data = Vec::new();
        data.extend_from_slice(&0x040Bu16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());   // pad
        data.extend_from_slice(&0x1020u32.to_le_bytes());  // type index

        let fl = LfFieldlist::parse(&data).unwrap();
        assert_eq!(fl.len(), 1);
        assert_eq!(fl.friend_classes().count(), 1);
    }

    #[test]
    fn test_fieldlist_virtual_base_classes() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::VirtualBaseClass {
            base_type_record: RecordNumber::type_record(0x1000),
            vbptr_type_record: RecordNumber::type_record(0x1001),
            vbptr_offset: 0,
            vbtable_offset: 4,
            access: 3,
        });
        fl.add_entry(FieldListEntry::IndirectVirtualBaseClass {
            base_type_record: RecordNumber::type_record(0x1002),
            vbptr_type_record: RecordNumber::type_record(0x1003),
            vbptr_offset: 0,
            vbtable_offset: 8,
            access: 3,
        });

        assert_eq!(fl.virtual_base_classes().count(), 1);
        assert_eq!(fl.indirect_virtual_base_classes().count(), 1);
        assert_eq!(fl.num_virtual_base_classes(), 2);
    }

    #[test]
    fn test_fieldlist_num_static_members() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::StaticMember {
            type_record: RecordNumber::type_record(0x0074),
            access: 3,
            name: "count".to_string(),
        });
        fl.add_entry(FieldListEntry::StaticMember {
            type_record: RecordNumber::type_record(0x0074),
            access: 3,
            name: "total".to_string(),
        });
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 0,
            access: 3,
            name: "x".to_string(),
        });

        assert_eq!(fl.num_static_members(), 2);
    }

    #[test]
    fn test_fieldlist_num_nested_types() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::NestedType {
            type_record: RecordNumber::type_record(0x3000),
            name: "Inner".to_string(),
        });
        assert_eq!(fl.num_nested_types(), 1);
    }

    #[test]
    fn test_fieldlist_num_enumerates() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::Enumerate {
            value: 0,
            access: 3,
            name: "RED".to_string(),
        });
        fl.add_entry(FieldListEntry::Enumerate {
            value: 1,
            access: 3,
            name: "GREEN".to_string(),
        });
        fl.add_entry(FieldListEntry::Enumerate {
            value: 2,
            access: 3,
            name: "BLUE".to_string(),
        });

        assert_eq!(fl.num_enumerates(), 3);
    }

    #[test]
    fn test_fieldlist_num_vftable_pointers() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::VfTablePointer {
            type_record: RecordNumber::type_record(0x2000),
        });
        assert_eq!(fl.num_vftable_pointers(), 1);
    }

    #[test]
    fn test_fieldlist_num_continuation_indices() {
        let mut fl = LfFieldlist::new();
        fl.add_entry(FieldListEntry::Index {
            type_record: RecordNumber::type_record(0x1005),
        });
        fl.add_entry(FieldListEntry::Index {
            type_record: RecordNumber::type_record(0x1006),
        });
        assert_eq!(fl.num_continuation_indices(), 2);
    }

    #[test]
    fn test_fieldlist_name() {
        let fl = LfFieldlist::new();
        assert_eq!(fl.name(), "");
    }

    #[test]
    fn test_fieldlist_has_entries() {
        let fl = LfFieldlist::new();
        assert!(!fl.has_entries());

        let mut fl2 = LfFieldlist::new();
        fl2.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 0,
            access: 3,
            name: "x".to_string(),
        });
        assert!(fl2.has_entries());
    }

    #[test]
    fn test_fieldlist_has_base_classes() {
        let mut fl = LfFieldlist::new();
        assert!(!fl.has_base_classes());

        fl.add_entry(FieldListEntry::BaseClass {
            type_record: RecordNumber::type_record(0x1000),
            offset: 0,
            access: 3,
        });
        assert!(fl.has_base_classes());
    }

    #[test]
    fn test_fieldlist_has_methods() {
        let mut fl = LfFieldlist::new();
        assert!(!fl.has_methods());

        fl.add_entry(FieldListEntry::OneMethod {
            type_record: RecordNumber::type_record(0x1011),
            vftable_offset: -1,
            access: 3,
            name: "foo".to_string(),
        });
        assert!(fl.has_methods());
    }

    #[test]
    fn test_fieldlist_has_nonstatic_members() {
        let mut fl = LfFieldlist::new();
        assert!(!fl.has_nonstatic_members());

        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 0,
            access: 3,
            name: "x".to_string(),
        });
        assert!(fl.has_nonstatic_members());
    }

    #[test]
    fn test_fieldlist_has_static_members() {
        let mut fl = LfFieldlist::new();
        assert!(!fl.has_static_members());

        fl.add_entry(FieldListEntry::StaticMember {
            type_record: RecordNumber::type_record(0x0074),
            access: 3,
            name: "count".to_string(),
        });
        assert!(fl.has_static_members());
    }

    #[test]
    fn test_fieldlist_has_enumerates() {
        let mut fl = LfFieldlist::new();
        assert!(!fl.has_enumerates());

        fl.add_entry(FieldListEntry::Enumerate {
            value: 0,
            access: 3,
            name: "RED".to_string(),
        });
        assert!(fl.has_enumerates());
    }

    #[test]
    fn test_fieldlist_has_nested_types() {
        let mut fl = LfFieldlist::new();
        assert!(!fl.has_nested_types());

        fl.add_entry(FieldListEntry::NestedType {
            type_record: RecordNumber::type_record(0x3000),
            name: "Inner".to_string(),
        });
        assert!(fl.has_nested_types());
    }

    #[test]
    fn test_fieldlist_has_continuation() {
        let mut fl = LfFieldlist::new();
        assert!(!fl.has_continuation());

        fl.add_entry(FieldListEntry::Index {
            type_record: RecordNumber::type_record(0x1005),
        });
        assert!(fl.has_continuation());
    }

    #[test]
    fn test_fieldlist_has_vftable_pointers() {
        let mut fl = LfFieldlist::new();
        assert!(!fl.has_vftable_pointers());

        fl.add_entry(FieldListEntry::VfTablePointer {
            type_record: RecordNumber::type_record(0x2000),
        });
        assert!(fl.has_vftable_pointers());
    }

    #[test]
    fn test_fieldlist_has_friend_functions() {
        let mut fl = LfFieldlist::new();
        assert!(!fl.has_friend_functions());

        fl.add_entry(FieldListEntry::FriendFunction {
            type_record: RecordNumber::type_record(0x1010),
            name: "operator+".to_string(),
        });
        assert!(fl.has_friend_functions());
    }

    #[test]
    fn test_fieldlist_has_friend_classes() {
        let mut fl = LfFieldlist::new();
        assert!(!fl.has_friend_classes());

        fl.add_entry(FieldListEntry::FriendClass {
            type_record: RecordNumber::type_record(0x1020),
        });
        assert!(fl.has_friend_classes());
    }

    #[test]
    fn test_fieldlist_eq() {
        let mut fl1 = LfFieldlist::new();
        fl1.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 0,
            access: 3,
            name: "x".to_string(),
        });

        let mut fl2 = LfFieldlist::new();
        fl2.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 0,
            access: 3,
            name: "x".to_string(),
        });

        assert_eq!(fl1, fl2);
    }

    #[test]
    fn test_fieldlist_mixed_entries_comprehensive() {
        let mut fl = LfFieldlist::new();

        // Add one of every type
        fl.add_entry(FieldListEntry::BaseClass {
            type_record: RecordNumber::type_record(0x1000),
            offset: 0,
            access: 3,
        });
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 8,
            access: 3,
            name: "data".to_string(),
        });
        fl.add_entry(FieldListEntry::StaticMember {
            type_record: RecordNumber::type_record(0x0074),
            access: 3,
            name: "count".to_string(),
        });
        fl.add_entry(FieldListEntry::OneMethod {
            type_record: RecordNumber::type_record(0x1011),
            vftable_offset: -1,
            access: 3,
            name: "foo".to_string(),
        });
        fl.add_entry(FieldListEntry::Enumerate {
            value: 42,
            access: 3,
            name: "ANSWER".to_string(),
        });
        fl.add_entry(FieldListEntry::NestedType {
            type_record: RecordNumber::type_record(0x3000),
            name: "Inner".to_string(),
        });
        fl.add_entry(FieldListEntry::VfTablePointer {
            type_record: RecordNumber::type_record(0x2000),
        });
        fl.add_entry(FieldListEntry::Index {
            type_record: RecordNumber::type_record(0x1005),
        });
        fl.add_entry(FieldListEntry::FriendFunction {
            type_record: RecordNumber::type_record(0x1010),
            name: "operator+".to_string(),
        });
        fl.add_entry(FieldListEntry::FriendClass {
            type_record: RecordNumber::type_record(0x1020),
        });
        fl.add_entry(FieldListEntry::Bitfield {
            type_record: RecordNumber::type_record(0x0074),
            bit_length: 4,
            bit_position: 0,
        });

        assert_eq!(fl.len(), 11);
        assert_eq!(fl.num_base_classes(), 1);
        assert_eq!(fl.num_nonstatic_members(), 1);
        assert_eq!(fl.num_static_members(), 1);
        assert_eq!(fl.num_methods(), 1);
        assert_eq!(fl.num_enumerates(), 1);
        assert_eq!(fl.num_nested_types(), 1);
        assert_eq!(fl.num_vftable_pointers(), 1);
        assert_eq!(fl.num_continuation_indices(), 1);
        assert_eq!(fl.num_friend_functions(), 1);
        assert_eq!(fl.num_friend_classes(), 1);
    }
}
