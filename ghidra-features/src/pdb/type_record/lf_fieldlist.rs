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
#[derive(Debug, Clone)]
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
}
