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
        assert_eq!(fl.field_list.continuation_indices().count(), 1);
    }
}
