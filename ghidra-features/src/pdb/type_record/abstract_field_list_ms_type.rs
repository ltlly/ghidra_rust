//! Abstract Field List MS Type -- field list type record.
//!
//! Ports Ghidra's `AbstractFieldListMsType` Java class.
//!
//! Represents the `LF_FIELDLIST` type record, which is a container that
//! holds the individual member, base class, method, enumerate, nested type,
//! and vftable pointer records for a composite (struct/class/union) or enum.

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::RecordNumber;

// =============================================================================
// Field list entry types
// =============================================================================

/// A single entry within a field list.
///
/// Mirrors the various `MsTypeField` subtypes from the Java implementation.
/// Each variant corresponds to a specific LF_* sub-record that can appear
/// inside an `LF_FIELDLIST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldListEntry {
    /// LF_BCLASS — a direct base class.
    BaseClass {
        /// Record number of the base class type.
        type_record: RecordNumber,
        /// Offset of the base class within the derived class.
        offset: u32,
        /// Access protection (public/private/protected).
        access: u16,
    },
    /// LF_VBCLASS — a virtual base class.
    VirtualBaseClass {
        /// Record number of the base class type.
        base_type_record: RecordNumber,
        /// Record number of the vbptr type.
        vbptr_type_record: RecordNumber,
        /// Offset of the vbptr within the object.
        vbptr_offset: u32,
        /// Offset within the vbtable.
        vbtable_offset: u32,
        /// Access protection.
        access: u16,
    },
    /// LF_IVBCLASS — an indirect virtual base class.
    IndirectVirtualBaseClass {
        /// Record number of the base class type.
        base_type_record: RecordNumber,
        /// Record number of the vbptr type.
        vbptr_type_record: RecordNumber,
        /// Offset of the vbptr within the object.
        vbptr_offset: u32,
        /// Offset within the vbtable.
        vbtable_offset: u32,
        /// Access protection.
        access: u16,
    },
    /// LF_MEMBER — a non-static data member.
    Member {
        /// Record number of the member's data type.
        type_record: RecordNumber,
        /// Byte offset within the containing composite.
        offset: u32,
        /// Access protection.
        access: u16,
        /// Member name.
        name: String,
    },
    /// LF_STMEMBER — a static data member.
    StaticMember {
        /// Record number of the member's data type.
        type_record: RecordNumber,
        /// Access protection.
        access: u16,
        /// Member name.
        name: String,
    },
    /// LF_METHOD — an overloaded method set.
    OverloadedMethod {
        /// Number of overloads.
        count: u16,
        /// Record number of the method list.
        method_list_record: RecordNumber,
        /// Method name.
        name: String,
    },
    /// LF_ONEMETHOD — a single (non-overloaded) method.
    OneMethod {
        /// Record number of the method's function type.
        type_record: RecordNumber,
        /// VFTable offset (-1 if not virtual).
        vftable_offset: i32,
        /// Access protection.
        access: u16,
        /// Method name.
        name: String,
    },
    /// LF_NESTTYPE — a nested type declaration.
    NestedType {
        /// Record number of the nested type.
        type_record: RecordNumber,
        /// Type name.
        name: String,
    },
    /// LF_ENUMERATE — an enum constant.
    Enumerate {
        /// The enum constant value.
        value: i64,
        /// Access protection.
        access: u16,
        /// Constant name.
        name: String,
    },
    /// LF_VFUNCTAB — a virtual function table pointer.
    VfTablePointer {
        /// Record number of the vftable type.
        type_record: RecordNumber,
    },
    /// LF_VFUNCOFF — a virtual function offset.
    VfFuncOffset {
        /// Record number of the method type.
        type_record: RecordNumber,
        /// Offset in the vftable.
        vftable_offset: u32,
    },
    /// LF_INDEX — a continuation index to another field list.
    Index {
        /// Record number of the continuation field list.
        type_record: RecordNumber,
    },
    /// LF_FRIENDFCN — a friend function declaration.
    FriendFunction {
        /// Record number of the friend function type.
        type_record: RecordNumber,
        /// Function name.
        name: String,
    },
    /// LF_BITFIELD — a bitfield member.
    Bitfield {
        /// Record number of the base type.
        type_record: RecordNumber,
        /// Bit length.
        bit_length: u8,
        /// Bit position.
        bit_position: u8,
    },
    /// An unrecognized entry.
    Unknown {
        /// The raw leaf ID.
        leaf_id: u16,
    },
}

impl FieldListEntry {
    /// Get the name of this entry, if it has one.
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Member { name, .. }
            | Self::StaticMember { name, .. }
            | Self::OverloadedMethod { name, .. }
            | Self::OneMethod { name, .. }
            | Self::NestedType { name, .. }
            | Self::Enumerate { name, .. }
            | Self::FriendFunction { name, .. } => Some(name),
            _ => None,
        }
    }

    /// Check if this is a base class entry (direct, virtual, or indirect).
    pub fn is_base_class(&self) -> bool {
        matches!(
            self,
            Self::BaseClass { .. }
                | Self::VirtualBaseClass { .. }
                | Self::IndirectVirtualBaseClass { .. }
        )
    }

    /// Check if this is a method entry (overloaded or single).
    pub fn is_method(&self) -> bool {
        matches!(self, Self::OverloadedMethod { .. } | Self::OneMethod { .. })
    }

    /// Check if this is a data member entry (static or non-static).
    pub fn is_member(&self) -> bool {
        matches!(self, Self::Member { .. } | Self::StaticMember { .. })
    }

    /// Check if this is a continuation index.
    pub fn is_index(&self) -> bool {
        matches!(self, Self::Index { .. })
    }
}

impl fmt::Display for FieldListEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BaseClass { type_record, offset, access } => {
                write!(f, "base({} @ {}, access={})", type_record, offset, access)
            }
            Self::VirtualBaseClass { base_type_record, .. } => {
                write!(f, "vbase({})", base_type_record)
            }
            Self::IndirectVirtualBaseClass { base_type_record, .. } => {
                write!(f, "ivbase({})", base_type_record)
            }
            Self::Member { type_record, offset, name, .. } => {
                write!(f, "{}: {} @ {}", name, type_record, offset)
            }
            Self::StaticMember { type_record, name, .. } => {
                write!(f, "static {}: {}", name, type_record)
            }
            Self::OverloadedMethod { count, name, .. } => {
                write!(f, "method {} ({} overloads)", name, count)
            }
            Self::OneMethod { type_record, name, .. } => {
                write!(f, "method {}: {}", name, type_record)
            }
            Self::NestedType { type_record, name } => {
                write!(f, "nested {} = {}", name, type_record)
            }
            Self::Enumerate { value, name, .. } => {
                write!(f, "{} = {}", name, value)
            }
            Self::VfTablePointer { type_record } => {
                write!(f, "vftptr({})", type_record)
            }
            Self::VfFuncOffset { type_record, vftable_offset } => {
                write!(f, "vfuncoff({}, {})", type_record, vftable_offset)
            }
            Self::Index { type_record } => {
                write!(f, "index({})", type_record)
            }
            Self::FriendFunction { type_record, name } => {
                write!(f, "friend {}: {}", name, type_record)
            }
            Self::Bitfield { type_record, bit_length, bit_position } => {
                write!(f, "bitfield({}, len={}, pos={})", type_record, bit_length, bit_position)
            }
            Self::Unknown { leaf_id } => {
                write!(f, "unknown(0x{:04X})", leaf_id)
            }
        }
    }
}

// =============================================================================
// AbstractFieldListMsType
// =============================================================================

/// Abstract base for PDB field list type records (`LF_FIELDLIST`).
///
/// The field list is a container that groups all sub-records (members,
/// base classes, methods, enumerates, nested types, etc.) belonging to
/// a composite or enum type.  In the Java hierarchy, this extends
/// `AbstractMsType` directly.
///
/// Sub-records are categorized into separate lists for convenient access,
/// mirroring the Java implementation's approach of filtering by `instanceof`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstractFieldListMsType {
    /// Record number of this type (set during TPI/IPI registration).
    record_number: RecordNumber,
    /// All entries in this field list, in order.
    entries: Vec<FieldListEntry>,
    /// Indices into `entries` for base class entries.
    base_class_indices: Vec<usize>,
    /// Indices into `entries` for method entries (overloaded + single).
    method_indices: Vec<usize>,
    /// Indices into `entries` for non-static member entries.
    nonstatic_member_indices: Vec<usize>,
    /// Indices into `entries` for static member entries.
    static_member_indices: Vec<usize>,
    /// Indices into `entries` for vftable pointer entries.
    vftable_pointer_indices: Vec<usize>,
    /// Indices into `entries` for nested type entries.
    nested_type_indices: Vec<usize>,
    /// Indices into `entries` for enumerate entries.
    enumerate_indices: Vec<usize>,
    /// Indices into `entries` for continuation index entries.
    index_indices: Vec<usize>,
}

impl AbstractFieldListMsType {
    /// Create a new empty field list.
    pub fn new() -> Self {
        Self {
            record_number: RecordNumber::NO_TYPE,
            entries: Vec::new(),
            base_class_indices: Vec::new(),
            method_indices: Vec::new(),
            nonstatic_member_indices: Vec::new(),
            static_member_indices: Vec::new(),
            vftable_pointer_indices: Vec::new(),
            nested_type_indices: Vec::new(),
            enumerate_indices: Vec::new(),
            index_indices: Vec::new(),
        }
    }

    /// Create from a parsed `FieldList` type record's fields vector.
    pub fn from_parsed(fields: Vec<FieldListEntry>) -> Self {
        let mut list = Self::new();
        for entry in fields {
            list.add_entry(entry);
        }
        list
    }

    /// Add a single entry to this field list.
    ///
    /// The entry is appended to the main list and indexed into the
    /// appropriate category list.
    pub fn add_entry(&mut self, entry: FieldListEntry) {
        let idx = self.entries.len();

        match &entry {
            FieldListEntry::BaseClass { .. }
            | FieldListEntry::VirtualBaseClass { .. }
            | FieldListEntry::IndirectVirtualBaseClass { .. } => {
                self.base_class_indices.push(idx);
            }
            FieldListEntry::OverloadedMethod { .. }
            | FieldListEntry::OneMethod { .. } => {
                self.method_indices.push(idx);
            }
            FieldListEntry::Member { .. } => {
                self.nonstatic_member_indices.push(idx);
            }
            FieldListEntry::StaticMember { .. } => {
                self.static_member_indices.push(idx);
            }
            FieldListEntry::VfTablePointer { .. } => {
                self.vftable_pointer_indices.push(idx);
            }
            FieldListEntry::NestedType { .. } => {
                self.nested_type_indices.push(idx);
            }
            FieldListEntry::Enumerate { .. } => {
                self.enumerate_indices.push(idx);
            }
            FieldListEntry::Index { .. } => {
                self.index_indices.push(idx);
            }
            _ => {} // Unknown and other entries are stored but not categorized
        }

        self.entries.push(entry);
    }

    /// Get all entries in this field list.
    pub fn entries(&self) -> &[FieldListEntry] {
        &self.entries
    }

    /// Get the base class entries.
    pub fn base_classes(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.base_class_indices.iter().map(move |&i| &self.entries[i])
    }

    /// Get the method entries (overloaded + single).
    pub fn methods(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.method_indices.iter().map(move |&i| &self.entries[i])
    }

    /// Get the non-static member entries.
    pub fn nonstatic_members(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.nonstatic_member_indices.iter().map(move |&i| &self.entries[i])
    }

    /// Get the static member entries.
    pub fn static_members(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.static_member_indices.iter().map(move |&i| &self.entries[i])
    }

    /// Get the vftable pointer entries.
    pub fn vftable_pointers(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.vftable_pointer_indices.iter().map(move |&i| &self.entries[i])
    }

    /// Get the nested type entries.
    pub fn nested_types(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.nested_type_indices.iter().map(move |&i| &self.entries[i])
    }

    /// Get the enumerate entries.
    pub fn enumerates(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.enumerate_indices.iter().map(move |&i| &self.entries[i])
    }

    /// Get the continuation index entries.
    pub fn continuation_indices(&self) -> impl Iterator<Item = &FieldListEntry> {
        self.index_indices.iter().map(move |&i| &self.entries[i])
    }

    /// Get the total number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if this field list is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Default for AbstractFieldListMsType {
    fn default() -> Self {
        Self::new()
    }
}

impl AbstractMsType for AbstractFieldListMsType {
    fn pdb_id(&self) -> u32 {
        0x0203 // LF_FIELDLIST
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        let mut result = String::new();

        // Emit base classes with " : " separator.
        let mut ds_bases = super::DelimiterState::new(" : ", ", ");
        for entry in self.base_classes() {
            let delim = ds_bases.out(true);
            result.push_str(delim);
            result.push_str(&entry.to_string());
        }

        // Emit members inside braces.
        result.push_str(" {");
        let mut ds_members = super::DelimiterState::new("", ",");
        for entry in self.entries() {
            if entry.is_base_class() || entry.is_index() {
                continue;
            }
            let delim = ds_members.out(true);
            result.push_str(delim);
            result.push_str(&entry.to_string());
        }
        result.push('}');

        // Indicate if there are method-only entries not shown.
        if !self.method_indices.is_empty() {
            result.push_str("...");
        }

        result
    }
}

impl fmt::Display for AbstractFieldListMsType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_field_list() {
        let fl = AbstractFieldListMsType::new();
        assert!(fl.is_empty());
        assert_eq!(fl.len(), 0);
        assert_eq!(fl.pdb_id(), 0x0203);
    }

    #[test]
    fn test_field_list_with_members() {
        let mut fl = AbstractFieldListMsType::new();
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 0,
            access: 3, // public
            name: "x".to_string(),
        });
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 4,
            access: 3,
            name: "y".to_string(),
        });

        assert_eq!(fl.len(), 2);
        assert_eq!(fl.nonstatic_members().count(), 2);
        assert_eq!(fl.base_classes().count(), 0);
    }

    #[test]
    fn test_field_list_with_base_class() {
        let mut fl = AbstractFieldListMsType::new();
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

        assert_eq!(fl.base_classes().count(), 1);
        assert_eq!(fl.nonstatic_members().count(), 1);
    }

    #[test]
    fn test_field_list_with_enumerate() {
        let mut fl = AbstractFieldListMsType::new();
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

        assert_eq!(fl.enumerates().count(), 2);
        assert_eq!(fl.len(), 2);
    }

    #[test]
    fn test_field_list_emit() {
        let mut fl = AbstractFieldListMsType::new();
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
    fn test_field_list_entry_name() {
        let entry = FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 0,
            access: 3,
            name: "myField".to_string(),
        };
        assert_eq!(entry.name(), Some("myField"));

        let entry = FieldListEntry::BaseClass {
            type_record: RecordNumber::type_record(0x1000),
            offset: 0,
            access: 3,
        };
        assert_eq!(entry.name(), None);
    }

    #[test]
    fn test_field_list_entry_display() {
        let entry = FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 4,
            access: 3,
            name: "x".to_string(),
        };
        assert_eq!(format!("{}", entry), "x: 0x0074 @ 4");

        let entry = FieldListEntry::Enumerate {
            value: 42,
            access: 3,
            name: "ANSWER".to_string(),
        };
        assert_eq!(format!("{}", entry), "ANSWER = 42");
    }

    #[test]
    fn test_field_list_with_index() {
        let mut fl = AbstractFieldListMsType::new();
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
        // Index entries should not appear in the emitted member list.
        let emitted = fl.emit(Bind::NONE);
        assert!(emitted.contains("a"));
    }

    #[test]
    fn test_field_list_with_methods() {
        let mut fl = AbstractFieldListMsType::new();
        fl.add_entry(FieldListEntry::OverloadedMethod {
            count: 3,
            method_list_record: RecordNumber::type_record(0x1010),
            name: "foo".to_string(),
        });

        assert_eq!(fl.methods().count(), 1);
        let emitted = fl.emit(Bind::NONE);
        assert!(emitted.contains("..."));
    }

    #[test]
    fn test_field_list_record_number() {
        let mut fl = AbstractFieldListMsType::new();
        assert!(fl.record_number().is_no_type());
        fl.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(fl.record_number().index(), 0x2000);
    }

    #[test]
    fn test_field_list_from_parsed() {
        let entries = vec![
            FieldListEntry::Member {
                type_record: RecordNumber::type_record(0x0074),
                offset: 0,
                access: 3,
                name: "x".to_string(),
            },
            FieldListEntry::StaticMember {
                type_record: RecordNumber::type_record(0x0074),
                access: 3,
                name: "count".to_string(),
            },
        ];

        let fl = AbstractFieldListMsType::from_parsed(entries);
        assert_eq!(fl.nonstatic_members().count(), 1);
        assert_eq!(fl.static_members().count(), 1);
    }

    #[test]
    fn test_field_list_bitfield() {
        let mut fl = AbstractFieldListMsType::new();
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
    fn test_field_list_display() {
        let mut fl = AbstractFieldListMsType::new();
        fl.add_entry(FieldListEntry::Member {
            type_record: RecordNumber::type_record(0x0074),
            offset: 0,
            access: 3,
            name: "value".to_string(),
        });

        let display = format!("{}", fl);
        assert!(display.contains("value"));
    }
}
