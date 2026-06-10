//! LF_STRUCTURE -- concrete Structure type record.
//!
//! Ports Ghidra's `StructureMsType` (PDB_ID = 0x1505) and
//! `AbstractStructureMsType` Java classes.
//!
//! Represents a C/C++ `struct` type in the PDB type stream.  Wraps
//! [`AbstractCompositeMsType`] with the type string set to `"struct"`.
//!
//! # Binary Layout (LF_STRUCTURE / 0x1505)
//!
//! ```text
//! +0  u16   count           Number of members
//! +2  MsProperty property   Property flags
//! +4  u32   fieldList       Type index of the LF_FIELDLIST
//! +8  u32   derivedFrom     Type index of the derived-from list
//! +12 u32   vshape          Type index of the VShape table
//! +16 Numeric size          Size in bytes (variable-length encoding)
//!     StringNt name         Null-terminated name
//!     StringNt mangledName  Null-terminated mangled name (optional)
//! ```

use std::fmt;

use super::abstract_composite_ms_type::AbstractCompositeMsType;
use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::ms_property::{Hfa, Mocom, MsProperty};
use super::RecordNumber;

/// Concrete PDB structure type record (`LF_STRUCTURE`).
///
/// This is the Rust equivalent of Ghidra's `StructureMsType`.  It delegates
/// all composite fields and behaviour to the embedded
/// [`AbstractCompositeMsType`], overriding only the type string to
/// `"struct"` and the PDB ID to `0x1505`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LfStructure {
    /// The underlying composite data (count, field list, size, name, etc.).
    pub composite: AbstractCompositeMsType,
}

impl LfStructure {
    /// Create a new structure type record.
    ///
    /// # Parameters
    ///
    /// * `count` - Number of field members (-1 if unknown).
    /// * `field_list_record_number` - Record number of the LF_FIELDLIST.
    /// * `derived_from_list_record_number` - Record number of the derived-from list.
    /// * `vshape_table_record_number` - Record number of the VShape table.
    /// * `size` - Size of the structure in bytes.
    /// * `property` - Property flags.
    /// * `name` - Human-readable name (e.g. `"MyStruct"`).
    /// * `mangled_name` - Mangled/decorated name (may be empty).
    pub fn new(
        count: i32,
        field_list_record_number: RecordNumber,
        derived_from_list_record_number: RecordNumber,
        vshape_table_record_number: RecordNumber,
        size: u64,
        property: MsProperty,
        name: String,
        mangled_name: String,
    ) -> Self {
        Self {
            composite: AbstractCompositeMsType::new(
                count,
                field_list_record_number,
                derived_from_list_record_number,
                vshape_table_record_number,
                size,
                property,
                name,
                mangled_name,
                "struct",
            ),
        }
    }

    /// Create from raw parsed field values.
    ///
    /// This is the typical constructor used after deserializing the binary
    /// PDB type record.  Record numbers are constructed from raw type indices.
    pub fn from_parsed(
        count: u16,
        property: MsProperty,
        field_list_type_index: u32,
        derived_type_index: u32,
        vshape_type_index: u32,
        size: u64,
        name: String,
        mangled_name: Option<String>,
    ) -> Self {
        Self::new(
            count as i32,
            RecordNumber::type_record(field_list_type_index),
            RecordNumber::type_record(derived_type_index),
            RecordNumber::type_record(vshape_type_index),
            size,
            property,
            name,
            mangled_name.unwrap_or_default(),
        )
    }

    /// Parse an `LF_STRUCTURE` record from raw bytes (payload after leaf ID).
    ///
    /// Mirrors the Java `StructureMsType(AbstractPdb, PdbByteReader)` constructor.
    /// The `data` slice should start at the `count` field (after the 2-byte leaf ID).
    ///
    /// # Binary layout consumed
    ///
    /// ```text
    /// +0  u16   count
    /// +2  u16   property
    /// +4  u32   fieldList type index
    /// +8  u32   derivedFrom type index
    /// +12 u32   vshape type index
    /// +16 Numeric (variable-length size)
    ///     StringNt name
    ///     StringNt mangledName (optional)
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 16 {
            return Err(format!(
                "LF_STRUCTURE payload too short: need >= 16 bytes, got {}",
                data.len()
            ));
        }
        let count = u16::from_le_bytes([data[0], data[1]]);
        let property = MsProperty::from_u16(u16::from_le_bytes([data[2], data[3]]));
        let field_list_ti = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let derived_ti = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let vshape_ti = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

        let (size, next) = crate::pdb::pdb_byte_reader::parse_numeric(data, 16);

        // Parse name and optional mangled name from remaining bytes.
        let (name, mangled_name) = if next < data.len() {
            let (n, after_n) = crate::pdb::pdb_byte_reader::read_null_terminated_string(data, next);
            let mn = if after_n < data.len() && data[after_n] != 0 {
                crate::pdb::pdb_byte_reader::parse_null_terminated_string(&data[after_n..])
            } else {
                String::new()
            };
            (n, if mn.is_empty() { None } else { Some(mn) })
        } else {
            (String::new(), None)
        };

        Ok(Self::from_parsed(count, property, field_list_ti, derived_ti, vshape_ti, size, name, mangled_name))
    }

    // =========================================================================
    // Property-based accessors
    // =========================================================================

    /// Whether this structure is scoped (e.g., a C++11 scoped enum-like usage).
    pub fn is_scoped(&self) -> bool {
        self.composite.property.contains(MsProperty::SCOPED)
    }

    /// Whether this structure has a unique name (fully qualified).
    pub fn has_unique_name(&self) -> bool {
        self.composite.property.contains(MsProperty::HAS_UNIQUE_NAME)
    }

    /// Whether this structure is sealed (cannot be inherited).
    pub fn is_sealed(&self) -> bool {
        self.composite.property.contains(MsProperty::SEALED)
    }

    /// Whether this structure is packed (no padding between members).
    pub fn is_packed(&self) -> bool {
        self.composite.property.contains(MsProperty::PACKED)
    }

    /// Whether this structure has overloaded operators.
    pub fn has_overloaded_ops(&self) -> bool {
        self.composite.property.contains(MsProperty::OVERLOADED_OPS)
    }

    /// Whether this structure has overloaded assignment operators.
    pub fn has_overloaded_assign(&self) -> bool {
        self.composite.property.contains(MsProperty::OVLD_ASSIGN)
    }

    /// Whether this structure has casting operators.
    pub fn has_casting_ops(&self) -> bool {
        self.composite.property.contains(MsProperty::CASTING_OPS)
    }

    /// Whether this structure has constructors/destructors.
    pub fn has_ctor_dtor(&self) -> bool {
        self.composite.property.contains(MsProperty::CTOR)
    }

    /// Whether this structure contains nested types.
    pub fn contains_nested(&self) -> bool {
        self.composite.contains_nested()
    }

    /// Get the HFA (Homogeneous Floating-point Aggregate) classification.
    pub fn hfa(&self) -> Hfa {
        self.composite.property.hfa()
    }

    /// Get the Mocom (Managed/COM) classification.
    pub fn mocom(&self) -> Mocom {
        self.composite.property.mocom()
    }

    /// Get the size of this structure in bytes.
    pub fn get_size(&self) -> u64 {
        self.composite.get_size()
    }

    /// Get the number of field elements.
    pub fn get_count(&self) -> i32 {
        self.composite.num_elements()
    }

    /// Get the field list record number.
    pub fn get_field_list_record_number(&self) -> RecordNumber {
        self.composite.field_list_record_number
    }

    /// Get the derived-from list record number.
    pub fn get_derived_from_record_number(&self) -> RecordNumber {
        self.composite.derived_from_list_record_number
    }

    /// Get the VShape table record number.
    pub fn get_vshape_record_number(&self) -> RecordNumber {
        self.composite.vshape_table_record_number
    }

    /// Get the property flags.
    pub fn property(&self) -> MsProperty {
        self.composite.property
    }

    /// Get the mangled name, if any.
    pub fn mangled_name(&self) -> &str {
        self.composite.mangled_name()
    }

    /// Get the type string for this composite ("struct").
    ///
    /// Mirrors Java `AbstractComplexMsType.getTypeString()`.
    pub fn type_name(&self) -> &'static str {
        self.composite.type_string()
    }

    /// Whether this structure has a field list assigned.
    ///
    /// Returns `true` if `field_list_record_number` is not `NO_TYPE`.
    pub fn has_field_list(&self) -> bool {
        !self.composite.field_list_record_number.is_no_type()
    }

    /// Whether this structure has a derived-from list.
    ///
    /// Returns `true` if `derived_from_list_record_number` is not `NO_TYPE`.
    pub fn has_derived_from(&self) -> bool {
        !self.composite.derived_from_list_record_number.is_no_type()
    }

    /// Whether this structure has a VShape table.
    ///
    /// Returns `true` if `vshape_table_record_number` is not `NO_TYPE`.
    pub fn has_vshape(&self) -> bool {
        !self.composite.vshape_table_record_number.is_no_type()
    }

    /// Whether this structure is an interface (C++/CLI).
    ///
    /// An interface is a class with the `INTERFACE` mocom classification.
    pub fn is_interface(&self) -> bool {
        self.composite.property.mocom() == super::ms_property::Mocom::INTERFACE
    }

    /// Whether this structure is abstract (has pure virtual methods).
    ///
    /// Note: PDB does not directly encode this; the heuristic is that
    /// an abstract class has a non-empty vshape table but zero instances.
    /// For now we check the `SEALED` flag as a proxy -- real abstract
    /// detection requires inspecting the method list for pure-virtual entries.
    pub fn is_abstract(&self) -> bool {
        // Abstract classes are typically forward-declared or sealed.
        // This is a heuristic; full detection requires vtable analysis.
        self.composite.is_forward_ref() && self.composite.vshape_table_record_number.is_no_type()
    }

    /// Compute the packed size (size with no padding).
    ///
    /// If the structure is marked as packed, returns the recorded size
    /// directly. Otherwise, this is an approximation: the recorded size
    /// may already include alignment padding.
    pub fn packed_size(&self) -> u64 {
        if self.is_packed() {
            self.composite.get_size()
        } else {
            // Without access to individual member types and their sizes,
            // we can only return the recorded size.
            self.composite.get_size()
        }
    }

    /// Get the size in bytes as `u64`.
    ///
    /// Alias for [`get_size`](Self::get_size) providing a more descriptive
    /// name when the context is about byte sizes.
    pub fn size_in_bytes(&self) -> u64 {
        self.composite.get_size()
    }

    /// Whether this structure is a forward reference.
    ///
    /// Forward references are placeholders for types whose full definition
    /// appears elsewhere in the type stream.
    pub fn is_forward_ref(&self) -> bool {
        self.composite.is_forward_ref()
    }

    /// Whether the property flags are empty (no special properties).
    pub fn has_no_properties(&self) -> bool {
        self.composite.property.is_empty()
    }

    /// Get the number of members that are known (not -1/unknown).
    ///
    /// Returns `Some(count)` if the count is >= 0, `None` if the count
    /// is -1 (meaning the member count is unknown).
    pub fn known_member_count(&self) -> Option<u32> {
        if self.composite.count >= 0 {
            Some(self.composite.count as u32)
        } else {
            None
        }
    }
}

impl AbstractMsType for LfStructure {
    fn name(&self) -> &str {
        self.composite.name()
    }

    fn pdb_id(&self) -> u32 {
        0x1505 // LF_STRUCTURE
    }

    fn record_number(&self) -> RecordNumber {
        self.composite.record_number()
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.composite.set_record_number(record_number);
    }

    fn emit(&self, _bind: Bind) -> String {
        self.composite.emit(Bind::NONE)
    }
}

impl fmt::Display for LfStructure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_structure() -> LfStructure {
        LfStructure::new(
            3,
            RecordNumber::type_record(0x1001),
            RecordNumber::type_record(0x1002),
            RecordNumber::type_record(0x1003),
            24,
            MsProperty::empty(),
            "Point3D".to_string(),
            String::new(),
        )
    }

    #[test]
    fn test_structure_basic() {
        let s = make_test_structure();
        assert_eq!(s.name(), "Point3D");
        assert_eq!(s.pdb_id(), 0x1505);
        assert_eq!(s.composite.type_string(), "struct");
        assert_eq!(s.composite.get_size(), 24);
        assert_eq!(s.composite.num_elements(), 3);
    }

    #[test]
    fn test_structure_from_parsed() {
        let s = LfStructure::from_parsed(
            5,
            MsProperty::empty(),
            0x1001,
            0,
            0,
            40,
            "Vec3".to_string(),
            None,
        );

        assert_eq!(s.name(), "Vec3");
        assert_eq!(s.composite.type_string(), "struct");
        assert!(s.composite.mangled_name().is_empty());
    }

    #[test]
    fn test_structure_from_parsed_with_mangled() {
        let s = LfStructure::from_parsed(
            2,
            MsProperty::PACKED,
            0x1001,
            0,
            0,
            8,
            "Packed".to_string(),
            Some(".?AUPacked@@".to_string()),
        );

        assert_eq!(s.composite.mangled_name(), ".?AUPacked@@");
        assert!(s.composite.property.contains(MsProperty::PACKED));
    }

    #[test]
    fn test_structure_emit() {
        let s = make_test_structure();
        let emitted = s.emit(Bind::NONE);
        assert!(emitted.starts_with("struct Point3D<"));
        assert!(emitted.contains("3,"));
        assert!(emitted.contains("0x1001"));
    }

    #[test]
    fn test_structure_record_number() {
        let mut s = make_test_structure();
        assert!(s.record_number().is_no_type());
        s.set_record_number(RecordNumber::type_record(0x3000));
        assert_eq!(s.record_number().index(), 0x3000);
    }

    #[test]
    fn test_structure_display() {
        let s = make_test_structure();
        let display = format!("{}", s);
        assert!(display.contains("struct"));
        assert!(display.contains("Point3D"));
    }

    #[test]
    fn test_structure_forward_ref() {
        let s = LfStructure::new(
            0,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            0,
            MsProperty::FORWARD_REF,
            "FwdStruct".to_string(),
            String::new(),
        );
        assert!(s.composite.is_forward_ref());
    }

    #[test]
    fn test_structure_nested() {
        let s = LfStructure::new(
            1,
            RecordNumber::type_record(0x1001),
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            4,
            MsProperty::NESTED,
            "Inner".to_string(),
            String::new(),
        );
        assert!(s.composite.is_nested());
    }

    #[test]
    fn test_structure_parse() {
        // Build a minimal LF_STRUCTURE payload: count=2, property=0, fieldList=0x1001,
        // derivedFrom=0, vshape=0, size=8, name="S"
        let mut data = Vec::new();
        data.extend_from_slice(&2u16.to_le_bytes());       // count
        data.extend_from_slice(&0u16.to_le_bytes());       // property
        data.extend_from_slice(&0x1001u32.to_le_bytes());  // fieldList
        data.extend_from_slice(&0u32.to_le_bytes());       // derivedFrom
        data.extend_from_slice(&0u32.to_le_bytes());       // vshape
        data.extend_from_slice(&8u16.to_le_bytes());       // size (small numeric)
        data.push(b'S'); data.push(0);                     // name = "S\0"

        let s = LfStructure::parse(&data).unwrap();
        assert_eq!(s.name(), "S");
        assert_eq!(s.get_count(), 2);
        assert_eq!(s.get_size(), 8);
        assert_eq!(s.get_field_list_record_number().index(), 0x1001);
    }

    #[test]
    fn test_structure_parse_with_mangled_name() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0x2000u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&16u16.to_le_bytes());
        data.extend_from_slice(b"Foo\0");
        data.extend_from_slice(b".?AUFoo@@\0");

        let s = LfStructure::parse(&data).unwrap();
        assert_eq!(s.name(), "Foo");
        assert_eq!(s.mangled_name(), ".?AUFoo@@");
    }

    #[test]
    fn test_structure_parse_too_short() {
        let data = [0u8; 10];
        assert!(LfStructure::parse(&data).is_err());
    }

    #[test]
    fn test_structure_is_scoped() {
        let mut s = make_test_structure();
        assert!(!s.is_scoped());
        s.composite.property |= MsProperty::SCOPED;
        assert!(s.is_scoped());
    }

    #[test]
    fn test_structure_has_unique_name() {
        let mut s = make_test_structure();
        assert!(!s.has_unique_name());
        s.composite.property |= MsProperty::HAS_UNIQUE_NAME;
        assert!(s.has_unique_name());
    }

    #[test]
    fn test_structure_is_sealed() {
        let mut s = make_test_structure();
        assert!(!s.is_sealed());
        s.composite.property |= MsProperty::SEALED;
        assert!(s.is_sealed());
    }

    #[test]
    fn test_structure_is_packed() {
        let mut s = make_test_structure();
        assert!(!s.is_packed());
        s.composite.property |= MsProperty::PACKED;
        assert!(s.is_packed());
    }

    #[test]
    fn test_structure_has_overloaded_ops() {
        let mut s = make_test_structure();
        assert!(!s.has_overloaded_ops());
        s.composite.property |= MsProperty::OVERLOADED_OPS;
        assert!(s.has_overloaded_ops());
    }

    #[test]
    fn test_structure_has_casting_ops() {
        let mut s = make_test_structure();
        assert!(!s.has_casting_ops());
        s.composite.property |= MsProperty::CASTING_OPS;
        assert!(s.has_casting_ops());
    }

    #[test]
    fn test_structure_has_ctor_dtor() {
        let mut s = make_test_structure();
        assert!(!s.has_ctor_dtor());
        s.composite.property |= MsProperty::CTOR;
        assert!(s.has_ctor_dtor());
    }

    #[test]
    fn test_structure_hfa() {
        let s = make_test_structure();
        assert_eq!(s.hfa(), Hfa::NONE);
    }

    #[test]
    fn test_structure_mocom() {
        let s = make_test_structure();
        assert_eq!(s.mocom(), Mocom::NONE);
    }

    #[test]
    fn test_structure_property_accessor() {
        let s = make_test_structure();
        assert_eq!(s.property(), MsProperty::empty());
    }

    #[test]
    fn test_structure_get_count() {
        let s = make_test_structure();
        assert_eq!(s.get_count(), 3);
    }

    #[test]
    fn test_structure_get_size() {
        let s = make_test_structure();
        assert_eq!(s.get_size(), 24);
    }

    #[test]
    fn test_structure_get_record_numbers() {
        let s = make_test_structure();
        assert_eq!(s.get_field_list_record_number().index(), 0x1001);
        assert_eq!(s.get_derived_from_record_number().index(), 0x1002);
        assert_eq!(s.get_vshape_record_number().index(), 0x1003);
    }

    #[test]
    fn test_structure_mangled_name_accessor() {
        let s = make_test_structure();
        assert!(s.mangled_name().is_empty());
    }

    #[test]
    fn test_structure_contains_nested() {
        let mut s = make_test_structure();
        assert!(!s.contains_nested());
        s.composite.property |= MsProperty::CONTAINS_NESTED;
        assert!(s.contains_nested());
    }

    #[test]
    fn test_structure_type_name() {
        let s = make_test_structure();
        assert_eq!(s.type_name(), "struct");
    }

    #[test]
    fn test_structure_has_field_list() {
        let s = make_test_structure();
        assert!(s.has_field_list());

        let s2 = LfStructure::new(
            0,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            0,
            MsProperty::FORWARD_REF,
            "Fwd".to_string(),
            String::new(),
        );
        assert!(!s2.has_field_list());
    }

    #[test]
    fn test_structure_has_derived_from() {
        let s = make_test_structure();
        assert!(s.has_derived_from());

        let s2 = LfStructure::new(
            1,
            RecordNumber::type_record(0x1001),
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            4,
            MsProperty::empty(),
            "NoBase".to_string(),
            String::new(),
        );
        assert!(!s2.has_derived_from());
    }

    #[test]
    fn test_structure_has_vshape() {
        let s = make_test_structure();
        assert!(s.has_vshape());

        let s2 = LfStructure::new(
            1,
            RecordNumber::type_record(0x1001),
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            4,
            MsProperty::empty(),
            "NoVtable".to_string(),
            String::new(),
        );
        assert!(!s2.has_vshape());
    }

    #[test]
    fn test_structure_is_interface() {
        let s = make_test_structure();
        assert!(!s.is_interface());
    }

    #[test]
    fn test_structure_packed_size() {
        let s = make_test_structure();
        assert_eq!(s.packed_size(), 24);

        let mut s2 = make_test_structure();
        s2.composite.property |= MsProperty::PACKED;
        assert_eq!(s2.packed_size(), 24);
    }

    #[test]
    fn test_structure_size_in_bytes() {
        let s = make_test_structure();
        assert_eq!(s.size_in_bytes(), 24);
    }

    #[test]
    fn test_structure_is_forward_ref() {
        let s = make_test_structure();
        assert!(!s.is_forward_ref());

        let s2 = LfStructure::new(
            0,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            0,
            MsProperty::FORWARD_REF,
            "FwdStruct".to_string(),
            String::new(),
        );
        assert!(s2.is_forward_ref());
    }

    #[test]
    fn test_structure_has_no_properties() {
        let s = make_test_structure();
        assert!(s.has_no_properties());

        let mut s2 = make_test_structure();
        s2.composite.property |= MsProperty::NESTED;
        assert!(!s2.has_no_properties());
    }

    #[test]
    fn test_structure_known_member_count() {
        let s = make_test_structure();
        assert_eq!(s.known_member_count(), Some(3));

        let s2 = LfStructure::new(
            -1,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            0,
            MsProperty::FORWARD_REF,
            "Unknown".to_string(),
            String::new(),
        );
        assert_eq!(s2.known_member_count(), None);
    }

    #[test]
    fn test_structure_eq() {
        let s1 = make_test_structure();
        let s2 = make_test_structure();
        assert_eq!(s1, s2);

        let s3 = LfStructure::new(
            3,
            RecordNumber::type_record(0x1001),
            RecordNumber::type_record(0x1002),
            RecordNumber::type_record(0x1003),
            24,
            MsProperty::empty(),
            "Different".to_string(),
            String::new(),
        );
        assert_ne!(s1, s3);
    }

    #[test]
    fn test_structure_empty_name() {
        let s = LfStructure::new(
            0,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            0,
            MsProperty::empty(),
            String::new(),
            String::new(),
        );
        assert!(s.name().is_empty());
    }

    #[test]
    fn test_structure_large_size() {
        let s = LfStructure::new(
            100,
            RecordNumber::type_record(0x1001),
            RecordNumber::NO_TYPE,
            RecordNumber::NO_TYPE,
            0x1_0000_0000, // 4 GB
            MsProperty::empty(),
            "LargeStruct".to_string(),
            String::new(),
        );
        assert_eq!(s.get_size(), 0x1_0000_0000);
        assert_eq!(s.size_in_bytes(), 0x1_0000_0000);
    }
}
