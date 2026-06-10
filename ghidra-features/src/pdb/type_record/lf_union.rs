//! LF_UNION -- concrete Union type record.
//!
//! Ports Ghidra's `UnionMsType` (PDB_ID = 0x1506) and
//! `AbstractUnionMsType` Java classes.
//!
//! Represents a C/C++ `union` type in the PDB type stream.  Wraps
//! [`AbstractCompositeMsType`] with the type string set to `"union"`.
//!
//! Unlike structures and classes, unions do **not** carry derived-from
//! lists or VShape tables; those fields are set to `NO_TYPE`.
//!
//! # Binary Layout (LF_UNION / 0x1506)
//!
//! ```text
//! +0  u16   count           Number of members
//! +2  MsProperty property   Property flags
//! +4  u32   fieldList       Type index of the LF_FIELDLIST
//!     Numeric size          Size in bytes (variable-length encoding)
//!     StringNt name         Null-terminated name (optional)
//!     StringNt mangledName  Null-terminated mangled name (optional)
//! ```

use std::fmt;

use super::abstract_composite_ms_type::AbstractCompositeMsType;
use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::ms_property::{Hfa, Mocom, MsProperty};
use super::RecordNumber;

/// Concrete PDB union type record (`LF_UNION`).
///
/// This is the Rust equivalent of Ghidra's `UnionMsType`.  It delegates
/// all composite fields and behaviour to the embedded
/// [`AbstractCompositeMsType`], overriding only the type string to
/// `"union"` and the PDB ID to `0x1506`.
#[derive(Debug, Clone)]
pub struct LfUnion {
    /// The underlying composite data (count, field list, size, name, etc.).
    pub composite: AbstractCompositeMsType,
}

impl LfUnion {
    /// Create a new union type record.
    ///
    /// # Parameters
    ///
    /// * `count` - Number of field members (-1 if unknown).
    /// * `field_list_record_number` - Record number of the LF_FIELDLIST.
    /// * `size` - Size of the union in bytes.
    /// * `property` - Property flags.
    /// * `name` - Human-readable name (e.g. `"MyUnion"`).
    /// * `mangled_name` - Mangled/decorated name (may be empty).
    pub fn new(
        count: i32,
        field_list_record_number: RecordNumber,
        size: u64,
        property: MsProperty,
        name: String,
        mangled_name: String,
    ) -> Self {
        Self {
            composite: AbstractCompositeMsType::new(
                count,
                field_list_record_number,
                RecordNumber::NO_TYPE, // unions have no derived-from list
                RecordNumber::NO_TYPE, // unions have no VShape table
                size,
                property,
                name,
                mangled_name,
                "union",
            ),
        }
    }

    /// Create from raw parsed field values.
    ///
    /// This is the typical constructor used after deserializing the binary
    /// PDB type record.  Record numbers are constructed from raw type indices.
    /// Derived-from and VShape indices are ignored (set to NO_TYPE) since
    /// unions do not have those fields.
    pub fn from_parsed(
        count: u16,
        property: MsProperty,
        field_list_type_index: u32,
        size: u64,
        name: String,
        mangled_name: Option<String>,
    ) -> Self {
        Self::new(
            count as i32,
            RecordNumber::type_record(field_list_type_index),
            size,
            property,
            name,
            mangled_name.unwrap_or_default(),
        )
    }

    /// Parse an `LF_UNION` record from raw bytes (payload after leaf ID).
    ///
    /// Mirrors the Java `UnionMsType(AbstractPdb, PdbByteReader)` constructor.
    /// Unlike LF_CLASS/LF_STRUCTURE, unions do not have derivedFrom or vshape fields.
    ///
    /// # Binary layout consumed
    ///
    /// ```text
    /// +0  u16   count
    /// +2  u16   property
    /// +4  u32   fieldList type index
    /// +8  Numeric (variable-length size)
    ///     StringNt name
    ///     StringNt mangledName (optional)
    /// ```
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 8 {
            return Err(format!(
                "LF_UNION payload too short: need >= 8 bytes, got {}",
                data.len()
            ));
        }
        let count = u16::from_le_bytes([data[0], data[1]]);
        let property = MsProperty::from_u16(u16::from_le_bytes([data[2], data[3]]));
        let field_list_ti = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        let (size, next) = crate::pdb::pdb_byte_reader::parse_numeric(data, 8);

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

        Ok(Self::from_parsed(count, property, field_list_ti, size, name, mangled_name))
    }

    // =========================================================================
    // Property-based accessors
    // =========================================================================

    /// Whether this union is scoped.
    pub fn is_scoped(&self) -> bool {
        self.composite.property.contains(MsProperty::SCOPED)
    }

    /// Whether this union has a unique name.
    pub fn has_unique_name(&self) -> bool {
        self.composite.property.contains(MsProperty::HAS_UNIQUE_NAME)
    }

    /// Whether this union is packed.
    pub fn is_packed(&self) -> bool {
        self.composite.property.contains(MsProperty::PACKED)
    }

    /// Whether this union has overloaded operators.
    pub fn has_overloaded_ops(&self) -> bool {
        self.composite.property.contains(MsProperty::OVERLOADED_OPS)
    }

    /// Whether this union has overloaded assignment operators.
    pub fn has_overloaded_assign(&self) -> bool {
        self.composite.property.contains(MsProperty::OVLD_ASSIGN)
    }

    /// Whether this union has casting operators.
    pub fn has_casting_ops(&self) -> bool {
        self.composite.property.contains(MsProperty::CASTING_OPS)
    }

    /// Whether this union has constructors/destructors.
    pub fn has_ctor_dtor(&self) -> bool {
        self.composite.property.contains(MsProperty::CTOR)
    }

    /// Whether this union contains nested types.
    pub fn contains_nested(&self) -> bool {
        self.composite.contains_nested()
    }

    /// Get the HFA classification.
    pub fn hfa(&self) -> Hfa {
        self.composite.property.hfa()
    }

    /// Get the Mocom classification.
    pub fn mocom(&self) -> Mocom {
        self.composite.property.mocom()
    }

    /// Get the size of this union in bytes.
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

    /// Get the property flags.
    pub fn property(&self) -> MsProperty {
        self.composite.property
    }

    /// Get the mangled name, if any.
    pub fn mangled_name(&self) -> &str {
        self.composite.mangled_name()
    }

    /// Get the type string for this composite ("union").
    ///
    /// Mirrors Java `AbstractComplexMsType.getTypeString()`.
    pub fn type_name(&self) -> &'static str {
        self.composite.type_string()
    }

    /// Whether this union has a field list assigned.
    pub fn has_field_list(&self) -> bool {
        !self.composite.field_list_record_number.is_no_type()
    }

    /// Compute the packed size (size with no padding).
    ///
    /// If the union is marked as packed, returns the recorded size directly.
    /// Otherwise returns the recorded size (which may include alignment padding).
    pub fn packed_size(&self) -> u64 {
        self.composite.get_size()
    }

    /// Whether this union is sealed (cannot be inherited).
    pub fn is_sealed(&self) -> bool {
        self.composite.property.contains(MsProperty::SEALED)
    }
}

impl AbstractMsType for LfUnion {
    fn name(&self) -> &str {
        self.composite.name()
    }

    fn pdb_id(&self) -> u32 {
        0x1506 // LF_UNION
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

impl fmt::Display for LfUnion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_union() -> LfUnion {
        LfUnion::new(
            3,
            RecordNumber::type_record(0x1001),
            16,
            MsProperty::empty(),
            "MyUnion".to_string(),
            String::new(),
        )
    }

    #[test]
    fn test_union_basic() {
        let u = make_test_union();
        assert_eq!(u.name(), "MyUnion");
        assert_eq!(u.pdb_id(), 0x1506);
        assert_eq!(u.composite.type_string(), "union");
        assert_eq!(u.composite.get_size(), 16);
        assert_eq!(u.composite.num_elements(), 3);
    }

    #[test]
    fn test_union_no_derived_from() {
        let u = make_test_union();
        // Unions always have NO_TYPE for derived-from and VShape.
        assert!(u.composite.derived_from_list_record_number.is_no_type());
        assert!(u.composite.vshape_table_record_number.is_no_type());
    }

    #[test]
    fn test_union_from_parsed() {
        let u = LfUnion::from_parsed(
            4,
            MsProperty::empty(),
            0x1001,
            32,
            "Variant".to_string(),
            None,
        );

        assert_eq!(u.name(), "Variant");
        assert_eq!(u.composite.type_string(), "union");
        assert!(u.composite.mangled_name().is_empty());
    }

    #[test]
    fn test_union_from_parsed_with_mangled() {
        let u = LfUnion::from_parsed(
            2,
            MsProperty::NESTED,
            0x1001,
            8,
            "Inner".to_string(),
            Some(".?ATInner@@".to_string()),
        );

        assert_eq!(u.composite.mangled_name(), ".?ATInner@@");
        assert!(u.composite.property.contains(MsProperty::NESTED));
    }

    #[test]
    fn test_union_emit() {
        let u = make_test_union();
        let emitted = u.emit(Bind::NONE);
        assert!(emitted.starts_with("union MyUnion<"));
        assert!(emitted.contains("3,"));
        assert!(emitted.contains("0x1001"));
    }

    #[test]
    fn test_union_record_number() {
        let mut u = make_test_union();
        assert!(u.record_number().is_no_type());
        u.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(u.record_number().index(), 0x2000);
    }

    #[test]
    fn test_union_display() {
        let u = make_test_union();
        let display = format!("{}", u);
        assert!(display.contains("union"));
        assert!(display.contains("MyUnion"));
    }

    #[test]
    fn test_union_forward_ref() {
        let u = LfUnion::new(
            0,
            RecordNumber::NO_TYPE,
            0,
            MsProperty::FORWARD_REF,
            "FwdUnion".to_string(),
            String::new(),
        );
        assert!(u.composite.is_forward_ref());
    }

    #[test]
    fn test_union_nested() {
        let u = LfUnion::new(
            2,
            RecordNumber::type_record(0x1001),
            8,
            MsProperty::NESTED,
            "Inner".to_string(),
            String::new(),
        );
        assert!(u.composite.is_nested());
    }

    #[test]
    fn test_union_empty_name() {
        let u = LfUnion::new(
            0,
            RecordNumber::NO_TYPE,
            0,
            MsProperty::empty(),
            String::new(),
            String::new(),
        );
        assert!(u.name().is_empty());
    }

    #[test]
    fn test_union_parse() {
        // LF_UNION payload: count=2, property=0, fieldList=0x1001, size=8, name="U"
        let mut data = Vec::new();
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0x1001u32.to_le_bytes());
        data.extend_from_slice(&8u16.to_le_bytes());  // small numeric size
        data.push(b'U'); data.push(0);

        let u = LfUnion::parse(&data).unwrap();
        assert_eq!(u.name(), "U");
        assert_eq!(u.get_count(), 2);
        assert_eq!(u.get_size(), 8);
        assert_eq!(u.pdb_id(), 0x1506);
    }

    #[test]
    fn test_union_parse_with_mangled() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u16.to_le_bytes());
        data.extend_from_slice(&0u16.to_le_bytes());
        data.extend_from_slice(&0x2000u32.to_le_bytes());
        data.extend_from_slice(&16u16.to_le_bytes());
        data.extend_from_slice(b"Variant\0");
        data.extend_from_slice(b".?ATVariant@@\0");

        let u = LfUnion::parse(&data).unwrap();
        assert_eq!(u.name(), "Variant");
        assert_eq!(u.mangled_name(), ".?ATVariant@@");
    }

    #[test]
    fn test_union_parse_too_short() {
        let data = [0u8; 5];
        assert!(LfUnion::parse(&data).is_err());
    }

    #[test]
    fn test_union_is_scoped() {
        let mut u = make_test_union();
        assert!(!u.is_scoped());
        u.composite.property |= MsProperty::SCOPED;
        assert!(u.is_scoped());
    }

    #[test]
    fn test_union_has_unique_name() {
        let mut u = make_test_union();
        assert!(!u.has_unique_name());
        u.composite.property |= MsProperty::HAS_UNIQUE_NAME;
        assert!(u.has_unique_name());
    }

    #[test]
    fn test_union_is_packed() {
        let mut u = make_test_union();
        assert!(!u.is_packed());
        u.composite.property |= MsProperty::PACKED;
        assert!(u.is_packed());
    }

    #[test]
    fn test_union_has_overloaded_ops() {
        let mut u = make_test_union();
        assert!(!u.has_overloaded_ops());
        u.composite.property |= MsProperty::OVERLOADED_OPS;
        assert!(u.has_overloaded_ops());
    }

    #[test]
    fn test_union_has_casting_ops() {
        let mut u = make_test_union();
        assert!(!u.has_casting_ops());
        u.composite.property |= MsProperty::CASTING_OPS;
        assert!(u.has_casting_ops());
    }

    #[test]
    fn test_union_has_ctor_dtor() {
        let mut u = make_test_union();
        assert!(!u.has_ctor_dtor());
        u.composite.property |= MsProperty::CTOR;
        assert!(u.has_ctor_dtor());
    }

    #[test]
    fn test_union_contains_nested() {
        let mut u = make_test_union();
        assert!(!u.contains_nested());
        u.composite.property |= MsProperty::CONTAINS_NESTED;
        assert!(u.contains_nested());
    }

    #[test]
    fn test_union_hfa() {
        let u = make_test_union();
        assert_eq!(u.hfa(), Hfa::NONE);
    }

    #[test]
    fn test_union_mocom() {
        let u = make_test_union();
        assert_eq!(u.mocom(), Mocom::NONE);
    }

    #[test]
    fn test_union_property_accessor() {
        let u = make_test_union();
        assert_eq!(u.property(), MsProperty::empty());
    }

    #[test]
    fn test_union_get_count() {
        let u = make_test_union();
        assert_eq!(u.get_count(), 3);
    }

    #[test]
    fn test_union_get_size() {
        let u = make_test_union();
        assert_eq!(u.get_size(), 16);
    }

    #[test]
    fn test_union_get_field_list_record_number() {
        let u = make_test_union();
        assert_eq!(u.get_field_list_record_number().index(), 0x1001);
    }

    #[test]
    fn test_union_mangled_name_accessor() {
        let u = make_test_union();
        assert!(u.mangled_name().is_empty());
    }

    #[test]
    fn test_union_type_name() {
        let u = make_test_union();
        assert_eq!(u.type_name(), "union");
    }

    #[test]
    fn test_union_has_field_list() {
        let u = make_test_union();
        assert!(u.has_field_list());

        let u2 = LfUnion::new(
            0,
            RecordNumber::NO_TYPE,
            0,
            MsProperty::FORWARD_REF,
            "Fwd".to_string(),
            String::new(),
        );
        assert!(!u2.has_field_list());
    }

    #[test]
    fn test_union_packed_size() {
        let u = make_test_union();
        assert_eq!(u.packed_size(), 16);

        let mut u2 = make_test_union();
        u2.composite.property |= MsProperty::PACKED;
        assert_eq!(u2.packed_size(), 16);
    }

    #[test]
    fn test_union_is_sealed_from_new_method() {
        let mut u = make_test_union();
        assert!(!u.is_sealed());
        u.composite.property |= MsProperty::SEALED;
        assert!(u.is_sealed());
    }
}
