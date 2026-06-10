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
use super::ms_property::MsProperty;
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
}
