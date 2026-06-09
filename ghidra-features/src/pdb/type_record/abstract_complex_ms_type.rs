//! AbstractComplexMsType -- base for PDB types that carry MsProperty.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.type.AbstractComplexMsType`.
//!
//! "Complex" here does not refer to real+imaginary numbers, but rather to
//! types that have property flags, a field descriptor list, and a name --
//! composites (structs, classes, unions) and enums.

use std::fmt;

use super::abstract_ms_type::AbstractMsType;
use super::bind::Bind;
use super::ms_property::MsProperty;
use super::RecordNumber;

/// Fields common to all "complex" PDB type records.
///
/// Complex types are those that have [`MsProperty`] flags -- namely
/// classes, structures, unions, and enums. This struct collects the
/// shared fields so that concrete type structs can embed it via
/// composition rather than inheritance.
///
/// # Fields
///
/// - `count` -- Number of members (-1 if the concrete type has no count).
/// - `field_descriptor_list` -- Record number of the LF_FIELDLIST for this type.
/// - `property` -- The [`MsProperty`] bitflags.
/// - `name` -- The type name (e.g., `"MyStruct"`).
/// - `mangled_name` -- Optional mangled/decorated name.
/// - `record_number` -- This type's record number in the TPI/IPI stream.
#[derive(Debug, Clone)]
pub struct ComplexTypeFields {
    /// Number of field elements. -1 means "no count field" for the concrete type.
    pub count: i32,
    /// Record number of the field descriptor list (LF_FIELDLIST).
    pub field_descriptor_list: RecordNumber,
    /// Property flags for this type.
    pub property: MsProperty,
    /// The name of this type.
    pub name: String,
    /// The mangled/decorated name, if present.
    pub mangled_name: String,
    /// The record number of this type in the type stream.
    pub record_number: RecordNumber,
}

impl ComplexTypeFields {
    /// Create new complex type fields.
    pub fn new(
        count: i32,
        field_descriptor_list: RecordNumber,
        property: MsProperty,
        name: String,
    ) -> Self {
        ComplexTypeFields {
            count,
            field_descriptor_list,
            property,
            name,
            mangled_name: String::new(),
            record_number: RecordNumber::NO_TYPE,
        }
    }

    /// Set the mangled name and return self (builder pattern).
    pub fn with_mangled_name(mut self, mangled: String) -> Self {
        self.mangled_name = mangled;
        self
    }

    /// Set the record number and return self (builder pattern).
    pub fn with_record_number(mut self, record: RecordNumber) -> Self {
        self.record_number = record;
        self
    }

    /// Return the number of elements, or `None` if count is -1.
    pub fn num_elements(&self) -> Option<i32> {
        if self.count < 0 {
            None
        } else {
            Some(self.count)
        }
    }

    /// Return the field descriptor list record number.
    pub fn field_descriptor_list(&self) -> RecordNumber {
        self.field_descriptor_list
    }

    /// Return the MsProperty of this type.
    pub fn ms_property(&self) -> MsProperty {
        self.property
    }

    /// Return the name of this type.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return the mangled name.
    pub fn mangled_name(&self) -> &str {
        &self.mangled_name
    }

    /// Whether this is a forward reference.
    pub fn is_forward_ref(&self) -> bool {
        self.property.contains(MsProperty::FORWARD_REF)
    }

    /// Whether this type is nested inside another type.
    pub fn is_nested(&self) -> bool {
        self.property.contains(MsProperty::NESTED)
    }
}

impl AbstractMsType for ComplexTypeFields {
    fn name(&self) -> &str {
        &self.name
    }

    fn pdb_id(&self) -> u32 {
        // This is a generic complex type; concrete subclasses override.
        0
    }

    fn record_number(&self) -> RecordNumber {
        self.record_number
    }

    fn set_record_number(&mut self, record_number: RecordNumber) {
        self.record_number = record_number;
    }

    fn emit(&self, _bind: Bind) -> String {
        let mut result = String::new();
        result.push_str(&self.name);
        if self.property != MsProperty::empty() {
            result.push('<');
            result.push_str(&format!("{}", self.property));
            result.push('>');
        }
        result
    }
}

impl fmt::Display for ComplexTypeFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.emit(Bind::NONE))
    }
}

/// Emit helper: format the common complex-type header.
///
/// Writes `type_name name { property_flags }` style output.
pub fn emit_complex_header(
    f: &mut fmt::Formatter<'_>,
    type_string: &str,
    fields: &ComplexTypeFields,
    bind: Bind,
) -> fmt::Result {
    // If a higher-precedence bind wraps us, add parentheses.
    if bind < Bind::PROC {
        write!(f, "(")?;
    }
    write!(f, "{} {}", type_string, fields.name)?;
    if fields.property != MsProperty::empty() {
        write!(f, " {{{}}}", fields.property)?;
    }
    if bind < Bind::PROC {
        write!(f, ")")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fields() -> ComplexTypeFields {
        let rn = RecordNumber::type_record(0x1000);
        let fl = RecordNumber::type_record(0x1001);
        ComplexTypeFields::new(3, fl, MsProperty::empty(), "MyStruct".to_string())
            .with_record_number(rn)
    }

    #[test]
    fn test_num_elements() {
        let f = make_fields();
        assert_eq!(f.num_elements(), Some(3));
    }

    #[test]
    fn test_num_elements_none() {
        let fl = RecordNumber::type_record(0x1001);
        let f = ComplexTypeFields::new(-1, fl, MsProperty::empty(), "X".to_string());
        assert_eq!(f.num_elements(), None);
    }

    #[test]
    fn test_field_descriptor_list() {
        let f = make_fields();
        assert_eq!(f.field_descriptor_list().index(), 0x1001);
    }

    #[test]
    fn test_mangled_name_empty() {
        let f = make_fields();
        assert!(f.mangled_name().is_empty());
    }

    #[test]
    fn test_mangled_name_some() {
        let fl = RecordNumber::type_record(0x1001);
        let f = ComplexTypeFields::new(0, fl, MsProperty::empty(), "X".to_string())
            .with_mangled_name("?X@@YAHXZ".to_string());
        assert_eq!(f.mangled_name(), "?X@@YAHXZ");
    }

    #[test]
    fn test_name() {
        let f = make_fields();
        assert_eq!(f.name(), "MyStruct");
    }

    #[test]
    fn test_ms_property() {
        let fl = RecordNumber::type_record(0x1001);
        let prop = MsProperty::from_u16(0x0001); // packed
        let f = ComplexTypeFields::new(0, fl, prop, "P".to_string());
        assert!(f.ms_property().contains(MsProperty::PACKED));
    }

    #[test]
    fn test_is_forward_ref() {
        let fl = RecordNumber::type_record(0x1001);
        let f = ComplexTypeFields::new(
            0,
            fl,
            MsProperty::FORWARD_REF,
            "Fwd".to_string(),
        );
        assert!(f.is_forward_ref());
    }

    #[test]
    fn test_is_nested() {
        let f = make_fields();
        assert!(!f.is_nested());

        let fl = RecordNumber::type_record(0x1001);
        let f2 = ComplexTypeFields::new(
            0,
            fl,
            MsProperty::NESTED,
            "Inner".to_string(),
        );
        assert!(f2.is_nested());
    }

    #[test]
    fn test_record_number() {
        let mut f = make_fields();
        assert_eq!(f.record_number().index(), 0x1000);
        f.set_record_number(RecordNumber::type_record(0x2000));
        assert_eq!(f.record_number().index(), 0x2000);
    }

    #[test]
    fn test_display() {
        let f = make_fields();
        let s = format!("{}", f);
        assert!(s.contains("MyStruct"));
    }

    #[test]
    fn test_emit_complex_header() {
        use std::fmt;
        let f = make_fields();

        struct FmtFn<F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result>(F);
        impl<F: Fn(&mut fmt::Formatter<'_>) -> fmt::Result> fmt::Display for FmtFn<F> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                (self.0)(f)
            }
        }

        let display = FmtFn(|fmter: &mut fmt::Formatter<'_>| {
            emit_complex_header(fmter, "struct", &f, Bind::NONE)
        });
        let s = format!("{}", display);
        assert!(s.contains("struct MyStruct"));
    }
}
