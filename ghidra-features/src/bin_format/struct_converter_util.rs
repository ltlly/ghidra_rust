//! Automatic struct-to-DataType conversion utility ported from Ghidra's
//! `ghidra.app.util.bin.StructConverterUtil`.
//!
//! The Java version uses reflection to discover private fields and convert
//! them to Ghidra DataType structures. In Rust, there is no runtime
//! reflection, so this module provides a trait-based approach:
//!
//! - [`FieldDescriptor`] describes a single struct field (name, type, offset)
//! - [`StructDescriptor`] collects field descriptors into a complete struct layout
//! - [`StructConverterUtil`] provides convenience methods for building
//!   descriptors from types that implement [`ReflectableStruct`]
//!
//! # Example
//!
//! ```
//! use ghidra_features::bin_format::struct_converter_util::*;
//! use ghidra_features::bin_format::types::DataTypeDescription;
//!
//! let mut desc = StructDescriptor::new("Elf64_Ehdr");
//! desc.add_field("e_ident", DataTypeDescription::Array {
//!     element: Box::new(DataTypeDescription::Byte),
//!     count: 16,
//! });
//! desc.add_field("e_type", DataTypeDescription::Word);
//! desc.add_field("e_machine", DataTypeDescription::Word);
//! desc.add_field("e_version", DataTypeDescription::DWord);
//! desc.add_field("e_entry", DataTypeDescription::QWord);
//!
//! assert_eq!(desc.name(), "Elf64_Ehdr");
//! assert_eq!(desc.field_count(), 5);
//! assert_eq!(desc.total_size(), Some(32));
//! ```

use std::fmt;

use super::types::DataTypeDescription;

// ---------------------------------------------------------------------------
// FieldDescriptor
// ---------------------------------------------------------------------------

/// Describes a single field in a binary struct layout.
///
/// Ported from the field introspection logic in `StructConverterUtil`.
/// Each field has a name, a data type, and optionally a byte offset
/// within the containing struct.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldDescriptor {
    /// The field name (e.g. "e_type", "sh_offset").
    name: String,
    /// The data type of this field.
    data_type: DataTypeDescription,
    /// Optional byte offset from the start of the struct.
    offset: Option<usize>,
}

impl FieldDescriptor {
    /// Create a new field descriptor.
    pub fn new(name: impl Into<String>, data_type: DataTypeDescription) -> Self {
        Self {
            name: name.into(),
            data_type,
            offset: None,
        }
    }

    /// Create a new field descriptor with an explicit byte offset.
    pub fn with_offset(
        name: impl Into<String>,
        data_type: DataTypeDescription,
        offset: usize,
    ) -> Self {
        Self {
            name: name.into(),
            data_type,
            offset: Some(offset),
        }
    }

    /// Returns the field name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the field's data type.
    pub fn data_type(&self) -> &DataTypeDescription {
        &self.data_type
    }

    /// Returns the byte offset, if explicitly set.
    pub fn offset(&self) -> Option<usize> {
        self.offset
    }

    /// Returns the size in bytes of this field, if known.
    pub fn size(&self) -> Option<usize> {
        self.data_type.size()
    }
}

impl fmt::Display for FieldDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.offset {
            Some(ofs) => write!(f, "[{:04x}] {}: {}", ofs, self.name, self.data_type),
            None => write!(f, "{}: {}", self.name, self.data_type),
        }
    }
}

// ---------------------------------------------------------------------------
// StructDescriptor
// ---------------------------------------------------------------------------

/// Describes the complete layout of a binary struct.
///
/// Collects ordered [`FieldDescriptor`] entries and computes the total
/// struct size. Equivalent to the `StructureDataType` created by the Java
/// `StructConverterUtil.toDataType()`.
#[derive(Debug, Clone)]
pub struct StructDescriptor {
    /// The struct type name.
    name: String,
    /// Ordered list of fields in declaration order.
    fields: Vec<FieldDescriptor>,
    /// Explicit size override (if set, overrides computed size).
    explicit_size: Option<usize>,
    /// Explicit alignment override.
    alignment: Option<usize>,
}

impl StructDescriptor {
    /// Create a new empty struct descriptor.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
            explicit_size: None,
            alignment: None,
        }
    }

    /// Create a struct descriptor with an explicit total size.
    pub fn with_size(name: impl Into<String>, size: usize) -> Self {
        Self {
            name: name.into(),
            fields: Vec::new(),
            explicit_size: Some(size),
            alignment: None,
        }
    }

    /// Set the struct alignment requirement.
    pub fn set_alignment(&mut self, alignment: usize) {
        self.alignment = Some(alignment);
    }

    /// Add a field to this struct.
    ///
    /// Fields should be added in declaration order (matching the binary layout).
    pub fn add_field(&mut self, name: impl Into<String>, data_type: DataTypeDescription) {
        self.fields.push(FieldDescriptor::new(name, data_type));
    }

    /// Add a field with an explicit byte offset.
    pub fn add_field_at(
        &mut self,
        name: impl Into<String>,
        data_type: DataTypeDescription,
        offset: usize,
    ) {
        self.fields
            .push(FieldDescriptor::with_offset(name, data_type, offset));
    }

    /// Add a field descriptor directly.
    pub fn push_field(&mut self, field: FieldDescriptor) {
        self.fields.push(field);
    }

    /// Returns the struct name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the number of fields in this struct.
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }

    /// Returns a slice of all field descriptors.
    pub fn fields(&self) -> &[FieldDescriptor] {
        &self.fields
    }

    /// Returns a mutable slice of all field descriptors.
    pub fn fields_mut(&mut self) -> &mut [FieldDescriptor] {
        &mut self.fields
    }

    /// Returns the alignment, if explicitly set.
    pub fn alignment(&self) -> Option<usize> {
        self.alignment
    }

    /// Compute the total size of this struct by summing field sizes.
    ///
    /// Returns `None` if any field has an unknown size and no explicit
    /// size override has been set.
    pub fn total_size(&self) -> Option<usize> {
        if let Some(size) = self.explicit_size {
            return Some(size);
        }
        self.fields.iter().try_fold(0usize, |acc, f| {
            f.size().map(|s| acc + s)
        })
    }

    /// Set an explicit total size override.
    pub fn set_total_size(&mut self, size: usize) {
        self.explicit_size = Some(size);
    }

    /// Returns the explicit size override, if set.
    pub fn explicit_size(&self) -> Option<usize> {
        self.explicit_size
    }

    /// Look up a field by name.
    pub fn field_by_name(&self, name: &str) -> Option<&FieldDescriptor> {
        self.fields.iter().find(|f| f.name() == name)
    }

    /// Look up a field by index.
    pub fn field_at(&self, index: usize) -> Option<&FieldDescriptor> {
        self.fields.get(index)
    }

    /// Convert this struct descriptor to a [`DataTypeDescription::Struct`].
    pub fn to_data_type(&self) -> DataTypeDescription {
        let fields: Vec<(String, DataTypeDescription)> = self
            .fields
            .iter()
            .map(|f| (f.name().to_string(), f.data_type().clone()))
            .collect();
        DataTypeDescription::Struct {
            name: self.name.clone(),
            size: fields.iter().filter_map(|(_, dt)| dt.size()).sum::<usize>() as u32,
            fields,
        }
    }

    /// Compute automatic field offsets assuming no padding.
    ///
    /// Fills in any fields that don't have explicit offsets, assigning
    /// them sequential offsets based on preceding field sizes.
    pub fn compute_offsets(&mut self) -> bool {
        let mut current_offset: usize = 0;
        for field in &mut self.fields {
            if field.offset.is_none() {
                field.offset = Some(current_offset);
            }
            match field.size() {
                Some(size) => current_offset = field.offset.unwrap() + size,
                None => return false, // cannot compute without all sizes known
            }
        }
        true
    }
}

impl fmt::Display for StructDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "struct {} {{", self.name)?;
        for field in &self.fields {
            writeln!(f, "    {},", field)?;
        }
        write!(f, "}}")?;
        if let Some(size) = self.total_size() {
            write!(f, " // {} bytes", size)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ReflectableStruct trait
// ---------------------------------------------------------------------------

/// Trait for Rust types that can describe their binary layout.
///
/// This is the Rust equivalent of the Java `StructConverter` interface's
/// reflection-based discovery. Types implementing this trait provide
/// their own field descriptors, making the conversion explicit rather
/// than relying on runtime reflection.
///
/// # Derive macro support
///
/// In practice, a derive macro would generate this implementation
/// automatically from struct field annotations. The manual impl is
/// shown here for completeness.
///
/// # Example
///
/// ```
/// use ghidra_features::bin_format::struct_converter_util::*;
/// use ghidra_features::bin_format::types::DataTypeDescription;
///
/// struct Elf32Ehdr {
///     e_ident: [u8; 16],
///     e_type: u16,
///     e_machine: u16,
///     e_version: u32,
/// }
///
/// impl ReflectableStruct for Elf32Ehdr {
///     fn struct_name() -> &'static str { "Elf32_Ehdr" }
///     fn field_descriptors() -> Vec<FieldDescriptor> {
///         vec![
///             FieldDescriptor::with_offset("e_ident", DataTypeDescription::Array {
///                 element: Box::new(DataTypeDescription::Byte), count: 16
///             }, 0),
///             FieldDescriptor::with_offset("e_type", DataTypeDescription::Word, 16),
///             FieldDescriptor::with_offset("e_machine", DataTypeDescription::Word, 18),
///             FieldDescriptor::with_offset("e_version", DataTypeDescription::DWord, 20),
///         ]
///     }
/// }
///
/// let desc = StructConverterUtil::from_type::<Elf32Ehdr>();
/// assert_eq!(desc.name(), "Elf32_Ehdr");
/// assert_eq!(desc.field_count(), 4);
/// ```
pub trait ReflectableStruct {
    /// Returns the name of this struct type.
    fn struct_name() -> &'static str;

    /// Returns the field descriptors for this struct's layout.
    fn field_descriptors() -> Vec<FieldDescriptor>;
}

// ---------------------------------------------------------------------------
// StructConverterUtil
// ---------------------------------------------------------------------------

/// Utility for converting Rust types to struct descriptors.
///
/// Ported from `ghidra.app.util.bin.StructConverterUtil`. The Java version
/// uses `java.lang.reflect.Field` to discover private fields and convert
/// them to Ghidra DataType structures. The Rust version uses the
/// [`ReflectableStruct`] trait instead.
pub struct StructConverterUtil;

impl StructConverterUtil {
    /// Create a [`StructDescriptor`] from a type that implements [`ReflectableStruct`].
    ///
    /// Equivalent to the Java `StructConverterUtil.toDataType(Class<?>)`.
    pub fn from_type<T: ReflectableStruct>() -> StructDescriptor {
        let mut desc = StructDescriptor::new(T::struct_name());
        for field in T::field_descriptors() {
            desc.push_field(field);
        }
        desc
    }

    /// Create a [`StructDescriptor`] from a type and compute automatic offsets.
    ///
    /// Equivalent to the Java `StructConverterUtil.toDataType(Object)` where
    /// the object instance is used for array length discovery.
    pub fn from_type_with_offsets<T: ReflectableStruct>() -> StructDescriptor {
        let mut desc = Self::from_type::<T>();
        desc.compute_offsets();
        desc
    }

    /// Parse a simple name from a fully qualified type name.
    ///
    /// Equivalent to `StructConverterUtil.parseName(Class<?>)`. Given a
    /// string like `"ghidra.app.util.bin.format.elf.ElfHeader"`, returns
    /// `"ElfHeader"`.
    ///
    /// # Example
    ///
    /// ```
    /// use ghidra_features::bin_format::struct_converter_util::StructConverterUtil;
    ///
    /// assert_eq!(StructConverterUtil::parse_name("ghidra.app.util.bin.ElfHeader"), "ElfHeader");
    /// assert_eq!(StructConverterUtil::parse_name("SimpleClass"), "SimpleClass");
    /// assert_eq!(StructConverterUtil::parse_name(""), "");
    /// ```
    pub fn parse_name(fully_qualified_name: &str) -> &str {
        match fully_qualified_name.rfind('.') {
            Some(pos) => &fully_qualified_name[pos + 1..],
            None => fully_qualified_name,
        }
    }

    /// Determine the [`DataTypeDescription`] for a primitive type size.
    ///
    /// Maps byte sizes to the appropriate Ghidra data type:
    /// - 1 -> Byte
    /// - 2 -> Word
    /// - 4 -> DWord
    /// - 8 -> QWord
    ///
    /// Returns `None` for sizes that don't map to a standard primitive.
    pub fn primitive_type_for_size(size: usize) -> Option<DataTypeDescription> {
        match size {
            1 => Some(DataTypeDescription::Byte),
            2 => Some(DataTypeDescription::Word),
            4 => Some(DataTypeDescription::DWord),
            8 => Some(DataTypeDescription::QWord),
            _ => None,
        }
    }

    /// Create an array [`DataTypeDescription`] with the given element type and count.
    ///
    /// Equivalent to `new ArrayDataType(elementType, count, elementLength)` in Java.
    pub fn array_type(element: DataTypeDescription, count: usize) -> DataTypeDescription {
        DataTypeDescription::Array {
            element: Box::new(element),
            count,
        }
    }

    /// Create a pointer [`DataTypeDescription`] pointing to the given inner type.
    pub fn pointer_to(inner: DataTypeDescription) -> DataTypeDescription {
        DataTypeDescription::PointerTo(Box::new(inner))
    }

    /// Validates that a field name is eligible for automatic conversion.
    ///
    /// In the Java version, fields starting with `_` are excluded, static
    /// fields are excluded, and only private/protected fields are included.
    /// This method checks the naming convention.
    ///
    /// Returns `true` if the field name is valid for automatic conversion.
    pub fn is_valid_field_name(name: &str) -> bool {
        !name.starts_with('_') && !name.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_descriptor_basic() {
        let field = FieldDescriptor::new("e_type", DataTypeDescription::Word);
        assert_eq!(field.name(), "e_type");
        assert_eq!(field.data_type(), &DataTypeDescription::Word);
        assert_eq!(field.size(), Some(2));
        assert_eq!(field.offset(), None);
    }

    #[test]
    fn test_field_descriptor_with_offset() {
        let field = FieldDescriptor::with_offset("e_entry", DataTypeDescription::QWord, 24);
        assert_eq!(field.offset(), Some(24));
        assert_eq!(field.size(), Some(8));
    }

    #[test]
    fn test_field_descriptor_display() {
        let field = FieldDescriptor::new("e_type", DataTypeDescription::Word);
        assert_eq!(field.to_string(), "e_type: word");

        let field_with_ofs = FieldDescriptor::with_offset("e_type", DataTypeDescription::Word, 16);
        assert_eq!(field_with_ofs.to_string(), "[0010] e_type: word");
    }

    #[test]
    fn test_struct_descriptor_new() {
        let desc = StructDescriptor::new("TestStruct");
        assert_eq!(desc.name(), "TestStruct");
        assert_eq!(desc.field_count(), 0);
        assert_eq!(desc.total_size(), Some(0));
    }

    #[test]
    fn test_struct_descriptor_with_size() {
        let desc = StructDescriptor::with_size("PaddedStruct", 64);
        assert_eq!(desc.total_size(), Some(64));
        assert_eq!(desc.explicit_size(), Some(64));
    }

    #[test]
    fn test_struct_descriptor_add_fields() {
        let mut desc = StructDescriptor::new("Elf64_Ehdr");
        desc.add_field(
            "e_ident",
            DataTypeDescription::Array {
                element: Box::new(DataTypeDescription::Byte),
                count: 16,
            },
        );
        desc.add_field("e_type", DataTypeDescription::Word);
        desc.add_field("e_machine", DataTypeDescription::Word);
        desc.add_field("e_version", DataTypeDescription::DWord);
        desc.add_field("e_entry", DataTypeDescription::QWord);

        assert_eq!(desc.field_count(), 5);
        // 16 (e_ident) + 2 (e_type) + 2 (e_machine) + 4 (e_version) + 8 (e_entry) = 32
        assert_eq!(desc.total_size(), Some(32));
    }

    #[test]
    fn test_struct_descriptor_field_lookup() {
        let mut desc = StructDescriptor::new("TestStruct");
        desc.add_field("alpha", DataTypeDescription::Byte);
        desc.add_field("beta", DataTypeDescription::Word);

        let alpha = desc.field_by_name("alpha").unwrap();
        assert_eq!(alpha.data_type(), &DataTypeDescription::Byte);

        let beta = desc.field_at(1).unwrap();
        assert_eq!(beta.name(), "beta");

        assert!(desc.field_by_name("nonexistent").is_none());
    }

    #[test]
    fn test_struct_descriptor_to_data_type() {
        let mut desc = StructDescriptor::new("Simple");
        desc.add_field("x", DataTypeDescription::DWord);
        desc.add_field("y", DataTypeDescription::DWord);

        let dt = desc.to_data_type();
        match dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "Simple");
                assert_eq!(fields.len(), 2);
                assert_eq!(fields[0].0, "x");
                assert_eq!(fields[1].0, "y");
            }
            _ => panic!("Expected Struct variant"),
        }
    }

    #[test]
    fn test_struct_descriptor_display() {
        let mut desc = StructDescriptor::new("Point");
        desc.add_field("x", DataTypeDescription::DWord);
        desc.add_field("y", DataTypeDescription::DWord);

        let display = desc.to_string();
        assert!(display.contains("struct Point"));
        assert!(display.contains("x: dword"));
        assert!(display.contains("y: dword"));
        assert!(display.contains("8 bytes"));
    }

    #[test]
    fn test_struct_descriptor_alignment() {
        let mut desc = StructDescriptor::new("Aligned");
        desc.set_alignment(16);
        assert_eq!(desc.alignment(), Some(16));
    }

    #[test]
    fn test_compute_offsets() {
        let mut desc = StructDescriptor::new("Header");
        desc.add_field("magic", DataTypeDescription::DWord);
        desc.add_field("version", DataTypeDescription::Word);
        desc.add_field("flags", DataTypeDescription::Word);
        desc.add_field("size", DataTypeDescription::QWord);

        assert!(desc.compute_offsets());

        assert_eq!(desc.field_by_name("magic").unwrap().offset(), Some(0));
        assert_eq!(desc.field_by_name("version").unwrap().offset(), Some(4));
        assert_eq!(desc.field_by_name("flags").unwrap().offset(), Some(6));
        assert_eq!(desc.field_by_name("size").unwrap().offset(), Some(8));
    }

    #[test]
    fn test_compute_offsets_with_unknown_size() {
        let mut desc = StructDescriptor::new("Partial");
        desc.add_field("name", DataTypeDescription::String); // unknown size
        desc.add_field("id", DataTypeDescription::DWord);

        assert!(!desc.compute_offsets());
    }

    #[test]
    fn test_parse_name() {
        assert_eq!(
            StructConverterUtil::parse_name("ghidra.app.util.bin.ElfHeader"),
            "ElfHeader"
        );
        assert_eq!(
            StructConverterUtil::parse_name("java.lang.String"),
            "String"
        );
        assert_eq!(
            StructConverterUtil::parse_name("SimpleClass"),
            "SimpleClass"
        );
        assert_eq!(StructConverterUtil::parse_name(""), "");
    }

    #[test]
    fn test_primitive_type_for_size() {
        assert_eq!(
            StructConverterUtil::primitive_type_for_size(1),
            Some(DataTypeDescription::Byte)
        );
        assert_eq!(
            StructConverterUtil::primitive_type_for_size(2),
            Some(DataTypeDescription::Word)
        );
        assert_eq!(
            StructConverterUtil::primitive_type_for_size(4),
            Some(DataTypeDescription::DWord)
        );
        assert_eq!(
            StructConverterUtil::primitive_type_for_size(8),
            Some(DataTypeDescription::QWord)
        );
        assert_eq!(StructConverterUtil::primitive_type_for_size(3), None);
        assert_eq!(StructConverterUtil::primitive_type_for_size(16), None);
    }

    #[test]
    fn test_array_type() {
        let arr = StructConverterUtil::array_type(DataTypeDescription::Byte, 16);
        match arr {
            DataTypeDescription::Array { ref element, count } => {
                assert_eq!(**element, DataTypeDescription::Byte);
                assert_eq!(count, 16);
            }
            _ => panic!("Expected Array variant"),
        }
        assert_eq!(arr.size(), Some(16));
    }

    #[test]
    fn test_pointer_to() {
        let ptr = StructConverterUtil::pointer_to(DataTypeDescription::DWord);
        match ptr {
            DataTypeDescription::PointerTo(inner) => {
                assert_eq!(*inner, DataTypeDescription::DWord);
            }
            _ => panic!("Expected PointerTo variant"),
        }
    }

    #[test]
    fn test_is_valid_field_name() {
        assert!(StructConverterUtil::is_valid_field_name("e_type"));
        assert!(StructConverterUtil::is_valid_field_name("name"));
        assert!(!StructConverterUtil::is_valid_field_name("_hidden"));
        assert!(!StructConverterUtil::is_valid_field_name(""));
    }

    // Test the ReflectableStruct trait
    struct TestElf32Shdr {
        _phantom: (), // excluded by convention
    }

    impl ReflectableStruct for TestElf32Shdr {
        fn struct_name() -> &'static str {
            "Elf32_Shdr"
        }

        fn field_descriptors() -> Vec<FieldDescriptor> {
            vec![
                FieldDescriptor::with_offset("sh_name", DataTypeDescription::DWord, 0),
                FieldDescriptor::with_offset("sh_type", DataTypeDescription::DWord, 4),
                FieldDescriptor::with_offset("sh_flags", DataTypeDescription::DWord, 8),
                FieldDescriptor::with_offset("sh_addr", DataTypeDescription::DWord, 12),
                FieldDescriptor::with_offset("sh_offset", DataTypeDescription::DWord, 16),
                FieldDescriptor::with_offset("sh_size", DataTypeDescription::DWord, 20),
                FieldDescriptor::with_offset("sh_link", DataTypeDescription::DWord, 24),
                FieldDescriptor::with_offset("sh_info", DataTypeDescription::DWord, 28),
                FieldDescriptor::with_offset("sh_addralign", DataTypeDescription::DWord, 32),
                FieldDescriptor::with_offset("sh_entsize", DataTypeDescription::DWord, 36),
            ]
        }
    }

    #[test]
    fn test_reflectable_struct() {
        let desc = StructConverterUtil::from_type::<TestElf32Shdr>();
        assert_eq!(desc.name(), "Elf32_Shdr");
        assert_eq!(desc.field_count(), 10);
        assert_eq!(desc.total_size(), Some(40));
    }

    #[test]
    fn test_from_type_with_offsets() {
        let desc = StructConverterUtil::from_type_with_offsets::<TestElf32Shdr>();
        assert_eq!(desc.field_by_name("sh_offset").unwrap().offset(), Some(16));
        assert_eq!(desc.field_by_name("sh_entsize").unwrap().offset(), Some(36));
    }

    #[test]
    fn test_struct_with_unknown_size_fields() {
        let mut desc = StructDescriptor::new("WithPointer");
        desc.add_field("data", DataTypeDescription::DWord);
        desc.add_field("ptr", DataTypeDescription::Pointer);
        // Pointer size is architecture-dependent, so total_size returns None
        assert_eq!(desc.total_size(), None);
    }
}
