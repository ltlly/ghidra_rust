//! Demangled data type -- ported from `DemangledDataType.java`.
//!
//! Extends `DemangledObject` with data-type-specific metadata:
//! category, size, signedness, and type qualifiers.

use crate::demangler::demangled_object::DemangledObject;

/// Classification of demangled data types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataTypeCategory {
    /// A primitive / built-in type (`int`, `float`, `bool`, etc.).
    Primitive,
    /// A pointer type (`T*`).
    Pointer,
    /// A reference type (`T&` or `T&&`).
    Reference,
    /// An array type (`T[N]`).
    Array,
    /// A struct / class / union.
    Structure,
    /// An `enum` or `enum class`.
    Enum,
    /// A function pointer / function type.
    FunctionPointer,
    /// A `typedef` or type alias.
    Typedef,
    /// A template instantiation.
    Template,
    /// A `void` type.
    Void,
    /// An unknown or unresolvable type.
    Unknown,
}

impl DataTypeCategory {
    /// Human-readable name for the category.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Primitive => "primitive",
            Self::Pointer => "pointer",
            Self::Reference => "reference",
            Self::Array => "array",
            Self::Structure => "structure",
            Self::Enum => "enum",
            Self::FunctionPointer => "function_pointer",
            Self::Typedef => "typedef",
            Self::Template => "template",
            Self::Void => "void",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for DataTypeCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A demangled data type symbol.
///
/// Corresponds to Java's `DemangledDataType`, which extends
/// `DemangledObject` with data-type-specific fields.
#[derive(Debug, Clone)]
pub struct DemangledDataType {
    /// The base demangled object (name, namespace, modifiers).
    pub base: DemangledObject,
    /// The data type category.
    category: DataTypeCategory,
    /// The demangled type name (e.g. `"int"`, `"std::vector<int>"`).
    type_name: String,
    /// The size in bytes, if known.
    size: Option<u64>,
    /// Whether this type is `signed`.
    is_signed: bool,
    /// Whether this type is `unsigned`.
    is_unsigned: bool,
    /// Whether this type is `const`.
    is_const: bool,
    /// Whether this type is `volatile`.
    is_volatile: bool,
    /// Pointer depth (0 = not a pointer, 1 = `T*`, 2 = `T**`, ...).
    pointer_depth: u32,
    /// Whether the pointer is `const`.
    pointer_is_const: bool,
    /// Whether this is a reference (`T&`).
    is_reference: bool,
    /// Whether this is an rvalue reference (`T&&`).
    is_rvalue_reference: bool,
    /// The base/pointee type name (for pointer/reference types).
    base_type: Option<String>,
    /// Array dimensions, if this is an array type.
    array_dimensions: Vec<u64>,
    /// Template arguments as strings.
    template_arguments: Vec<String>,
    /// Whether this is a packed type (`__attribute__((packed))`).
    is_packed: bool,
    /// The alignment in bytes, if specified.
    alignment: Option<u64>,
}

impl DemangledDataType {
    /// Create a new demangled data type from the original mangled name.
    pub fn new(original_mangled: impl Into<String>) -> Self {
        Self {
            base: DemangledObject::new(original_mangled),
            category: DataTypeCategory::Unknown,
            type_name: String::new(),
            size: None,
            is_signed: false,
            is_unsigned: false,
            is_const: false,
            is_volatile: false,
            pointer_depth: 0,
            pointer_is_const: false,
            is_reference: false,
            is_rvalue_reference: false,
            base_type: None,
            array_dimensions: Vec::new(),
            template_arguments: Vec::new(),
            is_packed: false,
            alignment: None,
        }
    }

    // -- category ----------------------------------------------------------

    /// Get the data type category.
    pub fn category(&self) -> DataTypeCategory {
        self.category
    }

    /// Set the data type category.
    pub fn set_category(&mut self, category: DataTypeCategory) {
        self.category = category;
    }

    // -- type_name ---------------------------------------------------------

    /// Get the demangled type name.
    pub fn type_name(&self) -> &str {
        &self.type_name
    }

    /// Set the demangled type name.
    pub fn set_type_name(&mut self, name: impl Into<String>) {
        self.type_name = name.into();
    }

    // -- size --------------------------------------------------------------

    /// Get the size in bytes, if known.
    pub fn size(&self) -> Option<u64> {
        self.size
    }

    /// Set the size in bytes.
    pub fn set_size(&mut self, size: u64) {
        self.size = Some(size);
    }

    // -- signedness --------------------------------------------------------

    /// Whether this type is `signed`.
    pub fn is_signed(&self) -> bool {
        self.is_signed
    }

    /// Set the signed flag.
    pub fn set_signed(&mut self, value: bool) {
        self.is_signed = value;
        if value {
            self.is_unsigned = false;
        }
    }

    /// Whether this type is `unsigned`.
    pub fn is_unsigned(&self) -> bool {
        self.is_unsigned
    }

    /// Set the unsigned flag.
    pub fn set_unsigned(&mut self, value: bool) {
        self.is_unsigned = value;
        if value {
            self.is_signed = false;
        }
    }

    // -- qualifiers --------------------------------------------------------

    /// Whether this type is `const`.
    pub fn is_const(&self) -> bool {
        self.is_const
    }

    /// Set the `const` flag.
    pub fn set_const(&mut self, value: bool) {
        self.is_const = value;
    }

    /// Whether this type is `volatile`.
    pub fn is_volatile(&self) -> bool {
        self.is_volatile
    }

    /// Set the `volatile` flag.
    pub fn set_volatile(&mut self, value: bool) {
        self.is_volatile = value;
    }

    // -- pointer / reference -----------------------------------------------

    /// Get the pointer depth (0 = not a pointer, 1 = `T*`, etc.).
    pub fn pointer_depth(&self) -> u32 {
        self.pointer_depth
    }

    /// Set the pointer depth.
    pub fn set_pointer_depth(&mut self, depth: u32) {
        self.pointer_depth = depth;
    }

    /// Whether the pointer is `const` (i.e. `T* const`).
    pub fn pointer_is_const(&self) -> bool {
        self.pointer_is_const
    }

    /// Set whether the pointer is `const`.
    pub fn set_pointer_is_const(&mut self, value: bool) {
        self.pointer_is_const = value;
    }

    /// Whether this type is an lvalue reference (`T&`).
    pub fn is_reference(&self) -> bool {
        self.is_reference
    }

    /// Set the lvalue reference flag.
    pub fn set_reference(&mut self, value: bool) {
        self.is_reference = value;
    }

    /// Whether this type is an rvalue reference (`T&&`).
    pub fn is_rvalue_reference(&self) -> bool {
        self.is_rvalue_reference
    }

    /// Set the rvalue reference flag.
    pub fn set_rvalue_reference(&mut self, value: bool) {
        self.is_rvalue_reference = value;
    }

    /// Whether this is a pointer type (any depth > 0).
    pub fn is_pointer(&self) -> bool {
        self.pointer_depth > 0
    }

    /// Get the base/pointee type name.
    pub fn base_type(&self) -> Option<&str> {
        self.base_type.as_deref()
    }

    /// Set the base/pointee type name.
    pub fn set_base_type(&mut self, ty: impl Into<String>) {
        self.base_type = Some(ty.into());
    }

    // -- array -------------------------------------------------------------

    /// Get the array dimensions.
    pub fn array_dimensions(&self) -> &[u64] {
        &self.array_dimensions
    }

    /// Set the array dimensions.
    pub fn set_array_dimensions(&mut self, dims: Vec<u64>) {
        self.array_dimensions = dims;
    }

    /// Add an array dimension.
    pub fn add_array_dimension(&mut self, size: u64) {
        self.array_dimensions.push(size);
    }

    /// Whether this is an array type.
    pub fn is_array(&self) -> bool {
        !self.array_dimensions.is_empty()
    }

    // -- template ----------------------------------------------------------

    /// Get the template arguments.
    pub fn template_arguments(&self) -> &[String] {
        &self.template_arguments
    }

    /// Set the template arguments.
    pub fn set_template_arguments(&mut self, args: Vec<String>) {
        self.template_arguments = args;
    }

    /// Add a single template argument.
    pub fn add_template_argument(&mut self, arg: impl Into<String>) {
        self.template_arguments.push(arg.into());
    }

    // -- packed / alignment ------------------------------------------------

    /// Whether this is a packed type.
    pub fn is_packed(&self) -> bool {
        self.is_packed
    }

    /// Set the packed flag.
    pub fn set_packed(&mut self, value: bool) {
        self.is_packed = value;
    }

    /// Get the alignment in bytes.
    pub fn alignment(&self) -> Option<u64> {
        self.alignment
    }

    /// Set the alignment in bytes.
    pub fn set_alignment(&mut self, align: u64) {
        self.alignment = Some(align);
    }

    // -- type string -------------------------------------------------------

    /// Build a human-readable type declaration string.
    ///
    /// Includes qualifiers, the type name, pointer decorators,
    /// reference markers, and array dimensions.
    pub fn type_declaration_string(&self) -> String {
        let mut decl = String::new();

        // Top-level qualifiers
        if self.is_const {
            decl.push_str("const ");
        }
        if self.is_volatile {
            decl.push_str("volatile ");
        }

        // Signed / unsigned
        if self.is_signed {
            decl.push_str("signed ");
        } else if self.is_unsigned {
            decl.push_str("unsigned ");
        }

        // Packed annotation
        if self.is_packed {
            decl.push_str("/* packed */ ");
        }

        // Type name
        let name = if !self.type_name.is_empty() {
            &self.type_name
        } else {
            self.base.name()
        };
        decl.push_str(name);

        // Template arguments
        if !self.template_arguments.is_empty() {
            decl.push('<');
            for (i, arg) in self.template_arguments.iter().enumerate() {
                if i > 0 {
                    decl.push_str(", ");
                }
                decl.push_str(arg);
            }
            decl.push('>');
        }

        // Pointer / reference decorators
        for _ in 0..self.pointer_depth {
            decl.push('*');
            if self.pointer_is_const {
                decl.push_str(" const");
            }
        }
        if self.is_reference {
            decl.push('&');
        }
        if self.is_rvalue_reference {
            decl.push_str("&&");
        }

        // Array dimensions
        for &dim in &self.array_dimensions {
            decl.push('[');
            if dim > 0 {
                decl.push_str(&dim.to_string());
            }
            decl.push(']');
        }

        decl
    }
}

impl std::fmt::Display for DemangledDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.type_declaration_string())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_data_type() {
        let dt = DemangledDataType::new("?x@@3HA");
        assert_eq!(dt.base.original_mangled(), "?x@@3HA");
        assert_eq!(dt.category(), DataTypeCategory::Unknown);
        assert!(dt.type_name().is_empty());
    }

    #[test]
    fn test_primitive_type() {
        let mut dt = DemangledDataType::new("_Z1xi");
        dt.set_type_name("int");
        dt.set_category(DataTypeCategory::Primitive);
        dt.set_size(4);
        assert_eq!(dt.type_name(), "int");
        assert_eq!(dt.category(), DataTypeCategory::Primitive);
        assert_eq!(dt.size(), Some(4));
    }

    #[test]
    fn test_signed_unsigned() {
        let mut dt = DemangledDataType::new("_Z1xi");
        dt.set_type_name("int");
        dt.set_signed(true);
        assert!(dt.is_signed());
        assert!(!dt.is_unsigned());

        dt.set_unsigned(true);
        assert!(dt.is_unsigned());
        assert!(!dt.is_signed());
    }

    #[test]
    fn test_pointer_type() {
        let mut dt = DemangledDataType::new("_Z1xi");
        dt.set_type_name("int");
        dt.set_pointer_depth(1);
        dt.set_category(DataTypeCategory::Pointer);
        assert!(dt.is_pointer());
        assert_eq!(dt.type_declaration_string(), "int*");
    }

    #[test]
    fn test_double_pointer() {
        let mut dt = DemangledDataType::new("_Z1xi");
        dt.set_type_name("int");
        dt.set_pointer_depth(2);
        assert_eq!(dt.type_declaration_string(), "int**");
    }

    #[test]
    fn test_pointer_const() {
        let mut dt = DemangledDataType::new("_Z1xi");
        dt.set_type_name("int");
        dt.set_pointer_depth(1);
        dt.set_pointer_is_const(true);
        assert_eq!(dt.type_declaration_string(), "int* const");
    }

    #[test]
    fn test_reference_type() {
        let mut dt = DemangledDataType::new("_Z1xi");
        dt.set_type_name("int");
        dt.set_reference(true);
        dt.set_category(DataTypeCategory::Reference);
        assert_eq!(dt.type_declaration_string(), "int&");
    }

    #[test]
    fn test_rvalue_reference() {
        let mut dt = DemangledDataType::new("_Z1xi");
        dt.set_type_name("int");
        dt.set_rvalue_reference(true);
        assert_eq!(dt.type_declaration_string(), "int&&");
    }

    #[test]
    fn test_const_type() {
        let mut dt = DemangledDataType::new("_Z1xi");
        dt.set_type_name("int");
        dt.set_const(true);
        assert_eq!(dt.type_declaration_string(), "const int");
    }

    #[test]
    fn test_unsigned_const() {
        let mut dt = DemangledDataType::new("_Z1xi");
        dt.set_type_name("int");
        dt.set_unsigned(true);
        dt.set_const(true);
        let s = dt.type_declaration_string();
        assert!(s.contains("const"));
        assert!(s.contains("unsigned"));
        assert!(s.contains("int"));
    }

    #[test]
    fn test_array_type() {
        let mut dt = DemangledDataType::new("_Z1ai");
        dt.set_type_name("int");
        dt.add_array_dimension(10);
        dt.set_category(DataTypeCategory::Array);
        assert!(dt.is_array());
        assert_eq!(dt.type_declaration_string(), "int[10]");
    }

    #[test]
    fn test_multidimensional_array() {
        let mut dt = DemangledDataType::new("_Z1ai");
        dt.set_type_name("int");
        dt.set_array_dimensions(vec![3, 4, 5]);
        assert_eq!(dt.type_declaration_string(), "int[3][4][5]");
    }

    #[test]
    fn test_template_type() {
        let mut dt = DemangledDataType::new("_ZN3vecE");
        dt.set_type_name("vector");
        dt.add_template_argument("int");
        dt.set_category(DataTypeCategory::Template);
        assert_eq!(dt.type_declaration_string(), "vector<int>");
    }

    #[test]
    fn test_packed_type() {
        let mut dt = DemangledDataType::new("_ZN1AE");
        dt.set_type_name("A");
        dt.set_packed(true);
        let s = dt.type_declaration_string();
        assert!(s.contains("packed"));
        assert!(s.contains("A"));
    }

    #[test]
    fn test_alignment() {
        let mut dt = DemangledDataType::new("_ZN1AE");
        dt.set_alignment(16);
        assert_eq!(dt.alignment(), Some(16));
    }

    #[test]
    fn test_category_display() {
        assert_eq!(format!("{}", DataTypeCategory::Primitive), "primitive");
        assert_eq!(format!("{}", DataTypeCategory::Structure), "structure");
    }

    #[test]
    fn test_display() {
        let mut dt = DemangledDataType::new("_Z1xi");
        dt.set_type_name("int");
        assert_eq!(format!("{}", dt), "int");
    }

    #[test]
    fn test_pointer_to_const() {
        let mut dt = DemangledDataType::new("_Z1xi");
        dt.set_type_name("int");
        dt.set_const(true);
        dt.set_pointer_depth(1);
        let s = dt.type_declaration_string();
        assert!(s.contains("const"));
        assert!(s.contains("*"));
    }
}
