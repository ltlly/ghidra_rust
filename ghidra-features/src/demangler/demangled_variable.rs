//! Demangled variable -- ported from `DemangledVariable.java`.
//!
//! Extends `DemangledObject` with variable-specific metadata:
//! data type, storage class, and mutability.

use crate::demangler::demangled_object::DemangledObject;

/// A demangled variable (global, static, or class member) symbol.
///
/// Corresponds to Java's `DemangledVariable`, which extends
/// `DemangledObject` with variable-specific fields.
#[derive(Debug, Clone)]
pub struct DemangledVariable {
    /// The base demangled object (name, namespace, modifiers).
    pub base: DemangledObject,
    /// The demangled data-type string.
    data_type: String,
    /// Whether the variable is `const`.
    is_const: bool,
    /// Whether the variable is `volatile`.
    is_volatile: bool,
    /// Whether the variable is `static`.
    is_static: bool,
    /// Whether the variable is `extern`.
    is_extern: bool,
    /// Whether the variable is `thread_local`.
    is_thread_local: bool,
    /// Whether the variable is `mutable`.
    is_mutable: bool,
    /// The array dimensions, if this is an array variable.
    array_dimensions: Vec<u64>,
    /// Bit-field width, if this is a bit-field member.
    bitfield_width: Option<u32>,
    /// Initializer / default value string, if recoverable.
    initial_value: Option<String>,
}

impl DemangledVariable {
    /// Create a new demangled variable from the original mangled name.
    pub fn new(original_mangled: impl Into<String>) -> Self {
        Self {
            base: DemangledObject::new(original_mangled),
            data_type: String::new(),
            is_const: false,
            is_volatile: false,
            is_static: false,
            is_extern: false,
            is_thread_local: false,
            is_mutable: false,
            array_dimensions: Vec::new(),
            bitfield_width: None,
            initial_value: None,
        }
    }

    // -- data_type ---------------------------------------------------------

    /// Get the demangled data-type string.
    pub fn data_type(&self) -> &str {
        &self.data_type
    }

    /// Set the demangled data-type string.
    pub fn set_data_type(&mut self, ty: impl Into<String>) {
        self.data_type = ty.into();
    }

    // -- qualifiers --------------------------------------------------------

    /// Whether the variable is `const`.
    pub fn is_const(&self) -> bool {
        self.is_const
    }

    /// Set the `const` flag.
    pub fn set_const(&mut self, value: bool) {
        self.is_const = value;
    }

    /// Whether the variable is `volatile`.
    pub fn is_volatile(&self) -> bool {
        self.is_volatile
    }

    /// Set the `volatile` flag.
    pub fn set_volatile(&mut self, value: bool) {
        self.is_volatile = value;
    }

    /// Whether the variable is `static`.
    pub fn is_static(&self) -> bool {
        self.is_static
    }

    /// Set the `static` flag.
    pub fn set_static(&mut self, value: bool) {
        self.is_static = value;
    }

    /// Whether the variable is `extern`.
    pub fn is_extern(&self) -> bool {
        self.is_extern
    }

    /// Set the `extern` flag.
    pub fn set_extern(&mut self, value: bool) {
        self.is_extern = value;
    }

    /// Whether the variable is `thread_local`.
    pub fn is_thread_local(&self) -> bool {
        self.is_thread_local
    }

    /// Set the `thread_local` flag.
    pub fn set_thread_local(&mut self, value: bool) {
        self.is_thread_local = value;
    }

    /// Whether the variable is `mutable`.
    pub fn is_mutable(&self) -> bool {
        self.is_mutable
    }

    /// Set the `mutable` flag.
    pub fn set_mutable(&mut self, value: bool) {
        self.is_mutable = value;
    }

    // -- array / bitfield --------------------------------------------------

    /// Get the array dimensions (empty if not an array).
    pub fn array_dimensions(&self) -> &[u64] {
        &self.array_dimensions
    }

    /// Set the array dimensions.
    pub fn set_array_dimensions(&mut self, dims: Vec<u64>) {
        self.array_dimensions = dims;
    }

    /// Add one array dimension.
    pub fn add_array_dimension(&mut self, size: u64) {
        self.array_dimensions.push(size);
    }

    /// Whether this variable is an array type.
    pub fn is_array(&self) -> bool {
        !self.array_dimensions.is_empty()
    }

    /// Get the bit-field width, if this is a bit-field member.
    pub fn bitfield_width(&self) -> Option<u32> {
        self.bitfield_width
    }

    /// Set the bit-field width.
    pub fn set_bitfield_width(&mut self, width: u32) {
        self.bitfield_width = Some(width);
    }

    /// Whether this is a bit-field member.
    pub fn is_bitfield(&self) -> bool {
        self.bitfield_width.is_some()
    }

    // -- initial_value -----------------------------------------------------

    /// Get the initial value string, if available.
    pub fn initial_value(&self) -> Option<&str> {
        self.initial_value.as_deref()
    }

    /// Set the initial value string.
    pub fn set_initial_value(&mut self, value: impl Into<String>) {
        self.initial_value = Some(value.into());
    }

    // -- declaration string ------------------------------------------------

    /// Build a human-readable declaration string.
    ///
    /// Format: `[qualifiers] type name[array_dims] [: bitfield_width]`
    pub fn declaration_string(&self) -> String {
        let mut decl = String::new();

        // Qualifiers
        if self.is_const {
            decl.push_str("const ");
        }
        if self.is_volatile {
            decl.push_str("volatile ");
        }
        if self.is_static {
            decl.push_str("static ");
        }
        if self.is_extern {
            decl.push_str("extern ");
        }
        if self.is_thread_local {
            decl.push_str("thread_local ");
        }
        if self.is_mutable {
            decl.push_str("mutable ");
        }

        // Type
        if !self.data_type.is_empty() {
            decl.push_str(&self.data_type);
            decl.push(' ');
        }

        // Name
        decl.push_str(&self.base.qualified_name());

        // Array dimensions
        for &dim in &self.array_dimensions {
            decl.push('[');
            if dim > 0 {
                decl.push_str(&dim.to_string());
            }
            decl.push(']');
        }

        // Bit-field
        if let Some(width) = self.bitfield_width {
            decl.push_str(&format!(" : {}", width));
        }

        decl
    }
}

impl std::fmt::Display for DemangledVariable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.declaration_string())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_variable() {
        let v = DemangledVariable::new("?g@@3HA");
        assert_eq!(v.base.original_mangled(), "?g@@3HA");
        assert!(v.data_type().is_empty());
        assert!(!v.is_const());
        assert!(!v.is_static());
    }

    #[test]
    fn test_variable_with_type() {
        let mut v = DemangledVariable::new("_Z1gi");
        v.base.set_name("g");
        v.set_data_type("int");
        assert_eq!(v.data_type(), "int");
    }

    #[test]
    fn test_qualifiers() {
        let mut v = DemangledVariable::new("_ZL1x");
        v.set_const(true);
        v.set_static(true);
        assert!(v.is_const());
        assert!(v.is_static());
        assert!(!v.is_volatile());
    }

    #[test]
    fn test_volatile_and_thread_local() {
        let mut v = DemangledVariable::new("_Z1xv");
        v.set_volatile(true);
        v.set_thread_local(true);
        assert!(v.is_volatile());
        assert!(v.is_thread_local());
    }

    #[test]
    fn test_array_variable() {
        let mut v = DemangledVariable::new("_Z1ai");
        v.base.set_name("a");
        v.set_data_type("int");
        v.set_array_dimensions(vec![10, 20]);
        assert!(v.is_array());
        assert_eq!(v.array_dimensions(), &[10, 20]);
    }

    #[test]
    fn test_add_array_dimension() {
        let mut v = DemangledVariable::new("_Z1a");
        v.add_array_dimension(5);
        v.add_array_dimension(3);
        assert!(v.is_array());
        assert_eq!(v.array_dimensions().len(), 2);
    }

    #[test]
    fn test_bitfield() {
        let mut v = DemangledVariable::new("_ZN3Foo1xE");
        v.base.set_name("x");
        v.set_data_type("unsigned int");
        v.set_bitfield_width(4);
        assert!(v.is_bitfield());
        assert_eq!(v.bitfield_width(), Some(4));
    }

    #[test]
    fn test_initial_value() {
        let mut v = DemangledVariable::new("_Z1xe");
        v.set_initial_value("42");
        assert_eq!(v.initial_value(), Some("42"));
    }

    #[test]
    fn test_declaration_string_simple() {
        let mut v = DemangledVariable::new("_Z1xi");
        v.base.set_name("x");
        v.set_data_type("int");
        assert_eq!(v.declaration_string(), "int x");
    }

    #[test]
    fn test_declaration_string_const_static() {
        let mut v = DemangledVariable::new("_ZN3Foo1xE");
        v.base.set_name("x");
        v.set_data_type("int");
        v.set_const(true);
        v.set_static(true);
        let decl = v.declaration_string();
        assert!(decl.contains("const"));
        assert!(decl.contains("static"));
        assert!(decl.contains("int"));
        assert!(decl.contains("x"));
    }

    #[test]
    fn test_declaration_string_array() {
        let mut v = DemangledVariable::new("_Z1ai");
        v.base.set_name("a");
        v.set_data_type("int");
        v.add_array_dimension(10);
        assert_eq!(v.declaration_string(), "int a[10]");
    }

    #[test]
    fn test_declaration_string_bitfield() {
        let mut v = DemangledVariable::new("_ZN3Foo1xE");
        v.base.set_name("x");
        v.set_data_type("unsigned int");
        v.set_bitfield_width(4);
        assert_eq!(v.declaration_string(), "unsigned int x : 4");
    }

    #[test]
    fn test_display() {
        let mut v = DemangledVariable::new("_Z1xi");
        v.base.set_name("x");
        v.set_data_type("int");
        assert_eq!(format!("{}", v), "int x");
    }
}
