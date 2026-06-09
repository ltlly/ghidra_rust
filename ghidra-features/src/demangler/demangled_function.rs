//! Demangled function -- ported from `DemangledFunction.java`.
//!
//! Extends `DemangledObject` with function-specific metadata:
//! return type, parameters, calling convention, and thunk/override flags.

use crate::demangler::demangled_object::DemangledObject;

/// A demangled function symbol.
///
/// Corresponds to Java's `DemangledFunction`, which extends
/// `DemangledObject` with function-specific fields.
#[derive(Debug, Clone)]
pub struct DemangledFunction {
    /// The base demangled object (name, namespace, modifiers).
    pub base: DemangledObject,
    /// The demangled return-type string.
    return_type: String,
    /// Ordered parameter type strings.
    parameter_types: Vec<String>,
    /// Ordered parameter names (may be empty if not recovered).
    parameter_names: Vec<String>,
    /// Calling convention string (e.g. `"__cdecl"`, `"__stdcall"`).
    calling_convention: String,
    /// Whether this function is a constructor.
    is_constructor: bool,
    /// Whether this function is a destructor.
    is_destructor: bool,
    /// Whether this is a virtual function.
    is_virtual: bool,
    /// Whether this is a pure virtual function.
    is_pure_virtual: bool,
    /// Whether this is a thunk function.
    is_thunk: bool,
    /// Whether this is a static function.
    is_static: bool,
    /// Whether the function has `extern "C"` linkage.
    is_extern_c: bool,
    /// Whether this is an operator overload.
    is_operator: bool,
    /// Whether this is a template instantiation.
    is_template: bool,
    /// Whether a `noexcept` specifier was recovered.
    is_noexcept: bool,
    /// Whether a `throw()` specifier was recovered.
    has_throw_specifier: bool,
    /// The override path (for virtual overrides).
    override_path: String,
}

impl DemangledFunction {
    /// Create a new demangled function from the original mangled name.
    pub fn new(original_mangled: impl Into<String>) -> Self {
        Self {
            base: DemangledObject::new(original_mangled),
            return_type: String::new(),
            parameter_types: Vec::new(),
            parameter_names: Vec::new(),
            calling_convention: String::new(),
            is_constructor: false,
            is_destructor: false,
            is_virtual: false,
            is_pure_virtual: false,
            is_thunk: false,
            is_static: false,
            is_extern_c: false,
            is_operator: false,
            is_template: false,
            is_noexcept: false,
            has_throw_specifier: false,
            override_path: String::new(),
        }
    }

    // -- return_type -------------------------------------------------------

    /// Get the demangled return type.
    pub fn return_type(&self) -> &str {
        &self.return_type
    }

    /// Set the demangled return type.
    pub fn set_return_type(&mut self, ty: impl Into<String>) {
        self.return_type = ty.into();
    }

    // -- parameters --------------------------------------------------------

    /// Get the parameter types.
    pub fn parameter_types(&self) -> &[String] {
        &self.parameter_types
    }

    /// Set the parameter types.
    pub fn set_parameter_types(&mut self, types: Vec<String>) {
        self.parameter_types = types;
    }

    /// Add a single parameter type.
    pub fn add_parameter_type(&mut self, ty: impl Into<String>) {
        self.parameter_types.push(ty.into());
    }

    /// Get the parameter names.
    pub fn parameter_names(&self) -> &[String] {
        &self.parameter_names
    }

    /// Set the parameter names.
    pub fn set_parameter_names(&mut self, names: Vec<String>) {
        self.parameter_names = names;
    }

    /// Add a single parameter name.
    pub fn add_parameter_name(&mut self, name: impl Into<String>) {
        self.parameter_names.push(name.into());
    }

    /// Get the number of parameters.
    pub fn parameter_count(&self) -> usize {
        self.parameter_types.len()
    }

    /// Whether the function takes no parameters (`void`).
    pub fn is_void_param(&self) -> bool {
        self.parameter_types.len() == 1 && self.parameter_types[0] == "void"
    }

    // -- calling_convention ------------------------------------------------

    /// Get the calling convention string.
    pub fn calling_convention(&self) -> &str {
        &self.calling_convention
    }

    /// Set the calling convention string.
    pub fn set_calling_convention(&mut self, cc: impl Into<String>) {
        self.calling_convention = cc.into();
    }

    // -- flags -------------------------------------------------------------

    /// Whether this function is a constructor.
    pub fn is_constructor(&self) -> bool {
        self.is_constructor
    }

    /// Set whether this function is a constructor.
    pub fn set_constructor(&mut self, value: bool) {
        self.is_constructor = value;
    }

    /// Whether this function is a destructor.
    pub fn is_destructor(&self) -> bool {
        self.is_destructor
    }

    /// Set whether this function is a destructor.
    pub fn set_destructor(&mut self, value: bool) {
        self.is_destructor = value;
    }

    /// Whether this is a virtual function.
    pub fn is_virtual(&self) -> bool {
        self.is_virtual
    }

    /// Set whether this is a virtual function.
    pub fn set_virtual(&mut self, value: bool) {
        self.is_virtual = value;
    }

    /// Whether this is a pure virtual function.
    pub fn is_pure_virtual(&self) -> bool {
        self.is_pure_virtual
    }

    /// Set whether this is a pure virtual function.
    pub fn set_pure_virtual(&mut self, value: bool) {
        self.is_pure_virtual = value;
    }

    /// Whether this is a thunk function.
    pub fn is_thunk(&self) -> bool {
        self.is_thunk
    }

    /// Set whether this is a thunk function.
    pub fn set_thunk(&mut self, value: bool) {
        self.is_thunk = value;
    }

    /// Whether this is a static function.
    pub fn is_static(&self) -> bool {
        self.is_static
    }

    /// Set whether this is a static function.
    pub fn set_static(&mut self, value: bool) {
        self.is_static = value;
    }

    /// Whether the function has `extern "C"` linkage.
    pub fn is_extern_c(&self) -> bool {
        self.is_extern_c
    }

    /// Set whether the function has `extern "C"` linkage.
    pub fn set_extern_c(&mut self, value: bool) {
        self.is_extern_c = value;
    }

    /// Whether this is an operator overload.
    pub fn is_operator(&self) -> bool {
        self.is_operator
    }

    /// Set whether this is an operator overload.
    pub fn set_operator(&mut self, value: bool) {
        self.is_operator = value;
    }

    /// Whether this is a template instantiation.
    pub fn is_template(&self) -> bool {
        self.is_template
    }

    /// Set whether this is a template instantiation.
    pub fn set_template(&mut self, value: bool) {
        self.is_template = value;
    }

    /// Whether a `noexcept` specifier was recovered.
    pub fn is_noexcept(&self) -> bool {
        self.is_noexcept
    }

    /// Set the `noexcept` flag.
    pub fn set_noexcept(&mut self, value: bool) {
        self.is_noexcept = value;
    }

    /// Whether a `throw()` specifier was recovered.
    pub fn has_throw_specifier(&self) -> bool {
        self.has_throw_specifier
    }

    /// Set the `throw()` specifier flag.
    pub fn set_throw_specifier(&mut self, value: bool) {
        self.has_throw_specifier = value;
    }

    /// Get the override path.
    pub fn override_path(&self) -> &str {
        &self.override_path
    }

    /// Set the override path.
    pub fn set_override_path(&mut self, path: impl Into<String>) {
        self.override_path = path.into();
    }

    // -- signature ---------------------------------------------------------

    /// Build a human-readable signature string.
    ///
    /// Format: `return_type calling_conv name(param_types)`
    pub fn signature_string(&self) -> String {
        let mut sig = String::new();

        // Return type
        if !self.return_type.is_empty() {
            sig.push_str(&self.return_type);
            sig.push(' ');
        }

        // Calling convention
        if !self.calling_convention.is_empty() {
            sig.push_str(&self.calling_convention);
            sig.push(' ');
        }

        // Name
        sig.push_str(&self.base.qualified_name());

        // Parameters
        sig.push('(');
        if self.is_void_param() {
            sig.push_str("void");
        } else {
            for (i, param) in self.parameter_types.iter().enumerate() {
                if i > 0 {
                    sig.push_str(", ");
                }
                sig.push_str(param);
                if i < self.parameter_names.len() && !self.parameter_names[i].is_empty() {
                    sig.push(' ');
                    sig.push_str(&self.parameter_names[i]);
                }
            }
        }
        sig.push(')');

        // Qualifiers
        if self.is_const_qualified() {
            sig.push_str(" const");
        }
        if self.is_noexcept {
            sig.push_str(" noexcept");
        }
        if self.has_throw_specifier {
            sig.push_str(" throw()");
        }
        if self.is_pure_virtual {
            sig.push_str(" = 0");
        }

        sig
    }

    // -- helper for const (backed by base storage_modifier) ----------------

    /// Whether the function is `const`-qualified.
    ///
    /// Uses `storage_modifier` to hold the const marker.
    pub fn is_const_qualified(&self) -> bool {
        self.base.storage_modifier().contains("const")
    }

    /// Set the `const` qualifier.
    pub fn set_const_qualified(&mut self, value: bool) {
        if value {
            self.base.set_storage_modifier("const");
        } else {
            let current = self.base.storage_modifier().replace("const", "").trim().to_string();
            self.base.set_storage_modifier(current);
        }
    }
}

impl std::fmt::Display for DemangledFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.signature_string())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_function() {
        let f = DemangledFunction::new("?foo@@YAXXZ");
        assert_eq!(f.base.original_mangled(), "?foo@@YAXXZ");
        assert!(f.return_type().is_empty());
        assert_eq!(f.parameter_count(), 0);
        assert!(!f.is_constructor());
        assert!(!f.is_destructor());
    }

    #[test]
    fn test_function_with_return_type() {
        let mut f = DemangledFunction::new("_Z3foov");
        f.base.set_name("foo");
        f.set_return_type("int");
        f.add_parameter_type("void");
        assert_eq!(f.return_type(), "int");
        assert!(f.is_void_param());
    }

    #[test]
    fn test_function_with_params() {
        let mut f = DemangledFunction::new("_Z3fooii");
        f.base.set_name("foo");
        f.set_return_type("void");
        f.set_parameter_types(vec!["int".into(), "float".into()]);
        f.set_parameter_names(vec!["x".into(), "y".into()]);
        assert_eq!(f.parameter_count(), 2);
        assert!(!f.is_void_param());
    }

    #[test]
    fn test_signature_string_simple() {
        let mut f = DemangledFunction::new("_Z3foov");
        f.base.set_name("foo");
        f.set_return_type("void");
        f.add_parameter_type("void");
        assert_eq!(f.signature_string(), "void foo(void)");
    }

    #[test]
    fn test_signature_string_with_cc() {
        let mut f = DemangledFunction::new("?foo@@YAXXZ");
        f.base.set_name("foo");
        f.set_return_type("void");
        f.set_calling_convention("__cdecl");
        f.add_parameter_type("void");
        assert_eq!(f.signature_string(), "void __cdecl foo(void)");
    }

    #[test]
    fn test_signature_string_with_params() {
        let mut f = DemangledFunction::new("_Z3fooi");
        f.base.set_name("foo");
        f.set_return_type("int");
        f.add_parameter_type("int");
        f.add_parameter_name("x");
        let sig = f.signature_string();
        assert!(sig.contains("int x"));
    }

    #[test]
    fn test_constructor_destructor_flags() {
        let mut f = DemangledFunction::new("_ZN3FooC1Ev");
        f.set_constructor(true);
        assert!(f.is_constructor());
        f.set_destructor(true);
        assert!(f.is_destructor());
    }

    #[test]
    fn test_virtual_flags() {
        let mut f = DemangledFunction::new("_ZN3Foo3barEv");
        f.set_virtual(true);
        f.set_pure_virtual(true);
        assert!(f.is_virtual());
        assert!(f.is_pure_virtual());
    }

    #[test]
    fn test_static_flag() {
        let mut f = DemangledFunction::new("_ZN3Foo3barEv");
        f.set_static(true);
        assert!(f.is_static());
    }

    #[test]
    fn test_display() {
        let mut f = DemangledFunction::new("_Z3foov");
        f.base.set_name("foo");
        f.set_return_type("void");
        f.add_parameter_type("void");
        assert_eq!(format!("{}", f), "void foo(void)");
    }
}
