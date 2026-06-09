//! Base demangled object -- ported from `DemangledObject.java`.
//!
//! Represents the common fields shared by all demangled symbols:
//! functions, variables, and data types.

use std::fmt;

/// The original mangled name is required; all other fields are optional
/// and populated during demangling.
///
/// This corresponds to Java's `DemangledObject`, which is the abstract
/// base class for `DemangledFunction`, `DemangledVariable`, and
/// `DemangledDataType`.
#[derive(Debug, Clone)]
pub struct DemangledObject {
    /// The original mangled symbol name.
    original_mangled: String,
    /// The fully-qualified demangled name (e.g. `"std::vector<int>::push_back"`).
    demangled_name: String,
    /// The simple (unqualified) name portion.
    name: String,
    /// Namespace / class path segments (outermost first).
    namespace: Vec<String>,
    /// Whether the symbol was successfully demangled.
    is_demangled: bool,
    /// Access specifier string (e.g. `"public"`, `"private"`).
    access_modifier: String,
    /// Storage / linkage modifier (e.g. `"static"`, `"extern"`).
    storage_modifier: String,
    /// Optional comment or annotation.
    comment: String,
    /// Overriding or special flags as a free-form string.
    special_prefix: String,
}

impl DemangledObject {
    /// Create a new demangled object with the given original mangled name.
    pub fn new(original_mangled: impl Into<String>) -> Self {
        Self {
            original_mangled: original_mangled.into(),
            demangled_name: String::new(),
            name: String::new(),
            namespace: Vec::new(),
            is_demangled: false,
            access_modifier: String::new(),
            storage_modifier: String::new(),
            comment: String::new(),
            special_prefix: String::new(),
        }
    }

    // -- original_mangled --------------------------------------------------

    /// Get the original mangled symbol name.
    pub fn original_mangled(&self) -> &str {
        &self.original_mangled
    }

    // -- demangled_name ----------------------------------------------------

    /// Get the fully-qualified demangled name.
    pub fn demangled_name(&self) -> &str {
        &self.demangled_name
    }

    /// Set the fully-qualified demangled name.
    pub fn set_demangled_name(&mut self, name: impl Into<String>) {
        self.demangled_name = name.into();
        self.is_demangled = true;
    }

    // -- name --------------------------------------------------------------

    /// Get the simple (unqualified) name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the simple (unqualified) name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    // -- namespace ---------------------------------------------------------

    /// Get the namespace/class path segments.
    pub fn namespace(&self) -> &[String] {
        &self.namespace
    }

    /// Set the namespace/class path segments.
    pub fn set_namespace(&mut self, ns: Vec<String>) {
        self.namespace = ns;
    }

    /// Get the fully-qualified name including namespace.
    ///
    /// If a namespace is present the result is `"ns::name"`, otherwise
    /// just the name.
    pub fn qualified_name(&self) -> String {
        if self.namespace.is_empty() {
            self.name.clone()
        } else {
            format!("{}::{}", self.namespace.join("::"), self.name)
        }
    }

    // -- is_demangled ------------------------------------------------------

    /// Whether the symbol was successfully demangled.
    pub fn is_demangled(&self) -> bool {
        self.is_demangled
    }

    /// Mark the object as successfully (or unsuccessfully) demangled.
    pub fn set_demangled(&mut self, value: bool) {
        self.is_demangled = value;
    }

    // -- access_modifier ---------------------------------------------------

    /// Get the access specifier (e.g. `"public"`, `"private"`).
    pub fn access_modifier(&self) -> &str {
        &self.access_modifier
    }

    /// Set the access specifier.
    pub fn set_access_modifier(&mut self, modifier: impl Into<String>) {
        self.access_modifier = modifier.into();
    }

    // -- storage_modifier --------------------------------------------------

    /// Get the storage/linkage modifier (e.g. `"static"`, `"extern"`).
    pub fn storage_modifier(&self) -> &str {
        &self.storage_modifier
    }

    /// Set the storage/linkage modifier.
    pub fn set_storage_modifier(&mut self, modifier: impl Into<String>) {
        self.storage_modifier = modifier.into();
    }

    // -- comment -----------------------------------------------------------

    /// Get the optional comment.
    pub fn comment(&self) -> &str {
        &self.comment
    }

    /// Set the optional comment.
    pub fn set_comment(&mut self, comment: impl Into<String>) {
        self.comment = comment.into();
    }

    // -- special_prefix ----------------------------------------------------

    /// Get the special prefix.
    pub fn special_prefix(&self) -> &str {
        &self.special_prefix
    }

    /// Set the special prefix.
    pub fn set_special_prefix(&mut self, prefix: impl Into<String>) {
        self.special_prefix = prefix.into();
    }

    // -- convenience -------------------------------------------------------

    /// Build a default `demangled_name` from namespace + name.
    pub fn build_demangled_name(&mut self) {
        self.demangled_name = self.qualified_name();
        self.is_demangled = true;
    }
}

impl fmt::Display for DemangledObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_demangled && !self.demangled_name.is_empty() {
            write!(f, "{}", self.demangled_name)
        } else {
            write!(f, "{}", self.original_mangled)
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_object() {
        let obj = DemangledObject::new("?foo@@YAXXZ");
        assert_eq!(obj.original_mangled(), "?foo@@YAXXZ");
        assert!(!obj.is_demangled());
        assert!(obj.name().is_empty());
    }

    #[test]
    fn test_set_demangled_name_marks_demangled() {
        let mut obj = DemangledObject::new("_Z3foov");
        assert!(!obj.is_demangled());
        obj.set_demangled_name("foo");
        assert!(obj.is_demangled());
        assert_eq!(obj.demangled_name(), "foo");
    }

    #[test]
    fn test_qualified_name_no_namespace() {
        let mut obj = DemangledObject::new("_Z3foov");
        obj.set_name("foo");
        assert_eq!(obj.qualified_name(), "foo");
    }

    #[test]
    fn test_qualified_name_with_namespace() {
        let mut obj = DemangledObject::new("_ZN3Foo3barE");
        obj.set_name("bar");
        obj.set_namespace(vec!["Foo".into()]);
        assert_eq!(obj.qualified_name(), "Foo::bar");
    }

    #[test]
    fn test_qualified_name_nested_namespace() {
        let mut obj = DemangledObject::new("_ZN3std3vec3VecE");
        obj.set_name("Vec");
        obj.set_namespace(vec!["std".into(), "vec".into()]);
        assert_eq!(obj.qualified_name(), "std::vec::Vec");
    }

    #[test]
    fn test_build_demangled_name() {
        let mut obj = DemangledObject::new("_ZN3Foo3barE");
        obj.set_name("bar");
        obj.set_namespace(vec!["Foo".into()]);
        obj.build_demangled_name();
        assert_eq!(obj.demangled_name(), "Foo::bar");
        assert!(obj.is_demangled());
    }

    #[test]
    fn test_display_demangled() {
        let mut obj = DemangledObject::new("_Z3foov");
        obj.set_demangled_name("foo(void)");
        assert_eq!(format!("{}", obj), "foo(void)");
    }

    #[test]
    fn test_display_not_demangled() {
        let obj = DemangledObject::new("?foo@@YAXXZ");
        assert_eq!(format!("{}", obj), "?foo@@YAXXZ");
    }

    #[test]
    fn test_access_and_storage_modifiers() {
        let mut obj = DemangledObject::new("_Z3foov");
        obj.set_access_modifier("public");
        obj.set_storage_modifier("static");
        assert_eq!(obj.access_modifier(), "public");
        assert_eq!(obj.storage_modifier(), "static");
    }

    #[test]
    fn test_comment_and_prefix() {
        let mut obj = DemangledObject::new("_Z3foov");
        obj.set_comment("test comment");
        obj.set_special_prefix("virtual");
        assert_eq!(obj.comment(), "test comment");
        assert_eq!(obj.special_prefix(), "virtual");
    }
}
