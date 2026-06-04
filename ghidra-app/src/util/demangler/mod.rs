//! Demangler framework (ported from `ghidra.app.util.demangler`).
//!
//! Provides:
//! - [`DemanglerOptions`] -- configuration for the demangling process
//! - [`DemangledObject`] -- result of demangling a mangled name
//! - [`DemanglerUtil`] -- utility methods for demangling
//! - [`Demangler`] trait -- interface for demangler implementations

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ===================================================================
// DemanglerOptions  (ghidra.app.util.demangler.DemanglerOptions)
// ===================================================================

/// Configuration options for the demangling process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemanglerOptions {
    /// Whether to apply calling conventions from the demangled signature.
    pub apply_calling_convention: bool,
    /// Whether to apply the demangled function signature.
    pub apply_signature: bool,
    /// Whether to perform disassembly for known data structures.
    pub do_disassembly: bool,
    /// Whether to only demangle names matching known patterns.
    pub demangle_only_known_patterns: bool,
}

impl Default for DemanglerOptions {
    fn default() -> Self {
        Self {
            apply_calling_convention: true,
            apply_signature: true,
            do_disassembly: true,
            demangle_only_known_patterns: true,
        }
    }
}

impl DemanglerOptions {
    /// Create options with all features enabled.
    pub fn all_enabled() -> Self {
        Self {
            apply_calling_convention: true,
            apply_signature: true,
            do_disassembly: true,
            demangle_only_known_patterns: false,
        }
    }

    /// Create options with only signature application enabled.
    pub fn signature_only() -> Self {
        Self {
            apply_calling_convention: false,
            apply_signature: true,
            do_disassembly: false,
            demangle_only_known_patterns: true,
        }
    }

    /// Create options with all features disabled.
    pub fn none() -> Self {
        Self {
            apply_calling_convention: false,
            apply_signature: false,
            do_disassembly: false,
            demangle_only_known_patterns: false,
        }
    }
}

// ===================================================================
// Demangler errors
// ===================================================================

/// Errors that can occur during demangling.
#[derive(Debug, Error)]
pub enum DemanglerError {
    /// The name does not match the expected mangling scheme.
    #[error("not a valid mangled name: {0}")]
    InvalidMangledName(String),
    /// The mangled name is truncated or corrupted.
    #[error("truncated mangled name")]
    TruncatedName,
    /// An unsupported type or construct was encountered.
    #[error("unsupported construct: {0}")]
    Unsupported(String),
    /// A generic demangling failure.
    #[error("demangling failed: {0}")]
    Failed(String),
}

// ===================================================================
// DemangledObject  (ghidra.app.util.demangler.DemangledObject)
// ===================================================================

/// The result of demangling a single name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemangledObject {
    /// The original mangled name.
    pub mangled: String,
    /// The demangled (human-readable) name.
    pub demangled: String,
    /// The namespace the symbol belongs to, if any.
    pub namespace: Option<String>,
    /// The function signature, if the symbol is a function.
    pub signature: Option<DemangledFunctionSignature>,
    /// The data type, if the symbol is a type.
    pub data_type: Option<String>,
    /// Calling convention, if known.
    pub calling_convention: Option<String>,
    /// Whether the symbol is a template specialization.
    pub is_template: bool,
    /// Whether the symbol is a constructor.
    pub is_constructor: bool,
    /// Whether the symbol is a destructor.
    pub is_destructor: bool,
    /// Whether the symbol is a virtual function.
    pub is_virtual: bool,
    /// Whether the symbol is a static member.
    pub is_static: bool,
}

/// Function signature obtained from demangling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemangledFunctionSignature {
    /// Return type.
    pub return_type: String,
    /// Parameter types (in order).
    pub parameters: Vec<String>,
    /// Whether the function is const-qualified.
    pub is_const: bool,
    /// Whether the function is noexcept.
    pub is_noexcept: bool,
}

impl DemangledObject {
    /// Create a new demangled object.
    pub fn new(mangled: impl Into<String>, demangled: impl Into<String>) -> Self {
        Self {
            mangled: mangled.into(),
            demangled: demangled.into(),
            namespace: None,
            signature: None,
            data_type: None,
            calling_convention: None,
            is_template: false,
            is_constructor: false,
            is_destructor: false,
            is_virtual: false,
            is_static: false,
        }
    }

    /// Return the fully qualified demangled name (namespace + name).
    pub fn fully_qualified_name(&self) -> String {
        match &self.namespace {
            Some(ns) => format!("{}::{}", ns, self.demangled),
            None => self.demangled.clone(),
        }
    }

    /// Return a C-like signature string.
    pub fn signature_string(&self) -> String {
        match &self.signature {
            Some(sig) => {
                let params = sig.parameters.join(", ");
                format!("{} {}({})", sig.return_type, self.demangled, params)
            }
            None => self.demangled.clone(),
        }
    }
}

// ===================================================================
// Demangler trait  (ghidra.app.util.demangler.Demangler)
// ===================================================================

/// Trait for name demangler implementations.
pub trait Demangler: Send + Sync {
    /// Return the name of this demangler (e.g. "Microsoft", "GNU").
    fn name(&self) -> &str;

    /// Attempt to demangle the given name.
    ///
    /// Returns `Ok(Some(demangled))` on success, `Ok(None)` if the name
    /// does not match this demangler's pattern, and `Err` on failure.
    fn demangle(
        &self,
        mangled_name: &str,
        options: &DemanglerOptions,
    ) -> Result<Option<DemangledObject>, DemanglerError>;
}

// ===================================================================
// DemanglerUtil  (ghidra.app.util.demangler.DemanglerUtil)
// ===================================================================

/// Utility methods for demangling.
pub struct DemanglerUtil;

impl DemanglerUtil {
    /// Check if a name looks like it could be a mangled Microsoft name.
    ///
    /// MSVC mangled names start with `?`.
    pub fn is_microsoft_mangled(name: &str) -> bool {
        name.starts_with('?')
    }

    /// Check if a name looks like it could be a mangled GNU/Itanium name.
    ///
    /// GNU/Itanium mangled names start with `_Z`.
    pub fn is_gnu_mangled(name: &str) -> bool {
        name.starts_with("_Z")
    }

    /// Check if a name looks like it could be a mangled D language name.
    ///
    /// D mangled names start with `_D`.
    pub fn is_d_mangled(name: &str) -> bool {
        name.starts_with("_D")
    }

    /// Check if a name looks like it could be a mangled Rust name.
    ///
    /// Rust mangled names start with `_R` (v0 mangling) or `_ZN` (legacy).
    pub fn is_rust_mangled(name: &str) -> bool {
        name.starts_with("_R") || name.starts_with("_ZN")
    }

    /// Try all registered demanglers on the given name and return the first
    /// successful result.
    pub fn demangle_with_all(
        demanglers: &[Box<dyn Demangler>],
        name: &str,
        options: &DemanglerOptions,
    ) -> Result<Option<DemangledObject>, DemanglerError> {
        for demangler in demanglers {
            if let Some(result) = demangler.demangle(name, options)? {
                return Ok(Some(result));
            }
        }
        Ok(None)
    }

    /// Generate a demangled function signature string.
    pub fn generate_signature(obj: &DemangledObject) -> String {
        obj.signature_string()
    }
}

// ===================================================================
// Tests
// ===================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demangler_options_defaults() {
        let opts = DemanglerOptions::default();
        assert!(opts.apply_calling_convention);
        assert!(opts.apply_signature);
        assert!(opts.do_disassembly);
        assert!(opts.demangle_only_known_patterns);
    }

    #[test]
    fn demangler_options_presets() {
        let all = DemanglerOptions::all_enabled();
        assert!(!all.demangle_only_known_patterns);

        let sig = DemanglerOptions::signature_only();
        assert!(!sig.do_disassembly);

        let none = DemanglerOptions::none();
        assert!(!none.apply_signature);
    }

    #[test]
    fn demangled_object_basic() {
        let obj = DemangledObject::new("?foo@@YAHXZ", "int __cdecl foo()");
        assert_eq!(obj.mangled, "?foo@@YAHXZ");
        assert_eq!(obj.demangled, "int __cdecl foo()");
        assert_eq!(obj.fully_qualified_name(), "int __cdecl foo()");
    }

    #[test]
    fn demangled_object_with_namespace() {
        let mut obj = DemangledObject::new("_ZN3Foo3barEv", "bar");
        obj.namespace = Some("Foo".into());
        assert_eq!(obj.fully_qualified_name(), "Foo::bar");
    }

    #[test]
    fn demangled_object_signature() {
        let mut obj = DemangledObject::new("_Z3fooi", "foo");
        obj.signature = Some(DemangledFunctionSignature {
            return_type: "int".into(),
            parameters: vec!["int".into()],
            is_const: false,
            is_noexcept: false,
        });
        assert_eq!(obj.signature_string(), "int foo(int)");
    }

    #[test]
    fn demangled_object_signature_const() {
        let mut obj = DemangledObject::new("_ZNK3Foo3barEv", "bar");
        obj.signature = Some(DemangledFunctionSignature {
            return_type: "void".into(),
            parameters: vec![],
            is_const: true,
            is_noexcept: false,
        });
        let sig = obj.signature_string();
        assert!(sig.contains("void"));
        assert!(sig.contains("bar"));
    }

    #[test]
    fn demangler_util_pattern_detection() {
        assert!(DemanglerUtil::is_microsoft_mangled("?foo@@YAHXZ"));
        assert!(!DemanglerUtil::is_microsoft_mangled("_Z3foo"));
        assert!(DemanglerUtil::is_gnu_mangled("_Z3foo"));
        assert!(!DemanglerUtil::is_gnu_mangled("?foo"));
        assert!(DemanglerUtil::is_d_mangled("_D3foo"));
        assert!(DemanglerUtil::is_rust_mangled("_RNvC7crate_3foo"));
        assert!(DemanglerUtil::is_rust_mangled("_ZN3foo"));
    }

    #[test]
    fn demangled_object_flags() {
        let mut obj = DemangledObject::new("test", "test");
        assert!(!obj.is_template);
        assert!(!obj.is_constructor);
        assert!(!obj.is_destructor);
        assert!(!obj.is_virtual);
        assert!(!obj.is_static);
        obj.is_template = true;
        obj.is_virtual = true;
        assert!(obj.is_template);
        assert!(obj.is_virtual);
    }

    #[test]
    fn demangler_error_display() {
        let err = DemanglerError::InvalidMangledName("bad".into());
        assert!(err.to_string().contains("bad"));
    }

    struct TestDemangler;

    impl Demangler for TestDemangler {
        fn name(&self) -> &str {
            "Test"
        }

        fn demangle(
            &self,
            mangled_name: &str,
            _options: &DemanglerOptions,
        ) -> Result<Option<DemangledObject>, DemanglerError> {
            if mangled_name.starts_with("TEST_") {
                let demangled = mangled_name
                    .strip_prefix("TEST_")
                    .unwrap()
                    .to_string();
                Ok(Some(DemangledObject::new(mangled_name, demangled)))
            } else {
                Ok(None)
            }
        }
    }

    #[test]
    fn demangler_trait_basic() {
        let d = TestDemangler;
        assert_eq!(d.name(), "Test");

        let opts = DemanglerOptions::default();
        let result = d.demangle("TEST_foo", &opts).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().demangled, "foo");

        let result = d.demangle("OTHER_bar", &opts).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn demangler_util_demangle_with_all() {
        let demanglers: Vec<Box<dyn Demangler>> = vec![Box::new(TestDemangler)];
        let opts = DemanglerOptions::default();

        let result = DemanglerUtil::demangle_with_all(&demanglers, "TEST_hello", &opts).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().demangled, "hello");

        let result = DemanglerUtil::demangle_with_all(&demanglers, "UNKNOWN", &opts).unwrap();
        assert!(result.is_none());
    }
}
