//! Demangler trait -- ported from `Demangler.java`.
//!
//! Defines the common interface that all demangler implementations
//! (Microsoft, GNU, etc.) must satisfy.

use crate::demangler::demangled_object::DemangledObject;
use crate::demangler::demangler_options::DemanglerOptions;

/// Errors that can occur during demangling.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DemanglerError {
    /// The symbol is empty or blank.
    #[error("Symbol is empty or blank")]
    EmptySymbol,

    /// The symbol does not match any known mangling scheme.
    #[error("Not a recognizable mangled symbol: {0}")]
    NotMangled(String),

    /// A parse error occurred during demangling.
    #[error("Parse error: {0}")]
    ParseError(String),

    /// The native demangler process failed (e.g. `c++filt`).
    #[error("Native demangler process error: {0}")]
    ProcessError(String),

    /// A back-reference in the mangled name is invalid.
    #[error("Invalid back-reference: {0}")]
    InvalidBackref(String),

    /// The mangled name has unparsed trailing characters.
    #[error("Characters remaining after demangling: {0} chars")]
    RemainingChars(usize),

    /// A generic demangling error.
    #[error("{0}")]
    Other(String),
}

impl From<String> for DemanglerError {
    fn from(msg: String) -> Self {
        DemanglerError::Other(msg)
    }
}

/// The common interface for all demanglers.
///
/// Corresponds to Java's `Demangler` interface. Each demangler
/// implementation (Microsoft, GNU, Rust, Swift, etc.) implements this
/// trait so that the analysis framework can operate uniformly.
///
/// # Type parameters
///
/// The trait is object-safe and can be used as `dyn Demangler`.
pub trait Demangler: Send + Sync {
    /// The name of this demangler (e.g. `"Microsoft Demangler"`).
    fn name(&self) -> &str;

    /// Demangle a single mangled symbol.
    ///
    /// Returns a `DemangledObject` on success, or a `DemanglerError` if the
    /// symbol could not be demangled.
    fn demangle(&self, mangled: &str) -> Result<DemangledObject, DemanglerError>;

    /// Demangle a mangled symbol, using the given options to control
    /// the demangling behavior.
    ///
    /// The default implementation ignores the options and delegates to
    /// `demangle()`. Implementations that honor options should override
    /// this method.
    fn demangle_with_options(
        &self,
        mangled: &str,
        _options: &DemanglerOptions,
    ) -> Result<DemangledObject, DemanglerError> {
        self.demangle(mangled)
    }

    /// Returns `true` if the given string looks like a mangled symbol
    /// that this demangler can handle.
    ///
    /// This is a cheap pre-filter; `demangle()` may still fail even
    /// when `can_demangle()` returns `true`.
    fn can_demangle(&self, mangled: &str) -> bool;

    /// Demangle a symbol at a specific address.
    ///
    /// Some demanglers may need the address for interpretation (e.g.
    /// to determine whether a symbol is a function or data). The
    /// default implementation ignores the address.
    fn demangle_at(
        &self,
        mangled: &str,
        _address: u64,
    ) -> Result<DemangledObject, DemanglerError> {
        self.demangle(mangled)
    }

    /// Get the default options for this demangler.
    ///
    /// The default returns `DemanglerOptions::new()` (project defaults).
    fn default_options(&self) -> DemanglerOptions {
        DemanglerOptions::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal demangler for testing the trait.
    struct TestDemangler;

    impl Demangler for TestDemangler {
        fn name(&self) -> &str {
            "Test Demangler"
        }

        fn can_demangle(&self, mangled: &str) -> bool {
            mangled.starts_with("_TEST_")
        }

        fn demangle(&self, mangled: &str) -> Result<DemangledObject, DemanglerError> {
            if !self.can_demangle(mangled) {
                return Err(DemanglerError::NotMangled(mangled.to_string()));
            }
            let mut obj = DemangledObject::new(mangled);
            let demangled = mangled.strip_prefix("_TEST_").unwrap_or(mangled);
            obj.set_name(demangled);
            obj.set_demangled_name(demangled);
            Ok(obj)
        }
    }

    #[test]
    fn test_demangler_name() {
        let d = TestDemangler;
        assert_eq!(d.name(), "Test Demangler");
    }

    #[test]
    fn test_can_demangle() {
        let d = TestDemangler;
        assert!(d.can_demangle("_TEST_foo"));
        assert!(!d.can_demangle("foo"));
        assert!(!d.can_demangle(""));
    }

    #[test]
    fn test_demangle_success() {
        let d = TestDemangler;
        let result = d.demangle("_TEST_foo").unwrap();
        assert_eq!(result.name(), "foo");
        assert_eq!(result.demangled_name(), "foo");
        assert!(result.is_demangled());
    }

    #[test]
    fn test_demangle_failure() {
        let d = TestDemangler;
        let result = d.demangle("not_mangled");
        assert!(result.is_err());
    }

    #[test]
    fn test_demangle_with_options_delegates() {
        let d = TestDemangler;
        let opts = DemanglerOptions::new();
        let result = d.demangle_with_options("_TEST_bar", &opts).unwrap();
        assert_eq!(result.name(), "bar");
    }

    #[test]
    fn test_demangle_at_delegates() {
        let d = TestDemangler;
        let result = d.demangle_at("_TEST_baz", 0x1000).unwrap();
        assert_eq!(result.name(), "baz");
    }

    #[test]
    fn test_default_options() {
        let d = TestDemangler;
        let opts = d.default_options();
        assert!(opts.apply_signature());
    }

    #[test]
    fn test_demangler_error_display() {
        assert_eq!(
            format!("{}", DemanglerError::EmptySymbol),
            "Symbol is empty or blank"
        );
        assert_eq!(
            format!("{}", DemanglerError::NotMangled("foo".into())),
            "Not a recognizable mangled symbol: foo"
        );
    }

    #[test]
    fn test_demangler_error_from_string() {
        let err: DemanglerError = "test error".to_string().into();
        assert_eq!(format!("{}", err), "test error");
    }

    #[test]
    fn test_dyn_demangler() {
        let d: Box<dyn Demangler> = Box::new(TestDemangler);
        assert_eq!(d.name(), "Test Demangler");
        assert!(d.can_demangle("_TEST_x"));
        let result = d.demangle("_TEST_x").unwrap();
        assert_eq!(result.name(), "x");
    }
}
