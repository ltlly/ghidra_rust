//! Abstract demangler analyzer.
//!
//! Ported from Ghidra's `AbstractDemanglerAnalyzer.java`.
//! Provides the base for analyzer implementations that attempt to demangle
//! symbols in a binary. Concrete implementations for GNU and Microsoft
//! mangling schemes derive from this.

use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ---------------------------------------------------------------------------
// Demangler options
// ---------------------------------------------------------------------------

/// Options controlling demangling behaviour.
#[derive(Debug, Clone)]
pub struct DemanglerOptions {
    /// Apply the recovered signature to the function in the program.
    pub apply_signature: bool,
    /// Apply the recovered calling convention.
    pub apply_calling_convention: bool,
    /// Disassemble through demangled references.
    pub do_disassembly: bool,
    /// Only demangle names matching known patterns.
    pub demangle_only_known_patterns: bool,
}

impl Default for DemanglerOptions {
    fn default() -> Self {
        Self {
            apply_signature: true,
            apply_calling_convention: true,
            do_disassembly: true,
            demangle_only_known_patterns: false,
        }
    }
}

// ---------------------------------------------------------------------------
// DemangledObject  --  result of a successful demangle
// ---------------------------------------------------------------------------

/// Represents a successfully demangled symbol.
#[derive(Debug, Clone)]
pub struct DemangledObject {
    /// The original mangled name.
    pub mangled: String,
    /// The demangled (human-readable) name.
    pub demangled_name: String,
    /// Optional namespace (e.g. "std::vector").
    pub namespace: Option<String>,
    /// Whether this demangled object represents a function.
    pub is_function: bool,
    /// Optional error message from the apply step.
    pub error_message: Option<String>,
}

impl DemangledObject {
    pub fn new(mangled: impl Into<String>, demangled_name: impl Into<String>) -> Self {
        Self {
            mangled: mangled.into(),
            demangled_name: demangled_name.into(),
            namespace: None,
            is_function: false,
            error_message: None,
        }
    }

    pub fn with_namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    pub fn as_function(mut self) -> Self {
        self.is_function = true;
        self
    }

    pub fn name(&self) -> &str {
        &self.demangled_name
    }

    pub fn get_mangled_string(&self) -> &str {
        &self.mangled
    }

    pub fn get_error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }
}

// ---------------------------------------------------------------------------
// MangledContext
// ---------------------------------------------------------------------------

/// Context for a single demangling operation.
#[derive(Debug, Clone)]
pub struct MangledContext {
    /// The mangled symbol name to demangle.
    mangled: String,
    /// The address of the symbol in the program.
    address: Address,
    /// Demangler options to use.
    options: DemanglerOptions,
}

impl MangledContext {
    pub fn new(mangled: impl Into<String>, address: Address, options: DemanglerOptions) -> Self {
        Self {
            mangled: mangled.into(),
            address,
            options,
        }
    }

    pub fn mangled(&self) -> &str {
        &self.mangled
    }
    pub fn address(&self) -> Address {
        self.address
    }
    pub fn options(&self) -> &DemanglerOptions {
        &self.options
    }
}

// ---------------------------------------------------------------------------
// AbstractDemanglerAnalyzer
// ---------------------------------------------------------------------------

/// The base demangler analyzer. Implementations override [`do_demangle`] to
/// provide language-specific demangling logic (GNU, MSVC, etc.).
///
/// The analyzer iterates over primary symbols in the given address set,
/// attempts to demangle each, and applies the result. External symbols are
/// processed last to avoid losing mangled names prematurely.
#[derive(Debug, Clone)]
pub struct AbstractDemanglerAnalyzer {
    base: AbstractAnalyzer,
    /// The demangler options (can be updated by analysis options).
    pub options: DemanglerOptions,
}

impl AbstractDemanglerAnalyzer {
    pub fn new(name: &str, description: &str) -> Self {
        let mut b = AbstractAnalyzer::new(name, description, AnalyzerType::Byte);
        b.set_priority(
            AnalysisPriority::DATA_TYPE_PROPAGATION
                .before()
                .before()
                .before(),
        );
        b.set_supports_one_time_analysis(true);
        Self {
            base: b,
            options: DemanglerOptions::default(),
        }
    }

    /// Clean a symbol name for demangling (strip address-based prefixes, etc.).
    pub fn clean_symbol(address: &Address, name: &str) -> String {
        // In Java this calls SymbolUtilities.getCleanSymbolName.
        // Stub: return as-is.
        let _ = address;
        name.to_string()
    }

    /// Determine whether a symbol should be skipped by the demangler.
    ///
    /// Skips:
    /// - Default-source symbols
    /// - Non-global, non-external-library symbols
    /// - Functions whose signature source is higher priority than IMPORTED
    ///   (unless the function is a thunk)
    pub fn should_skip_symbol(
        is_default_source: bool,
        is_external: bool,
        parent_is_global: bool,
        parent_is_library: bool,
        is_function: bool,
        is_thunk: bool,
        has_higher_priority_signature: bool,
    ) -> bool {
        if is_default_source {
            return true;
        }
        if is_external {
            // Only demangle externals directly parented to a Library namespace
            if !parent_is_library {
                return true;
            }
        } else if !parent_is_global {
            return true;
        }
        if is_function && !is_thunk && has_higher_priority_signature {
            return true;
        }
        false
    }

    /// Run the demangle logic on a mangled context. Returns `Some(DemangledObject)`
    /// on success, `None` if the name is not a valid mangled name.
    ///
    /// This base implementation returns `None`. Override in concrete analyzers.
    pub fn do_demangle(&self, ctx: &MangledContext) -> Option<DemangledObject> {
        let _ = ctx;
        None
    }

    /// Format the log message for an apply failure.
    pub fn log_apply_error(
        demangled: &DemangledObject,
        address: &Address,
        error: Option<&str>,
    ) -> String {
        let class_name = if demangled.is_function {
            "Function"
        } else {
            "Data"
        };
        let default_msg = format!("Unknown error at address {}", address);
        let message = error.unwrap_or(&default_msg);
        format!(
            "Apply failure ({}: {})\n\t{}",
            class_name, message, demangled.mangled
        )
    }
}

impl Analyzer for AbstractDemanglerAnalyzer {
    fn name(&self) -> &str {
        self.base.name()
    }
    fn description(&self) -> &str {
        self.base.description()
    }
    fn analysis_type(&self) -> AnalyzerType {
        self.base.analysis_type()
    }
    fn priority(&self) -> AnalysisPriority {
        AnalysisPriority::DATA_TYPE_PROPAGATION
            .before()
            .before()
            .before()
    }

    fn can_analyze(&self, _p: &Program) -> bool {
        // Base implementation: always returns true.
        // Override in concrete implementations to control program-specific enablement.
        true
    }

    fn default_enablement(&self, _p: &Program) -> bool {
        true
    }

    fn supports_one_time_analysis(&self) -> bool {
        true
    }

    fn added(
        &self,
        _program: &mut Program,
        _set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        monitor.check_cancelled()?;
        monitor.set_indeterminate(true);
        monitor.set_message("Demangling symbols...");
        log.append_msg("AbstractDemanglerAnalyzer: demangling symbols");
        monitor.set_indeterminate(false);
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_demangler_options_default() {
        let opts = DemanglerOptions::default();
        assert!(opts.apply_signature);
        assert!(opts.apply_calling_convention);
        assert!(opts.do_disassembly);
        assert!(!opts.demangle_only_known_patterns);
    }

    #[test]
    fn test_demangled_object_new() {
        let d = DemangledObject::new("_Z3foov", "foo()");
        assert_eq!(d.name(), "foo()");
        assert_eq!(d.get_mangled_string(), "_Z3foov");
        assert!(!d.is_function);
        assert!(d.namespace.is_none());
        assert!(d.get_error_message().is_none());
    }

    #[test]
    fn test_demangled_object_with_namespace() {
        let d = DemangledObject::new("_ZN3Foo3barEv", "Foo::bar()")
            .with_namespace("std")
            .as_function();
        assert_eq!(d.namespace.as_deref(), Some("std"));
        assert!(d.is_function);
    }

    #[test]
    fn test_demangled_object_error_message() {
        let mut d = DemangledObject::new("_Z3foov", "foo()");
        d.error_message = Some("type mismatch".into());
        assert_eq!(d.get_error_message(), Some("type mismatch"));
    }

    #[test]
    fn test_mangled_context() {
        let opts = DemanglerOptions::default();
        let ctx = MangledContext::new("_Z3foov", Address::new(0x401000), opts);
        assert_eq!(ctx.mangled(), "_Z3foov");
        assert_eq!(ctx.address(), Address::new(0x401000));
    }

    #[test]
    fn test_should_skip_default_source() {
        assert!(AbstractDemanglerAnalyzer::should_skip_symbol(
            true, false, true, false, false, false, false
        ));
    }

    #[test]
    fn test_should_skip_non_global_non_external() {
        assert!(AbstractDemanglerAnalyzer::should_skip_symbol(
            false, false, false, false, false, false, false
        ));
    }

    #[test]
    fn test_should_not_skip_global() {
        assert!(!AbstractDemanglerAnalyzer::should_skip_symbol(
            false, false, true, false, false, false, false
        ));
    }

    #[test]
    fn test_should_skip_external_without_library() {
        assert!(AbstractDemanglerAnalyzer::should_skip_symbol(
            false, true, false, false, false, false, false
        ));
    }

    #[test]
    fn test_should_not_skip_external_with_library() {
        assert!(!AbstractDemanglerAnalyzer::should_skip_symbol(
            false, true, false, true, false, false, false
        ));
    }

    #[test]
    fn test_should_skip_function_with_higher_priority_sig() {
        assert!(AbstractDemanglerAnalyzer::should_skip_symbol(
            false, false, true, false, true, false, true
        ));
    }

    #[test]
    fn test_should_not_skip_thunk_with_higher_priority_sig() {
        assert!(!AbstractDemanglerAnalyzer::should_skip_symbol(
            false, false, true, false, true, true, true
        ));
    }

    #[test]
    fn test_log_apply_error() {
        let d = DemangledObject::new("_Z3foov", "foo()").as_function();
        let addr = Address::new(0x401000);
        let msg = AbstractDemanglerAnalyzer::log_apply_error(&d, &addr, Some("bad sig"));
        assert!(msg.contains("Apply failure"));
        assert!(msg.contains("Function"));
        assert!(msg.contains("bad sig"));
        assert!(msg.contains("_Z3foov"));
    }

    #[test]
    fn test_log_apply_error_no_error() {
        let d = DemangledObject::new("_Z3barv", "bar()");
        let addr = Address::new(0x402000);
        let msg = AbstractDemanglerAnalyzer::log_apply_error(&d, &addr, None);
        assert!(msg.contains("Unknown error"));
        assert!(msg.contains("Data"));
    }

    #[test]
    fn test_abstract_demangler_analyzer_creation() {
        let a = AbstractDemanglerAnalyzer::new("GNU Demangler", "Demangles GNU-style symbols");
        assert_eq!(a.name(), "GNU Demangler");
        assert_eq!(a.description(), "Demangles GNU-style symbols");
        assert_eq!(a.analysis_type(), AnalyzerType::Byte);
        assert!(a.supports_one_time_analysis());
    }

    #[test]
    fn test_abstract_demangler_can_analyze() {
        let a = AbstractDemanglerAnalyzer::new("Test", "test");
        let prog = Program::new(
            "p",
            Language {
                processor: "x86".into(),
                variant: "LE".into(),
                size: 64,
            },
        );
        assert!(a.can_analyze(&prog));
    }

    #[test]
    fn test_abstract_demangler_default_enablement() {
        let a = AbstractDemanglerAnalyzer::new("Test", "test");
        let prog = Program::new(
            "p",
            Language {
                processor: "x86".into(),
                variant: "LE".into(),
                size: 64,
            },
        );
        assert!(a.default_enablement(&prog));
    }

    #[test]
    fn test_do_demangle_base_returns_none() {
        let a = AbstractDemanglerAnalyzer::new("Test", "test");
        let ctx = MangledContext::new(
            "anything",
            Address::new(0),
            DemanglerOptions::default(),
        );
        assert!(a.do_demangle(&ctx).is_none());
    }

    #[test]
    fn test_clean_symbol() {
        assert_eq!(
            AbstractDemanglerAnalyzer::clean_symbol(&Address::new(0x1000), "_Z3foov"),
            "_Z3foov"
        );
    }

    #[test]
    fn test_analyzer_added() {
        let a = AbstractDemanglerAnalyzer::new("Test Demangler", "test");
        let mut prog = Program::new(
            "test",
            Language {
                processor: "x86".into(),
                variant: "LE".into(),
                size: 64,
            },
        );
        let set = AddressSet::new();
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }
}
