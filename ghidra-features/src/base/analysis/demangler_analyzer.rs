//! Demangler analyzer.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.analysis.DemanglerAnalyzer`.
//!
//! This analyzer reads mangled symbol names (C++ MSVC, Itanium/GCC,
//! Rust, D, etc.) and demangles them into human-readable form.  The
//! demangled information is used to:
//!
//! - Set function signatures (return type, parameters)
//! - Create namespaces and class structures
//! - Populate label names
//! - Identify virtual tables and RTTI structures

use std::collections::HashMap;

use super::analyzer::{
    AbstractAnalyzer, Address, AddressSet, AnalysisPriority, Analyzer, AnalyzerType,
    CancelledError, MessageLog, Program, TaskMonitor,
};

// ---------------------------------------------------------------------------
// Demangled type model
// ---------------------------------------------------------------------------
/// The calling convention extracted from a mangled name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallingConvention {
    Cdecl,
    Stdcall,
    Fastcall,
    Thiscall,
    Vectorcall,
    CxxMethod,
    Unknown,
}

/// A single function parameter extracted from the mangled name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemangledParameter {
    pub type_name: String,
    pub name: Option<String>,
    pub is_const: bool,
    pub is_reference: bool,
    pub is_pointer: bool,
}

impl DemangledParameter {
    pub fn new(type_name: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            name: None,
            is_const: false,
            is_reference: false,
            is_pointer: false,
        }
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn as_const(mut self) -> Self {
        self.is_const = true;
        self
    }

    pub fn as_reference(mut self) -> Self {
        self.is_reference = true;
        self
    }

    pub fn as_pointer(mut self) -> Self {
        self.is_pointer = true;
        self
    }
}

/// The result of demangling a symbol name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemangledSymbol {
    /// The original mangled name.
    pub mangled: String,
    /// The fully qualified demangled name.
    pub demangled: String,
    /// Namespace components (e.g., `["std", "vector"]`).
    pub namespaces: Vec<String>,
    /// Class / struct name, if any.
    pub class_name: Option<String>,
    /// Function name (unqualified).
    pub function_name: String,
    /// Return type, if present.
    pub return_type: Option<String>,
    /// Parameters.
    pub parameters: Vec<DemangledParameter>,
    /// Whether this is a constructor.
    pub is_constructor: bool,
    /// Whether this is a destructor.
    pub is_destructor: bool,
    /// Whether this is a static function.
    pub is_static: bool,
    /// Whether this is a virtual function.
    pub is_virtual: bool,
    /// The calling convention.
    pub calling_convention: CallingConvention,
}

impl DemangledSymbol {
    /// Construct a simple demangled symbol with just a function name.
    pub fn simple(mangled: impl Into<String>, function_name: impl Into<String>) -> Self {
        let fname = function_name.into();
        Self {
            mangled: mangled.into(),
            demangled: fname.clone(),
            namespaces: Vec::new(),
            class_name: None,
            function_name: fname,
            return_type: None,
            parameters: Vec::new(),
            is_constructor: false,
            is_destructor: false,
            is_static: false,
            is_virtual: false,
            calling_convention: CallingConvention::Unknown,
        }
    }

    /// The fully qualified name including namespaces and class.
    pub fn qualified_name(&self) -> String {
        let mut parts: Vec<&str> = self.namespaces.iter().map(|s| s.as_str()).collect();
        if let Some(ref cls) = self.class_name {
            parts.push(cls);
        }
        parts.push(&self.function_name);
        parts.join("::")
    }

    /// Format a human-readable signature string.
    pub fn signature(&self) -> String {
        let ret = self.return_type.as_deref().unwrap_or("void");
        let params: Vec<String> = if self.parameters.is_empty() {
            vec!["void".to_string()]
        } else {
            self.parameters.iter().map(|p| p.type_name.clone()).collect()
        };
        format!("{} {}({})", ret, self.qualified_name(), params.join(", "))
    }
}

// ---------------------------------------------------------------------------
// Demangling strategies
// ---------------------------------------------------------------------------
/// Trait for language-specific demanglers.
pub trait Demangler: std::fmt::Debug + Send + Sync {
    /// Human-readable name of this demangling strategy.
    fn name(&self) -> &str;

    /// Whether this demangler can handle the given mangled name.
    fn can_demangle(&self, mangled: &str) -> bool;

    /// Attempt to demangle the given name.
    fn demangle(&self, mangled: &str) -> Option<DemangledSymbol>;
}

/// MSVC C++ name demangler.
///
/// Handles names starting with `?` (MSVC decorated names).
#[derive(Debug)]
pub struct MsvcDemangler {
    prefix: String,
}

impl MsvcDemangler {
    pub fn new() -> Self {
        Self {
            prefix: "?".to_string(),
        }
    }
}

impl Default for MsvcDemangler {
    fn default() -> Self {
        Self::new()
    }
}

impl Demangler for MsvcDemangler {
    fn name(&self) -> &str {
        "MSVC C++ Demangler"
    }

    fn can_demangle(&self, mangled: &str) -> bool {
        mangled.starts_with('?')
    }

    fn demangle(&self, _mangled: &str) -> Option<DemangledSymbol> {
        // Placeholder: full MSVC demangling is complex.
        None
    }
}

/// Itanium/GCC ABI name demangler.
///
/// Handles names starting with `_Z`.
#[derive(Debug)]
pub struct ItaniumDemangler {
    prefix: String,
}

impl ItaniumDemangler {
    pub fn new() -> Self {
        Self {
            prefix: "_Z".to_string(),
        }
    }
}

impl Default for ItaniumDemangler {
    fn default() -> Self {
        Self::new()
    }
}

impl Demangler for ItaniumDemangler {
    fn name(&self) -> &str {
        "Itanium/GCC Demangler"
    }

    fn can_demangle(&self, mangled: &str) -> bool {
        mangled.starts_with("_Z")
    }

    fn demangle(&self, _mangled: &str) -> Option<DemangledSymbol> {
        // Placeholder: full Itanium demangling is complex.
        None
    }
}

/// Rust name demangler.
///
/// Handles names starting with `_R` (Rust v0 mangling scheme) or the
/// legacy `_ZN` prefix.
#[derive(Debug)]
pub struct RustDemangler;

impl RustDemangler {
    pub fn new() -> Self {
        Self
    }
}

impl Demangler for RustDemangler {
    fn name(&self) -> &str {
        "Rust Demangler"
    }

    fn can_demangle(&self, mangled: &str) -> bool {
        mangled.starts_with("_R") || mangled.starts_with("_ZN")
    }

    fn demangle(&self, _mangled: &str) -> Option<DemangledSymbol> {
        // Placeholder: real Rust demangling uses the `rustc_demangle` crate.
        None
    }
}

// ---------------------------------------------------------------------------
// DemanglerAnalyzer
// ---------------------------------------------------------------------------
/// Demangles symbol names and applies demangled information to the program.
///
/// Runs at [`AnalysisPriority::FUNCTION_ID_ANALYSIS`] and is triggered
/// by [`AnalyzerType::Function`] changes.
#[derive(Debug)]
pub struct DemanglerAnalyzer {
    base: AbstractAnalyzer,
    demanglers: Vec<Box<dyn Demangler>>,
    /// Whether to set function signatures from demangled info.
    pub apply_signatures: bool,
    /// Whether to create namespace labels.
    pub create_namespaces: bool,
    /// Statistics: number of symbols successfully demangled.
    pub demangle_count: usize,
}

impl DemanglerAnalyzer {
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(
            "Demangler Analyzer",
            "Demangles C++/Rust/Java symbol names",
            AnalyzerType::Function,
        );
        base.set_priority(AnalysisPriority::FUNCTION_ID_ANALYSIS);
        base.set_supports_one_time_analysis(true);
        Self {
            base,
            demanglers: vec![
                Box::new(MsvcDemangler::new()),
                Box::new(ItaniumDemangler::new()),
                Box::new(RustDemangler::new()),
            ],
            apply_signatures: true,
            create_namespaces: true,
            demangle_count: 0,
        }
    }

    /// Try to demangle a name using the registered demanglers.
    pub fn demangle(&self, name: &str) -> Option<DemangledSymbol> {
        for d in &self.demanglers {
            if d.can_demangle(name) {
                if let Some(result) = d.demangle(name) {
                    return Some(result);
                }
            }
        }
        None
    }

    /// Register an additional demangler.
    pub fn add_demangler(&mut self, demangler: Box<dyn Demangler>) {
        self.demanglers.push(demangler);
    }

    /// Get the names of all registered demanglers.
    pub fn demangler_names(&self) -> Vec<&str> {
        self.demanglers.iter().map(|d| d.name()).collect()
    }
}

impl Default for DemanglerAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for DemanglerAnalyzer {
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
        self.base.priority()
    }

    fn supports_one_time_analysis(&self) -> bool {
        self.base.supports_one_time_analysis()
    }

    fn can_analyze(&self, _program: &Program) -> bool {
        true
    }

    fn added(
        &self,
        program: &mut Program,
        _set: &AddressSet,
        monitor: &dyn TaskMonitor,
        log: &mut MessageLog,
    ) -> Result<bool, CancelledError> {
        let mut demangled_count = 0usize;

        for func in program.function_manager.get_functions(true) {
            monitor.check_cancelled()?;

            if self.demangle(&func.name).is_some() {
                demangled_count += 1;
            }
        }

        if demangled_count > 0 {
            log.append_msg(&format!("Demangled {} symbols", demangled_count));
        }
        Ok(demangled_count > 0)
    }

    fn register_options(&self, _program: &Program) -> Vec<super::analyzer::AnalysisOption> {
        vec![
            super::analyzer::AnalysisOption {
                name: "Apply signatures".to_string(),
                description: "Apply demangled signatures to functions".to_string(),
                default_value: super::analyzer::AnalysisOptionValue::Bool(true),
                current_value: super::analyzer::AnalysisOptionValue::Bool(self.apply_signatures),
            },
            super::analyzer::AnalysisOption {
                name: "Create namespaces".to_string(),
                description: "Create namespace labels from demangled names".to_string(),
                default_value: super::analyzer::AnalysisOptionValue::Bool(true),
                current_value: super::analyzer::AnalysisOptionValue::Bool(self.create_namespaces),
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::analyzer::{AddressRange, BasicTaskMonitor, Function, FunctionManager, Language};

    fn make_lang() -> Language {
        Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        }
    }

    fn make_program_with_functions(names: &[&str]) -> Program {
        let lang = make_lang();
        let mut prog = Program::new("test_demangle", lang);
        prog.image_base = 0x400000;
        prog.memory.add_range(AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        // FunctionManager doesn't expose a public push method, so we
        // build one directly via the struct literal (tests are in the
        // same crate, and the field is pub(crate)-visible via the
        // auto_analysis_manager tests already doing this).
        for (i, name) in names.iter().enumerate() {
            prog.function_manager.add_function(Function {
                entry: Address::new(0x401000 + (i as u64) * 0x100),
                name: name.to_string(),
            });
        }
        prog
    }

    #[test]
    fn test_demangler_analyzer_creation() {
        let a = DemanglerAnalyzer::new();
        assert_eq!(a.name(), "Demangler Analyzer");
        assert_eq!(a.analysis_type(), AnalyzerType::Function);
        assert!(a.supports_one_time_analysis());
        assert!(a.apply_signatures);
        assert!(a.create_namespaces);
    }

    #[test]
    fn test_demangler_analyzer_can_analyze() {
        let a = DemanglerAnalyzer::new();
        assert!(a.can_analyze(&make_program_with_functions(&[])));
    }

    #[test]
    fn test_demangler_analyzer_demangler_names() {
        let a = DemanglerAnalyzer::new();
        let names = a.demangler_names();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"MSVC C++ Demangler"));
        assert!(names.contains(&"Itanium/GCC Demangler"));
        assert!(names.contains(&"Rust Demangler"));
    }

    #[test]
    fn test_msvc_demangler() {
        let d = MsvcDemangler::new();
        assert_eq!(d.name(), "MSVC C++ Demangler");
        assert!(d.can_demangle("?func@@YAXXZ"));
        assert!(!d.can_demangle("_Z3foov"));
        assert!(d.demangle("?func@@YAXXZ").is_none()); // placeholder
    }

    #[test]
    fn test_itanium_demangler() {
        let d = ItaniumDemangler::new();
        assert_eq!(d.name(), "Itanium/GCC Demangler");
        assert!(d.can_demangle("_Z3foov"));
        assert!(!d.can_demangle("?func"));
        assert!(d.demangle("_Z3foov").is_none()); // placeholder
    }

    #[test]
    fn test_rust_demangler() {
        let d = RustDemangler::new();
        assert_eq!(d.name(), "Rust Demangler");
        assert!(d.can_demangle("_RINsCs5b7"));
        assert!(d.can_demangle("_ZN3foo3barE"));
        assert!(!d.can_demangle("?func"));
        assert!(d.demangle("_RINsCs5b7").is_none()); // placeholder
    }

    #[test]
    fn test_demangled_symbol_simple() {
        let sym = DemangledSymbol::simple("_Z3foov", "foo");
        assert_eq!(sym.mangled, "_Z3foov");
        assert_eq!(sym.function_name, "foo");
        assert_eq!(sym.demangled, "foo");
        assert!(sym.namespaces.is_empty());
        assert!(sym.class_name.is_none());
        assert!(sym.parameters.is_empty());
        assert!(!sym.is_constructor);
        assert!(!sym.is_destructor);
        assert!(!sym.is_static);
        assert!(!sym.is_virtual);
    }

    #[test]
    fn test_demangled_symbol_qualified_name() {
        let mut sym = DemangledSymbol::simple("_Z", "bar");
        sym.namespaces = vec!["std".into(), "io".into()];
        sym.class_name = Some("Writer".into());
        assert_eq!(sym.qualified_name(), "std::io::Writer::bar");
    }

    #[test]
    fn test_demangled_symbol_signature() {
        let mut sym = DemangledSymbol::simple("_Z", "add");
        sym.return_type = Some("int".into());
        sym.parameters = vec![
            DemangledParameter::new("int"),
            DemangledParameter::new("int"),
        ];
        assert_eq!(sym.signature(), "int add(int, int)");
    }

    #[test]
    fn test_demangled_symbol_signature_no_params() {
        let sym = DemangledSymbol::simple("_Z", "foo");
        assert_eq!(sym.signature(), "void foo(void)");
    }

    #[test]
    fn test_demangled_parameter_builder() {
        let p = DemangledParameter::new("int")
            .with_name("x")
            .as_const()
            .as_reference();
        assert_eq!(p.type_name, "int");
        assert_eq!(p.name, Some("x".into()));
        assert!(p.is_const);
        assert!(p.is_reference);
        assert!(!p.is_pointer);
    }

    #[test]
    fn test_demangled_parameter_pointer() {
        let p = DemangledParameter::new("char").as_pointer();
        assert!(p.is_pointer);
    }

    #[test]
    fn test_demangler_analyzer_demangle() {
        let a = DemanglerAnalyzer::new();
        // All demanglers are placeholders, so demangle returns None
        assert!(a.demangle("?func@@YAXXZ").is_none());
        assert!(a.demangle("_Z3foov").is_none());
        assert!(a.demangle("not_mangled").is_none());
    }

    #[test]
    fn test_demangler_analyzer_run_with_mangled() {
        let a = DemanglerAnalyzer::new();
        let mut prog = make_program_with_functions(&[
            "?func@@YAXXZ",
            "_Z3foov",
            "_ZN3barE",
            "plain_name",
        ]);
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        // Placeholder demanglers don't actually demangle, so result is Ok(false)
        let result = a.added(&mut prog, &set, &monitor, &mut log).unwrap();
        assert!(!result); // placeholder returns None for all
    }

    #[test]
    fn test_demangler_analyzer_run_empty() {
        let a = DemanglerAnalyzer::new();
        let mut prog = make_program_with_functions(&[]);
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        let monitor = BasicTaskMonitor::new();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log).unwrap();
        assert!(!result);
    }

    #[test]
    fn test_demangler_analyzer_cancelled() {
        let a = DemanglerAnalyzer::new();
        let mut prog = make_program_with_functions(&["_Z3foov"]);
        let set = AddressSet::from_range(AddressRange::new(
            Address::new(0x400000),
            Address::new(0x500000),
        ));
        let monitor = BasicTaskMonitor::new();
        monitor.cancel();
        let mut log = MessageLog::new();
        let result = a.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_err());
    }

    #[test]
    fn test_demangler_analyzer_options() {
        let a = DemanglerAnalyzer::new();
        let prog = make_program_with_functions(&[]);
        let opts = a.register_options(&prog);
        assert_eq!(opts.len(), 2);
        assert_eq!(opts[0].name, "Apply signatures");
        assert_eq!(opts[1].name, "Create namespaces");
    }

    #[test]
    fn test_add_custom_demangler() {
        #[derive(Debug)]
        struct TestDemangler;
        impl Demangler for TestDemangler {
            fn name(&self) -> &str { "Test Demangler" }
            fn can_demangle(&self, _: &str) -> bool { false }
            fn demangle(&self, _: &str) -> Option<DemangledSymbol> { None }
        }

        let mut a = DemanglerAnalyzer::new();
        a.add_demangler(Box::new(TestDemangler));
        assert_eq!(a.demangler_names().len(), 4);
        assert!(a.demangler_names().contains(&"Test Demangler"));
    }

    #[test]
    fn test_calling_convention_variants() {
        assert_ne!(CallingConvention::Cdecl, CallingConvention::Stdcall);
        assert_ne!(CallingConvention::Fastcall, CallingConvention::Thiscall);
    }

    #[test]
    fn test_demangled_symbol_flags() {
        let mut sym = DemangledSymbol::simple("_Z", "ctor");
        sym.is_constructor = true;
        sym.is_virtual = true;
        sym.calling_convention = CallingConvention::CxxMethod;
        assert!(sym.is_constructor);
        assert!(sym.is_virtual);
        assert_eq!(sym.calling_convention, CallingConvention::CxxMethod);
    }
}
