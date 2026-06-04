//! GNU/GCC demangler integration.
//!
//! This module provides demangling of symbols created by GNU GCC toolchains.
//! It wraps the native `c++filt` (or compatible) demangler command and parses
//! the output into structured demangled objects.
//!
//! # Porting Notes
//!
//! The original Java `GnuDemangler` delegates to a native process
//! (`GnuDemanglerNativeProcess`) that runs `c++filt`. The Rust port
//! provides the same high-level interface: `can_demangle()` checks
//! whether a mangled string matches a known GNU pattern, and
//! `demangle()` spawns the native demangler or uses a built-in parser.

use crate::demangler::microsoft::DemangleError;
use crate::base::analyzer::core::*;
use crate::base::analyzer::priority::*;
use crate::base::analyzer::r#trait::*;

// ---------------------------------------------------------------------------
// DemanglerParseException
// ---------------------------------------------------------------------------

/// Exception to signal a problem parsing a demangled string.
///
/// Corresponds to Java's `DemanglerParseException`.
#[derive(Debug, Clone)]
pub struct DemanglerParseException {
    message: String,
}

impl DemanglerParseException {
    /// Create a new parse exception with the given message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Get the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for DemanglerParseException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DemanglerParseException: {}", self.message)
    }
}

impl std::error::Error for DemanglerParseException {}

// ---------------------------------------------------------------------------
// GnuDemanglerFormat  (extended with Auto)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// GnuDemanglerFormat
// ---------------------------------------------------------------------------

/// Known GNU mangling format prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GnuDemanglerFormat {
    /// Auto-detect the format.
    Auto,
    /// GCC 2.x mangling
    GnuV2,
    /// GCC 3.x+ mangling (the `_Z` prefix)
    GnuV3,
    /// Rust mangling
    Rust,
    /// D language mangling
    Dlang,
    /// Unknown/unsupported format
    Unknown,
}

// ---------------------------------------------------------------------------
// GnuDemangler
// ---------------------------------------------------------------------------

/// A demangler for GNU/GCC mangled symbols.
///
/// This corresponds to the Java `GnuDemangler` class.
pub struct GnuDemangler {
    /// Path to the `c++filt` executable (or compatible demangler).
    demangler_path: String,
    /// Additional arguments to pass to the demangler.
    demangler_args: Vec<String>,
}

impl GnuDemangler {
    /// Create a new GNU demangler with the default `c++filt` path.
    pub fn new() -> Self {
        Self {
            demangler_path: "c++filt".to_string(),
            demangler_args: Vec::new(),
        }
    }

    /// Create a new GNU demangler with a custom demangler path.
    pub fn with_path(path: &str) -> Self {
        Self {
            demangler_path: path.to_string(),
            demangler_args: Vec::new(),
        }
    }

    /// Set additional arguments for the demangler process.
    pub fn set_args(&mut self, args: Vec<String>) {
        self.demangler_args = args;
    }

    /// Returns true if the mangled string appears to be a GNU-style mangled name.
    ///
    /// Recognizes:
    /// - `_Z` prefix (GCC v3+)
    /// - GNU v2 patterns (names starting with a digit, etc.)
    /// - DWARF references (`DW.ref.`)
    /// - Global constructors/destructors (`_GLOBAL_`)
    pub fn can_demangle(&self, mangled: &str) -> bool {
        if mangled.is_empty() {
            return false;
        }

        // DWARF reference symbols
        if mangled.starts_with("DW.ref.") {
            return true;
        }

        // Global constructors/destructors
        if mangled.starts_with("_GLOBAL_") {
            return true;
        }

        // GCC v3+ mangling
        if mangled.starts_with("_Z") {
            return true;
        }

        // GNU v2 patterns (starts with a digit, underscore, or dollar)
        Self::is_gnu2_or_3_pattern(mangled)
    }

    /// Returns the detected mangling format for the given string.
    pub fn detect_format(mangled: &str) -> GnuDemanglerFormat {
        if mangled.starts_with("_Z") {
            GnuDemanglerFormat::GnuV3
        } else if mangled.starts_with("__R") {
            GnuDemanglerFormat::Rust
        } else if mangled.starts_with("_D") {
            GnuDemanglerFormat::Dlang
        } else if Self::is_gnu2_or_3_pattern(mangled) {
            GnuDemanglerFormat::GnuV2
        } else {
            GnuDemanglerFormat::Unknown
        }
    }

    /// Check if a string matches GNU v2 or v3 naming patterns.
    fn is_gnu2_or_3_pattern(mangled: &str) -> bool {
        if mangled.starts_with('_') {
            return true;
        }
        // Names starting with digits are typically GNU v2 constructors/destructors
        mangled
            .chars()
            .next()
            .map_or(false, |c| c.is_ascii_digit())
    }

    /// Determines if the given mangled string should be skipped (not demangled).
    ///
    /// Versioned symbols (`@` not at position 0), triple-underscore prefixed
    /// names, and certain non-mangled patterns are skipped.
    pub fn should_skip(&self, mangled: &str) -> bool {
        // Versioned symbols (e.g., "foo@@GLIBC_2.5")
        if let Some(pos) = mangled.find('@') {
            if pos > 0 {
                return true;
            }
        }

        // Not a mangled symbol but the demangler will try anyway
        if mangled.starts_with("___") {
            return true;
        }

        false
    }

    /// Demangle a GNU-style mangled symbol.
    ///
    /// This invokes the native `c++filt` process and parses the result.
    ///
    /// # Errors
    ///
    /// Returns `DemangleError` if the native demangler fails or the output
    /// cannot be parsed.
    pub fn demangle(&self, mangled: &str) -> Result<String, DemangleError> {
        if !self.can_demangle(mangled) {
            return Err(DemangleError::InvalidSymbol(
                "Not a recognizable GNU mangled symbol".to_string(),
            ));
        }

        let output = self.invoke_native_demangler(mangled)?;
        Ok(output)
    }

    /// Invoke the native demangler process.
    fn invoke_native_demangler(&self, mangled: &str) -> Result<String, DemangleError> {
        use std::process::Command;

        let mut cmd = Command::new(&self.demangler_path);
        cmd.args(&self.demangler_args);
        cmd.arg(mangled);
        cmd.stdin(std::process::Stdio::null());

        let output = cmd.output().map_err(|e| {
            DemangleError::InvalidSymbol(format!("Failed to run demangler: {}", e))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DemangleError::InvalidSymbol(format!(
                "Demangler failed: {}",
                stderr
            )));
        }

        let result = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if result == mangled || result.is_empty() {
            return Err(DemangleError::InvalidSymbol(
                "Demangler did not produce a demangled result".to_string(),
            ));
        }

        Ok(result)
    }

    /// Parse the demangled output string into a structured `DemangledObject`.
    ///
    /// This handles common output patterns from `c++filt` including namespace
    /// qualifiers, template arguments, and function signatures.
    pub fn parse_demangled(&self, mangled: &str, demangled: &str) -> DemangledGnuSymbol {
        DemangledGnuSymbol::parse(mangled, demangled)
    }
}

impl Default for GnuDemangler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DemangledGnuSymbol
// ---------------------------------------------------------------------------

/// A parsed GNU-demangled symbol.
///
/// This corresponds to what `GnuDemanglerParser` produces in the Java code.
#[derive(Debug, Clone)]
pub struct DemangledGnuSymbol {
    /// The original mangled name.
    pub mangled: String,
    /// The full demangled name.
    pub demangled: String,
    /// The detected namespace path (e.g., `["std", "vector"]`).
    pub namespace_parts: Vec<String>,
    /// The base name (without namespace qualifications).
    pub base_name: String,
    /// Template arguments if present (e.g., `["int", "std::allocator<int>"]`).
    pub template_args: Vec<String>,
    /// Whether this is a constructor.
    pub is_constructor: bool,
    /// Whether this is a destructor.
    pub is_destructor: bool,
    /// The demangling format detected.
    pub format: GnuDemanglerFormat,
}

impl DemangledGnuSymbol {
    /// Parse a demangled symbol string into its components.
    fn parse(mangled: &str, demangled: &str) -> Self {
        let format = GnuDemangler::detect_format(mangled);
        let mut sym = Self {
            mangled: mangled.to_string(),
            demangled: demangled.to_string(),
            namespace_parts: Vec::new(),
            base_name: String::new(),
            template_args: Vec::new(),
            is_constructor: false,
            is_destructor: false,
            format,
        };
        sym.parse_demangled_string(demangled);
        sym
    }

    fn parse_demangled_string(&mut self, demangled: &str) {
        // Strip any leading type qualifiers that c++filt might add
        let stripped = demangled.trim();

        // Split by "::" for namespace qualifiers, respecting angle brackets
        let parts = Self::split_namespace_parts(stripped);
        if parts.len() > 1 {
            self.base_name = parts.last().map(|s| s.as_str()).unwrap_or("").to_string();
            self.namespace_parts = parts[..parts.len() - 1]
                .iter()
                .map(|s| s.to_string())
                .collect();
        } else {
            self.base_name = stripped.to_string();
        }

        // Detect constructor/destructor
        if self.base_name.starts_with('~') {
            self.is_destructor = true;
            self.base_name = self.base_name[1..].to_string();
        }

        // Check if the base name matches any namespace component
        // (constructors have the class name as the function name)
        if let Some(ns_last) = self.namespace_parts.last() {
            let base_no_template = self
                .base_name
                .split('<')
                .next()
                .unwrap_or(&self.base_name);
            if base_no_template == ns_last.as_str() {
                self.is_constructor = true;
            }
        }

        // Parse template arguments from the base name
        if let Some(open) = self.base_name.find('<') {
            if let Some(close) = self.base_name.rfind('>') {
                let args_str = &self.base_name[open + 1..close];
                self.template_args = Self::split_template_args(args_str);
            }
        }
    }

    /// Split by `::` respecting nested angle brackets.
    fn split_namespace_parts(s: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut depth = 0;
        let mut current = String::new();
        let mut chars = s.chars().peekable();

        while let Some(ch) = chars.next() {
            match ch {
                '<' => {
                    depth += 1;
                    current.push(ch);
                }
                '>' => {
                    depth -= 1;
                    current.push(ch);
                }
                ':' if depth == 0 && chars.peek() == Some(&':') => {
                    chars.next(); // skip second ':'
                    if !current.is_empty() {
                        result.push(current.clone());
                        current.clear();
                    }
                }
                _ => {
                    current.push(ch);
                }
            }
        }

        if !current.is_empty() {
            result.push(current);
        }

        result
    }

    /// Split template arguments respecting nested angle brackets.
    fn split_template_args(args: &str) -> Vec<String> {
        let mut result = Vec::new();
        let mut depth = 0;
        let mut current = String::new();

        for ch in args.chars() {
            match ch {
                '<' => {
                    depth += 1;
                    current.push(ch);
                }
                '>' => {
                    depth -= 1;
                    current.push(ch);
                }
                ',' if depth == 0 => {
                    result.push(current.trim().to_string());
                    current.clear();
                }
                _ => {
                    current.push(ch);
                }
            }
        }

        if !current.trim().is_empty() {
            result.push(current.trim().to_string());
        }

        result
    }

    /// Get the fully qualified name (namespace::name) without template arguments.
    pub fn qualified_name(&self) -> String {
        let base = self
            .base_name
            .split('<')
            .next()
            .unwrap_or(&self.base_name);
        if self.namespace_parts.is_empty() {
            base.to_string()
        } else {
            format!("{}::{}", self.namespace_parts.join("::"), base)
        }
    }
}

// ---------------------------------------------------------------------------
// GnuDemanglerOptions
// ---------------------------------------------------------------------------

/// Options for the GNU demangler.
///
/// Corresponds to Java's `GnuDemanglerOptions`.
#[derive(Debug, Clone)]
pub struct GnuDemanglerOptions {
    /// The demangling format to use.
    format: GnuDemanglerFormat,
    /// Whether to use standard text replacements.
    use_standard_replacements: bool,
    /// Timeout for the native demangler process (in seconds).
    timeout_seconds: u64,
    /// Name/path of the demangler executable.
    demangler_name: String,
    /// Additional arguments for the demangler executable.
    demangler_args: Vec<String>,
}

impl GnuDemanglerOptions {
    /// The default demangler version key.
    pub const GNU_DEMANGLER_V2_41: &'static str = "demangler_gnu_v2_41";
    /// The default demangler version.
    pub const GNU_DEMANGLER_DEFAULT: &'static str = Self::GNU_DEMANGLER_V2_41;
    /// The default timeout (in seconds).
    pub const DEFAULT_TIMEOUT: u64 = 20;

    /// Create new options with default values.
    pub fn new() -> Self {
        Self {
            format: GnuDemanglerFormat::Auto,
            use_standard_replacements: true,
            timeout_seconds: Self::DEFAULT_TIMEOUT,
            demangler_name: "c++filt".to_string(),
            demangler_args: Vec::new(),
        }
    }

    /// Get the demangling format.
    pub fn format(&self) -> GnuDemanglerFormat {
        self.format
    }

    /// Set the demangling format.
    pub fn set_format(&mut self, format: GnuDemanglerFormat) {
        self.format = format;
    }

    /// Get the format argument string for the native demangler.
    pub fn format_argument(&self) -> &str {
        match self.format {
            GnuDemanglerFormat::Auto => "",
            GnuDemanglerFormat::GnuV2 => "-s gnu-v2",
            GnuDemanglerFormat::GnuV3 => "-s gnu-v3",
            GnuDemanglerFormat::Rust => "-s rust",
            GnuDemanglerFormat::Dlang => "-s dlang",
            GnuDemanglerFormat::Unknown => "",
        }
    }

    /// Whether standard text replacements should be applied.
    pub fn should_use_standard_replacements(&self) -> bool {
        self.use_standard_replacements
    }

    /// Set whether to use standard replacements.
    pub fn set_use_standard_replacements(&mut self, use_replacements: bool) {
        self.use_standard_replacements = use_replacements;
    }

    /// Get the timeout in seconds.
    pub fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds
    }

    /// Set the timeout in seconds.
    pub fn set_timeout_seconds(&mut self, timeout: u64) {
        self.timeout_seconds = timeout;
    }

    /// Get the demangler name/path.
    pub fn demangler_name(&self) -> &str {
        &self.demangler_name
    }

    /// Set the demangler name/path.
    pub fn set_demangler_name(&mut self, name: String) {
        self.demangler_name = name;
    }

    /// Get the demangler arguments.
    pub fn demangler_arguments(&self) -> &[String] {
        &self.demangler_args
    }

    /// Set the demangler arguments.
    pub fn set_demangler_arguments(&mut self, args: Vec<String>) {
        self.demangler_args = args;
    }
}

impl Default for GnuDemanglerOptions {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GnuDemanglerReplacement
// ---------------------------------------------------------------------------

/// Text replacement patterns applied to demangled output.
///
/// The GNU demangler may produce output that contains encoded types or
/// identifiers that need to be translated to more readable forms.
///
/// Corresponds to Java's `GnuDemanglerReplacement`.
#[derive(Debug, Clone)]
pub struct GnuDemanglerReplacement {
    /// The pattern to search for.
    pub pattern: String,
    /// The replacement text.
    pub replacement: String,
    /// Whether this is a regex pattern (vs. literal).
    pub is_regex: bool,
}

impl GnuDemanglerReplacement {
    /// Create a new literal text replacement.
    pub fn new(pattern: impl Into<String>, replacement: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            replacement: replacement.into(),
            is_regex: false,
        }
    }

    /// Create a new regex-based replacement.
    pub fn regex(pattern: impl Into<String>, replacement: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            replacement: replacement.into(),
            is_regex: true,
        }
    }

    /// Apply this replacement to the given string.
    ///
    /// Returns the modified string.
    pub fn apply(&self, input: &str) -> String {
        if self.is_regex {
            // Use regex replacement
            match regex::Regex::new(&self.pattern) {
                Ok(re) => re.replace_all(input, self.replacement.as_str()).to_string(),
                Err(_) => input.to_string(),
            }
        } else {
            input.replace(&self.pattern, &self.replacement)
        }
    }
}

/// A collection of replacement patterns.
///
/// Corresponds to the `default.gnu.demangler.replacements.txt` file.
#[derive(Debug, Clone)]
pub struct GnuDemanglerReplacements {
    /// The replacement patterns.
    replacements: Vec<GnuDemanglerReplacement>,
}

impl GnuDemanglerReplacements {
    /// Create a new empty replacement set.
    pub fn new() -> Self {
        Self {
            replacements: Vec::new(),
        }
    }

    /// Create the default replacements (equivalent to the shipped
    /// `default.gnu.demangler.replacements.txt`).
    pub fn defaults() -> Self {
        let mut r = Self::new();

        // Standard C++ type replacements
        r.add(GnuDemanglerReplacement::new(
            "std::basic_string<char, std::char_traits<char>, std::allocator<char> >",
            "std::string",
        ));
        r.add(GnuDemanglerReplacement::new(
            "std::basic_string<wchar_t, std::char_traits<wchar_t>, std::allocator<wchar_t> >",
            "std::wstring",
        ));
        r.add(GnuDemanglerReplacement::new(
            "std::basic_ostream<char, std::char_traits<char> >",
            "std::ostream",
        ));
        r.add(GnuDemanglerReplacement::new(
            "std::basic_istream<char, std::char_traits<char> >",
            "std::istream",
        ));
        r.add(GnuDemanglerReplacement::new(
            "std::basic_iostream<char, std::char_traits<char> >",
            "std::iostream",
        ));
        r.add(GnuDemanglerReplacement::new(
            "std::basic_ostream<wchar_t, std::char_traits<wchar_t> >",
            "std::wostream",
        ));
        r.add(GnuDemanglerReplacement::new(
            "std::basic_istream<wchar_t, std::char_traits<wchar_t> >",
            "std::wistream",
        ));

        r
    }

    /// Add a replacement pattern.
    pub fn add(&mut self, replacement: GnuDemanglerReplacement) {
        self.replacements.push(replacement);
    }

    /// Apply all replacements to the given string, in order.
    pub fn apply_all(&self, input: &str) -> String {
        let mut result = input.to_string();
        for replacement in &self.replacements {
            result = replacement.apply(&result);
        }
        result
    }

    /// Get the number of replacements.
    pub fn len(&self) -> usize {
        self.replacements.len()
    }

    /// Check if the replacement set is empty.
    pub fn is_empty(&self) -> bool {
        self.replacements.is_empty()
    }
}

impl Default for GnuDemanglerReplacements {
    fn default() -> Self {
        Self::defaults()
    }
}

// ---------------------------------------------------------------------------
// GnuDemanglerAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer for GNU/GCC mangled symbols.
///
/// Runs as part of the auto-analysis pipeline and attempts to demangle
/// symbols matching GNU mangling patterns.
///
/// Corresponds to Java's `GnuDemanglerAnalyzer`.
#[derive(Debug, Clone)]
pub struct GnuDemanglerAnalyzer {
    base: AbstractAnalyzer,
    /// The demangler options.
    pub options: GnuDemanglerOptions,
    /// The text replacements to apply.
    replacements: GnuDemanglerReplacements,
}

impl GnuDemanglerAnalyzer {
    /// The analyzer name.
    pub const NAME: &'static str = "Demangler GNU";
    /// The analyzer description.
    pub const DESCRIPTION: &'static str =
        "After a function is created, this analyzer will attempt to demangle \
         the name and apply datatypes to parameters using the GNU demangler.";

    /// Options key for standard replacements.
    pub const OPTION_USE_REPLACEMENTS: &'static str = "gnuDemanglerUseStandardReplacements";

    /// Create a new analyzer.
    pub fn new() -> Self {
        let mut base = AbstractAnalyzer::new(Self::NAME, Self::DESCRIPTION, AnalyzerType::Byte);
        base.set_priority(
            AnalysisPriority::DATA_TYPE_PROPAGATION
                .before()
                .before()
                .before(),
        );
        base.set_supports_one_time_analysis(true);
        Self {
            base,
            options: GnuDemanglerOptions::default(),
            replacements: GnuDemanglerReplacements::defaults(),
        }
    }

    /// Get the replacements.
    pub fn replacements(&self) -> &GnuDemanglerReplacements {
        &self.replacements
    }

    /// Set the replacements.
    pub fn set_replacements(&mut self, replacements: GnuDemanglerReplacements) {
        self.replacements = replacements;
    }

    /// Attempt to demangle a symbol name.
    ///
    /// Returns `Some(demangled)` if the name was successfully demangled,
    /// or `None` if the name is not a GNU-mangled symbol.
    pub fn demangle_symbol(&self, mangled: &str) -> Option<String> {
        let demangler = GnuDemangler::new();

        if !demangler.can_demangle(mangled) || demangler.should_skip(mangled) {
            return None;
        }

        // Attempt native demangling
        match demangler.demangle(mangled) {
            Ok(mut result) => {
                // Apply standard replacements if configured
                if self.options.should_use_standard_replacements() {
                    result = self.replacements.apply_all(&result);
                }
                Some(result)
            }
            Err(_) => None,
        }
    }
}

impl Default for GnuDemanglerAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for GnuDemanglerAnalyzer {
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

    fn can_analyze(&self, _program: &Program) -> bool {
        // Can analyze any program; will check individual symbols
        true
    }

    fn default_enablement(&self, _program: &Program) -> bool {
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
        monitor.set_message("Demangling GNU symbols...");
        log.append_msg("GnuDemanglerAnalyzer: demangling GNU-style symbols");
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
    fn test_gnu_can_demangle() {
        let d = GnuDemangler::new();
        assert!(d.can_demangle("_Z3foov"));
        assert!(d.can_demangle("_ZN3Foo3barEv"));
        assert!(d.can_demangle("DW.ref.__gxx_personality_v0"));
        assert!(d.can_demangle("_GLOBAL__I_main"));
        assert!(d.can_demangle("12my_functionv"));
        assert!(!d.can_demangle("plain_symbol"));
        assert!(!d.can_demangle(""));
    }

    #[test]
    fn test_gnu_detect_format() {
        assert_eq!(
            GnuDemangler::detect_format("_Z3foov"),
            GnuDemanglerFormat::GnuV3
        );
        assert_eq!(
            GnuDemangler::detect_format("__R12my_functionv"),
            GnuDemanglerFormat::Rust
        );
        assert_eq!(
            GnuDemangler::detect_format("12my_functionv"),
            GnuDemanglerFormat::GnuV2
        );
    }

    #[test]
    fn test_gnu_should_skip() {
        let d = GnuDemangler::new();
        assert!(d.should_skip("foo@@GLIBC_2.5"));
        assert!(d.should_skip("___something"));
        assert!(!d.should_skip("_Z3foov"));
        assert!(!d.should_skip("@versioned")); // @ at position 0 is OK
    }

    #[test]
    fn test_parse_demangled_simple() {
        let d = GnuDemangler::new();
        let sym = d.parse_demangled("_Z3foov", "foo()");
        assert_eq!(sym.base_name, "foo()");
        assert_eq!(sym.mangled, "_Z3foov");
    }

    #[test]
    fn test_parse_demangled_namespaced() {
        let d = GnuDemangler::new();
        let sym = d.parse_demangled(
            "_ZN3std6vectorIiSaIiEE5beginEv",
            "std::vector<int, std::allocator<int>>::begin()",
        );
        assert_eq!(sym.namespace_parts, vec!["std", "vector<int, std::allocator<int>>"]);
        assert_eq!(sym.base_name, "begin()");
    }

    #[test]
    fn test_parse_demangled_destructor() {
        let d = GnuDemangler::new();
        let sym = d.parse_demangled("_ZN3FooD1Ev", "Foo::~Foo()");
        assert!(sym.is_destructor);
    }

    #[test]
    fn test_split_template_args() {
        let args = DemangledGnuSymbol::split_template_args("int, std::vector<int, char>");
        assert_eq!(args.len(), 2);
        assert_eq!(args[0], "int");
        assert_eq!(args[1], "std::vector<int, char>");
    }

    // --- DemanglerParseException ---

    #[test]
    fn test_demangler_parse_exception() {
        let e = DemanglerParseException::new("unexpected token");
        assert_eq!(e.message(), "unexpected token");
        assert!(e.to_string().contains("unexpected token"));
        assert!(std::error::Error::source(&e).is_none());
    }

    // --- GnuDemanglerOptions ---

    #[test]
    fn test_gnu_demangler_options_default() {
        let opts = GnuDemanglerOptions::new();
        assert_eq!(opts.format(), GnuDemanglerFormat::Auto);
        assert!(opts.should_use_standard_replacements());
        assert_eq!(opts.timeout_seconds(), 20);
        assert_eq!(opts.demangler_name(), "c++filt");
    }

    #[test]
    fn test_gnu_demangler_options_format_argument() {
        let mut opts = GnuDemanglerOptions::new();
        assert_eq!(opts.format_argument(), ""); // Auto -> no arg

        opts.set_format(GnuDemanglerFormat::GnuV2);
        assert_eq!(opts.format_argument(), "-s gnu-v2");

        opts.set_format(GnuDemanglerFormat::GnuV3);
        assert_eq!(opts.format_argument(), "-s gnu-v3");

        opts.set_format(GnuDemanglerFormat::Rust);
        assert_eq!(opts.format_argument(), "-s rust");

        opts.set_format(GnuDemanglerFormat::Dlang);
        assert_eq!(opts.format_argument(), "-s dlang");
    }

    #[test]
    fn test_gnu_demangler_options_setters() {
        let mut opts = GnuDemanglerOptions::new();
        opts.set_use_standard_replacements(false);
        assert!(!opts.should_use_standard_replacements());

        opts.set_timeout_seconds(60);
        assert_eq!(opts.timeout_seconds(), 60);

        opts.set_demangler_name("/usr/bin/c++filt".into());
        assert_eq!(opts.demangler_name(), "/usr/bin/c++filt");

        opts.set_demangler_arguments(vec!["-n".into()]);
        assert_eq!(opts.demangler_arguments(), &["-n"]);
    }

    #[test]
    fn test_gnu_demangler_format_default() {
        let opts = GnuDemanglerOptions::default();
        assert_eq!(opts.format(), GnuDemanglerFormat::Auto);
    }

    // --- GnuDemanglerReplacement ---

    #[test]
    fn test_replacement_literal() {
        let r = GnuDemanglerReplacement::new("foo", "bar");
        assert_eq!(r.apply("hello foo world"), "hello bar world");
        assert_eq!(r.apply("no match"), "no match");
    }

    #[test]
    fn test_replacement_regex() {
        let r = GnuDemanglerReplacement::regex(r"\bint\b", "int32_t");
        assert_eq!(r.apply("void foo(int x)"), "void foo(int32_t x)");
        // Word boundary correctly does NOT match inside "internal"
        assert_eq!(r.apply("internal"), "internal");
        // Match standalone "int"
        assert_eq!(r.apply("int"), "int32_t");
    }

    #[test]
    fn test_replacement_regex_invalid() {
        let r = GnuDemanglerReplacement::regex("[invalid", "replacement");
        // Invalid regex should return input unchanged
        assert_eq!(r.apply("test"), "test");
    }

    // --- GnuDemanglerReplacements ---

    #[test]
    fn test_replacements_collection() {
        let mut reps = GnuDemanglerReplacements::new();
        assert!(reps.is_empty());
        assert_eq!(reps.len(), 0);

        reps.add(GnuDemanglerReplacement::new("foo", "bar"));
        reps.add(GnuDemanglerReplacement::new("hello", "world"));
        assert_eq!(reps.len(), 2);
        assert!(!reps.is_empty());

        assert_eq!(reps.apply_all("foo and hello"), "bar and world");
    }

    #[test]
    fn test_replacements_defaults() {
        let reps = GnuDemanglerReplacements::defaults();
        assert!(!reps.is_empty());

        // Test std::string replacement
        let input = "std::basic_string<char, std::char_traits<char>, std::allocator<char> > foo()";
        let result = reps.apply_all(input);
        assert!(result.contains("std::string"));
        assert!(!result.contains("basic_string<char"));
    }

    #[test]
    fn test_replacements_default_trait() {
        let reps = GnuDemanglerReplacements::default();
        assert!(!reps.is_empty()); // defaults() is called
    }

    // --- GnuDemanglerAnalyzer ---

    #[test]
    fn test_gnu_demangler_analyzer_creation() {
        let analyzer = GnuDemanglerAnalyzer::new();
        assert_eq!(analyzer.name(), GnuDemanglerAnalyzer::NAME);
        assert!(analyzer.supports_one_time_analysis());
        assert_eq!(analyzer.analysis_type(), AnalyzerType::Byte);
    }

    #[test]
    fn test_gnu_demangler_analyzer_can_analyze() {
        let analyzer = GnuDemanglerAnalyzer::new();
        let prog = Program::new(
            "test",
            Language {
                processor: "x86".into(),
                variant: "LE".into(),
                size: 64,
            },
        );
        assert!(analyzer.can_analyze(&prog));
        assert!(analyzer.default_enablement(&prog));
    }

    #[test]
    fn test_gnu_demangler_analyzer_replacements() {
        let analyzer = GnuDemanglerAnalyzer::new();
        assert!(!analyzer.replacements().is_empty());

        let mut analyzer2 = GnuDemanglerAnalyzer::new();
        analyzer2.set_replacements(GnuDemanglerReplacements::new());
        assert!(analyzer2.replacements().is_empty());
    }

    #[test]
    fn test_gnu_demangler_analyzer_added() {
        let analyzer = GnuDemanglerAnalyzer::new();
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
        let result = analyzer.added(&mut prog, &set, &monitor, &mut log);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_gnu_demangler_analyzer_demangle_non_mangled() {
        let analyzer = GnuDemanglerAnalyzer::new();
        // Non-mangled symbols should return None
        assert!(analyzer.demangle_symbol("plain_symbol").is_none());
        assert!(analyzer.demangle_symbol("").is_none());
    }

    #[test]
    fn test_gnu_demangler_analyzer_demangle_skipped() {
        let analyzer = GnuDemanglerAnalyzer::new();
        // Versioned symbols should be skipped
        assert!(analyzer.demangle_symbol("foo@@GLIBC_2.5").is_none());
        assert!(analyzer.demangle_symbol("___something").is_none());
    }
}
