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

// ---------------------------------------------------------------------------
// GnuDemanglerFormat
// ---------------------------------------------------------------------------

/// Known GNU mangling format prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GnuDemanglerFormat {
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
            self.base_name = parts.last().unwrap_or(&"").to_string();
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
}
