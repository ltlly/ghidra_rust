//! ExternalSymbolResolverAnalyzer -- analyzer for linking unresolved
//! external symbols.
//!
//! Ported from
//! `ghidra.app.plugin.core.analysis.ExternalSymbolResolverAnalyzer`.
//!
//! This analyzer resolves unresolved external symbols by looking them
//! up in the program's required libraries list.  When a program is
//! loaded (e.g., from an ELF or Mach-O binary), external symbols may
//! reference functions or data in shared libraries.  This analyzer
//! attempts to match those unresolved references to symbols found in
//! the project's library programs.
//!
//! # Supported formats
//!
//! The analyzer activates only for ELF and Mach-O executables.
//!
//! # Examples
//!
//! ```rust
//! use ghidra_features::external::external_symbol_resolver_analyzer::{
//!     ExternalSymbolResolverAnalyzer,
//! };
//! use ghidra_features::external::ExternalManagerDB;
//! use ghidra_core::symbol::SourceType;
//! use ghidra_core::addr::Address;
//!
//! let mut analyzer = ExternalSymbolResolverAnalyzer::new();
//! assert_eq!(analyzer.name(), "External Symbol Resolver");
//! assert!(analyzer.supports_one_time_analysis());
//! ```

use std::collections::BTreeMap;
use std::fmt;

use ghidra_core::addr::Address;
use ghidra_core::symbol::SourceType;

use super::external_location_db::ExternalLocationDB;
use super::external_manager_db::ExternalManagerDB;

// ---------------------------------------------------------------------------
// Executable format
// ---------------------------------------------------------------------------

/// Supported executable formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutableFormat {
    /// ELF (Executable and Linkable Format) -- Linux, BSD, etc.
    Elf,
    /// Mach-O -- macOS, iOS, etc.
    MachO,
    /// PE (Portable Executable) -- Windows.
    Pe,
    /// Unknown or unsupported format.
    Unknown,
}

impl fmt::Display for ExecutableFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutableFormat::Elf => write!(f, "ELF"),
            ExecutableFormat::MachO => write!(f, "Mach-O"),
            ExecutableFormat::Pe => write!(f, "PE"),
            ExecutableFormat::Unknown => write!(f, "Unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// UnresolvedSymbol
// ---------------------------------------------------------------------------

/// An unresolved external symbol that needs to be linked.
///
/// This represents a symbol reference in the current program that has
/// not yet been resolved to a specific library symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedSymbol {
    /// The name of the unresolved symbol.
    pub name: String,
    /// The library name this symbol is expected to come from (if known).
    pub library_hint: Option<String>,
    /// The address in the current program that references this symbol.
    pub reference_address: Option<Address>,
    /// The source type of the original reference.
    pub source: SourceType,
}

impl UnresolvedSymbol {
    /// Create a new unresolved symbol.
    pub fn new(
        name: impl Into<String>,
        library_hint: Option<&str>,
        reference_address: Option<Address>,
        source: SourceType,
    ) -> Self {
        Self {
            name: name.into(),
            library_hint: library_hint.map(|s| s.to_string()),
            reference_address,
            source,
        }
    }
}

// ---------------------------------------------------------------------------
// ResolvedSymbol
// ---------------------------------------------------------------------------

/// A symbol that has been successfully resolved to a library symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSymbol {
    /// The name of the resolved symbol.
    pub name: String,
    /// The library where the symbol was found.
    pub library_name: String,
    /// The address of the symbol in the external library (if known).
    pub external_address: Option<Address>,
    /// The address in the current program that references this symbol.
    pub reference_address: Option<Address>,
}

impl ResolvedSymbol {
    /// Create a new resolved symbol.
    pub fn new(
        name: impl Into<String>,
        library_name: impl Into<String>,
        external_address: Option<Address>,
        reference_address: Option<Address>,
    ) -> Self {
        Self {
            name: name.into(),
            library_name: library_name.into(),
            external_address,
            reference_address,
        }
    }
}

// ---------------------------------------------------------------------------
// ProblemLibrary
// ---------------------------------------------------------------------------

/// Information about a library that had resolution problems.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProblemLibrary {
    /// The library name.
    pub name: String,
    /// The reason the library is problematic.
    pub reason: String,
    /// The number of symbols that could not be resolved.
    pub unresolved_count: usize,
}

impl ProblemLibrary {
    /// Create new problem library info.
    pub fn new(
        name: impl Into<String>,
        reason: impl Into<String>,
        unresolved_count: usize,
    ) -> Self {
        Self {
            name: name.into(),
            reason: reason.into(),
            unresolved_count,
        }
    }
}

// ---------------------------------------------------------------------------
// ExternalSymbolResolver
// ---------------------------------------------------------------------------

/// Resolves unresolved external symbols by looking them up in available
/// libraries.
///
/// This is a simplified version of Ghidra's `ExternalSymbolResolver`.
/// It maintains a registry of known library symbols and attempts to
/// match unresolved symbols against them.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::external_symbol_resolver_analyzer::{
///     ExternalSymbolResolver, UnresolvedSymbol, ResolvedSymbol,
/// };
/// use ghidra_core::symbol::SourceType;
/// use ghidra_core::addr::Address;
///
/// let mut resolver = ExternalSymbolResolver::new();
///
/// // Register known library symbols
/// resolver.add_library_symbol("libc", "printf", Some(Address::new(0x1000)));
/// resolver.add_library_symbol("libc", "malloc", Some(Address::new(0x2000)));
/// resolver.add_library_symbol("libm", "sin", Some(Address::new(0x3000)));
///
/// // Add unresolved symbols
/// resolver.add_unresolved(UnresolvedSymbol::new(
///     "printf", Some("libc"), Some(Address::new(0x401000)), SourceType::Imported,
/// ));
///
/// // Resolve
/// let results = resolver.resolve();
/// assert_eq!(results.len(), 1);
/// assert_eq!(results[0].library_name, "libc");
/// ```
#[derive(Debug, Clone, Default)]
pub struct ExternalSymbolResolver {
    /// Known library symbols: library name -> (symbol name -> external address).
    library_symbols: BTreeMap<String, BTreeMap<String, Option<Address>>>,
    /// Unresolved symbols to be resolved.
    unresolved: Vec<UnresolvedSymbol>,
    /// Resolved symbols.
    resolved: Vec<ResolvedSymbol>,
    /// Problem libraries encountered during resolution.
    problem_libraries: Vec<ProblemLibrary>,
    /// Informational log messages.
    log_messages: Vec<String>,
}

impl ExternalSymbolResolver {
    /// Create a new resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a known symbol in a library.
    ///
    /// * `library_name` -- the library containing the symbol.
    /// * `symbol_name` -- the symbol name.
    /// * `address` -- the address of the symbol in the external program
    ///   (optional).
    pub fn add_library_symbol(
        &mut self,
        library_name: &str,
        symbol_name: &str,
        address: Option<Address>,
    ) {
        self.library_symbols
            .entry(library_name.to_string())
            .or_default()
            .insert(symbol_name.to_string(), address);
    }

    /// Add an unresolved symbol to be resolved.
    pub fn add_unresolved(&mut self, symbol: UnresolvedSymbol) {
        self.unresolved.push(symbol);
    }

    /// Run the resolution process.
    ///
    /// For each unresolved symbol, attempts to find a matching symbol in
    /// the registered libraries.  If a library hint is provided, that
    /// library is searched first; otherwise all libraries are searched.
    ///
    /// Returns the list of successfully resolved symbols.
    pub fn resolve(&mut self) -> &[ResolvedSymbol] {
        self.resolved.clear();
        self.problem_libraries.clear();
        self.log_messages.clear();

        let mut remaining_unresolved: Vec<UnresolvedSymbol> = Vec::new();

        // Move unresolved out of self to avoid borrow conflicts
        let unresolved: Vec<UnresolvedSymbol> = std::mem::take(&mut self.unresolved);
        for sym in unresolved {
            if let Some(resolved) = self.try_resolve_symbol(&sym) {
                self.log_messages.push(format!(
                    "Resolved '{}' in library '{}'",
                    resolved.name, resolved.library_name
                ));
                self.resolved.push(resolved);
            } else {
                remaining_unresolved.push(sym);
            }
        }

        // Track problem libraries
        let mut lib_counts: BTreeMap<String, usize> = BTreeMap::new();
        for sym in &remaining_unresolved {
            if let Some(lib) = &sym.library_hint {
                *lib_counts.entry(lib.clone()).or_insert(0) += 1;
            }
        }
        for (lib, count) in lib_counts {
            self.problem_libraries.push(ProblemLibrary::new(
                &lib,
                format!("{} symbols could not be resolved", count),
                count,
            ));
        }

        self.unresolved = remaining_unresolved;
        &self.resolved
    }

    /// Try to resolve a single symbol.
    fn try_resolve_symbol(&self, sym: &UnresolvedSymbol) -> Option<ResolvedSymbol> {
        // If we have a library hint, search that library first
        if let Some(lib_hint) = &sym.library_hint {
            if let Some(lib_symbols) = self.library_symbols.get(lib_hint) {
                if let Some(addr) = lib_symbols.get(&sym.name) {
                    return Some(ResolvedSymbol::new(
                        &sym.name,
                        lib_hint,
                        *addr,
                        sym.reference_address,
                    ));
                }
            }
        }

        // Search all libraries
        for (lib_name, lib_symbols) in &self.library_symbols {
            // Skip if we already searched this library via hint
            if Some(lib_name.as_str()) == sym.library_hint.as_deref() {
                continue;
            }
            if let Some(addr) = lib_symbols.get(&sym.name) {
                return Some(ResolvedSymbol::new(
                    &sym.name,
                    lib_name,
                    *addr,
                    sym.reference_address,
                ));
            }
        }

        None
    }

    /// Returns the list of resolved symbols.
    pub fn resolved_symbols(&self) -> &[ResolvedSymbol] {
        &self.resolved
    }

    /// Returns the list of unresolved symbols (those that could not be
    /// resolved).
    pub fn unresolved_symbols(&self) -> &[UnresolvedSymbol] {
        &self.unresolved
    }

    /// Returns `true` if there are problem libraries.
    pub fn has_problem_libraries(&self) -> bool {
        !self.problem_libraries.is_empty()
    }

    /// Returns the list of problem libraries.
    pub fn problem_libraries(&self) -> &[ProblemLibrary] {
        &self.problem_libraries
    }

    /// Returns the informational log messages.
    pub fn log_messages(&self) -> &[String] {
        &self.log_messages
    }

    /// Log information using the provided callback.
    pub fn log_info<F: FnMut(&str)>(&self, mut callback: F, problems_only: bool) {
        for msg in &self.log_messages {
            if !problems_only {
                callback(msg);
            }
        }
        for prob in &self.problem_libraries {
            callback(&format!(
                "Problem library '{}': {} ({} unresolved)",
                prob.name, prob.reason, prob.unresolved_count
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Analyzer error
// ---------------------------------------------------------------------------

/// Errors that can occur during external symbol resolution analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolverAnalyzerError {
    /// Analysis was cancelled.
    Cancelled,
    /// The program is not in a supported format.
    UnsupportedFormat(String),
    /// No parent folder available for looking up libraries.
    NoParentFolder,
    /// General error.
    Other(String),
}

impl fmt::Display for ResolverAnalyzerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolverAnalyzerError::Cancelled => write!(f, "Analysis cancelled"),
            ResolverAnalyzerError::UnsupportedFormat(fmt) => {
                write!(f, "Unsupported format: {}", fmt)
            }
            ResolverAnalyzerError::NoParentFolder => {
                write!(f, "No parent folder available for library lookup")
            }
            ResolverAnalyzerError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ResolverAnalyzerError {}

// ---------------------------------------------------------------------------
// ExternalSymbolResolverAnalyzer
// ---------------------------------------------------------------------------

/// Analyzer that links unresolved external symbols to the first symbol
/// found in the program's required libraries list.
///
/// This is the Rust port of Ghidra's `ExternalSymbolResolverAnalyzer`.
/// It runs once during auto-analysis (supports one-time analysis) and
/// attempts to resolve external symbol references by searching through
/// the project's library programs.
///
/// The analyzer only activates for ELF and Mach-O executables.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::{
///     ExternalSymbolResolverAnalyzer, ExecutableFormat,
/// };
///
/// let analyzer = ExternalSymbolResolverAnalyzer::new();
/// assert_eq!(analyzer.name(), "External Symbol Resolver");
/// assert!(analyzer.supports_one_time_analysis());
/// assert!(analyzer.can_analyze(ExecutableFormat::Elf));
/// assert!(analyzer.can_analyze(ExecutableFormat::MachO));
/// assert!(!analyzer.can_analyze(ExecutableFormat::Pe));
/// ```
#[derive(Debug, Clone)]
pub struct ExternalSymbolResolverAnalyzer {
    /// The analyzer name.
    name: String,
    /// The analyzer description.
    description: String,
    /// Whether the analyzer is enabled by default.
    enabled: bool,
    /// Whether this analyzer supports one-time analysis only.
    one_time: bool,
}

impl ExternalSymbolResolverAnalyzer {
    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self {
            name: "External Symbol Resolver".to_string(),
            description: "Links unresolved external symbols to the first symbol found in the program's required libraries list (found in program properties).".to_string(),
            enabled: true,
            one_time: true,
        }
    }

    /// Returns the analyzer name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the analyzer description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns whether the analyzer is enabled by default.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set whether the analyzer is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns whether this analyzer supports one-time analysis.
    pub fn supports_one_time_analysis(&self) -> bool {
        self.one_time
    }

    /// Check if the analyzer can analyze a program with the given format.
    ///
    /// Returns `true` only for ELF and Mach-O formats.
    pub fn can_analyze(&self, format: ExecutableFormat) -> bool {
        matches!(format, ExecutableFormat::Elf | ExecutableFormat::MachO)
    }

    /// Run the analysis.
    ///
    /// Creates an [`ExternalSymbolResolver`], populates it with
    /// unresolved symbols from the external manager, and attempts to
    /// resolve them using the provided library symbol registry.
    ///
    /// # Arguments
    ///
    /// * `ext_mgr` -- the external manager containing unresolved symbols.
    /// * `format` -- the executable format (must be ELF or Mach-O).
    /// * `library_symbols` -- a map of library name to known symbols in
    ///   that library, each with an optional external address.
    ///
    /// # Returns
    ///
    /// Returns the [`ExternalSymbolResolver`] with resolution results.
    pub fn analyze(
        &self,
        ext_mgr: &ExternalManagerDB,
        format: ExecutableFormat,
        library_symbols: &BTreeMap<String, BTreeMap<String, Option<Address>>>,
    ) -> Result<ExternalSymbolResolver, ResolverAnalyzerError> {
        if !self.can_analyze(format) {
            return Err(ResolverAnalyzerError::UnsupportedFormat(format.to_string()));
        }

        let mut resolver = ExternalSymbolResolver::new();

        // Register known library symbols
        for (lib_name, symbols) in library_symbols {
            for (sym_name, addr) in symbols {
                resolver.add_library_symbol(lib_name, sym_name, *addr);
            }
        }

        // Find unresolved symbols from the external manager
        // An unresolved symbol is one that has a label but the library
        // doesn't have a known program path (meaning it hasn't been
        // linked yet).
        for loc in ext_mgr.all_locations() {
            if let Some(label) = loc.label() {
                // If the library has no path, consider it unresolved
                let lib_name = loc.library_name();
                let has_path = ext_mgr.get_external_library_path(lib_name).is_some();

                if !has_path {
                    resolver.add_unresolved(UnresolvedSymbol::new(
                        label,
                        Some(lib_name),
                        loc.external_program_address(),
                        loc.source(),
                    ));
                }
            }
        }

        // Run resolution
        resolver.resolve();

        Ok(resolver)
    }
}

impl Default for ExternalSymbolResolverAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyzer_properties() {
        let analyzer = ExternalSymbolResolverAnalyzer::new();
        assert_eq!(analyzer.name(), "External Symbol Resolver");
        assert!(analyzer.is_enabled());
        assert!(analyzer.supports_one_time_analysis());
        assert!(!analyzer.description().is_empty());
    }

    #[test]
    fn test_can_analyze_elf() {
        let analyzer = ExternalSymbolResolverAnalyzer::new();
        assert!(analyzer.can_analyze(ExecutableFormat::Elf));
    }

    #[test]
    fn test_can_analyze_macho() {
        let analyzer = ExternalSymbolResolverAnalyzer::new();
        assert!(analyzer.can_analyze(ExecutableFormat::MachO));
    }

    #[test]
    fn test_cannot_analyze_pe() {
        let analyzer = ExternalSymbolResolverAnalyzer::new();
        assert!(!analyzer.can_analyze(ExecutableFormat::Pe));
    }

    #[test]
    fn test_cannot_analyze_unknown() {
        let analyzer = ExternalSymbolResolverAnalyzer::new();
        assert!(!analyzer.can_analyze(ExecutableFormat::Unknown));
    }

    #[test]
    fn test_analyze_unsupported_format() {
        let analyzer = ExternalSymbolResolverAnalyzer::new();
        let ext_mgr = ExternalManagerDB::new();
        let lib_symbols = BTreeMap::new();

        let result = analyzer.analyze(&ext_mgr, ExecutableFormat::Pe, &lib_symbols);
        assert!(result.is_err());
        match result.unwrap_err() {
            ResolverAnalyzerError::UnsupportedFormat(_) => {}
            _ => panic!("Expected UnsupportedFormat error"),
        }
    }

    #[test]
    fn test_analyze_resolves_symbols() {
        let analyzer = ExternalSymbolResolverAnalyzer::new();

        // Set up external manager with unresolved symbols
        let mut ext_mgr = ExternalManagerDB::new();
        ext_mgr.add_library("libc", SourceType::Imported).unwrap();
        ext_mgr
            .add_ext_function("libc", "printf", None, SourceType::Imported)
            .unwrap();
        ext_mgr
            .add_ext_function("libc", "malloc", None, SourceType::Imported)
            .unwrap();

        // Set up known library symbols
        let mut lib_symbols = BTreeMap::new();
        let mut libc_syms = BTreeMap::new();
        libc_syms.insert("printf".to_string(), Some(Address::new(0x1000)));
        libc_syms.insert("malloc".to_string(), Some(Address::new(0x2000)));
        lib_symbols.insert("libc".to_string(), libc_syms);

        let result = analyzer
            .analyze(&ext_mgr, ExecutableFormat::Elf, &lib_symbols)
            .unwrap();

        assert_eq!(result.resolved_symbols().len(), 2);
        assert!(!result.has_problem_libraries());
    }

    #[test]
    fn test_analyze_partial_resolution() {
        let analyzer = ExternalSymbolResolverAnalyzer::new();

        let mut ext_mgr = ExternalManagerDB::new();
        ext_mgr.add_library("libc", SourceType::Imported).unwrap();
        ext_mgr
            .add_ext_function("libc", "printf", None, SourceType::Imported)
            .unwrap();
        ext_mgr
            .add_ext_function("libc", "unknown_func", None, SourceType::Imported)
            .unwrap();

        // Only printf is known
        let mut lib_symbols = BTreeMap::new();
        let mut libc_syms = BTreeMap::new();
        libc_syms.insert("printf".to_string(), Some(Address::new(0x1000)));
        lib_symbols.insert("libc".to_string(), libc_syms);

        let result = analyzer
            .analyze(&ext_mgr, ExecutableFormat::Elf, &lib_symbols)
            .unwrap();

        assert_eq!(result.resolved_symbols().len(), 1);
        assert_eq!(result.unresolved_symbols().len(), 1);
        assert!(result.has_problem_libraries());
    }

    #[test]
    fn test_resolver_basic() {
        let mut resolver = ExternalSymbolResolver::new();

        resolver.add_library_symbol("libc", "printf", Some(Address::new(0x1000)));
        resolver.add_library_symbol("libc", "malloc", Some(Address::new(0x2000)));

        resolver.add_unresolved(UnresolvedSymbol::new(
            "printf",
            Some("libc"),
            Some(Address::new(0x401000)),
            SourceType::Imported,
        ));

        let results = resolver.resolve();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "printf");
        assert_eq!(results[0].library_name, "libc");
        assert_eq!(results[0].external_address, Some(Address::new(0x1000)));
    }

    #[test]
    fn test_resolver_cross_library_search() {
        let mut resolver = ExternalSymbolResolver::new();

        resolver.add_library_symbol("libm", "sin", Some(Address::new(0x3000)));

        // Unresolved symbol with wrong library hint
        resolver.add_unresolved(UnresolvedSymbol::new(
            "sin",
            Some("libc"),
            None,
            SourceType::Imported,
        ));

        let results = resolver.resolve();
        // Should find it in libm after failing in libc
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].library_name, "libm");
    }

    #[test]
    fn test_resolver_no_match() {
        let mut resolver = ExternalSymbolResolver::new();

        resolver.add_library_symbol("libc", "printf", Some(Address::new(0x1000)));

        resolver.add_unresolved(UnresolvedSymbol::new(
            "nonexistent_func",
            Some("libc"),
            None,
            SourceType::Imported,
        ));

        let results = resolver.resolve();
        assert_eq!(results.len(), 0);
        assert_eq!(resolver.unresolved_symbols().len(), 1);
        assert!(resolver.has_problem_libraries());
    }

    #[test]
    fn test_resolver_multiple_unresolved() {
        let mut resolver = ExternalSymbolResolver::new();

        resolver.add_library_symbol("libc", "printf", Some(Address::new(0x1000)));
        resolver.add_library_symbol("libc", "malloc", Some(Address::new(0x2000)));
        resolver.add_library_symbol("libm", "sin", Some(Address::new(0x3000)));

        resolver.add_unresolved(UnresolvedSymbol::new(
            "printf",
            Some("libc"),
            None,
            SourceType::Imported,
        ));
        resolver.add_unresolved(UnresolvedSymbol::new(
            "malloc",
            Some("libc"),
            None,
            SourceType::Imported,
        ));
        resolver.add_unresolved(UnresolvedSymbol::new(
            "sin",
            Some("libm"),
            None,
            SourceType::Imported,
        ));

        let results = resolver.resolve();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_resolver_log_info() {
        let mut resolver = ExternalSymbolResolver::new();

        resolver.add_library_symbol("libc", "printf", Some(Address::new(0x1000)));

        resolver.add_unresolved(UnresolvedSymbol::new(
            "printf",
            Some("libc"),
            None,
            SourceType::Imported,
        ));
        resolver.add_unresolved(UnresolvedSymbol::new(
            "unknown",
            Some("libc"),
            None,
            SourceType::Imported,
        ));

        resolver.resolve();

        let mut messages = Vec::new();
        resolver.log_info(|msg| messages.push(msg.to_string()), false);
        assert!(!messages.is_empty());
    }

    #[test]
    fn test_resolver_log_info_problems_only() {
        let mut resolver = ExternalSymbolResolver::new();

        resolver.add_library_symbol("libc", "printf", Some(Address::new(0x1000)));

        resolver.add_unresolved(UnresolvedSymbol::new(
            "printf",
            Some("libc"),
            None,
            SourceType::Imported,
        ));
        resolver.add_unresolved(UnresolvedSymbol::new(
            "unknown",
            Some("libc"),
            None,
            SourceType::Imported,
        ));

        resolver.resolve();

        let mut messages = Vec::new();
        resolver.log_info(|msg| messages.push(msg.to_string()), true);
        // Only problem library messages
        assert!(!messages.is_empty());
    }

    #[test]
    fn test_executable_format_display() {
        assert_eq!(ExecutableFormat::Elf.to_string(), "ELF");
        assert_eq!(ExecutableFormat::MachO.to_string(), "Mach-O");
        assert_eq!(ExecutableFormat::Pe.to_string(), "PE");
        assert_eq!(ExecutableFormat::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn test_analyzer_set_enabled() {
        let mut analyzer = ExternalSymbolResolverAnalyzer::new();
        assert!(analyzer.is_enabled());
        analyzer.set_enabled(false);
        assert!(!analyzer.is_enabled());
    }

    #[test]
    fn test_problem_library() {
        let prob = ProblemLibrary::new("libc", "not found", 5);
        assert_eq!(prob.name, "libc");
        assert_eq!(prob.reason, "not found");
        assert_eq!(prob.unresolved_count, 5);
    }

    #[test]
    fn test_resolved_symbol() {
        let resolved = ResolvedSymbol::new(
            "printf",
            "libc",
            Some(Address::new(0x1000)),
            Some(Address::new(0x401000)),
        );
        assert_eq!(resolved.name, "printf");
        assert_eq!(resolved.library_name, "libc");
        assert_eq!(resolved.external_address, Some(Address::new(0x1000)));
        assert_eq!(resolved.reference_address, Some(Address::new(0x401000)));
    }

    #[test]
    fn test_unresolved_symbol() {
        let sym = UnresolvedSymbol::new(
            "printf",
            Some("libc"),
            Some(Address::new(0x401000)),
            SourceType::Imported,
        );
        assert_eq!(sym.name, "printf");
        assert_eq!(sym.library_hint, Some("libc".to_string()));
        assert_eq!(sym.reference_address, Some(Address::new(0x401000)));
        assert_eq!(sym.source, SourceType::Imported);
    }
}
