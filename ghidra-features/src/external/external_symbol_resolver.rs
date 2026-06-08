//! ExternalSymbolResolver -- resolves dangling external function symbols.
//!
//! Ported from `ghidra.program.util.ExternalSymbolResolver`.
//!
//! Moves dangling external function symbols found in the
//! `EXTERNAL/UNKNOWN` namespace into the namespace of the external
//! library that publishes a matching symbol.
//!
//! The resolver operates on one or more programs that have been queued
//! via [`ExternalSymbolResolver::add_program_to_fixup`].  When
//! [`ExternalSymbolResolver::fix_unresolved_external_symbols`] is
//! called, each program's unresolved external symbols are matched
//! against the exported symbols of the program's required libraries.
//!
//! # Examples
//!
//! ```rust
//! use ghidra_features::external::external_symbol_resolver::{
//!     ExternalSymbolResolver, ProgramSymbolTable, LibraryExportTable,
//! };
//! use ghidra_features::external::ExternalManagerDB;
//! use ghidra_core::symbol::SourceType;
//! use ghidra_core::addr::Address;
//!
//! let mut resolver = ExternalSymbolResolver::new();
//!
//! // Register a program with unresolved symbols
//! let mut ext_mgr = ExternalManagerDB::new();
//! ext_mgr.add_library("<UNKNOWN>", SourceType::Imported).unwrap();
//! ext_mgr.add_ext_function("<UNKNOWN>", "printf", None, SourceType::Imported).unwrap();
//!
//! let mut symbol_table = ProgramSymbolTable::new();
//! symbol_table.add_unknown_symbol("printf", None, SourceType::Imported);
//! let export_tables = vec![
//!     LibraryExportTable::new("libc", vec!["printf".to_string(), "malloc".to_string()]),
//! ];
//!
//! resolver.add_program_to_fixup("prog1", ext_mgr, symbol_table);
//! let results = resolver.fix_unresolved_external_symbols(&export_tables);
//! assert_eq!(results.len(), 1);
//! assert_eq!(results[0].resolved_count, 1);
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ghidra_core::addr::Address;
use ghidra_core::symbol::SourceType;

use super::external_location_db::ExternalLocationDB;
use super::external_manager_db::{ExternalManagerDB, UNKNOWN_LIBRARY};

// ---------------------------------------------------------------------------
// ProgramSymbolTable
// ---------------------------------------------------------------------------

/// Simplified symbol table for a program.
///
/// In the Java implementation this is backed by the program's
/// `SymbolTable`.  This struct provides the minimum API needed by the
/// resolver: querying symbols in the EXTERNAL/UNKNOWN namespace and
/// checking if a symbol is an external entry point.
#[derive(Debug, Clone, Default)]
pub struct ProgramSymbolTable {
    /// Symbols in the EXTERNAL/UNKNOWN namespace.
    /// Maps symbol ID to symbol info.
    unknown_symbols: BTreeMap<u64, SymbolInfo>,
    /// Next symbol ID.
    next_id: u64,
    /// Exported symbol names (external entry points).
    exported_names: BTreeSet<String>,
}

/// Information about a symbol in the program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolInfo {
    /// The symbol ID.
    pub id: u64,
    /// The symbol name.
    pub name: String,
    /// The address of the symbol.
    pub address: Option<Address>,
    /// Whether this symbol is an external entry point.
    pub is_external_entry_point: bool,
    /// The source type.
    pub source: SourceType,
}

impl ProgramSymbolTable {
    /// Create a new empty symbol table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a symbol to the EXTERNAL/UNKNOWN namespace.
    ///
    /// Returns the assigned symbol ID.
    pub fn add_unknown_symbol(
        &mut self,
        name: impl Into<String>,
        address: Option<Address>,
        source: SourceType,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.unknown_symbols.insert(
            id,
            SymbolInfo {
                id,
                name: name.into(),
                address,
                is_external_entry_point: false,
                source,
            },
        );
        id
    }

    /// Mark a symbol as an external entry point.
    pub fn set_external_entry_point(&mut self, id: u64, is_entry: bool) {
        if let Some(sym) = self.unknown_symbols.get_mut(&id) {
            sym.is_external_entry_point = is_entry;
        }
    }

    /// Register an exported symbol name.
    pub fn add_export(&mut self, name: impl Into<String>) {
        self.exported_names.insert(name.into());
    }

    /// Get all symbol IDs in the EXTERNAL/UNKNOWN namespace.
    pub fn unknown_symbol_ids(&self) -> Vec<u64> {
        self.unknown_symbols.keys().copied().collect()
    }

    /// Get symbol info by ID.
    pub fn get_symbol(&self, id: u64) -> Option<&SymbolInfo> {
        self.unknown_symbols.get(&id)
    }

    /// Get mutable symbol info by ID.
    pub fn get_symbol_mut(&mut self, id: u64) -> Option<&mut SymbolInfo> {
        self.unknown_symbols.get_mut(&id)
    }

    /// Remove a symbol by ID.
    pub fn remove_symbol(&mut self, id: u64) -> Option<SymbolInfo> {
        self.unknown_symbols.remove(&id)
    }

    /// Check if a name is an exported symbol.
    pub fn is_exported_symbol(&self, name: &str) -> bool {
        self.exported_names.contains(name)
    }

    /// Returns the number of symbols in the EXTERNAL/UNKNOWN namespace.
    pub fn unknown_symbol_count(&self) -> usize {
        self.unknown_symbols.len()
    }
}

// ---------------------------------------------------------------------------
// LibraryExportTable
// ---------------------------------------------------------------------------

/// Represents the exported symbols of an external library program.
///
/// In the Java implementation this comes from opening the library
/// program and querying its symbol table for external entry points.
#[derive(Debug, Clone)]
pub struct LibraryExportTable {
    /// The library name.
    pub library_name: String,
    /// The project path to the library program.
    pub program_path: Option<String>,
    /// Exported symbol names.
    exports: BTreeSet<String>,
}

impl LibraryExportTable {
    /// Create a new export table.
    pub fn new(
        library_name: impl Into<String>,
        exports: Vec<String>,
    ) -> Self {
        Self {
            library_name: library_name.into(),
            program_path: None,
            exports: exports.into_iter().collect(),
        }
    }

    /// Create a new export table with a program path.
    pub fn with_path(
        library_name: impl Into<String>,
        program_path: impl Into<String>,
        exports: Vec<String>,
    ) -> Self {
        Self {
            library_name: library_name.into(),
            program_path: Some(program_path.into()),
            exports: exports.into_iter().collect(),
        }
    }

    /// Check if this library exports the given symbol name.
    pub fn has_export(&self, name: &str) -> bool {
        self.exports.contains(name)
    }

    /// Get all exported symbol names.
    pub fn exports(&self) -> &BTreeSet<String> {
        &self.exports
    }

    /// Returns the number of exported symbols.
    pub fn export_count(&self) -> usize {
        self.exports.len()
    }
}

// ---------------------------------------------------------------------------
// ExtLibInfo
// ---------------------------------------------------------------------------

/// Information about an external library that is being searched for
/// symbol resolution.
///
/// This corresponds to the inner `ExtLibInfo` class in the Java
/// implementation.
#[derive(Debug, Clone)]
pub struct ExtLibInfo {
    /// The library name.
    name: String,
    /// The associated program path (if any).
    associated_program_path: Option<String>,
    /// Symbols resolved to this library.
    resolved_symbols: Vec<String>,
    /// Problem encountered while accessing the library (if any).
    problem: Option<String>,
}

impl ExtLibInfo {
    /// Create new external library info.
    pub fn new(
        name: impl Into<String>,
        associated_program_path: Option<String>,
        problem: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            associated_program_path,
            resolved_symbols: Vec::new(),
            problem,
        }
    }

    /// Returns the library name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the associated program path.
    pub fn associated_program_path(&self) -> Option<&str> {
        self.associated_program_path.as_deref()
    }

    /// Returns the symbols resolved to this library.
    pub fn resolved_symbols(&self) -> &[String] {
        &self.resolved_symbols
    }

    /// Returns the problem message, if any.
    pub fn problem(&self) -> Option<&str> {
        self.problem.as_deref()
    }

    /// Returns true if there was a problem accessing this library.
    pub fn has_problem(&self) -> bool {
        self.problem.is_some()
    }
}

// ---------------------------------------------------------------------------
// Resolution result
// ---------------------------------------------------------------------------

/// The result of resolving external symbols for a single program.
#[derive(Debug, Clone)]
pub struct ResolutionResult {
    /// Total number of external symbols found.
    pub total_external_symbols: usize,
    /// Number of symbols that were resolved.
    pub resolved_count: usize,
    /// Number of symbols that remain unresolved.
    pub unresolved_count: usize,
    /// Libraries that had problems.
    pub problem_libraries: Vec<String>,
    /// Per-library resolution details.
    pub library_details: Vec<LibraryResolutionDetail>,
}

/// Details about resolution for a single library.
#[derive(Debug, Clone)]
pub struct LibraryResolutionDetail {
    /// The library name.
    pub library_name: String,
    /// The associated program path.
    pub program_path: Option<String>,
    /// Symbols resolved to this library.
    pub resolved_symbols: Vec<String>,
    /// Problem message, if any.
    pub problem: Option<String>,
}

// ---------------------------------------------------------------------------
// ProgramSymbolResolver (per-program resolver)
// ---------------------------------------------------------------------------

/// Resolves external symbols for a single program.
///
/// This is the Rust equivalent of the Java inner class
/// `ProgramSymbolResolver`.  It holds a reference to the program's
/// external manager and symbol table, and performs the actual
/// resolution logic.
#[derive(Debug)]
pub struct ProgramSymbolResolver {
    /// A label for this program (e.g., project path).
    program_path: String,
    /// The program's external manager.
    ext_mgr: ExternalManagerDB,
    /// The program's symbol table.
    symbol_table: ProgramSymbolTable,
    /// External library info gathered during resolution.
    ext_libs: Vec<ExtLibInfo>,
    /// IDs of unresolved external functions.
    unresolved_ids: Vec<u64>,
    /// Total external symbol count.
    external_symbol_count: usize,
}

impl ProgramSymbolResolver {
    /// Create a new resolver for a program.
    pub fn new(
        program_path: impl Into<String>,
        ext_mgr: ExternalManagerDB,
        symbol_table: ProgramSymbolTable,
    ) -> Self {
        Self {
            program_path: program_path.into(),
            ext_mgr,
            symbol_table,
            ext_libs: Vec::new(),
            unresolved_ids: Vec::new(),
            external_symbol_count: 0,
        }
    }

    /// Returns the program path.
    pub fn program_path(&self) -> &str {
        &self.program_path
    }

    /// Returns the number of resolved symbols.
    pub fn resolved_symbol_count(&self) -> usize {
        self.external_symbol_count - self.unresolved_ids.len()
    }

    /// Get the IDs of unresolved external functions in the
    /// EXTERNAL/UNKNOWN namespace.
    ///
    /// This corresponds to `getUnresolvedExternalFunctionIds()` in the
    /// Java implementation.
    fn get_unresolved_external_function_ids(&self) -> Vec<u64> {
        let mut ids = Vec::new();

        // Check if the UNKNOWN library exists
        if !self.ext_mgr.contains_library(UNKNOWN_LIBRARY) {
            return ids;
        }

        // Get all symbols in the EXTERNAL/UNKNOWN namespace
        for &sym_id in self.symbol_table.unknown_symbol_ids().iter() {
            if let Some(sym) = self.symbol_table.get_symbol(sym_id) {
                // Only include symbols that are not from DEFAULT source
                // (mirrors the Java check: s.getSource() != SourceType.DEFAULT)
                if sym.source != SourceType::Default {
                    ids.push(sym_id);
                }
            }
        }

        ids
    }

    /// Get the list of libraries to search for resolution.
    ///
    /// This corresponds to `getLibsToSearch()` in the Java
    /// implementation.
    fn get_libs_to_search(
        &self,
        export_tables: &[LibraryExportTable],
    ) -> Vec<ExtLibInfo> {
        let mut result = Vec::new();

        // Get library names from the external manager (in search order)
        for lib_name in self.ext_mgr.get_library_names() {
            if lib_name == UNKNOWN_LIBRARY {
                continue;
            }

            let lib_info = self.ext_mgr.get_library_info(&lib_name);
            let lib_path = lib_info.and_then(|i| i.path.clone());

            // Find matching export table
            let export_table = export_tables
                .iter()
                .find(|t| t.library_name == lib_name);

            let problem = if lib_path.is_some() && export_table.is_none() {
                Some(format!("Library program not found: {}", lib_path.as_deref().unwrap_or("")))
            } else {
                None
            };

            result.push(ExtLibInfo::new(&lib_name, lib_path, problem));
        }

        result
    }

    /// Resolve symbols to a specific library.
    ///
    /// This corresponds to `resolveSymbolsToLibrary()` in the Java
    /// implementation.  For each unresolved symbol, checks if the
    /// library exports a symbol with a matching name.
    fn resolve_symbols_to_library(
        &mut self,
        ext_lib: &mut ExtLibInfo,
        export_table: Option<&LibraryExportTable>,
    ) {
        let mut resolved_ids = Vec::new();

        for &sym_id in &self.unresolved_ids {
            let sym = match self.symbol_table.get_symbol(sym_id) {
                Some(s) => s.clone(),
                None => {
                    // Symbol was concurrently removed
                    resolved_ids.push(sym_id);
                    continue;
                }
            };

            // Get the external location for this symbol
            let ext_loc_name = self
                .ext_mgr
                .get_external_locations_by_label(&sym.name)
                .first()
                .map(|loc| {
                    loc.original_imported_name()
                        .unwrap_or_else(|| loc.label().unwrap_or(&sym.name))
                        .to_string()
                })
                .unwrap_or_else(|| sym.name.clone());

            // Check if the library exports this symbol
            let is_exported = export_table
                .map(|t| t.has_export(&ext_loc_name))
                .unwrap_or(false);

            if is_exported {
                resolved_ids.push(sym_id);
                ext_lib.resolved_symbols.push(sym.name.clone());
            }
        }

        // Remove resolved IDs from the unresolved list
        self.unresolved_ids
            .retain(|id| !resolved_ids.contains(id));
    }

    /// Run the resolution process for this program.
    ///
    /// This corresponds to `resolveExternalSymbols()` in the Java
    /// implementation.
    pub fn resolve_external_symbols(
        &mut self,
        export_tables: &[LibraryExportTable],
    ) -> ResolutionResult {
        self.unresolved_ids = self.get_unresolved_external_function_ids();
        self.external_symbol_count = self.unresolved_ids.len();

        if self.unresolved_ids.is_empty() {
            return ResolutionResult {
                total_external_symbols: 0,
                resolved_count: 0,
                unresolved_count: 0,
                problem_libraries: Vec::new(),
                library_details: Vec::new(),
            };
        }

        self.ext_libs = self.get_libs_to_search(export_tables);

        if !self.ext_libs.is_empty() {
            // Move ext_libs out of self to avoid borrow conflicts
            let mut ext_libs = std::mem::take(&mut self.ext_libs);
            for ext_lib in &mut ext_libs {
                let export_table = export_tables
                    .iter()
                    .find(|t| t.library_name == ext_lib.name);
                self.resolve_symbols_to_library(ext_lib, export_table);
            }
            self.ext_libs = ext_libs;
        }

        // For any remaining unresolved symbols (e.g., in the UNKNOWN library),
        // try to match them directly against all export tables.
        if !self.unresolved_ids.is_empty() {
            let mut resolved_ids = Vec::new();
            for &sym_id in &self.unresolved_ids {
                if let Some(sym) = self.symbol_table.get_symbol(sym_id) {
                    // Get the name to search for, checking external locations
                    // for original imported names (mangled names)
                    let search_name = self
                        .ext_mgr
                        .get_external_locations_by_label(&sym.name)
                        .first()
                        .and_then(|loc| loc.original_imported_name())
                        .unwrap_or(&sym.name);
                    for table in export_tables {
                        if table.has_export(search_name) {
                            resolved_ids.push(sym_id);
                            break;
                        }
                    }
                }
            }
            self.unresolved_ids
                .retain(|id| !resolved_ids.contains(id));
        }

        let resolved_count = self.external_symbol_count - self.unresolved_ids.len();
        let problem_libraries: Vec<String> = self
            .ext_libs
            .iter()
            .filter(|l| l.has_problem())
            .map(|l| l.name().to_string())
            .collect();

        let library_details: Vec<LibraryResolutionDetail> = self
            .ext_libs
            .iter()
            .map(|l| LibraryResolutionDetail {
                library_name: l.name().to_string(),
                program_path: l.associated_program_path().map(|s| s.to_string()),
                resolved_symbols: l.resolved_symbols().to_vec(),
                problem: l.problem().map(|s| s.to_string()),
            })
            .collect();

        ResolutionResult {
            total_external_symbols: self.external_symbol_count,
            resolved_count,
            unresolved_count: self.unresolved_ids.len(),
            problem_libraries,
            library_details,
        }
    }

    /// Generate a log of the resolution results.
    ///
    /// This corresponds to `log()` in the Java implementation.
    pub fn log<F: FnMut(&ProgramSymbolResolver), G: FnMut(&str)>(
        &self,
        mut log_detail: F,
        mut log_msg: G,
        short_summary: bool,
    ) {
        let changed = self.unresolved_ids.len() != self.external_symbol_count;
        let has_some_libraries = self
            .ext_libs
            .iter()
            .any(|l| l.has_problem() || l.associated_program_path().is_some());

        if self.ext_libs.is_empty() && self.external_symbol_count == 0 {
            return;
        }

        if !changed && !has_some_libraries {
            log_msg(&format!(
                "Resolving External Symbols of [{}] - {} unresolved symbols, no external libraries configured - skipping",
                self.program_path, self.external_symbol_count
            ));
            return;
        }

        log_msg(&format!(
            "Resolving External Symbols of [{}]{}",
            self.program_path,
            if short_summary { " - Summary" } else { "" }
        ));
        log_msg(&format!(
            "\t{} external symbols resolved, {} remain unresolved",
            self.resolved_symbol_count(),
            self.unresolved_ids.len()
        ));

        for ext_lib in &self.ext_libs {
            let logged_path = ext_lib
                .associated_program_path()
                .unwrap_or("missing");

            if let Some(problem) = ext_lib.problem() {
                log_msg(&format!(
                    "\t[{}] -> {}, {}",
                    ext_lib.name(),
                    logged_path,
                    problem
                ));
            } else if ext_lib.associated_program_path().is_some() {
                log_msg(&format!(
                    "\t[{}] -> {}, {} new symbols resolved",
                    ext_lib.name(),
                    logged_path,
                    ext_lib.resolved_symbols().len()
                ));
            } else {
                log_msg(&format!(
                    "\t[{}] -> {}",
                    ext_lib.name(),
                    logged_path
                ));
            }

            if !short_summary {
                for symbol_name in ext_lib.resolved_symbols() {
                    log_msg(&format!("\t\t[{}]", symbol_name));
                }
            }
        }

        if !short_summary && changed {
            if !self.unresolved_ids.is_empty() {
                log_msg(&format!(
                    "\tUnresolved remaining {}:",
                    self.unresolved_ids.len()
                ));
                for &sym_id in &self.unresolved_ids {
                    if let Some(sym) = self.symbol_table.get_symbol(sym_id) {
                        log_msg(&format!("\t\t[{}]", sym.name));
                    }
                }
            }
        }

        // Call the detail callback for each library
        for _ext_lib in &self.ext_libs {
            log_detail(self);
        }
    }
}

// ---------------------------------------------------------------------------
// ExternalSymbolResolver
// ---------------------------------------------------------------------------

/// Resolves dangling external function symbols found in the
/// `EXTERNAL/UNKNOWN` namespace into the namespace of the external
/// library that publishes a matching symbol.
///
/// This is the Rust port of Ghidra's `ExternalSymbolResolver`.  It
/// manages a collection of programs that need their external symbols
/// resolved, and performs the resolution when
/// [`fix_unresolved_external_symbols`](Self::fix_unresolved_external_symbols)
/// is called.
///
/// # Examples
///
/// ```rust
/// use ghidra_features::external::external_symbol_resolver::{
///     ExternalSymbolResolver, ProgramSymbolTable, LibraryExportTable,
/// };
/// use ghidra_features::external::ExternalManagerDB;
/// use ghidra_core::symbol::SourceType;
///
/// let mut resolver = ExternalSymbolResolver::new();
///
/// let mut ext_mgr = ExternalManagerDB::new();
/// ext_mgr.add_library("<UNKNOWN>", SourceType::Default).unwrap();
/// ext_mgr.add_ext_function("<UNKNOWN>", "printf", None, SourceType::Imported).unwrap();
///
/// let symbol_table = ProgramSymbolTable::new();
/// let export_tables = vec![
///     LibraryExportTable::new("libc", vec!["printf".to_string()]),
/// ];
///
/// resolver.add_program_to_fixup("prog1", ext_mgr, symbol_table);
/// let results = resolver.fix_unresolved_external_symbols(&export_tables);
/// assert_eq!(results.len(), 1);
/// ```
#[derive(Debug, Default)]
pub struct ExternalSymbolResolver {
    /// Programs queued for resolution.
    programs_to_fix: Vec<ProgramSymbolResolver>,
    /// Problem libraries encountered across all programs.
    problem_libraries: BTreeMap<String, String>,
}

impl ExternalSymbolResolver {
    /// Create a new resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Queue a program for external symbol resolution.
    ///
    /// This corresponds to `addProgramToFixup(Program)` in the Java
    /// implementation.
    pub fn add_program_to_fixup(
        &mut self,
        program_path: impl Into<String>,
        ext_mgr: ExternalManagerDB,
        symbol_table: ProgramSymbolTable,
    ) {
        let path = program_path.into();
        self.programs_to_fix
            .push(ProgramSymbolResolver::new(&path, ext_mgr, symbol_table));
    }

    /// Returns `true` if there were errors opening external library
    /// programs.
    pub fn has_problem_libraries(&self) -> bool {
        !self.problem_libraries.is_empty()
    }

    /// Returns the problem libraries.
    pub fn problem_libraries(&self) -> &BTreeMap<String, String> {
        &self.problem_libraries
    }

    /// Resolve all queued programs' external symbols.
    ///
    /// This corresponds to `fixUnresolvedExternalSymbols()` in the Java
    /// implementation.
    pub fn fix_unresolved_external_symbols(
        &mut self,
        export_tables: &[LibraryExportTable],
    ) -> Vec<ResolutionResult> {
        let mut results = Vec::new();

        for psr in &mut self.programs_to_fix {
            let result = psr.resolve_external_symbols(export_tables);

            // Track problem libraries
            for lib in &result.problem_libraries {
                self.problem_libraries
                    .insert(lib.clone(), "Library not found".to_string());
            }

            results.push(result);
        }

        results
    }

    /// Log information about the resolution results.
    ///
    /// This corresponds to `logInfo(Consumer, boolean)` in the Java
    /// implementation.
    pub fn log_info<F: FnMut(&str)>(&self, mut logger: F, short_summary: bool) {
        for psr in &self.programs_to_fix {
            psr.log(
                |_| {},
                |msg| logger(msg),
                short_summary,
            );
        }
    }

    /// Returns the number of queued programs.
    pub fn program_count(&self) -> usize {
        self.programs_to_fix.len()
    }

    /// Returns the total number of resolved symbols across all
    /// programs.
    pub fn total_resolved(&self) -> usize {
        self.programs_to_fix
            .iter()
            .map(|psr| psr.resolved_symbol_count())
            .sum()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ext_mgr_with_unknown() -> ExternalManagerDB {
        let mut mgr = ExternalManagerDB::new();
        mgr.add_library(UNKNOWN_LIBRARY, SourceType::Default)
            .unwrap();
        mgr
    }

    #[test]
    fn test_program_symbol_table_basic() {
        let mut table = ProgramSymbolTable::new();
        let id = table.add_unknown_symbol("printf", None, SourceType::Imported);
        assert_eq!(table.unknown_symbol_count(), 1);
        assert_eq!(table.get_symbol(id).unwrap().name, "printf");
    }

    #[test]
    fn test_program_symbol_table_exports() {
        let mut table = ProgramSymbolTable::new();
        table.add_export("printf");
        table.add_export("malloc");
        assert!(table.is_exported_symbol("printf"));
        assert!(table.is_exported_symbol("malloc"));
        assert!(!table.is_exported_symbol("unknown"));
    }

    #[test]
    fn test_library_export_table() {
        let table = LibraryExportTable::new(
            "libc",
            vec!["printf".to_string(), "malloc".to_string()],
        );
        assert_eq!(table.library_name, "libc");
        assert!(table.has_export("printf"));
        assert!(table.has_export("malloc"));
        assert!(!table.has_export("unknown"));
        assert_eq!(table.export_count(), 2);
    }

    #[test]
    fn test_library_export_table_with_path() {
        let table = LibraryExportTable::with_path(
            "libc",
            "/usr/lib/libc.so",
            vec!["printf".to_string()],
        );
        assert_eq!(table.program_path, Some("/usr/lib/libc.so".to_string()));
    }

    #[test]
    fn test_ext_lib_info() {
        let info = ExtLibInfo::new("libc", Some("/usr/lib/libc.so".to_string()), None);
        assert_eq!(info.name(), "libc");
        assert_eq!(
            info.associated_program_path(),
            Some("/usr/lib/libc.so")
        );
        assert!(!info.has_problem());
    }

    #[test]
    fn test_ext_lib_info_with_problem() {
        let info = ExtLibInfo::new("libfoo", None, Some("not found".to_string()));
        assert!(info.has_problem());
        assert_eq!(info.problem(), Some("not found"));
    }

    #[test]
    fn test_resolver_no_programs() {
        let mut resolver = ExternalSymbolResolver::new();
        let export_tables: Vec<LibraryExportTable> = Vec::new();
        let results = resolver.fix_unresolved_external_symbols(&export_tables);
        assert!(results.is_empty());
        assert_eq!(resolver.program_count(), 0);
        assert!(!resolver.has_problem_libraries());
    }

    #[test]
    fn test_resolver_no_unresolved_symbols() {
        let mut resolver = ExternalSymbolResolver::new();

        let ext_mgr = ExternalManagerDB::new();
        let symbol_table = ProgramSymbolTable::new();

        resolver.add_program_to_fixup("prog1", ext_mgr, symbol_table);

        let export_tables: Vec<LibraryExportTable> = Vec::new();
        let results = resolver.fix_unresolved_external_symbols(&export_tables);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].total_external_symbols, 0);
        assert_eq!(results[0].resolved_count, 0);
    }

    #[test]
    fn test_resolver_resolves_symbols() {
        let mut resolver = ExternalSymbolResolver::new();

        let mut ext_mgr = make_ext_mgr_with_unknown();
        ext_mgr
            .add_ext_function(UNKNOWN_LIBRARY, "printf", None, SourceType::Imported)
            .unwrap();

        let mut symbol_table = ProgramSymbolTable::new();
        let sym_id = symbol_table.add_unknown_symbol("printf", None, SourceType::Imported);
        // Mark as non-default source (matches Java check)
        symbol_table.get_symbol_mut(sym_id).unwrap().source = SourceType::Imported;

        resolver.add_program_to_fixup("prog1", ext_mgr, symbol_table);

        let export_tables = vec![LibraryExportTable::new(
            "libc",
            vec!["printf".to_string(), "malloc".to_string()],
        )];

        let results = resolver.fix_unresolved_external_symbols(&export_tables);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].total_external_symbols, 1);
        assert_eq!(results[0].resolved_count, 1);
        assert_eq!(results[0].unresolved_count, 0);
    }

    #[test]
    fn test_resolver_partial_resolution() {
        let mut resolver = ExternalSymbolResolver::new();

        let mut ext_mgr = make_ext_mgr_with_unknown();
        ext_mgr
            .add_ext_function(UNKNOWN_LIBRARY, "printf", None, SourceType::Imported)
            .unwrap();
        ext_mgr
            .add_ext_function(UNKNOWN_LIBRARY, "unknown_func", None, SourceType::Imported)
            .unwrap();

        let mut symbol_table = ProgramSymbolTable::new();
        let id1 = symbol_table.add_unknown_symbol("printf", None, SourceType::Imported);
        symbol_table.get_symbol_mut(id1).unwrap().source = SourceType::Imported;
        let id2 = symbol_table.add_unknown_symbol("unknown_func", None, SourceType::Imported);
        symbol_table.get_symbol_mut(id2).unwrap().source = SourceType::Imported;

        resolver.add_program_to_fixup("prog1", ext_mgr, symbol_table);

        // Only printf is known
        let export_tables = vec![LibraryExportTable::new(
            "libc",
            vec!["printf".to_string()],
        )];

        let results = resolver.fix_unresolved_external_symbols(&export_tables);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].total_external_symbols, 2);
        assert_eq!(results[0].resolved_count, 1);
        assert_eq!(results[0].unresolved_count, 1);
    }

    #[test]
    fn test_resolver_multiple_programs() {
        let mut resolver = ExternalSymbolResolver::new();

        // Program 1
        let mut ext_mgr1 = make_ext_mgr_with_unknown();
        ext_mgr1
            .add_ext_function(UNKNOWN_LIBRARY, "printf", None, SourceType::Imported)
            .unwrap();
        let mut sym_table1 = ProgramSymbolTable::new();
        let id1 = sym_table1.add_unknown_symbol("printf", None, SourceType::Imported);
        sym_table1.get_symbol_mut(id1).unwrap().source = SourceType::Imported;
        resolver.add_program_to_fixup("prog1", ext_mgr1, sym_table1);

        // Program 2
        let mut ext_mgr2 = make_ext_mgr_with_unknown();
        ext_mgr2
            .add_ext_function(UNKNOWN_LIBRARY, "malloc", None, SourceType::Imported)
            .unwrap();
        let mut sym_table2 = ProgramSymbolTable::new();
        let id2 = sym_table2.add_unknown_symbol("malloc", None, SourceType::Imported);
        sym_table2.get_symbol_mut(id2).unwrap().source = SourceType::Imported;
        resolver.add_program_to_fixup("prog2", ext_mgr2, sym_table2);

        let export_tables = vec![LibraryExportTable::new(
            "libc",
            vec!["printf".to_string(), "malloc".to_string()],
        )];

        let results = resolver.fix_unresolved_external_symbols(&export_tables);

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].resolved_count, 1);
        assert_eq!(results[1].resolved_count, 1);
        assert_eq!(resolver.total_resolved(), 2);
    }

    #[test]
    fn test_resolver_skips_default_source() {
        let mut resolver = ExternalSymbolResolver::new();

        let mut ext_mgr = make_ext_mgr_with_unknown();
        ext_mgr
            .add_ext_function(UNKNOWN_LIBRARY, "printf", None, SourceType::Default)
            .unwrap();

        let mut symbol_table = ProgramSymbolTable::new();
        // Default source should be skipped
        symbol_table.add_unknown_symbol("printf", None, SourceType::Default);

        resolver.add_program_to_fixup("prog1", ext_mgr, symbol_table);

        let export_tables = vec![LibraryExportTable::new(
            "libc",
            vec!["printf".to_string()],
        )];

        let results = resolver.fix_unresolved_external_symbols(&export_tables);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].total_external_symbols, 0);
        assert_eq!(results[0].resolved_count, 0);
    }

    #[test]
    fn test_resolver_with_original_imported_name() {
        let mut resolver = ExternalSymbolResolver::new();

        let mut ext_mgr = make_ext_mgr_with_unknown();
        // Add a location with an original imported name (mangled)
        let mut loc = ExternalLocationDB::new_function(
            UNKNOWN_LIBRARY,
            "demangled_printf",
            None,
            SourceType::Imported,
        );
        loc.set_original_imported_name(Some("_printf".to_string()));
        ext_mgr.add_external_location(loc).unwrap();

        let mut symbol_table = ProgramSymbolTable::new();
        let id = symbol_table.add_unknown_symbol("demangled_printf", None, SourceType::Imported);
        symbol_table.get_symbol_mut(id).unwrap().source = SourceType::Imported;

        resolver.add_program_to_fixup("prog1", ext_mgr, symbol_table);

        // Library exports the mangled name
        let export_tables = vec![LibraryExportTable::new(
            "libc",
            vec!["_printf".to_string()],
        )];

        let results = resolver.fix_unresolved_external_symbols(&export_tables);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].resolved_count, 1);
    }

    #[test]
    fn test_resolver_no_matching_library() {
        let mut resolver = ExternalSymbolResolver::new();

        let mut ext_mgr = make_ext_mgr_with_unknown();
        ext_mgr
            .add_library("libfoo", SourceType::Imported)
            .unwrap();
        ext_mgr
            .add_ext_function(UNKNOWN_LIBRARY, "printf", None, SourceType::Imported)
            .unwrap();

        let mut symbol_table = ProgramSymbolTable::new();
        let id = symbol_table.add_unknown_symbol("printf", None, SourceType::Imported);
        symbol_table.get_symbol_mut(id).unwrap().source = SourceType::Imported;

        resolver.add_program_to_fixup("prog1", ext_mgr, symbol_table);

        // No export tables provided -- library has no program
        let export_tables: Vec<LibraryExportTable> = Vec::new();

        let results = resolver.fix_unresolved_external_symbols(&export_tables);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].resolved_count, 0);
        assert_eq!(results[0].unresolved_count, 1);
    }

    #[test]
    fn test_resolution_result_fields() {
        let result = ResolutionResult {
            total_external_symbols: 10,
            resolved_count: 7,
            unresolved_count: 3,
            problem_libraries: vec!["libfoo".to_string()],
            library_details: vec![LibraryResolutionDetail {
                library_name: "libc".to_string(),
                program_path: Some("/usr/lib/libc.so".to_string()),
                resolved_symbols: vec!["printf".to_string()],
                problem: None,
            }],
        };

        assert_eq!(result.total_external_symbols, 10);
        assert_eq!(result.resolved_count, 7);
        assert_eq!(result.unresolved_count, 3);
        assert_eq!(result.problem_libraries.len(), 1);
        assert_eq!(result.library_details.len(), 1);
        assert_eq!(result.library_details[0].library_name, "libc");
    }

    #[test]
    fn test_log_info() {
        let mut resolver = ExternalSymbolResolver::new();

        let mut ext_mgr = make_ext_mgr_with_unknown();
        ext_mgr
            .add_ext_function(UNKNOWN_LIBRARY, "printf", None, SourceType::Imported)
            .unwrap();

        let mut symbol_table = ProgramSymbolTable::new();
        let id = symbol_table.add_unknown_symbol("printf", None, SourceType::Imported);
        symbol_table.get_symbol_mut(id).unwrap().source = SourceType::Imported;

        resolver.add_program_to_fixup("prog1", ext_mgr, symbol_table);

        let export_tables = vec![LibraryExportTable::new(
            "libc",
            vec!["printf".to_string()],
        )];

        resolver.fix_unresolved_external_symbols(&export_tables);

        let mut messages = Vec::new();
        resolver.log_info(|msg| messages.push(msg.to_string()), false);
        assert!(!messages.is_empty());
    }

    #[test]
    fn test_program_symbol_table_remove() {
        let mut table = ProgramSymbolTable::new();
        let id = table.add_unknown_symbol("test", None, SourceType::Imported);
        assert_eq!(table.unknown_symbol_count(), 1);

        let removed = table.remove_symbol(id);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "test");
        assert_eq!(table.unknown_symbol_count(), 0);
    }

    #[test]
    fn test_program_symbol_table_entry_point() {
        let mut table = ProgramSymbolTable::new();
        let id = table.add_unknown_symbol("main", None, SourceType::Imported);
        table.set_external_entry_point(id, true);

        let sym = table.get_symbol(id).unwrap();
        assert!(sym.is_external_entry_point);
    }
}
