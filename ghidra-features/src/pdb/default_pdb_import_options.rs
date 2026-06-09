//! Default PDB Import Options -- options controlling PDB file import.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb.DefaultPdbImportOptions`
//! and `ghidra.app.util.pdb.PdbParserConstants`.
//!
//! These options control how a PDB file is imported into a Ghidra program,
//! including what information to load, how to handle conflicts with existing
//! data types and symbols, and various processing preferences.

use std::fmt;

use super::pdb_applicator_options::{
    ObjectOrientedClassLayout, PdbApplicatorControl, PdbApplicatorOptions,
};
use super::find_option::{FindOption, FindOptions};

// =============================================================================
// PDB Import Source
// =============================================================================

/// The source from which a PDB file was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PdbImportSource {
    /// PDB was loaded from a file path specified by the user.
    UserSpecified,
    /// PDB was found embedded in the PE file.
    Embedded,
    /// PDB was found in the same directory as the binary.
    SameDirectory,
    /// PDB was downloaded from a symbol server.
    SymbolServer,
    /// PDB was found in a local symbol store.
    LocalSymbolStore,
    /// PDB source is unknown.
    Unknown,
}

impl PdbImportSource {
    /// Get the human-readable label for this source.
    pub fn label(&self) -> &'static str {
        match self {
            PdbImportSource::UserSpecified => "User Specified",
            PdbImportSource::Embedded => "Embedded",
            PdbImportSource::SameDirectory => "Same Directory",
            PdbImportSource::SymbolServer => "Symbol Server",
            PdbImportSource::LocalSymbolStore => "Local Symbol Store",
            PdbImportSource::Unknown => "Unknown",
        }
    }
}

impl fmt::Display for PdbImportSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// =============================================================================
// Default PDB Import Options
// =============================================================================

/// Options controlling PDB file import behavior.
///
/// These options specify how a PDB file should be loaded and applied
/// to a Ghidra program. They combine file search preferences with
/// application processing options.
///
/// Ports Ghidra's `DefaultPdbImportOptions`.
#[derive(Debug, Clone)]
pub struct DefaultPdbImportOptions {
    /// Whether to search for PDB files automatically.
    auto_search: bool,
    /// Whether to search symbol servers for PDB files.
    search_symbol_servers: bool,
    /// Whether to search the local filesystem for PDB files.
    search_local: bool,
    /// Whether to use the embedded PDB if available.
    use_embedded: bool,
    /// User-specified PDB file path.
    user_pdb_path: Option<String>,
    /// Whether to ask the user for a PDB file if automatic search fails.
    ask_user: bool,
    /// Whether to load type information from the PDB.
    load_types: bool,
    /// Whether to load symbol information from the PDB.
    load_symbols: bool,
    /// Whether to apply function signatures.
    apply_function_signatures: bool,
    /// Whether to apply source file line number information.
    apply_source_lines: bool,
    /// Whether to apply data type information.
    apply_data_types: bool,
    /// Whether to apply external (import) symbol information.
    apply_external_info: bool,
    /// The object-oriented class layout strategy.
    class_layout: ObjectOrientedClassLayout,
    /// The source from which the PDB was obtained.
    import_source: PdbImportSource,
    /// Options for symbol server searching.
    find_options: FindOptions,
}

impl DefaultPdbImportOptions {
    /// Create a new DefaultPdbImportOptions with Ghidra's default values.
    pub fn new() -> Self {
        Self {
            auto_search: true,
            search_symbol_servers: true,
            search_local: true,
            use_embedded: true,
            user_pdb_path: None,
            ask_user: true,
            load_types: true,
            load_symbols: true,
            apply_function_signatures: true,
            apply_source_lines: true,
            apply_data_types: true,
            apply_external_info: true,
            class_layout: ObjectOrientedClassLayout::MembersOnly,
            import_source: PdbImportSource::Unknown,
            find_options: FindOptions::new(),
        }
    }

    /// Create options configured for a quick, minimal import.
    ///
    /// Only loads symbols; skips types and source information.
    pub fn minimal() -> Self {
        Self {
            auto_search: true,
            search_symbol_servers: false,
            search_local: true,
            use_embedded: true,
            user_pdb_path: None,
            ask_user: false,
            load_types: false,
            load_symbols: true,
            apply_function_signatures: false,
            apply_source_lines: false,
            apply_data_types: false,
            apply_external_info: false,
            class_layout: ObjectOrientedClassLayout::MembersOnly,
            import_source: PdbImportSource::Unknown,
            find_options: FindOptions::new(),
        }
    }

    /// Create options configured for a full import.
    ///
    /// Loads all available PDB data including types, symbols, source
    /// information, and external symbols.
    pub fn full() -> Self {
        Self {
            auto_search: true,
            search_symbol_servers: true,
            search_local: true,
            use_embedded: true,
            user_pdb_path: None,
            ask_user: true,
            load_types: true,
            load_symbols: true,
            apply_function_signatures: true,
            apply_source_lines: true,
            apply_data_types: true,
            apply_external_info: true,
            class_layout: ObjectOrientedClassLayout::ClassHierarchy,
            import_source: PdbImportSource::Unknown,
            find_options: FindOptions::with(&[FindOption::AnyAge]),
        }
    }

    // =========================================================================
    // Accessors and setters
    // =========================================================================

    /// Check if automatic PDB search is enabled.
    pub fn auto_search(&self) -> bool {
        self.auto_search
    }

    /// Set whether to search for PDB files automatically.
    pub fn set_auto_search(&mut self, auto_search: bool) {
        self.auto_search = auto_search;
    }

    /// Check if symbol server search is enabled.
    pub fn search_symbol_servers(&self) -> bool {
        self.search_symbol_servers
    }

    /// Set whether to search symbol servers.
    pub fn set_search_symbol_servers(&mut self, search: bool) {
        self.search_symbol_servers = search;
    }

    /// Check if local filesystem search is enabled.
    pub fn search_local(&self) -> bool {
        self.search_local
    }

    /// Set whether to search the local filesystem.
    pub fn set_search_local(&mut self, search: bool) {
        self.search_local = search;
    }

    /// Check if embedded PDB usage is enabled.
    pub fn use_embedded(&self) -> bool {
        self.use_embedded
    }

    /// Set whether to use embedded PDB files.
    pub fn set_use_embedded(&mut self, use_embedded: bool) {
        self.use_embedded = use_embedded;
    }

    /// Get the user-specified PDB path.
    pub fn user_pdb_path(&self) -> Option<&str> {
        self.user_pdb_path.as_deref()
    }

    /// Set a user-specified PDB file path.
    pub fn set_user_pdb_path(&mut self, path: Option<String>) {
        self.user_pdb_path = path;
    }

    /// Check if the user should be prompted for a PDB path.
    pub fn ask_user(&self) -> bool {
        self.ask_user
    }

    /// Set whether to ask the user for a PDB file path.
    pub fn set_ask_user(&mut self, ask: bool) {
        self.ask_user = ask;
    }

    /// Check if type information should be loaded.
    pub fn load_types(&self) -> bool {
        self.load_types
    }

    /// Set whether to load type information.
    pub fn set_load_types(&mut self, load: bool) {
        self.load_types = load;
    }

    /// Check if symbol information should be loaded.
    pub fn load_symbols(&self) -> bool {
        self.load_symbols
    }

    /// Set whether to load symbol information.
    pub fn set_load_symbols(&mut self, load: bool) {
        self.load_symbols = load;
    }

    /// Check if function signatures should be applied.
    pub fn apply_function_signatures(&self) -> bool {
        self.apply_function_signatures
    }

    /// Set whether to apply function signatures.
    pub fn set_apply_function_signatures(&mut self, apply: bool) {
        self.apply_function_signatures = apply;
    }

    /// Check if source line numbers should be applied.
    pub fn apply_source_lines(&self) -> bool {
        self.apply_source_lines
    }

    /// Set whether to apply source line numbers.
    pub fn set_apply_source_lines(&mut self, apply: bool) {
        self.apply_source_lines = apply;
    }

    /// Check if data type information should be applied.
    pub fn apply_data_types(&self) -> bool {
        self.apply_data_types
    }

    /// Set whether to apply data type information.
    pub fn set_apply_data_types(&mut self, apply: bool) {
        self.apply_data_types = apply;
    }

    /// Check if external symbol information should be applied.
    pub fn apply_external_info(&self) -> bool {
        self.apply_external_info
    }

    /// Set whether to apply external symbol information.
    pub fn set_apply_external_info(&mut self, apply: bool) {
        self.apply_external_info = apply;
    }

    /// Get the class layout strategy.
    pub fn class_layout(&self) -> ObjectOrientedClassLayout {
        self.class_layout
    }

    /// Set the class layout strategy.
    pub fn set_class_layout(&mut self, layout: ObjectOrientedClassLayout) {
        self.class_layout = layout;
    }

    /// Get the import source.
    pub fn import_source(&self) -> PdbImportSource {
        self.import_source
    }

    /// Set the import source.
    pub fn set_import_source(&mut self, source: PdbImportSource) {
        self.import_source = source;
    }

    /// Get the find options.
    pub fn find_options(&self) -> &FindOptions {
        &self.find_options
    }

    /// Get mutable access to the find options.
    pub fn find_options_mut(&mut self) -> &mut FindOptions {
        &mut self.find_options
    }

    // =========================================================================
    // Conversion to applicator options
    // =========================================================================

    /// Convert these import options into a `PdbApplicatorOptions`.
    ///
    /// This maps the import-level settings to the applicator-level settings
    /// used when applying PDB data to a program.
    pub fn to_applicator_options(&self) -> PdbApplicatorOptions {
        let mut opts = PdbApplicatorOptions::new();

        // Set the processing control based on what we're loading
        if self.load_types && self.load_symbols {
            opts.set_control(PdbApplicatorControl::All);
        } else if self.load_types {
            opts.set_control(PdbApplicatorControl::DataTypesOnly);
        } else if self.load_symbols {
            opts.set_control(PdbApplicatorControl::PublicSymbolsOnly);
        }

        opts.set_apply_source_line_numbers(self.apply_source_lines);
        opts.set_composite_layout(self.class_layout);

        opts
    }

    // =========================================================================
    // Validation
    // =========================================================================

    /// Validate that these options are consistent.
    ///
    /// Returns an error string if the options are invalid.
    pub fn validate(&self) -> Result<(), String> {
        if !self.load_types && !self.load_symbols {
            return Err(
                "At least one of load_types or load_symbols must be enabled".to_string(),
            );
        }
        if self.user_pdb_path.is_some() && self.auto_search {
            // This is valid -- user path takes priority
        }
        Ok(())
    }

    /// Reset all options to their default values.
    pub fn set_defaults(&mut self) {
        *self = Self::new();
    }
}

impl Default for DefaultPdbImportOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DefaultPdbImportOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DefaultPdbImportOptions [types={}, symbols={}, lines={}, layout={}, source={}]",
            self.load_types, self.load_symbols, self.apply_source_lines,
            self.class_layout, self.import_source,
        )
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_options() {
        let opts = DefaultPdbImportOptions::new();
        assert!(opts.auto_search());
        assert!(opts.search_symbol_servers());
        assert!(opts.search_local());
        assert!(opts.use_embedded());
        assert!(opts.load_types());
        assert!(opts.load_symbols());
        assert!(opts.apply_function_signatures());
        assert!(opts.apply_source_lines());
        assert!(opts.apply_data_types());
        assert!(opts.apply_external_info());
        assert_eq!(opts.class_layout(), ObjectOrientedClassLayout::MembersOnly);
        assert_eq!(opts.import_source(), PdbImportSource::Unknown);
    }

    #[test]
    fn test_minimal_options() {
        let opts = DefaultPdbImportOptions::minimal();
        assert!(!opts.load_types());
        assert!(opts.load_symbols());
        assert!(!opts.search_symbol_servers());
        assert!(!opts.ask_user());
        assert!(!opts.apply_source_lines());
    }

    #[test]
    fn test_full_options() {
        let opts = DefaultPdbImportOptions::full();
        assert!(opts.load_types());
        assert!(opts.load_symbols());
        assert!(opts.search_symbol_servers());
        assert_eq!(opts.class_layout(), ObjectOrientedClassLayout::ClassHierarchy);
    }

    #[test]
    fn test_to_applicator_options() {
        let mut opts = DefaultPdbImportOptions::new();
        opts.set_load_types(true);
        opts.set_load_symbols(true);
        let app_opts = opts.to_applicator_options();
        assert_eq!(app_opts.control(), PdbApplicatorControl::All);

        let mut opts2 = DefaultPdbImportOptions::new();
        opts2.set_load_types(true);
        opts2.set_load_symbols(false);
        let app_opts2 = opts2.to_applicator_options();
        assert_eq!(app_opts2.control(), PdbApplicatorControl::DataTypesOnly);
    }

    #[test]
    fn test_validate() {
        let opts = DefaultPdbImportOptions::new();
        assert!(opts.validate().is_ok());

        let mut invalid = DefaultPdbImportOptions::new();
        invalid.set_load_types(false);
        invalid.set_load_symbols(false);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn test_setters() {
        let mut opts = DefaultPdbImportOptions::new();
        opts.set_auto_search(false);
        assert!(!opts.auto_search());

        opts.set_user_pdb_path(Some("/path/to/file.pdb".to_string()));
        assert_eq!(opts.user_pdb_path(), Some("/path/to/file.pdb"));

        opts.set_class_layout(ObjectOrientedClassLayout::ClassHierarchy);
        assert_eq!(opts.class_layout(), ObjectOrientedClassLayout::ClassHierarchy);
    }

    #[test]
    fn test_set_defaults() {
        let mut opts = DefaultPdbImportOptions::new();
        opts.set_load_types(false);
        opts.set_load_symbols(false);
        opts.set_defaults();
        assert!(opts.load_types());
        assert!(opts.load_symbols());
    }

    #[test]
    fn test_display() {
        let opts = DefaultPdbImportOptions::new();
        let s = format!("{}", opts);
        assert!(s.contains("DefaultPdbImportOptions"));
        assert!(s.contains("types=true"));
        assert!(s.contains("symbols=true"));
    }

    #[test]
    fn test_import_source_display() {
        assert_eq!(format!("{}", PdbImportSource::UserSpecified), "User Specified");
        assert_eq!(format!("{}", PdbImportSource::SymbolServer), "Symbol Server");
    }

    #[test]
    fn test_find_options() {
        let opts = DefaultPdbImportOptions::full();
        assert!(opts.find_options().any_age());
    }
}
