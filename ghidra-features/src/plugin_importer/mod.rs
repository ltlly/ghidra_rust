//! Importer plugin: import binary files into Ghidra projects.
//!
//! Ported from `ghidra.plugin.importer`.
//!
//! Provides the importer plugin, language selection model, and import
//! utilities for loading programs into a Ghidra project.

// ---------------------------------------------------------------------------
// ImportOptions
// ---------------------------------------------------------------------------

/// Options for importing a binary file into a Ghidra project.
#[derive(Debug, Clone)]
pub struct ImportOptions {
    /// The language/compiler spec to use (e.g., "x86:LE:64:default").
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// Base address override (0 means use file headers).
    pub base_address: u64,
    /// Whether to apply analysis after import.
    pub apply_analysis: bool,
    /// The destination folder in the project (e.g., "/").
    pub destination_folder: String,
    /// Whether to load libraries referenced by the binary.
    pub load_libraries: bool,
    /// Custom program name (None means use the filename).
    pub program_name: Option<String>,
}

impl ImportOptions {
    /// Create default import options for the given language.
    pub fn new(language_id: &str, compiler_spec_id: &str) -> Self {
        Self {
            language_id: language_id.to_string(),
            compiler_spec_id: compiler_spec_id.to_string(),
            base_address: 0,
            apply_analysis: true,
            destination_folder: "/".to_string(),
            load_libraries: true,
            program_name: None,
        }
    }

    /// Set the base address.
    pub fn with_base_address(mut self, addr: u64) -> Self {
        self.base_address = addr;
        self
    }

    /// Set whether to apply analysis.
    pub fn with_analysis(mut self, apply: bool) -> Self {
        self.apply_analysis = apply;
        self
    }

    /// Set the destination folder.
    pub fn with_destination(mut self, folder: &str) -> Self {
        self.destination_folder = folder.to_string();
        self
    }

    /// Set a custom program name.
    pub fn with_name(mut self, name: &str) -> Self {
        self.program_name = Some(name.to_string());
        self
    }
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self::new("x86:LE:64:default", "default")
    }
}

// ---------------------------------------------------------------------------
// LanguageInfo
// ---------------------------------------------------------------------------

/// Describes a supported language/compiler-spec pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageInfo {
    /// The language ID (e.g., "x86:LE:64:default").
    pub language_id: String,
    /// The compiler spec ID (e.g., "default", "gcc").
    pub compiler_spec_id: String,
    /// Human-readable description of the language.
    pub description: String,
    /// The processor name (e.g., "x86", "ARM", "MIPS").
    pub processor: String,
    /// Address size in bits.
    pub address_size: u32,
    /// Endianness: true for little-endian.
    pub little_endian: bool,
}

impl LanguageInfo {
    /// Create a new language info entry.
    pub fn new(
        language_id: &str,
        compiler_spec_id: &str,
        description: &str,
        processor: &str,
        address_size: u32,
        little_endian: bool,
    ) -> Self {
        Self {
            language_id: language_id.to_string(),
            compiler_spec_id: compiler_spec_id.to_string(),
            description: description.to_string(),
            processor: processor.to_string(),
            address_size,
            little_endian,
        }
    }

    /// Full identifier string.
    pub fn full_id(&self) -> String {
        format!("{}:{}", self.language_id, self.compiler_spec_id)
    }
}

// ---------------------------------------------------------------------------
// LanguageSortedTableModel
// ---------------------------------------------------------------------------

/// A table model of available languages, sorted by description.
#[derive(Debug, Clone, Default)]
pub struct LanguageSortedTableModel {
    entries: Vec<LanguageInfo>,
}

impl LanguageSortedTableModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a language entry.
    pub fn add(&mut self, info: LanguageInfo) {
        self.entries.push(info);
        self.entries.sort_by(|a, b| a.description.cmp(&b.description));
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the model is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get an entry by index.
    pub fn get(&self, index: usize) -> Option<&LanguageInfo> {
        self.entries.get(index)
    }

    /// Find an entry by language ID.
    pub fn find_by_language_id(&self, id: &str) -> Option<&LanguageInfo> {
        self.entries.iter().find(|e| e.language_id == id)
    }

    /// Filter entries by processor name.
    pub fn filter_by_processor(&self, processor: &str) -> Vec<&LanguageInfo> {
        self.entries
            .iter()
            .filter(|e| e.processor.eq_ignore_ascii_case(processor))
            .collect()
    }

    /// Search entries by description substring.
    pub fn search(&self, query: &str) -> Vec<&LanguageInfo> {
        let lower_query = query.to_lowercase();
        self.entries
            .iter()
            .filter(|e| e.description.to_lowercase().contains(&lower_query))
            .collect()
    }

    /// All entries as a slice.
    pub fn entries(&self) -> &[LanguageInfo] {
        &self.entries
    }
}

// ---------------------------------------------------------------------------
// ImporterUtilities
// ---------------------------------------------------------------------------

/// Utility functions for the importer.
pub struct ImporterUtilities;

impl ImporterUtilities {
    /// Guess a program name from a file path.
    pub fn guess_program_name(file_path: &str) -> String {
        let name = file_path
            .rsplit('/')
            .next()
            .unwrap_or(file_path)
            .rsplit('\\')
            .next()
            .unwrap_or(file_path);
        name.to_string()
    }

    /// Check if a file extension suggests a binary that can be imported.
    pub fn is_importable_extension(ext: &str) -> bool {
        matches!(
            ext.to_lowercase().as_str(),
            "exe"
                | "dll"
                | "so"
                | "dylib"
                | "elf"
                | "o"
                | "a"
                | "lib"
                | "sys"
                | "ko"
                | "bin"
                | "rom"
                | "fw"
                | "axf"
                | "out"
        )
    }
}

// ---------------------------------------------------------------------------
// LcsSelectionEvent
// ---------------------------------------------------------------------------

/// Event fired when the user selects a language/compiler-spec.
#[derive(Debug, Clone)]
pub struct LcsSelectionEvent {
    /// The selected language info.
    pub language: LanguageInfo,
    /// Index in the table.
    pub index: usize,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_options_default() {
        let opts = ImportOptions::default();
        assert_eq!(opts.language_id, "x86:LE:64:default");
        assert_eq!(opts.compiler_spec_id, "default");
        assert_eq!(opts.base_address, 0);
        assert!(opts.apply_analysis);
    }

    #[test]
    fn test_import_options_builder() {
        let opts = ImportOptions::new("ARM:LE:32:v8", "gcc")
            .with_base_address(0x8000)
            .with_analysis(false)
            .with_destination("/imports")
            .with_name("firmware");
        assert_eq!(opts.base_address, 0x8000);
        assert!(!opts.apply_analysis);
        assert_eq!(opts.destination_folder, "/imports");
        assert_eq!(opts.program_name, Some("firmware".into()));
    }

    #[test]
    fn test_language_info() {
        let lang = LanguageInfo::new(
            "x86:LE:64:default",
            "default",
            "x86 64-bit little-endian",
            "x86",
            64,
            true,
        );
        assert_eq!(lang.full_id(), "x86:LE:64:default:default");
        assert_eq!(lang.address_size, 64);
        assert!(lang.little_endian);
    }

    #[test]
    fn test_language_model_sorted() {
        let mut model = LanguageSortedTableModel::new();
        model.add(LanguageInfo::new("z", "default", "Z processor", "z", 32, true));
        model.add(LanguageInfo::new("a", "default", "A processor", "a", 32, true));
        assert_eq!(model.len(), 2);
        // Should be sorted by description
        assert_eq!(model.get(0).unwrap().description, "A processor");
        assert_eq!(model.get(1).unwrap().description, "Z processor");
    }

    #[test]
    fn test_language_model_search() {
        let mut model = LanguageSortedTableModel::new();
        model.add(LanguageInfo::new(
            "x86:LE:64:default",
            "default",
            "x86 64-bit LE",
            "x86",
            64,
            true,
        ));
        model.add(LanguageInfo::new(
            "ARM:LE:32:v8",
            "gcc",
            "ARM Thumb mode",
            "ARM",
            32,
            true,
        ));

        let results = model.search("x86");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].processor, "x86");
    }

    #[test]
    fn test_language_model_filter_by_processor() {
        let mut model = LanguageSortedTableModel::new();
        model.add(LanguageInfo::new("x86:LE:32:default", "default", "x86 32", "x86", 32, true));
        model.add(LanguageInfo::new("x86:LE:64:default", "default", "x86 64", "x86", 64, true));
        model.add(LanguageInfo::new("ARM:LE:32:v8", "default", "ARM", "ARM", 32, true));

        let x86 = model.filter_by_processor("x86");
        assert_eq!(x86.len(), 2);
    }

    #[test]
    fn test_guess_program_name() {
        assert_eq!(
            ImporterUtilities::guess_program_name("/path/to/program.exe"),
            "program.exe"
        );
        assert_eq!(
            ImporterUtilities::guess_program_name("simple"),
            "simple"
        );
    }

    #[test]
    fn test_importable_extension() {
        assert!(ImporterUtilities::is_importable_extension("exe"));
        assert!(ImporterUtilities::is_importable_extension("so"));
        assert!(ImporterUtilities::is_importable_extension("ELF"));
        assert!(!ImporterUtilities::is_importable_extension("txt"));
        assert!(!ImporterUtilities::is_importable_extension("pdf"));
    }

    #[test]
    fn test_lcs_selection_event() {
        let lang = LanguageInfo::new("x86:LE:64:default", "default", "desc", "x86", 64, true);
        let event = LcsSelectionEvent {
            language: lang.clone(),
            index: 3,
        };
        assert_eq!(event.index, 3);
        assert_eq!(event.language.language_id, "x86:LE:64:default");
    }
}
