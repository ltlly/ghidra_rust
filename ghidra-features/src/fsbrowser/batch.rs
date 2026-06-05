//! Batch import framework.
//!
//! Ported from `ghidra.plugins.importer.batch` package.
//!
//! Provides the data structures and logic for importing multiple files
//! at once, segregating them by loader, file extension, and architecture
//! (language/compiler-spec pair).
//!
//! # Key Types
//!
//! - [`BatchInfo`] -- Main state for a batch import operation
//! - [`BatchGroup`] -- A group of files sharing the same loader and arch
//! - [`BatchGroupLoadSpec`] -- A language/compiler-spec pair for a group
//! - [`BatchSegregatingCriteria`] -- Criteria for grouping files
//! - [`BatchImportTableModel`] -- Table model for the import dialog
//! - [`UserAddedSourceInfo`] -- Metadata about a user-added source file

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::path::PathBuf;

use super::Fsrl;

// ---------------------------------------------------------------------------
// LanguageCompilerSpecPair -- language + compiler specification
// ---------------------------------------------------------------------------

/// A pair identifying a processor language and compiler specification.
///
/// Ported from `ghidra.program.model.lang.LanguageCompilerSpecPair`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LanguageCompilerSpecPair {
    /// Language ID (e.g., "x86:LE:64:default").
    pub language_id: String,
    /// Compiler spec ID (e.g., "default", "windows").
    pub compiler_spec_id: String,
}

impl LanguageCompilerSpecPair {
    /// Create a new pair.
    pub fn new(language_id: impl Into<String>, compiler_spec_id: impl Into<String>) -> Self {
        Self {
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
        }
    }
}

impl fmt::Display for LanguageCompilerSpecPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.language_id, self.compiler_spec_id)
    }
}

// ---------------------------------------------------------------------------
// LoadSpec -- a loader's suggested load specification
// ---------------------------------------------------------------------------

/// A loader's suggested load specification for a file.
///
/// Ported from `ghidra.app.util.opinion.LoadSpec`.
#[derive(Debug, Clone)]
pub struct LoadSpec {
    /// The language/compiler-spec pair.
    pub lcs_pair: LanguageCompilerSpecPair,
    /// Whether this is the loader's preferred spec.
    pub preferred: bool,
}

impl LoadSpec {
    /// Create a new load spec.
    pub fn new(lcs_pair: LanguageCompilerSpecPair, preferred: bool) -> Self {
        Self { lcs_pair, preferred }
    }
}

// ---------------------------------------------------------------------------
// BatchGroupLoadSpec -- load spec for a batch group
// ---------------------------------------------------------------------------

/// A language/compiler-spec pair used to segregate files in a batch import.
///
/// Similar to [`LoadSpec`] but not associated with a specific loader.
///
/// Ported from `ghidra.plugins.importer.batch.BatchGroupLoadSpec`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BatchGroupLoadSpec {
    /// The language/compiler-spec pair.
    pub lcs_pair: LanguageCompilerSpecPair,
    /// Whether this is the preferred load spec.
    pub preferred: bool,
}

impl BatchGroupLoadSpec {
    /// Create from a [`LoadSpec`].
    pub fn from_load_spec(spec: &LoadSpec) -> Self {
        Self {
            lcs_pair: spec.lcs_pair.clone(),
            preferred: spec.preferred,
        }
    }

    /// Check if this spec matches a given [`LoadSpec`].
    pub fn matches(&self, spec: &LoadSpec) -> bool {
        self.lcs_pair == spec.lcs_pair
    }
}

impl fmt::Display for BatchGroupLoadSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.lcs_pair, if self.preferred { "*" } else { "" })
    }
}

impl PartialOrd for BatchGroupLoadSpec {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BatchGroupLoadSpec {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_string().cmp(&other.to_string())
    }
}

// ---------------------------------------------------------------------------
// BatchSegregatingCriteria -- criteria for grouping files
// ---------------------------------------------------------------------------

/// Identifying criteria that group files during batch import.
///
/// Files are segregated by file extension, loader name, and the set
/// of available load specs (language/compiler-spec pairs).
///
/// Ported from `ghidra.plugins.importer.batch.BatchSegregatingCriteria`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchSegregatingCriteria {
    /// File extension of the source file.
    pub file_ext: String,
    /// Name of the loader that can handle this file.
    pub loader_name: String,
    /// The set of available load specs.
    pub group_load_specs: Vec<BatchGroupLoadSpec>,
}

impl BatchSegregatingCriteria {
    /// Create new criteria.
    pub fn new(
        file_ext: impl Into<String>,
        loader_name: impl Into<String>,
        load_specs: Vec<LoadSpec>,
    ) -> Self {
        let group_load_specs: Vec<BatchGroupLoadSpec> = load_specs
            .iter()
            .map(BatchGroupLoadSpec::from_load_spec)
            .collect();
        Self {
            file_ext: file_ext.into(),
            loader_name: loader_name.into(),
            group_load_specs,
        }
    }

    /// Get the sorted list of load specs.
    pub fn sorted_load_specs(&self) -> Vec<&BatchGroupLoadSpec> {
        let mut specs: Vec<_> = self.group_load_specs.iter().collect();
        specs.sort();
        specs
    }

    /// Get the first preferred load spec, if any.
    pub fn first_preferred(&self) -> Option<&BatchGroupLoadSpec> {
        self.group_load_specs.iter().find(|s| s.preferred)
    }

    /// Get the number of load specs.
    pub fn load_spec_count(&self) -> usize {
        self.group_load_specs.len()
    }
}

impl fmt::Display for BatchSegregatingCriteria {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[ext: {}, loader: {}, load specs: {:?}]",
            self.file_ext, self.loader_name, self.group_load_specs
        )
    }
}

// ---------------------------------------------------------------------------
// UserAddedSourceInfo -- metadata about a source file added by the user
// ---------------------------------------------------------------------------

/// Metadata about a file added to the batch import by the user.
///
/// Ported from `ghidra.plugins.importer.batch.UserAddedSourceInfo`.
#[derive(Debug, Clone)]
pub struct UserAddedSourceInfo {
    /// Path to the source file on disk.
    pub source_path: PathBuf,
    /// FSRL of the file (if it came from a mounted filesystem).
    pub fsrl: Option<Fsrl>,
    /// Whether the file was discovered inside a container.
    pub from_container: bool,
    /// Nesting depth (0 = directly added by user).
    pub depth: u32,
}

impl UserAddedSourceInfo {
    /// Create for a file directly added by the user.
    pub fn from_path(path: PathBuf) -> Self {
        Self {
            source_path: path,
            fsrl: None,
            from_container: false,
            depth: 0,
        }
    }

    /// Create for a file discovered inside a container.
    pub fn from_container(path: PathBuf, fsrl: Fsrl, depth: u32) -> Self {
        Self {
            source_path: path,
            fsrl: Some(fsrl),
            from_container: true,
            depth,
        }
    }
}

// ---------------------------------------------------------------------------
// BatchLoadConfig -- per-file load configuration
// ---------------------------------------------------------------------------

/// Configuration for loading a specific file in a batch import.
#[derive(Debug, Clone)]
pub struct BatchLoadConfig {
    /// The selected load spec for this file.
    pub load_spec: BatchGroupLoadSpec,
    /// Override base address (None = use default from headers).
    pub base_address: Option<u64>,
    /// Whether to run analysis after loading.
    pub apply_analysis: bool,
}

impl BatchLoadConfig {
    /// Create with defaults.
    pub fn new(load_spec: BatchGroupLoadSpec) -> Self {
        Self {
            load_spec,
            base_address: None,
            apply_analysis: true,
        }
    }

    /// Set a custom base address.
    pub fn with_base_address(mut self, addr: u64) -> Self {
        self.base_address = Some(addr);
        self
    }

    /// Disable analysis.
    pub fn without_analysis(mut self) -> Self {
        self.apply_analysis = false;
        self
    }
}

// ---------------------------------------------------------------------------
// BatchGroup -- a group of files sharing the same criteria
// ---------------------------------------------------------------------------

/// A group of files that share the same loader and architecture.
///
/// All files in a group can be loaded with the same loader and
/// language/compiler-spec settings.
///
/// Ported from `ghidra.plugins.importer.batch.BatchGroup`.
#[derive(Debug, Clone)]
pub struct BatchGroup {
    /// The segregating criteria for this group.
    pub criteria: BatchSegregatingCriteria,
    /// Files in this group, with their load configurations.
    pub files: Vec<BatchFileEntry>,
    /// Whether this group is selected for import.
    pub selected: bool,
    /// The group's display name (derived from criteria).
    pub display_name: String,
}

/// A single file entry in a batch group.
#[derive(Debug, Clone)]
pub struct BatchFileEntry {
    /// Path to the source file.
    pub path: PathBuf,
    /// File name for display.
    pub name: String,
    /// File size in bytes.
    pub size: u64,
    /// Per-file load configuration.
    pub config: BatchLoadConfig,
    /// Optional user-added source info.
    pub source_info: Option<UserAddedSourceInfo>,
}

impl BatchGroup {
    /// Create a new batch group.
    pub fn new(criteria: BatchSegregatingCriteria) -> Self {
        let display_name = format!(
            "{} ({})",
            criteria.file_ext, criteria.loader_name
        );
        Self {
            criteria,
            files: Vec::new(),
            selected: true,
            display_name,
        }
    }

    /// Add a file to the group.
    pub fn add_file(&mut self, entry: BatchFileEntry) {
        self.files.push(entry);
    }

    /// Get the total number of files in this group.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Get total size of all files in this group.
    pub fn total_size(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }

    /// Get the preferred load spec for this group.
    pub fn preferred_load_spec(&self) -> Option<&BatchGroupLoadSpec> {
        self.criteria.first_preferred()
    }
}

// ---------------------------------------------------------------------------
// BatchInfo -- main state for a batch import operation
// ---------------------------------------------------------------------------

/// Main state object for a batch import operation.
///
/// Contains all the grouped files, tracks user-added sources, and
/// manages the recursion into containers.
///
/// Ported from `ghidra.plugins.importer.batch.BatchInfo`.
#[derive(Debug, Clone)]
pub struct BatchInfo {
    /// Groups of files, keyed by segregating criteria.
    pub groups: HashMap<String, BatchGroup>,
    /// FSRLs of user-added files (for dedup).
    user_added_fsrls: HashSet<String>,
    /// Metadata about all user-added sources.
    pub user_added_sources: Vec<UserAddedSourceInfo>,
    /// Maximum container recursion depth.
    pub max_depth: u32,
    /// Whether the import is currently in progress.
    pub importing: bool,
}

impl BatchInfo {
    /// Maximum depth: unlimited.
    pub const MAXDEPTH_UNLIMITED: u32 = 0;
    /// Default maximum depth.
    pub const MAXDEPTH_DEFAULT: u32 = 2;

    /// Create a new batch info with default settings.
    pub fn new() -> Self {
        Self {
            groups: HashMap::new(),
            user_added_fsrls: HashSet::new(),
            user_added_sources: Vec::new(),
            max_depth: Self::MAXDEPTH_DEFAULT,
            importing: false,
        }
    }

    /// Set the maximum recursion depth.
    pub fn set_max_depth(&mut self, depth: u32) {
        self.max_depth = depth;
    }

    /// Add a source file to the batch import.
    pub fn add_source(&mut self, source: UserAddedSourceInfo) {
        if let Some(ref fsrl) = source.fsrl {
            if self.user_added_fsrls.contains(&fsrl.uri) {
                return; // duplicate
            }
            self.user_added_fsrls.insert(fsrl.uri.clone());
        }
        self.user_added_sources.push(source);
    }

    /// Add a group to the batch import.
    pub fn add_group(&mut self, group: BatchGroup) {
        self.groups.insert(group.display_name.clone(), group);
    }

    /// Get the total number of files across all groups.
    pub fn total_file_count(&self) -> usize {
        self.groups.values().map(|g| g.file_count()).sum()
    }

    /// Get the total size across all groups.
    pub fn total_size(&self) -> u64 {
        self.groups.values().map(|g| g.total_size()).sum()
    }

    /// Get the number of groups.
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Get selected groups (those marked for import).
    pub fn selected_groups(&self) -> Vec<&BatchGroup> {
        self.groups.values().filter(|g| g.selected).collect()
    }

    /// Get the total number of files in selected groups.
    pub fn selected_file_count(&self) -> usize {
        self.selected_groups().iter().map(|g| g.file_count()).sum()
    }

    /// Clear all groups and sources.
    pub fn clear(&mut self) {
        self.groups.clear();
        self.user_added_fsrls.clear();
        self.user_added_sources.clear();
    }

    /// Check if the batch info has any files.
    pub fn is_empty(&self) -> bool {
        self.groups.is_empty()
    }

    /// Check if a given depth should be recursed into.
    pub fn should_recurse(&self, current_depth: u32) -> bool {
        self.max_depth == Self::MAXDEPTH_UNLIMITED || current_depth < self.max_depth
    }
}

impl Default for BatchInfo {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BatchImportTableModel -- table model for the import dialog
// ---------------------------------------------------------------------------

/// Column identifiers for the batch import table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BatchTableColumn {
    /// Whether the row is selected for import.
    Selected,
    /// File name.
    FileName,
    /// File extension.
    Extension,
    /// Loader name.
    Loader,
    /// Language/compiler-spec.
    Language,
    /// File size.
    Size,
    /// Number of files in the group.
    FileCount,
}

/// A row in the batch import table.
#[derive(Debug, Clone)]
pub struct BatchTableRow {
    /// Whether this row is selected.
    pub selected: bool,
    /// The group display name.
    pub display_name: String,
    /// File extension.
    pub extension: String,
    /// Loader name.
    pub loader: String,
    /// Language/compiler-spec (preferred).
    pub language: String,
    /// Total size of files in the group.
    pub total_size: u64,
    /// Number of files.
    pub file_count: usize,
}

/// Table model for displaying batch import groups.
///
/// Ported from `ghidra.plugins.importer.batch.BatchImportTableModel`.
#[derive(Debug, Clone)]
pub struct BatchImportTableModel {
    /// The rows of the table.
    pub rows: Vec<BatchTableRow>,
    /// Column definitions.
    pub columns: Vec<BatchTableColumn>,
}

impl BatchImportTableModel {
    /// Create a new table model from a [`BatchInfo`].
    pub fn from_batch_info(info: &BatchInfo) -> Self {
        let columns = vec![
            BatchTableColumn::Selected,
            BatchTableColumn::FileName,
            BatchTableColumn::Extension,
            BatchTableColumn::Loader,
            BatchTableColumn::Language,
            BatchTableColumn::Size,
            BatchTableColumn::FileCount,
        ];

        let rows = info
            .groups
            .values()
            .map(|group| {
                let language = group
                    .preferred_load_spec()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "none".to_string());

                BatchTableRow {
                    selected: group.selected,
                    display_name: group.display_name.clone(),
                    extension: group.criteria.file_ext.clone(),
                    loader: group.criteria.loader_name.clone(),
                    language,
                    total_size: group.total_size(),
                    file_count: group.file_count(),
                }
            })
            .collect();

        Self { rows, columns }
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get the number of columns.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Toggle selection of a row.
    pub fn toggle_selection(&mut self, row: usize) {
        if let Some(r) = self.rows.get_mut(row) {
            r.selected = !r.selected;
        }
    }

    /// Select all rows.
    pub fn select_all(&mut self) {
        for row in &mut self.rows {
            row.selected = true;
        }
    }

    /// Deselect all rows.
    pub fn deselect_all(&mut self) {
        for row in &mut self.rows {
            row.selected = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_lcs(lang: &str, compiler: &str) -> LanguageCompilerSpecPair {
        LanguageCompilerSpecPair::new(lang, compiler)
    }

    fn make_load_spec(lang: &str, compiler: &str, preferred: bool) -> LoadSpec {
        LoadSpec::new(make_lcs(lang, compiler), preferred)
    }

    #[test]
    fn test_language_compiler_spec_pair() {
        let pair = make_lcs("x86:LE:64:default", "default");
        assert_eq!(pair.language_id, "x86:LE:64:default");
        assert_eq!(pair.compiler_spec_id, "default");
        assert_eq!(pair.to_string(), "x86:LE:64:default:default");
    }

    #[test]
    fn test_batch_group_load_spec() {
        let spec = make_load_spec("x86:LE:64:default", "default", true);
        let batch_spec = BatchGroupLoadSpec::from_load_spec(&spec);
        assert!(batch_spec.preferred);
        assert_eq!(batch_spec.to_string(), "x86:LE:64:default:default*");
    }

    #[test]
    fn test_batch_group_load_spec_match() {
        let spec1 = make_load_spec("x86:LE:64:default", "default", true);
        let spec2 = make_load_spec("x86:LE:64:default", "default", false);
        let batch_spec = BatchGroupLoadSpec::from_load_spec(&spec1);
        assert!(batch_spec.matches(&spec2));
    }

    #[test]
    fn test_batch_seggregating_criteria() {
        let specs = vec![
            make_load_spec("x86:LE:64:default", "default", true),
            make_load_spec("x86:LE:32:default", "default", false),
        ];
        let criteria = BatchSegregatingCriteria::new("exe", "PE Loader", specs);
        assert_eq!(criteria.file_ext, "exe");
        assert_eq!(criteria.loader_name, "PE Loader");
        assert_eq!(criteria.group_load_specs.len(), 2);

        let preferred = criteria.first_preferred();
        assert!(preferred.is_some());
        assert!(preferred.unwrap().preferred);
    }

    #[test]
    fn test_batch_info_lifecycle() {
        let mut info = BatchInfo::new();
        assert!(info.is_empty());
        assert_eq!(info.max_depth, BatchInfo::MAXDEPTH_DEFAULT);

        // Add a source
        info.add_source(UserAddedSourceInfo::from_path(PathBuf::from("/tmp/test.exe")));
        assert_eq!(info.user_added_sources.len(), 1);

        // Add a group
        let criteria = BatchSegregatingCriteria::new(
            "exe",
            "PE Loader",
            vec![make_load_spec("x86:LE:64:default", "default", true)],
        );
        let mut group = BatchGroup::new(criteria);
        group.add_file(BatchFileEntry {
            path: PathBuf::from("/tmp/test.exe"),
            name: "test.exe".to_string(),
            size: 1024,
            config: BatchLoadConfig::new(BatchGroupLoadSpec::from_load_spec(
                &make_load_spec("x86:LE:64:default", "default", true),
            )),
            source_info: None,
        });

        info.add_group(group);
        assert_eq!(info.group_count(), 1);
        assert_eq!(info.total_file_count(), 1);
        assert_eq!(info.total_size(), 1024);
    }

    #[test]
    fn test_batch_info_dedup() {
        let mut info = BatchInfo::new();
        let fsrl = Fsrl::new("file:///tmp/test.exe", "test.exe");

        info.add_source(UserAddedSourceInfo::from_container(
            PathBuf::from("/tmp/test.exe"),
            fsrl.clone(),
            1,
        ));
        info.add_source(UserAddedSourceInfo::from_container(
            PathBuf::from("/tmp/test.exe"),
            fsrl,
            1,
        ));

        // Second add should be deduped
        assert_eq!(info.user_added_sources.len(), 1);
    }

    #[test]
    fn test_batch_info_should_recurse() {
        let mut info = BatchInfo::new();
        info.set_max_depth(3);

        assert!(info.should_recurse(0));
        assert!(info.should_recurse(1));
        assert!(info.should_recurse(2));
        assert!(!info.should_recurse(3));

        info.set_max_depth(BatchInfo::MAXDEPTH_UNLIMITED);
        assert!(info.should_recurse(100));
    }

    #[test]
    fn test_batch_info_selected() {
        let mut info = BatchInfo::new();

        let criteria1 = BatchSegregatingCriteria::new(
            "exe",
            "PE",
            vec![make_load_spec("x86:LE:64:default", "default", true)],
        );
        let mut group1 = BatchGroup::new(criteria1);
        group1.selected = true;
        group1.add_file(BatchFileEntry {
            path: PathBuf::from("/tmp/a.exe"),
            name: "a.exe".to_string(),
            size: 100,
            config: BatchLoadConfig::new(BatchGroupLoadSpec::from_load_spec(
                &make_load_spec("x86:LE:64:default", "default", true),
            )),
            source_info: None,
        });

        let criteria2 = BatchSegregatingCriteria::new(
            "so",
            "ELF",
            vec![make_load_spec("ARM:LE:32:v8", "default", true)],
        );
        let mut group2 = BatchGroup::new(criteria2);
        group2.selected = false;

        info.add_group(group1);
        info.add_group(group2);

        assert_eq!(info.selected_groups().len(), 1);
        assert_eq!(info.selected_file_count(), 1);
    }

    #[test]
    fn test_batch_info_clear() {
        let mut info = BatchInfo::new();
        info.add_source(UserAddedSourceInfo::from_path(PathBuf::from("/tmp/test.exe")));
        let criteria = BatchSegregatingCriteria::new("exe", "PE", vec![]);
        info.add_group(BatchGroup::new(criteria));

        info.clear();
        assert!(info.is_empty());
        assert!(info.user_added_sources.is_empty());
    }

    #[test]
    fn test_batch_group() {
        let criteria = BatchSegregatingCriteria::new(
            "elf",
            "ELF Loader",
            vec![make_load_spec("ARM:LE:32:v8", "default", true)],
        );
        let mut group = BatchGroup::new(criteria);
        assert_eq!(group.display_name, "elf (ELF Loader)");
        assert!(group.selected);

        group.add_file(BatchFileEntry {
            path: PathBuf::from("/tmp/lib.so"),
            name: "lib.so".to_string(),
            size: 4096,
            config: BatchLoadConfig::new(BatchGroupLoadSpec::from_load_spec(
                &make_load_spec("ARM:LE:32:v8", "default", true),
            )),
            source_info: None,
        });

        assert_eq!(group.file_count(), 1);
        assert_eq!(group.total_size(), 4096);
    }

    #[test]
    fn test_batch_load_config() {
        let config = BatchLoadConfig::new(BatchGroupLoadSpec::from_load_spec(
            &make_load_spec("x86:LE:64:default", "default", true),
        ))
        .with_base_address(0x400000)
        .without_analysis();

        assert_eq!(config.base_address, Some(0x400000));
        assert!(!config.apply_analysis);
    }

    #[test]
    fn test_batch_import_table_model() {
        let mut info = BatchInfo::new();

        let criteria = BatchSegregatingCriteria::new(
            "exe",
            "PE",
            vec![make_load_spec("x86:LE:64:default", "default", true)],
        );
        let mut group = BatchGroup::new(criteria);
        group.add_file(BatchFileEntry {
            path: PathBuf::from("/tmp/test.exe"),
            name: "test.exe".to_string(),
            size: 2048,
            config: BatchLoadConfig::new(BatchGroupLoadSpec::from_load_spec(
                &make_load_spec("x86:LE:64:default", "default", true),
            )),
            source_info: None,
        });
        info.add_group(group);

        let mut model = BatchImportTableModel::from_batch_info(&info);
        assert_eq!(model.row_count(), 1);
        assert_eq!(model.column_count(), 7);
        assert!(model.rows[0].selected);

        model.toggle_selection(0);
        assert!(!model.rows[0].selected);

        model.select_all();
        assert!(model.rows[0].selected);
    }

    #[test]
    fn test_user_added_source_info() {
        let info = UserAddedSourceInfo::from_path(PathBuf::from("/tmp/test.bin"));
        assert!(!info.from_container);
        assert_eq!(info.depth, 0);
        assert!(info.fsrl.is_none());

        let info = UserAddedSourceInfo::from_container(
            PathBuf::from("/tmp/archive.zip"),
            Fsrl::new("zipfs:/inner.bin", "inner.bin"),
            2,
        );
        assert!(info.from_container);
        assert_eq!(info.depth, 2);
        assert!(info.fsrl.is_some());
    }
}
