//! Import (loading) framework ported from Ghidra's `ghidra.app.util.importer`
//! package.
//!
//! Provides the high-level program import pipeline:
//! - [`ProgramLoaderBuilder`] -- builder-pattern API for configuring and
//!   running a binary import
//! - [`LoadSpecChooser`] trait / [`LcsHintLoadSpecChooser`] -- selects among
//!   competing load specs
//! - [`OptionChooser`] trait -- selects among loader options
//! - [`LibrarySearchPathManager`] -- manages search paths for shared libraries
//! - [`MultipleProgramsException`] -- error when a file contains multiple programs
//! - Import option types matching Java's `ghidra.app.util.importer.options.*`
//! - [`AutoImporter`] -- one-shot convenience import
//!
//! # Example
//!
//! ```rust,no_run
//! use ghidra_features::importer::*;
//! use ghidra_features::loader::framework::*;
//!
//! let data = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
//! let mut log = MessageLog::new();
//! let results = AutoImporter::import_bytes(&data, "test.elf", &[], &mut log).unwrap();
//! assert_eq!(results.len(), 1);
//! ```

pub mod import_plugin;
pub mod import_service;

use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;

use crate::loader::framework::{
    CompilerSpecId, LanguageCompilerSpecPair, LanguageId, LoadError, LoadOption,
    LoadResults, LoadSpec, LoaderTier, MessageLog,
};

// ---------------------------------------------------------------------------
// LoadSpecChooser
// ---------------------------------------------------------------------------

/// Chooses a [`LoadSpec`] for a loader to use.
///
/// Ported from `ghidra.app.util.importer.LoadSpecChooser`.
pub trait LoadSpecChooser: Send + Sync {
    /// Choose a load spec from the available options.
    ///
    /// Returns the chosen load spec, or `None` if none is acceptable.
    fn choose(&self, specs: &[LoadSpecChoice]) -> Option<usize>;

    /// The desired language ID, if any.
    fn desired_language_id(&self) -> Option<&LanguageId> {
        None
    }

    /// The desired compiler spec ID, if any.
    fn desired_compiler_spec_id(&self) -> Option<&CompilerSpecId> {
        None
    }
}

/// A load spec that can be chosen.
#[derive(Debug, Clone)]
pub struct LoadSpecChoice {
    /// The loader name.
    pub loader_name: String,
    /// The load spec.
    pub load_spec: LoadSpec,
    /// Index into the choices list.
    pub index: usize,
}

/// Always choose the first preferred load spec.
///
/// Ported from `LoadSpecChooser.CHOOSE_THE_FIRST_PREFERRED`.
pub struct FirstPreferredLoadSpecChooser;

impl LoadSpecChooser for FirstPreferredLoadSpecChooser {
    fn choose(&self, specs: &[LoadSpecChoice]) -> Option<usize> {
        specs
            .iter()
            .find(|s| s.load_spec.is_preferred)
            .map(|s| s.index)
    }
}

/// Choose based on a language/compiler spec hint.
///
/// Ported from `ghidra.app.util.importer.LcsHintLoadSpecChooser`.
pub struct LcsHintLoadSpecChooser {
    pub language_id: Option<LanguageId>,
    pub compiler_spec_id: Option<CompilerSpecId>,
}

impl LcsHintLoadSpecChooser {
    pub fn new(
        language_id: Option<LanguageId>,
        compiler_spec_id: Option<CompilerSpecId>,
    ) -> Self {
        Self {
            language_id,
            compiler_spec_id,
        }
    }

    /// Create from a language/compiler spec pair.
    pub fn from_pair(pair: &LanguageCompilerSpecPair) -> Self {
        Self {
            language_id: Some(pair.language_id.clone()),
            compiler_spec_id: Some(pair.compiler_spec_id.clone()),
        }
    }
}

impl LoadSpecChooser for LcsHintLoadSpecChooser {
    fn choose(&self, specs: &[LoadSpecChoice]) -> Option<usize> {
        // First try exact match
        if let (Some(lang), Some(compiler)) = (&self.language_id, &self.compiler_spec_id) {
            if let Some(s) = specs.iter().find(|s| {
                s.load_spec
                    .language_compiler_spec
                    .as_ref()
                    .map(|lcs| &lcs.language_id == lang && &lcs.compiler_spec_id == compiler)
                    .unwrap_or(false)
            }) {
                return Some(s.index);
            }
        }

        // Then try language-only match
        if let Some(lang) = &self.language_id {
            if let Some(s) = specs.iter().find(|s| {
                s.load_spec
                    .language_compiler_spec
                    .as_ref()
                    .map(|lcs| &lcs.language_id == lang)
                    .unwrap_or(false)
            }) {
                return Some(s.index);
            }
        }

        // Fall back to first preferred
        specs
            .iter()
            .find(|s| s.load_spec.is_preferred)
            .map(|s| s.index)
    }

    fn desired_language_id(&self) -> Option<&LanguageId> {
        self.language_id.as_ref()
    }

    fn desired_compiler_spec_id(&self) -> Option<&CompilerSpecId> {
        self.compiler_spec_id.as_ref()
    }
}

/// Choose based on a compiler spec hint only.
///
/// Ported from `ghidra.app.util.importer.CsHintLoadSpecChooser`.
pub struct CsHintLoadSpecChooser {
    pub compiler_spec_id: CompilerSpecId,
}

impl CsHintLoadSpecChooser {
    pub fn new(compiler_spec_id: CompilerSpecId) -> Self {
        Self { compiler_spec_id }
    }
}

impl LoadSpecChooser for CsHintLoadSpecChooser {
    fn choose(&self, specs: &[LoadSpecChoice]) -> Option<usize> {
        specs
            .iter()
            .find(|s| {
                s.load_spec
                    .language_compiler_spec
                    .as_ref()
                    .map(|lcs| lcs.compiler_spec_id == self.compiler_spec_id)
                    .unwrap_or(false)
            })
            .or_else(|| specs.iter().find(|s| s.load_spec.is_preferred))
            .map(|s| s.index)
    }

    fn desired_compiler_spec_id(&self) -> Option<&CompilerSpecId> {
        Some(&self.compiler_spec_id)
    }
}

// ---------------------------------------------------------------------------
// OptionChooser
// ---------------------------------------------------------------------------

/// Chooses which loader options to use.
///
/// Ported from `ghidra.app.util.importer.OptionChooser`.
pub trait OptionChooser: Send + Sync {
    /// Choose which options to apply.
    fn choose(&self, available_options: Vec<LoadOption>) -> Vec<LoadOption>;

    /// Get any command-line loader arguments.
    fn loader_args(&self) -> Vec<(String, String)> {
        Vec::new()
    }
}

/// Default option chooser that passes through all options unchanged.
pub struct DefaultOptionChooser;

impl OptionChooser for DefaultOptionChooser {
    fn choose(&self, options: Vec<LoadOption>) -> Vec<LoadOption> {
        options
    }
}

// ---------------------------------------------------------------------------
// LoaderFilter
// ---------------------------------------------------------------------------

/// Filter for restricting which loaders to try.
///
/// Ported from `ghidra.app.util.importer.LoaderService.ACCEPT_ALL`.
pub trait LoaderFilter: Send + Sync {
    /// Returns true if the loader with the given name should be considered.
    fn accept(&self, loader_name: &str) -> bool;
}

/// Accepts all loaders.
pub struct AcceptAllLoaders;

impl LoaderFilter for AcceptAllLoaders {
    fn accept(&self, _loader_name: &str) -> bool {
        true
    }
}

/// Accepts only a single named loader.
///
/// Ported from `ghidra.app.util.importer.SingleLoaderFilter`.
pub struct SingleLoaderFilter {
    pub accepted_name: String,
}

impl SingleLoaderFilter {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            accepted_name: name.into(),
        }
    }
}

impl LoaderFilter for SingleLoaderFilter {
    fn accept(&self, loader_name: &str) -> bool {
        loader_name == self.accepted_name
    }
}

// ---------------------------------------------------------------------------
// MultipleProgramsException
// ---------------------------------------------------------------------------

/// Error when a binary file contains multiple programs (e.g., MZ + PE stub).
///
/// Ported from `ghidra.app.util.importer.MultipleProgramsException`.
#[derive(Debug)]
pub struct MultipleProgramsException {
    pub message: String,
}

impl MultipleProgramsException {
    pub fn new() -> Self {
        Self {
            message: "Multiple programs found in file".into(),
        }
    }

    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Default for MultipleProgramsException {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MultipleProgramsException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Multiple programs: {}", self.message)
    }
}

impl std::error::Error for MultipleProgramsException {}

// ---------------------------------------------------------------------------
// LibrarySearchPathManager
// ---------------------------------------------------------------------------

/// Manages search paths for resolving shared library dependencies.
///
/// Ported from `ghidra.app.util.importer.LibrarySearchPathManager`.
#[derive(Debug, Clone, Default)]
pub struct LibrarySearchPathManager {
    /// Paths to search for libraries.
    paths: Vec<PathBuf>,
    /// Library name overrides (name -> resolved path).
    overrides: HashMap<String, PathBuf>,
}

impl LibrarySearchPathManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a search path.
    pub fn add_path(&mut self, path: impl Into<PathBuf>) {
        self.paths.push(path.into());
    }

    /// Add multiple search paths.
    pub fn add_paths(&mut self, paths: impl IntoIterator<Item = impl Into<PathBuf>>) {
        for p in paths {
            self.paths.push(p.into());
        }
    }

    /// Get all search paths.
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// Add a library name override (maps library name to resolved path).
    pub fn add_override(&mut self, library_name: impl Into<String>, path: impl Into<PathBuf>) {
        self.overrides.insert(library_name.into(), path.into());
    }

    /// Resolve a library name to a path by searching in order.
    pub fn resolve(&self, library_name: &str) -> Option<PathBuf> {
        // Check overrides first
        if let Some(override_path) = self.overrides.get(library_name) {
            if override_path.exists() {
                return Some(override_path.clone());
            }
        }

        // Search paths
        for path in &self.paths {
            let candidate = path.join(library_name);
            if candidate.exists() {
                return Some(candidate);
            }
        }

        None
    }

    /// Check if a library name has been resolved.
    pub fn has_library(&self, library_name: &str) -> bool {
        self.resolve(library_name).is_some()
    }

    /// Get the number of registered paths.
    pub fn num_paths(&self) -> usize {
        self.paths.len()
    }

    /// Get the number of overrides.
    pub fn num_overrides(&self) -> usize {
        self.overrides.len()
    }
}

// ---------------------------------------------------------------------------
// Import Option types
// ---------------------------------------------------------------------------

/// A typed import option.
///
/// Ported from `ghidra.app.util.importer.options.AbstractOption` and subclasses.
#[derive(Debug, Clone)]
pub enum ImportOption {
    Boolean {
        name: String,
        value: bool,
        default: bool,
        description: Option<String>,
    },
    String {
        name: String,
        value: String,
        default: String,
        description: Option<String>,
    },
    Integer {
        name: String,
        value: i64,
        default: i64,
        description: Option<String>,
    },
    HexLong {
        name: String,
        value: u64,
        default: u64,
        description: Option<String>,
    },
    Address {
        name: String,
        value: u64,
        default: u64,
        description: Option<String>,
    },
    AddressSpace {
        name: String,
        value: String,
        default: String,
        description: Option<String>,
    },
    DomainFile {
        name: String,
        value: Option<String>,
        description: Option<String>,
    },
    DomainFolder {
        name: String,
        value: Option<String>,
        description: Option<String>,
    },
}

impl ImportOption {
    /// Create a boolean option.
    pub fn boolean(name: impl Into<String>, default: bool) -> Self {
        ImportOption::Boolean {
            name: name.into(),
            value: default,
            default,
            description: None,
        }
    }

    /// Create a string option.
    pub fn string(name: impl Into<String>, default: impl Into<String>) -> Self {
        let d = default.into();
        ImportOption::String {
            name: name.into(),
            value: d.clone(),
            default: d,
            description: None,
        }
    }

    /// Create an integer option.
    pub fn integer(name: impl Into<String>, default: i64) -> Self {
        ImportOption::Integer {
            name: name.into(),
            value: default,
            default,
            description: None,
        }
    }

    /// Create a hex long option.
    pub fn hex_long(name: impl Into<String>, default: u64) -> Self {
        ImportOption::HexLong {
            name: name.into(),
            value: default,
            default,
            description: None,
        }
    }

    /// Create an address option.
    pub fn address(name: impl Into<String>, default: u64) -> Self {
        ImportOption::Address {
            name: name.into(),
            value: default,
            default,
            description: None,
        }
    }

    /// Get the option name.
    pub fn name(&self) -> &str {
        match self {
            ImportOption::Boolean { name, .. } => name,
            ImportOption::String { name, .. } => name,
            ImportOption::Integer { name, .. } => name,
            ImportOption::HexLong { name, .. } => name,
            ImportOption::Address { name, .. } => name,
            ImportOption::AddressSpace { name, .. } => name,
            ImportOption::DomainFile { name, .. } => name,
            ImportOption::DomainFolder { name, .. } => name,
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        let d = Some(desc.into());
        match &mut self {
            ImportOption::Boolean { description, .. } => *description = d,
            ImportOption::String { description, .. } => *description = d,
            ImportOption::Integer { description, .. } => *description = d,
            ImportOption::HexLong { description, .. } => *description = d,
            ImportOption::Address { description, .. } => *description = d,
            ImportOption::AddressSpace { description, .. } => *description = d,
            ImportOption::DomainFile { description, .. } => *description = d,
            ImportOption::DomainFolder { description, .. } => *description = d,
        }
        self
    }

    /// Get the value as a boolean.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            ImportOption::Boolean { value, .. } => Some(*value),
            _ => None,
        }
    }

    /// Get the value as a string.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            ImportOption::String { value, .. } => Some(value),
            ImportOption::AddressSpace { value, .. } => Some(value),
            _ => None,
        }
    }

    /// Get the value as i64.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            ImportOption::Integer { value, .. } => Some(*value),
            _ => None,
        }
    }

    /// Get the value as u64.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            ImportOption::HexLong { value, .. } => Some(*value),
            ImportOption::Address { value, .. } => Some(*value),
            ImportOption::Integer { value, .. } => Some(*value as u64),
            _ => None,
        }
    }

    /// Reset the value to its default.
    pub fn reset_to_default(&mut self) {
        match self {
            ImportOption::Boolean { value, default, .. } => *value = *default,
            ImportOption::String { value, default, .. } => *value = default.clone(),
            ImportOption::Integer { value, default, .. } => *value = *default,
            ImportOption::HexLong { value, default, .. } => *value = *default,
            ImportOption::Address { value, default, .. } => *value = *default,
            ImportOption::AddressSpace { value, default, .. } => *value = default.clone(),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// ProgramLoaderBuilder
// ---------------------------------------------------------------------------

/// Builder for configuring and running a program import.
///
/// Ported from `ghidra.app.util.importer.ProgramLoader.Builder`.
///
/// # Example
///
/// ```rust,no_run
/// use ghidra_features::importer::*;
/// use ghidra_features::loader::framework::*;
///
/// let data = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
///                  2, 0, 62, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
/// let mut log = MessageLog::new();
/// let results = ProgramLoaderBuilder::new()
///     .source_bytes(data, "test.elf")
///     .load_spec_chooser(Box::new(FirstPreferredLoadSpecChooser))
///     .run(&mut log)
///     .unwrap();
/// ```
pub struct ProgramLoaderBuilder {
    data: Option<Vec<u8>>,
    name: String,
    language_id: Option<LanguageId>,
    compiler_spec_id: Option<CompilerSpecId>,
    load_spec_chooser: Option<Box<dyn LoadSpecChooser>>,
    option_chooser: Option<Box<dyn OptionChooser>>,
    loader_filter: Option<Box<dyn LoaderFilter>>,
    loader_args: Vec<(String, String)>,
    options: Vec<LoadOption>,
    mirror_fs_layout: bool,
}

impl ProgramLoaderBuilder {
    pub fn new() -> Self {
        Self {
            data: None,
            name: String::new(),
            language_id: None,
            compiler_spec_id: None,
            load_spec_chooser: None,
            option_chooser: None,
            loader_filter: None,
            loader_args: Vec::new(),
            options: Vec::new(),
            mirror_fs_layout: false,
        }
    }

    /// Set the source data and name.
    pub fn source_bytes(mut self, data: Vec<u8>, name: impl Into<String>) -> Self {
        self.data = Some(data);
        self.name = name.into();
        self
    }

    /// Set a language/compiler spec hint.
    pub fn language_hint(mut self, language_id: impl Into<String>) -> Self {
        self.language_id = Some(LanguageId(language_id.into()));
        self
    }

    /// Set a compiler spec hint.
    pub fn compiler_hint(mut self, compiler_spec_id: impl Into<String>) -> Self {
        self.compiler_spec_id = Some(CompilerSpecId(compiler_spec_id.into()));
        self
    }

    /// Set the load spec chooser.
    pub fn load_spec_chooser(mut self, chooser: Box<dyn LoadSpecChooser>) -> Self {
        self.load_spec_chooser = Some(chooser);
        self
    }

    /// Set the option chooser.
    pub fn option_chooser(mut self, chooser: Box<dyn OptionChooser>) -> Self {
        self.option_chooser = Some(chooser);
        self
    }

    /// Set a loader filter.
    pub fn loader_filter(mut self, filter: Box<dyn LoaderFilter>) -> Self {
        self.loader_filter = Some(filter);
        self
    }

    /// Add a loader argument.
    pub fn loader_arg(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.loader_args.push((key.into(), value.into()));
        self
    }

    /// Add a load option.
    pub fn option(mut self, option: LoadOption) -> Self {
        self.options.push(option);
        self
    }

    /// Set mirror filesystem layout flag.
    pub fn mirror_fs_layout(mut self, mirror: bool) -> Self {
        self.mirror_fs_layout = mirror;
        self
    }

    /// Execute the import.
    pub fn run(self, log: &mut MessageLog) -> Result<LoadResults, LoadError> {
        let data = self
            .data
            .ok_or_else(|| LoadError::InvalidOption("No source data provided".into()))?;

        // Auto-detect format and load
        crate::loader::auto_load(&data, &self.options, log)
    }
}

impl Default for ProgramLoaderBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AutoImporter
// ---------------------------------------------------------------------------

/// Convenience methods for automatic (headless) imports.
///
/// Ported from `ghidra.app.util.importer.AutoImporter`.
pub struct AutoImporter;

impl AutoImporter {
    /// Import a byte slice, auto-detecting format.
    pub fn import_bytes(
        data: &[u8],
        _name: &str,
        options: &[LoadOption],
        log: &mut MessageLog,
    ) -> Result<LoadResults, LoadError> {
        crate::loader::auto_load(data, options, log)
    }

    /// Import using a specific loader.
    pub fn import_with_loader(
        data: &[u8],
        loader_name: &str,
        options: &[LoadOption],
        log: &mut MessageLog,
    ) -> Result<LoadResults, LoadError> {
        crate::loader::load_with_loader(loader_name, data, options, log)
    }

    /// Detect the format of a byte slice.
    pub fn detect_format(data: &[u8]) -> Option<&'static str> {
        crate::loader::detect_format(data)
    }

    /// Find all load specs for a byte slice.
    pub fn find_load_specs(data: &[u8]) -> Vec<(String, Vec<LoadSpec>)> {
        crate::loader::find_all_load_specs(data)
    }
}

// ---------------------------------------------------------------------------
// LoaderMap (opinion)
// ---------------------------------------------------------------------------

/// A map of loader names to their load specs.
///
/// Ported from `ghidra.app.util.opinion.LoaderMap`.
#[derive(Debug, Clone, Default)]
pub struct LoaderMap {
    entries: Vec<LoaderMapEntry>,
}

#[derive(Debug, Clone)]
struct LoaderMapEntry {
    loader_name: String,
    tier: LoaderTier,
    tier_priority: i32,
    specs: Vec<LoadSpec>,
}

impl LoaderMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a loader with its load specs.
    pub fn insert(
        &mut self,
        loader_name: impl Into<String>,
        tier: LoaderTier,
        tier_priority: i32,
        specs: Vec<LoadSpec>,
    ) {
        let loader_name = loader_name.into();
        // Remove existing entry with same name
        self.entries.retain(|e| e.loader_name != loader_name);
        self.entries.push(LoaderMapEntry {
            loader_name,
            tier,
            tier_priority,
            specs,
        });
        // Keep sorted by tier and priority
        self.entries
            .sort_by_key(|e| (e.tier.priority() as i32, e.tier_priority));
    }

    /// Get all loader names in priority order.
    pub fn loader_names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.loader_name.as_str()).collect()
    }

    /// Get all load specs for a loader.
    pub fn get_specs(&self, loader_name: &str) -> Option<&[LoadSpec]> {
        self.entries
            .iter()
            .find(|e| e.loader_name == loader_name)
            .map(|e| e.specs.as_slice())
    }

    /// Get all entries as (name, specs) pairs.
    pub fn entries(&self) -> Vec<(&str, &[LoadSpec])> {
        self.entries
            .iter()
            .map(|e| (e.loader_name.as_str(), e.specs.as_slice()))
            .collect()
    }

    /// Get the number of loaders.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Find the first preferred load spec across all loaders.
    pub fn first_preferred(&self) -> Option<(&str, &LoadSpec)> {
        for entry in &self.entries {
            if let Some(spec) = entry.specs.iter().find(|s| s.is_preferred) {
                return Some((&entry.loader_name, spec));
            }
        }
        None
    }

    /// Get all load specs across all loaders, flattened.
    pub fn all_specs(&self) -> Vec<(&str, &LoadSpec)> {
        self.entries
            .iter()
            .flat_map(|e| e.specs.iter().map(move |s| (e.loader_name.as_str(), s)))
            .collect()
    }
}

impl fmt::Display for LoaderMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for entry in &self.entries {
            writeln!(
                f,
                "{} - {} load specs",
                entry.loader_name,
                entry.specs.len()
            )?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MemorySection (opinion helper)
// ---------------------------------------------------------------------------

/// Defines a memory section to be loaded.
///
/// Ported from `ghidra.app.util.opinion.MemorySection`.
#[derive(Debug, Clone)]
pub struct MemorySection {
    /// Section name.
    pub name: String,
    /// File offset of the section data.
    pub file_offset: u64,
    /// Byte length of the section.
    pub length: u64,
    /// Physical start address.
    pub start_address: u64,
    /// Whether this section is initialized (has file data).
    pub is_initialized: bool,
    /// Read permission.
    pub is_readable: bool,
    /// Write permission.
    pub is_writable: bool,
    /// Execute permission.
    pub is_executable: bool,
    /// Optional comment.
    pub comment: Option<String>,
    /// Whether fragmentation is OK (may be split on conflict).
    pub is_fragmentation_ok: bool,
}

impl MemorySection {
    /// Create a new memory section.
    pub fn new(
        name: impl Into<String>,
        file_offset: u64,
        length: u64,
        start_address: u64,
    ) -> Self {
        Self {
            name: name.into(),
            file_offset,
            length,
            start_address,
            is_initialized: true,
            is_readable: true,
            is_writable: false,
            is_executable: false,
            comment: None,
            is_fragmentation_ok: true,
        }
    }

    /// Create an uninitialized (BSS) section.
    pub fn uninitialized(
        name: impl Into<String>,
        start_address: u64,
        length: u64,
    ) -> Self {
        Self {
            name: name.into(),
            file_offset: 0,
            length,
            start_address,
            is_initialized: false,
            is_readable: true,
            is_writable: true,
            is_executable: false,
            comment: None,
            is_fragmentation_ok: true,
        }
    }

    /// Get the end address.
    pub fn end_address(&self) -> u64 {
        self.start_address + self.length
    }

    /// Set permissions.
    pub fn with_permissions(mut self, read: bool, write: bool, execute: bool) -> Self {
        self.is_readable = read;
        self.is_writable = write;
        self.is_executable = execute;
        self
    }

    /// Set comment.
    pub fn with_comment(mut self, comment: impl Into<String>) -> Self {
        self.comment = Some(comment.into());
        self
    }

    /// Set fragmentation OK flag.
    pub fn with_fragmentation_ok(mut self, ok: bool) -> Self {
        self.is_fragmentation_ok = ok;
        self
    }
}

// ---------------------------------------------------------------------------
// MemorySectionResolver
// ---------------------------------------------------------------------------

/// Resolves memory section layout, handling overlaps and conflicts.
///
/// Ported from `ghidra.app.util.opinion.MemorySectionResolver`.
#[derive(Debug, Default)]
pub struct MemorySectionResolver {
    sections: Vec<MemorySection>,
}

impl MemorySectionResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a memory section.
    pub fn add_section(&mut self, section: MemorySection) {
        self.sections.push(section);
    }

    /// Get all sections.
    pub fn sections(&self) -> &[MemorySection] {
        &self.sections
    }

    /// Check for overlaps between sections.
    ///
    /// Returns a list of (section_a_index, section_b_index) pairs for
    /// sections that overlap in address space.
    pub fn find_overlaps(&self) -> Vec<(usize, usize)> {
        let mut overlaps = Vec::new();
        for i in 0..self.sections.len() {
            for j in (i + 1)..self.sections.len() {
                let a = &self.sections[i];
                let b = &self.sections[j];
                if a.start_address < b.end_address() && b.start_address < a.end_address() {
                    overlaps.push((i, j));
                }
            }
        }
        overlaps
    }

    /// Resolve the section layout, returning the final ordered sections.
    ///
    /// Sections are sorted by start address. Fragmentable sections that
    /// overlap with non-fragmentable ones may be split.
    pub fn resolve(&self) -> Vec<MemorySection> {
        let mut resolved: Vec<MemorySection> = self.sections.clone();
        resolved.sort_by_key(|s| s.start_address);
        resolved
    }

    /// Get the total memory footprint (min address to max address).
    pub fn total_range(&self) -> Option<(u64, u64)> {
        if self.sections.is_empty() {
            return None;
        }
        let min = self.sections.iter().map(|s| s.start_address).min()?;
        let max = self.sections.iter().map(|s| s.end_address()).max()?;
        Some((min, max))
    }

    /// Get the number of sections.
    pub fn num_sections(&self) -> usize {
        self.sections.len()
    }

    /// Clear all sections.
    pub fn clear(&mut self) {
        self.sections.clear();
    }
}

// ---------------------------------------------------------------------------
// LibraryHints (opinion helper)
// ---------------------------------------------------------------------------

/// Hints for resolving library dependencies.
///
/// Ported from `ghidra.app.util.opinion.LibraryHints`.
#[derive(Debug, Clone, Default)]
pub struct LibraryHints {
    /// Library name to search path mappings.
    pub hints: HashMap<String, Vec<PathBuf>>,
}

impl LibraryHints {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a hint for a library.
    pub fn add_hint(&mut self, library_name: impl Into<String>, path: impl Into<PathBuf>) {
        self.hints
            .entry(library_name.into())
            .or_default()
            .push(path.into());
    }

    /// Get the hints for a library.
    pub fn get_hints(&self, library_name: &str) -> Option<&[PathBuf]> {
        self.hints.get(library_name).map(|v| v.as_slice())
    }

    /// Check if a library has hints.
    pub fn has_hints(&self, library_name: &str) -> bool {
        self.hints.contains_key(library_name)
    }
}

// ---------------------------------------------------------------------------
// DefExportLine (opinion helper for DEF file parsing)
// ---------------------------------------------------------------------------

/// A parsed line from a Windows DEF file (module definition).
///
/// Ported from `ghidra.app.util.opinion.DefExportLine`.
#[derive(Debug, Clone)]
pub struct DefExportLine {
    /// Exported symbol name.
    pub name: String,
    /// Optional ordinal number.
    pub ordinal: Option<u32>,
    /// Optional internal name (if different from export name).
    pub internal_name: Option<String>,
    /// Whether the export is by name (vs ordinal-only).
    pub by_name: bool,
    /// Whether this is a data export.
    pub is_data: bool,
    /// Whether this is a private export.
    pub is_private: bool,
}

impl DefExportLine {
    /// Parse a DEF export line.
    ///
    /// Supports formats like:
    /// - `FunctionName`
    /// - `FunctionName @1`
    /// - `FunctionName=InternalName @2`
    /// - `FunctionName @3 DATA`
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('[') {
            return None;
        }

        let (rest, is_data) = if line.to_uppercase().ends_with(" DATA") {
            (&line[..line.len() - 5], true)
        } else if line.to_uppercase().ends_with(" PRIVATE") {
            (&line[..line.len() - 8], false) // Private handling below
        } else {
            (line, false)
        };

        let (rest, is_private) = if rest.to_uppercase().ends_with(" PRIVATE") {
            (&rest[..rest.len() - 8], true)
        } else {
            (rest, false)
        };

        // Split on '@' for ordinal
        let (name_part, ordinal) = if let Some(at_pos) = rest.find('@') {
            let ordinal_str = rest[at_pos + 1..].trim();
            let ord = ordinal_str.parse::<u32>().ok();
            (&rest[..at_pos], ord)
        } else {
            (rest, None)
        };

        // Split on '=' for internal name
        let (name, internal_name) = if let Some(eq_pos) = name_part.find('=') {
            (
                name_part[..eq_pos].trim().to_string(),
                Some(name_part[eq_pos + 1..].trim().to_string()),
            )
        } else {
            (name_part.trim().to_string(), None)
        };

        if name.is_empty() {
            return None;
        }

        Some(DefExportLine {
            name,
            ordinal,
            internal_name,
            by_name: true,
            is_data,
            is_private,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_preferred_chooser() {
        let chooser = FirstPreferredLoadSpecChooser;
        let specs = vec![
            LoadSpecChoice {
                loader_name: "ELF".into(),
                load_spec: LoadSpec::with_unknown_language("ELF", 0, true),
                index: 0,
            },
            LoadSpecChoice {
                loader_name: "Binary".into(),
                load_spec: LoadSpec {
                    loader_name: "Binary".into(),
                    image_base: 0,
                    language_compiler_spec: None,
                    is_preferred: true,
                    requires_language_compiler_spec: false,
                },
                index: 1,
            },
        ];
        assert_eq!(chooser.choose(&specs), Some(1));
    }

    #[test]
    fn test_first_preferred_no_preferred() {
        let chooser = FirstPreferredLoadSpecChooser;
        let specs = vec![
            LoadSpecChoice {
                loader_name: "ELF".into(),
                load_spec: LoadSpec::with_unknown_language("ELF", 0, true),
                index: 0,
            },
        ];
        assert_eq!(chooser.choose(&specs), None);
    }

    #[test]
    fn test_lcs_hint_chooser() {
        let chooser = LcsHintLoadSpecChooser::from_pair(&LanguageCompilerSpecPair::new(
            "x86:LE:64:default",
            "default",
        ));
        let lcs = LanguageCompilerSpecPair::new("x86:LE:64:default", "default");
        let specs = vec![
            LoadSpecChoice {
                loader_name: "ELF".into(),
                load_spec: LoadSpec::new("ELF", 0x400000, lcs, true),
                index: 0,
            },
        ];
        assert_eq!(chooser.choose(&specs), Some(0));
    }

    #[test]
    fn test_cs_hint_chooser() {
        let chooser = CsHintLoadSpecChooser::new(CompilerSpecId("windows".into()));
        let lcs1 = LanguageCompilerSpecPair::new("x86:LE:64:default", "default");
        let lcs2 = LanguageCompilerSpecPair::new("x86:LE:64:default", "windows");
        let specs = vec![
            LoadSpecChoice {
                loader_name: "ELF".into(),
                load_spec: LoadSpec::new("ELF", 0, lcs1, false),
                index: 0,
            },
            LoadSpecChoice {
                loader_name: "PE".into(),
                load_spec: LoadSpec::new("PE", 0, lcs2, true),
                index: 1,
            },
        ];
        assert_eq!(chooser.choose(&specs), Some(1));
    }

    #[test]
    fn test_multiple_programs_exception() {
        let e = MultipleProgramsException::new();
        assert!(e.to_string().contains("Multiple programs"));

        let e2 = MultipleProgramsException::with_message("MZ+PE");
        assert!(e2.to_string().contains("MZ+PE"));
    }

    #[test]
    fn test_library_search_path_manager() {
        let mut mgr = LibrarySearchPathManager::new();
        assert!(mgr.paths().is_empty());

        mgr.add_path("/usr/lib");
        mgr.add_path("/usr/local/lib");
        assert_eq!(mgr.num_paths(), 2);

        mgr.add_override("libc.so", "/lib/x86_64-linux-gnu/libc.so.6");
        assert_eq!(mgr.num_overrides(), 1);
    }

    #[test]
    fn test_import_option_boolean() {
        let opt = ImportOption::boolean("Overlay", true);
        assert_eq!(opt.name(), "Overlay");
        assert_eq!(opt.as_bool(), Some(true));
        assert!(opt.as_str().is_none());
    }

    #[test]
    fn test_import_option_string() {
        let opt = ImportOption::string("Block Name", ".text");
        assert_eq!(opt.as_str(), Some(".text"));
    }

    #[test]
    fn test_import_option_integer() {
        let opt = ImportOption::integer("Base Address", 0x400000);
        assert_eq!(opt.as_i64(), Some(0x400000));
        assert_eq!(opt.as_u64(), Some(0x400000));
    }

    #[test]
    fn test_import_option_hex_long() {
        let opt = ImportOption::hex_long("Offset", 0x1000);
        assert_eq!(opt.as_u64(), Some(0x1000));
    }

    #[test]
    fn test_import_option_address() {
        let opt = ImportOption::address("Entry Point", 0x401000);
        assert_eq!(opt.as_u64(), Some(0x401000));
    }

    #[test]
    fn test_import_option_with_description() {
        let opt = ImportOption::boolean("Test", false).with_description("A test option");
        match &opt {
            ImportOption::Boolean { description, .. } => {
                assert_eq!(description.as_deref(), Some("A test option"));
            }
            _ => panic!("wrong type"),
        }
    }

    #[test]
    fn test_import_option_reset() {
        let mut opt = ImportOption::boolean("Test", true);
        match &mut opt {
            ImportOption::Boolean { value, .. } => *value = false,
            _ => {}
        }
        assert_eq!(opt.as_bool(), Some(false));
        opt.reset_to_default();
        assert_eq!(opt.as_bool(), Some(true));
    }

    #[test]
    fn test_program_loader_builder_no_data() {
        let mut log = MessageLog::new();
        let result = ProgramLoaderBuilder::new().run(&mut log);
        assert!(result.is_err());
    }

    #[test]
    fn test_auto_importer() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2; // ELFCLASS64
        data[5] = 1; // ELFDATA2LSB
        data[6] = 1; // EV_CURRENT
        data[16] = 2; // ET_EXEC
        data[18] = 62; // EM_X86_64

        let mut log = MessageLog::new();
        let results = AutoImporter::import_bytes(&data, "test.elf", &[], &mut log).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_auto_importer_detect_format() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        assert_eq!(AutoImporter::detect_format(&data), Some("Executable and Linking Format (ELF)"));

        let unknown = [0x00u8; 16];
        assert!(AutoImporter::detect_format(&unknown).is_none());
    }

    #[test]
    fn test_auto_importer_find_specs() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 2;
        data[5] = 1;
        let specs = AutoImporter::find_load_specs(&data);
        assert!(!specs.is_empty());
    }

    #[test]
    fn test_loader_map() {
        let mut map = LoaderMap::new();
        assert!(map.is_empty());

        map.insert(
            "ELF",
            LoaderTier::GenericTargetLoader,
            0,
            vec![LoadSpec::with_unknown_language("ELF", 0x400000, true)],
        );
        map.insert(
            "Raw Binary",
            LoaderTier::UntargetedLoader,
            100,
            vec![LoadSpec::with_unknown_language("Raw Binary", 0, true)],
        );

        assert_eq!(map.len(), 2);
        let names = map.loader_names();
        assert_eq!(names[0], "ELF");
        assert_eq!(names[1], "Raw Binary");
    }

    #[test]
    fn test_loader_map_first_preferred() {
        let mut map = LoaderMap::new();
        map.insert(
            "ELF",
            LoaderTier::GenericTargetLoader,
            0,
            vec![LoadSpec::with_unknown_language("ELF", 0, false)],
        );
        let (name, _spec) = map.first_preferred().unwrap();
        assert_eq!(name, "ELF");
    }

    #[test]
    fn test_loader_map_display() {
        let mut map = LoaderMap::new();
        map.insert(
            "ELF",
            LoaderTier::GenericTargetLoader,
            0,
            vec![LoadSpec::with_unknown_language("ELF", 0, true)],
        );
        let display = format!("{}", map);
        assert!(display.contains("ELF"));
        assert!(display.contains("1 load specs"));
    }

    #[test]
    fn test_memory_section() {
        let section = MemorySection::new(".text", 0x1000, 0x2000, 0x401000);
        assert_eq!(section.name, ".text");
        assert_eq!(section.file_offset, 0x1000);
        assert_eq!(section.length, 0x2000);
        assert_eq!(section.start_address, 0x401000);
        assert_eq!(section.end_address(), 0x403000);
        assert!(section.is_initialized);
        assert!(section.is_readable);
        assert!(!section.is_writable);
    }

    #[test]
    fn test_memory_section_uninitialized() {
        let section = MemorySection::uninitialized(".bss", 0x500000, 0x10000);
        assert!(!section.is_initialized);
        assert!(section.is_writable);
    }

    #[test]
    fn test_memory_section_builder() {
        let section = MemorySection::new(".data", 0, 1024, 0x600000)
            .with_permissions(true, true, false)
            .with_comment("initialized data")
            .with_fragmentation_ok(false);
        assert!(section.is_writable);
        assert_eq!(section.comment.as_deref(), Some("initialized data"));
        assert!(!section.is_fragmentation_ok);
    }

    #[test]
    fn test_memory_section_resolver() {
        let mut resolver = MemorySectionResolver::new();
        assert_eq!(resolver.num_sections(), 0);

        resolver.add_section(MemorySection::new(".text", 0x1000, 0x2000, 0x401000));
        resolver.add_section(MemorySection::new(".data", 0x3000, 0x1000, 0x403000));
        assert_eq!(resolver.num_sections(), 2);

        let overlaps = resolver.find_overlaps();
        assert!(overlaps.is_empty()); // no overlap
    }

    #[test]
    fn test_memory_section_resolver_overlap() {
        let mut resolver = MemorySectionResolver::new();
        resolver.add_section(MemorySection::new(".a", 0, 100, 0x1000));
        resolver.add_section(MemorySection::new(".b", 0, 100, 0x1050)); // overlaps

        let overlaps = resolver.find_overlaps();
        assert_eq!(overlaps.len(), 1);
        assert_eq!(overlaps[0], (0, 1));
    }

    #[test]
    fn test_memory_section_resolver_total_range() {
        let mut resolver = MemorySectionResolver::new();
        resolver.add_section(MemorySection::new(".text", 0, 100, 0x401000));
        resolver.add_section(MemorySection::new(".data", 0, 50, 0x403000));

        let (min, max) = resolver.total_range().unwrap();
        assert_eq!(min, 0x401000);
        assert_eq!(max, 0x403032); // 0x403000 + 50
    }

    #[test]
    fn test_memory_section_resolver_resolve() {
        let mut resolver = MemorySectionResolver::new();
        resolver.add_section(MemorySection::new(".data", 0, 100, 0x403000));
        resolver.add_section(MemorySection::new(".text", 0, 100, 0x401000));

        let resolved = resolver.resolve();
        assert_eq!(resolved[0].name, ".text"); // sorted by address
        assert_eq!(resolved[1].name, ".data");
    }

    #[test]
    fn test_def_export_line() {
        let line = DefExportLine::parse("MyFunction @1").unwrap();
        assert_eq!(line.name, "MyFunction");
        assert_eq!(line.ordinal, Some(1));
        assert!(line.by_name);
        assert!(!line.is_data);
    }

    #[test]
    fn test_def_export_line_with_internal_name() {
        let line = DefExportLine::parse("ExportName=InternalName @5").unwrap();
        assert_eq!(line.name, "ExportName");
        assert_eq!(line.internal_name.as_deref(), Some("InternalName"));
        assert_eq!(line.ordinal, Some(5));
    }

    #[test]
    fn test_def_export_line_data() {
        let line = DefExportLine::parse("GlobalVar @3 DATA").unwrap();
        assert_eq!(line.name, "GlobalVar");
        assert!(line.is_data);
    }

    #[test]
    fn test_def_export_line_no_ordinal() {
        let line = DefExportLine::parse("SimpleFunc").unwrap();
        assert_eq!(line.name, "SimpleFunc");
        assert_eq!(line.ordinal, None);
    }

    #[test]
    fn test_def_export_line_comment() {
        assert!(DefExportLine::parse("; this is a comment").is_none());
        assert!(DefExportLine::parse("[EXPORTS]").is_none());
    }

    #[test]
    fn test_def_export_line_empty() {
        assert!(DefExportLine::parse("").is_none());
        assert!(DefExportLine::parse("   ").is_none());
    }

    #[test]
    fn test_library_hints() {
        let mut hints = LibraryHints::new();
        assert!(!hints.has_hints("libc.so"));

        hints.add_hint("libc.so", "/lib/x86_64-linux-gnu/libc.so.6");
        hints.add_hint("libc.so", "/usr/lib/libc.so.6");
        assert!(hints.has_hints("libc.so"));
        assert_eq!(hints.get_hints("libc.so").unwrap().len(), 2);
    }

    #[test]
    fn test_single_loader_filter() {
        let filter = SingleLoaderFilter::new("ELF");
        assert!(filter.accept("ELF"));
        assert!(!filter.accept("PE"));
        assert!(!filter.accept("Binary"));
    }

    #[test]
    fn test_accept_all_loaders() {
        let filter = AcceptAllLoaders;
        assert!(filter.accept("ELF"));
        assert!(filter.accept("PE"));
        assert!(filter.accept("anything"));
    }

    #[test]
    fn test_default_option_chooser() {
        let chooser = DefaultOptionChooser;
        let opts = vec![
            LoadOption::new_bool("Test", true),
            LoadOption::new_string("Name", "value"),
        ];
        let result = chooser.choose(opts);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_loader_map_insert_overwrite() {
        let mut map = LoaderMap::new();
        map.insert("ELF", LoaderTier::GenericTargetLoader, 0, vec![]);
        map.insert(
            "ELF",
            LoaderTier::GenericTargetLoader,
            1,
            vec![LoadSpec::with_unknown_language("ELF", 0, true)],
        );
        assert_eq!(map.len(), 1); // overwritten
        assert_eq!(map.get_specs("ELF").unwrap().len(), 1);
    }
}
