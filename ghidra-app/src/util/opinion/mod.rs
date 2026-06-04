//! Loader framework (ported from `ghidra.app.util.opinion`).
//!
//! This module provides:
//! - [`Loader`] trait -- the interface all file-format loaders implement
//! - [`LoadSpec`] -- describes a loader configuration (processor, language, compiler spec)
//! - [`Loaded`] -- a loaded program result
//! - [`LoadResults`] -- collection of `Loaded` programs from a single import
//! - [`LoaderTier`] -- loader classification (native, analysis-derived, etc.)

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::util::importer::MessageLog;
use crate::util::{GhidraOption, OptionValue};

// ===================================================================
// LoaderTier  (ghidra.app.util.opinion.LoaderTier)
// ===================================================================

/// Classification of how a `Loader` identifies files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LoaderTier {
    /// Primary loaders that identify files by magic bytes / headers.
    ///
    /// Examples: ELF, PE, Mach-O.
    Native,

    /// Loaders that require analysis (e.g. pattern matching) to
    /// identify the format.
    ///
    /// Examples: COFF variants, some firmware formats.
    AnalysisDerived,

    /// Loaders that use heuristics to guess the format.
    Heuristic,

    /// Low-confidence / fallback loaders (e.g. raw binary).
    Unknown,
}

impl LoaderTier {
    /// Priority value for sorting (lower = higher priority).
    pub fn priority(self) -> u32 {
        match self {
            Self::Native => 0,
            Self::AnalysisDerived => 1,
            Self::Heuristic => 2,
            Self::Unknown => 3,
        }
    }
}

// ===================================================================
// LoadSpec  (ghidra.app.util.opinion.LoadSpec)
// ===================================================================

/// Describes a loader configuration.
///
/// Each `LoadSpec` maps a specific loader to a (language, compiler-spec)
/// pair. When a file can be loaded in multiple ways, the loader produces
/// multiple `LoadSpec`s.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadSpec {
    /// The loader that produced this spec.
    pub loader_name: String,
    /// Processor name (e.g. "x86", "ARM", "MIPS").
    pub processor: String,
    /// Address size in bits.
    pub address_size: usize,
    /// Endianness.
    pub big_endian: bool,
    /// Language variant identifier (e.g. "LE:64:default").
    pub variant: String,
    /// Compiler spec identifier (e.g. "default", "gcc", "windows").
    pub compiler_spec: String,
    /// Tier / confidence of this load spec.
    pub tier: LoaderTier,
    /// Whether this spec was found via analysis rather than header parsing.
    pub analyzed: bool,
    /// Additional properties.
    pub properties: HashMap<String, String>,
}

impl LoadSpec {
    /// Create a new load spec.
    pub fn new(
        loader_name: impl Into<String>,
        processor: impl Into<String>,
        address_size: usize,
        big_endian: bool,
    ) -> Self {
        Self {
            loader_name: loader_name.into(),
            processor: processor.into(),
            address_size,
            big_endian,
            variant: "default".into(),
            compiler_spec: "default".into(),
            tier: LoaderTier::Native,
            analyzed: false,
            properties: HashMap::new(),
        }
    }

    /// Builder: set variant.
    pub fn with_variant(mut self, v: impl Into<String>) -> Self {
        self.variant = v.into();
        self
    }

    /// Builder: set compiler spec.
    pub fn with_compiler_spec(mut self, cs: impl Into<String>) -> Self {
        self.compiler_spec = cs.into();
        self
    }

    /// Builder: set tier.
    pub fn with_tier(mut self, tier: LoaderTier) -> Self {
        self.tier = tier;
        self
    }

    /// Builder: mark as analysis-derived.
    pub fn as_analyzed(mut self) -> Self {
        self.analyzed = true;
        self.tier = LoaderTier::AnalysisDerived;
        self
    }

    /// Return the full language ID string.
    pub fn language_id(&self) -> String {
        format!(
            "{}:{}:{}",
            if self.big_endian { "BE" } else { "LE" },
            self.address_size,
            self.variant
        )
    }
}

// ===================================================================
// Loader errors
// ===================================================================

/// Errors that can occur during loading.
#[derive(Debug, Error)]
pub enum LoaderError {
    /// The file format is not supported by this loader.
    #[error("unsupported format: {0}")]
    Unsupported(String),
    /// A parsing error occurred.
    #[error("parse error: {0}")]
    ParseError(String),
    /// The load was cancelled.
    #[error("load cancelled")]
    Cancelled,
    /// Version mismatch (e.g. unsupported DWARF version).
    #[error("version error: {0}")]
    VersionError(String),
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ===================================================================
// Loaded  (ghidra.app.util.opinion.Loaded)
// ===================================================================

/// Represents a single program produced by a loader.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// Name of the loaded program.
    pub name: String,
    /// The load spec used.
    pub load_spec: LoadSpec,
    /// Address space name.
    pub address_space: String,
    /// Base address.
    pub base_address: u64,
    /// Length of loaded image.
    pub image_length: u64,
    /// Optional messages.
    pub messages: MessageLog,
}

impl Loaded {
    /// Create a new loaded program entry.
    pub fn new(name: impl Into<String>, load_spec: LoadSpec, base_address: u64) -> Self {
        Self {
            name: name.into(),
            load_spec,
            address_space: "default".into(),
            base_address,
            image_length: 0,
            messages: MessageLog::new(),
        }
    }
}

// ===================================================================
// LoadResults  (ghidra.app.util.opinion.LoadResults)
// ===================================================================

/// Collection of programs produced from a single import operation.
#[derive(Debug, Clone)]
pub struct LoadResults {
    results: Vec<Loaded>,
}

impl LoadResults {
    /// Create empty results.
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    /// Create results from a single loaded program.
    pub fn single(loaded: Loaded) -> Self {
        Self {
            results: vec![loaded],
        }
    }

    /// Add a loaded program.
    pub fn push(&mut self, loaded: Loaded) {
        self.results.push(loaded);
    }

    /// Return the number of loaded programs.
    pub fn len(&self) -> usize {
        self.results.len()
    }

    /// Return `true` if empty.
    pub fn is_empty(&self) -> bool {
        self.results.is_empty()
    }

    /// Get the first (primary) loaded program.
    pub fn primary(&self) -> Option<&Loaded> {
        self.results.first()
    }

    /// Get all loaded programs.
    pub fn all(&self) -> &[Loaded] {
        &self.results
    }

    /// Consume and return all loaded programs.
    pub fn into_inner(self) -> Vec<Loaded> {
        self.results
    }

    /// Return `true` if any loaded program has errors.
    pub fn has_errors(&self) -> bool {
        self.results.iter().any(|r| r.messages.has_errors())
    }
}

impl Default for LoadResults {
    fn default() -> Self {
        Self::new()
    }
}

// ===================================================================
// Loader trait  (ghidra.app.util.opinion.Loader)
// ===================================================================

/// Interface that all file-format loaders must implement.
///
/// A loader identifies one file format and knows how to parse it into
/// one or more programs.
pub trait Loader: Send + Sync {
    /// Human-readable name (e.g. "ELF Loader", "PE Loader").
    fn name(&self) -> &str;

    /// Return the loader tier (native, analysis-derived, etc.).
    fn tier(&self) -> LoaderTier;

    /// Return the command-line argument prefix for this loader's options.
    fn command_line_arg_prefix(&self) -> &str {
        "-loader"
    }

    /// Find all `LoadSpec`s for the given data.
    ///
    /// Return an empty list if this loader cannot handle the data.
    fn find_load_specs(
        &self,
        data: &[u8],
        library_search_paths: &[&str],
    ) -> Vec<LoadSpec>;

    /// Return the default options for this loader.
    fn default_options(&self, load_spec: &LoadSpec) -> Vec<GhidraOption>;

    /// Validate that the provided options are acceptable.
    fn validate_options(
        &self,
        load_spec: &LoadSpec,
        options: &[GhidraOption],
    ) -> Result<(), String>;

    /// Load the data into one or more programs.
    ///
    /// This is the main entry point for loading.
    fn load(
        &self,
        data: &[u8],
        load_spec: &LoadSpec,
        options: &[GhidraOption],
        log: &MessageLog,
    ) -> Result<LoadResults, LoaderError>;
}

// ===================================================================
// Loader utilities
// ===================================================================

/// Sort loaders by priority (tier, then name).
pub fn sort_loaders(loaders: &mut [Box<dyn Loader>]) {
    loaders.sort_by(|a, b| {
        a.tier()
            .priority()
            .cmp(&b.tier().priority())
            .then_with(|| a.name().cmp(b.name()))
    });
}

/// Find the first loader that can handle the given data.
pub fn find_first_compatible_loader<'a>(
    loaders: &'a [Box<dyn Loader>],
    data: &[u8],
) -> Option<&'a dyn Loader> {
    for loader in loaders {
        let specs = loader.find_load_specs(data, &[]);
        if !specs.is_empty() {
            return Some(loader.as_ref());
        }
    }
    None
}

/// Find all load specs from all registered loaders.
pub fn find_all_load_specs(
    loaders: &[Box<dyn Loader>],
    data: &[u8],
) -> Vec<(usize, LoadSpec)> {
    let mut result = Vec::new();
    for (idx, loader) in loaders.iter().enumerate() {
        let specs = loader.find_load_specs(data, &[]);
        for spec in specs {
            result.push((idx, spec));
        }
    }
    result
}

// ===================================================================
// Tests
// ===================================================================

#[cfg(test)]
mod tests {
    use super::*;

    struct TestLoader {
        name: String,
    }

    impl Loader for TestLoader {
        fn name(&self) -> &str {
            &self.name
        }

        fn tier(&self) -> LoaderTier {
            LoaderTier::Native
        }

        fn find_load_specs(&self, data: &[u8], _: &[&str]) -> Vec<LoadSpec> {
            if data.starts_with(&[0x7F, b'E', b'L', b'F']) {
                vec![LoadSpec::new(&self.name, "x86", 64, false)]
            } else {
                vec![]
            }
        }

        fn default_options(&self, _: &LoadSpec) -> Vec<GhidraOption> {
            vec![GhidraOption::bool_opt("Apply Signature", true)]
        }

        fn validate_options(&self, _: &LoadSpec, _: &[GhidraOption]) -> Result<(), String> {
            Ok(())
        }

        fn load(
            &self,
            _: &[u8],
            spec: &LoadSpec,
            _: &[GhidraOption],
            _: &MessageLog,
        ) -> Result<LoadResults, LoaderError> {
            Ok(LoadResults::single(Loaded::new(
                "test",
                spec.clone(),
                0x400000,
            )))
        }
    }

    #[test]
    fn load_spec_builder() {
        let spec = LoadSpec::new("ELF", "x86", 64, false)
            .with_variant("LE:64:default")
            .with_compiler_spec("gcc")
            .with_tier(LoaderTier::Native);
        assert_eq!(spec.loader_name, "ELF");
        assert_eq!(spec.processor, "x86");
        assert_eq!(spec.address_size, 64);
        assert!(!spec.big_endian);
        assert_eq!(spec.variant, "LE:64:default");
        assert_eq!(spec.compiler_spec, "gcc");
        assert_eq!(spec.language_id(), "LE:64:LE:64:default");
    }

    #[test]
    fn load_spec_analyzed() {
        let spec = LoadSpec::new("COFF", "ARM", 32, false).as_analyzed();
        assert!(spec.analyzed);
        assert_eq!(spec.tier, LoaderTier::AnalysisDerived);
    }

    #[test]
    fn loader_tier_ordering() {
        assert!(LoaderTier::Native < LoaderTier::AnalysisDerived);
        assert!(LoaderTier::AnalysisDerived < LoaderTier::Heuristic);
        assert!(LoaderTier::Heuristic < LoaderTier::Unknown);
    }

    #[test]
    fn test_loader_finds_elf() {
        let loader = TestLoader {
            name: "ELF".into(),
        };
        let elf_data = vec![0x7F, b'E', b'L', b'F', 2, 1, 1, 0];
        let specs = loader.find_load_specs(&elf_data, &[]);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].processor, "x86");
    }

    #[test]
    fn test_loader_rejects_non_elf() {
        let loader = TestLoader {
            name: "ELF".into(),
        };
        let data = vec![0x4D, 0x5A]; // MZ
        let specs = loader.find_load_specs(&data, &[]);
        assert!(specs.is_empty());
    }

    #[test]
    fn test_loader_default_options() {
        let loader = TestLoader {
            name: "ELF".into(),
        };
        let spec = LoadSpec::new("ELF", "x86", 64, false);
        let opts = loader.default_options(&spec);
        assert_eq!(opts.len(), 1);
        assert_eq!(opts[0].name, "Apply Signature");
    }

    #[test]
    fn test_loader_load() {
        let loader = TestLoader {
            name: "ELF".into(),
        };
        let spec = LoadSpec::new("ELF", "x86", 64, false);
        let log = MessageLog::new();
        let result = loader.load(&[0x7F, b'E', b'L', b'F'], &spec, &[], &log).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result.primary().unwrap().name, "test");
        assert_eq!(result.primary().unwrap().base_address, 0x400000);
    }

    #[test]
    fn load_results_basic() {
        let results = LoadResults::new();
        assert!(results.is_empty());
        assert_eq!(results.len(), 0);
        assert!(results.primary().is_none());

        let mut results = LoadResults::new();
        let spec = LoadSpec::new("ELF", "x86", 64, false);
        results.push(Loaded::new("prog", spec, 0x400000));
        assert_eq!(results.len(), 1);
        assert!(results.primary().is_some());
    }

    #[test]
    fn load_results_has_errors() {
        let mut results = LoadResults::new();
        let spec = LoadSpec::new("ELF", "x86", 64, false);
        let mut loaded = Loaded::new("prog", spec, 0x400000);
        loaded.messages.error("something went wrong");
        results.push(loaded);
        assert!(results.has_errors());
    }

    #[test]
    fn find_first_compatible_loader_test() {
        let loaders: Vec<Box<dyn Loader>> = vec![
            Box::new(TestLoader {
                name: "ELF".into(),
            }),
        ];
        let elf_data = vec![0x7F, b'E', b'L', b'F'];
        let loader = find_first_compatible_loader(&loaders, &elf_data);
        assert!(loader.is_some());
        assert_eq!(loader.unwrap().name(), "ELF");

        let mz_data = vec![0x4D, 0x5A];
        let loader = find_first_compatible_loader(&loaders, &mz_data);
        assert!(loader.is_none());
    }

    #[test]
    fn find_all_load_specs_test() {
        let loaders: Vec<Box<dyn Loader>> = vec![
            Box::new(TestLoader {
                name: "ELF".into(),
            }),
        ];
        let elf_data = vec![0x7F, b'E', b'L', b'F'];
        let all = find_all_load_specs(&loaders, &elf_data);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].1.loader_name, "ELF");
    }
}
