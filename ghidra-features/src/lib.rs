//! Ghidra Rust - Features crate.
//!
//! This crate provides analysis features including:
//! - `base`: The auto-analysis framework (analyzers, scheduler, manager)
//! - `fileformats`: Binary format parsers (ELF, PE, Mach-O, raw)
//! - `dex`: DEX/Dalvik executable parser for Android
//! - `dwarf`: DWARF debug information parser
//! - `pdb`: Microsoft PDB debug information parser
//! - `swift`: Swift name demangling and type metadata
//! - `byte_patterns`: Byte pattern matching and closed sequence mining
//! - `function_id`: Function identification via hash-based signature matching
//! - `microsoft_code_analyzer`: MSVC RTTI, vtables, and SEH analysis
//! - `system_emulation`: P-code based emulation and syscall handling
//! - `ghidra_server`: Ghidra Server -- repository management, authentication, block-stream I/O
//! - `pyghidra`: PyGhidra -- Python interpreter integration, property bridging
//! - `ghidra_go`: GhidraGo -- send Ghidra URLs to a running instance via IPC
//!
//! # Feature Manager
//!
//! The [`FeatureManager`] is the central registry that holds all available
//! [`Analyzer`] instances for automatic code analysis and [`BinaryLoader`]
//! instances for loading different binary file formats into [`Program`]s.

pub mod base;
pub mod bsim;
pub mod codebrowser;
pub mod external;
pub mod bsim_elastic;
pub mod byte_patterns;
pub mod datamgr;
pub mod byteviewer;
pub mod demangler;
pub mod codecompare;
pub mod debug;
pub mod dex;
pub mod dwarf;
pub mod fileformats;
pub mod function_id;
pub mod functiongraph;
pub mod ghidra_go;
pub mod ghidra_server;
pub mod graphservices;
pub mod lisa;
pub mod loader;
pub mod machine_learning;
pub mod microsoft_code_analyzer;
pub mod objc;
pub mod pdb;
pub mod programdiff;
pub mod programtree;
pub mod progmgr;
pub mod pyghidra;
pub mod sarif;
pub mod recognizers;
pub mod rust;
pub mod swift;
pub mod system_emulation;
pub mod table;
pub mod versiontracking;

pub use base::analyzer::*;
pub use dwarf::*;
pub use fileformats::*;
pub use pdb::*;

// ---------------------------------------------------------------------------
// FeatureManager
// ---------------------------------------------------------------------------

/// Manages registered analyzers and binary loaders.
///
/// The `FeatureManager` is the central registry for all analysis features.
/// It holds a collection of [`Analyzer`] instances for automatic analysis
/// and [`BinaryLoader`] instances for loading binary files into [`Program`]s.
///
/// # Example
///
/// ```ignore
/// use ghidra_features::{FeatureManager, BinaryLoader, LoadOptions};
/// use ghidra_features::base::analyzer::FunctionStartAnalyzer;
///
/// let mut manager = FeatureManager::new();
/// manager.add_analyzer(Box::new(FunctionStartAnalyzer::new()));
///
/// // Find a loader for a given binary blob
/// if let Some(loader) = manager.find_loader(&data) {
///     let program = loader.load(&data, &LoadOptions::default())?;
/// }
/// ```
pub struct FeatureManager {
    /// Registered analysis passes.
    pub analyzers: Vec<Box<dyn Analyzer>>,
    /// Registered binary format loaders.
    pub loaders: Vec<Box<dyn BinaryLoader>>,
}

impl FeatureManager {
    /// Create a new empty feature manager.
    pub fn new() -> Self {
        Self {
            analyzers: Vec::new(),
            loaders: Vec::new(),
        }
    }

    /// Register an analyzer.
    ///
    /// The analyzer will be available for automatic analysis sessions
    /// managed by an [`AutoAnalysisManager`](base::analyzer::AutoAnalysisManager).
    pub fn add_analyzer(&mut self, analyzer: Box<dyn Analyzer>) {
        self.analyzers.push(analyzer);
    }

    /// Register a binary loader.
    ///
    /// Loaders are checked in registration order when
    /// [`find_loader`](FeatureManager::find_loader) is called.
    pub fn add_loader(&mut self, loader: Box<dyn BinaryLoader>) {
        self.loaders.push(loader);
    }

    /// Find the first loader that can handle the given binary data.
    ///
    /// Each registered loader's [`BinaryLoader::can_load`] method is
    /// called in registration order. The first loader to return `true`
    /// is returned.
    pub fn find_loader(&self, data: &[u8]) -> Option<&dyn BinaryLoader> {
        self.loaders
            .iter()
            .find(|l| l.can_load(data))
            .map(|l| l.as_ref())
    }

    /// Load binary data using the first compatible loader.
    ///
    /// This is a convenience method that combines
    /// [`find_loader`](FeatureManager::find_loader) and
    /// [`BinaryLoader::load`].
    ///
    /// # Errors
    ///
    /// Returns an error if no compatible loader is found or if loading fails.
    pub fn load(
        &self,
        data: &[u8],
        options: &LoadOptions,
    ) -> anyhow::Result<Program> {
        match self.find_loader(data) {
            Some(loader) => loader.load(data, options),
            None => Err(anyhow::anyhow!(
                "No binary loader found for the given data"
            )),
        }
    }
}

impl Default for FeatureManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BinaryLoader trait
// ---------------------------------------------------------------------------

/// Trait for loading a binary file format into a [`Program`].
///
/// Each implementor handles a specific file format (ELF, PE, Mach-O,
/// raw binary, etc.) and is responsible for parsing headers, creating
/// memory blocks, populating the symbol table, and setting up the
/// initial listing and address space.
///
/// # Implementing
///
/// ```ignore
/// use ghidra_features::{
///     BinaryLoader, LoadOptions,
///     base::analyzer::{Program, Language},
/// };
///
/// struct ElfLoader;
///
/// impl BinaryLoader for ElfLoader {
///     fn name(&self) -> &str {
///         "ELF"
///     }
///
///     fn can_load(&self, data: &[u8]) -> bool {
///         data.len() >= 4 && &data[0..4] == b"\x7FELF"
///     }
///
///     fn load(&self, data: &[u8], options: &LoadOptions) -> anyhow::Result<Program> {
///         // Parse ELF headers, create memory blocks, populate listing
///         let mut program = Program::new("elf_binary", Language {
///             processor: "x86".into(),
///             variant: "LE".into(),
///             size: 64,
///         });
///         // ... populate program from data
///         Ok(program)
///     }
/// }
/// ```
pub trait BinaryLoader: Send + Sync {
    /// The human-readable name of this loader (e.g., "ELF", "PE", "Mach-O").
    fn name(&self) -> &str;

    /// Check whether this loader can handle the given data.
    ///
    /// This typically inspects magic bytes or other format-specific
    /// signatures near the beginning of the data buffer. Implementations
    /// should be fast and avoid full parsing -- this method is called
    /// for every registered loader until a match is found.
    fn can_load(&self, data: &[u8]) -> bool;

    /// Parse the data and produce a [`Program`] ready for analysis.
    ///
    /// # Parameters
    ///
    /// * `data` - The raw bytes of the binary file.
    /// * `options` - Loading options including base address, architecture
    ///   hint, and whether to run automatic analysis after loading.
    ///
    /// # Errors
    ///
    /// Returns an error if the data is malformed or cannot be fully parsed.
    fn load(&self, data: &[u8], options: &LoadOptions) -> anyhow::Result<Program>;
}

// ---------------------------------------------------------------------------
// LoadOptions
// ---------------------------------------------------------------------------

/// Options that control how a binary file is loaded.
///
/// These correspond to the settings a user would configure in the
/// Ghidra "Import File" dialog.
///
/// # Examples
///
/// ```ignore
/// // Load at the default address with full analysis
/// let opts = LoadOptions::default();
///
/// // Load at a specific base with analysis disabled
/// let opts = LoadOptions {
///     base_address: 0x400000,
///     architecture: Some("x86:LE:64:default".into()),
///     apply_analysis: false,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct LoadOptions {
    /// The preferred base address for the loaded image.
    /// When `0`, the address is taken from the file headers.
    pub base_address: u64,
    /// An optional architecture/language override
    /// (e.g., `"x86:LE:64:default"`, `"ARM:LE:32:v8"`).
    /// When `None`, the architecture is inferred from the binary headers.
    pub architecture: Option<String>,
    /// Whether to run the full auto-analysis pipeline after loading.
    pub apply_analysis: bool,
}

impl Default for LoadOptions {
    fn default() -> Self {
        Self {
            base_address: 0,
            architecture: None,
            apply_analysis: true,
        }
    }
}
