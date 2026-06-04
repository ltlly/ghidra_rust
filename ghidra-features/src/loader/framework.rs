//! Core loader framework types ported from Ghidra's `ghidra.app.util.opinion` package.
//!
//! Provides the foundational types that all loaders use:
//! - [`LoaderTier`] - priority classification for loaders
//! - [`LoadSpec`] - a possible way for a loader to load a file
//! - [`LanguageId`] / [`CompilerSpecId`] - language/compiler identifiers
//! - [`LoadOption`] - typed load option with name/value pairs
//! - [`LoadResults`] / [`Loaded`] - results of a load operation
//! - [`LoadError`] - error type for load failures
//! - [`MessageLog`] - log messages during load
//! - [`ImporterSettings`] - configuration for a load operation
//! - [`QueryResult`] / [`QueryOpinionService`] - opinion-based language detection

use std::fmt;

// ---------------------------------------------------------------------------
// LoaderTier
// ---------------------------------------------------------------------------

/// Priority tier for loader ordering.
///
/// Lower tiers are preferred. A loader's tier determines how specific its
/// format detection is. For example, ELF/PE loaders are `GENERIC_TARGET_LOADER`,
/// while the raw binary loader is `UNTARGETED_LOADER`.
///
/// Ported from `ghidra.app.util.opinion.LoaderTier`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoaderTier {
    /// Very specific loaders (e.g., GZF, XML, DyldCache).
    SpecializedTargetLoader,
    /// Well-known formats (ELF, PE, Mach-O, COFF).
    GenericTargetLoader,
    /// Formats that could be multiple things.
    AmbiguousTargetLoader,
    /// Catch-all loaders (Raw Binary, Intel Hex, Motorola Hex).
    UntargetedLoader,
}

impl LoaderTier {
    /// Return numeric ordering value (lower is higher priority).
    pub fn priority(&self) -> u32 {
        match self {
            LoaderTier::SpecializedTargetLoader => 0,
            LoaderTier::GenericTargetLoader => 1,
            LoaderTier::AmbiguousTargetLoader => 2,
            LoaderTier::UntargetedLoader => 3,
        }
    }
}

impl fmt::Display for LoaderTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoaderTier::SpecializedTargetLoader => write!(f, "Specialized Target Loader"),
            LoaderTier::GenericTargetLoader => write!(f, "Generic Target Loader"),
            LoaderTier::AmbiguousTargetLoader => write!(f, "Ambiguous Target Loader"),
            LoaderTier::UntargetedLoader => write!(f, "Untargeted Loader"),
        }
    }
}

// ---------------------------------------------------------------------------
// Language / Compiler identifiers
// ---------------------------------------------------------------------------

/// A language identifier (e.g., `"x86:LE:64:default"`).
///
/// Corresponds to Ghidra's `LanguageID`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LanguageId(pub String);

impl LanguageId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LanguageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for LanguageId {
    fn from(s: &str) -> Self {
        LanguageId(s.to_string())
    }
}

impl From<String> for LanguageId {
    fn from(s: String) -> Self {
        LanguageId(s)
    }
}

/// A compiler specification identifier (e.g., `"default"`, `"windows"`, `"golang"`).
///
/// Corresponds to Ghidra's `CompilerSpecID`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CompilerSpecId(pub String);

impl CompilerSpecId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CompilerSpecId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for CompilerSpecId {
    fn from(s: &str) -> Self {
        CompilerSpecId(s.to_string())
    }
}

/// A (language, compiler spec) pair.
///
/// Corresponds to Ghidra's `LanguageCompilerSpecPair`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LanguageCompilerSpecPair {
    pub language_id: LanguageId,
    pub compiler_spec_id: CompilerSpecId,
}

impl LanguageCompilerSpecPair {
    pub fn new(language_id: impl Into<LanguageId>, compiler_spec_id: impl Into<CompilerSpecId>) -> Self {
        Self {
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
        }
    }
}

impl fmt::Display for LanguageCompilerSpecPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} / {}", self.language_id, self.compiler_spec_id)
    }
}

// ---------------------------------------------------------------------------
// LoadSpec
// ---------------------------------------------------------------------------

/// Represents a possible way for a loader to load a file.
///
/// Each load spec carries the desired image base, an optional language/compiler
/// pair, and whether this is the preferred spec for the given file.
///
/// Ported from `ghidra.app.util.opinion.LoadSpec`.
#[derive(Debug, Clone)]
pub struct LoadSpec {
    /// Loader name that produced this spec.
    pub loader_name: String,
    /// Desired image base address.
    pub image_base: u64,
    /// Optional language/compiler pair. `None` means unknown/any.
    pub language_compiler_spec: Option<LanguageCompilerSpecPair>,
    /// Whether this is the preferred way to load.
    pub is_preferred: bool,
    /// Whether a language/compiler pair is required.
    pub requires_language_compiler_spec: bool,
}

impl LoadSpec {
    /// Create a fully-specified load spec.
    pub fn new(
        loader_name: impl Into<String>,
        image_base: u64,
        lcs: LanguageCompilerSpecPair,
        is_preferred: bool,
    ) -> Self {
        Self {
            loader_name: loader_name.into(),
            image_base,
            language_compiler_spec: Some(lcs),
            is_preferred,
            requires_language_compiler_spec: true,
        }
    }

    /// Create a load spec from a `QueryResult`.
    pub fn from_query_result(
        loader_name: impl Into<String>,
        image_base: u64,
        result: &QueryResult,
    ) -> Self {
        Self {
            loader_name: loader_name.into(),
            image_base,
            language_compiler_spec: Some(result.pair.clone()),
            is_preferred: result.preferred,
            requires_language_compiler_spec: true,
        }
    }

    /// Create a load spec with unknown language/compiler.
    ///
    /// Some loaders (e.g., raw binary) don't require a specific language.
    pub fn with_unknown_language(
        loader_name: impl Into<String>,
        image_base: u64,
        requires_lcs: bool,
    ) -> Self {
        Self {
            loader_name: loader_name.into(),
            image_base,
            language_compiler_spec: None,
            is_preferred: !requires_lcs,
            requires_language_compiler_spec: requires_lcs,
        }
    }

    /// Returns true if this spec is complete (has a language/compiler if one is required).
    pub fn is_complete(&self) -> bool {
        !self.requires_language_compiler_spec || self.language_compiler_spec.is_some()
    }
}

// ---------------------------------------------------------------------------
// LoadOption
// ---------------------------------------------------------------------------

/// A typed loader option.
///
/// Corresponds to Ghidra's `ghidra.app.util.Option`.
#[derive(Debug, Clone)]
pub enum LoadOptionValue {
    Boolean(bool),
    String(String),
    Integer(i64),
    HexInteger(u64),
    Address(u64),
}

impl LoadOptionValue {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            LoadOptionValue::Boolean(v) => Some(*v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            LoadOptionValue::String(v) => Some(v.as_str()),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            LoadOptionValue::HexInteger(v) => Some(*v),
            LoadOptionValue::Integer(v) => Some(*v as u64),
            LoadOptionValue::Address(v) => Some(*v),
            _ => None,
        }
    }
}

impl fmt::Display for LoadOptionValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadOptionValue::Boolean(v) => write!(f, "{}", v),
            LoadOptionValue::String(v) => write!(f, "{}", v),
            LoadOptionValue::Integer(v) => write!(f, "{}", v),
            LoadOptionValue::HexInteger(v) => write!(f, "0x{:x}", v),
            LoadOptionValue::Address(v) => write!(f, "0x{:x}", v),
        }
    }
}

/// A named load option with a value.
#[derive(Debug, Clone)]
pub struct LoadOption {
    pub name: String,
    pub value: LoadOptionValue,
}

impl LoadOption {
    pub fn new_bool(name: impl Into<String>, value: bool) -> Self {
        Self {
            name: name.into(),
            value: LoadOptionValue::Boolean(value),
        }
    }

    pub fn new_string(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: LoadOptionValue::String(value.into()),
        }
    }

    pub fn new_address(name: impl Into<String>, value: u64) -> Self {
        Self {
            name: name.into(),
            value: LoadOptionValue::Address(value),
        }
    }

    pub fn new_hex(name: impl Into<String>, value: u64) -> Self {
        Self {
            name: name.into(),
            value: LoadOptionValue::HexInteger(value),
        }
    }
}

/// Find a boolean option by name, returning the default if not found.
pub fn get_option_bool(options: &[LoadOption], name: &str, default: bool) -> bool {
    options
        .iter()
        .find(|o| o.name == name)
        .and_then(|o| o.value.as_bool())
        .unwrap_or(default)
}

/// Find a string option by name, returning the default if not found.
pub fn get_option_str<'a>(options: &'a [LoadOption], name: &str, default: &'a str) -> &'a str {
    options
        .iter()
        .find(|o| o.name == name)
        .and_then(|o| o.value.as_str())
        .unwrap_or(default)
}

/// Find a u64 option by name, returning the default if not found.
pub fn get_option_u64(options: &[LoadOption], name: &str, default: u64) -> u64 {
    options
        .iter()
        .find(|o| o.name == name)
        .and_then(|o| o.value.as_u64())
        .unwrap_or(default)
}

// ---------------------------------------------------------------------------
// QueryResult / QueryOpinionService
// ---------------------------------------------------------------------------

/// The result of a language/compiler query.
///
/// Ported from `ghidra.app.util.opinion.QueryResult`.
#[derive(Debug, Clone)]
pub struct QueryResult {
    pub pair: LanguageCompilerSpecPair,
    pub preferred: bool,
}

impl QueryResult {
    pub fn new(pair: LanguageCompilerSpecPair, preferred: bool) -> Self {
        Self { pair, preferred }
    }

    pub fn preferred(pair: LanguageCompilerSpecPair) -> Self {
        Self { pair, preferred: true }
    }

    pub fn non_preferred(pair: LanguageCompilerSpecPair) -> Self {
        Self { pair, preferred: false }
    }
}

/// Simplified opinion service for mapping machine types to language/compiler pairs.
///
/// Ported from `ghidra.app.util.opinion.QueryOpinionService`.
///
/// This is a simplified version that provides built-in mappings for common
/// architectures. The full Ghidra implementation uses XML opinion files.
pub struct QueryOpinionService;

impl QueryOpinionService {
    /// Query for language/compiler pairs matching the given loader, machine, and secondary key.
    pub fn query(loader_name: &str, machine: &str, secondary: Option<&str>) -> Vec<QueryResult> {
        let machine_lower = machine.to_lowercase();
        let sec = secondary.unwrap_or("default");

        match loader_name {
            "Executable and Linking Format (ELF)" => Self::query_elf(&machine_lower, sec),
            "Portable Executable (PE)" => Self::query_pe(&machine_lower, sec),
            "Mac OS X Mach-O" => Self::query_macho(&machine_lower, sec),
            "Common Object File Format (COFF)" | "Microsoft COFF" => {
                Self::query_coff(&machine_lower, sec)
            }
            "Old-style DOS Executable (MZ)" => Self::query_mz(),
            "Relocatable Object Module Format (OMF)" => Self::query_omf(&machine_lower, sec),
            "UNIX A.out" => Self::query_aout(&machine_lower, sec),
            "System Object Model (SOM)" => Self::query_som(),
            "Preferred Executable Format (PEF)" => Self::query_pef(&machine_lower),
            _ => vec![],
        }
    }

    fn query_elf(machine: &str, secondary: &str) -> Vec<QueryResult> {
        let lcs = match machine {
            m if m.contains("x86") && m.contains("64") => {
                LanguageCompilerSpecPair::new("x86:LE:64:default", secondary)
            }
            m if m.contains("x86") || m.contains("i386") || m.contains("i686") => {
                LanguageCompilerSpecPair::new("x86:LE:32:default", secondary)
            }
            m if m.contains("aarch64") || m.contains("arm64") => {
                LanguageCompilerSpecPair::new("AARCH64:LE:64:v8A", secondary)
            }
            m if m.contains("arm") && m.contains("eb") => {
                LanguageCompilerSpecPair::new("ARM:BE:32:v8", secondary)
            }
            m if m.contains("arm") => {
                LanguageCompilerSpecPair::new("ARM:LE:32:v8", secondary)
            }
            m if m.contains("mips") && m.contains("64") && m.contains("el") => {
                LanguageCompilerSpecPair::new("MIPS:LE:64:default", secondary)
            }
            m if m.contains("mips") && m.contains("64") => {
                LanguageCompilerSpecPair::new("MIPS:BE:64:default", secondary)
            }
            m if m.contains("mips") && m.contains("el") => {
                LanguageCompilerSpecPair::new("MIPS:LE:32:default", secondary)
            }
            m if m.contains("mips") => {
                LanguageCompilerSpecPair::new("MIPS:BE:32:default", secondary)
            }
            m if m.contains("powerpc") && m.contains("64") && m.contains("le") => {
                LanguageCompilerSpecPair::new("PowerPC:BE:64:default", secondary)
            }
            m if m.contains("powerpc") && m.contains("64") => {
                LanguageCompilerSpecPair::new("PowerPC:BE:64:64-LE", secondary)
            }
            m if m.contains("powerpc") => {
                LanguageCompilerSpecPair::new("PowerPC:BE:32:default", secondary)
            }
            m if m.contains("riscv") && m.contains("64") => {
                LanguageCompilerSpecPair::new("RISCV:LE:64:default", secondary)
            }
            m if m.contains("riscv") && m.contains("32") => {
                LanguageCompilerSpecPair::new("RISCV:LE:32:default", secondary)
            }
            m if m.contains("sparc") && m.contains("64") => {
                LanguageCompilerSpecPair::new("SPARC:BE:64:default", secondary)
            }
            m if m.contains("sparc") => {
                LanguageCompilerSpecPair::new("SPARC:BE:32:default", secondary)
            }
            _ => return vec![],
        };
        vec![QueryResult::preferred(lcs)]
    }

    fn query_pe(machine: &str, secondary: &str) -> Vec<QueryResult> {
        let lcs = match machine {
            m if m.contains("amd64") || m.contains("x86_64") || m.contains("x64") => {
                LanguageCompilerSpecPair::new("x86:LE:64:default", secondary)
            }
            m if m.contains("i386") || m.contains("x86") => {
                LanguageCompilerSpecPair::new("x86:LE:32:default", secondary)
            }
            m if m.contains("arm64") || m.contains("aarch64") => {
                LanguageCompilerSpecPair::new("AARCH64:LE:64:v8A", secondary)
            }
            m if m.contains("arm") => {
                LanguageCompilerSpecPair::new("ARM:LE:32:v8", secondary)
            }
            _ => return vec![],
        };
        vec![QueryResult::preferred(lcs)]
    }

    fn query_macho(machine: &str, secondary: &str) -> Vec<QueryResult> {
        let lcs = match machine {
            m if m.contains("x86_64") => {
                LanguageCompilerSpecPair::new("x86:LE:64:default", secondary)
            }
            m if m.contains("i386") || m.contains("x86") => {
                LanguageCompilerSpecPair::new("x86:LE:32:default", secondary)
            }
            m if m.contains("arm64") || m.contains("aarch64") => {
                LanguageCompilerSpecPair::new("AARCH64:LE:64:v8A", secondary)
            }
            m if m.contains("arm") => {
                LanguageCompilerSpecPair::new("ARM:LE:32:v8", secondary)
            }
            m if m.contains("ppc64") => {
                LanguageCompilerSpecPair::new("PowerPC:BE:64:default", secondary)
            }
            m if m.contains("ppc") || m.contains("powerpc") => {
                LanguageCompilerSpecPair::new("PowerPC:BE:32:default", secondary)
            }
            _ => return vec![],
        };
        vec![QueryResult::preferred(lcs)]
    }

    fn query_coff(machine: &str, secondary: &str) -> Vec<QueryResult> {
        let lcs = match machine {
            m if m.contains("amd64") || m.contains("x86_64") => {
                LanguageCompilerSpecPair::new("x86:LE:64:default", secondary)
            }
            m if m.contains("i386") || m.contains("x86") => {
                LanguageCompilerSpecPair::new("x86:LE:32:default", secondary)
            }
            m if m.contains("arm64") || m.contains("aarch64") => {
                LanguageCompilerSpecPair::new("AARCH64:LE:64:v8A", secondary)
            }
            m if m.contains("arm") => {
                LanguageCompilerSpecPair::new("ARM:LE:32:v8", secondary)
            }
            _ => return vec![],
        };
        vec![QueryResult::preferred(lcs)]
    }

    fn query_mz() -> Vec<QueryResult> {
        vec![QueryResult::preferred(LanguageCompilerSpecPair::new(
            "x86:LE:16:Real Mode",
            "default",
        ))]
    }

    fn query_omf(machine: &str, secondary: &str) -> Vec<QueryResult> {
        let lcs = match machine {
            m if m.contains("i386") || m.contains("x86") => {
                LanguageCompilerSpecPair::new("x86:LE:32:default", secondary)
            }
            m if m.contains("arm") => {
                LanguageCompilerSpecPair::new("ARM:LE:32:v8", secondary)
            }
            _ => return vec![],
        };
        vec![QueryResult::preferred(lcs)]
    }

    fn query_aout(machine: &str, secondary: &str) -> Vec<QueryResult> {
        let lcs = match machine {
            m if m.contains("m68k") || m.contains("68000") => {
                LanguageCompilerSpecPair::new("68000:BE:32:default", secondary)
            }
            m if m.contains("sparc") => {
                LanguageCompilerSpecPair::new("SPARC:BE:32:default", secondary)
            }
            m if m.contains("i386") || m.contains("x86") => {
                LanguageCompilerSpecPair::new("x86:LE:32:default", secondary)
            }
            m if m.contains("mips") => {
                LanguageCompilerSpecPair::new("MIPS:BE:32:default", secondary)
            }
            _ => return vec![],
        };
        vec![QueryResult::preferred(lcs)]
    }

    fn query_som() -> Vec<QueryResult> {
        vec![QueryResult::preferred(LanguageCompilerSpecPair::new(
            "PA-RISC:BE:32:default",
            "default",
        ))]
    }

    fn query_pef(machine: &str) -> Vec<QueryResult> {
        let lcs = match machine {
            m if m.contains("pwpc") || m.contains("powerpc") => {
                LanguageCompilerSpecPair::new("PowerPC:BE:32:default", "default")
            }
            m if m.contains("m68k") || m.contains("68000") => {
                LanguageCompilerSpecPair::new("68000:BE:32:default", "default")
            }
            _ => return vec![],
        };
        vec![QueryResult::preferred(lcs)]
    }
}

// ---------------------------------------------------------------------------
// LoadError
// ---------------------------------------------------------------------------

/// Error type for load operations.
///
/// Ported from `ghidra.app.util.opinion.LoadException`.
#[derive(Debug)]
pub enum LoadError {
    /// The file format was not recognized.
    UnsupportedFormat(String),
    /// The file is malformed.
    MalformedInput(String),
    /// A required option is missing or invalid.
    InvalidOption(String),
    /// I/O error during load.
    Io(std::io::Error),
    /// The load was cancelled by the user.
    Cancelled,
    /// Address overflow during memory layout.
    AddressOverflow(String),
    /// Duplicate name in symbol table or memory block.
    DuplicateName(String),
    /// Generic load failure.
    Other(String),
}

impl fmt::Display for LoadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LoadError::UnsupportedFormat(msg) => write!(f, "Unsupported format: {}", msg),
            LoadError::MalformedInput(msg) => write!(f, "Malformed input: {}", msg),
            LoadError::InvalidOption(msg) => write!(f, "Invalid option: {}", msg),
            LoadError::Io(e) => write!(f, "I/O error: {}", e),
            LoadError::Cancelled => write!(f, "Load cancelled"),
            LoadError::AddressOverflow(msg) => write!(f, "Address overflow: {}", msg),
            LoadError::DuplicateName(msg) => write!(f, "Duplicate name: {}", msg),
            LoadError::Other(msg) => write!(f, "Load error: {}", msg),
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LoadError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for LoadError {
    fn from(e: std::io::Error) -> Self {
        LoadError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// MessageLog
// ---------------------------------------------------------------------------

/// Accumulates messages during a load operation.
///
/// Ported from `ghidra.app.util.importer.MessageLog`.
#[derive(Debug, Clone, Default)]
pub struct MessageLog {
    messages: Vec<(MessageLevel, String)>,
}

/// Severity of a log message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageLevel {
    Info,
    Warning,
    Error,
}

impl MessageLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn info(&mut self, msg: impl Into<String>) {
        self.messages.push((MessageLevel::Info, msg.into()));
    }

    pub fn warning(&mut self, msg: impl Into<String>) {
        self.messages.push((MessageLevel::Warning, msg.into()));
    }

    pub fn error(&mut self, msg: impl Into<String>) {
        self.messages.push((MessageLevel::Error, msg.into()));
    }

    /// Append a message (defaults to Info level).
    pub fn append_msg(&mut self, msg: impl Into<String>) {
        self.info(msg);
    }

    /// Append an error message.
    pub fn append_error(&mut self, msg: impl Into<String>) {
        self.error(msg);
    }

    pub fn messages(&self) -> &[(MessageLevel, String)] {
        &self.messages
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn has_errors(&self) -> bool {
        self.messages
            .iter()
            .any(|(level, _)| *level == MessageLevel::Error)
    }

    pub fn clear(&mut self) {
        self.messages.clear();
    }
}

impl fmt::Display for MessageLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (level, msg) in &self.messages {
            writeln!(f, "[{}] {}", level, msg)?;
        }
        Ok(())
    }
}

impl fmt::Display for MessageLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MessageLevel::Info => write!(f, "INFO"),
            MessageLevel::Warning => write!(f, "WARN"),
            MessageLevel::Error => write!(f, "ERROR"),
        }
    }
}

// ---------------------------------------------------------------------------
// ImporterSettings
// ---------------------------------------------------------------------------

/// Configuration for a load operation.
///
/// Ported from `ghidra.app.util.opinion.Loader.ImporterSettings`.
#[derive(Debug, Clone)]
pub struct ImporterSettings {
    /// The name for the primary loaded object.
    pub import_name: String,
    /// The load spec to use.
    pub load_spec: Option<LoadSpec>,
    /// Load options.
    pub options: Vec<LoadOption>,
    /// Whether to mirror filesystem layout.
    pub mirror_fs_layout: bool,
}

impl ImporterSettings {
    pub fn new(import_name: impl Into<String>) -> Self {
        Self {
            import_name: import_name.into(),
            load_spec: None,
            options: Vec::new(),
            mirror_fs_layout: false,
        }
    }

    /// Get just the filename portion of the import name.
    pub fn import_name_only(&self) -> &str {
        self.import_name
            .rsplit_once(&['/', '\\'][..])
            .map(|(_, name)| name)
            .unwrap_or(&self.import_name)
    }

    /// Get just the path portion of the import name.
    pub fn import_path_only(&self) -> &str {
        self.import_name
            .rsplit_once(&['/', '\\'][..])
            .map(|(path, _)| path)
            .unwrap_or("")
    }
}

// ---------------------------------------------------------------------------
// Loaded / LoadResults
// ---------------------------------------------------------------------------

/// Represents a single loaded program.
///
/// Ported from `ghidra.app.util.opinion.Loaded`.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// Name of the loaded object.
    pub name: String,
    /// The load spec used.
    pub load_spec: Option<LoadSpec>,
    /// Program data loaded from the file.
    pub program: crate::base::analyzer::Program,
}

impl Loaded {
    pub fn new(
        name: impl Into<String>,
        program: crate::base::analyzer::Program,
        load_spec: Option<LoadSpec>,
    ) -> Self {
        Self {
            name: name.into(),
            program,
            load_spec,
        }
    }
}

/// Results of a load operation containing one or more loaded objects.
///
/// Ported from `ghidra.app.util.opinion.LoadResults`.
#[derive(Debug)]
pub struct LoadResults {
    pub loaded: Vec<Loaded>,
    pub log: MessageLog,
}

impl LoadResults {
    pub fn new(loaded: Vec<Loaded>, log: MessageLog) -> Self {
        Self { loaded, log }
    }

    pub fn single(loaded: Loaded, log: MessageLog) -> Self {
        Self {
            loaded: vec![loaded],
            log,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.loaded.is_empty()
    }

    pub fn len(&self) -> usize {
        self.loaded.len()
    }

    /// Get the first loaded program.
    pub fn first(&self) -> Option<&Loaded> {
        self.loaded.first()
    }

    /// Iterate over loaded programs.
    pub fn iter(&self) -> impl Iterator<Item = &Loaded> {
        self.loaded.iter()
    }

    /// Return true if there were errors during loading.
    pub fn has_errors(&self) -> bool {
        self.log.has_errors()
    }
}

// ---------------------------------------------------------------------------
// Loader registry
// ---------------------------------------------------------------------------

/// Registry of all available loaders.
///
/// Manages loader discovery, ordering, and selection. Loaders are
/// registered with a tier and priority, and the registry finds the
/// appropriate loader for a given file.
pub struct LoaderRegistry {
    loaders: Vec<RegisteredLoader>,
}

struct RegisteredLoader {
    name: String,
    tier: LoaderTier,
    tier_priority: i32,
}

impl LoaderRegistry {
    pub fn new() -> Self {
        Self {
            loaders: Vec::new(),
        }
    }

    /// Register a loader with the given tier and priority.
    pub fn register(&mut self, name: impl Into<String>, tier: LoaderTier, tier_priority: i32) {
        let name = name.into();
        if self.loaders.iter().any(|l| l.name == name) {
            return; // already registered
        }
        self.loaders.push(RegisteredLoader {
            name,
            tier,
            tier_priority,
        });
        // Keep sorted by (tier, priority)
        self.loaders
            .sort_by_key(|l| (l.tier.priority() as i32, l.tier_priority));
    }

    /// Get the names of all registered loaders in priority order.
    pub fn loader_names(&self) -> Vec<&str> {
        self.loaders.iter().map(|l| l.name.as_str()).collect()
    }

    /// Get the count of registered loaders.
    pub fn len(&self) -> usize {
        self.loaders.len()
    }

    pub fn is_empty(&self) -> bool {
        self.loaders.is_empty()
    }

    /// Find a loader by name.
    pub fn find_by_name(&self, name: &str) -> Option<(&str, LoaderTier, i32)> {
        self.loaders
            .iter()
            .find(|l| l.name == name)
            .map(|l| (l.name.as_str(), l.tier, l.tier_priority))
    }
}

impl Default for LoaderRegistry {
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
    fn test_loader_tier_ordering() {
        assert!(LoaderTier::SpecializedTargetLoader < LoaderTier::GenericTargetLoader);
        assert!(LoaderTier::GenericTargetLoader < LoaderTier::AmbiguousTargetLoader);
        assert!(LoaderTier::AmbiguousTargetLoader < LoaderTier::UntargetedLoader);
    }

    #[test]
    fn test_loader_tier_display() {
        assert_eq!(
            LoaderTier::GenericTargetLoader.to_string(),
            "Generic Target Loader"
        );
    }

    #[test]
    fn test_loader_tier_priority() {
        assert!(LoaderTier::SpecializedTargetLoader.priority() < LoaderTier::UntargetedLoader.priority());
    }

    #[test]
    fn test_load_spec_creation() {
        let lcs = LanguageCompilerSpecPair::new("x86:LE:64:default", "default");
        let spec = LoadSpec::new("ELF", 0x400000, lcs, true);
        assert_eq!(spec.loader_name, "ELF");
        assert_eq!(spec.image_base, 0x400000);
        assert!(spec.is_preferred);
        assert!(spec.is_complete());
    }

    #[test]
    fn test_load_spec_unknown_language() {
        let spec = LoadSpec::with_unknown_language("Raw Binary", 0, true);
        assert!(spec.language_compiler_spec.is_none());
        assert!(!spec.is_complete());
    }

    #[test]
    fn test_load_spec_complete_with_lcs() {
        let lcs = LanguageCompilerSpecPair::new("x86:LE:64:default", "default");
        let spec = LoadSpec::new("ELF", 0, lcs, true);
        assert!(spec.is_complete());
    }

    #[test]
    fn test_query_result() {
        let lcs = LanguageCompilerSpecPair::new("x86:LE:64:default", "windows");
        let qr = QueryResult::preferred(lcs.clone());
        assert!(qr.preferred);
        assert_eq!(qr.pair.language_id.as_str(), "x86:LE:64:default");

        let qr2 = QueryResult::non_preferred(lcs);
        assert!(!qr2.preferred);
    }

    #[test]
    fn test_query_opinion_elf_x86_64() {
        let results =
            QueryOpinionService::query("Executable and Linking Format (ELF)", "x86-64", None);
        assert!(!results.is_empty());
        assert_eq!(
            results[0].pair.language_id.as_str(),
            "x86:LE:64:default"
        );
    }

    #[test]
    fn test_query_opinion_elf_arm() {
        let results = QueryOpinionService::query(
            "Executable and Linking Format (ELF)",
            "ARM",
            Some("default"),
        );
        assert!(!results.is_empty());
        assert_eq!(results[0].pair.language_id.as_str(), "ARM:LE:32:v8");
    }

    #[test]
    fn test_query_opinion_pe_x86() {
        let results =
            QueryOpinionService::query("Portable Executable (PE)", "i386", Some("windows"));
        assert!(!results.is_empty());
        assert_eq!(results[0].pair.language_id.as_str(), "x86:LE:32:default");
    }

    #[test]
    fn test_query_opinion_pe_amd64() {
        let results = QueryOpinionService::query("Portable Executable (PE)", "amd64", None);
        assert!(!results.is_empty());
        assert_eq!(
            results[0].pair.language_id.as_str(),
            "x86:LE:64:default"
        );
    }

    #[test]
    fn test_query_opinion_macho() {
        let results = QueryOpinionService::query("Mac OS X Mach-O", "x86_64", None);
        assert!(!results.is_empty());
    }

    #[test]
    fn test_query_opinion_mz() {
        let results = QueryOpinionService::query("Old-style DOS Executable (MZ)", "0", None);
        assert!(!results.is_empty());
        assert_eq!(
            results[0].pair.language_id.as_str(),
            "x86:LE:16:Real Mode"
        );
    }

    #[test]
    fn test_query_opinion_unknown_loader() {
        let results = QueryOpinionService::query("Unknown Loader", "x86", None);
        assert!(results.is_empty());
    }

    #[test]
    fn test_load_option_values() {
        let opt = LoadOption::new_bool("Test", true);
        assert_eq!(opt.value.as_bool(), Some(true));
        assert!(opt.value.as_str().is_none());

        let opt2 = LoadOption::new_string("Name", "value");
        assert_eq!(opt2.value.as_str(), Some("value"));

        let opt3 = LoadOption::new_hex("Offset", 0x1000);
        assert_eq!(opt3.value.as_u64(), Some(0x1000));
    }

    #[test]
    fn test_get_option_helpers() {
        let opts = vec![
            LoadOption::new_bool("Overlay", true),
            LoadOption::new_string("Block Name", ".text"),
            LoadOption::new_hex("Base Address", 0x400000),
        ];
        assert!(get_option_bool(&opts, "Overlay", false));
        assert!(!get_option_bool(&opts, "Missing", false));
        assert_eq!(get_option_str(&opts, "Block Name", ""), ".text");
        assert_eq!(get_option_str(&opts, "Missing", "default"), "default");
        assert_eq!(get_option_u64(&opts, "Base Address", 0), 0x400000);
    }

    #[test]
    fn test_message_log() {
        let mut log = MessageLog::new();
        assert!(log.is_empty());

        log.info("Loading...");
        log.warning("Section empty");
        log.error("Failed to parse");
        assert_eq!(log.len(), 3);
        assert!(log.has_errors());
        assert_eq!(log.messages()[0].0, MessageLevel::Info);

        log.clear();
        assert!(log.is_empty());
    }

    #[test]
    fn test_message_log_display() {
        let mut log = MessageLog::new();
        log.info("test");
        let display = format!("{}", log);
        assert!(display.contains("INFO"));
        assert!(display.contains("test"));
    }

    #[test]
    fn test_importer_settings() {
        let settings = ImporterSettings::new("/path/to/file.exe");
        assert_eq!(settings.import_name, "/path/to/file.exe");
        assert_eq!(settings.import_name_only(), "file.exe");
        assert_eq!(settings.import_path_only(), "/path/to");
    }

    #[test]
    fn test_importer_settings_no_path() {
        let settings = ImporterSettings::new("file.exe");
        assert_eq!(settings.import_name_only(), "file.exe");
        assert_eq!(settings.import_path_only(), "");
    }

    #[test]
    fn test_loaded_and_results() {
        let lang = crate::base::analyzer::Language {
            processor: "x86".into(),
            variant: "LE".into(),
            size: 64,
        };
        let prog = crate::base::analyzer::Program::new("test", lang);
        let loaded = Loaded::new("test.exe", prog, None);
        let results = LoadResults::single(loaded, MessageLog::new());

        assert_eq!(results.len(), 1);
        assert!(!results.has_errors());
        assert!(results.first().is_some());
    }

    #[test]
    fn test_loader_registry() {
        let mut reg = LoaderRegistry::new();
        assert!(reg.is_empty());

        reg.register("Raw Binary", LoaderTier::UntargetedLoader, 100);
        reg.register("ELF", LoaderTier::GenericTargetLoader, 0);
        reg.register("PE", LoaderTier::GenericTargetLoader, 1);

        assert_eq!(reg.len(), 3);

        let names = reg.loader_names();
        assert_eq!(names[0], "ELF"); // GenericTargetLoader comes first
        assert_eq!(names[1], "PE");
        assert_eq!(names[2], "Raw Binary"); // UntargetedLoader is last

        assert!(reg.find_by_name("ELF").is_some());
        assert!(reg.find_by_name("Missing").is_none());
    }

    #[test]
    fn test_loader_registry_duplicate() {
        let mut reg = LoaderRegistry::new();
        reg.register("ELF", LoaderTier::GenericTargetLoader, 0);
        reg.register("ELF", LoaderTier::GenericTargetLoader, 0);
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn test_language_compiler_spec_pair() {
        let lcs = LanguageCompilerSpecPair::new("x86:LE:64:default", "windows");
        assert_eq!(lcs.language_id.as_str(), "x86:LE:64:default");
        assert_eq!(lcs.compiler_spec_id.as_str(), "windows");
        assert!(format!("{}", lcs).contains("x86"));
    }

    #[test]
    fn test_load_error_display() {
        let err = LoadError::UnsupportedFormat("not ELF".to_string());
        assert!(err.to_string().contains("Unsupported format"));

        let err = LoadError::MalformedInput("bad header".to_string());
        assert!(err.to_string().contains("Malformed input"));

        let err = LoadError::Cancelled;
        assert!(err.to_string().contains("cancelled"));
    }

    #[test]
    fn test_load_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = LoadError::from(io_err);
        assert!(err.to_string().contains("I/O error"));
    }

    #[test]
    fn test_load_spec_from_query_result() {
        let lcs = LanguageCompilerSpecPair::new("x86:LE:64:default", "default");
        let qr = QueryResult::preferred(lcs);
        let spec = LoadSpec::from_query_result("ELF", 0x400000, &qr);
        assert!(spec.is_preferred);
        assert_eq!(spec.image_base, 0x400000);
    }

    #[test]
    fn test_load_option_value_display() {
        assert_eq!(LoadOptionValue::Boolean(true).to_string(), "true");
        assert_eq!(LoadOptionValue::String("test".into()).to_string(), "test");
        assert_eq!(LoadOptionValue::HexInteger(0xFF).to_string(), "0xff");
    }
}
