//! Loader opinion and service framework ported from Ghidra's
//! `ghidra.app.util.opinion` package.
//!
//! This module provides:
//! - [`LoaderService`] -- factory for discovering and querying loaders
//! - [`LoaderMap`] -- maps loaders to their supported load specs
//! - [`LoadException`] -- error type for loader failures
//! - [`AddressSetPartitioner`] -- partitions address sets at split points
//! - [`QueryOpinionService`] -- opinion-based language/compiler querying
//! - [`LibraryLookupStrategy`] -- how to resolve library dependencies
//! - [`AnalysisTarget`] -- describes the analysis target for a load
//! - Additional loader implementations: [`BinaryRawLoader`], [`DefLoader`],
//!   [`GdtLoader`], [`GzfLoader`], [`DbgLoader`]
//!
//! # Example
//!
//! ```rust
//! use ghidra_features::app_util_opinion::*;
//! use ghidra_features::loader::framework::*;
//!
//! // Query all loaders for supported load specs
//! let data = vec![0x7f, b'E', b'L', b'F', 2, 1, 1, 0];
//! let loader_map = LoaderService::get_supported_load_specs(&data);
//! for (name, specs) in loader_map.iter() {
//!     println!("{}: {} load specs", name, specs.len());
//! }
//! ```

use std::collections::BTreeMap;
use std::fmt;

use crate::base::analyzer::{Address, AddressRange, AddressSet};
use crate::loader::framework::{
    LanguageCompilerSpecPair, LoadOption, LoadSpec, LoaderTier, QueryOpinionService,
};

// ---------------------------------------------------------------------------
// LoadException
// ---------------------------------------------------------------------------

/// Error type for expected loader failures.
///
/// Ported from `ghidra.app.util.opinion.LoadException`.
#[derive(Debug)]
pub struct LoadException {
    message: String,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl LoadException {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    pub fn with_source(message: impl Into<String>, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for LoadException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LoadException: {}", self.message)
    }
}

impl std::error::Error for LoadException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e.as_ref() as _)
    }
}

// ---------------------------------------------------------------------------
// LoaderOpinionException
// ---------------------------------------------------------------------------

/// Error when loader opinions cannot be resolved.
///
/// Ported from `ghidra.app.util.opinion.LoaderOpinionException`.
#[derive(Debug)]
pub struct LoaderOpinionException {
    message: String,
}

impl LoaderOpinionException {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl fmt::Display for LoaderOpinionException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LoaderOpinionException: {}", self.message)
    }
}

impl std::error::Error for LoaderOpinionException {}

// ---------------------------------------------------------------------------
// LoaderMap
// ---------------------------------------------------------------------------

/// A map from loader name to their supported [`LoadSpec`]s.
///
/// The map is sorted by loader name (via `BTreeMap`), matching Ghidra's
/// `TreeMap<Loader, Collection<LoadSpec>>` behavior.
///
/// Ported from `ghidra.app.util.opinion.LoaderMap`.
#[derive(Debug, Clone, Default)]
pub struct LoaderMap {
    inner: BTreeMap<String, Vec<LoadSpec>>,
}

impl LoaderMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert load specs for a loader.
    pub fn insert(&mut self, loader_name: impl Into<String>, specs: Vec<LoadSpec>) {
        self.inner.insert(loader_name.into(), specs);
    }

    /// Get the load specs for a loader.
    pub fn get(&self, loader_name: &str) -> Option<&Vec<LoadSpec>> {
        self.inner.get(loader_name)
    }

    /// Check if the map contains a loader.
    pub fn contains_loader(&self, loader_name: &str) -> bool {
        self.inner.contains_key(loader_name)
    }

    /// Iterate over (loader_name, specs) pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Vec<LoadSpec>)> {
        self.inner.iter()
    }

    /// Get the number of loaders.
    pub fn loader_count(&self) -> usize {
        self.inner.len()
    }

    /// Get the total number of load specs across all loaders.
    pub fn total_spec_count(&self) -> usize {
        self.inner.values().map(|v| v.len()).sum()
    }

    /// Check if the map is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Get all loader names.
    pub fn loader_names(&self) -> Vec<&String> {
        self.inner.keys().collect()
    }

    /// Get all load specs as a flat list.
    pub fn all_specs(&self) -> Vec<(String, LoadSpec)> {
        self.inner
            .iter()
            .flat_map(|(name, specs)| {
                specs
                    .iter()
                    .map(move |spec| (name.clone(), spec.clone()))
            })
            .collect()
    }
}

impl fmt::Display for LoaderMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (name, specs) in &self.inner {
            writeln!(f, "{} - {} load specs", name, specs.len())?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LoaderService
// ---------------------------------------------------------------------------

/// Factory and utility methods for working with loaders.
///
/// Ported from `ghidra.app.util.opinion.LoaderService`.
pub struct LoaderService;

impl LoaderService {
    /// Get all supported load specs for the given data from all registered loaders.
    ///
    /// Equivalent to Java's `LoaderService.getAllSupportedLoadSpecs()`.
    pub fn get_supported_load_specs(data: &[u8]) -> LoaderMap {
        let mut map = LoaderMap::new();

        // ELF
        if crate::loader::elf_loader::is_elf(data) {
            let specs = crate::loader::elf_loader::find_elf_load_specs(data);
            if !specs.is_empty() {
                map.insert(crate::loader::elf_loader::ELF_NAME, specs);
            }
        }

        // PE
        if crate::loader::pe_loader::is_pe(data) {
            let specs = crate::loader::pe_loader::find_pe_load_specs(data);
            if !specs.is_empty() {
                map.insert(crate::loader::pe_loader::PE_NAME, specs);
            }
        }

        // Mach-O
        if crate::loader::macho_loader::is_macho(data) {
            let specs = crate::loader::macho_loader::find_macho_load_specs(data);
            if !specs.is_empty() {
                map.insert(crate::loader::macho_loader::MACH_O_NAME, specs);
            }
        }

        // COFF
        if crate::loader::coff_loader::is_coff(data) {
            let specs = crate::loader::coff_loader::find_coff_load_specs(data, false);
            if !specs.is_empty() {
                map.insert(crate::loader::coff_loader::COFF_NAME, specs);
            }
            // MS COFF
            let ms_specs = crate::loader::coff_loader::find_coff_load_specs(data, true);
            if !ms_specs.is_empty() {
                map.insert(crate::loader::coff_loader::MS_COFF_NAME, ms_specs);
            }
        }

        // MZ
        if crate::loader::mz_loader::is_mz(data) {
            let specs = crate::loader::mz_loader::find_mz_load_specs();
            map.insert(crate::loader::mz_loader::MZ_NAME, specs);
        }

        // Intel HEX
        if crate::loader::hex_loader::is_intel_hex(data) {
            map.insert(
                crate::loader::hex_loader::INTEL_HEX_NAME,
                vec![LoadSpec::with_unknown_language(
                    crate::loader::hex_loader::INTEL_HEX_NAME, 0, true,
                )],
            );
        }

        // Motorola S-Record
        if crate::loader::hex_loader::is_motorola_hex(data) {
            map.insert(
                crate::loader::hex_loader::MOTOROLA_HEX_NAME,
                vec![LoadSpec::with_unknown_language(
                    crate::loader::hex_loader::MOTOROLA_HEX_NAME, 0, true,
                )],
            );
        }

        map
    }

    /// Get all known loader names, sorted.
    pub fn get_all_loader_names() -> Vec<String> {
        vec![
            crate::loader::elf_loader::ELF_NAME.to_string(),
            crate::loader::pe_loader::PE_NAME.to_string(),
            crate::loader::macho_loader::MACH_O_NAME.to_string(),
            crate::loader::coff_loader::COFF_NAME.to_string(),
            crate::loader::coff_loader::MS_COFF_NAME.to_string(),
            crate::loader::mz_loader::MZ_NAME.to_string(),
            crate::loader::hex_loader::INTEL_HEX_NAME.to_string(),
            crate::loader::hex_loader::MOTOROLA_HEX_NAME.to_string(),
            BinaryRawLoader::BINARY_RAW_NAME.to_string(),
            DefLoader::DEF_NAME.to_string(),
        ]
    }

    /// Get a loader class by name.
    pub fn get_loader_class_by_name(name: &str) -> Option<&'static str> {
        Self::get_all_loader_names()
            .into_iter()
            .find(|n| n == name)
            .map(|n| Box::leak(n.into_boxed_str()) as &str)
    }
}

// ---------------------------------------------------------------------------
// LibraryLookupStrategy
// ---------------------------------------------------------------------------

/// Strategy for resolving library dependencies during load.
///
/// Ported from `ghidra.app.util.opinion.LibraryLookupStrategy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LibraryLookupStrategy {
    /// Search the filesystem for library files.
    FilesystemSearch,
    /// Search the Ghidra project for library programs.
    ProjectSearch,
    /// Use a specified search path.
    CustomPath,
    /// Skip library resolution.
    Skip,
}

impl LibraryLookupStrategy {
    pub fn name(&self) -> &'static str {
        match self {
            LibraryLookupStrategy::FilesystemSearch => "Filesystem Search",
            LibraryLookupStrategy::ProjectSearch => "Project Search",
            LibraryLookupStrategy::CustomPath => "Custom Path",
            LibraryLookupStrategy::Skip => "Skip",
        }
    }
}

impl fmt::Display for LibraryLookupStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// AnalysisTarget
// ---------------------------------------------------------------------------

/// Describes the analysis target for a load.
///
/// Ported from `ghidra.app.util.opinion.AnalysisTarget`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnalysisTarget {
    /// Executable analysis (default).
    Executable,
    /// Library analysis (shared library).
    Library,
    /// Object file analysis.
    ObjectFile,
    /// Core dump analysis.
    CoreDump,
    /// Firmware analysis.
    Firmware,
}

impl AnalysisTarget {
    pub fn name(&self) -> &'static str {
        match self {
            AnalysisTarget::Executable => "Executable",
            AnalysisTarget::Library => "Library",
            AnalysisTarget::ObjectFile => "Object File",
            AnalysisTarget::CoreDump => "Core Dump",
            AnalysisTarget::Firmware => "Firmware",
        }
    }
}

impl fmt::Display for AnalysisTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// AddressSetPartitioner
// ---------------------------------------------------------------------------

/// Partitions an [`AddressSet`] into sub-ranges at specified partition addresses.
///
/// Given a set of partition addresses, splits any range that contains a
/// partition point (other than at its minimum) into two sub-ranges.
///
/// Ported from `ghidra.app.util.opinion.AddressSetPartitioner`.
#[derive(Debug, Clone)]
pub struct AddressSetPartitioner {
    ranges: Vec<AddressRange>,
    range_data: std::collections::HashMap<u64, Vec<u8>>,
}

impl AddressSetPartitioner {
    /// Create a new partitioner that splits the address set at the given partition addresses.
    ///
    /// `range_data` maps the start address offset of each original range to its byte data.
    pub fn new(
        set: &AddressSet,
        range_data: &std::collections::HashMap<u64, Vec<u8>>,
        partition_set: &[Address],
    ) -> Self {
        let mut ranges: Vec<AddressRange> = set.iter().copied().collect();
        ranges.sort_by_key(|r| r.start.offset);

        let mut partitions: Vec<Address> = partition_set.to_vec();
        partitions.sort_by_key(|a| a.offset);
        partitions.dedup_by_key(|a| a.offset);

        let mut result_ranges = Vec::new();
        let mut result_data: std::collections::HashMap<u64, Vec<u8>> = std::collections::HashMap::new();

        for range in ranges {
            let mut current_start = range.start;
            let current_end = range.end;

            // Find partitions that fall within this range (but not at start)
            let mut splits: Vec<Address> = partitions
                .iter()
                .filter(|p| p.offset > range.start.offset && p.offset <= range.end.offset)
                .copied()
                .collect();
            splits.sort_by_key(|a| a.offset);

            for split_addr in splits {
                let first_end = Address::new(split_addr.offset - 1);
                result_ranges.push(AddressRange::new(current_start, first_end));

                // Copy data for the first subrange
                if let Some(data) = range_data.get(&range.start.offset) {
                    let offset = (current_start.offset - range.start.offset) as usize;
                    let len = (first_end.offset - current_start.offset + 1) as usize;
                    if offset + len <= data.len() {
                        result_data.insert(current_start.offset, data[offset..offset + len].to_vec());
                    }
                }

                current_start = split_addr;
            }

            result_ranges.push(AddressRange::new(current_start, current_end));

            // Copy data for the remaining subrange
            if let Some(data) = range_data.get(&range.start.offset) {
                let offset = (current_start.offset - range.start.offset) as usize;
                let len = (current_end.offset - current_start.offset + 1) as usize;
                if offset + len <= data.len() {
                    result_data.insert(current_start.offset, data[offset..offset + len].to_vec());
                }
            }
        }

        result_ranges.sort_by_key(|r| r.start.offset);

        Self {
            ranges: result_ranges,
            range_data: result_data,
        }
    }

    /// Get the partitioned address ranges.
    pub fn ranges(&self) -> &[AddressRange] {
        &self.ranges
    }

    /// Get the byte data for a range starting at the given address.
    pub fn get_range_data(&self, start: &Address) -> Option<&Vec<u8>> {
        self.range_data.get(&start.offset)
    }

    /// Get the number of partitioned ranges.
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

impl IntoIterator for AddressSetPartitioner {
    type Item = AddressRange;
    type IntoIter = std::vec::IntoIter<AddressRange>;

    fn into_iter(self) -> Self::IntoIter {
        self.ranges.into_iter()
    }
}

// ---------------------------------------------------------------------------
// BinaryRawLoader
// ---------------------------------------------------------------------------

/// Raw binary loader that loads any file as a raw binary blob.
///
/// This is the fallback loader with the lowest priority (`UNTARGETED_LOADER` tier).
///
/// Ported from `ghidra.app.util.opinion.BinaryLoader`.
#[derive(Debug, Clone)]
pub struct BinaryRawLoader;

impl BinaryRawLoader {
    pub const BINARY_RAW_NAME: &'static str = "Raw Binary";
    pub const OPTION_BASE_ADDRESS: &'static str = "Base Address";
    pub const OPTION_FILE_OFFSET: &'static str = "File Offset";
    pub const OPTION_LENGTH: &'static str = "Length";
    pub const OPTION_BLOCK_NAME: &'static str = "Block Name";
    pub const OPTION_IS_OVERLAY: &'static str = "Overlay";

    /// Get the tier for this loader.
    pub fn tier(&self) -> LoaderTier {
        LoaderTier::UntargetedLoader
    }

    /// Get the priority within the tier.
    pub fn tier_priority(&self) -> u32 {
        100
    }

    /// Find supported load specs -- returns all language/compiler pairs as non-preferred.
    pub fn find_supported_load_specs(&self) -> Vec<LoadSpec> {
        // Raw binary supports any language as non-preferred
        vec![LoadSpec::with_unknown_language(
            Self::BINARY_RAW_NAME,
            0,
            true,
        )]
    }

    /// Get default options for raw binary loading.
    pub fn default_options(file_length: u64) -> Vec<LoadOption> {
        vec![
            LoadOption::new_address(Self::OPTION_BASE_ADDRESS, 0),
            LoadOption::new_hex(Self::OPTION_FILE_OFFSET, 0),
            LoadOption::new_hex(Self::OPTION_LENGTH, file_length),
            LoadOption::new_string(Self::OPTION_BLOCK_NAME, ""),
            LoadOption::new_bool(Self::OPTION_IS_OVERLAY, false),
        ]
    }

    /// Validate options for raw binary loading.
    pub fn validate_options(
        options: &[LoadOption],
        file_length: u64,
    ) -> Result<(), String> {
        let base_addr = options
            .iter()
            .find(|o| o.name == Self::OPTION_BASE_ADDRESS)
            .and_then(|o| o.value.as_u64())
            .unwrap_or(0);

        let file_offset = options
            .iter()
            .find(|o| o.name == Self::OPTION_FILE_OFFSET)
            .and_then(|o| o.value.as_u64())
            .unwrap_or(0);

        let length = options
            .iter()
            .find(|o| o.name == Self::OPTION_LENGTH)
            .and_then(|o| o.value.as_u64())
            .unwrap_or(file_length);

        if file_offset >= file_length {
            return Err(format!(
                "File Offset must be less than file length {} (0x{:x})",
                file_length, file_length
            ));
        }

        if file_offset + length > file_length {
            return Err(format!(
                "File Offset + Length (0x{:x}) too large; set length to 0x{:x}",
                file_offset + length,
                file_length - file_offset
            ));
        }

        if base_addr.checked_add(length).is_none() {
            return Err("Base address + length overflow".into());
        }

        Ok(())
    }

    /// Get the loader name.
    pub fn name(&self) -> &str {
        Self::BINARY_RAW_NAME
    }

    /// Raw binary loader should apply processor labels by default.
    pub fn should_apply_processor_labels(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// DefLoader
// ---------------------------------------------------------------------------

/// Loader for Microsoft DEF (Module Definition) files.
///
/// DEF files describe exported symbols from a DLL.
///
/// Ported from `ghidra.app.util.opinion.DefLoader`.
#[derive(Debug, Clone)]
pub struct DefLoader;

/// A parsed DEF export line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefExportLine {
    /// The exported symbol name.
    pub name: String,
    /// Optional ordinal number.
    pub ordinal: Option<u32>,
    /// Optional forwarded name.
    pub forwarded_name: Option<String>,
    /// Whether this is a DATA export.
    pub is_data: bool,
    /// Whether this is a PRIVATE export.
    pub is_private: bool,
}

impl DefExportLine {
    /// Parse a DEF EXPORT line.
    ///
    /// Format: `name[=internalname] [@ordinal [NONAME]] [PRIVATE] [DATA]`
    pub fn parse(line: &str) -> Self {
        let line = line.trim();
        let mut parts = line.split_whitespace();
        let name_part = parts.next().unwrap_or("").to_string();

        // Parse name (may contain = for forwarding)
        let (name, forwarded_name) = if let Some(eq_pos) = name_part.find('=') {
            (
                name_part[..eq_pos].to_string(),
                Some(name_part[eq_pos + 1..].to_string()),
            )
        } else {
            (name_part, None)
        };

        let mut ordinal = None;
        let mut is_data = false;
        let mut is_private = false;

        for part in parts {
            if part.starts_with('@') {
                ordinal = part[1..].parse().ok();
            } else if part.eq_ignore_ascii_case("DATA") {
                is_data = true;
            } else if part.eq_ignore_ascii_case("PRIVATE") {
                is_private = true;
            } else if part.eq_ignore_ascii_case("NONAME") {
                // NONAME indicates export by ordinal only
            }
        }

        Self {
            name,
            ordinal,
            forwarded_name,
            is_data,
            is_private,
        }
    }
}

impl DefLoader {
    pub const DEF_NAME: &'static str = "Module Definition (DEF)";

    /// Detect if data is a DEF file.
    pub fn is_def(data: &[u8]) -> bool {
        let text = String::from_utf8_lossy(&data[..data.len().min(1024)]);
        let upper = text.to_uppercase();
        upper.contains("LIBRARY") || upper.contains("EXPORTS")
    }

    /// Parse DEF exports from byte data.
    pub fn parse_exports(data: &[u8]) -> Vec<DefExportLine> {
        let text = String::from_utf8_lossy(data);
        let mut exports = Vec::new();
        let mut in_exports = false;

        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with(';') || trimmed.is_empty() {
                continue;
            }
            if trimmed.starts_with("LIBRARY") {
                continue;
            }
            if trimmed.starts_with("EXPORTS") {
                in_exports = true;
                continue;
            }
            if in_exports && !trimmed.starts_with("NAME")
                && !trimmed.starts_with("DESCRIPTION")
                && !trimmed.starts_with("STACKSIZE")
                && !trimmed.starts_with("HEAPSIZE")
                && !trimmed.starts_with("VERSION")
                && !trimmed.starts_with("SECTIONS")
            {
                exports.push(DefExportLine::parse(trimmed));
            }
        }

        exports
    }

    pub fn name(&self) -> &str {
        Self::DEF_NAME
    }

    pub fn tier(&self) -> LoaderTier {
        LoaderTier::GenericTargetLoader
    }

    pub fn tier_priority(&self) -> u32 {
        50
    }

    pub fn find_supported_load_specs(&self, data: &[u8]) -> Vec<LoadSpec> {
        if Self::is_def(data) {
            vec![LoadSpec::with_unknown_language(
                Self::DEF_NAME, 0, true,
            )]
        } else {
            vec![]
        }
    }
}

// ---------------------------------------------------------------------------
// GdtLoader
// ---------------------------------------------------------------------------

/// Loader for Ghidra packed data type archives (.gdt files).
///
/// Ported from `ghidra.app.util.opinion.GdtLoader`.
#[derive(Debug, Clone)]
pub struct GdtLoader;

impl GdtLoader {
    pub const GDT_NAME: &'static str = "Ghidra Type Archive (GDT)";

    /// Detect if data is a GDT file (packed database format).
    pub fn is_gdt(data: &[u8]) -> bool {
        // Ghidra packed databases start with specific magic bytes
        // or can be SQLite databases containing type archives
        data.len() >= 16 && (data[0..4] == [0x47, 0x44, 0x42, 0x00] || // "GDB\0"
            data[0..16] == *b"SQLite format 3\0")
    }

    pub fn name(&self) -> &str {
        Self::GDT_NAME
    }

    pub fn tier(&self) -> LoaderTier {
        LoaderTier::SpecializedTargetLoader
    }

    pub fn tier_priority(&self) -> u32 {
        0
    }

    pub fn find_supported_load_specs(&self, data: &[u8]) -> Vec<LoadSpec> {
        if Self::is_gdt(data) {
            vec![LoadSpec::with_unknown_language(
                Self::GDT_NAME, 0, false,
            )]
        } else {
            vec![]
        }
    }
}

// ---------------------------------------------------------------------------
// GzfLoader
// ---------------------------------------------------------------------------

/// Loader for Ghidra packed program files (.gzf files).
///
/// Ported from `ghidra.app.util.opinion.GzfLoader`.
#[derive(Debug, Clone)]
pub struct GzfLoader;

impl GzfLoader {
    pub const GZF_NAME: &'static str = "GZF Input Format";

    /// Detect if data is a GZF file.
    pub fn is_gzf(data: &[u8]) -> bool {
        // GZF files are Ghidra packed databases containing programs
        data.len() >= 4 && data[0..4] == [0x47, 0x44, 0x42, 0x00] // "GDB\0"
    }

    pub fn name(&self) -> &str {
        Self::GZF_NAME
    }

    pub fn tier(&self) -> LoaderTier {
        LoaderTier::SpecializedTargetLoader
    }

    pub fn tier_priority(&self) -> u32 {
        0
    }

    pub fn find_supported_load_specs(&self, data: &[u8]) -> Vec<LoadSpec> {
        if Self::is_gzf(data) {
            vec![LoadSpec::with_unknown_language(
                Self::GZF_NAME, 0, true,
            )]
        } else {
            vec![]
        }
    }
}

// ---------------------------------------------------------------------------
// DbgLoader
// ---------------------------------------------------------------------------

/// Loader for Microsoft DBG (debug symbols) files.
///
/// DBG files contain debug information in CodeView format.
///
/// Ported from `ghidra.app.util.opinion.DbgLoader`.
#[derive(Debug, Clone)]
pub struct DbgLoader;

/// Separate debug header format for DBG files.
#[derive(Debug, Clone)]
pub struct SeparateDebugHeader {
    pub signature: u32,
    pub machine: u16,
    pub characteristics: u16,
    pub time_date_stamp: u32,
    pub checksum: u32,
    pub image_base: u32,
    pub size_of_image: u32,
    pub number_of_sections: u32,
    pub exported_names_size: u32,
    pub debug_directory_size: u32,
    pub reserved: [u32; 3],
}

impl SeparateDebugHeader {
    pub const IMAGE_SEPARATE_DEBUG_SIGNATURE: u32 = 0x4944_4D50; // 'IDMP'

    /// Parse from byte data.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 46 {
            return None;
        }
        let signature = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if signature != Self::IMAGE_SEPARATE_DEBUG_SIGNATURE {
            return None;
        }
        Some(Self {
            signature,
            machine: u16::from_le_bytes([data[4], data[5]]),
            characteristics: u16::from_le_bytes([data[6], data[7]]),
            time_date_stamp: u32::from_le_bytes([data[8], data[9], data[10], data[11]]),
            checksum: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
            image_base: u32::from_le_bytes([data[16], data[17], data[18], data[19]]),
            size_of_image: u32::from_le_bytes([data[20], data[21], data[22], data[23]]),
            number_of_sections: u32::from_le_bytes([data[24], data[25], data[26], data[27]]),
            exported_names_size: u32::from_le_bytes([data[28], data[29], data[30], data[31]]),
            debug_directory_size: u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
            reserved: [
                u32::from_le_bytes([data[36], data[37], data[38], data[39]]),
                u32::from_le_bytes([data[40], data[41], data[42], data[43]]),
                u32::from_le_bytes([data[44], data[45], data[46], data[47].min(0)]),
            ],
        })
    }

    /// Get a machine name string for the machine type.
    pub fn machine_name(&self) -> &'static str {
        match self.machine {
            0x014c => "x86",
            0x0200 => "IA64",
            0x8664 => "x86_64",
            0x01c4 => "ARM",
            0xAA64 => "AARCH64",
            _ => "unknown",
        }
    }
}

impl DbgLoader {
    pub const DBG_NAME: &'static str = "Debug Symbols (DBG)";
    const MIN_BYTE_LENGTH: usize = 46;

    /// Detect if data is a DBG file.
    pub fn is_dbg(data: &[u8]) -> bool {
        SeparateDebugHeader::parse(data).is_some()
    }

    /// Find supported load specs for a DBG file.
    pub fn find_supported_load_specs(&self, data: &[u8]) -> Vec<LoadSpec> {
        let header = match SeparateDebugHeader::parse(data) {
            Some(h) => h,
            None => return vec![],
        };

        let image_base = header.image_base as u64;
        let machine = header.machine_name();

        let mut load_specs = Vec::new();
        let opinions = QueryOpinionService::query(Self::DBG_NAME, machine, None);
        for result in opinions {
            load_specs.push(LoadSpec::from_query_result(
                Self::DBG_NAME,
                image_base,
                &result,
            ));
        }

        if load_specs.is_empty() {
            load_specs.push(LoadSpec::with_unknown_language(
                Self::DBG_NAME, image_base, true,
            ));
        }

        load_specs
    }

    pub fn name(&self) -> &str {
        Self::DBG_NAME
    }

    pub fn tier(&self) -> LoaderTier {
        LoaderTier::SpecializedTargetLoader
    }

    pub fn tier_priority(&self) -> u32 {
        10
    }
}

// ---------------------------------------------------------------------------
// LibraryHints / LibraryLookupTable
// ---------------------------------------------------------------------------

/// Hints for resolving library dependencies.
///
/// Ported from `ghidra.app.util.opinion.LibraryHints`.
#[derive(Debug, Clone)]
pub struct LibraryHints {
    hints: Vec<LibraryHint>,
}

/// A single library hint.
#[derive(Debug, Clone)]
pub struct LibraryHint {
    /// Library name (e.g., "kernel32.dll").
    pub library_name: String,
    /// The preferred path to search.
    pub preferred_path: Option<String>,
    /// The language/compiler spec for this library.
    pub lcs: Option<LanguageCompilerSpecPair>,
    /// Additional search paths.
    pub search_paths: Vec<String>,
}

impl LibraryHints {
    pub fn new() -> Self {
        Self { hints: Vec::new() }
    }

    pub fn add_hint(&mut self, hint: LibraryHint) {
        self.hints.push(hint);
    }

    pub fn find_hint(&self, library_name: &str) -> Option<&LibraryHint> {
        self.hints.iter().find(|h| h.library_name == library_name)
    }

    pub fn len(&self) -> usize {
        self.hints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hints.is_empty()
    }

    pub fn hints(&self) -> &[LibraryHint] {
        &self.hints
    }
}

impl Default for LibraryHints {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// BoundedBufferedReader
// ---------------------------------------------------------------------------

/// A buffered reader that enforces a maximum line length.
///
/// Ported from `ghidra.app.util.opinion.BoundedBufferedReader`.
#[derive(Debug)]
pub struct BoundedBufferedReader<R> {
    inner: R,
    max_line_length: usize,
    buffer: Vec<u8>,
}

impl<R: std::io::BufRead> BoundedBufferedReader<R> {
    pub fn new(inner: R, max_line_length: usize) -> Self {
        Self {
            inner,
            max_line_length,
            buffer: Vec::new(),
        }
    }

    /// Read a line, truncating to the maximum length.
    pub fn read_line(&mut self) -> std::io::Result<Option<String>> {
        self.buffer.clear();
        let bytes_read = self.inner.read_until(b'\n', &mut self.buffer)?;
        if bytes_read == 0 {
            return Ok(None);
        }

        let mut s = String::from_utf8_lossy(&self.buffer).into_owned();
        // Remove trailing newline
        if s.ends_with('\n') {
            s.pop();
            if s.ends_with('\r') {
                s.pop();
            }
        }

        // Truncate if needed
        if s.len() > self.max_line_length {
            s.truncate(self.max_line_length);
        }

        Ok(Some(s))
    }

    /// Read all lines, respecting the max line length.
    pub fn read_lines(&mut self) -> std::io::Result<Vec<String>> {
        let mut lines = Vec::new();
        while let Some(line) = self.read_line()? {
            lines.push(line);
        }
        Ok(lines)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_exception_display() {
        let e = LoadException::new("test error");
        assert_eq!(e.to_string(), "LoadException: test error");
        assert_eq!(e.message(), "test error");
    }

    #[test]
    fn test_loader_opinion_exception_display() {
        let e = LoaderOpinionException::new("bad opinion");
        assert!(e.to_string().contains("bad opinion"));
    }

    #[test]
    fn test_loader_map_basic() {
        let mut map = LoaderMap::new();
        assert!(map.is_empty());

        map.insert("ELF", vec![LoadSpec::with_unknown_language("ELF", 0, true)]);
        assert_eq!(map.loader_count(), 1);
        assert_eq!(map.total_spec_count(), 1);
        assert!(map.contains_loader("ELF"));
        assert!(!map.contains_loader("PE"));
    }

    #[test]
    fn test_loader_map_display() {
        let mut map = LoaderMap::new();
        map.insert("ELF", vec![
            LoadSpec::with_unknown_language("ELF", 0x400000, true),
            LoadSpec::with_unknown_language("ELF", 0, true),
        ]);
        map.insert("PE", vec![LoadSpec::with_unknown_language("PE", 0x10000, true)]);

        let display = map.to_string();
        assert!(display.contains("ELF - 2 load specs"));
        assert!(display.contains("PE - 1 load specs"));
    }

    #[test]
    fn test_loader_map_all_specs() {
        let mut map = LoaderMap::new();
        map.insert("A", vec![LoadSpec::with_unknown_language("A", 0, true)]);
        map.insert("B", vec![
            LoadSpec::with_unknown_language("B", 0, true),
            LoadSpec::with_unknown_language("B", 100, false),
        ]);

        let all = map.all_specs();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_loader_map_sorted() {
        let mut map = LoaderMap::new();
        map.insert("Zebra", vec![]);
        map.insert("Alpha", vec![]);
        map.insert("Middle", vec![]);

        let names: Vec<&String> = map.loader_names().into_iter().collect();
        assert_eq!(names, vec!["Alpha", "Middle", "Zebra"]);
    }

    #[test]
    fn test_address_set_partitioner_no_splits() {
        let mut set = AddressSet::new();
        set.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));

        let range_map = std::collections::HashMap::new();
        let partitioner = AddressSetPartitioner::new(&set, &range_map, &[]);
        assert_eq!(partitioner.len(), 1);
        assert_eq!(partitioner.ranges()[0].start.offset, 0x1000);
        assert_eq!(partitioner.ranges()[0].end.offset, 0x1FFF);
    }

    #[test]
    fn test_address_set_partitioner_with_split() {
        let mut set = AddressSet::new();
        set.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));

        let range_map = std::collections::HashMap::new();
        let partitions = vec![Address::new(0x1800)];
        let partitioner = AddressSetPartitioner::new(&set, &range_map, &partitions);

        assert_eq!(partitioner.len(), 2);
        assert_eq!(partitioner.ranges()[0].start.offset, 0x1000);
        assert_eq!(partitioner.ranges()[0].end.offset, 0x17FF);
        assert_eq!(partitioner.ranges()[1].start.offset, 0x1800);
        assert_eq!(partitioner.ranges()[1].end.offset, 0x1FFF);
    }

    #[test]
    fn test_address_set_partitioner_split_at_start() {
        // Splitting at the start of a range should NOT split it
        let mut set = AddressSet::new();
        set.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));

        let range_map = std::collections::HashMap::new();
        let partitions = vec![Address::new(0x1000)];
        let partitioner = AddressSetPartitioner::new(&set, &range_map, &partitions);

        assert_eq!(partitioner.len(), 1);
    }

    #[test]
    fn test_address_set_partitioner_with_data() {
        let mut set = AddressSet::new();
        set.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x100F)));

        let mut range_data = std::collections::HashMap::new();
        range_data.insert(0x1000u64, vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);

        let partitions = vec![Address::new(0x1008)];
        let partitioner = AddressSetPartitioner::new(&set, &range_data, &partitions);

        assert_eq!(partitioner.len(), 2);

        let data0 = partitioner.get_range_data(&Address::new(0x1000)).unwrap();
        assert_eq!(data0.len(), 8);
        assert_eq!(data0[0], 0);
        assert_eq!(data0[7], 7);

        let data1 = partitioner.get_range_data(&Address::new(0x1008)).unwrap();
        assert_eq!(data1.len(), 8);
        assert_eq!(data1[0], 8);
        assert_eq!(data1[7], 15);
    }

    #[test]
    fn test_binary_raw_loader() {
        let loader = BinaryRawLoader;
        assert_eq!(loader.name(), "Raw Binary");
        assert_eq!(loader.tier(), LoaderTier::UntargetedLoader);
        assert!(loader.should_apply_processor_labels());
    }

    #[test]
    fn test_binary_raw_loader_validate() {
        let opts = BinaryRawLoader::default_options(1024);
        assert!(BinaryRawLoader::validate_options(&opts, 1024).is_ok());

        // Bad offset
        let bad_opts = vec![
            LoadOption::new_hex(BinaryRawLoader::OPTION_FILE_OFFSET, 2000),
            LoadOption::new_hex(BinaryRawLoader::OPTION_LENGTH, 100),
            LoadOption::new_address(BinaryRawLoader::OPTION_BASE_ADDRESS, 0),
        ];
        assert!(BinaryRawLoader::validate_options(&bad_opts, 1024).is_err());
    }

    #[test]
    fn test_def_export_line_parse() {
        let line = "MyFunction";
        let exp = DefExportLine::parse(line);
        assert_eq!(exp.name, "MyFunction");
        assert!(exp.ordinal.is_none());
        assert!(!exp.is_data);

        let line = "MyFunc @5";
        let exp = DefExportLine::parse(line);
        assert_eq!(exp.name, "MyFunc");
        assert_eq!(exp.ordinal, Some(5));

        let line = "MyData @10 DATA PRIVATE";
        let exp = DefExportLine::parse(line);
        assert_eq!(exp.name, "MyData");
        assert_eq!(exp.ordinal, Some(10));
        assert!(exp.is_data);
        assert!(exp.is_private);

        let line = "Exported=Internal @3";
        let exp = DefExportLine::parse(line);
        assert_eq!(exp.name, "Exported");
        assert_eq!(exp.forwarded_name, Some("Internal".to_string()));
        assert_eq!(exp.ordinal, Some(3));
    }

    #[test]
    fn test_def_loader_is_def() {
        let data = b"LIBRARY MyLib\nEXPORTS\n  MyFunc @1\n";
        assert!(DefLoader::is_def(data));

        let data = b"EXPORTS\n  Func1\n  Func2\n";
        assert!(DefLoader::is_def(data));

        let data = b"\x7fELF";
        assert!(!DefLoader::is_def(data));
    }

    #[test]
    fn test_def_loader_parse_exports() {
        let data = b"LIBRARY MyLib\nEXPORTS\n  Func1 @1\n  Func2 @2 DATA\n  Func3 @3 PRIVATE\n";
        let exports = DefLoader::parse_exports(data);
        assert_eq!(exports.len(), 3);
        assert_eq!(exports[0].name, "Func1");
        assert_eq!(exports[0].ordinal, Some(1));
        assert_eq!(exports[1].name, "Func2");
        assert!(exports[1].is_data);
        assert_eq!(exports[2].name, "Func3");
        assert!(exports[2].is_private);
    }

    #[test]
    fn test_dbg_loader() {
        let loader = DbgLoader;
        assert_eq!(loader.name(), "Debug Symbols (DBG)");
        assert_eq!(loader.tier(), LoaderTier::SpecializedTargetLoader);

        // Invalid data
        assert!(!DbgLoader::is_dbg(&[0u8; 16]));
        assert!(loader.find_supported_load_specs(&[0u8; 16]).is_empty());
    }

    #[test]
    fn test_separate_debug_header() {
        // Too short
        assert!(SeparateDebugHeader::parse(&[0u8; 10]).is_none());

        // Wrong signature
        assert!(SeparateDebugHeader::parse(&[0u8; 64]).is_none());
    }

    #[test]
    fn test_separate_debug_header_parse() {
        let mut data = vec![0u8; 64];
        // Signature: 'IDMP' in LE
        data[0] = b'P';
        data[1] = b'M';
        data[2] = b'D';
        data[3] = b'I';
        // Machine: x86 (0x014c)
        data[4] = 0x4c;
        data[5] = 0x01;

        let header = SeparateDebugHeader::parse(&data).unwrap();
        assert_eq!(header.signature, SeparateDebugHeader::IMAGE_SEPARATE_DEBUG_SIGNATURE);
        assert_eq!(header.machine, 0x014c);
        assert_eq!(header.machine_name(), "x86");
    }

    #[test]
    fn test_gdt_loader() {
        let loader = GdtLoader;
        assert_eq!(loader.name(), "Ghidra Type Archive (GDT)");
        assert_eq!(loader.tier(), LoaderTier::SpecializedTargetLoader);

        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"GDB\0");
        assert!(GdtLoader::is_gdt(&data));
        assert_eq!(loader.find_supported_load_specs(&data).len(), 1);
    }

    #[test]
    fn test_gzf_loader() {
        let loader = GzfLoader;
        assert_eq!(loader.name(), "GZF Input Format");
        assert_eq!(loader.tier(), LoaderTier::SpecializedTargetLoader);

        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"GDB\0");
        assert!(GzfLoader::is_gzf(&data));
        assert_eq!(loader.find_supported_load_specs(&data).len(), 1);
    }

    #[test]
    fn test_library_hints() {
        let mut hints = LibraryHints::new();
        assert!(hints.is_empty());

        hints.add_hint(LibraryHint {
            library_name: "kernel32.dll".into(),
            preferred_path: Some("C:\\Windows\\System32".into()),
            lcs: None,
            search_paths: vec![],
        });

        assert_eq!(hints.len(), 1);
        let hint = hints.find_hint("kernel32.dll").unwrap();
        assert_eq!(hint.library_name, "kernel32.dll");
        assert!(hints.find_hint("ntdll.dll").is_none());
    }

    #[test]
    fn test_bounded_buffered_reader() {
        let data = b"line1\nline2\na very long line that should be truncated\n";
        let cursor = std::io::Cursor::new(data);
        let mut reader = BoundedBufferedReader::new(std::io::BufReader::new(cursor), 10);
        let lines = reader.read_lines().unwrap();

        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "line1");
        assert_eq!(lines[1], "line2");
        assert_eq!(lines[2], "a very lon"); // truncated to 10 chars
    }

    #[test]
    fn test_library_lookup_strategy_display() {
        assert_eq!(LibraryLookupStrategy::FilesystemSearch.to_string(), "Filesystem Search");
        assert_eq!(LibraryLookupStrategy::Skip.to_string(), "Skip");
    }

    #[test]
    fn test_analysis_target_display() {
        assert_eq!(AnalysisTarget::Executable.to_string(), "Executable");
        assert_eq!(AnalysisTarget::CoreDump.to_string(), "Core Dump");
    }

    #[test]
    fn test_loader_service_get_all_names() {
        let names = LoaderService::get_all_loader_names();
        assert!(names.iter().any(|n| n == "Raw Binary"));
        assert!(names.iter().any(|n| n == "Module Definition (DEF)"));
    }

    #[test]
    fn test_address_set_partitioner_into_iter() {
        let mut set = AddressSet::new();
        set.add_range(AddressRange::new(Address::new(0x1000), Address::new(0x1FFF)));

        let range_map = std::collections::HashMap::new();
        let partitioner = AddressSetPartitioner::new(&set, &range_map, &[Address::new(0x1500)]);

        let ranges: Vec<AddressRange> = partitioner.into_iter().collect();
        assert_eq!(ranges.len(), 2);
    }
}
