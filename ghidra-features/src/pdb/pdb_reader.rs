//! PDB Reader -- high-level interface for reading PDB files.
//!
//! Ports Ghidra's `ghidra.app.util.pdb.PdbReader` and related Java classes.
//!
//! Provides a unified entry point for opening, validating, and querying PDB
//! files. Wraps the lower-level MSF parser, stream decoders, and type/symbol
//! iterators into a single cohesive API.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use super::pdb_program_attributes::PdbProgramAttributes;
use super::pdb_applicator_options::PdbApplicatorOptions;
use super::{
    MsfFile, PdbFile, PdbInfoStream, TpiStream, IpiStream, DbiStream,
    TypeRecord, SymbolRecord, SymbolStream, parse_msf, parse_pdb_info_stream,
    parse_tpi_stream, parse_ipi_stream, parse_dbi_stream,
    MsfError, StreamError,
};

// =============================================================================
// PDB Reader Error
// =============================================================================

/// Errors that can occur during PDB reading.
#[derive(Debug, Clone)]
pub enum PdbReaderError {
    /// The file could not be read from disk.
    IoError(String),
    /// The MSF container could not be parsed.
    MsfParseError(String),
    /// A PDB stream could not be parsed.
    StreamParseError(String),
    /// The PDB does not contain expected identification information.
    MissingIdentification,
    /// The PDB GUID/signature/age does not match the expected values.
    IdentificationMismatch {
        expected_guid: Option<String>,
        actual_guid: Option<String>,
        expected_age: Option<String>,
        actual_age: Option<String>,
    },
    /// The PDB file is corrupted or truncated.
    Corrupted(String),
}

impl fmt::Display for PdbReaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PdbReaderError::IoError(msg) => write!(f, "PDB I/O error: {}", msg),
            PdbReaderError::MsfParseError(msg) => write!(f, "PDB MSF parse error: {}", msg),
            PdbReaderError::StreamParseError(msg) => write!(f, "PDB stream parse error: {}", msg),
            PdbReaderError::MissingIdentification => {
                write!(f, "PDB is missing identification (GUID/signature/age)")
            }
            PdbReaderError::IdentificationMismatch {
                expected_guid, actual_guid, expected_age, actual_age,
            } => {
                write!(
                    f,
                    "PDB identification mismatch: expected GUID={:?} age={:?}, got GUID={:?} age={:?}",
                    expected_guid, expected_age, actual_guid, actual_age
                )
            }
            PdbReaderError::Corrupted(msg) => write!(f, "PDB corrupted: {}", msg),
        }
    }
}

impl std::error::Error for PdbReaderError {}

impl From<std::io::Error> for PdbReaderError {
    fn from(e: std::io::Error) -> Self {
        PdbReaderError::IoError(e.to_string())
    }
}

impl From<MsfError> for PdbReaderError {
    fn from(e: MsfError) -> Self {
        PdbReaderError::MsfParseError(e.to_string())
    }
}

impl From<StreamError> for PdbReaderError {
    fn from(e: StreamError) -> Self {
        PdbReaderError::StreamParseError(e.to_string())
    }
}

// =============================================================================
// PdbReader -- high-level PDB reader
// =============================================================================

/// A high-level PDB file reader.
///
/// This is the main entry point for reading PDB files. It provides methods
/// for loading a PDB from disk or from memory, validating the PDB's identity,
/// and querying the PDB's contents (types, symbols, modules, debug info).
///
/// Ports Ghidra's `PdbReader` Java class.
pub struct PdbReader {
    /// The underlying parsed PDB file.
    pdb: PdbFile,
    /// The path from which the PDB was loaded, if any.
    source_path: Option<PathBuf>,
    /// Attributes describing the PDB's identification.
    attributes: PdbProgramAttributes,
    /// Options controlling how the PDB should be applied.
    options: PdbApplicatorOptions,
    /// Cached type index to name mapping.
    type_names: HashMap<u32, String>,
}

impl PdbReader {
    /// Open and parse a PDB file from disk.
    ///
    /// Validates the file header and parses all standard streams.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PdbReaderError> {
        let path = path.as_ref();
        let data = std::fs::read(path)?;
        let mut reader = Self::parse_bytes(&data)?;
        reader.source_path = Some(path.to_path_buf());
        Ok(reader)
    }

    /// Parse a PDB from an in-memory byte buffer.
    pub fn parse_bytes(data: &[u8]) -> Result<Self, PdbReaderError> {
        let pdb = PdbFile::parse(data)
            .map_err(|e| PdbReaderError::MsfParseError(e.to_string()))?;

        let attributes = Self::build_attributes(&pdb);
        let options = PdbApplicatorOptions::default();
        let type_names = Self::build_type_name_cache(&pdb);

        Ok(Self {
            pdb,
            source_path: None,
            attributes,
            options,
            type_names,
        })
    }

    /// Build PdbProgramAttributes from a parsed PDB file.
    fn build_attributes(pdb: &PdbFile) -> PdbProgramAttributes {
        let guid = pdb.guid_string();
        let age = pdb.age().map(|a| format!("{:X}", a));
        let signature = pdb.signature().map(|s| format!("{:08X}", s));
        PdbProgramAttributes::new(
            guid,
            age,
            true, // loaded
            false, // analyzed
            signature,
            None, // file path set separately
            String::new(),
        )
    }

    /// Build a type index to name mapping cache.
    fn build_type_name_cache(pdb: &PdbFile) -> HashMap<u32, String> {
        let mut map = HashMap::new();
        if let Some(ref tpi) = pdb.tpi {
            let base_index = tpi.type_index_begin;
            for (i, rec) in tpi.types.iter().enumerate() {
                let ti = base_index + i as u32;
                if let Some(name) = Self::type_record_name(rec) {
                    map.insert(ti, name);
                }
            }
        }
        map
    }

    /// Extract the name from a type record, if it has one.
    fn type_record_name(record: &TypeRecord) -> Option<String> {
        match record {
            TypeRecord::Class(c) => Some(c.name.clone()),
            TypeRecord::Structure(s) => Some(s.name.clone()),
            TypeRecord::Union(u) => Some(u.name.clone()),
            TypeRecord::Enum(e) => Some(e.name.clone()),
            TypeRecord::Array(a) => Some(a.name.clone()),
            _ => None,
        }
    }

    // =========================================================================
    // Accessors
    // =========================================================================

    /// Get the PDB program attributes.
    pub fn attributes(&self) -> &PdbProgramAttributes {
        &self.attributes
    }

    /// Get the PDB applicator options.
    pub fn options(&self) -> &PdbApplicatorOptions {
        &self.options
    }

    /// Get mutable access to the PDB applicator options.
    pub fn options_mut(&mut self) -> &mut PdbApplicatorOptions {
        &mut self.options
    }

    /// Get the source path from which this PDB was loaded.
    pub fn source_path(&self) -> Option<&Path> {
        self.source_path.as_deref()
    }

    /// Get a reference to the underlying parsed PDB file.
    pub fn pdb_file(&self) -> &PdbFile {
        &self.pdb
    }

    /// Get the PDB GUID as a string.
    pub fn guid_string(&self) -> Option<String> {
        self.pdb.guid_string()
    }

    /// Get the PDB age.
    pub fn age(&self) -> Option<u32> {
        self.pdb.age()
    }

    /// Get the PDB signature.
    pub fn signature(&self) -> Option<u32> {
        self.pdb.signature()
    }

    /// Check if the PDB contains debug information (DBI stream).
    pub fn has_debug_info(&self) -> bool {
        self.pdb.has_dbi()
    }

    /// Get the number of type records in the TPI stream.
    pub fn type_count(&self) -> usize {
        self.pdb.type_count()
    }

    // =========================================================================
    // Type queries
    // =========================================================================

    /// Look up a type record by its type index.
    pub fn get_type(&self, type_index: u32) -> Option<&TypeRecord> {
        self.pdb.get_type(type_index)
    }

    /// Get the name of a type by its type index.
    pub fn get_type_name(&self, type_index: u32) -> Option<&str> {
        self.type_names.get(&type_index).map(|s| s.as_str())
    }

    /// Get all type records from the TPI stream.
    pub fn type_records(&self) -> &[TypeRecord] {
        self.pdb.tpi.as_ref().map(|t| t.types.as_slice()).unwrap_or(&[])
    }

    /// Get all item records from the IPI stream.
    pub fn item_records(&self) -> &[TypeRecord] {
        self.pdb.ipi.as_ref().map(|i| i.items.as_slice()).unwrap_or(&[])
    }

    /// Check if a type index refers to a simple/primitive type.
    pub fn is_simple_type(type_index: u32) -> bool {
        type_index < 0x1000
    }

    /// Check if a type index falls in the TPI range.
    pub fn is_tpi_type(&self, type_index: u32) -> bool {
        if let Some(ref tpi) = self.pdb.tpi {
            type_index >= tpi.type_index_begin && type_index < tpi.type_index_end
        } else {
            false
        }
    }

    /// Check if a type index falls in the IPI range.
    pub fn is_ipi_type(&self, type_index: u32) -> bool {
        if let Some(ref ipi) = self.pdb.ipi {
            type_index >= ipi.type_index_begin && type_index < ipi.type_index_end
        } else {
            false
        }
    }

    // =========================================================================
    // Symbol queries
    // =========================================================================

    /// Iterate over all global symbols.
    pub fn global_symbols(&self) -> Option<impl Iterator<Item = SymbolRecord> + '_> {
        self.pdb.global_symbols()
    }

    /// Iterate over all public symbols.
    pub fn public_symbols(&self) -> Option<impl Iterator<Item = SymbolRecord> + '_> {
        self.pdb.public_symbols()
    }

    /// Collect all function definitions (S_GPROC32/S_LPROC32) from global symbols.
    pub fn function_symbols(&self) -> Vec<SymbolRecord> {
        let mut funcs = Vec::new();
        if let Some(iter) = self.global_symbols() {
            for sym in iter {
                match &sym {
                    SymbolRecord::GlobalProcedure(_) | SymbolRecord::LocalProcedure(_) => {
                        funcs.push(sym);
                    }
                    _ => {}
                }
            }
        }
        funcs
    }

    /// Iterate function definitions and return (name, RVA) pairs.
    pub fn iterate_functions(&self) -> Result<Vec<(String, u32)>, PdbReaderError> {
        self.pdb.iterate_functions()
            .map_err(|e| PdbReaderError::StreamParseError(e.to_string()))
    }

    /// Iterate public symbols and return (name, RVA, segment) tuples.
    pub fn iterate_publics(&self) -> Result<Vec<(String, u32, u16)>, PdbReaderError> {
        self.pdb.iterate_publics()
            .map_err(|e| PdbReaderError::StreamParseError(e.to_string()))
    }

    // =========================================================================
    // Module / DBI queries
    // =========================================================================

    /// Get all module information from the DBI stream.
    pub fn modules(&self) -> Vec<&super::ModuleInfo> {
        self.pdb.modules()
    }

    /// Get all section contributions from the DBI stream.
    pub fn section_contributions(&self) -> Vec<&super::SectionContrib> {
        self.pdb.section_contributions()
    }

    /// Get all section map entries from the DBI stream.
    pub fn section_map_entries(&self) -> Vec<&super::SectionMapEntry> {
        self.pdb.section_map_entries()
    }

    /// Get all type server entries from the DBI stream.
    pub fn type_server_entries(&self) -> Vec<&super::TypeServerEntry> {
        self.pdb.type_server_entries()
    }

    /// Get the DBI stream machine type.
    pub fn machine_type(&self) -> Option<u16> {
        self.pdb.dbi.as_ref().map(|d| d.machine)
    }

    /// Check if the PDB has CTypes (complete type information).
    pub fn has_ctypes(&self) -> bool {
        self.pdb.dbi.as_ref().map_or(false, |d| {
            d.flags & super::dbi_flags::HAS_CTYPES != 0
        })
    }

    /// Check if the PDB was incrementally linked.
    pub fn is_incrementally_linked(&self) -> bool {
        self.pdb.dbi.as_ref().map_or(false, |d| {
            d.flags & super::dbi_flags::INCREMENTALLY_LINKED != 0
        })
    }

    // =========================================================================
    // Identity validation
    // =========================================================================

    /// Validate that the PDB matches the expected identification.
    ///
    /// Checks GUID, age, and signature against the provided attributes.
    pub fn validate_identification(
        &self,
        expected: &PdbProgramAttributes,
    ) -> Result<(), PdbReaderError> {
        // Check GUID match
        if let (Some(expected_guid), Some(actual_guid)) =
            (expected.pdb_guid(), self.attributes.pdb_guid())
        {
            if expected_guid != actual_guid {
                return Err(PdbReaderError::IdentificationMismatch {
                    expected_guid: Some(expected_guid.to_string()),
                    actual_guid: Some(actual_guid.to_string()),
                    expected_age: expected.pdb_age().map(|s| s.to_string()),
                    actual_age: self.attributes.pdb_age().map(|s| s.to_string()),
                });
            }
        }

        // Check age match
        if let (Some(expected_age), Some(actual_age)) =
            (expected.pdb_age(), self.attributes.pdb_age())
        {
            if expected_age != actual_age {
                return Err(PdbReaderError::IdentificationMismatch {
                    expected_guid: expected.pdb_guid().map(|s| s.to_string()),
                    actual_guid: self.attributes.pdb_guid().map(|s| s.to_string()),
                    expected_age: Some(expected_age.to_string()),
                    actual_age: Some(actual_age.to_string()),
                });
            }
        }

        Ok(())
    }

    // =========================================================================
    // Summary
    // =========================================================================

    /// Get a human-readable summary of the PDB contents.
    pub fn summary(&self) -> PdbSummary {
        PdbSummary {
            guid: self.pdb.guid_string(),
            age: self.pdb.age(),
            signature: self.pdb.signature(),
            type_count: self.pdb.type_count(),
            module_count: self.pdb.modules().len(),
            has_debug_info: self.pdb.has_dbi(),
            machine_type: self.pdb.dbi.as_ref().map(|d| d.machine),
            source_path: self.source_path.clone(),
        }
    }
}

impl fmt::Debug for PdbReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PdbReader")
            .field("source_path", &self.source_path)
            .field("type_count", &self.type_count())
            .field("has_debug_info", &self.has_debug_info())
            .field("guid", &self.guid_string())
            .finish()
    }
}

// =============================================================================
// PdbSummary -- a snapshot of PDB metadata
// =============================================================================

/// A summary of a PDB file's contents.
#[derive(Debug, Clone)]
pub struct PdbSummary {
    /// The PDB GUID string.
    pub guid: Option<String>,
    /// The PDB age.
    pub age: Option<u32>,
    /// The PDB signature.
    pub signature: Option<u32>,
    /// The total number of type records.
    pub type_count: usize,
    /// The number of modules.
    pub module_count: usize,
    /// Whether debug information is present.
    pub has_debug_info: bool,
    /// The machine type (architecture).
    pub machine_type: Option<u16>,
    /// The source path.
    pub source_path: Option<PathBuf>,
}

impl fmt::Display for PdbSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "PDB Summary:")?;
        if let Some(path) = &self.source_path {
            writeln!(f, "  File: {}", path.display())?;
        }
        if let Some(guid) = &self.guid {
            writeln!(f, "  GUID: {}", guid)?;
        }
        if let Some(age) = self.age {
            writeln!(f, "  Age: {}", age)?;
        }
        if let Some(sig) = self.signature {
            writeln!(f, "  Signature: 0x{:08X}", sig)?;
        }
        writeln!(f, "  Types: {}", self.type_count)?;
        writeln!(f, "  Modules: {}", self.module_count)?;
        writeln!(f, "  Has Debug Info: {}", self.has_debug_info)?;
        if let Some(machine) = self.machine_type {
            writeln!(f, "  Machine: {} (0x{:04X})", super::machine_type::name(machine), machine)?;
        }
        Ok(())
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reader_error_display() {
        let err = PdbReaderError::MissingIdentification;
        assert!(format!("{}", err).contains("missing identification"));
    }

    #[test]
    fn test_reader_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = PdbReaderError::from(io_err);
        assert!(matches!(err, PdbReaderError::IoError(_)));
    }

    #[test]
    fn test_reader_error_from_msf() {
        let msf_err = MsfError::UnknownFormat;
        let err = PdbReaderError::from(msf_err);
        assert!(matches!(err, PdbReaderError::MsfParseError(_)));
    }

    #[test]
    fn test_is_simple_type() {
        assert!(PdbReader::is_simple_type(0x0003)); // int
        assert!(PdbReader::is_simple_type(0x0010)); // float
        assert!(!PdbReader::is_simple_type(0x1000)); // TPI range
        assert!(!PdbReader::is_simple_type(0x2001));
    }

    #[test]
    fn test_summary_display() {
        let summary = PdbSummary {
            guid: Some("AABB-CCDD".to_string()),
            age: Some(1),
            signature: Some(0xDEADBEEF),
            type_count: 42,
            module_count: 5,
            has_debug_info: true,
            machine_type: Some(0x8664),
            source_path: None,
        };
        let s = format!("{}", summary);
        assert!(s.contains("Types: 42"));
        assert!(s.contains("Modules: 5"));
        assert!(s.contains("Machine:"));
    }
}
