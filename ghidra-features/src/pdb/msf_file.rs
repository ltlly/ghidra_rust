//! MSF File -- dedicated module for the Multi-Stream Format container.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb.PdbParserMs` and
//! related MSF container classes.
//!
//! The MSF (Multi-Stream Format) is the container format used by PDB files.
//! It divides the file into fixed-size pages and provides a directory that
//! maps virtual stream numbers to sequences of pages. This module provides
//! a higher-level API on top of the raw parsing functions in the parent module.
//!
//! # Architecture
//!
//! The MSF file consists of:
//! - A **header** (magic bytes, page size, number of pages, free page map).
//! - A **directory** mapping stream indices to page lists.
//! - A set of **pages** (blocks) that contain the actual stream data.
//!
//! Standard PDB stream assignments:
//! - Stream 0: MSF directory itself
//! - Stream 1: PDB Info (GUID, age, named streams)
//! - Stream 2: TPI (Type Information)
//! - Stream 3: DBI (Debug Information)
//! - Stream 4: IPI (Item Information)

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

use super::{MsfFile, MsfDirectory, MsfStreamInfo, MsfError, parse_msf};

// =============================================================================
// Known Stream Indices
// =============================================================================

/// Well-known PDB stream numbers.
pub mod streams {
    /// The MSF directory stream.
    pub const DIRECTORY: u32 = 0;
    /// The PDB Info stream (version, GUID, age, named streams).
    pub const PDB_INFO: u32 = 1;
    /// The TPI (Type Information) stream.
    pub const TPI: u32 = 2;
    /// The DBI (Debug Information) stream.
    pub const DBI: u32 = 3;
    /// The IPI (Item Information) stream.
    pub const IPI: u32 = 4;
    /// The Global Symbol Index stream (GSI).
    /// The actual stream number is read from the DBI header.
    pub const GSI_HINT: u32 = 5;
    /// The Public Symbol Index stream (PSI).
    /// The actual stream number is read from the DBI header.
    pub const PSI_HINT: u32 = 6;
}

// =============================================================================
// MsfStreamHandle -- a typed handle to a stream within an MsfFile
// =============================================================================

/// A typed handle to a specific stream within an MSF file.
///
/// Provides convenience methods for accessing stream data without
/// needing to remember the raw stream index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MsfStreamHandle {
    /// The stream index within the MSF directory.
    index: u32,
}

impl MsfStreamHandle {
    /// Create a handle from a raw stream index.
    pub fn new(index: u32) -> Self {
        Self { index }
    }

    /// Get the stream index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Create a handle to the PDB Info stream.
    pub fn pdb_info() -> Self {
        Self { index: streams::PDB_INFO }
    }

    /// Create a handle to the TPI stream.
    pub fn tpi() -> Self {
        Self { index: streams::TPI }
    }

    /// Create a handle to the DBI stream.
    pub fn dbi() -> Self {
        Self { index: streams::DBI }
    }

    /// Create a handle to the IPI stream.
    pub fn ipi() -> Self {
        Self { index: streams::IPI }
    }

    /// Check if this handle refers to a well-known stream.
    pub fn is_known_stream(&self) -> bool {
        matches!(self.index, 0..=4)
    }

    /// Get the name of this stream, if it is a well-known stream.
    pub fn name(&self) -> Option<&'static str> {
        match self.index {
            streams::DIRECTORY => Some("MSF Directory"),
            streams::PDB_INFO => Some("PDB Info"),
            streams::TPI => Some("TPI"),
            streams::DBI => Some("DBI"),
            streams::IPI => Some("IPI"),
            _ => None,
        }
    }
}

impl fmt::Display for MsfStreamHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.name() {
            write!(f, "Stream {} ({})", self.index, name)
        } else {
            write!(f, "Stream {}", self.index)
        }
    }
}

// =============================================================================
// MsfFileInfo -- detailed information about an MSF file
// =============================================================================

/// Detailed information about an MSF file's structure.
///
/// Provides metadata about the MSF container without needing to hold
/// all the page data in memory.
#[derive(Debug, Clone)]
pub struct MsfFileInfo {
    /// The MSF format version (200 or 700).
    pub version: MsfVersion,
    /// The page size in bytes.
    pub page_size: u32,
    /// The total number of pages.
    pub num_pages: u32,
    /// The total file size (num_pages * page_size).
    pub total_size: u64,
    /// The number of streams in the directory.
    pub num_streams: u32,
    /// Information about each stream.
    pub streams: Vec<MsfStreamSummary>,
}

/// The MSF format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsfVersion {
    /// MSF version 2.00 (older format, 16-bit page numbers).
    V200,
    /// MSF version 7.00 (current format, 32-bit page numbers).
    V700,
}

impl fmt::Display for MsfVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MsfVersion::V200 => write!(f, "2.00"),
            MsfVersion::V700 => write!(f, "7.00"),
        }
    }
}

/// Summary information about a single stream within the MSF.
#[derive(Debug, Clone)]
pub struct MsfStreamSummary {
    /// The stream index.
    pub index: u32,
    /// The stream size in bytes.
    pub size: u32,
    /// The number of pages used by this stream.
    pub num_pages: u32,
    /// The well-known name of this stream, if applicable.
    pub name: Option<&'static str>,
}

impl fmt::Display for MsfStreamSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.name {
            write!(
                f,
                "Stream {}: {} ({} bytes, {} pages)",
                self.index, name, self.size, self.num_pages
            )
        } else {
            write!(
                f,
                "Stream {}: ({} bytes, {} pages)",
                self.index, self.size, self.num_pages
            )
        }
    }
}

// =============================================================================
// MsfFileExt -- extension methods for MsfFile
// =============================================================================

/// Extension methods for the [`MsfFile`] type.
///
/// These methods provide a higher-level API on top of the raw MsfFile
/// parsed by the parent module's `parse_msf` function.
pub trait MsfFileExt {
    /// Get detailed information about the MSF file structure.
    fn info(&self) -> MsfFileInfo;

    /// Read a stream by handle.
    fn read_stream_by_handle(&self, handle: MsfStreamHandle) -> Option<Vec<u8>>;

    /// Read the PDB Info stream.
    fn read_pdb_info_stream(&self) -> Option<Vec<u8>>;

    /// Read the TPI stream.
    fn read_tpi_stream(&self) -> Option<Vec<u8>>;

    /// Read the DBI stream.
    fn read_dbi_stream(&self) -> Option<Vec<u8>>;

    /// Read the IPI stream.
    fn read_ipi_stream(&self) -> Option<Vec<u8>>;

    /// Get a summary of all streams.
    fn stream_summaries(&self) -> Vec<MsfStreamSummary>;

    /// Find a named stream by its name.
    ///
    /// Searches the PDB Info stream's named stream table for a stream
    /// with the given name. Returns the stream index if found.
    fn find_named_stream_index(&self, name: &str) -> Option<u32>;

    /// Count the total number of non-empty streams.
    fn non_empty_stream_count(&self) -> usize;

    /// Check if the MSF file appears to be valid.
    fn validate(&self) -> Result<(), MsfValidationError>;
}

/// Errors returned by MSF validation.
#[derive(Debug, Clone)]
pub enum MsfValidationError {
    /// The MSF has no streams.
    NoStreams,
    /// A stream index references a page that is out of range.
    InvalidPageReference { stream: u32, page: u32 },
    /// The MSF has zero page size.
    ZeroPageSize,
    /// A stream has an inconsistent size.
    StreamSizeMismatch { stream: u32, expected: u32, actual: u32 },
}

impl fmt::Display for MsfValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MsfValidationError::NoStreams => write!(f, "MSF has no streams"),
            MsfValidationError::InvalidPageReference { stream, page } => {
                write!(
                    f,
                    "Stream {} references out-of-range page {}",
                    stream, page
                )
            }
            MsfValidationError::ZeroPageSize => write!(f, "MSF has zero page size"),
            MsfValidationError::StreamSizeMismatch {
                stream, expected, actual,
            } => {
                write!(
                    f,
                    "Stream {} size mismatch: expected {}, got {}",
                    stream, expected, actual
                )
            }
        }
    }
}

impl std::error::Error for MsfValidationError {}

impl MsfFileExt for MsfFile {
    fn info(&self) -> MsfFileInfo {
        let page_size = self.block_size;
        let num_pages = self.blocks.len() as u32;
        let total_size = num_pages as u64 * page_size as u64;
        let num_streams = self.directory.streams.len() as u32;

        // Detect version based on block count / page size heuristics.
        // V700 is the modern standard; V200 is legacy.
        let version = if page_size >= 0x1000 {
            MsfVersion::V700
        } else {
            MsfVersion::V200
        };

        let streams = self.stream_summaries();

        MsfFileInfo {
            version,
            page_size,
            num_pages,
            total_size,
            num_streams,
            streams,
        }
    }

    fn read_stream_by_handle(&self, handle: MsfStreamHandle) -> Option<Vec<u8>> {
        self.read_stream(handle.index())
    }

    fn read_pdb_info_stream(&self) -> Option<Vec<u8>> {
        self.read_stream(streams::PDB_INFO)
    }

    fn read_tpi_stream(&self) -> Option<Vec<u8>> {
        self.read_stream(streams::TPI)
    }

    fn read_dbi_stream(&self) -> Option<Vec<u8>> {
        self.read_stream(streams::DBI)
    }

    fn read_ipi_stream(&self) -> Option<Vec<u8>> {
        self.read_stream(streams::IPI)
    }

    fn stream_summaries(&self) -> Vec<MsfStreamSummary> {
        self.directory
            .streams
            .iter()
            .enumerate()
            .map(|(i, info)| {
                let handle = MsfStreamHandle::new(i as u32);
                let num_pages = if info.size == 0 || info.size == 0xFFFFFFFF {
                    0
                } else {
                    ((info.size + self.block_size - 1) / self.block_size) as usize as u32
                };
                MsfStreamSummary {
                    index: i as u32,
                    size: info.size,
                    num_pages,
                    name: handle.name(),
                }
            })
            .collect()
    }

    fn find_named_stream_index(&self, name: &str) -> Option<u32> {
        // Read the PDB info stream and parse named streams
        let info_data = self.read_pdb_info_stream()?;
        if info_data.len() < 28 {
            return None;
        }
        let info = super::parse_pdb_info_stream(&info_data).ok()?;
        info.named_streams
            .iter()
            .find(|ns| ns.name == name)
            .map(|ns| ns.stream_index)
    }

    fn non_empty_stream_count(&self) -> usize {
        self.directory
            .streams
            .iter()
            .filter(|s| s.size != 0 && s.size != 0xFFFFFFFF)
            .count()
    }

    fn validate(&self) -> Result<(), MsfValidationError> {
        if self.directory.streams.is_empty() {
            return Err(MsfValidationError::NoStreams);
        }
        if self.block_size == 0 {
            return Err(MsfValidationError::ZeroPageSize);
        }

        let max_page = self.blocks.len() as u32;
        for (i, stream) in self.directory.streams.iter().enumerate() {
            for &page in &stream.block_indices {
                if page >= max_page {
                    return Err(MsfValidationError::InvalidPageReference {
                        stream: i as u32,
                        page,
                    });
                }
            }
        }

        Ok(())
    }
}

// =============================================================================
// MsfParser -- convenient parsing API
// =============================================================================

/// A high-level MSF parser.
///
/// Wraps the raw `parse_msf` function with validation and information
/// extraction.
pub struct MsfParser;

impl MsfParser {
    /// Parse an MSF file from raw bytes.
    ///
    /// Validates the parsed result and returns the MsfFile.
    pub fn parse(data: &[u8]) -> Result<MsfFile, MsfParserError> {
        let msf = parse_msf(data).map_err(MsfParserError::MsfError)?;
        msf.validate().map_err(MsfParserError::ValidationError)?;
        Ok(msf)
    }

    /// Parse an MSF file from disk.
    pub fn open(path: impl AsRef<Path>) -> Result<MsfFile, MsfParserError> {
        let data = std::fs::read(path.as_ref()).map_err(|e| {
            MsfParserError::IoError(e.to_string())
        })?;
        Self::parse(&data)
    }

    /// Get file info from raw bytes without retaining the parsed MsfFile.
    pub fn peek_info(data: &[u8]) -> Result<MsfFileInfo, MsfParserError> {
        let msf = Self::parse(data)?;
        Ok(msf.info())
    }
}

/// Errors from the MsfParser.
#[derive(Debug, Clone)]
pub enum MsfParserError {
    /// Low-level MSF parsing error.
    MsfError(MsfError),
    /// Validation error after parsing.
    ValidationError(MsfValidationError),
    /// I/O error reading from disk.
    IoError(String),
}

impl fmt::Display for MsfParserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MsfParserError::MsfError(e) => write!(f, "MSF parse error: {}", e),
            MsfParserError::ValidationError(e) => write!(f, "MSF validation error: {}", e),
            MsfParserError::IoError(msg) => write!(f, "MSF I/O error: {}", msg),
        }
    }
}

impl std::error::Error for MsfParserError {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_handle_known() {
        let h = MsfStreamHandle::pdb_info();
        assert_eq!(h.index(), streams::PDB_INFO);
        assert!(h.is_known_stream());
        assert_eq!(h.name(), Some("PDB Info"));
        assert_eq!(format!("{}", h), "Stream 1 (PDB Info)");
    }

    #[test]
    fn test_stream_handle_unknown() {
        let h = MsfStreamHandle::new(99);
        assert_eq!(h.index(), 99);
        assert!(!h.is_known_stream());
        assert_eq!(h.name(), None);
        assert_eq!(format!("{}", h), "Stream 99");
    }

    #[test]
    fn test_stream_handle_all_known() {
        assert_eq!(MsfStreamHandle::new(0).name(), Some("MSF Directory"));
        assert_eq!(MsfStreamHandle::new(1).name(), Some("PDB Info"));
        assert_eq!(MsfStreamHandle::new(2).name(), Some("TPI"));
        assert_eq!(MsfStreamHandle::new(3).name(), Some("DBI"));
        assert_eq!(MsfStreamHandle::new(4).name(), Some("IPI"));
    }

    #[test]
    fn test_msf_version_display() {
        assert_eq!(format!("{}", MsfVersion::V200), "2.00");
        assert_eq!(format!("{}", MsfVersion::V700), "7.00");
    }

    #[test]
    fn test_validation_error_display() {
        let err = MsfValidationError::NoStreams;
        assert!(format!("{}", err).contains("no streams"));

        let err2 = MsfValidationError::InvalidPageReference { stream: 3, page: 99 };
        assert!(format!("{}", err2).contains("Stream 3"));
        assert!(format!("{}", err2).contains("page 99"));

        let err3 = MsfValidationError::ZeroPageSize;
        assert!(format!("{}", err3).contains("zero page size"));

        let err4 = MsfValidationError::StreamSizeMismatch {
            stream: 2,
            expected: 100,
            actual: 50,
        };
        assert!(format!("{}", err4).contains("mismatch"));
    }

    #[test]
    fn test_parser_error_display() {
        let err = MsfParserError::MsfError(MsfError::UnknownFormat);
        assert!(format!("{}", err).contains("MSF parse error"));

        let err2 = MsfParserError::IoError("test".to_string());
        assert!(format!("{}", err2).contains("I/O error"));
    }

    #[test]
    fn test_stream_summary_display() {
        let summary = MsfStreamSummary {
            index: 2,
            size: 4096,
            num_pages: 1,
            name: Some("TPI"),
        };
        let s = format!("{}", summary);
        assert!(s.contains("Stream 2"));
        assert!(s.contains("TPI"));
        assert!(s.contains("4096 bytes"));

        let summary2 = MsfStreamSummary {
            index: 10,
            size: 100,
            num_pages: 1,
            name: None,
        };
        let s2 = format!("{}", summary2);
        assert!(s2.contains("Stream 10"));
        assert!(s2.contains("100 bytes"));
    }

    #[test]
    fn test_msf_file_info_display() {
        let info = MsfFileInfo {
            version: MsfVersion::V700,
            page_size: 4096,
            num_pages: 10,
            total_size: 40960,
            num_streams: 5,
            streams: vec![],
        };
        // MsfFileInfo doesn't impl Display directly, but we can check its fields
        assert_eq!(info.version, MsfVersion::V700);
        assert_eq!(info.page_size, 4096);
        assert_eq!(info.num_streams, 5);
    }
}
