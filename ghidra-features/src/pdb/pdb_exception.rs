//! PDB exception / error types.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.PdbException`
//! and related Java exception hierarchy.
//!
//! Provides a unified error type for all PDB operations that is distinct
//! from the lower-level `MsfError` / `StreamError` in `errors.rs`.  The
//! `PdbException` type covers the full range of failures: I/O, truncation,
//! format violations, and semantic errors.

use std::fmt;

// =============================================================================
// PdbException
// =============================================================================
/// Unified error type for PDB operations.
///
/// This covers the full range of failures that can occur when reading,
/// parsing, or applying a PDB file. It is designed to be a convenient
/// top-level error type that can represent any failure mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PdbException {
    /// The input data was truncated before a complete record could be read.
    Truncated {
        context: String,
        expected: usize,
        actual: usize,
    },
    /// A magic number or signature did not match the expected value.
    BadMagic {
        context: String,
        expected: u32,
        actual: u32,
    },
    /// An unsupported version was encountered.
    UnsupportedVersion {
        context: String,
        version: u32,
    },
    /// An invalid or out-of-range value was encountered.
    InvalidValue {
        context: String,
        value: String,
    },
    /// A stream index is out of range.
    InvalidStream {
        index: u32,
        num_streams: u32,
    },
    /// A page number is out of range.
    InvalidPage {
        page: u32,
        num_pages: u32,
    },
    /// A type index could not be resolved.
    InvalidTypeIndex {
        index: u32,
    },
    /// A record has an unexpected length.
    BadRecordLength {
        context: String,
        expected: usize,
        actual: usize,
    },
    /// An I/O error occurred.
    IoError(String),
    /// An error originating from the MSF container layer.
    MsfError(String),
    /// An error originating from the stream parsing layer.
    StreamError(String),
    /// A generic parse error with a descriptive message.
    ParseError(String),
    /// The PDB GUID/signature/age does not match expected values.
    IdentificationMismatch {
        expected_guid: Option<String>,
        actual_guid: Option<String>,
        expected_age: Option<String>,
        actual_age: Option<String>,
    },
    /// The PDB file is corrupted or internally inconsistent.
    Corrupted(String),
}

impl PdbException {
    /// Create a truncation error.
    pub fn truncated(context: &str, expected: usize, actual: usize) -> Self {
        PdbException::Truncated {
            context: context.to_string(),
            expected,
            actual,
        }
    }

    /// Create a bad-magic error.
    pub fn bad_magic(context: &str, expected: u32, actual: u32) -> Self {
        PdbException::BadMagic {
            context: context.to_string(),
            expected,
            actual,
        }
    }

    /// Create an unsupported-version error.
    pub fn unsupported_version(context: &str, version: u32) -> Self {
        PdbException::UnsupportedVersion {
            context: context.to_string(),
            version,
        }
    }

    /// Create an invalid-value error.
    pub fn invalid_value(context: &str, value: impl fmt::Display) -> Self {
        PdbException::InvalidValue {
            context: context.to_string(),
            value: value.to_string(),
        }
    }

    /// Create a parse error.
    pub fn parse_error(msg: impl Into<String>) -> Self {
        PdbException::ParseError(msg.into())
    }

    /// Create a corrupted-file error.
    pub fn corrupted(msg: impl Into<String>) -> Self {
        PdbException::Corrupted(msg.into())
    }
}

impl fmt::Display for PdbException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PdbException::Truncated { context, expected, actual } => {
                write!(
                    f,
                    "{}: truncated input (expected {} bytes, got {})",
                    context, expected, actual
                )
            }
            PdbException::BadMagic { context, expected, actual } => {
                write!(
                    f,
                    "{}: bad magic (expected 0x{:08X}, got 0x{:08X})",
                    context, expected, actual
                )
            }
            PdbException::UnsupportedVersion { context, version } => {
                write!(f, "{}: unsupported version {}", context, version)
            }
            PdbException::InvalidValue { context, value } => {
                write!(f, "{}: invalid value '{}'", context, value)
            }
            PdbException::InvalidStream { index, num_streams } => {
                write!(
                    f,
                    "invalid stream index {} (have {} streams)",
                    index, num_streams
                )
            }
            PdbException::InvalidPage { page, num_pages } => {
                write!(
                    f,
                    "invalid page number {} (have {} pages)",
                    page, num_pages
                )
            }
            PdbException::InvalidTypeIndex { index } => {
                write!(f, "invalid type index 0x{:08X}", index)
            }
            PdbException::BadRecordLength { context, expected, actual } => {
                write!(
                    f,
                    "{}: bad record length (expected {}, got {})",
                    context, expected, actual
                )
            }
            PdbException::IoError(msg) => write!(f, "PDB I/O error: {}", msg),
            PdbException::MsfError(msg) => write!(f, "PDB MSF error: {}", msg),
            PdbException::StreamError(msg) => write!(f, "PDB stream error: {}", msg),
            PdbException::ParseError(msg) => write!(f, "PDB parse error: {}", msg),
            PdbException::IdentificationMismatch {
                expected_guid,
                actual_guid,
                expected_age,
                actual_age,
            } => {
                write!(
                    f,
                    "PDB identification mismatch: expected GUID={:?} age={:?}, got GUID={:?} age={:?}",
                    expected_guid, expected_age, actual_guid, actual_age
                )
            }
            PdbException::Corrupted(msg) => write!(f, "PDB corrupted: {}", msg),
        }
    }
}

impl std::error::Error for PdbException {}

// Conversion from std::io::Error
impl From<std::io::Error> for PdbException {
    fn from(e: std::io::Error) -> Self {
        PdbException::IoError(e.to_string())
    }
}

// Conversion from the MSF-level error (errors.rs)
impl From<super::errors::MsfError> for PdbException {
    fn from(e: super::errors::MsfError) -> Self {
        PdbException::MsfError(e.to_string())
    }
}

// Conversion from the MSF-level error (mod.rs inline MsfError)
impl From<super::MsfError> for PdbException {
    fn from(e: super::MsfError) -> Self {
        PdbException::MsfError(e.to_string())
    }
}

// Conversion from the stream-level error (errors.rs)
impl From<super::errors::StreamError> for PdbException {
    fn from(e: super::errors::StreamError) -> Self {
        PdbException::StreamError(e.to_string())
    }
}

// Conversion from the stream-level error (mod.rs inline StreamError)
impl From<super::StreamError> for PdbException {
    fn from(e: super::StreamError) -> Self {
        PdbException::StreamError(e.to_string())
    }
}

// Conversion from the MSF container error
impl From<super::msf_file::MsfParserError> for PdbException {
    fn from(e: super::msf_file::MsfParserError) -> Self {
        PdbException::MsfError(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncated_display() {
        let e = PdbException::truncated("TPI header", 56, 20);
        assert!(e.to_string().contains("TPI header"));
        assert!(e.to_string().contains("56"));
        assert!(e.to_string().contains("20"));
    }

    #[test]
    fn test_bad_magic_display() {
        let e = PdbException::bad_magic("MSF", 0x70000000, 0x12345678);
        assert!(e.to_string().contains("bad magic"));
        assert!(e.to_string().contains("0x70000000"));
    }

    #[test]
    fn test_unsupported_version_display() {
        let e = PdbException::unsupported_version("TPI", 20200402);
        assert!(e.to_string().contains("unsupported version"));
        assert!(e.to_string().contains("20200402"));
    }

    #[test]
    fn test_invalid_value_display() {
        let e = PdbException::invalid_value("page size", format!("0x{:04X}", 0x1234));
        assert!(e.to_string().contains("page size"));
        assert!(e.to_string().contains("0x1234"));
    }

    #[test]
    fn test_invalid_stream_display() {
        let e = PdbException::InvalidStream { index: 42, num_streams: 10 };
        assert!(e.to_string().contains("42"));
        assert!(e.to_string().contains("10"));
    }

    #[test]
    fn test_invalid_page_display() {
        let e = PdbException::InvalidPage { page: 999, num_pages: 100 };
        assert!(e.to_string().contains("999"));
    }

    #[test]
    fn test_invalid_type_index_display() {
        let e = PdbException::InvalidTypeIndex { index: 0xDEADBEEF };
        assert!(e.to_string().contains("DEADBEEF"));
    }

    #[test]
    fn test_bad_record_length_display() {
        let e = PdbException::BadRecordLength {
            context: "LF_CLASS".to_string(),
            expected: 16,
            actual: 8,
        };
        assert!(e.to_string().contains("LF_CLASS"));
        assert!(e.to_string().contains("16"));
        assert!(e.to_string().contains("8"));
    }

    #[test]
    fn test_io_error_display() {
        let e = PdbException::IoError("file not found".to_string());
        assert!(e.to_string().contains("I/O error"));
        assert!(e.to_string().contains("file not found"));
    }

    #[test]
    fn test_msf_error_display() {
        let e = PdbException::MsfError("bad page".to_string());
        assert!(e.to_string().contains("MSF error"));
    }

    #[test]
    fn test_stream_error_display() {
        let e = PdbException::StreamError("bad header".to_string());
        assert!(e.to_string().contains("stream error"));
    }

    #[test]
    fn test_parse_error_display() {
        let e = PdbException::parse_error("unexpected byte");
        assert!(e.to_string().contains("parse error"));
        assert!(e.to_string().contains("unexpected byte"));
    }

    #[test]
    fn test_identification_mismatch_display() {
        let e = PdbException::IdentificationMismatch {
            expected_guid: Some("AABB".to_string()),
            actual_guid: Some("CCDD".to_string()),
            expected_age: Some("1".to_string()),
            actual_age: Some("2".to_string()),
        };
        assert!(e.to_string().contains("AABB"));
        assert!(e.to_string().contains("CCDD"));
    }

    #[test]
    fn test_corrupted_display() {
        let e = PdbException::corrupted("inconsistent directory");
        assert!(e.to_string().contains("corrupted"));
        assert!(e.to_string().contains("inconsistent directory"));
    }

    #[test]
    fn test_is_std_error() {
        let e = PdbException::parse_error("test");
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn test_clone_eq() {
        let e = PdbException::truncated("test", 10, 5);
        let e2 = e.clone();
        assert_eq!(e, e2);
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let e = PdbException::from(io_err);
        assert!(matches!(e, PdbException::IoError(_)));
    }

    #[test]
    fn test_from_msf_error() {
        let msf_err = super::super::errors::MsfError::UnknownFormat;
        let e = PdbException::from(msf_err);
        assert!(matches!(e, PdbException::MsfError(_)));
    }

    #[test]
    fn test_from_stream_error() {
        let stream_err = super::super::errors::StreamError::ParseError("bad".to_string());
        let e = PdbException::from(stream_err);
        assert!(matches!(e, PdbException::StreamError(_)));
    }
}
