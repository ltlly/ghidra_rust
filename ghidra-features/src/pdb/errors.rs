//! PDB error types.

use std::fmt;
use nom::error::{ErrorKind, ParseError};

/// Errors that can occur during MSF / PDB parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsfError {
    TruncatedInput { expected: usize, actual: usize },
    UnknownFormat,
    InvalidPageSize(u32),
    InvalidStreamNumber(u32),
    OutOfRangePageNumber(u32),
    NomError(String),
}

impl fmt::Display for MsfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MsfError::TruncatedInput { expected, actual } =>
                write!(f, "MSF truncated input: expected {} bytes, got {}", expected, actual),
            MsfError::UnknownFormat => write!(f, "MSF format not detected (unknown magic)"),
            MsfError::InvalidPageSize(size) => write!(f, "MSF invalid page size: 0x{:08X}", size),
            MsfError::InvalidStreamNumber(n) => write!(f, "MSF invalid stream number: {}", n),
            MsfError::OutOfRangePageNumber(n) => write!(f, "MSF out-of-range page number: {}", n),
            MsfError::NomError(s) => write!(f, "MSF parse error: {}", s),
        }
    }
}

impl std::error::Error for MsfError {}

impl<I> ParseError<I> for MsfError {
    fn from_error_kind(_input: I, _kind: ErrorKind) -> Self {
        MsfError::NomError("nom parse error".to_string())
    }
    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self { other }
}

/// Errors for PDB stream parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    Truncated { stream: &'static str, expected: usize, actual: usize },
    BadMagic { stream: &'static str, expected: u32, actual: u32 },
    UnsupportedVersion { stream: &'static str, version: u32 },
    ParseError(String),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamError::Truncated { stream, expected, actual } =>
                write!(f, "{} stream truncated: expected {} bytes, got {}", stream, expected, actual),
            StreamError::BadMagic { stream, expected, actual } =>
                write!(f, "{} stream bad magic: expected 0x{:08X}, got 0x{:08X}", stream, expected, actual),
            StreamError::UnsupportedVersion { stream, version } =>
                write!(f, "{} stream unsupported version: {}", stream, version),
            StreamError::ParseError(s) => write!(f, "stream parse error: {}", s),
        }
    }
}

impl std::error::Error for StreamError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msf_error_truncated_input() {
        let e = MsfError::TruncatedInput { expected: 100, actual: 50 };
        assert!(e.to_string().contains("expected 100"));
        assert!(e.to_string().contains("got 50"));
    }

    #[test]
    fn test_msf_error_unknown_format() {
        let e = MsfError::UnknownFormat;
        assert!(e.to_string().contains("unknown magic"));
    }

    #[test]
    fn test_msf_error_invalid_page_size() {
        let e = MsfError::InvalidPageSize(0x2000);
        assert!(e.to_string().contains("0x00002000"));
    }

    #[test]
    fn test_msf_error_invalid_stream() {
        let e = MsfError::InvalidStreamNumber(42);
        assert!(e.to_string().contains("42"));
    }

    #[test]
    fn test_msf_error_out_of_range_page() {
        let e = MsfError::OutOfRangePageNumber(999);
        assert!(e.to_string().contains("999"));
    }

    #[test]
    fn test_msf_error_nom() {
        let e = MsfError::NomError("bad input".into());
        assert!(e.to_string().contains("bad input"));
    }

    #[test]
    fn test_msf_error_is_std_error() {
        let e = MsfError::UnknownFormat;
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn test_msf_error_parse_error_trait() {
        let e = MsfError::from_error_kind("input", ErrorKind::Tag);
        assert!(matches!(e, MsfError::NomError(_)));
    }

    #[test]
    fn test_msf_error_append() {
        let e = MsfError::InvalidPageSize(1);
        let result = MsfError::append("input", ErrorKind::Tag, e.clone());
        assert_eq!(result, e);
    }

    #[test]
    fn test_stream_error_truncated() {
        let e = StreamError::Truncated { stream: "TPI", expected: 256, actual: 128 };
        assert!(e.to_string().contains("TPI"));
        assert!(e.to_string().contains("256"));
    }

    #[test]
    fn test_stream_error_bad_magic() {
        let e = StreamError::BadMagic { stream: "DBI", expected: 0xFFFFFFFF, actual: 0x12345678 };
        assert!(e.to_string().contains("DBI"));
        assert!(e.to_string().contains("0xFFFFFFFF"));
    }

    #[test]
    fn test_stream_error_unsupported_version() {
        let e = StreamError::UnsupportedVersion { stream: "OMAP", version: 20200402 };
        assert!(e.to_string().contains("20200402"));
    }

    #[test]
    fn test_stream_error_parse_error() {
        let e = StreamError::ParseError("unexpected byte".into());
        assert!(e.to_string().contains("unexpected byte"));
    }

    #[test]
    fn test_stream_error_is_std_error() {
        let e = StreamError::ParseError("test".into());
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn test_stream_error_clone_eq() {
        let e = StreamError::ParseError("test".into());
        let e2 = e.clone();
        assert_eq!(e, e2);
    }
}
