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
