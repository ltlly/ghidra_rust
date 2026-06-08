//! DebugInfoProvider -- base trait for DWARF debug file providers.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.DebugInfoProvider`,
//! `DebugFileProvider`, `DebugStreamProvider`, and `DebugFileStorage`.
//!
//! This module defines the trait hierarchy for objects that can provide
//! DWARF external debug files.  The hierarchy is:
//!
//! - [`DebugInfoProvider`] -- base trait (name, descriptive name, status)
//!   - [`DebugFileProvider`] -- provides debug files as [`std::path::PathBuf`]
//!   - [`DebugStreamProvider`] -- provides debug data as byte streams
//!     - [`DebugFileStorage`] -- can also store streamed debug data

use std::fmt;
use std::io::Read;
use std::path::PathBuf;

use super::debug_info_provider_status::DebugInfoProviderStatus;
use super::external_debug_info::ExternalDebugInfo;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur when interacting with debug info providers.
#[derive(Debug)]
pub enum DebugProviderError {
    /// An I/O error occurred.
    Io(std::io::Error),
    /// The operation was cancelled.
    Cancelled,
    /// A general error with a message.
    Other(String),
}

impl std::fmt::Display for DebugProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DebugProviderError::Io(e) => write!(f, "I/O error: {}", e),
            DebugProviderError::Cancelled => write!(f, "Operation cancelled"),
            DebugProviderError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for DebugProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DebugProviderError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for DebugProviderError {
    fn from(e: std::io::Error) -> Self {
        DebugProviderError::Io(e)
    }
}

/// Result type for debug provider operations.
pub type DebugProviderResult<T> = Result<T, DebugProviderError>;

// ---------------------------------------------------------------------------
// StreamInfo
// ---------------------------------------------------------------------------

/// Information about a stream returned by a [`DebugStreamProvider`].
///
/// Contains the byte reader and the total content length (which may be
/// `-1` if unknown).
pub struct StreamInfo {
    /// The byte stream reader.
    reader: Box<dyn Read>,
    /// The total content length in bytes, or `-1` if unknown.
    content_length: i64,
}

impl fmt::Debug for StreamInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamInfo")
            .field("content_length", &self.content_length)
            .finish()
    }
}

impl StreamInfo {
    /// Creates a new `StreamInfo`.
    pub fn new(reader: Box<dyn Read>, content_length: i64) -> Self {
        Self {
            reader,
            content_length,
        }
    }

    /// Returns the content length, or `-1` if unknown.
    pub fn content_length(&self) -> i64 {
        self.content_length
    }

    /// Consumes the `StreamInfo` and returns the inner reader.
    pub fn into_reader(self) -> Box<dyn Read> {
        self.reader
    }

    /// Returns a mutable reference to the inner reader.
    pub fn reader(&mut self) -> &mut dyn Read {
        &mut *self.reader
    }
}

// ---------------------------------------------------------------------------
// Traits
// ---------------------------------------------------------------------------

/// Base trait for objects that can provide DWARF debug files.
///
/// See [`DebugFileProvider`] and [`DebugStreamProvider`] for the
/// concrete sub-traits.
pub trait DebugInfoProvider: std::fmt::Debug {
    /// Returns the serialized name of this provider instance.
    ///
    /// Typically formatted as `"scheme://data"`, e.g.
    /// `"debuglink:///usr/lib/debug"`.
    fn name(&self) -> &str;

    /// Returns a human-readable description of this provider, suitable
    /// for display in UI lists or prompts.
    fn descriptive_name(&self) -> &str;

    /// Returns the current status of this provider.
    fn status(&self) -> DebugInfoProviderStatus;
}

/// A [`DebugInfoProvider`] that can directly provide debug files on the
/// local filesystem.
pub trait DebugFileProvider: DebugInfoProvider {
    /// Searches for a debug file matching the criteria in `debug_info`.
    ///
    /// Returns the path to the matching file, or `None` if not found.
    fn get_file(&self, debug_info: &ExternalDebugInfo) -> DebugProviderResult<Option<PathBuf>>;
}

/// A [`DebugInfoProvider`] that returns debug objects as a byte stream.
///
/// This is used by HTTP-based providers (e.g. debuginfod servers) that
/// return data over the network rather than as local files.
pub trait DebugStreamProvider: DebugInfoProvider {
    /// Fetches a debug object as a stream.
    ///
    /// Returns a [`StreamInfo`] containing the data, or `None` if not found.
    fn get_stream(&self, debug_info: &ExternalDebugInfo) -> DebugProviderResult<Option<StreamInfo>>;
}

/// A [`DebugFileProvider`] that also supports storing streamed debug data
/// to the local filesystem.
///
/// This is the interface implemented by local cache providers that can
/// store data fetched from a [`DebugStreamProvider`].
pub trait DebugFileStorage: DebugFileProvider {
    /// Stores the contents of `stream` to the local filesystem.
    ///
    /// Returns the path to the stored file.
    fn put_stream(
        &self,
        id: &ExternalDebugInfo,
        stream: StreamInfo,
    ) -> DebugProviderResult<PathBuf>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_info() {
        let data: &[u8] = b"hello world";
        let si = StreamInfo::new(Box::new(data), 11);
        assert_eq!(si.content_length(), 11);
    }

    #[test]
    fn test_debug_provider_error_display() {
        let err = DebugProviderError::Cancelled;
        assert_eq!(err.to_string(), "Operation cancelled");

        let err = DebugProviderError::Other("test".into());
        assert_eq!(err.to_string(), "test");
    }

    #[test]
    fn test_debug_provider_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err: DebugProviderError = io_err.into();
        assert!(err.to_string().contains("not found"));
    }
}
