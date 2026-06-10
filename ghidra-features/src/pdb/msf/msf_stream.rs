//! MSF Stream abstraction.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.msf.MsfStream`
//! and related stream handling classes.
//!
//! An MSF stream is a virtual byte sequence stored across one or more
//! fixed-size pages in the MSF container. This module provides a
//! lightweight wrapper that owns its data and provides convenient
//! access methods.

use std::fmt;

use super::super::pdb_byte_reader::PdbByteReader;

// =============================================================================
// Well-known stream indices
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
    pub const GSI_HINT: u32 = 5;
    /// The Public Symbol Index stream (PSI).
    pub const PSI_HINT: u32 = 6;
}

// =============================================================================
// MsfStream
// =============================================================================
/// An MSF stream -- a virtual byte sequence reconstructed from pages.
///
/// Holds the raw data of a single PDB stream. Provides methods for
/// creating a byte reader, checking emptiness, and accessing the data.
#[derive(Clone, PartialEq, Eq)]
pub struct MsfStream {
    /// The stream index within the MSF directory.
    index: u32,
    /// The reconstructed stream data.
    data: Vec<u8>,
}

impl MsfStream {
    /// Create a new stream with the given index and data.
    pub fn new(index: u32, data: Vec<u8>) -> Self {
        Self { index, data }
    }

    /// Get the stream index.
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Get the size of the stream data in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Whether the stream is empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get a reference to the raw stream data.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consume the stream and return the raw data.
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Create a [`PdbByteReader`] over this stream's data.
    pub fn reader(&self) -> PdbByteReader<'_> {
        PdbByteReader::new(&self.data)
    }

    /// Whether this is a well-known stream index (0..=4).
    pub fn is_known(&self) -> bool {
        self.index <= 4
    }

    /// Get the well-known name of this stream, if applicable.
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

impl fmt::Debug for MsfStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MsfStream")
            .field("index", &self.index)
            .field("name", &self.name())
            .field("len", &self.data.len())
            .finish()
    }
}

impl fmt::Display for MsfStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.name() {
            write!(f, "Stream {} ({}) - {} bytes", self.index, name, self.data.len())
        } else {
            write!(f, "Stream {} - {} bytes", self.index, self.data.len())
        }
    }
}

// =============================================================================
// MsfStreamInfo -- metadata about a stream before data is read
// =============================================================================
/// Metadata about a stream within the MSF directory.
///
/// This is the lightweight, pre-read form of stream information. The
/// actual data is only read on demand via `MsfContainer::read_stream()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsfStreamInfo {
    /// The stream index.
    pub index: u32,
    /// The size of the stream in bytes.
    pub size: u32,
    /// The number of pages used by this stream.
    pub num_pages: u32,
}

impl MsfStreamInfo {
    /// Whether this stream is empty or invalid.
    pub fn is_empty(&self) -> bool {
        self.size == 0 || self.size == 0xFFFFFFFF
    }

    /// Whether this is a well-known stream.
    pub fn is_known(&self) -> bool {
        self.index <= 4
    }

    /// Get the well-known name, if applicable.
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

impl fmt::Display for MsfStreamInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.name() {
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
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stream_new() {
        let s = MsfStream::new(1, vec![1, 2, 3]);
        assert_eq!(s.index(), 1);
        assert_eq!(s.len(), 3);
        assert!(!s.is_empty());
        assert_eq!(s.data(), &[1, 2, 3]);
    }

    #[test]
    fn test_stream_empty() {
        let s = MsfStream::new(0, vec![]);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn test_stream_name() {
        assert_eq!(MsfStream::new(0, vec![]).name(), Some("MSF Directory"));
        assert_eq!(MsfStream::new(1, vec![]).name(), Some("PDB Info"));
        assert_eq!(MsfStream::new(2, vec![]).name(), Some("TPI"));
        assert_eq!(MsfStream::new(3, vec![]).name(), Some("DBI"));
        assert_eq!(MsfStream::new(4, vec![]).name(), Some("IPI"));
        assert_eq!(MsfStream::new(5, vec![]).name(), None);
        assert_eq!(MsfStream::new(99, vec![]).name(), None);
    }

    #[test]
    fn test_stream_is_known() {
        assert!(MsfStream::new(0, vec![]).is_known());
        assert!(MsfStream::new(4, vec![]).is_known());
        assert!(!MsfStream::new(5, vec![]).is_known());
    }

    #[test]
    fn test_stream_reader() {
        let s = MsfStream::new(1, vec![0x78, 0x56, 0x34, 0x12]);
        let mut reader = s.reader();
        assert_eq!(reader.read_u32().unwrap(), 0x12345678);
    }

    #[test]
    fn test_stream_into_data() {
        let s = MsfStream::new(1, vec![10, 20, 30]);
        let data = s.into_data();
        assert_eq!(data, vec![10, 20, 30]);
    }

    #[test]
    fn test_stream_display() {
        let s = MsfStream::new(2, vec![0u8; 4096]);
        let display = format!("{}", s);
        assert!(display.contains("Stream 2"));
        assert!(display.contains("TPI"));
        assert!(display.contains("4096 bytes"));

        let s2 = MsfStream::new(99, vec![0u8; 100]);
        let display2 = format!("{}", s2);
        assert!(display2.contains("Stream 99"));
        assert!(display2.contains("100 bytes"));
    }

    #[test]
    fn test_stream_debug() {
        let s = MsfStream::new(1, vec![1, 2]);
        let debug = format!("{:?}", s);
        assert!(debug.contains("MsfStream"));
        assert!(debug.contains("PDB Info"));
    }

    #[test]
    fn test_stream_clone_eq() {
        let s1 = MsfStream::new(1, vec![1, 2, 3]);
        let s2 = s1.clone();
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_stream_info_is_empty() {
        let info = MsfStreamInfo { index: 0, size: 0, num_pages: 0 };
        assert!(info.is_empty());

        let info = MsfStreamInfo { index: 0, size: 0xFFFFFFFF, num_pages: 0 };
        assert!(info.is_empty());

        let info = MsfStreamInfo { index: 0, size: 100, num_pages: 1 };
        assert!(!info.is_empty());
    }

    #[test]
    fn test_stream_info_name() {
        assert_eq!(
            MsfStreamInfo { index: 0, size: 0, num_pages: 0 }.name(),
            Some("MSF Directory")
        );
        assert_eq!(
            MsfStreamInfo { index: 1, size: 100, num_pages: 1 }.name(),
            Some("PDB Info")
        );
        assert_eq!(
            MsfStreamInfo { index: 10, size: 100, num_pages: 1 }.name(),
            None
        );
    }

    #[test]
    fn test_stream_info_display() {
        let info = MsfStreamInfo { index: 2, size: 4096, num_pages: 1 };
        let s = format!("{}", info);
        assert!(s.contains("TPI"));
        assert!(s.contains("4096 bytes"));

        let info2 = MsfStreamInfo { index: 10, size: 100, num_pages: 1 };
        let s2 = format!("{}", info2);
        assert!(s2.contains("Stream 10"));
    }

    #[test]
    fn test_stream_info_is_known() {
        assert!(MsfStreamInfo { index: 0, size: 0, num_pages: 0 }.is_known());
        assert!(MsfStreamInfo { index: 4, size: 0, num_pages: 0 }.is_known());
        assert!(!MsfStreamInfo { index: 5, size: 0, num_pages: 0 }.is_known());
    }

    #[test]
    fn test_streams_constants() {
        assert_eq!(streams::DIRECTORY, 0);
        assert_eq!(streams::PDB_INFO, 1);
        assert_eq!(streams::TPI, 2);
        assert_eq!(streams::DBI, 3);
        assert_eq!(streams::IPI, 4);
        assert_eq!(streams::GSI_HINT, 5);
        assert_eq!(streams::PSI_HINT, 6);
    }
}
