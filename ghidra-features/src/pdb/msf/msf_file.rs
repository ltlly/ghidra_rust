//! MSF File format -- low-level container types.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb.PdbParserMs` and
//! the MSF container classes from `ghidra.app.util.bin.format.pdb2.pdbreader.msf`.
//!
//! The MSF (Multi-Stream Format) is the container format used by PDB files.
//! It divides the file into fixed-size pages and provides a directory that
//! maps virtual stream numbers to sequences of pages.
//!
//! This module defines the low-level MSF container types: header, page
//! table, directory, and the `MsfContainer` struct which owns all parsed
//! MSF data and provides stream-reading methods.
//!
//! Standard PDB stream assignments:
//! - Stream 0: MSF directory itself
//! - Stream 1: PDB Info (GUID, age, named streams)
//! - Stream 2: TPI (Type Information)
//! - Stream 3: DBI (Debug Information)
//! - Stream 4: IPI (Item Information)

use std::fmt;

use super::super::pdb_byte_reader::{read_u16_le, read_u32_le, is_power_of_two};
use super::super::pdb_exception::PdbException;
use super::msf_stream::MsfStream;

// =============================================================================
// MSF Magic Constants
// =============================================================================

/// Magic bytes for MSF version 2.00 (older format, 16-bit page numbers).
pub const MSF_V200_MAGIC: &[u8] = b"Microsoft C/C++ program database 2.00\r\n\x1aJG";
/// Magic bytes for MSF version 7.00 (current format, 32-bit page numbers).
pub const MSF_V700_MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS";

// =============================================================================
// MsfVersion
// =============================================================================

/// The MSF format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsfVersion {
    /// MSF version 2.00 (older format, 16-bit page numbers).
    V200,
    /// MSF version 7.00 (current format, 32-bit page numbers).
    V700,
}

impl MsfVersion {
    /// Detect the version from the magic bytes at the start of the file.
    pub fn detect(data: &[u8]) -> Result<Self, PdbException> {
        if data.len() < MSF_V200_MAGIC.len() {
            return Err(PdbException::truncated("MSF magic", MSF_V200_MAGIC.len(), data.len()));
        }
        if &data[..MSF_V700_MAGIC.len()] == MSF_V700_MAGIC {
            Ok(MsfVersion::V700)
        } else if &data[..MSF_V200_MAGIC.len()] == MSF_V200_MAGIC {
            Ok(MsfVersion::V200)
        } else {
            Err(PdbException::bad_magic("MSF", 0, 0))
        }
    }
}

impl fmt::Display for MsfVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MsfVersion::V200 => write!(f, "2.00"),
            MsfVersion::V700 => write!(f, "7.00"),
        }
    }
}

// =============================================================================
// MsfHeader
// =============================================================================

/// Parsed MSF file header.
#[derive(Debug, Clone)]
pub struct MsfHeader {
    /// The MSF format version.
    pub version: MsfVersion,
    /// The page size in bytes (must be a power of two, 0x200..0x8000).
    pub page_size: u32,
    /// The total number of pages in the file.
    pub num_pages: u32,
    /// The page number of the free page map.
    pub free_page_map_page: u32,
    /// The size of page numbers in bytes (2 for V200, 4 for V700).
    pub page_number_size: u32,
    /// The byte offset of the directory stream.
    pub directory_offset: usize,
    /// The length of the directory stream in bytes.
    pub directory_length: u32,
}

impl MsfHeader {
    /// Parse an MSF header from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, PdbException> {
        let version = MsfVersion::detect(data)?;
        match version {
            MsfVersion::V200 => Self::parse_v200(data),
            MsfVersion::V700 => Self::parse_v700(data),
        }
    }

    fn parse_v200(data: &[u8]) -> Result<Self, PdbException> {
        let page_size_offset = MSF_V200_MAGIC.len() + 2;
        if data.len() < page_size_offset + 4 {
            return Err(PdbException::truncated("MSF v200 header", page_size_offset + 4, data.len()));
        }
        let page_size = read_u32_le(data, page_size_offset);
        if !is_power_of_two(page_size) || page_size < 0x0200 || page_size > 0x8000 {
            return Err(PdbException::invalid_value("MSF page size", format!("0x{:08X}", page_size)));
        }
        let fp_offset = page_size_offset + 4;
        let np_offset = fp_offset + 2;
        if data.len() < np_offset + 2 {
            return Err(PdbException::truncated("MSF v200 header", np_offset + 2, data.len()));
        }
        let free_page_map_page = read_u16_le(data, fp_offset) as u32;
        let num_pages = read_u16_le(data, np_offset) as u32;
        let dir_info_offset = np_offset + 2;
        let (dir_offset, dir_len) = parse_dir_stream_info(data, dir_info_offset, 2)?;

        Ok(MsfHeader {
            version: MsfVersion::V200,
            page_size,
            num_pages,
            free_page_map_page,
            page_number_size: 2,
            directory_offset: dir_offset,
            directory_length: dir_len,
        })
    }

    fn parse_v700(data: &[u8]) -> Result<Self, PdbException> {
        let page_size_offset = MSF_V700_MAGIC.len() + 3;
        if data.len() < page_size_offset + 4 {
            return Err(PdbException::truncated("MSF v700 header", page_size_offset + 4, data.len()));
        }
        let page_size = read_u32_le(data, page_size_offset);
        if !is_power_of_two(page_size) || page_size < 0x0200 || page_size > 0x8000 {
            return Err(PdbException::invalid_value("MSF page size", format!("0x{:08X}", page_size)));
        }
        let fp_offset = page_size_offset + 4;
        let np_offset = fp_offset + 4;
        let ndb_offset = np_offset + 4;
        if data.len() < ndb_offset + 4 {
            return Err(PdbException::truncated("MSF v700 header", ndb_offset + 4, data.len()));
        }
        let free_page_map_page = read_u32_le(data, fp_offset);
        let num_pages = read_u32_le(data, np_offset);
        let _num_directory_bytes = read_u32_le(data, ndb_offset);
        let dir_info_offset = ndb_offset + 4;
        let (dir_offset, dir_len) = parse_dir_stream_info(data, dir_info_offset, 4)?;

        Ok(MsfHeader {
            version: MsfVersion::V700,
            page_size,
            num_pages,
            free_page_map_page,
            page_number_size: 4,
            directory_offset: dir_offset,
            directory_length: dir_len,
        })
    }
}

fn parse_dir_stream_info(data: &[u8], offset: usize, page_number_size: u32) -> Result<(usize, u32), PdbException> {
    if offset + 8 > data.len() {
        return Err(PdbException::truncated("MSF directory info", offset + 8, data.len()));
    }
    let stream_length = read_u32_le(data, offset);
    let _map_address = read_u32_le(data, offset + 4);
    if stream_length == 0 {
        return Ok((0, 0));
    }
    let page_size = 0x1000u32;
    let num_dir_pages = (stream_length + page_size - 1) / page_size;
    let mut page_numbers = Vec::with_capacity(num_dir_pages as usize);
    let pn_offset = offset + 8;
    for i in 0..num_dir_pages as usize {
        let cur = pn_offset + i * page_number_size as usize;
        if page_number_size == 2 {
            if cur + 2 > data.len() { break; }
            let pn = read_u16_le(data, cur) as u32;
            if pn == 0 { break; }
            page_numbers.push(pn);
        } else {
            if cur + 4 > data.len() { break; }
            let pn = read_u32_le(data, cur);
            if pn == 0 { break; }
            page_numbers.push(pn);
        }
    }
    let dir_byte_offset = if !page_numbers.is_empty() {
        page_numbers[0] as usize * 0x1000
    } else {
        0
    };
    Ok((dir_byte_offset, stream_length))
}

// =============================================================================
// MsfDirectoryEntry
// =============================================================================

/// Information about a single stream within the MSF directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsfDirectoryEntry {
    /// The size of the stream in bytes.
    pub size: u32,
    /// The page numbers that contain the stream data.
    pub pages: Vec<u32>,
}

// =============================================================================
// MsfContainer
// =============================================================================

/// A fully parsed MSF container.
///
/// Owns all page data and the directory. Provides methods for reading
/// stream data by reconstructing it from its constituent pages.
#[derive(Debug, Clone)]
pub struct MsfContainer {
    /// The parsed header.
    pub header: MsfHeader,
    /// All page data. `pages[i]` is the i-th page.
    pub pages: Vec<Vec<u8>>,
    /// The directory listing all streams.
    pub directory: Vec<MsfDirectoryEntry>,
}

impl MsfContainer {
    /// Parse an MSF container from raw bytes.
    pub fn parse(data: &[u8]) -> Result<Self, PdbException> {
        let header = MsfHeader::parse(data)?;

        // Read all pages
        let page_size = header.page_size as usize;
        let mut pages = Vec::with_capacity(header.num_pages as usize);
        for i in 0..header.num_pages as usize {
            let start = i * page_size;
            let end = start + page_size;
            if end > data.len() {
                let mut page = vec![0u8; page_size];
                let available = data.len().saturating_sub(start);
                page[..available].copy_from_slice(&data[start..data.len()]);
                pages.push(page);
                break;
            }
            pages.push(data[start..end].to_vec());
        }

        // Parse directory
        let directory = Self::parse_directory(data, &header)?;

        Ok(MsfContainer { header, pages, directory })
    }

    fn parse_directory(data: &[u8], header: &MsfHeader) -> Result<Vec<MsfDirectoryEntry>, PdbException> {
        let dir_bytes = Self::read_raw_stream(data, header, header.directory_offset, header.directory_length)?;
        Self::parse_directory_from_bytes(&dir_bytes, header)
    }

    fn read_raw_stream(data: &[u8], header: &MsfHeader, start_offset: usize, stream_len: u32) -> Result<Vec<u8>, PdbException> {
        if stream_len == 0 || stream_len == 0xFFFFFFFF {
            return Ok(Vec::new());
        }
        let page_size = header.page_size as usize;
        let num_pages = ((stream_len as usize) + page_size - 1) / page_size;
        let mut buf = vec![0u8; stream_len as usize];
        let mut written = 0usize;
        for i in 0..num_pages {
            let page_start = start_offset + i * page_size;
            let available = data.len().saturating_sub(page_start).min(page_size);
            let to_copy = available.min(buf.len() - written);
            if to_copy == 0 { break; }
            buf[written..written + to_copy].copy_from_slice(&data[page_start..page_start + to_copy]);
            written += to_copy;
        }
        Ok(buf)
    }

    fn parse_directory_from_bytes(dir_bytes: &[u8], header: &MsfHeader) -> Result<Vec<MsfDirectoryEntry>, PdbException> {
        if dir_bytes.is_empty() {
            return Ok(Vec::new());
        }
        if dir_bytes.len() < 4 {
            return Err(PdbException::truncated("MSF directory", 4, dir_bytes.len()));
        }
        let num_streams = read_u32_le(dir_bytes, 0) as usize;
        let size_offset = 4;
        let sizes_end = size_offset + num_streams * 4;
        if dir_bytes.len() < sizes_end {
            return Err(PdbException::truncated("MSF directory sizes", sizes_end, dir_bytes.len()));
        }
        let mut entries = Vec::with_capacity(num_streams);
        let page_number_size = header.page_number_size as usize;
        let page_size = header.page_size;
        let mut pn_cursor = sizes_end;
        for i in 0..num_streams {
            let sz = read_u32_le(dir_bytes, size_offset + i * 4);
            let num_pages = if sz == 0 || sz == 0xFFFFFFFF {
                0
            } else {
                ((sz + page_size - 1) / page_size) as usize
            };
            let mut pages = Vec::with_capacity(num_pages);
            for _ in 0..num_pages {
                if pn_cursor + page_number_size > dir_bytes.len() { break; }
                let pn = if page_number_size == 2 {
                    let v = read_u16_le(dir_bytes, pn_cursor) as u32;
                    pn_cursor += 2;
                    v
                } else {
                    let v = read_u32_le(dir_bytes, pn_cursor);
                    pn_cursor += 4;
                    v
                };
                if pn == 0 { break; }
                pages.push(pn);
            }
            entries.push(MsfDirectoryEntry { size: sz, pages });
        }
        Ok(entries)
    }

    /// Get the number of streams.
    pub fn num_streams(&self) -> usize {
        self.directory.len()
    }

    /// Get the size of a stream, or `None` if the index is invalid.
    pub fn stream_size(&self, index: u32) -> Option<u32> {
        self.directory.get(index as usize).map(|e| e.size)
    }

    /// Read the full contents of a stream by index.
    pub fn read_stream(&self, index: u32) -> Option<MsfStream> {
        let entry = self.directory.get(index as usize)?;
        if entry.size == 0 || entry.size == 0xFFFFFFFF {
            return Some(MsfStream::new(index, Vec::new()));
        }
        let page_size = self.header.page_size as usize;
        let mut buf = vec![0u8; entry.size as usize];
        let mut bytes_written = 0usize;
        for &page_num in &entry.pages {
            let page = self.pages.get(page_num as usize)?;
            let to_copy = page_size.min(buf.len() - bytes_written);
            buf[bytes_written..bytes_written + to_copy].copy_from_slice(&page[..to_copy]);
            bytes_written += to_copy;
            if bytes_written >= buf.len() { break; }
        }
        Some(MsfStream::new(index, buf))
    }

    /// Read the raw bytes of a stream by index (returns Vec<u8>).
    pub fn read_stream_bytes(&self, index: u32) -> Option<Vec<u8>> {
        self.read_stream(index).map(|s| s.into_data())
    }

    /// Get the MSF version.
    pub fn version(&self) -> MsfVersion {
        self.header.version
    }

    /// Get the page size.
    pub fn page_size(&self) -> u32 {
        self.header.page_size
    }

    /// Get the total number of pages.
    pub fn num_pages(&self) -> u32 {
        self.header.num_pages
    }

    /// Validate the MSF container structure.
    pub fn validate(&self) -> Result<(), MsfContainerError> {
        if self.directory.is_empty() {
            return Err(MsfContainerError::NoStreams);
        }
        if self.header.page_size == 0 {
            return Err(MsfContainerError::ZeroPageSize);
        }
        let max_page = self.pages.len() as u32;
        for (i, entry) in self.directory.iter().enumerate() {
            for &page in &entry.pages {
                if page >= max_page {
                    return Err(MsfContainerError::InvalidPageReference {
                        stream: i as u32,
                        page,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Errors returned by MSF container validation.
#[derive(Debug, Clone)]
pub enum MsfContainerError {
    /// The MSF has no streams.
    NoStreams,
    /// The MSF has zero page size.
    ZeroPageSize,
    /// A stream references an out-of-range page.
    InvalidPageReference { stream: u32, page: u32 },
}

impl fmt::Display for MsfContainerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MsfContainerError::NoStreams => write!(f, "MSF has no streams"),
            MsfContainerError::ZeroPageSize => write!(f, "MSF has zero page size"),
            MsfContainerError::InvalidPageReference { stream, page } => {
                write!(f, "Stream {} references out-of-range page {}", stream, page)
            }
        }
    }
}

impl std::error::Error for MsfContainerError {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_msf_version_display() {
        assert_eq!(format!("{}", MsfVersion::V200), "2.00");
        assert_eq!(format!("{}", MsfVersion::V700), "7.00");
    }

    #[test]
    fn test_msf_version_detect_short_data() {
        let data = [0u8; 10];
        assert!(MsfVersion::detect(&data).is_err());
    }

    #[test]
    fn test_msf_version_detect_v700() {
        let mut data = vec![0u8; 64];
        data[..MSF_V700_MAGIC.len()].copy_from_slice(MSF_V700_MAGIC);
        assert_eq!(MsfVersion::detect(&data).unwrap(), MsfVersion::V700);
    }

    #[test]
    fn test_msf_version_detect_v200() {
        let mut data = vec![0u8; 64];
        data[..MSF_V200_MAGIC.len()].copy_from_slice(MSF_V200_MAGIC);
        assert_eq!(MsfVersion::detect(&data).unwrap(), MsfVersion::V200);
    }

    #[test]
    fn test_msf_version_detect_unknown() {
        let data = vec![0xFFu8; 64];
        assert!(MsfVersion::detect(&data).is_err());
    }

    #[test]
    fn test_container_error_display() {
        let e = MsfContainerError::NoStreams;
        assert!(e.to_string().contains("no streams"));

        let e = MsfContainerError::ZeroPageSize;
        assert!(e.to_string().contains("zero page size"));

        let e = MsfContainerError::InvalidPageReference { stream: 3, page: 99 };
        assert!(e.to_string().contains("Stream 3"));
        assert!(e.to_string().contains("page 99"));
    }

    #[test]
    fn test_directory_entry_size() {
        let entry = MsfDirectoryEntry {
            size: 4096,
            pages: vec![0, 1, 2],
        };
        assert_eq!(entry.size, 4096);
        assert_eq!(entry.pages.len(), 3);
    }

    #[test]
    fn test_msf_header_parse_v700() {
        let mut data = Vec::new();
        data.extend_from_slice(MSF_V700_MAGIC);
        data.extend_from_slice(&[0u8; 3]); // padding
        let block_size: u32 = 0x1000;
        data.extend_from_slice(&block_size.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes()); // free page map
        data.extend_from_slice(&2u32.to_le_bytes()); // num pages
        data.extend_from_slice(&0u32.to_le_bytes()); // num directory bytes
        data.extend_from_slice(&0u32.to_le_bytes()); // dir stream length
        data.extend_from_slice(&0u32.to_le_bytes()); // dir map address
        data.resize(2 * 0x1000, 0);

        let header = MsfHeader::parse(&data).unwrap();
        assert_eq!(header.version, MsfVersion::V700);
        assert_eq!(header.page_size, 0x1000);
        assert_eq!(header.num_pages, 2);
        assert_eq!(header.page_number_size, 4);
    }

    #[test]
    fn test_container_parse_minimal() {
        let mut data = Vec::new();
        data.extend_from_slice(MSF_V700_MAGIC);
        data.extend_from_slice(&[0u8; 3]);
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // page size
        data.extend_from_slice(&1u32.to_le_bytes()); // free page map
        data.extend_from_slice(&2u32.to_le_bytes()); // num pages
        data.extend_from_slice(&0u32.to_le_bytes()); // num directory bytes
        data.extend_from_slice(&0u32.to_le_bytes()); // dir stream length
        data.extend_from_slice(&0u32.to_le_bytes()); // dir map address
        data.resize(2 * 0x1000, 0);

        let container = MsfContainer::parse(&data).unwrap();
        assert_eq!(container.num_streams(), 0);
        assert_eq!(container.page_size(), 0x1000);
    }

    #[test]
    fn test_container_num_streams_empty() {
        let mut data = Vec::new();
        data.extend_from_slice(MSF_V700_MAGIC);
        data.extend_from_slice(&[0u8; 3]);
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.resize(2 * 0x1000, 0);

        let container = MsfContainer::parse(&data).unwrap();
        assert_eq!(container.stream_size(0), None);
        assert!(container.read_stream(0).is_none());
    }
}
