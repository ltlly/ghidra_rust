//! Windows MiniDump (MDMP) format parser.
//!
//! Ported from Ghidra's `ghidra.file.formats.dump.mdmp` package.
//!
//! References:
//! - Microsoft MiniDump format: <https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/>

use nom::number::complete::{le_u16, le_u32, le_u64};
use std::fmt;

// ═══════════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════════

/// MiniDump signature: `"MDMP"`.
pub const MDMP_SIGNATURE: u32 = 0x504D444D; // "MDMP" in LE

/// MiniDump version.
pub const MDMP_VERSION: u32 = 0xA793;

// Stream types.
pub const MDMP_UNUSED_STREAM: u32 = 0;
pub const MDMP_RESERVED_STREAM_0: u32 = 1;
pub const MDMP_RESERVED_STREAM_1: u32 = 2;
pub const MDMP_THREAD_LIST_STREAM: u32 = 3;
pub const MDMP_MODULE_LIST_STREAM: u32 = 4;
pub const MDMP_MEMORY_LIST_STREAM: u32 = 5;
pub const MDMP_EXCEPTION_STREAM: u32 = 6;
pub const MDMP_SYSTEM_INFO_STREAM: u32 = 7;
pub const MDMP_THREAD_EX_LIST_STREAM: u32 = 8;
pub const MDMP_MEMORY_64_LIST_STREAM: u32 = 9;
pub const MDMP_COMMENT_STREAM_A: u32 = 10;
pub const MDMP_COMMENT_STREAM_W: u32 = 11;
pub const MDMP_HANDLE_DATA_STREAM: u32 = 12;
pub const MDMP_FUNCTION_TABLE_STREAM: u32 = 13;
pub const MDMP_UNLOADED_MODULE_LIST_STREAM: u32 = 14;
pub const MDMP_MISC_INFO_STREAM: u32 = 15;
pub const MDMP_MEMORY_INFO_LIST_STREAM: u32 = 16;
pub const MDMP_THREAD_INFO_LIST_STREAM: u32 = 17;
pub const MDMP_HANDLE_OPERATION_LIST_STREAM: u32 = 18;
pub const MDMP_TOKEN_STREAM: u32 = 19;
pub const MDMP_JAVASCRIPT_DATA_STREAM: u32 = 20;
pub const MDMP_SYSTEM_MEMORY_INFO_1_STREAM: u32 = 21;
pub const MDMP_PROCESS_VM_COUNTERS_1_STREAM: u32 = 22;
pub const MDMP_THREAD_NAMES_STREAM: u32 = 24;

// ═══════════════════════════════════════════════════════════════════════════════════
// MiniDump Header
// ═══════════════════════════════════════════════════════════════════════════════════

/// MiniDump header.
#[derive(Debug, Clone)]
pub struct MinidumpHeader {
    /// Signature: `0x504D444D` ("MDMP").
    pub signature: u32,
    /// Version.
    pub version: u32,
    /// Number of streams.
    pub number_of_streams: u32,
    /// RVA of the stream directory.
    pub stream_directory_rva: u32,
    /// Checksum (or 0).
    pub checksum: u32,
    /// Reserved / time date stamp.
    pub time_date_stamp: u32,
    /// Flags.
    pub flags: u64,
}

impl MinidumpHeader {
    /// Header size (32 bytes).
    pub const SIZE: usize = 32;

    /// Parse a MiniDump header.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short for MiniDump header".to_string());
        }

        let signature = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if signature != MDMP_SIGNATURE {
            return Err(format!("Invalid MDMP signature: 0x{:08X}", signature));
        }

        let version = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let number_of_streams = u32::from_le_bytes(data[8..12].try_into().unwrap());
        let stream_directory_rva = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let checksum = u32::from_le_bytes(data[16..20].try_into().unwrap());
        let time_date_stamp = u32::from_le_bytes(data[20..24].try_into().unwrap());
        let flags = u64::from_le_bytes(data[24..32].try_into().unwrap());

        Ok(MinidumpHeader {
            signature,
            version,
            number_of_streams,
            stream_directory_rva,
            checksum,
            time_date_stamp,
            flags,
        })
    }

    pub fn is_valid(&self) -> bool {
        self.signature == MDMP_SIGNATURE
    }
}

// ═══════════════════════════════════════════════════════════════════════════════════
// MiniDump Stream Directory Entry
// ═══════════════════════════════════════════════════════════════════════════════════

/// A stream directory entry.
#[derive(Debug, Clone, Copy)]
pub struct MinidumpStreamDescriptor {
    /// Stream type.
    pub stream_type: u32,
    /// Data size.
    pub data_size: u32,
    /// RVA of the stream data.
    pub rva: u32,
}

impl MinidumpStreamDescriptor {
    pub const SIZE: usize = 12;

    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < Self::SIZE {
            return Err("Data too short".to_string());
        }
        Ok(MinidumpStreamDescriptor {
            stream_type: u32::from_le_bytes(data[0..4].try_into().unwrap()),
            data_size: u32::from_le_bytes(data[4..8].try_into().unwrap()),
            rva: u32::from_le_bytes(data[8..12].try_into().unwrap()),
        })
    }
}

/// Check if data starts with MDMP signature.
pub fn is_minidump(data: &[u8]) -> bool {
    data.len() >= 4 && u32::from_le_bytes([data[0], data[1], data[2], data[3]]) == MDMP_SIGNATURE
}

// ═══════════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_minidump() {
        assert!(is_minidump(&MDMP_SIGNATURE.to_le_bytes()));
        assert!(!is_minidump(&[0x00; 4]));
    }

    #[test]
    fn test_header_parse() {
        let mut data = vec![0u8; MinidumpHeader::SIZE];
        data[0..4].copy_from_slice(&MDMP_SIGNATURE.to_le_bytes());
        data[4..8].copy_from_slice(&MDMP_VERSION.to_le_bytes());
        data[8..12].copy_from_slice(&5u32.to_le_bytes()); // number_of_streams
        data[12..16].copy_from_slice(&32u32.to_le_bytes()); // stream_directory_rva

        let hdr = MinidumpHeader::parse(&data).unwrap();
        assert!(hdr.is_valid());
        assert_eq!(hdr.version, MDMP_VERSION);
        assert_eq!(hdr.number_of_streams, 5);
        assert_eq!(hdr.stream_directory_rva, 32);
    }

    #[test]
    fn test_header_invalid() {
        assert!(MinidumpHeader::parse(&[0u8; MinidumpHeader::SIZE]).is_err());
    }

    #[test]
    fn test_stream_types() {
        assert_eq!(MDMP_THREAD_LIST_STREAM, 3);
        assert_eq!(MDMP_MODULE_LIST_STREAM, 4);
        assert_eq!(MDMP_MEMORY_LIST_STREAM, 5);
        assert_eq!(MDMP_SYSTEM_INFO_STREAM, 7);
        assert_eq!(MDMP_MEMORY_64_LIST_STREAM, 9);
    }

    #[test]
    fn test_stream_descriptor_parse() {
        let mut data = vec![0u8; MinidumpStreamDescriptor::SIZE];
        data[0..4].copy_from_slice(&MDMP_MODULE_LIST_STREAM.to_le_bytes());
        data[4..8].copy_from_slice(&1024u32.to_le_bytes());
        data[8..12].copy_from_slice(&200u32.to_le_bytes());

        let desc = MinidumpStreamDescriptor::parse(&data).unwrap();
        assert_eq!(desc.stream_type, MDMP_MODULE_LIST_STREAM);
        assert_eq!(desc.data_size, 1024);
        assert_eq!(desc.rva, 200);
    }
}
