//! PEF section header ported from Ghidra's `SectionHeader.java`.
//!
//! Represents a section header within a PEF container, including the
//! section metadata and the packed-data unpacking logic.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use super::packed_data_opcodes::PackedDataOpcodes;
use super::section_kind::SectionKind;
use super::section_share_kind::SectionShareKind;

/// No name offset sentinel value (-1 as a signed 32-bit integer).
pub const NO_NAME_OFFSET: i32 = -1;

/// PEF section header.
///
/// See Apple's PEFBinaryFormat.h:
/// ```c
/// struct PEFSectionHeader {
///     SInt32   nameOffset;
///     UInt32   defaultAddress;
///     UInt32   totalLength;
///     UInt32   unpackedLength;
///     UInt32   containerLength;
///     UInt32   containerOffset;
///     UInt8    sectionKind;
///     UInt8    shareKind;
///     UInt8    alignment;
///     UInt8    reservedA;
/// };
/// ```
#[derive(Debug, Clone)]
pub struct SectionHeader {
    /// Offset of name within the section name table, -1 means unnamed.
    name_offset: i32,
    /// Default address, affects relocations.
    default_address: u32,
    /// Fully expanded size in bytes of the section contents.
    total_length: u32,
    /// Size in bytes of the "initialized" part of the contents.
    unpacked_length: u32,
    /// Size in bytes of the raw data in the container.
    container_length: u32,
    /// Offset of section's raw data.
    container_offset: u32,
    /// Kind of section contents/usage.
    section_kind: SectionKind,
    /// Sharing level, if a writeable section.
    share_kind: SectionShareKind,
    /// Preferred alignment, expressed as log 2.
    alignment: u8,
    /// Reserved, must be zero.
    reserved_a: u8,
    /// The section name, if resolved.
    name: Option<String>,
}

impl SectionHeader {
    /// Size of a PEF section header in bytes.
    pub const SIZE: usize = 28;

    /// Create a section header with the given parameters.
    ///
    /// This is primarily intended for testing and for constructing headers
    /// from known values (e.g., when building a container programmatically).
    pub fn new(
        name_offset: i32,
        default_address: u32,
        total_length: u32,
        unpacked_length: u32,
        container_length: u32,
        container_offset: u32,
        section_kind: SectionKind,
        share_kind: SectionShareKind,
        alignment: u8,
    ) -> Self {
        Self {
            name_offset,
            default_address,
            total_length,
            unpacked_length,
            container_length,
            container_offset,
            section_kind,
            share_kind,
            alignment,
            reserved_a: 0,
            name: None,
        }
    }

    /// Parse a section header from a big-endian binary reader.
    pub fn parse(reader: &mut BinaryReader) -> io::Result<Self> {
        let name_offset = reader.read_next_i32()?;
        let default_address = reader.read_next_u32()?;
        let total_length = reader.read_next_u32()?;
        let unpacked_length = reader.read_next_u32()?;
        let container_length = reader.read_next_u32()?;
        let container_offset = reader.read_next_u32()?;
        let section_kind_raw = reader.read_next_u8()?;
        let share_kind_raw = reader.read_next_u8()?;
        let alignment = reader.read_next_u8()?;
        let reserved_a = reader.read_next_u8()?;

        let section_kind = SectionKind::from_value(section_kind_raw)
            .unwrap_or(SectionKind::Code);
        let share_kind = SectionShareKind::from_value(share_kind_raw)
            .unwrap_or(SectionShareKind::ShareNone);

        // Name is resolved externally if name_offset != -1
        let name = None;

        Ok(Self {
            name_offset,
            default_address,
            total_length,
            unpacked_length,
            container_length,
            container_offset,
            section_kind,
            share_kind,
            alignment,
            reserved_a,
            name,
        })
    }

    /// Returns the offset from the start of the section name table.
    ///
    /// A value of -1 indicates an unnamed section.
    pub fn name_offset(&self) -> i32 {
        self.name_offset
    }

    /// Returns the resolved section name, or the section kind name
    /// if no name was resolved.
    pub fn name(&self) -> String {
        match &self.name {
            Some(n) => n.clone(),
            None => self.section_kind.name().to_string(),
        }
    }

    /// Set the resolved section name.
    pub fn set_name(&mut self, name: String) {
        self.name = Some(name);
    }

    /// Returns true if this section has a name offset (not -1).
    pub fn has_name(&self) -> bool {
        self.name_offset != NO_NAME_OFFSET
    }

    /// Returns the preferred address of this section.
    pub fn default_address(&self) -> u32 {
        self.default_address
    }

    /// Returns the fully expanded size in bytes of the section contents.
    pub fn total_length(&self) -> u32 {
        self.total_length
    }

    /// Returns the size in bytes of the "initialized" part of the contents.
    pub fn unpacked_length(&self) -> u32 {
        self.unpacked_length
    }

    /// Returns the size in bytes of the raw data in the container.
    pub fn container_length(&self) -> u32 {
        self.container_length
    }

    /// Returns the offset of section's raw data.
    pub fn container_offset(&self) -> u32 {
        self.container_offset
    }

    /// Returns the section kind.
    pub fn section_kind(&self) -> SectionKind {
        self.section_kind
    }

    /// Returns the sharing level.
    pub fn share_kind(&self) -> SectionShareKind {
        self.share_kind
    }

    /// Returns the preferred alignment (as log 2).
    pub fn alignment(&self) -> u8 {
        self.alignment
    }

    /// Returns the reserved field.
    pub fn reserved_a(&self) -> u8 {
        self.reserved_a
    }

    /// Returns true if this section has read permissions (always true for PEF).
    pub fn is_readable(&self) -> bool {
        true
    }

    /// Returns true if this section has write permissions.
    pub fn is_writable(&self) -> bool {
        matches!(
            self.section_kind,
            SectionKind::UnpackedData
                | SectionKind::PackedData
                | SectionKind::ExecutableData
        )
    }

    /// Returns true if this section has execute permissions.
    pub fn is_executable(&self) -> bool {
        matches!(
            self.section_kind,
            SectionKind::Code | SectionKind::ExecutableData
        )
    }

    /// Unpack the data in a packed section.
    ///
    /// Calling this method is only valid on a section with kind [`SectionKind::PackedData`].
    ///
    /// `container_data` is the full PEF container data; the section data is at
    /// `container_offset..container_offset+container_length`.
    ///
    /// Returns the unpacked data bytes.
    pub fn unpack_data(&self, container_data: &[u8]) -> io::Result<Vec<u8>> {
        if self.section_kind != SectionKind::PackedData {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Attempt to unpack a section that is not packed",
            ));
        }

        let start = self.container_offset as usize;
        let end = start + self.container_length as usize;
        if end > container_data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Packed section data extends beyond container",
            ));
        }

        let input = &container_data[start..end];
        let mut output = vec![0u8; self.unpacked_length as usize];
        let mut in_pos = 0;
        let mut out_pos = 0;

        while out_pos < output.len() && in_pos < input.len() {
            let value = input[in_pos];
            in_pos += 1;

            let mut count = (value & 0x1f) as usize; // low 5 bits
            if count == 0 {
                count = Self::unpack_next_value(input, &mut in_pos)?;
            }

            let opcode = PackedDataOpcodes::from_value(value >> 5);

            match opcode {
                Some(PackedDataOpcodes::Zero) => {
                    // Zero-fill count bytes
                    let fill = std::cmp::min(count, output.len() - out_pos);
                    for i in 0..fill {
                        output[out_pos + i] = 0;
                    }
                    out_pos += fill;
                }
                Some(PackedDataOpcodes::Block) => {
                    // Block copy count bytes
                    let copy = std::cmp::min(count, std::cmp::min(input.len() - in_pos, output.len() - out_pos));
                    output[out_pos..out_pos + copy].copy_from_slice(&input[in_pos..in_pos + copy]);
                    in_pos += copy;
                    out_pos += copy;
                }
                Some(PackedDataOpcodes::Repeat) => {
                    // Repeat pattern count bytes, repeat_count+1 times
                    let repeat_count = Self::unpack_next_value(input, &mut in_pos)?;
                    let pattern_len = std::cmp::min(count, input.len() - in_pos);
                    let pattern: Vec<u8> = input[in_pos..in_pos + pattern_len].to_vec();
                    in_pos += pattern_len;

                    for _ in 0..=repeat_count {
                        let copy = std::cmp::min(pattern.len(), output.len() - out_pos);
                        output[out_pos..out_pos + copy].copy_from_slice(&pattern[..copy]);
                        out_pos += copy;
                    }
                }
                Some(PackedDataOpcodes::RepeatBlock) => {
                    // Interleaved repeated and unique data
                    let common_size = count;
                    let custom_size = Self::unpack_next_value(input, &mut in_pos)?;
                    let repeat_count = Self::unpack_next_value(input, &mut in_pos)?;

                    let common_len = std::cmp::min(common_size, input.len() - in_pos);
                    let common_data: Vec<u8> = input[in_pos..in_pos + common_len].to_vec();
                    in_pos += common_len;

                    for _ in 0..repeat_count {
                        // Copy common data
                        let copy_c = std::cmp::min(common_data.len(), output.len() - out_pos);
                        output[out_pos..out_pos + copy_c].copy_from_slice(&common_data[..copy_c]);
                        out_pos += copy_c;

                        // Copy custom data
                        let custom_len = std::cmp::min(custom_size, input.len() - in_pos);
                        let copy_x = std::cmp::min(custom_len, output.len() - out_pos);
                        output[out_pos..out_pos + copy_x].copy_from_slice(&input[in_pos..in_pos + copy_x]);
                        in_pos += copy_x;
                        out_pos += copy_x;
                    }

                    // Final common data pattern
                    let copy_c = std::cmp::min(common_data.len(), output.len() - out_pos);
                    output[out_pos..out_pos + copy_c].copy_from_slice(&common_data[..copy_c]);
                    out_pos += copy_c;
                }
                Some(PackedDataOpcodes::RepeatZero) => {
                    // Interleaved zero and unique data
                    let common_size = count;
                    let custom_size = Self::unpack_next_value(input, &mut in_pos)?;
                    let repeat_count = Self::unpack_next_value(input, &mut in_pos)?;

                    for _ in 0..repeat_count {
                        // Skip common size of zero bytes
                        out_pos += std::cmp::min(common_size, output.len() - out_pos);

                        // Copy custom data
                        let custom_len = std::cmp::min(custom_size, input.len() - in_pos);
                        let copy = std::cmp::min(custom_len, output.len() - out_pos);
                        output[out_pos..out_pos + copy].copy_from_slice(&input[in_pos..in_pos + copy]);
                        in_pos += copy;
                        out_pos += copy;
                    }

                    // Final common size of zero bytes
                    out_pos += std::cmp::min(common_size, output.len() - out_pos);
                }
                _ => {
                    // Unrecognized opcode -- skip
                }
            }
        }

        Ok(output)
    }

    /// Unpack a variable-length value from the input stream.
    ///
    /// Reads 7-bit encoded values where bit 7 indicates continuation.
    fn unpack_next_value(input: &[u8], pos: &mut usize) -> io::Result<usize> {
        let mut unpacked: usize = 0;
        loop {
            if *pos >= input.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Unexpected end of packed data while reading variable-length value",
                ));
            }
            unpacked <<= 7;
            let value = input[*pos];
            *pos += 1;
            unpacked += (value & 0x7f) as usize;
            if value & 0x80 == 0 {
                break;
            }
        }
        Ok(unpacked)
    }
}

impl std::fmt::Display for SectionHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Name={} Kind={} Share={}",
            self.name(),
            self.section_kind,
            self.share_kind
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_section_header_bytes(
        name_offset: i32,
        default_address: u32,
        total_length: u32,
        unpacked_length: u32,
        container_length: u32,
        container_offset: u32,
        section_kind: u8,
        share_kind: u8,
        alignment: u8,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&name_offset.to_be_bytes());
        data.extend_from_slice(&default_address.to_be_bytes());
        data.extend_from_slice(&total_length.to_be_bytes());
        data.extend_from_slice(&unpacked_length.to_be_bytes());
        data.extend_from_slice(&container_length.to_be_bytes());
        data.extend_from_slice(&container_offset.to_be_bytes());
        data.push(section_kind);
        data.push(share_kind);
        data.push(alignment);
        data.push(0); // reservedA
        data
    }

    #[test]
    fn test_parse_section_header() {
        let bytes = make_section_header_bytes(-1, 0x1000, 100, 100, 100, 0, 0, 0, 2);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let header = SectionHeader::parse(&mut reader).unwrap();

        assert_eq!(header.name_offset(), -1);
        assert!(!header.has_name());
        assert_eq!(header.default_address(), 0x1000);
        assert_eq!(header.total_length(), 100);
        assert_eq!(header.unpacked_length(), 100);
        assert_eq!(header.container_length(), 100);
        assert_eq!(header.container_offset(), 0);
        assert_eq!(header.section_kind(), SectionKind::Code);
        assert_eq!(header.share_kind(), SectionShareKind::ShareNone);
        assert_eq!(header.alignment(), 2);
        assert!(header.is_readable());
        assert!(!header.is_writable());
        assert!(header.is_executable());
    }

    #[test]
    fn test_parse_loader_section() {
        let bytes = make_section_header_bytes(-1, 0, 200, 200, 200, 56, 4, 0, 2);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let header = SectionHeader::parse(&mut reader).unwrap();

        assert_eq!(header.section_kind(), SectionKind::Loader);
        assert!(!header.is_writable());
        assert!(!header.is_executable());
    }

    #[test]
    fn test_parse_data_section_writable() {
        let bytes = make_section_header_bytes(-1, 0, 100, 100, 100, 0, 1, 0, 2);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let header = SectionHeader::parse(&mut reader).unwrap();

        assert_eq!(header.section_kind(), SectionKind::UnpackedData);
        assert!(header.is_writable());
        assert!(!header.is_executable());
    }

    #[test]
    fn test_parse_executable_data() {
        let bytes = make_section_header_bytes(-1, 0, 100, 100, 100, 0, 6, 0, 2);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let header = SectionHeader::parse(&mut reader).unwrap();

        assert_eq!(header.section_kind(), SectionKind::ExecutableData);
        assert!(header.is_writable());
        assert!(header.is_executable());
    }

    #[test]
    fn test_section_header_display() {
        let bytes = make_section_header_bytes(-1, 0, 0, 0, 0, 0, 0, 0, 0);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let header = SectionHeader::parse(&mut reader).unwrap();
        let s = format!("{}", header);
        assert!(s.contains("Code"));
    }

    #[test]
    fn test_section_header_set_name() {
        let bytes = make_section_header_bytes(10, 0, 0, 0, 0, 0, 0, 0, 0);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let mut header = SectionHeader::parse(&mut reader).unwrap();

        assert!(header.has_name());
        assert_eq!(header.name(), "Code"); // fallback to kind name

        header.set_name(".text".to_string());
        assert_eq!(header.name(), ".text");
    }

    #[test]
    fn test_unpack_zero_fill() {
        // Packed section with a Zero opcode: count=4
        // Opcode byte: (0 << 5) | 4 = 0x04
        let packed = vec![0x04u8];
        let bytes = make_section_header_bytes(-1, 0, 4, 4, 1, 0, 2, 0, 0);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let header = SectionHeader::parse(&mut reader).unwrap();

        let result = header.unpack_data(&packed).unwrap();
        assert_eq!(result, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_unpack_block_copy() {
        // Packed section with a Block opcode: count=3
        // Opcode byte: (1 << 5) | 3 = 0x23
        let packed = vec![0x23, 0xAA, 0xBB, 0xCC];
        let bytes = make_section_header_bytes(-1, 0, 3, 3, 4, 0, 2, 0, 0);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let header = SectionHeader::parse(&mut reader).unwrap();

        let result = header.unpack_data(&packed).unwrap();
        assert_eq!(result, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_unpack_not_packed_error() {
        let bytes = make_section_header_bytes(-1, 0, 10, 10, 10, 0, 3, 0, 0);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let header = SectionHeader::parse(&mut reader).unwrap();

        let result = header.unpack_data(&[0u8; 10]);
        assert!(result.is_err());
    }

    #[test]
    fn test_unpack_repeat() {
        // Repeat opcode: count=2, repeatCount=1 (so repeat 2 times total)
        // Opcode byte: (2 << 5) | 2 = 0x42
        // Variable repeat count = 1 (encoded as single byte: 0x01)
        // Pattern: [0xDE, 0xAD]
        let packed = vec![0x42, 0x01, 0xDE, 0xAD];
        let bytes = make_section_header_bytes(-1, 0, 4, 4, 4, 0, 2, 0, 0);
        let mut reader = BinaryReader::from_bytes(&bytes, false);
        let header = SectionHeader::parse(&mut reader).unwrap();

        let result = header.unpack_data(&packed).unwrap();
        // repeat_count=1, so pattern repeated 2 times (0..=repeat_count)
        assert_eq!(result, vec![0xDE, 0xAD, 0xDE, 0xAD]);
    }
}
