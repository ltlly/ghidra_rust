//! PEF container header ported from Ghidra's `ContainerHeader.java`.
//!
//! The top-level structure of a PEF (Preferred Executable Format) binary.
//! Parses the container header, validates the magic tags and architecture,
//! and then parses all section headers and the loader info.

use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use super::loader_info_header::LoaderInfoHeader;
use super::section_header::SectionHeader;
use super::section_kind::SectionKind;

/// Magic tag 1: "Joy!".
pub const TAG1: &str = "Joy!";
/// Magic tag 2: "peff" (yes, with two f's).
pub const TAG2: &str = "peff";

/// Architecture constant for PowerPC CFM.
pub const ARCHITECTURE_PPC: &str = "pwpc";
/// Architecture constant for CFm-68k.
pub const ARCHITECTURE_68K: &str = "m68k";

/// PEF container header.
///
/// See Apple's PEFBinaryFormat.h:
/// ```c
/// struct PEFContainerHeader {
///     OSType  tag1;              // Must contain 'Joy!'.
///     OSType  tag2;              // Must contain 'peff'.
///     OSType  architecture;      // The ISA for code sections.
///     UInt32  formatVersion;     // The physical format version.
///     UInt32  dateTimeStamp;     // Macintosh format creation/modification stamp.
///     UInt32  oldDefVersion;     // Old definition version number.
///     UInt32  oldImpVersion;     // Old implementation version number.
///     UInt32  currentVersion;    // Current version number.
///     UInt16  sectionCount;      // Total number of section headers.
///     UInt16  instSectionCount;  // Number of instantiated sections.
///     UInt32  reservedA;         // Reserved, must be zero.
/// };
/// ```
#[derive(Debug)]
pub struct ContainerHeader {
    /// Always "Joy!".
    tag1: String,
    /// Always "peff".
    tag2: String,
    /// The ISA for code sections ("pwpc" or "m68k").
    architecture: String,
    /// The physical format version (currently 1).
    format_version: u32,
    /// Macintosh format creation/modification stamp.
    ///
    /// Seconds since Jan 1, 1904.
    date_time_stamp: u32,
    /// Old definition version number for the code fragment.
    old_def_version: u32,
    /// Old implementation version number for the code fragment.
    old_imp_version: u32,
    /// Current version number for the code fragment.
    current_version: u32,
    /// Total number of section headers that follow.
    section_count: u16,
    /// Number of instantiated sections.
    inst_section_count: u16,
    /// Reserved, must be zero.
    reserved_a: u32,

    /// The parsed section headers.
    sections: Vec<SectionHeader>,
    /// The parsed loader info (if a loader section exists).
    loader: Option<LoaderInfoHeader>,
}

impl ContainerHeader {
    /// Size of the PEF container header in bytes.
    pub const SIZE: usize = 40;

    /// Parse a PEF container header and all sections from the given data.
    ///
    /// The data should be the entire PEF file contents. The reader is
    /// configured for big-endian (PEF is always big-endian).
    pub fn parse(data: &[u8]) -> io::Result<Self> {
        let mut reader = BinaryReader::from_bytes(data, false); // big-endian

        // Read header fields
        let tag1 = reader.read_next_fixed_string(4)?;
        let tag2 = reader.read_next_fixed_string(4)?;
        let architecture = reader.read_next_fixed_string(4)?;
        let format_version = reader.read_next_u32()?;
        let date_time_stamp = reader.read_next_u32()?;
        let old_def_version = reader.read_next_u32()?;
        let old_imp_version = reader.read_next_u32()?;
        let current_version = reader.read_next_u32()?;
        let section_count = reader.read_next_u16()?;
        let inst_section_count = reader.read_next_u16()?;
        let reserved_a = reader.read_next_u32()?;

        // Validate magic tags
        if tag1 != TAG1 || tag2 != TAG2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Invalid PEF file: expected tags '{}'/'{}', got '{}'/'{}'",
                    TAG1, TAG2, tag1, tag2
                ),
            ));
        }

        // Validate architecture
        if architecture != ARCHITECTURE_PPC && architecture != ARCHITECTURE_68K {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid PEF architecture: {}", architecture),
            ));
        }

        // Parse section headers
        let mut sections = Vec::with_capacity(section_count as usize);
        let mut loader: Option<LoaderInfoHeader> = None;

        for _ in 0..section_count {
            let section = SectionHeader::parse(&mut reader)?;
            if section.section_kind() == SectionKind::Loader {
                if loader.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Multiple loader sections exist in PEF container",
                    ));
                }
                loader = Some(LoaderInfoHeader::parse(&mut reader, &section)?);
            }
            sections.push(section);
        }

        Ok(Self {
            tag1,
            tag2,
            architecture,
            format_version,
            date_time_stamp,
            old_def_version,
            old_imp_version,
            current_version,
            section_count,
            inst_section_count,
            reserved_a,
            sections,
            loader,
        })
    }

    /// Always returns "Joy!".
    pub fn tag1(&self) -> &str {
        &self.tag1
    }

    /// Always returns "peff".
    pub fn tag2(&self) -> &str {
        &self.tag2
    }

    /// Returns the architecture for this container.
    ///
    /// Either "pwpc" (PowerPC CFM) or "m68k" (CFm-68k).
    pub fn architecture(&self) -> &str {
        &self.architecture
    }

    /// Returns the version of this PEF container (currently 1).
    pub fn format_version(&self) -> u32 {
        self.format_version
    }

    /// Returns the creation/modification date of this PEF container.
    ///
    /// The stamp follows the Mac time-measurement scheme: number of
    /// seconds since Jan 1, 1904.
    pub fn date_time_stamp(&self) -> u32 {
        self.date_time_stamp
    }

    /// Returns the old CFM definition version.
    pub fn old_def_version(&self) -> u32 {
        self.old_def_version
    }

    /// Returns the old CFM implementation version.
    pub fn old_imp_version(&self) -> u32 {
        self.old_imp_version
    }

    /// Returns the current CFM version.
    pub fn current_version(&self) -> u32 {
        self.current_version
    }

    /// Returns the total number of sections in this container.
    pub fn section_count(&self) -> u16 {
        self.section_count
    }

    /// Returns the number of instantiated sections.
    ///
    /// Instantiated sections contain code or data required for execution.
    pub fn instantiated_section_count(&self) -> u16 {
        self.inst_section_count
    }

    /// Returns the reserved field (always zero).
    pub fn reserved_a(&self) -> u32 {
        self.reserved_a
    }

    /// Returns the parsed section headers.
    pub fn sections(&self) -> &[SectionHeader] {
        &self.sections
    }

    /// Returns the loader info header, if a loader section exists.
    pub fn loader(&self) -> Option<&LoaderInfoHeader> {
        self.loader.as_ref()
    }

    /// Returns the image base address (always 0 for PEF).
    pub fn image_base(&self) -> u64 {
        0
    }
}

impl std::fmt::Display for ContainerHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ContainerHeader({} {} arch={} version={} sections={})",
            self.tag1, self.tag2, self.architecture, self.format_version, self.section_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid PEF container header (40 bytes, big-endian).
    fn make_pef_header(
        architecture: &str,
        section_count: u16,
        inst_section_count: u16,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"Joy!");
        data.extend_from_slice(b"peff");
        data.extend_from_slice(architecture.as_bytes());
        data.extend_from_slice(&1u32.to_be_bytes()); // formatVersion
        data.extend_from_slice(&0u32.to_be_bytes()); // dateTimeStamp
        data.extend_from_slice(&0u32.to_be_bytes()); // oldDefVersion
        data.extend_from_slice(&0u32.to_be_bytes()); // oldImpVersion
        data.extend_from_slice(&0u32.to_be_bytes()); // currentVersion
        data.extend_from_slice(&section_count.to_be_bytes());
        data.extend_from_slice(&inst_section_count.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes()); // reservedA
        data
    }

    /// Build a PEF section header (28 bytes, big-endian).
    fn make_section_header(
        section_kind: u8,
        container_length: u32,
        container_offset: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&(-1i32).to_be_bytes()); // nameOffset
        data.extend_from_slice(&0u32.to_be_bytes()); // defaultAddress
        data.extend_from_slice(&container_length.to_be_bytes()); // totalLength
        data.extend_from_slice(&container_length.to_be_bytes()); // unpackedLength
        data.extend_from_slice(&container_length.to_be_bytes()); // containerLength
        data.extend_from_slice(&container_offset.to_be_bytes()); // containerOffset
        data.push(section_kind);
        data.push(0); // shareKind
        data.push(2); // alignment
        data.push(0); // reservedA
        data
    }

    #[test]
    fn test_parse_empty_pef_container() {
        let mut data = make_pef_header("pwpc", 0, 0);
        let header = ContainerHeader::parse(&data).unwrap();

        assert_eq!(header.tag1(), "Joy!");
        assert_eq!(header.tag2(), "peff");
        assert_eq!(header.architecture(), "pwpc");
        assert_eq!(header.format_version(), 1);
        assert_eq!(header.section_count(), 0);
        assert_eq!(header.instantiated_section_count(), 0);
        assert!(header.sections().is_empty());
        assert!(header.loader().is_none());
        assert_eq!(header.image_base(), 0);
    }

    #[test]
    fn test_parse_pef_with_code_section() {
        let mut data = make_pef_header("pwpc", 1, 1);
        // Section 0: Code section with 10 bytes of data
        data.extend_from_slice(&make_section_header(0, 10, data.len() as u32 + 28));
        // 10 bytes of dummy code data
        data.extend_from_slice(&[0x4E, 0x80, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        let header = ContainerHeader::parse(&data).unwrap();
        assert_eq!(header.section_count(), 1);
        assert_eq!(header.sections()[0].section_kind(), SectionKind::Code);
    }

    #[test]
    fn test_parse_68k_architecture() {
        let data = make_pef_header("m68k", 0, 0);
        let header = ContainerHeader::parse(&data).unwrap();
        assert_eq!(header.architecture(), "m68k");
    }

    #[test]
    fn test_invalid_magic_tag1() {
        let mut data = make_pef_header("pwpc", 0, 0);
        data[0] = b'X'; // Corrupt tag1
        let result = ContainerHeader::parse(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid PEF file"));
    }

    #[test]
    fn test_invalid_magic_tag2() {
        let mut data = make_pef_header("pwpc", 0, 0);
        data[4] = b'X'; // Corrupt tag2
        let result = ContainerHeader::parse(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_architecture() {
        let mut data = make_pef_header("pwpc", 0, 0);
        // Replace architecture with "xxxx"
        data[8] = b'x';
        data[9] = b'x';
        data[10] = b'x';
        data[11] = b'x';
        let result = ContainerHeader::parse(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("Invalid PEF architecture"));
    }

    #[test]
    fn test_truncated_data() {
        let data = b"Joy!peff"; // Too short
        let result = ContainerHeader::parse(data);
        assert!(result.is_err());
    }

    #[test]
    fn test_container_header_display() {
        let data = make_pef_header("pwpc", 0, 0);
        let header = ContainerHeader::parse(&data).unwrap();
        let s = format!("{}", header);
        assert!(s.contains("Joy!"));
        assert!(s.contains("peff"));
        assert!(s.contains("pwpc"));
    }

    #[test]
    fn test_date_time_stamp() {
        let mut data = make_pef_header("pwpc", 0, 0);
        // Set dateTimeStamp at offset 16
        data[16..20].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        let header = ContainerHeader::parse(&data).unwrap();
        assert_eq!(header.date_time_stamp(), 0xDEAD_BEEF);
    }

    #[test]
    fn test_version_fields() {
        let mut data = make_pef_header("pwpc", 0, 0);
        data[20..24].copy_from_slice(&10u32.to_be_bytes()); // oldDefVersion
        data[24..28].copy_from_slice(&20u32.to_be_bytes()); // oldImpVersion
        data[28..32].copy_from_slice(&30u32.to_be_bytes()); // currentVersion
        let header = ContainerHeader::parse(&data).unwrap();
        assert_eq!(header.old_def_version(), 10);
        assert_eq!(header.old_imp_version(), 20);
        assert_eq!(header.current_version(), 30);
    }
}
