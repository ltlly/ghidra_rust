//! Fat header parser ported from Ghidra's `FatHeader.java`.
//!
//! Represents a Mach-O Universal Binary (fat) header that contains one or
//! more architecture slices. The fat header is always stored in big-endian
//! format regardless of the target architecture.
//!
//! See: <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/fat.h>

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::byte_provider::ByteProviderWrapper;
use crate::bin_format::types::{DataTypeDescription, StructConverter};

use super::fat_arch::{FatArch, SIZEOF_FAT_ARCH};
use super::ubi_exception::UbiException;

/// Magic number for big-endian fat binaries: `0xCAFEBABE`.
pub const FAT_MAGIC: u32 = 0xCAFEBABE;

/// Magic number for little-endian (swapped) fat binaries: `0xBEBAFECA`.
pub const FAT_CIGAM: u32 = 0xBEBAFECA;

/// Maximum reasonable number of fat architectures (sanity bound).
const MAX_FAT_ARCH_COUNT: i32 = 0x1000;

/// Represents a `fat_header` structure plus its `fat_arch` entries.
///
/// Ported from `ghidra.app.util.bin.format.ubi.FatHeader`.
///
/// ```text
/// struct fat_header {
///     uint32_t magic;      // FAT_MAGIC or FAT_CIGAM
///     uint32_t nfat_arch;  // Number of fat_arch entries
/// };
/// // followed by nfat_arch fat_arch structs
/// ```
///
/// The header also extracts per-architecture metadata (offset, size) for
/// each Mach-O slice found inside the fat binary.
#[derive(Debug, Clone)]
pub struct FatHeader {
    /// The raw magic number (should be `FAT_MAGIC` or `FAT_CIGAM`).
    magic: u32,
    /// Number of fat architecture entries.
    nfat_arch: u32,
    /// Parsed architecture entries.
    architectures: Vec<FatArch>,
    /// Per-architecture file start offsets (absolute within the provider).
    arch_starts: Vec<u64>,
    /// Per-architecture sizes in bytes.
    arch_sizes: Vec<u64>,
}

impl FatHeader {
    /// Parse a fat header from a byte slice.
    ///
    /// The fat header is always big-endian. This method validates the magic
    /// number and architecture count, then reads all `fat_arch` entries.
    ///
    /// # Errors
    ///
    /// Returns `UbiException` if the magic number is invalid, the architecture
    /// count is out of range, or an I/O error occurs.
    pub fn from_bytes(data: &[u8]) -> Result<Self, UbiException> {
        let mut reader = BinaryReader::from_bytes(data, false); // big-endian
        Self::parse_with_reader(&mut reader)
    }

    /// Internal parsing from a pre-configured big-endian reader.
    fn parse_with_reader(reader: &mut BinaryReader) -> Result<Self, UbiException> {
        let magic = reader
            .read_next_u32()
            .map_err(UbiException::from)?;

        if magic != FAT_MAGIC && magic != FAT_CIGAM {
            return Err(UbiException::new("Invalid UBI file."));
        }

        let nfat_arch = reader
            .read_next_i32()
            .map_err(UbiException::from)? as u32;

        // Sanity check on architecture count.
        if (nfat_arch as i32) > MAX_FAT_ARCH_COUNT || (nfat_arch as i32) < 0 {
            return Err(UbiException::new("Invalid UBI file."));
        }

        let mut architectures = Vec::with_capacity(nfat_arch as usize);
        for _ in 0..nfat_arch {
            let arch = FatArch::parse(reader).map_err(UbiException::from)?;
            architectures.push(arch);
        }

        // Build per-architecture start/size arrays.
        let arch_starts: Vec<u64> = architectures.iter().map(|a| a.offset as u64).collect();
        let arch_sizes: Vec<u64> = architectures.iter().map(|a| a.size as u64).collect();

        Ok(Self {
            magic,
            nfat_arch,
            architectures,
            arch_starts,
            arch_sizes,
        })
    }

    /// Returns the raw magic number.
    pub fn magic(&self) -> u32 {
        self.magic
    }

    /// Returns the number of fat architecture entries.
    pub fn fat_architecture_count(&self) -> u32 {
        self.nfat_arch
    }

    /// Returns a slice of the architecture entries.
    pub fn architectures(&self) -> &[FatArch] {
        &self.architectures
    }

    /// Returns the file start offsets for each architecture slice.
    pub fn arch_starts(&self) -> &[u64] {
        &self.arch_starts
    }

    /// Returns the sizes for each architecture slice.
    pub fn arch_sizes(&self) -> &[u64] {
        &self.arch_sizes
    }

    /// Returns true if the magic indicates a byte-swapped (CIGAM) header.
    pub fn is_swapped(&self) -> bool {
        self.magic == FAT_CIGAM
    }

    /// Returns the total size of the header plus all fat_arch entries in bytes.
    pub fn header_size(&self) -> usize {
        8 + (self.nfat_arch as usize) * SIZEOF_FAT_ARCH
    }

    /// Looks up the architecture entry for a given CPU type, if present.
    pub fn find_arch(&self, cputype: i32) -> Option<&FatArch> {
        self.architectures.iter().find(|a| a.cputype == cputype)
    }

    /// Returns a byte provider wrapping the data for a specific architecture
    /// slice within the given parent provider.
    ///
    /// The returned provider is a window over the sub-range of the parent
    /// that corresponds to the architecture at `arch_index`.
    ///
    /// Returns `None` if the architecture index is out of range.
    pub fn arch_provider(
        &self,
        provider: Box<dyn crate::bin_format::byte_provider::ByteProvider>,
        arch_index: usize,
    ) -> Option<ByteProviderWrapper> {
        if arch_index >= self.architectures.len() {
            return None;
        }
        let arch = &self.architectures[arch_index];
        Some(ByteProviderWrapper::new(provider, arch.offset as u64, arch.size as u64))
    }
}

impl StructConverter for FatHeader {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "fat_header".to_string(),
            size: (8 + self.nfat_arch * 20) as u32,
            fields: vec![
                ("magic".into(), DataTypeDescription::DWord),
                ("nfat_arch".into(), DataTypeDescription::DWord),
                (
                    "fat_arch[]".into(),
                    DataTypeDescription::Array {
                        element: Box::new(DataTypeDescription::Struct {
                            name: "fat_arch".to_string(),
                            size: 20,
                            fields: vec![
                                ("cputype".into(), DataTypeDescription::DWord),
                                ("cpusubtype".into(), DataTypeDescription::DWord),
                                ("offset".into(), DataTypeDescription::DWord),
                                ("size".into(), DataTypeDescription::DWord),
                                ("align".into(), DataTypeDescription::DWord),
                            ],
                        }),
                        count: self.nfat_arch as usize,
                    },
                ),
            ],
        }
    }
}

impl BinaryWritable for FatHeader {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        writer.write_u32(self.magic);
        writer.write_u32(self.nfat_arch);
        for arch in &self.architectures {
            arch.write_to(writer)?;
        }
        Ok(())
    }
}

impl fmt::Display for FatHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FatHeader {{ magic=0x{:08X}, nfat_arch={}, header_size={} }}",
            self.magic,
            self.nfat_arch,
            self.header_size()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal fat header with the given architectures (big-endian).
    fn make_fat_header_bytes(archs: &[(i32, i32, u32, u32, u32)]) -> Vec<u8> {
        let mut data = Vec::new();
        // magic
        data.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        // nfat_arch
        data.extend_from_slice(&(archs.len() as u32).to_be_bytes());
        // fat_arch entries
        for &(cputype, cpusubtype, offset, size, align) in archs {
            data.extend_from_slice(&cputype.to_be_bytes());
            data.extend_from_slice(&cpusubtype.to_be_bytes());
            data.extend_from_slice(&offset.to_be_bytes());
            data.extend_from_slice(&size.to_be_bytes());
            data.extend_from_slice(&align.to_be_bytes());
        }
        data
    }

    #[test]
    fn test_parse_fat_header_single_arch() {
        let data = make_fat_header_bytes(&[(7, 3, 0x1000, 0x5000, 14)]);
        let header = FatHeader::from_bytes(&data).unwrap();

        assert_eq!(header.magic(), FAT_MAGIC);
        assert_eq!(header.fat_architecture_count(), 1);
        assert_eq!(header.architectures().len(), 1);
        assert_eq!(header.architectures()[0].cputype, 7);
        assert_eq!(header.arch_starts(), &[0x1000]);
        assert_eq!(header.arch_sizes(), &[0x5000]);
    }

    #[test]
    fn test_parse_fat_header_multi_arch() {
        let data = make_fat_header_bytes(&[
            (7, 3, 0x1000, 0x5000, 14),         // x86
            (12 | 0x01000000, 0, 0x6000, 0x8000, 15), // arm64
        ]);
        let header = FatHeader::from_bytes(&data).unwrap();

        assert_eq!(header.fat_architecture_count(), 2);
        assert_eq!(header.architectures()[0].cputype, 7);
        assert_eq!(header.architectures()[1].cputype, 12 | 0x01000000);
        assert_eq!(header.header_size(), 8 + 2 * SIZEOF_FAT_ARCH);
    }

    #[test]
    fn test_parse_fat_header_cigam() {
        let mut data = make_fat_header_bytes(&[(7, 3, 0x1000, 0x5000, 14)]);
        // Overwrite magic with CIGAM
        data[0..4].copy_from_slice(&FAT_CIGAM.to_be_bytes());
        let header = FatHeader::from_bytes(&data).unwrap();

        assert_eq!(header.magic(), FAT_CIGAM);
        assert!(header.is_swapped());
    }

    #[test]
    fn test_parse_fat_header_invalid_magic() {
        let mut data = vec![0u8; 28];
        // Invalid magic: 0x00000001
        data[0] = 0x00;
        data[1] = 0x00;
        data[2] = 0x00;
        data[3] = 0x01;
        // nfat_arch = 1
        data[7] = 0x01;
        let result = FatHeader::from_bytes(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.message().contains("Invalid UBI"));
    }

    #[test]
    fn test_parse_fat_header_negative_count() {
        let mut data = vec![0u8; 8 + SIZEOF_FAT_ARCH];
        data[0..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        data[4..8].copy_from_slice(&(-1i32 as u32).to_be_bytes());
        let result = FatHeader::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_fat_header_excessive_count() {
        let mut data = vec![0u8; 8];
        data[0..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        data[4..8].copy_from_slice(&(0x1001u32).to_be_bytes());
        let result = FatHeader::from_bytes(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_fat_header_find_arch() {
        let data = make_fat_header_bytes(&[
            (7, 3, 0x1000, 0x5000, 14),
            (12 | 0x01000000, 0, 0x6000, 0x8000, 15),
        ]);
        let header = FatHeader::from_bytes(&data).unwrap();

        assert!(header.find_arch(7).is_some());
        assert!(header.find_arch(12 | 0x01000000).is_some());
        assert!(header.find_arch(999).is_none());
    }

    #[test]
    fn test_fat_header_struct_converter() {
        let data = make_fat_header_bytes(&[(7, 3, 0x1000, 0x5000, 14)]);
        let header = FatHeader::from_bytes(&data).unwrap();

        let dt = header.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "fat_header");
                assert_eq!(fields.len(), 3);
                assert_eq!(fields[0].0, "magic");
                assert_eq!(fields[1].0, "nfat_arch");
                assert_eq!(fields[2].0, "fat_arch[]");
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_fat_header_write_roundtrip() {
        let data = make_fat_header_bytes(&[
            (7, 3, 0x1000, 0x5000, 14),
            (12 | 0x01000000, 0, 0x6000, 0x8000, 15),
        ]);
        let header = FatHeader::from_bytes(&data).unwrap();

        let mut writer = BinaryWriter::new(false); // big-endian
        header.write_to(&mut writer).unwrap();
        let written = writer.into_vec();

        assert_eq!(written, data);
    }

    #[test]
    fn test_fat_header_display() {
        let data = make_fat_header_bytes(&[(7, 3, 0x1000, 0x5000, 14)]);
        let header = FatHeader::from_bytes(&data).unwrap();
        let s = format!("{}", header);

        assert!(s.contains("0xCAFEBABE"));
        assert!(s.contains("nfat_arch=1"));
    }

    #[test]
    fn test_fat_header_is_not_swapped() {
        let data = make_fat_header_bytes(&[(7, 3, 0x1000, 0x5000, 14)]);
        let header = FatHeader::from_bytes(&data).unwrap();
        assert!(!header.is_swapped());
    }

    #[test]
    fn test_fat_header_empty_architectures() {
        let mut data = Vec::new();
        data.extend_from_slice(&FAT_MAGIC.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        let header = FatHeader::from_bytes(&data).unwrap();

        assert_eq!(header.fat_architecture_count(), 0);
        assert!(header.architectures().is_empty());
        assert_eq!(header.header_size(), 8);
    }

    #[test]
    fn test_fat_header_truncated() {
        let data = vec![0xCA, 0xFE, 0xBA, 0xBE]; // magic only, no count
        let result = FatHeader::from_bytes(&data);
        assert!(result.is_err());
    }
}
