//! Fat architecture entry ported from Ghidra's `FatArch.java`.
//!
//! Represents a single `fat_arch` structure within a Mach-O Universal
//! Binary (fat) header. Each entry describes one architecture slice
//! (CPU type, subtype, file offset, size, and alignment).

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;
use crate::bin_format::binary_writer::{BinaryWritable, BinaryWriter};
use crate::bin_format::types::{DataTypeDescription, StructConverter};

/// Size of a single `fat_arch` entry in bytes (5 x i32 = 20 bytes).
pub const SIZEOF_FAT_ARCH: usize = 20;

/// Represents a `fat_arch` structure.
///
/// Ported from `ghidra.app.util.bin.format.ubi.FatArch`.
///
/// Each entry is 20 bytes:
/// ```text
/// int32_t  cputype;     // CPU type (e.g., x86_64, arm64)
/// int32_t  cpusubtype;  // CPU subtype
/// uint32_t offset;      // File offset to this object file
/// uint32_t size;        // Size of this object file
/// uint32_t align;       // Alignment as a power of 2
/// ```
///
/// See: <https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/fat.h.auto.html>
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FatArch {
    /// CPU type identifier (e.g., 7 = x86, 12 = arm64).
    pub cputype: i32,
    /// CPU subtype identifier.
    pub cpusubtype: i32,
    /// File offset to this object file slice.
    pub offset: u32,
    /// Size of this object file slice in bytes.
    pub size: u32,
    /// Alignment as a power of 2.
    pub align: u32,
}

impl FatArch {
    /// Parse a `fat_arch` entry from a binary reader.
    ///
    /// The reader must be positioned at the start of a 20-byte `fat_arch`
    /// record. The reader's endianness should match the fat header
    /// (typically big-endian for fat binaries).
    pub fn parse(reader: &mut BinaryReader) -> io::Result<Self> {
        Ok(Self {
            cputype: reader.read_next_i32()?,
            cpusubtype: reader.read_next_i32()?,
            offset: reader.read_next_u32()?,
            size: reader.read_next_u32()?,
            align: reader.read_next_u32()?,
        })
    }

    /// Returns the CPU type.
    pub fn cpu_type(&self) -> i32 {
        self.cputype
    }

    /// Returns the CPU subtype.
    pub fn cpu_sub_type(&self) -> i32 {
        self.cpusubtype
    }

    /// Returns the file offset to this object file.
    pub fn file_offset(&self) -> u32 {
        self.offset
    }

    /// Returns the size of this object file.
    pub fn file_size(&self) -> u32 {
        self.size
    }

    /// Returns the alignment as a power of 2.
    pub fn alignment(&self) -> u32 {
        self.align
    }

    /// Returns the alignment as a byte count (2^align).
    pub fn alignment_bytes(&self) -> u64 {
        1u64 << self.align
    }
}

impl StructConverter for FatArch {
    fn to_data_type(&self) -> DataTypeDescription {
        DataTypeDescription::Struct {
            name: "fat_arch".to_string(),
            size: 20,
            fields: vec![
                ("cputype".into(), DataTypeDescription::DWord),
                ("cpusubtype".into(), DataTypeDescription::DWord),
                ("offset".into(), DataTypeDescription::DWord),
                ("size".into(), DataTypeDescription::DWord),
                ("align".into(), DataTypeDescription::DWord),
            ],
        }
    }
}

impl BinaryWritable for FatArch {
    fn write_to(&self, writer: &mut BinaryWriter) -> io::Result<()> {
        writer.write_i32(self.cputype);
        writer.write_i32(self.cpusubtype);
        writer.write_u32(self.offset);
        writer.write_u32(self.size);
        writer.write_u32(self.align);
        Ok(())
    }
}

impl fmt::Display for FatArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FatArch {{ cpu=0x{:08X}, sub=0x{:08X}, offset=0x{:08X}, size=0x{:08X}, align={} }}",
            self.cputype, self.cpusubtype, self.offset, self.size, self.align
        )
    }
}

// ---------------------------------------------------------------------------
// CPU type constants (common subset from mach/machine.h)
// ---------------------------------------------------------------------------

/// CPU type constants for Mach-O fat headers.
///
/// These are a subset of the constants defined in `<mach/machine.h>`.
pub mod cpu_types {
    /// Motorola 68k (historical).
    pub const CPU_TYPE_MC680X0: i32 = 6;
    /// Intel x86 (32-bit).
    pub const CPU_TYPE_X86: i32 = 7;
    /// Intel x86-64.
    pub const CPU_TYPE_X86_64: i32 = CPU_TYPE_X86 | 0x01000000;
    /// ARM (32-bit).
    pub const CPU_TYPE_ARM: i32 = 12;
    /// ARM64 / AArch64.
    pub const CPU_TYPE_ARM64: i32 = CPU_TYPE_ARM | 0x01000000;
    /// PowerPC.
    pub const CPU_TYPE_POWERPC: i32 = 18;
    /// PowerPC 64-bit.
    pub const CPU_TYPE_POWERPC64: i32 = CPU_TYPE_POWERPC | 0x01000000;

    /// Returns a human-readable name for a CPU type, if known.
    pub fn cpu_type_name(cputype: i32) -> Option<&'static str> {
        match cputype {
            CPU_TYPE_MC680X0 => Some("m68k"),
            CPU_TYPE_X86 => Some("x86"),
            CPU_TYPE_X86_64 => Some("x86_64"),
            CPU_TYPE_ARM => Some("arm"),
            CPU_TYPE_ARM64 => Some("arm64"),
            CPU_TYPE_POWERPC => Some("ppc"),
            CPU_TYPE_POWERPC64 => Some("ppc64"),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fat_arch_bytes(cputype: i32, cpusubtype: i32, offset: u32, size: u32, align: u32) -> Vec<u8> {
        let mut data = Vec::with_capacity(SIZEOF_FAT_ARCH);
        data.extend_from_slice(&cputype.to_be_bytes());
        data.extend_from_slice(&cpusubtype.to_be_bytes());
        data.extend_from_slice(&offset.to_be_bytes());
        data.extend_from_slice(&size.to_be_bytes());
        data.extend_from_slice(&align.to_be_bytes());
        data
    }

    #[test]
    fn test_parse_fat_arch() {
        let data = make_fat_arch_bytes(7, 3, 0x1000, 0x5000, 14);
        let mut reader = BinaryReader::from_bytes(&data, false); // big-endian
        let arch = FatArch::parse(&mut reader).unwrap();

        assert_eq!(arch.cputype, 7);
        assert_eq!(arch.cpusubtype, 3);
        assert_eq!(arch.offset, 0x1000);
        assert_eq!(arch.size, 0x5000);
        assert_eq!(arch.align, 14);
    }

    #[test]
    fn test_fat_arch_accessors() {
        let data = make_fat_arch_bytes(12 | 0x01000000, 0, 0x2000, 0x8000, 15);
        let mut reader = BinaryReader::from_bytes(&data, false);
        let arch = FatArch::parse(&mut reader).unwrap();

        assert_eq!(arch.cpu_type(), 12 | 0x01000000);
        assert_eq!(arch.cpu_sub_type(), 0);
        assert_eq!(arch.file_offset(), 0x2000);
        assert_eq!(arch.file_size(), 0x8000);
        assert_eq!(arch.alignment(), 15);
        assert_eq!(arch.alignment_bytes(), 32768);
    }

    #[test]
    fn test_fat_arch_struct_converter() {
        let data = make_fat_arch_bytes(7, 3, 0x1000, 0x5000, 14);
        let mut reader = BinaryReader::from_bytes(&data, false);
        let arch = FatArch::parse(&mut reader).unwrap();

        let dt = arch.to_data_type();
        match &dt {
            DataTypeDescription::Struct { name, fields, .. } => {
                assert_eq!(name, "fat_arch");
                assert_eq!(fields.len(), 5);
                assert_eq!(fields[0].0, "cputype");
                assert_eq!(fields[1].0, "cpusubtype");
                assert_eq!(fields[2].0, "offset");
                assert_eq!(fields[3].0, "size");
                assert_eq!(fields[4].0, "align");
            }
            _ => panic!("Expected Struct"),
        }
    }

    #[test]
    fn test_fat_arch_write_roundtrip() {
        let data = make_fat_arch_bytes(7, 3, 0x1000, 0x5000, 14);
        let mut reader = BinaryReader::from_bytes(&data, false);
        let arch = FatArch::parse(&mut reader).unwrap();

        let mut writer = BinaryWriter::new(false); // big-endian
        arch.write_to(&mut writer).unwrap();
        let written = writer.into_vec();

        assert_eq!(written, data);
    }

    #[test]
    fn test_fat_arch_display() {
        let data = make_fat_arch_bytes(7, 3, 0x1000, 0x5000, 14);
        let mut reader = BinaryReader::from_bytes(&data, false);
        let arch = FatArch::parse(&mut reader).unwrap();
        let s = format!("{}", arch);

        assert!(s.contains("0x00000007")); // cputype
        assert!(s.contains("0x00001000")); // offset
    }

    #[test]
    fn test_fat_arch_clone_eq() {
        let data = make_fat_arch_bytes(7, 3, 0x1000, 0x5000, 14);
        let mut reader = BinaryReader::from_bytes(&data, false);
        let arch = FatArch::parse(&mut reader).unwrap();
        let arch2 = arch.clone();
        assert_eq!(arch, arch2);
    }

    #[test]
    fn test_cpu_type_names() {
        use super::cpu_types::*;
        assert_eq!(cpu_type_name(CPU_TYPE_X86), Some("x86"));
        assert_eq!(cpu_type_name(CPU_TYPE_X86_64), Some("x86_64"));
        assert_eq!(cpu_type_name(CPU_TYPE_ARM), Some("arm"));
        assert_eq!(cpu_type_name(CPU_TYPE_ARM64), Some("arm64"));
        assert_eq!(cpu_type_name(CPU_TYPE_POWERPC), Some("ppc"));
        assert_eq!(cpu_type_name(999), None);
    }

    #[test]
    fn test_fat_arch_truncated_data() {
        let data = vec![0u8; 10]; // too short
        let mut reader = BinaryReader::from_bytes(&data, false);
        assert!(FatArch::parse(&mut reader).is_err());
    }
}
