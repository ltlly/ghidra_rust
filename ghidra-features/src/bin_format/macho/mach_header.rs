//! Mach-O header structure ported from Ghidra's
//! `ghidra.app.util.bin.format.macho.MachHeader`.
//!
//! Represents a `mach_header` / `mach_header_64` structure.
//!
//! Reference: <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>

use super::cpu_types::{CPU_ARCH_ABI64, CPU_TYPE_ARM};
use super::mach_constants::{self, is_little_endian, is_magic, MH_CIGAM, MH_CIGAM_64, MH_MAGIC, MH_MAGIC_64, NAME_LENGTH};
use super::mach_exception::MachException;
use super::mach_header_types::{self, MH_EXECUTE, MH_FILESET};
use super::relocation_info::RelocationInfo;
use super::section_types;

/// Maximum number of load commands to prevent runaway parsing.
const MAX_LOAD_COMMANDS: i32 = 32_768;

/// Represents a `mach_header` or `mach_header_64` structure.
#[derive(Debug, Clone)]
pub struct MachHeader {
    magic: u32,
    cpu_type: i32,
    cpu_sub_type: i32,
    file_type: u32,
    n_cmds: u32,
    size_of_cmds: u32,
    flags: u32,
    /// Only present in 64-bit Mach-O.
    reserved: u32,
    is_32bit: bool,
    /// Byte offset into the provider where this header starts.
    start_index_in_provider: u64,
    /// Start index for relative offset calculations (0 for dyld cache).
    start_index: u64,
    /// Byte offset of the first load command.
    command_index: u64,
}

impl MachHeader {
    /// Maximum number of load commands allowed.
    pub const MAX_LOAD_COMMANDS: i32 = MAX_LOAD_COMMANDS;

    /// Parses a MachHeader from the given bytes.
    ///
    /// `data` should point to the start of the Mach-O (or at `offset` within a larger buffer).
    /// `offset` is the byte offset where the Mach-O header begins in the provider.
    /// `is_remaining_relative` controls whether subsequent offsets are relative to `offset`.
    pub fn parse(
        data: &[u8],
        offset: u64,
        is_remaining_relative: bool,
    ) -> Result<Self, MachException> {
        if data.len() < (offset as usize) + 4 {
            return Err(MachException::new("Not enough data for Mach-O magic"));
        }
        let magic_off = offset as usize;
        let magic = u32::from_be_bytes([
            data[magic_off],
            data[magic_off + 1],
            data[magic_off + 2],
            data[magic_off + 3],
        ]);

        if !is_magic(magic) {
            return Err(MachException::new("Invalid Mach-O binary."));
        }

        let le = is_little_endian(magic);
        let is_64 = magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
        let is_32bit = !is_64;

        // Minimum header size: 7 u32s = 28 bytes (+ 4 for reserved in 64-bit)
        let header_size: usize = if is_32bit { 28 } else { 32 };
        if data.len() < (offset as usize) + header_size {
            return Err(MachException::new("Not enough data for Mach-O header"));
        }

        let mut pos = (offset as usize) + 4; // skip magic
        let cpu_type = read_i32(data, &mut pos, le);
        let cpu_sub_type = read_i32(data, &mut pos, le);
        let file_type = read_u32(data, &mut pos, le);
        let n_cmds = read_u32(data, &mut pos, le);
        let size_of_cmds = read_u32(data, &mut pos, le);
        let flags = read_u32(data, &mut pos, le);

        let reserved = if !is_32bit {
            read_u32(data, &mut pos, le)
        } else {
            0
        };

        let start_index = if is_remaining_relative { offset } else { 0 };
        let command_index = pos as u64;

        Ok(MachHeader {
            magic,
            cpu_type,
            cpu_sub_type,
            file_type,
            n_cmds,
            size_of_cmds,
            flags,
            reserved,
            is_32bit,
            start_index_in_provider: offset,
            start_index,
            command_index,
        })
    }

    /// Creates a MachHeader byte array.
    pub fn create(
        magic: u32,
        cpu_type: i32,
        cpu_sub_type: i32,
        file_type: u32,
        n_cmds: u32,
        size_of_cmds: u32,
        flags: u32,
        reserved: u32,
    ) -> Result<Vec<u8>, MachException> {
        if !is_magic(magic) {
            return Err(MachException::new(format!("Invalid magic: 0x{:x}", magic)));
        }

        let le = magic == MH_MAGIC || magic == MH_MAGIC_64;
        let is_64 = magic == MH_MAGIC_64 || magic == MH_CIGAM_64;
        let size: usize = if is_64 { 0x20 } else { 0x1C };
        let mut bytes = vec![0u8; size];

        let mut pos = 0;
        write_u32(&mut bytes, &mut pos, magic, le);
        write_i32(&mut bytes, &mut pos, cpu_type, le);
        write_i32(&mut bytes, &mut pos, cpu_sub_type, le);
        write_u32(&mut bytes, &mut pos, file_type, le);
        write_u32(&mut bytes, &mut pos, n_cmds, le);
        write_u32(&mut bytes, &mut pos, size_of_cmds, le);
        write_u32(&mut bytes, &mut pos, flags, le);
        if is_64 {
            write_u32(&mut bytes, &mut pos, reserved, le);
        }

        Ok(bytes)
    }

    /// Checks if the given data starts with a Mach-O magic number.
    pub fn is_mach_header(data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        is_magic(magic)
    }

    /// Returns the magic number.
    pub fn magic(&self) -> u32 {
        self.magic
    }

    /// Returns the CPU type.
    pub fn cpu_type(&self) -> i32 {
        self.cpu_type
    }

    /// Returns the CPU subtype.
    pub fn cpu_sub_type(&self) -> i32 {
        self.cpu_sub_type
    }

    /// Returns the file type.
    pub fn file_type(&self) -> u32 {
        self.file_type
    }

    /// Returns the number of load commands.
    pub fn number_of_commands(&self) -> u32 {
        self.n_cmds
    }

    /// Returns the total size of all load commands.
    pub fn size_of_commands(&self) -> u32 {
        self.size_of_cmds
    }

    /// Returns the flags.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns the reserved field (64-bit only).
    ///
    /// Returns `Err` if this is a 32-bit header.
    pub fn reserved(&self) -> Result<u32, MachException> {
        if self.is_32bit {
            Err(MachException::new(
                "Field does not exist for 32 bit Mach-O files.",
            ))
        } else {
            Ok(self.reserved)
        }
    }

    /// Returns the image base (always 0 for Mach-O).
    pub fn image_base(&self) -> u64 {
        0
    }

    /// Returns `true` if this is a 32-bit Mach-O.
    pub fn is_32bit(&self) -> bool {
        self.is_32bit
    }

    /// Returns the address size (4 for 32-bit, 8 for 64-bit).
    pub fn address_size(&self) -> u8 {
        if self.is_32bit { 4 } else { 8 }
    }

    /// Returns `true` if the data is little-endian.
    pub fn is_little_endian(&self) -> bool {
        is_little_endian(self.magic)
    }

    /// Returns the start index for offset calculations.
    pub fn start_index(&self) -> u64 {
        self.start_index
    }

    /// Returns the offset of this header in the provider.
    pub fn start_index_in_provider(&self) -> u64 {
        self.start_index_in_provider
    }

    /// Returns the byte offset of the first load command.
    pub fn command_index(&self) -> u64 {
        self.command_index
    }

    /// Returns the size of this header in bytes.
    pub fn size(&self) -> u64 {
        self.command_index - self.start_index_in_provider
    }

    /// Returns a human-readable description of the header.
    pub fn description(&self) -> String {
        format!(
            "Magic: 0x{:x}\nCPU Type: {} ({})\nFile Type: {} ({})\nFlags: 0b{:b}\n{}",
            self.magic,
            self.cpu_type,
            super::cpu_types::cpu_type_to_processor(self.cpu_type)
                .unwrap_or("unknown"),
            self.file_type,
            mach_header_types::file_type_name(self.file_type),
            self.flags,
            mach_header_types::get_flag_names(self.flags)
                .iter()
                .map(|f| format!("  {}\n", f))
                .collect::<String>(),
        )
    }

    /// Validates that the number of load commands is within bounds.
    pub fn validate_num_load_commands(&self) -> Result<(), MachException> {
        if self.n_cmds as i32 > MAX_LOAD_COMMANDS || (self.n_cmds as i32) < 0 {
            Err(MachException::new(format!(
                "Invalid number of load commands ({})",
                self.n_cmds
            )))
        } else {
            Ok(())
        }
    }
}

impl std::fmt::Display for MachHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn read_u32(data: &[u8], pos: &mut usize, le: bool) -> u32 {
    let val = if le {
        u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]])
    } else {
        u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]])
    };
    *pos += 4;
    val
}

fn read_i32(data: &[u8], pos: &mut usize, le: bool) -> i32 {
    read_u32(data, pos, le) as i32
}

fn write_u32(buf: &mut [u8], pos: &mut usize, val: u32, le: bool) {
    let bytes = if le { val.to_le_bytes() } else { val.to_be_bytes() };
    buf[*pos..*pos + 4].copy_from_slice(&bytes);
    *pos += 4;
}

fn write_i32(buf: &mut [u8], pos: &mut usize, val: i32, le: bool) {
    write_u32(buf, pos, val as u32, le);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_header_64_le() -> Vec<u8> {
        // 64-bit little-endian Mach-O header
        let mut data = Vec::new();
        data.extend_from_slice(&MH_CIGAM_64.to_le_bytes()); // magic (LE)
        data.extend_from_slice(&(0x0100_0000u32 | 7).to_le_bytes()); // CPU_TYPE_X86_64
        data.extend_from_slice(&3u32.to_le_bytes()); // cpuSubType
        data.extend_from_slice(&2u32.to_le_bytes()); // fileType = MH_EXECUTE
        data.extend_from_slice(&5u32.to_le_bytes()); // ncmds
        data.extend_from_slice(&500u32.to_le_bytes()); // sizeofcmds
        data.extend_from_slice(&0x0020_0000u32.to_le_bytes()); // flags = MH_PIE
        data.extend_from_slice(&0u32.to_le_bytes()); // reserved
        data
    }

    fn make_header_32_be() -> Vec<u8> {
        // 32-bit big-endian Mach-O header
        let mut data = Vec::new();
        data.extend_from_slice(&MH_MAGIC.to_be_bytes()); // magic (BE)
        data.extend_from_slice(&18i32.to_be_bytes()); // CPU_TYPE_POWERPC
        data.extend_from_slice(&0i32.to_be_bytes()); // cpuSubType
        data.extend_from_slice(&2u32.to_be_bytes()); // fileType = MH_EXECUTE
        data.extend_from_slice(&3u32.to_be_bytes()); // ncmds
        data.extend_from_slice(&200u32.to_be_bytes()); // sizeofcmds
        data.extend_from_slice(&0u32.to_be_bytes()); // flags
        data
    }

    #[test]
    fn test_parse_64bit_le() {
        let data = make_header_64_le();
        let hdr = MachHeader::parse(&data, 0, true).unwrap();
        assert!(!hdr.is_32bit());
        assert_eq!(hdr.address_size(), 8);
        assert!(hdr.is_little_endian());
        assert_eq!(hdr.cpu_type(), 0x0100_0007); // X86_64
        assert_eq!(hdr.file_type(), 2); // MH_EXECUTE
        assert_eq!(hdr.number_of_commands(), 5);
        assert_eq!(hdr.size_of_commands(), 500);
        assert!(hdr.reserved().is_ok());
        assert_eq!(hdr.reserved().unwrap(), 0);
    }

    #[test]
    fn test_parse_32bit_be() {
        let data = make_header_32_be();
        let hdr = MachHeader::parse(&data, 0, true).unwrap();
        assert!(hdr.is_32bit());
        assert_eq!(hdr.address_size(), 4);
        assert!(!hdr.is_little_endian());
        assert_eq!(hdr.cpu_type(), 18); // POWERPC
        assert_eq!(hdr.file_type(), 2); // MH_EXECUTE
        assert!(hdr.reserved().is_err());
    }

    #[test]
    fn test_invalid_magic() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert!(MachHeader::parse(&data, 0, true).is_err());
    }

    #[test]
    fn test_insufficient_data() {
        let data = vec![0xFE, 0xED, 0xFA]; // only 3 bytes
        assert!(MachHeader::parse(&data, 0, true).is_err());
    }

    #[test]
    fn test_is_mach_header() {
        let data = make_header_64_le();
        assert!(MachHeader::is_mach_header(&data));
        assert!(!MachHeader::is_mach_header(&[0xDE, 0xAD, 0xBE, 0xEF]));
        assert!(!MachHeader::is_mach_header(&[0x7F]));
    }

    #[test]
    fn test_create_and_roundtrip() {
        let bytes = MachHeader::create(
            MH_CIGAM_64, 0x0100_0007, 3, 2, 5, 500, 0x0020_0000, 0,
        )
        .unwrap();
        assert_eq!(bytes.len(), 0x20);
        let hdr = MachHeader::parse(&bytes, 0, true).unwrap();
        assert_eq!(hdr.cpu_type(), 0x0100_0007);
        assert_eq!(hdr.file_type(), 2);
    }

    #[test]
    fn test_create_invalid_magic() {
        assert!(MachHeader::create(0xDEADBEEF, 0, 0, 0, 0, 0, 0, 0).is_err());
    }

    #[test]
    fn test_description() {
        let data = make_header_64_le();
        let hdr = MachHeader::parse(&data, 0, true).unwrap();
        let desc = hdr.description();
        assert!(desc.contains("Magic:"));
        assert!(desc.contains("EXECUTE"));
    }

    #[test]
    fn test_validate_num_load_commands() {
        let data = make_header_64_le();
        let mut hdr = MachHeader::parse(&data, 0, true).unwrap();
        assert!(hdr.validate_num_load_commands().is_ok());
    }

    #[test]
    fn test_display() {
        let data = make_header_64_le();
        let hdr = MachHeader::parse(&data, 0, true).unwrap();
        let s = format!("{}", hdr);
        assert!(s.contains("Magic:"));
    }
}
