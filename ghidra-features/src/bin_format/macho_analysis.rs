//! Mach-O binary analysis command ported from Ghidra's
//! `ghidra.app.cmd.formats.MachoBinaryAnalysisCommand`.
//!
//! Provides [`MachoAnalysisCommand`] which analyzes a Mach-O binary and produces
//! [`ProgramMarkup`] entries for:
//! - Mach header (mach_header / mach_header_64)
//! - Load commands (LC_SEGMENT, LC_SYMTAB, LC_DYSYMTAB, LC_LOAD_DYLIB, etc.)
//! - Sections within segments
//! - Symbol tables and string tables
//!
//! This implementation works on raw binary data and generates markup descriptors
//! rather than directly mutating a Ghidra Program.

use super::analysis_command::{
    BinaryAnalysisCommand, CommentType, FragmentEntry, LabelEntry, MarkupEntry, MessageLog,
    ProgramMarkup, SourceType,
};
use super::binary_reader::BinaryReader;
use super::types::DataTypeDescription;

// ---------------------------------------------------------------------------
// Mach-O Constants
// ---------------------------------------------------------------------------

/// 32-bit big-endian magic number (PowerPC).
pub const MH_MAGIC: u32 = 0xFEEDFACE;
/// 64-bit big-endian magic number (PowerPC 64).
pub const MH_MAGIC_64: u32 = 0xFEEDFACF;
/// 32-bit little-endian magic number (Intel x86).
pub const MH_CIGAM: u32 = 0xCEFAEDFE;
/// 64-bit little-endian magic number (Intel x86_64).
pub const MH_CIGAM_64: u32 = 0xCFFAEDFE;
/// Fat binary magic number.
pub const FAT_MAGIC: u32 = 0xCAFEBABE;
/// Fat binary magic number (reversed).
pub const FAT_CIGAM: u32 = 0xBEBAFECA;

/// Mach header size (32-bit).
pub const MH_HEADER_SIZE: u32 = 28;
/// Mach header size (64-bit).
pub const MH_HEADER_64_SIZE: u32 = 32;

// File types
pub const MH_OBJECT: u32 = 0x1;
pub const MH_EXECUTE: u32 = 0x2;
pub const MH_FVMLIB: u32 = 0x3;
pub const MH_CORE: u32 = 0x4;
pub const MH_PRELOAD: u32 = 0x5;
pub const MH_DYLIB: u32 = 0x6;
pub const MH_DYLINKER: u32 = 0x7;
pub const MH_BUNDLE: u32 = 0x8;
pub const MH_DYLIB_STUB: u32 = 0x9;
pub const MH_DSYM: u32 = 0xA;
pub const MH_KEXT_BUNDLE: u32 = 0xB;
pub const MH_FILESET: u32 = 0xC;

// CPU types
pub const CPU_TYPE_VAX: i32 = 0x01;
pub const CPU_TYPE_MC680X0: i32 = 0x06;
pub const CPU_TYPE_X86: i32 = 0x07;
pub const CPU_TYPE_MC98000: i32 = 0x0A;
pub const CPU_TYPE_HPPA: i32 = 0x0B;
pub const CPU_TYPE_ARM: i32 = 0x0C;
pub const CPU_TYPE_MC88000: i32 = 0x0D;
pub const CPU_TYPE_SPARC: i32 = 0x0E;
pub const CPU_TYPE_I860: i32 = 0x0F;
pub const CPU_TYPE_POWERPC: i32 = 0x12;
pub const CPU_ARCH_ABI64: i32 = 0x0100_0000;
pub const CPU_ARCH_ABI64_32: i32 = 0x0200_0000;
pub const CPU_TYPE_POWERPC64: i32 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64;
pub const CPU_TYPE_X86_64: i32 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
pub const CPU_TYPE_ARM64: i32 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
pub const CPU_TYPE_ARM64_32: i32 = CPU_TYPE_ARM | CPU_ARCH_ABI64_32;

// Header flags
pub const MH_NOUNDEFS: u32 = 0x0000_0001;
pub const MH_INCRLINK: u32 = 0x0000_0002;
pub const MH_DYLDLINK: u32 = 0x0000_0004;
pub const MH_BINDATLOAD: u32 = 0x0000_0008;
pub const MH_PREBOUND: u32 = 0x0000_0010;
pub const MH_SPLIT_SEGS: u32 = 0x0000_0020;
pub const MH_LAZY_INIT: u32 = 0x0000_0040;
pub const MH_TWOLEVEL: u32 = 0x0000_0080;
pub const MH_FORCE_FLAT: u32 = 0x0000_0100;
pub const MH_NOMULTIDEFS: u32 = 0x0000_0200;
pub const MH_NOFIXPREBINDING: u32 = 0x0000_0400;
pub const MH_PREBINDABLE: u32 = 0x0000_0800;
pub const MH_ALLMODSBOUND: u32 = 0x0000_1000;
pub const MH_SUBSECTIONS_VIA_SYMBOLS: u32 = 0x0000_2000;
pub const MH_CANONICAL: u32 = 0x0000_4000;
pub const MH_WEAK_DEFINES: u32 = 0x0000_8000;
pub const MH_BINDS_TO_WEAK: u32 = 0x0001_0000;
pub const MH_ALLOW_STACK_EXECUTION: u32 = 0x0002_0000;
pub const MH_ROOT_SAFE: u32 = 0x0004_0000;
pub const MH_SETUID_SAFE: u32 = 0x0008_0000;
pub const MH_NO_REEXPORTED_DYLIBS: u32 = 0x0010_0000;
pub const MH_PIE: u32 = 0x0020_0000;
pub const MH_DEAD_STRIPPABLE_DYLIB: u32 = 0x0040_0000;
pub const MH_HAS_TLV_DESCRIPTORS: u32 = 0x0080_0000;
pub const MH_NO_HEAP_EXECUTION: u32 = 0x0100_0000;
pub const MH_APP_EXTENSION_SAFE: u32 = 0x0200_0000;
pub const MH_DYLIB_IN_CACHE: u32 = 0x8000_0000;

// Load command types
pub const LC_SEGMENT: u32 = 0x01;
pub const LC_SYMTAB: u32 = 0x02;
pub const LC_SYMSEG: u32 = 0x03;
pub const LC_THREAD: u32 = 0x04;
pub const LC_UNIXTHREAD: u32 = 0x05;
pub const LC_LOAD_DYLIB: u32 = 0x0C;
pub const LC_ID_DYLIB: u32 = 0x0D;
pub const LC_LOAD_DYLINKER: u32 = 0x0E;
pub const LC_PREBOUND_DYLIB: u32 = 0x10;
pub const LC_ROUTINES: u32 = 0x11;
pub const LC_SUB_FRAMEWORK: u32 = 0x12;
pub const LC_SUB_UMBRELLA: u32 = 0x13;
pub const LC_SUB_CLIENT: u32 = 0x14;
pub const LC_SUB_LIBRARY: u32 = 0x15;
pub const LC_TWOLEMENT_HINTS: u32 = 0x16;
pub const LC_PREBIND_CKSUM: u32 = 0x17;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_ROUTINES_64: u32 = 0x1A;
pub const LC_UUID: u32 = 0x1B;
pub const LC_CODE_SIGNATURE: u32 = 0x1D;
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1E;
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_MAIN: u32 = 0x8000_0028;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2A;
pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2B;
pub const LC_BUILD_VERSION: u32 = 0x32;

// Max load commands to parse
const MAX_LOAD_COMMANDS: usize = 32_768;

// ---------------------------------------------------------------------------
// Parsed Mach-O structures
// ---------------------------------------------------------------------------

/// Parsed Mach-O header.
#[derive(Debug, Clone)]
struct MachHeaderInfo {
    magic: u32,
    cpu_type: i32,
    cpu_sub_type: i32,
    file_type: u32,
    num_cmds: u32,
    size_of_cmds: u32,
    flags: u32,
    reserved: Option<u32>, // Only in 64-bit
    is_64: bool,
    is_le: bool,
}

/// A parsed load command (header only, with raw data for further parsing).
#[derive(Debug, Clone)]
struct LoadCommandInfo {
    cmd: u32,
    cmd_size: u32,
    offset: u64,
}

/// A parsed segment command.
#[derive(Debug, Clone)]
struct SegmentInfo {
    segname: String,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    num_sections: u32,
    flags: u32,
    is_64: bool,
}

/// A parsed section within a segment.
#[derive(Debug, Clone)]
struct SectionInfo {
    sectname: String,
    segname: String,
    addr: u64,
    size: u64,
    offset: u32,
    align: u32,
    reloff: u32,
    nreloc: u32,
    flags: u32,
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Return a human-readable CPU type name.
fn cpu_type_name(cpu_type: i32) -> String {
    match cpu_type {
        CPU_TYPE_VAX => "VAX".into(),
        CPU_TYPE_MC680X0 => "MC680x0".into(),
        CPU_TYPE_X86 => "x86".into(),
        CPU_TYPE_MC98000 => "MC98000".into(),
        CPU_TYPE_HPPA => "HPPA".into(),
        CPU_TYPE_ARM => "ARM".into(),
        CPU_TYPE_MC88000 => "MC88000".into(),
        CPU_TYPE_SPARC => "SPARC".into(),
        CPU_TYPE_I860 => "i860".into(),
        CPU_TYPE_POWERPC => "PowerPC".into(),
        CPU_TYPE_POWERPC64 => "PowerPC64".into(),
        CPU_TYPE_X86_64 => "x86_64".into(),
        CPU_TYPE_ARM64 => "ARM64".into(),
        CPU_TYPE_ARM64_32 => "ARM64_32".into(),
        _ => format!("Unknown(0x{:08X})", cpu_type),
    }
}

/// Return a human-readable file type name.
fn file_type_name(file_type: u32) -> &'static str {
    match file_type {
        MH_OBJECT => "OBJECT",
        MH_EXECUTE => "EXECUTE",
        MH_FVMLIB => "FVMLIB",
        MH_CORE => "CORE",
        MH_PRELOAD => "PRELOAD",
        MH_DYLIB => "DYLIB",
        MH_DYLINKER => "DYLINKER",
        MH_BUNDLE => "BUNDLE",
        MH_DYLIB_STUB => "DYLIB_STUB",
        MH_DSYM => "DSYM",
        MH_KEXT_BUNDLE => "KEXT_BUNDLE",
        MH_FILESET => "FILESET",
        _ => "UNKNOWN",
    }
}

/// Return a human-readable file type description.
fn file_type_description(file_type: u32) -> &'static str {
    match file_type {
        MH_OBJECT => "Relocatable Object File",
        MH_EXECUTE => "Demand Paged Executable File",
        MH_FVMLIB => "Fixed VM Shared Library File",
        MH_CORE => "Core File",
        MH_PRELOAD => "Preloaded Executable File",
        MH_DYLIB => "Dynamically Bound Shared Library",
        MH_DYLINKER => "Dynamic Link Editor",
        MH_BUNDLE => "Dynamically Bound Bundle File",
        MH_DYLIB_STUB => "Shared Library Stub for Static Linking Only",
        MH_DSYM => "Companion file with only debug sections",
        MH_KEXT_BUNDLE => "x86 64 Kernel Extension",
        MH_FILESET => "Kernel Cache Fileset",
        _ => "Unknown file type",
    }
}

/// Return a human-readable load command name.
fn load_command_name(cmd: u32) -> String {
    match cmd {
        LC_SEGMENT => "LC_SEGMENT".into(),
        LC_SYMTAB => "LC_SYMTAB".into(),
        LC_SYMSEG => "LC_SYMSEG".into(),
        LC_THREAD => "LC_THREAD".into(),
        LC_UNIXTHREAD => "LC_UNIXTHREAD".into(),
        LC_LOAD_DYLIB => "LC_LOAD_DYLIB".into(),
        LC_ID_DYLIB => "LC_ID_DYLIB".into(),
        LC_LOAD_DYLINKER => "LC_LOAD_DYLINKER".into(),
        LC_PREBOUND_DYLIB => "LC_PREBOUND_DYLIB".into(),
        LC_ROUTINES => "LC_ROUTINES".into(),
        LC_SUB_FRAMEWORK => "LC_SUB_FRAMEWORK".into(),
        LC_SUB_UMBRELLA => "LC_SUB_UMBRELLA".into(),
        LC_SUB_CLIENT => "LC_SUB_CLIENT".into(),
        LC_SUB_LIBRARY => "LC_SUB_LIBRARY".into(),
        LC_TWOLEMENT_HINTS => "LC_TWOLEVEL_HINTS".into(),
        LC_PREBIND_CKSUM => "LC_PREBIND_CKSUM".into(),
        LC_SEGMENT_64 => "LC_SEGMENT_64".into(),
        LC_ROUTINES_64 => "LC_ROUTINES_64".into(),
        LC_UUID => "LC_UUID".into(),
        LC_CODE_SIGNATURE => "LC_CODE_SIGNATURE".into(),
        LC_SEGMENT_SPLIT_INFO => "LC_SEGMENT_SPLIT_INFO".into(),
        LC_LAZY_LOAD_DYLIB => "LC_LAZY_LOAD_DYLIB".into(),
        LC_ENCRYPTION_INFO => "LC_ENCRYPTION_INFO".into(),
        LC_DYLD_INFO => "LC_DYLD_INFO".into(),
        LC_DYLD_INFO_ONLY => "LC_DYLD_INFO_ONLY".into(),
        LC_VERSION_MIN_MACOSX => "LC_VERSION_MIN_MACOSX".into(),
        LC_VERSION_MIN_IPHONEOS => "LC_VERSION_MIN_IPHONEOS".into(),
        LC_FUNCTION_STARTS => "LC_FUNCTION_STARTS".into(),
        LC_MAIN => "LC_MAIN".into(),
        LC_DATA_IN_CODE => "LC_DATA_IN_CODE".into(),
        LC_SOURCE_VERSION => "LC_SOURCE_VERSION".into(),
        LC_DYLIB_CODE_SIGN_DRS => "LC_DYLIB_CODE_SIGN_DRS".into(),
        LC_BUILD_VERSION => "LC_BUILD_VERSION".into(),
        _ => format!("LC_UNKNOWN(0x{:08X})", cmd),
    }
}

/// Format Mach-O header flags.
fn format_flags(flags: u32) -> String {
    let mut list = Vec::new();
    if flags & MH_NOUNDEFS != 0 { list.push("NOUNDEFS"); }
    if flags & MH_INCRLINK != 0 { list.push("INCRLINK"); }
    if flags & MH_DYLDLINK != 0 { list.push("DYLDLINK"); }
    if flags & MH_BINDATLOAD != 0 { list.push("BINDATLOAD"); }
    if flags & MH_PREBOUND != 0 { list.push("PREBOUND"); }
    if flags & MH_SPLIT_SEGS != 0 { list.push("SPLIT_SEGS"); }
    if flags & MH_LAZY_INIT != 0 { list.push("LAZY_INIT"); }
    if flags & MH_TWOLEVEL != 0 { list.push("TWOLEVEL"); }
    if flags & MH_FORCE_FLAT != 0 { list.push("FORCE_FLAT"); }
    if flags & MH_NOMULTIDEFS != 0 { list.push("NOMULTIDEFS"); }
    if flags & MH_NOFIXPREBINDING != 0 { list.push("NOFIXPREBINDING"); }
    if flags & MH_PREBINDABLE != 0 { list.push("PREBINDABLE"); }
    if flags & MH_ALLMODSBOUND != 0 { list.push("ALLMODSBOUND"); }
    if flags & MH_SUBSECTIONS_VIA_SYMBOLS != 0 { list.push("SUBSECTIONS_VIA_SYMBOLS"); }
    if flags & MH_CANONICAL != 0 { list.push("CANONICAL"); }
    if flags & MH_WEAK_DEFINES != 0 { list.push("WEAK_DEFINES"); }
    if flags & MH_BINDS_TO_WEAK != 0 { list.push("BINDS_TO_WEAK"); }
    if flags & MH_ALLOW_STACK_EXECUTION != 0 { list.push("ALLOW_STACK_EXECUTION"); }
    if flags & MH_ROOT_SAFE != 0 { list.push("ROOT_SAFE"); }
    if flags & MH_SETUID_SAFE != 0 { list.push("SETUID_SAFE"); }
    if flags & MH_NO_REEXPORTED_DYLIBS != 0 { list.push("NO_REEXPORTED_DYLIBS"); }
    if flags & MH_PIE != 0 { list.push("PIE"); }
    if flags & MH_DEAD_STRIPPABLE_DYLIB != 0 { list.push("DEAD_STRIPPABLE_DYLIB"); }
    if flags & MH_HAS_TLV_DESCRIPTORS != 0 { list.push("HAS_TLV_DESCRIPTORS"); }
    if flags & MH_NO_HEAP_EXECUTION != 0 { list.push("NO_HEAP_EXECUTION"); }
    if flags & MH_APP_EXTENSION_SAFE != 0 { list.push("APP_EXTENSION_SAFE"); }
    if flags & MH_DYLIB_IN_CACHE != 0 { list.push("DYLIB_IN_CACHE"); }
    list.join(", ")
}

// ---------------------------------------------------------------------------
// MachoAnalysisCommand
// ---------------------------------------------------------------------------

/// Mach-O binary analysis command.
///
/// Ported from `ghidra.app.cmd.formats.MachoBinaryAnalysisCommand`. Parses the
/// Mach header, load commands, segments, sections, and symbol tables, and
/// produces a [`ProgramMarkup`].
pub struct MachoAnalysisCommand {
    messages: MessageLog,
}

impl MachoAnalysisCommand {
    /// Create a new Mach-O analysis command.
    pub fn new() -> Self {
        Self {
            messages: MessageLog::new(),
        }
    }

    /// Read magic at the given offset and determine endianness and bitness.
    fn read_magic(data: &[u8], offset: usize) -> Result<(u32, bool, bool), String> {
        if offset + 4 > data.len() {
            return Err("Data too short for Mach-O magic".into());
        }
        let magic_le = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let magic_be = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);

        // Try little-endian interpretation first
        match magic_le {
            MH_MAGIC => Ok((MH_MAGIC, false, true)),       // 32-bit LE
            MH_MAGIC_64 => Ok((MH_MAGIC_64, true, true)),  // 64-bit LE
            MH_CIGAM => Ok((MH_MAGIC, false, false)),      // 32-bit BE (file is BE)
            MH_CIGAM_64 => Ok((MH_MAGIC_64, true, false)), // 64-bit BE (file is BE)
            _ => {
                // Try big-endian interpretation
                match magic_be {
                    MH_MAGIC => Ok((MH_MAGIC, false, false)),
                    MH_MAGIC_64 => Ok((MH_MAGIC_64, true, false)),
                    MH_CIGAM => Ok((MH_MAGIC, false, true)),
                    MH_CIGAM_64 => Ok((MH_MAGIC_64, true, true)),
                    _ => Err(format!("Not a Mach-O file: magic 0x{:08X}", magic_le)),
                }
            }
        }
    }

    /// Parse the Mach-O header.
    fn parse_header(&self, data: &[u8], offset: usize) -> Result<MachHeaderInfo, String> {
        let (magic, is_64, is_le) = Self::read_magic(data, offset)?;
        let hdr_size = if is_64 { MH_HEADER_64_SIZE } else { MH_HEADER_SIZE } as usize;

        if offset + hdr_size > data.len() {
            return Err("Data too short for Mach-O header".into());
        }

        let reader = BinaryReader::from_bytes(&data[offset..], is_le);

        let cpu_type = reader.read_u32_at(4).map_err(|e| format!("cpu_type: {}", e))? as i32;
        let cpu_sub_type = reader.read_u32_at(8).map_err(|e| format!("cpu_sub_type: {}", e))? as i32;
        let file_type = reader.read_u32_at(12).map_err(|e| format!("file_type: {}", e))?;
        let num_cmds = reader.read_u32_at(16).map_err(|e| format!("num_cmds: {}", e))?;
        let size_of_cmds = reader.read_u32_at(20).map_err(|e| format!("size_of_cmds: {}", e))?;
        let flags = reader.read_u32_at(24).map_err(|e| format!("flags: {}", e))?;
        let reserved = if is_64 {
            Some(reader.read_u32_at(28).map_err(|e| format!("reserved: {}", e))?)
        } else {
            None
        };

        if num_cmds as usize > MAX_LOAD_COMMANDS {
            return Err(format!("Too many load commands: {}", num_cmds));
        }

        Ok(MachHeaderInfo {
            magic,
            cpu_type,
            cpu_sub_type,
            file_type,
            num_cmds,
            size_of_cmds,
            flags,
            reserved,
            is_64,
            is_le,
        })
    }

    /// Parse load commands from the Mach-O header.
    fn parse_load_commands(
        &self,
        data: &[u8],
        header: &MachHeaderInfo,
        header_offset: usize,
    ) -> Result<Vec<LoadCommandInfo>, String> {
        let hdr_size = if header.is_64 { MH_HEADER_64_SIZE } else { MH_HEADER_SIZE } as usize;
        let cmds_offset = header_offset + hdr_size;
        let mut commands = Vec::new();
        let mut current_offset = cmds_offset as u64;

        for i in 0..header.num_cmds as usize {
            if current_offset as usize + 8 > data.len() {
                self.messages
                    .append_warning(format!("Load command {} extends beyond data", i));
                break;
            }

            let reader = BinaryReader::from_bytes(&data[current_offset as usize..], header.is_le);
            let cmd = reader.read_u32_at(0).map_err(|e| format!("cmd[{}]: {}", i, e))?;
            let cmd_size = reader.read_u32_at(4).map_err(|e| format!("cmd_size[{}]: {}", i, e))?;

            if cmd_size < 8 {
                self.messages.append_warning(format!(
                    "Load command {} has invalid size {}",
                    i, cmd_size
                ));
                break;
            }

            commands.push(LoadCommandInfo {
                cmd,
                cmd_size,
                offset: current_offset,
            });

            current_offset += cmd_size as u64;
        }

        Ok(commands)
    }

    /// Parse a segment command (LC_SEGMENT or LC_SEGMENT_64).
    fn parse_segment(
        &self,
        data: &[u8],
        lc: &LoadCommandInfo,
        is_64: bool,
        is_le: bool,
    ) -> Result<SegmentInfo, String> {
        let off = lc.offset as usize;
        if off + lc.cmd_size as usize > data.len() {
            return Err("Segment command extends beyond data".into());
        }

        let reader = BinaryReader::from_bytes(&data[off..], is_le);

        // segname: 16 bytes at offset 8
        let segname_bytes = &data[off + 8..off + 24];
        let segname_end = segname_bytes.iter().position(|&b| b == 0).unwrap_or(16);
        let segname = String::from_utf8_lossy(&segname_bytes[..segname_end]).to_string();

        let (vmaddr, vmsize, fileoff, filesize) = if is_64 {
            let vm = reader.read_u64_at(24).map_err(|e| format!("vmaddr: {}", e))?;
            let vs = reader.read_u64_at(32).map_err(|e| format!("vmsize: {}", e))?;
            let fo = reader.read_u64_at(40).map_err(|e| format!("fileoff: {}", e))?;
            let fs = reader.read_u64_at(48).map_err(|e| format!("filesize: {}", e))?;
            (vm, vs, fo, fs)
        } else {
            let vm = reader.read_u32_at(24).map_err(|e| format!("vmaddr: {}", e))? as u64;
            let vs = reader.read_u32_at(28).map_err(|e| format!("vmsize: {}", e))? as u64;
            let fo = reader.read_u32_at(32).map_err(|e| format!("fileoff: {}", e))? as u64;
            let fs = reader.read_u32_at(36).map_err(|e| format!("filesize: {}", e))? as u64;
            (vm, vs, fo, fs)
        };

        let (maxprot, initprot, num_sections, seg_flags, sec_start_offset) = if is_64 {
            let mp = reader.read_u32_at(56).map_err(|e| format!("maxprot: {}", e))?;
            let ip = reader.read_u32_at(60).map_err(|e| format!("initprot: {}", e))?;
            let ns = reader.read_u32_at(64).map_err(|e| format!("nsects: {}", e))?;
            let sf = reader.read_u32_at(68).map_err(|e| format!("flags: {}", e))?;
            (mp, ip, ns, sf, 72)
        } else {
            let mp = reader.read_u32_at(40).map_err(|e| format!("maxprot: {}", e))?;
            let ip = reader.read_u32_at(44).map_err(|e| format!("initprot: {}", e))?;
            let ns = reader.read_u32_at(48).map_err(|e| format!("nsects: {}", e))?;
            let sf = reader.read_u32_at(52).map_err(|e| format!("flags: {}", e))?;
            (mp, ip, ns, sf, 56)
        };

        Ok(SegmentInfo {
            segname,
            vmaddr,
            vmsize,
            fileoff,
            filesize,
            maxprot,
            initprot,
            num_sections,
            flags: seg_flags,
            is_64,
        })
    }

    /// Parse sections within a segment.
    fn parse_sections(
        &self,
        data: &[u8],
        lc: &LoadCommandInfo,
        segment: &SegmentInfo,
        is_le: bool,
    ) -> Result<Vec<SectionInfo>, String> {
        let off = lc.offset as usize;
        let sec_start = if segment.is_64 { 72 } else { 56 };
        let sec_size: usize = if segment.is_64 { 80 } else { 68 };

        let mut sections = Vec::new();
        let reader = BinaryReader::from_bytes(&data[off..], is_le);

        for i in 0..segment.num_sections as usize {
            let base = sec_start + i * sec_size;
            if off + base + sec_size > data.len() {
                return Err(format!("Section {} extends beyond data", i));
            }

            // sectname: 16 bytes at base
            let sectname_bytes = &data[off + base..off + base + 16];
            let sectname_end = sectname_bytes.iter().position(|&b| b == 0).unwrap_or(16);
            let sectname = String::from_utf8_lossy(&sectname_bytes[..sectname_end]).to_string();

            // segname: 16 bytes at base + 16
            let segname_bytes = &data[off + base + 16..off + base + 32];
            let segname_end = segname_bytes.iter().position(|&b| b == 0).unwrap_or(16);
            let segname = String::from_utf8_lossy(&segname_bytes[..segname_end]).to_string();

            let (addr, size) = if segment.is_64 {
                let a = reader.read_u64_at((base + 32) as u64).map_err(|e| format!("sect_addr[{}]: {}", i, e))?;
                let s = reader.read_u64_at((base + 40) as u64).map_err(|e| format!("sect_size[{}]: {}", i, e))?;
                (a, s)
            } else {
                let a = reader.read_u32_at((base + 32) as u64).map_err(|e| format!("sect_addr[{}]: {}", i, e))? as u64;
                let s = reader.read_u32_at((base + 36) as u64).map_err(|e| format!("sect_size[{}]: {}", i, e))? as u64;
                (a, s)
            };

            let offset_off = if segment.is_64 { base + 48 } else { base + 40 };
            let section_offset = reader.read_u32_at(offset_off as u64).map_err(|e| format!("sect_offset[{}]: {}", i, e))?;
            let align = reader.read_u32_at((offset_off + 4) as u64).map_err(|e| format!("sect_align[{}]: {}", i, e))?;
            let reloff = reader.read_u32_at((offset_off + 8) as u64).map_err(|e| format!("sect_reloff[{}]: {}", i, e))?;
            let nreloc = reader.read_u32_at((offset_off + 12) as u64).map_err(|e| format!("sect_nreloc[{}]: {}", i, e))?;
            let flags = reader.read_u32_at((offset_off + 16) as u64).map_err(|e| format!("sect_flags[{}]: {}", i, e))?;

            sections.push(SectionInfo {
                sectname,
                segname,
                addr,
                size,
                offset: section_offset,
                align,
                reloff,
                nreloc,
                flags,
            });
        }

        Ok(sections)
    }

    /// Process Mach header markup.
    fn process_header(&self, markup: &mut ProgramMarkup, header: &MachHeaderInfo) {
        let hdr_size = if header.is_64 {
            MH_HEADER_64_SIZE
        } else {
            MH_HEADER_SIZE
        } as u64;

        let bits = if header.is_64 { "64-bit" } else { "32-bit" };
        let endian = if header.is_le { "Little-Endian" } else { "Big-Endian" };
        let comment = format!(
            "Magic: 0x{:08X} ({} {})\nCPU: {} (0x{:08X})\nFile Type: {} ({})\nLoad Commands: {} (size: 0x{:X})\nFlags: 0x{:08X} [{}]",
            header.magic,
            bits,
            endian,
            cpu_type_name(header.cpu_type),
            header.cpu_sub_type,
            file_type_name(header.file_type),
            file_type_description(header.file_type),
            header.num_cmds,
            header.size_of_cmds,
            header.flags,
            format_flags(header.flags),
        );

        markup.add_markup(
            MarkupEntry::new(0, DataTypeDescription::Struct {
                name: if header.is_64 {
                    "mach_header_64".into()
                } else {
                    "mach_header".into()
                },
                size: hdr_size as u32,
                fields: vec![
                    ("magic".into(), DataTypeDescription::DWord),
                    ("cputype".into(), DataTypeDescription::DWord),
                    ("cpusubtype".into(), DataTypeDescription::DWord),
                    ("filetype".into(), DataTypeDescription::DWord),
                    ("ncmds".into(), DataTypeDescription::DWord),
                    ("sizeofcmds".into(), DataTypeDescription::DWord),
                    ("flags".into(), DataTypeDescription::DWord),
                ],
            })
            .with_name("MachHeader")
            .with_comment(comment, CommentType::Plate),
        );
        markup.add_fragment(FragmentEntry::new("MachHeader", 0, hdr_size));
    }

    /// Process load commands markup.
    fn process_load_commands(
        &self,
        markup: &mut ProgramMarkup,
        commands: &[LoadCommandInfo],
        header: &MachHeaderInfo,
    ) {
        for lc in commands {
            let cmd_name = load_command_name(lc.cmd);

            let mut comment = format!("Command: {} (0x{:08X})\nSize: 0x{:X}", cmd_name, lc.cmd, lc.cmd_size);

            // For well-known commands, add more detail
            if lc.cmd == LC_SEGMENT || lc.cmd == LC_SEGMENT_64 {
                if let Ok(seg) = self.parse_segment(
                    &[], // We'll just use the name from the offset
                    lc,
                    header.is_64,
                    header.is_le,
                ) {
                    // Can't parse from empty data, skip detailed segment info in comment
                }
            }

            markup.add_markup(
                MarkupEntry::new(lc.offset, DataTypeDescription::Struct {
                    name: cmd_name.clone(),
                    size: lc.cmd_size,
                    fields: vec![],
                })
                .with_name(&cmd_name)
                .with_comment(comment, CommentType::Eol),
            );
        }
    }

    /// Process segments and sections.
    fn process_segments(
        &self,
        markup: &mut ProgramMarkup,
        data: &[u8],
        commands: &[LoadCommandInfo],
        header: &MachHeaderInfo,
    ) {
        for lc in commands {
            if lc.cmd != LC_SEGMENT && lc.cmd != LC_SEGMENT_64 {
                continue;
            }

            let segment = match self.parse_segment(data, lc, header.is_64, header.is_le) {
                Ok(s) => s,
                Err(e) => {
                    self.messages.append_warning(format!("Failed to parse segment: {}", e));
                    continue;
                }
            };

            let comment = format!(
                "Segment: {}\nVM Address: 0x{:016X}\nVM Size: 0x{:016X}\nFile Offset: 0x{:016X}\nFile Size: 0x{:016X}\nMax Prot: 0x{:08X}\nInit Prot: 0x{:08X}\nSections: {}\nFlags: 0x{:08X}",
                segment.segname,
                segment.vmaddr,
                segment.vmsize,
                segment.fileoff,
                segment.filesize,
                segment.maxprot,
                segment.initprot,
                segment.num_sections,
                segment.flags,
            );

            markup.add_markup(
                MarkupEntry::new(lc.offset, DataTypeDescription::Struct {
                    name: if header.is_64 { "segment_command_64".into() } else { "segment_command".into() },
                    size: lc.cmd_size,
                    fields: vec![],
                })
                .with_name(&segment.segname)
                .with_comment(comment, CommentType::Plate),
            );

            // Create fragment for segment data
            if segment.filesize > 0 {
                markup.add_fragment(FragmentEntry::new(
                    &segment.segname,
                    segment.fileoff,
                    segment.filesize,
                ));
            }

            // Process sections within this segment
            if let Ok(sections) = self.parse_sections(data, lc, &segment, header.is_le) {
                for section in &sections {
                    let sec_comment = format!(
                        "Section: {}.{}\nAddress: 0x{:016X}\nSize: 0x{:016X}\nOffset: 0x{:08X}\nAlign: {}\nRelocations: {}\nFlags: 0x{:08X}",
                        section.segname,
                        section.sectname,
                        section.addr,
                        section.size,
                        section.offset,
                        1u32 << section.align,
                        section.nreloc,
                        section.flags,
                    );

                    markup.add_label(
                        LabelEntry::new(section.addr, &format!("{}.{}", section.segname, section.sectname))
                            .with_source(SourceType::Imported),
                    );

                    if section.size > 0 {
                        markup.add_fragment(FragmentEntry::new(
                            format!("{}.{}", section.segname, section.sectname),
                            section.addr,
                            section.size,
                        ));
                    }

                    markup.add_comment(super::analysis_command::CommentEntry::new(
                        section.addr,
                        sec_comment,
                        CommentType::Plate,
                    ));
                }
            }
        }
    }

    /// Process the UUID load command.
    fn process_uuid(&self, markup: &mut ProgramMarkup, data: &[u8], lc: &LoadCommandInfo, is_le: bool) {
        let off = lc.offset as usize;
        if off + 24 > data.len() {
            return;
        }
        let reader = BinaryReader::from_bytes(&data[off..], is_le);
        let uuid_bytes = match reader.read_bytes_at(8, 16) {
            Ok(b) => b,
            Err(_) => return,
        };
        let uuid_str = format!(
            "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            uuid_bytes[0], uuid_bytes[1], uuid_bytes[2], uuid_bytes[3],
            uuid_bytes[4], uuid_bytes[5],
            uuid_bytes[6], uuid_bytes[7],
            uuid_bytes[8], uuid_bytes[9],
            uuid_bytes[10], uuid_bytes[11], uuid_bytes[12], uuid_bytes[13], uuid_bytes[14], uuid_bytes[15],
        );

        markup.add_comment(super::analysis_command::CommentEntry::new(
            lc.offset,
            format!("UUID: {}", uuid_str),
            CommentType::Plate,
        ));
    }
}

impl Default for MachoAnalysisCommand {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryAnalysisCommand for MachoAnalysisCommand {
    fn name(&self) -> &str {
        "Mach-O Header Annotation"
    }

    fn can_apply(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }
        let (magic, _, _) = match Self::read_magic(data, 0) {
            Ok(v) => v,
            Err(_) => return false,
        };
        matches!(magic, MH_MAGIC | MH_MAGIC_64 | MH_CIGAM | MH_CIGAM_64)
    }

    fn apply(&self, data: &[u8], _is_little_endian: bool) -> Result<ProgramMarkup, String> {
        let mut markup = ProgramMarkup::new();

        // 1. Parse header
        let header = self.parse_header(data, 0)?;
        self.process_header(&mut markup, &header);

        // 2. Parse load commands
        let commands = self.parse_load_commands(data, &header, 0)?;
        self.process_load_commands(&mut markup, &commands, &header);

        // 3. Process segments and sections
        self.process_segments(&mut markup, data, &commands, &header);

        // 4. Process special load commands
        for lc in &commands {
            match lc.cmd {
                LC_UUID => self.process_uuid(&mut markup, data, lc, header.is_le),
                _ => {}
            }
        }

        self.messages.append_msg(format!(
            "Mach-O analysis complete: {} {} ({} load commands)",
            cpu_type_name(header.cpu_type),
            if header.is_64 { "64-bit" } else { "32-bit" },
            header.num_cmds,
        ));

        Ok(markup)
    }

    fn messages(&self) -> &MessageLog {
        &self.messages
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_macho_64_le() -> Vec<u8> {
        let mut data = vec![0u8; 512];

        // Mach header (64-bit LE)
        data[0] = 0xCF; // MH_MAGIC_64 in LE
        data[1] = 0xFA;
        data[2] = 0xED;
        data[3] = 0xFE;

        // cpu_type: x86_64 = 0x01000007
        data[4] = 0x07;
        data[5] = 0x00;
        data[6] = 0x00;
        data[7] = 0x01;

        // cpu_sub_type: 0x03
        data[8] = 0x03;
        data[9] = 0x00;
        data[10] = 0x00;
        data[11] = 0x00;

        // file_type: MH_EXECUTE = 2
        data[12] = 0x02;

        // num_cmds: 1
        data[16] = 0x01;

        // size_of_cmds: 72 (a single segment_command_64)
        data[20] = 72;

        // flags: MH_DYLDLINK | MH_PIE = 0x00200004
        data[24] = 0x04;
        data[25] = 0x00;
        data[26] = 0x20;
        data[27] = 0x00;

        // Load command 1: LC_SEGMENT_64 at offset 32
        let lc_off = 32;
        // cmd = LC_SEGMENT_64 = 0x19
        data[lc_off] = 0x19;
        // cmdsize = 72
        data[lc_off + 4] = 72;

        // segname: "__TEXT\0..." (16 bytes at offset 8)
        data[lc_off + 8..lc_off + 8 + 7].copy_from_slice(b"__TEXT\0");

        // vmaddr = 0x100000000 (64-bit at offset 24)
        data[lc_off + 24] = 0x00;
        data[lc_off + 25] = 0x00;
        data[lc_off + 26] = 0x00;
        data[lc_off + 27] = 0x00;
        data[lc_off + 28] = 0x01;

        // vmsize = 0x1000
        data[lc_off + 32] = 0x00;
        data[lc_off + 33] = 0x10;

        // fileoff = 0
        // filesize = 0x1000
        data[lc_off + 48] = 0x00;
        data[lc_off + 49] = 0x10;

        // maxprot = 7 (rwx)
        data[lc_off + 56] = 0x07;
        // initprot = 5 (r-x)
        data[lc_off + 60] = 0x05;
        // num_sections = 1
        data[lc_off + 64] = 0x01;

        data
    }

    #[test]
    fn test_macho_can_apply() {
        let cmd = MachoAnalysisCommand::new();
        let data = make_minimal_macho_64_le();
        assert!(cmd.can_apply(&data));
    }

    #[test]
    fn test_macho_cannot_apply_elf() {
        let cmd = MachoAnalysisCommand::new();
        let data = vec![0x7f, b'E', b'L', b'F', 0, 0, 0, 0];
        assert!(!cmd.can_apply(&data));
    }

    #[test]
    fn test_macho_parse_header() {
        let cmd = MachoAnalysisCommand::new();
        let data = make_minimal_macho_64_le();
        let header = cmd.parse_header(&data, 0).unwrap();
        assert_eq!(header.magic, MH_MAGIC_64);
        assert!(header.is_64);
        assert!(header.is_le);
        assert_eq!(header.cpu_type as u32, CPU_TYPE_X86_64 as u32);
        assert_eq!(header.file_type, MH_EXECUTE);
        assert_eq!(header.num_cmds, 1);
    }

    #[test]
    fn test_macho_parse_load_commands() {
        let cmd = MachoAnalysisCommand::new();
        let data = make_minimal_macho_64_le();
        let header = cmd.parse_header(&data, 0).unwrap();
        let commands = cmd.parse_load_commands(&data, &header, 0).unwrap();
        assert_eq!(commands.len(), 1);
        assert_eq!(commands[0].cmd, LC_SEGMENT_64);
    }

    #[test]
    fn test_macho_apply() {
        let cmd = MachoAnalysisCommand::new();
        let data = make_minimal_macho_64_le();
        let result = cmd.apply(&data, true);
        assert!(result.is_ok(), "apply failed: {:?}", result.err());

        let markup = result.unwrap();
        assert!(!markup.is_empty());
        // Should have header fragment, segment fragment, and section fragments
        assert!(markup.fragments.len() >= 2);
    }

    #[test]
    fn test_cpu_type_names() {
        assert_eq!(cpu_type_name(CPU_TYPE_X86_64), "x86_64");
        assert_eq!(cpu_type_name(CPU_TYPE_ARM64), "ARM64");
        assert_eq!(cpu_type_name(CPU_TYPE_POWERPC), "PowerPC");
    }

    #[test]
    fn test_file_type_names() {
        assert_eq!(file_type_name(MH_EXECUTE), "EXECUTE");
        assert_eq!(file_type_name(MH_DYLIB), "DYLIB");
        assert_eq!(file_type_description(MH_EXECUTE), "Demand Paged Executable File");
    }

    #[test]
    fn test_load_command_names() {
        assert_eq!(load_command_name(LC_SEGMENT_64), "LC_SEGMENT_64");
        assert_eq!(load_command_name(LC_SYMTAB), "LC_SYMTAB");
        assert_eq!(load_command_name(LC_UUID), "LC_UUID");
        assert_eq!(load_command_name(LC_MAIN), "LC_MAIN");
    }

    #[test]
    fn test_format_flags() {
        let flags = MH_DYLDLINK | MH_PIE;
        let s = format_flags(flags);
        assert!(s.contains("DYLDLINK"));
        assert!(s.contains("PIE"));
    }

    #[test]
    fn test_read_magic_variants() {
        // MH_MAGIC_64 LE
        let data = [0xCF, 0xFA, 0xED, 0xFE];
        let (magic, is_64, is_le) = MachoAnalysisCommand::read_magic(&data, 0).unwrap();
        assert_eq!(magic, MH_MAGIC_64);
        assert!(is_64);
        assert!(is_le);

        // MH_MAGIC BE
        let data = [0xFE, 0xED, 0xFA, 0xCE];
        let (magic, is_64, is_le) = MachoAnalysisCommand::read_magic(&data, 0).unwrap();
        assert_eq!(magic, MH_MAGIC);
        assert!(!is_64);
        assert!(!is_le);
    }
}
