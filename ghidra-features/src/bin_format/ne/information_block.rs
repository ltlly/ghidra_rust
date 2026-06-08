//! NE Information Block (IMAGE_OS2_HEADER) ported from Ghidra's
//! `ghidra.app.util.bin.format.ne.InformationBlock`.
//!
//! Represents the main header of a Windows New Executable (NE format),
//! defined in WINNT.H as `IMAGE_OS2_HEADER`.

use std::fmt;
use std::io;

use crate::bin_format::binary_reader::BinaryReader;

use super::InvalidWindowsHeaderError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// NE signature: "NE" = 0x454E
pub const IMAGE_NE_SIGNATURE: u16 = 0x454E;

// Program flags
pub const FLAGS_PROG_NO_AUTO_DATA: u8 = 0x00;
pub const FLAGS_PROG_SINGLE_DATA: u8 = 0x01;
pub const FLAGS_PROG_MULTIPLE_DATA: u8 = 0x02;
pub const FLAGS_PROG_GLOBAL_INIT: u8 = 0x04;
pub const FLAGS_PROG_PROTECTED_MODE: u8 = 0x08;
pub const FLAGS_PROG_8086: u8 = 0x10;
pub const FLAGS_PROG_80286: u8 = 0x20;
pub const FLAGS_PROG_80386: u8 = 0x40;
pub const FLAGS_PROG_80X87: u8 = 0x80;

// Application flags
pub const FLAGS_APP_FULL_SCREEN: u8 = 0x01;
pub const FLAGS_APP_WIN_PM_COMPATIBLE: u8 = 0x02;
pub const FLAGS_APP_WINDOWS_PM: u8 = 0x03;
pub const FLAGS_APP_LOAD_CODE: u8 = 0x08;
pub const FLAGS_APP_LINK_ERRS: u8 = 0x20;
pub const FLAGS_APP_NONCONFORMING_PROG: u8 = 0x40;
pub const FLAGS_APP_LIBRARY_MODULE: u8 = 0x80;

// Executable type constants
pub const EXETYPE_UNKNOWN: u8 = 0x00;
pub const EXETYPE_OS2: u8 = 0x01;
pub const EXETYPE_WINDOWS: u8 = 0x02;
pub const EXETYPE_EUROPEAN_DOS_4: u8 = 0x04;
pub const EXETYPE_RESERVED4: u8 = 0x08;
pub const EXETYPE_WINDOWS_386: u8 = 0x04;
pub const EXETYPE_BOSS: u8 = 0x05;
pub const EXETYPE_PHARLAP_286_OS2: u8 = 0x81;
pub const EXETYPE_PHARLAP_286_WIN: u8 = 0x82;

// Other flags
pub const OTHER_FLAGS_SUPPORTS_LONG_NAMES: u8 = 0x00;
pub const OTHER_FLAGS_PROTECTED_MODE: u8 = 0x01;
pub const OTHER_FLAGS_PROPORTIONAL_FONT: u8 = 0x02;
pub const OTHER_FLAGS_GANGLOAD_AREA: u8 = 0x04;

// ---------------------------------------------------------------------------
// InformationBlock
// ---------------------------------------------------------------------------

/// The NE header information block (IMAGE_OS2_HEADER).
///
/// This structure contains all the metadata for a Windows New Executable,
/// including segment counts, table offsets, entry point, and flags.
///
/// ```text
/// typedef struct _IMAGE_OS2_HEADER {
///     WORD   ne_magic;         // Magic number (0x454E = "NE")
///     CHAR   ne_ver;           // Version number
///     CHAR   ne_rev;           // Revision number
///     WORD   ne_enttab;        // Offset of Entry Table
///     WORD   ne_cbenttab;      // Number of bytes in Entry Table
///     LONG   ne_crc;           // Checksum of whole file
///     WORD   ne_flags;         // Flag word
///     WORD   ne_autodata;      // Automatic data segment number
///     WORD   ne_heap;          // Initial heap allocation
///     WORD   ne_stack;         // Initial stack allocation
///     LONG   ne_csip;          // Initial CS:IP setting
///     LONG   ne_sssp;          // Initial SS:SP setting
///     WORD   ne_cseg;          // Count of file segments
///     WORD   ne_cmod;          // Entries in Module Reference Table
///     WORD   ne_cbnrestab;     // Size of non-resident name table
///     WORD   ne_segtab;        // Offset of Segment Table
///     WORD   ne_rsrctab;       // Offset of Resource Table
///     WORD   ne_restab;        // Offset of resident name table
///     WORD   ne_modtab;        // Offset of Module Reference Table
///     WORD   ne_imptab;        // Offset of Imported Names Table
///     LONG   ne_nrestab;       // Offset of Non-resident Names Table
///     WORD   ne_cmovent;       // Count of movable entries
///     WORD   ne_align;         // Segment alignment shift count
///     WORD   ne_cres;          // Count of resource segments
///     BYTE   ne_exetyp;        // Target Operating system
///     BYTE   ne_flagsothers;   // Other .EXE flags
///     WORD   ne_pretthunks;    // offset to return thunks
///     WORD   ne_psegrefbytes;  // offset to segment ref. bytes
///     WORD   ne_swaparea;      // Minimum code swap area size
///     WORD   ne_expver;        // Expected Windows version number
/// } IMAGE_OS2_HEADER;
/// ```
#[derive(Debug, Clone)]
pub struct InformationBlock {
    ne_magic: u16,
    ne_ver: u8,
    ne_rev: u8,
    ne_enttab: u16,
    ne_cbenttab: u16,
    ne_crc: i32,
    ne_flags_prog: u8,
    ne_flags_app: u8,
    ne_autodata: u16,
    ne_heap: u16,
    ne_stack: u16,
    ne_csip: i32,
    ne_sssp: i32,
    ne_cseg: u16,
    ne_cmod: u16,
    ne_cbnrestab: u16,
    ne_segtab: u16,
    ne_rsrctab: u16,
    ne_restab: u16,
    ne_modtab: u16,
    ne_imptab: u16,
    ne_nrestab: i32,
    ne_cmovent: u16,
    ne_align: u16,
    ne_cres: u16,
    ne_exetyp: u8,
    ne_flagsothers: u8,
    ne_pretthunks: u16,
    ne_psegrefbytes: u16,
    ne_swaparea: u16,
    ne_expver: u16,
}

impl InformationBlock {
    /// Parse an information block from the reader at the given index.
    pub fn parse(reader: &mut BinaryReader, index: u64) -> Result<Self, InvalidWindowsHeaderError> {
        let old_index = reader.cursor();
        reader.set_cursor(index);

        let ne_magic = match reader.read_next_u16() {
            Ok(v) => v,
            Err(_) => {
                reader.set_cursor(old_index);
                return Err(InvalidWindowsHeaderError);
            }
        };

        if ne_magic != IMAGE_NE_SIGNATURE {
            reader.set_cursor(old_index);
            return Err(InvalidWindowsHeaderError);
        }

        let ne_ver = reader.read_next_u8().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_rev = reader.read_next_u8().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_enttab = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_cbenttab = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_crc = reader.read_next_i32().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_flags_prog = reader.read_next_u8().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_flags_app = reader.read_next_u8().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_autodata = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_heap = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_stack = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_csip = reader.read_next_i32().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_sssp = reader.read_next_i32().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_cseg = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_cmod = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_cbnrestab = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_segtab = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_rsrctab = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_restab = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_modtab = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_imptab = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_nrestab = reader.read_next_i32().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_cmovent = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_align = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_cres = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_exetyp = reader.read_next_u8().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_flagsothers = reader.read_next_u8().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_pretthunks = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_psegrefbytes = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_swaparea = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;
        let ne_expver = reader.read_next_u16().map_err(|_| InvalidWindowsHeaderError)?;

        reader.set_cursor(old_index);

        Ok(Self {
            ne_magic,
            ne_ver,
            ne_rev,
            ne_enttab,
            ne_cbenttab,
            ne_crc,
            ne_flags_prog,
            ne_flags_app,
            ne_autodata,
            ne_heap,
            ne_stack,
            ne_csip,
            ne_sssp,
            ne_cseg,
            ne_cmod,
            ne_cbnrestab,
            ne_segtab,
            ne_rsrctab,
            ne_restab,
            ne_modtab,
            ne_imptab,
            ne_nrestab,
            ne_cmovent,
            ne_align,
            ne_cres,
            ne_exetyp,
            ne_flagsothers,
            ne_pretthunks,
            ne_psegrefbytes,
            ne_swaparea,
            ne_expver,
        })
    }

    /// Returns the magic number (should be 0x454E).
    pub fn magic(&self) -> u16 {
        self.ne_magic
    }

    /// Returns the version number.
    pub fn version(&self) -> u8 {
        self.ne_ver
    }

    /// Returns the revision number.
    pub fn revision(&self) -> u8 {
        self.ne_rev
    }

    /// Returns the checksum.
    pub fn checksum(&self) -> i32 {
        self.ne_crc
    }

    /// Returns the initial heap size.
    pub fn initial_heap_size(&self) -> u16 {
        self.ne_heap
    }

    /// Returns the initial stack size.
    pub fn initial_stack_size(&self) -> u16 {
        self.ne_stack
    }

    /// Returns the target operating system type.
    pub fn target_op_sys(&self) -> u8 {
        self.ne_exetyp
    }

    /// Returns the minimum code swap size.
    pub fn min_code_swap_size(&self) -> u16 {
        self.ne_swaparea
    }

    /// Returns the expected Windows version.
    pub fn expected_windows_version(&self) -> u16 {
        self.ne_expver
    }

    /// Returns the automatic data segment number.
    pub fn automatic_data_segment(&self) -> u16 {
        self.ne_autodata
    }

    /// Returns the other flags byte.
    pub fn other_flags(&self) -> u8 {
        self.ne_flagsothers
    }

    /// Returns the program flags.
    pub fn program_flags(&self) -> u8 {
        self.ne_flags_prog
    }

    /// Returns the application flags.
    pub fn application_flags(&self) -> u8 {
        self.ne_flags_app
    }

    /// Returns the segment portion of the initial CS:IP entry point.
    pub fn entry_point_segment(&self) -> u16 {
        ((self.ne_csip >> 16) & 0xffff) as u16
    }

    /// Returns the offset portion of the initial CS:IP entry point.
    pub fn entry_point_offset(&self) -> u16 {
        (self.ne_csip & 0xffff) as u16
    }

    /// Returns the segment portion of the initial SS:SP stack pointer.
    pub fn stack_pointer_segment(&self) -> u16 {
        ((self.ne_sssp >> 16) & 0xffff) as u16
    }

    /// Returns the offset portion of the initial SS:SP stack pointer.
    pub fn stack_pointer_offset(&self) -> u16 {
        (self.ne_sssp & 0xffff) as u16
    }

    // --- Package-level accessors (matching Java's package-private) ---

    /// Offset of segment table, relative to NE header start.
    pub fn segment_table_offset(&self) -> u16 {
        self.ne_segtab
    }

    /// Number of segments.
    pub fn segment_count(&self) -> u16 {
        self.ne_cseg
    }

    /// Segment alignment shift count (log2 of segment sector size).
    pub fn segment_alignment_shift_count(&self) -> u16 {
        self.ne_align
    }

    /// Offset of resource table, relative to NE header start.
    pub fn resource_table_offset(&self) -> u16 {
        self.ne_rsrctab
    }

    /// Offset of resident name table, relative to NE header start.
    pub fn resident_name_table_offset(&self) -> u16 {
        self.ne_restab
    }

    /// Offset of module reference table, relative to NE header start.
    pub fn module_reference_table_offset(&self) -> u16 {
        self.ne_modtab
    }

    /// Number of entries in the module reference table.
    pub fn module_reference_table_count(&self) -> u16 {
        self.ne_cmod
    }

    /// Offset of imported names table, relative to NE header start.
    pub fn imported_names_table_offset(&self) -> u16 {
        self.ne_imptab
    }

    /// Offset of entry table, relative to NE header start.
    pub fn entry_table_offset(&self) -> u16 {
        self.ne_enttab
    }

    /// Number of bytes in the entry table.
    pub fn entry_table_size(&self) -> u16 {
        self.ne_cbenttab
    }

    /// Offset of non-resident name table, relative to beginning of file.
    pub fn non_resident_name_table_offset(&self) -> i32 {
        self.ne_nrestab
    }

    /// Number of bytes in the non-resident name table.
    pub fn non_resident_name_table_size(&self) -> u16 {
        self.ne_cbnrestab
    }

    /// Count of movable entries.
    pub fn moveable_entries_count(&self) -> u16 {
        self.ne_cmovent
    }

    /// Count of resource segments.
    pub fn resource_segment_count(&self) -> u16 {
        self.ne_cres
    }

    /// Offset to return thunks.
    pub fn return_offset_thunk(&self) -> u16 {
        self.ne_pretthunks
    }

    /// Offset to segment reference bytes.
    pub fn segment_ref_byte_offset(&self) -> u16 {
        self.ne_psegrefbytes
    }

    /// Returns a human-readable string for the target OS.
    pub fn target_op_sys_as_string(&self) -> &str {
        match self.ne_exetyp {
            EXETYPE_UNKNOWN => "Unknown",
            EXETYPE_OS2 => "OS/2",
            EXETYPE_WINDOWS => "Windows",
            EXETYPE_RESERVED4 => "Reserved 4",
            EXETYPE_WINDOWS_386 => "Windows 386",
            EXETYPE_BOSS => "Borland Operating System Services",
            EXETYPE_PHARLAP_286_OS2 => "Pharlap 286 OS/2",
            EXETYPE_PHARLAP_286_WIN => "Pharlap 286 Windows",
            _ => "Unknown",
        }
    }

    /// Returns a human-readable description of application flags.
    pub fn application_flags_as_string(&self) -> String {
        let mut parts = Vec::new();
        let app_type = self.ne_flags_app & 0x03;
        if app_type == FLAGS_APP_FULL_SCREEN {
            parts.push("Full Screen");
        } else if app_type == FLAGS_APP_WIN_PM_COMPATIBLE {
            parts.push("Windows P.M. API Compatible");
        } else if app_type == FLAGS_APP_WINDOWS_PM {
            parts.push("Windows P.M. API");
        }
        if self.ne_flags_app & FLAGS_APP_LIBRARY_MODULE != 0 {
            parts.push("Library Module");
        }
        if self.ne_flags_app & FLAGS_APP_LINK_ERRS != 0 {
            parts.push("Link Errors");
        }
        if self.ne_flags_app & FLAGS_APP_LOAD_CODE != 0 {
            parts.push("Load Code");
        }
        if self.ne_flags_app & FLAGS_APP_NONCONFORMING_PROG != 0 {
            parts.push("Nonconforming");
        }
        parts.join("\n")
    }

    /// Returns a human-readable description of program flags.
    pub fn program_flags_as_string(&self) -> String {
        let mut parts = Vec::new();
        if self.ne_flags_prog & FLAGS_PROG_80286 != 0 {
            parts.push("80286");
        }
        if self.ne_flags_prog & FLAGS_PROG_80386 != 0 {
            parts.push("80386");
        }
        if self.ne_flags_prog & FLAGS_PROG_8086 != 0 {
            parts.push("8086");
        }
        if self.ne_flags_prog & FLAGS_PROG_GLOBAL_INIT != 0 {
            parts.push("Global Init");
        }
        if self.ne_flags_prog & FLAGS_PROG_SINGLE_DATA != 0 {
            parts.push("Single Data");
        }
        if self.ne_flags_prog & FLAGS_PROG_MULTIPLE_DATA != 0 {
            parts.push("Multi Data");
        }
        if self.ne_flags_prog & FLAGS_PROG_NO_AUTO_DATA != 0 {
            parts.push("No Auto Data");
        }
        if self.ne_flags_prog & FLAGS_PROG_PROTECTED_MODE != 0 {
            parts.push("Protected Mode");
        }
        parts.join("\n")
    }

    /// Returns a human-readable description of other flags.
    pub fn other_flags_as_string(&self) -> String {
        let mut parts = Vec::new();
        if self.ne_flagsothers & OTHER_FLAGS_GANGLOAD_AREA != 0 {
            parts.push("Gangload Area");
        }
        if self.ne_flagsothers & OTHER_FLAGS_PROPORTIONAL_FONT != 0 {
            parts.push("Proportional Font");
        }
        if self.ne_flagsothers & OTHER_FLAGS_PROTECTED_MODE != 0 {
            parts.push("Protected Mode");
        }
        if self.ne_flagsothers & OTHER_FLAGS_SUPPORTS_LONG_NAMES != 0 {
            parts.push("Long Name Support");
        }
        parts.join("\n")
    }
}

impl fmt::Display for InformationBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InformationBlock {{ magic=0x{:04X}, ver={}, rev={}, segments={}, entry=0x{:04X}:0x{:04X} }}",
            self.ne_magic,
            self.ne_ver,
            self.ne_rev,
            self.ne_cseg,
            self.entry_point_segment(),
            self.entry_point_offset()
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_info_block_bytes() -> Vec<u8> {
        // Build a minimal valid IMAGE_OS2_HEADER (64 bytes total)
        let mut data = vec![0u8; 64];

        // ne_magic = 0x454E (little-endian)
        data[0] = 0x4E;
        data[1] = 0x45;

        // ne_ver = 5, ne_rev = 1
        data[2] = 5;
        data[3] = 1;

        // ne_enttab = 0x0040 (offset to entry table)
        data[4] = 0x40;
        data[5] = 0x00;

        // ne_cbenttab = 0x0100 (entry table size)
        data[6] = 0x00;
        data[7] = 0x01;

        // ne_crc = 0
        data[8..12].fill(0);

        // ne_flags (program=0x01 single data, app=0x00)
        data[12] = FLAGS_PROG_SINGLE_DATA;
        data[13] = 0x00;

        // ne_autodata = 2
        data[14] = 0x02;
        data[15] = 0x00;

        // ne_heap = 0x0800
        data[16] = 0x00;
        data[17] = 0x08;

        // ne_stack = 0x1000
        data[18] = 0x00;
        data[19] = 0x10;

        // ne_csip = 0x0001:0x0100 (segment 1, offset 0x100)
        data[20] = 0x00;
        data[21] = 0x01;
        data[22] = 0x01;
        data[23] = 0x00;

        // ne_sssp = 0x0002:0x0200 (segment 2, offset 0x200)
        data[24] = 0x00;
        data[25] = 0x02;
        data[26] = 0x02;
        data[27] = 0x00;

        // ne_cseg = 3
        data[28] = 0x03;
        data[29] = 0x00;

        // ne_cmod = 1
        data[30] = 0x01;
        data[31] = 0x00;

        // ne_cbnrestab = 0x0020
        data[32] = 0x20;
        data[33] = 0x00;

        // ne_segtab = 0x0040
        data[34] = 0x40;
        data[35] = 0x00;

        // ne_rsrctab = 0x0060
        data[36] = 0x60;
        data[37] = 0x00;

        // ne_restab = 0x0080
        data[38] = 0x80;
        data[39] = 0x00;

        // ne_modtab = 0x00A0
        data[40] = 0xA0;
        data[41] = 0x00;

        // ne_imptab = 0x00B0
        data[42] = 0xB0;
        data[43] = 0x00;

        // ne_nrestab = 0x0200 (relative to file start)
        data[44] = 0x00;
        data[45] = 0x02;
        data[46] = 0x00;
        data[47] = 0x00;

        // ne_cmovent = 2
        data[48] = 0x02;
        data[49] = 0x00;

        // ne_align = 4 (shift count, 1<<4 = 16 byte alignment)
        data[50] = 0x04;
        data[51] = 0x00;

        // ne_cres = 1
        data[52] = 0x01;
        data[53] = 0x00;

        // ne_exetyp = EXETYPE_WINDOWS (0x02)
        data[54] = EXETYPE_WINDOWS;

        // ne_flagsothers = 0
        data[55] = 0x00;

        // ne_pretthunks = 0
        data[56] = 0x00;
        data[57] = 0x00;

        // ne_psegrefbytes = 0
        data[58] = 0x00;
        data[59] = 0x00;

        // ne_swaparea = 0x0200
        data[60] = 0x00;
        data[61] = 0x02;

        // ne_expver = 0x030A (Windows 3.10)
        data[62] = 0x0A;
        data[63] = 0x03;

        data
    }

    #[test]
    fn test_parse_information_block() {
        let data = make_info_block_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let block = InformationBlock::parse(&mut reader, 0).unwrap();

        assert_eq!(block.magic(), IMAGE_NE_SIGNATURE);
        assert_eq!(block.version(), 5);
        assert_eq!(block.revision(), 1);
        assert_eq!(block.segment_count(), 3);
        assert_eq!(block.automatic_data_segment(), 2);
        assert_eq!(block.initial_heap_size(), 0x0800);
        assert_eq!(block.initial_stack_size(), 0x1000);
        assert_eq!(block.target_op_sys(), EXETYPE_WINDOWS);
        assert_eq!(block.expected_windows_version(), 0x030A);
        assert_eq!(block.segment_alignment_shift_count(), 4);
    }

    #[test]
    fn test_entry_point() {
        let data = make_info_block_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let block = InformationBlock::parse(&mut reader, 0).unwrap();

        assert_eq!(block.entry_point_segment(), 1);
        assert_eq!(block.entry_point_offset(), 0x0100);
    }

    #[test]
    fn test_stack_pointer() {
        let data = make_info_block_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let block = InformationBlock::parse(&mut reader, 0).unwrap();

        assert_eq!(block.stack_pointer_segment(), 2);
        assert_eq!(block.stack_pointer_offset(), 0x0200);
    }

    #[test]
    fn test_table_offsets() {
        let data = make_info_block_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let block = InformationBlock::parse(&mut reader, 0).unwrap();

        assert_eq!(block.segment_table_offset(), 0x0040);
        assert_eq!(block.resource_table_offset(), 0x0060);
        assert_eq!(block.resident_name_table_offset(), 0x0080);
        assert_eq!(block.module_reference_table_offset(), 0x00A0);
        assert_eq!(block.imported_names_table_offset(), 0x00B0);
        assert_eq!(block.entry_table_offset(), 0x0040);
        assert_eq!(block.entry_table_size(), 0x0100);
        assert_eq!(block.non_resident_name_table_offset(), 0x0200);
    }

    #[test]
    fn test_target_os_string() {
        let data = make_info_block_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let block = InformationBlock::parse(&mut reader, 0).unwrap();

        assert_eq!(block.target_op_sys_as_string(), "Windows");
    }

    #[test]
    fn test_invalid_signature() {
        let mut data = make_info_block_bytes();
        // Corrupt the magic
        data[0] = 0x00;
        data[1] = 0x00;
        let mut reader = BinaryReader::from_bytes(&data, true);
        let result = InformationBlock::parse(&mut reader, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_display() {
        let data = make_info_block_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let block = InformationBlock::parse(&mut reader, 0).unwrap();

        let s = format!("{}", block);
        assert!(s.contains("0x454E"));
        assert!(s.contains("segments=3"));
    }

    #[test]
    fn test_program_flags_string() {
        let data = make_info_block_bytes();
        let mut reader = BinaryReader::from_bytes(&data, true);
        let block = InformationBlock::parse(&mut reader, 0).unwrap();

        let flags = block.program_flags_as_string();
        assert!(flags.contains("Single Data"));
    }

    #[test]
    fn test_program_flags_multiple() {
        let mut data = make_info_block_bytes();
        // Set multiple program flags: 80286 | ProtectedMode | SingleData
        data[12] = FLAGS_PROG_80286 | FLAGS_PROG_PROTECTED_MODE | FLAGS_PROG_SINGLE_DATA;
        let mut reader = BinaryReader::from_bytes(&data, true);
        let block = InformationBlock::parse(&mut reader, 0).unwrap();

        let flags = block.program_flags_as_string();
        assert!(flags.contains("80286"));
        assert!(flags.contains("Protected Mode"));
        assert!(flags.contains("Single Data"));
    }

    #[test]
    fn test_application_flags_library() {
        let mut data = make_info_block_bytes();
        data[13] = FLAGS_APP_FULL_SCREEN | FLAGS_APP_LIBRARY_MODULE;
        let mut reader = BinaryReader::from_bytes(&data, true);
        let block = InformationBlock::parse(&mut reader, 0).unwrap();

        let flags = block.application_flags_as_string();
        assert!(flags.contains("Full Screen"));
        assert!(flags.contains("Library Module"));
    }

    #[test]
    fn test_other_flags() {
        let mut data = make_info_block_bytes();
        data[55] = OTHER_FLAGS_PROPORTIONAL_FONT | OTHER_FLAGS_PROTECTED_MODE;
        let mut reader = BinaryReader::from_bytes(&data, true);
        let block = InformationBlock::parse(&mut reader, 0).unwrap();

        let flags = block.other_flags_as_string();
        assert!(flags.contains("Proportional Font"));
        assert!(flags.contains("Protected Mode"));
    }
}
