//! PE (Portable Executable) constants ported from Ghidra's
//! `ghidra.app.util.bin.format.pe.Constants`,
//! `ghidra.app.util.bin.format.pe.MachineConstants`, and
//! `ghidra.app.util.bin.format.pe.MachineName`.
//!
//! Provides all constant values used in PE file format data structures,
//! machine type identifiers, and utility functions for resolving machine names.

// ---------------------------------------------------------------------------
// Constants from ghidra.app.util.bin.format.pe.Constants
// ---------------------------------------------------------------------------

/// A 64-bit ordinal flag.
pub const IMAGE_ORDINAL_FLAG64: u64 = 0x8000_0000_0000_0000;

/// A 32-bit ordinal flag.
pub const IMAGE_ORDINAL_FLAG32: u32 = 0x8000_0000;

/// The magic number for PE files: "PE\0\0" (0x00004550).
pub const IMAGE_NT_SIGNATURE: u32 = 0x0000_4550;

/// The magic number for OS/2 files: "NE" (0x454E).
pub const IMAGE_OS2_SIGNATURE: u16 = 0x454E;

/// The magic number for little endian OS/2 files: "LE" (0x454C).
pub const IMAGE_OS2_SIGNATURE_LE: u16 = 0x454C;

/// The magic number for VXD files: "LE" (0x454C).
pub const IMAGE_VXD_SIGNATURE: u16 = 0x454C;

/// The 32-bit optional header magic number.
pub const IMAGE_NT_OPTIONAL_HDR32_MAGIC: u16 = 0x10B;

/// The 64-bit optional header magic number.
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20B;

/// The ROM optional header magic number.
pub const IMAGE_ROM_OPTIONAL_HDR_MAGIC: u16 = 0x107;

/// The size of the ROM optional header.
pub const IMAGE_SIZEOF_ROM_OPTIONAL_HEADER: usize = 56;

/// The size of the standard optional header.
pub const IMAGE_SIZEOF_STD_OPTIONAL_HEADER: usize = 28;

/// The size of the 32-bit optional header, in bytes.
pub const IMAGE_SIZEOF_NT_OPTIONAL32_HEADER: usize = 224;

/// The size of the 64-bit optional header, in bytes.
pub const IMAGE_SIZEOF_NT_OPTIONAL64_HEADER: usize = 240;

/// The size of the archive start header.
pub const IMAGE_ARCHIVE_START_SIZE: usize = 8;

/// The archive start magic value.
pub const IMAGE_ARCHIVE_START: &[u8] = b"!<arch>\n";

/// The archive end magic value.
pub const IMAGE_ARCHIVE_END: &[u8] = b"`\n";

/// The archive padding.
pub const IMAGE_ARCHIVE_PAD: &[u8] = b"\n";

/// The archive linker member.
pub const IMAGE_ARCHIVE_LINKER_MEMBER: &[u8] = b"/               ";

/// The archive long names member.
pub const IMAGE_ARCHIVE_LONGNAMES_MEMBER: &[u8] = b"//              ";

// ---------------------------------------------------------------------------
// DOS header constants
// ---------------------------------------------------------------------------

/// DOS signature: "MZ" (0x5A4D).
pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D;

/// Size of IMAGE_DOS_HEADER in bytes.
pub const IMAGE_DOS_HEADER_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// File header constants
// ---------------------------------------------------------------------------

/// Size of IMAGE_FILE_HEADER in bytes.
pub const IMAGE_FILE_HEADER_SIZE: usize = 20;

/// Size of a section header entry.
pub const IMAGE_SIZEOF_SECTION_HEADER: usize = 40;

/// Size of short name in section header.
pub const IMAGE_SIZEOF_SHORT_NAME: usize = 8;

/// Maximum number of data directories.
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

// ---------------------------------------------------------------------------
// File header characteristics flags
// ---------------------------------------------------------------------------

/// Image only, Windows CE, and Microsoft Windows NT and later.
/// This indicates that the file does not contain base relocations
/// and must therefore be loaded at its preferred base address.
pub const IMAGE_FILE_RELOCS_STRIPPED: u16 = 0x0001;

/// Image only. This indicates that the image file is valid and can be run.
pub const IMAGE_FILE_EXECUTABLE_IMAGE: u16 = 0x0002;

/// COFF line numbers have been removed.
pub const IMAGE_FILE_LINE_NUMS_STRIPPED: u16 = 0x0004;

/// COFF symbol table entries for local symbols have been removed.
pub const IMAGE_FILE_LOCAL_SYMS_STRIPPED: u16 = 0x0008;

/// Obsolete. Aggressively trim working set.
pub const IMAGE_FILE_AGGRESIVE_WS_TRIM: u16 = 0x0010;

/// Application can handle > 2 GB addresses.
pub const IMAGE_FILE_LARGE_ADDRESS_AWARE: u16 = 0x0020;

/// Little endian: the least significant bit (LSB) precedes the
/// most significant bit (MSB) in memory.
pub const IMAGE_FILE_BYTES_REVERSED_LO: u16 = 0x0080;

/// Machine is based on a 32-bit-word architecture.
pub const IMAGE_FILE_32BIT_MACHINE: u16 = 0x0100;

/// Debugging information is removed from the image file.
pub const IMAGE_FILE_DEBUG_STRIPPED: u16 = 0x0200;

/// If the image is on removable media, fully load it and copy it to the swap file.
pub const IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP: u16 = 0x0400;

/// If the image is on network media, fully load it and copy it to the swap file.
pub const IMAGE_FILE_NET_RUN_FROM_SWAP: u16 = 0x0800;

/// The image file is a system file, not a user program.
pub const IMAGE_FILE_SYSTEM: u16 = 0x1000;

/// The image file is a dynamic-link library (DLL).
pub const IMAGE_FILE_DLL: u16 = 0x2000;

/// The file should be run only on a uniprocessor machine.
pub const IMAGE_FILE_UP_SYSTEM_ONLY: u16 = 0x4000;

/// Big endian: the MSB precedes the LSB in memory.
pub const IMAGE_FILE_BYTES_REVERSED_HI: u16 = 0x8000;

// ---------------------------------------------------------------------------
// Data directory indices
// ---------------------------------------------------------------------------

/// Export Table
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
/// Import Table
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
/// Resource Table
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
/// Exception Table
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
/// Certificate Table (Security)
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
/// Base Relocation Table
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
/// Debug
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
/// Architecture
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
/// Global Pointer
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
/// TLS Table
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
/// Load Config Table
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
/// Bound Import
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
/// Import Address Table
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
/// Delay Import Descriptor
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
/// CLR Runtime Header
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

// ---------------------------------------------------------------------------
// MachineConstants from ghidra.app.util.bin.format.pe.MachineConstants
// ---------------------------------------------------------------------------

/// The contents of this field are assumed to be applicable to any machine type.
pub const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0x0000;

/// Intel 386.
pub const IMAGE_FILE_MACHINE_I386: u16 = 0x014C;

/// MIPS little-endian, 0x160 big-endian.
pub const IMAGE_FILE_MACHINE_R3000: u16 = 0x0162;

/// MIPS little-endian.
pub const IMAGE_FILE_MACHINE_R4000: u16 = 0x0166;

/// MIPS little-endian.
pub const IMAGE_FILE_MACHINE_R10000: u16 = 0x0168;

/// MIPS little-endian WCE v2.
pub const IMAGE_FILE_MACHINE_WCEMIPSV2: u16 = 0x0169;

/// Alpha_AXP.
pub const IMAGE_FILE_MACHINE_ALPHA: u16 = 0x0184;

/// SH3 little-endian.
pub const IMAGE_FILE_MACHINE_SH3: u16 = 0x01A2;

pub const IMAGE_FILE_MACHINE_SH3DSP: u16 = 0x01A3;

/// SH3E little-endian.
pub const IMAGE_FILE_MACHINE_SH3E: u16 = 0x01A4;

/// SH4 little-endian.
pub const IMAGE_FILE_MACHINE_SH4: u16 = 0x01A6;

/// SH5.
pub const IMAGE_FILE_MACHINE_SH5: u16 = 0x01A8;

/// ARM Little-Endian.
pub const IMAGE_FILE_MACHINE_ARM: u16 = 0x01C0;

/// ARM Thumb/Thumb-2 Little-Endian.
pub const IMAGE_FILE_MACHINE_THUMB: u16 = 0x01C2;

/// ARM Thumb-2 Little-Endian.
pub const IMAGE_FILE_MACHINE_ARMNT: u16 = 0x01C4;

pub const IMAGE_FILE_MACHINE_AM33: u16 = 0x01D3;

/// PowerPC Little-Endian.
pub const IMAGE_FILE_MACHINE_POWERPC: u16 = 0x01F0;

/// PowerPC with floating point support.
pub const IMAGE_FILE_MACHINE_POWERPCFP: u16 = 0x01F1;

/// Intel 64 (Itanium).
pub const IMAGE_FILE_MACHINE_IA64: u16 = 0x0200;

/// MIPS.
pub const IMAGE_FILE_MACHINE_MIPS16: u16 = 0x0266;

/// ALPHA64.
pub const IMAGE_FILE_MACHINE_ALPHA64: u16 = 0x0284;

/// MIPS.
pub const IMAGE_FILE_MACHINE_MIPSFPU: u16 = 0x0366;

/// MIPS.
pub const IMAGE_FILE_MACHINE_MIPSFPU16: u16 = 0x0466;

/// Infineon.
pub const IMAGE_FILE_MACHINE_TRICORE: u16 = 0x0520;

pub const IMAGE_FILE_MACHINE_CEF: u16 = 0x0CEF;

/// EFI Byte Code.
pub const IMAGE_FILE_MACHINE_EBC: u16 = 0x0EBC;

/// AMD64 (K8).
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

/// M32R little-endian.
pub const IMAGE_FILE_MACHINE_M32R: u16 = 0x9041;

/// ARM v8 64-bit.
pub const IMAGE_FILE_MACHINE_ARM64: u16 = 0xAA64;

pub const IMAGE_FILE_MACHINE_CEE: u16 = 0xC0EE;

/// AXP64 (alias for ALPHA64).
pub const IMAGE_FILE_MACHINE_AXP64: u16 = IMAGE_FILE_MACHINE_ALPHA64;

// ---------------------------------------------------------------------------
// Rich header constants
// ---------------------------------------------------------------------------

/// Rich header magic "DanS" (xor-decoded).
pub const RICH_MAGIC: u32 = 0x536E6144;

/// Rich header signature.
pub const RICH_SIGNATURE: u32 = 0x68636952; // "Rich"

// ---------------------------------------------------------------------------
// Utility functions (ported from MachineName.java)
// ---------------------------------------------------------------------------

/// Returns the machine type name for the given PE machine identifier.
///
/// This is a port of `MachineName.getName()` from Ghidra.
pub fn machine_type_name(machine: u16) -> &'static str {
    match machine {
        IMAGE_FILE_MACHINE_UNKNOWN => "UNKNOWN",
        IMAGE_FILE_MACHINE_I386 => "I386",
        IMAGE_FILE_MACHINE_R3000 => "R3000",
        IMAGE_FILE_MACHINE_R4000 => "R4000",
        IMAGE_FILE_MACHINE_R10000 => "R10000",
        IMAGE_FILE_MACHINE_WCEMIPSV2 => "WCEMIPSV2",
        IMAGE_FILE_MACHINE_ALPHA => "ALPHA",
        IMAGE_FILE_MACHINE_SH3 => "SH3",
        IMAGE_FILE_MACHINE_SH3DSP => "SH3DSP",
        IMAGE_FILE_MACHINE_SH3E => "SH3E",
        IMAGE_FILE_MACHINE_SH4 => "SH4",
        IMAGE_FILE_MACHINE_SH5 => "SH5",
        IMAGE_FILE_MACHINE_ARM => "ARM",
        IMAGE_FILE_MACHINE_THUMB => "THUMB",
        IMAGE_FILE_MACHINE_ARMNT => "ARMNT",
        IMAGE_FILE_MACHINE_AM33 => "AM33",
        IMAGE_FILE_MACHINE_POWERPC => "POWERPC",
        IMAGE_FILE_MACHINE_POWERPCFP => "POWERPCFP",
        IMAGE_FILE_MACHINE_IA64 => "IA64",
        IMAGE_FILE_MACHINE_MIPS16 => "MIPS16",
        IMAGE_FILE_MACHINE_ALPHA64 => "ALPHA64",
        IMAGE_FILE_MACHINE_MIPSFPU => "MIPSFPU",
        IMAGE_FILE_MACHINE_MIPSFPU16 => "MIPSFPU16",
        IMAGE_FILE_MACHINE_TRICORE => "TRICORE",
        IMAGE_FILE_MACHINE_CEF => "CEF",
        IMAGE_FILE_MACHINE_EBC => "EBC",
        IMAGE_FILE_MACHINE_AMD64 => "AMD64",
        IMAGE_FILE_MACHINE_M32R => "M32R",
        IMAGE_FILE_MACHINE_ARM64 => "ARM64",
        IMAGE_FILE_MACHINE_CEE => "CEE",
        _ => "UNKNOWN",
    }
}

/// Returns `true` if the given machine type represents a 64-bit architecture.
pub fn is_64bit_machine(machine: u16) -> bool {
    matches!(
        machine,
        IMAGE_FILE_MACHINE_AMD64
            | IMAGE_FILE_MACHINE_IA64
            | IMAGE_FILE_MACHINE_ALPHA64
            | IMAGE_FILE_MACHINE_ARM64
    )
}

/// Returns `true` if the given machine type represents a 32-bit architecture.
pub fn is_32bit_machine(machine: u16) -> bool {
    matches!(
        machine,
        IMAGE_FILE_MACHINE_I386
            | IMAGE_FILE_MACHINE_R3000
            | IMAGE_FILE_MACHINE_R4000
            | IMAGE_FILE_MACHINE_R10000
            | IMAGE_FILE_MACHINE_WCEMIPSV2
            | IMAGE_FILE_MACHINE_ALPHA
            | IMAGE_FILE_MACHINE_SH3
            | IMAGE_FILE_MACHINE_SH3DSP
            | IMAGE_FILE_MACHINE_SH3E
            | IMAGE_FILE_MACHINE_SH4
            | IMAGE_FILE_MACHINE_SH5
            | IMAGE_FILE_MACHINE_ARM
            | IMAGE_FILE_MACHINE_THUMB
            | IMAGE_FILE_MACHINE_ARMNT
            | IMAGE_FILE_MACHINE_AM33
            | IMAGE_FILE_MACHINE_POWERPC
            | IMAGE_FILE_MACHINE_POWERPCFP
            | IMAGE_FILE_MACHINE_MIPS16
            | IMAGE_FILE_MACHINE_MIPSFPU
            | IMAGE_FILE_MACHINE_MIPSFPU16
            | IMAGE_FILE_MACHINE_TRICORE
            | IMAGE_FILE_MACHINE_M32R
    )
}

/// Returns the Ghidra processor name for the given PE machine type.
///
/// Returns `None` if the machine type is unknown or not mapped to a processor.
pub fn machine_to_processor(machine: u16) -> Option<&'static str> {
    match machine {
        IMAGE_FILE_MACHINE_I386 => Some("x86"),
        IMAGE_FILE_MACHINE_AMD64 => Some("x86"),
        IMAGE_FILE_MACHINE_POWERPC => Some("PowerPC"),
        IMAGE_FILE_MACHINE_POWERPCFP => Some("PowerPC"),
        IMAGE_FILE_MACHINE_IA64 => Some("ia64"),
        IMAGE_FILE_MACHINE_ARM => Some("ARM"),
        IMAGE_FILE_MACHINE_THUMB => Some("ARM"),
        IMAGE_FILE_MACHINE_ARMNT => Some("ARM"),
        IMAGE_FILE_MACHINE_ARM64 => Some("AARCH64"),
        IMAGE_FILE_MACHINE_MIPS16 => Some("MIPS"),
        IMAGE_FILE_MACHINE_MIPSFPU => Some("MIPS"),
        IMAGE_FILE_MACHINE_MIPSFPU16 => Some("MIPS"),
        IMAGE_FILE_MACHINE_R3000 => Some("MIPS"),
        IMAGE_FILE_MACHINE_R4000 => Some("MIPS"),
        IMAGE_FILE_MACHINE_R10000 => Some("MIPS"),
        IMAGE_FILE_MACHINE_SH3 => Some("SuperH"),
        IMAGE_FILE_MACHINE_SH3DSP => Some("SuperH"),
        IMAGE_FILE_MACHINE_SH3E => Some("SuperH"),
        IMAGE_FILE_MACHINE_SH4 => Some("SuperH"),
        IMAGE_FILE_MACHINE_SH5 => Some("SuperH"),
        IMAGE_FILE_MACHINE_TRICORE => Some("TriCore"),
        IMAGE_FILE_MACHINE_M32R => Some("M32R"),
        IMAGE_FILE_MACHINE_ALPHA => Some("Alpha"),
        IMAGE_FILE_MACHINE_ALPHA64 => Some("Alpha"),
        _ => None,
    }
}

/// Returns the bit size (32 or 64) for the given machine type.
///
/// # Errors
/// Returns an error string if the machine type is unrecognized.
pub fn machine_bit_size(machine: u16) -> Result<u8, String> {
    if is_64bit_machine(machine) {
        Ok(64)
    } else if is_32bit_machine(machine) {
        Ok(32)
    } else {
        Err(format!(
            "Unrecognized PE machine type: 0x{:04X}",
            machine
        ))
    }
}

/// Returns human-readable names for the data directory at the given index.
pub fn data_directory_name(index: usize) -> &'static str {
    const NAMES: [&str; IMAGE_NUMBEROF_DIRECTORY_ENTRIES] = [
        "Export Table",
        "Import Table",
        "Resource Table",
        "Exception Table",
        "Certificate Table",
        "Base Relocation Table",
        "Debug",
        "Architecture",
        "Global Pointer",
        "TLS Table",
        "Load Config Table",
        "Bound Import",
        "Import Address Table",
        "Delay Import Descriptor",
        "CLR Runtime Header",
        "Reserved",
    ];
    if index < NAMES.len() {
        NAMES[index]
    } else {
        "Unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_image_nt_signature() {
        assert_eq!(IMAGE_NT_SIGNATURE, 0x0000_4550);
        // "PE\0\0"
        assert_eq!(&IMAGE_NT_SIGNATURE.to_le_bytes(), b"PE\0\0");
    }

    #[test]
    fn test_image_dos_signature() {
        assert_eq!(IMAGE_DOS_SIGNATURE, 0x5A4D);
        // "MZ"
        assert_eq!(&IMAGE_DOS_SIGNATURE.to_le_bytes(), b"MZ");
    }

    #[test]
    fn test_optional_header_magics() {
        assert_eq!(IMAGE_NT_OPTIONAL_HDR32_MAGIC, 0x10B);
        assert_eq!(IMAGE_NT_OPTIONAL_HDR64_MAGIC, 0x20B);
        assert_eq!(IMAGE_ROM_OPTIONAL_HDR_MAGIC, 0x107);
    }

    #[test]
    fn test_machine_type_name() {
        assert_eq!(machine_type_name(IMAGE_FILE_MACHINE_I386), "I386");
        assert_eq!(machine_type_name(IMAGE_FILE_MACHINE_AMD64), "AMD64");
        assert_eq!(machine_type_name(IMAGE_FILE_MACHINE_ARM64), "ARM64");
        assert_eq!(machine_type_name(IMAGE_FILE_MACHINE_UNKNOWN), "UNKNOWN");
        assert_eq!(machine_type_name(0xFFFF), "UNKNOWN");
    }

    #[test]
    fn test_is_64bit_machine() {
        assert!(is_64bit_machine(IMAGE_FILE_MACHINE_AMD64));
        assert!(is_64bit_machine(IMAGE_FILE_MACHINE_IA64));
        assert!(is_64bit_machine(IMAGE_FILE_MACHINE_ARM64));
        assert!(is_64bit_machine(IMAGE_FILE_MACHINE_ALPHA64));
        assert!(!is_64bit_machine(IMAGE_FILE_MACHINE_I386));
        assert!(!is_64bit_machine(IMAGE_FILE_MACHINE_ARM));
    }

    #[test]
    fn test_is_32bit_machine() {
        assert!(is_32bit_machine(IMAGE_FILE_MACHINE_I386));
        assert!(is_32bit_machine(IMAGE_FILE_MACHINE_ARM));
        assert!(is_32bit_machine(IMAGE_FILE_MACHINE_POWERPC));
        assert!(!is_32bit_machine(IMAGE_FILE_MACHINE_AMD64));
        assert!(!is_32bit_machine(IMAGE_FILE_MACHINE_UNKNOWN));
    }

    #[test]
    fn test_machine_to_processor() {
        assert_eq!(machine_to_processor(IMAGE_FILE_MACHINE_I386), Some("x86"));
        assert_eq!(machine_to_processor(IMAGE_FILE_MACHINE_AMD64), Some("x86"));
        assert_eq!(
            machine_to_processor(IMAGE_FILE_MACHINE_ARM64),
            Some("AARCH64")
        );
        assert_eq!(
            machine_to_processor(IMAGE_FILE_MACHINE_POWERPC),
            Some("PowerPC")
        );
        assert_eq!(machine_to_processor(IMAGE_FILE_MACHINE_UNKNOWN), None);
    }

    #[test]
    fn test_machine_bit_size() {
        assert_eq!(machine_bit_size(IMAGE_FILE_MACHINE_I386), Ok(32));
        assert_eq!(machine_bit_size(IMAGE_FILE_MACHINE_AMD64), Ok(64));
        assert_eq!(machine_bit_size(IMAGE_FILE_MACHINE_ARM64), Ok(64));
        assert!(machine_bit_size(IMAGE_FILE_MACHINE_UNKNOWN).is_err());
    }

    #[test]
    fn test_data_directory_name() {
        assert_eq!(data_directory_name(0), "Export Table");
        assert_eq!(data_directory_name(1), "Import Table");
        assert_eq!(data_directory_name(5), "Base Relocation Table");
        assert_eq!(data_directory_name(15), "Reserved");
        assert_eq!(data_directory_name(99), "Unknown");
    }

    #[test]
    fn test_archive_magic() {
        assert_eq!(IMAGE_ARCHIVE_START, b"!<arch>\n");
        assert_eq!(IMAGE_ARCHIVE_END, b"`\n");
        assert_eq!(IMAGE_ARCHIVE_LINKER_MEMBER, b"/               ");
        assert_eq!(
            IMAGE_ARCHIVE_LONGNAMES_MEMBER,
            b"//              "
        );
    }

    #[test]
    fn test_ordinal_flags() {
        assert_eq!(IMAGE_ORDINAL_FLAG64, 0x8000_0000_0000_0000);
        assert_eq!(IMAGE_ORDINAL_FLAG32, 0x8000_0000);
    }

    #[test]
    fn test_header_sizes() {
        assert_eq!(IMAGE_DOS_HEADER_SIZE, 64);
        assert_eq!(IMAGE_FILE_HEADER_SIZE, 20);
        assert_eq!(IMAGE_SIZEOF_SECTION_HEADER, 40);
        assert_eq!(IMAGE_SIZEOF_SHORT_NAME, 8);
        assert_eq!(IMAGE_SIZEOF_NT_OPTIONAL32_HEADER, 224);
        assert_eq!(IMAGE_SIZEOF_NT_OPTIONAL64_HEADER, 240);
        assert_eq!(IMAGE_NUMBEROF_DIRECTORY_ENTRIES, 16);
    }
}
