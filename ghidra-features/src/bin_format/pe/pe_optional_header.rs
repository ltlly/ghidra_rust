//! PE Optional Header ported from Ghidra's `ghidra.app.util.bin.format.pe.OptionalHeader`.
//!
//! Represents the `IMAGE_OPTIONAL_HEADER32` and `IMAGE_OPTIONAL_HEADER64` structures
//! as defined in `winnt.h`.
//!
//! ```text
//! typedef struct _IMAGE_OPTIONAL_HEADER {
//!     WORD    Magic;
//!     BYTE    MajorLinkerVersion;
//!     BYTE    MinorLinkerVersion;
//!     DWORD   SizeOfCode;
//!     DWORD   SizeOfInitializedData;
//!     DWORD   SizeOfUninitializedData;
//!     DWORD   AddressOfEntryPoint;
//!     DWORD   BaseOfCode;
//!     DWORD   BaseOfData;            // 32-bit only
//!     ULONGLONG ImageBase;           // DWORD in 32-bit, ULONGLONG in 64-bit
//!     DWORD   SectionAlignment;
//!     DWORD   FileAlignment;
//!     WORD    MajorOperatingSystemVersion;
//!     WORD    MinorOperatingSystemVersion;
//!     WORD    MajorImageVersion;
//!     WORD    MinorImageVersion;
//!     WORD    MajorSubsystemVersion;
//!     WORD    MinorSubsystemVersion;
//!     DWORD   Win32VersionValue;
//!     DWORD   SizeOfImage;
//!     DWORD   SizeOfHeaders;
//!     DWORD   CheckSum;
//!     WORD    Subsystem;
//!     WORD    DllCharacteristics;
//!     ULONGLONG SizeOfStackReserve;  // DWORD in 32-bit, ULONGLONG in 64-bit
//!     ULONGLONG SizeOfStackCommit;
//!     ULONGLONG SizeOfHeapReserve;
//!     ULONGLONG SizeOfHeapCommit;
//!     DWORD   LoaderFlags;
//!     DWORD   NumberOfRvaAndSizes;
//!     IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
//! };
//! ```

use std::fmt;
use std::io;

use super::pe_constants::{
    IMAGE_NT_OPTIONAL_HDR32_MAGIC, IMAGE_NT_OPTIONAL_HDR64_MAGIC, IMAGE_ROM_OPTIONAL_HDR_MAGIC,
};

/// Size of an `IMAGE_DATA_DIRECTORY` entry (VirtualAddress + Size = 8 bytes).
pub const IMAGE_SIZEOF_IMAGE_DIRECTORY_ENTRY: usize = 8;

/// The count of data directories in the optional header.
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

// ---------------------------------------------------------------------------
// Data directory index constants
// ---------------------------------------------------------------------------

/// Export directory index.
pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
/// Import directory index.
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: usize = 1;
/// Resource directory index.
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: usize = 2;
/// Exception directory index.
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: usize = 3;
/// Security directory index.
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: usize = 4;
/// Base Relocation Table directory index.
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;
/// Debug directory index.
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
/// Architecture Specific Data directory index.
pub const IMAGE_DIRECTORY_ENTRY_ARCHITECTURE: usize = 7;
/// Global Pointer directory index.
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: usize = 8;
/// TLS directory index.
pub const IMAGE_DIRECTORY_ENTRY_TLS: usize = 9;
/// Load Configuration directory index.
pub const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG: usize = 10;
/// Bound Import directory index.
pub const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT: usize = 11;
/// Import Address Table directory index.
pub const IMAGE_DIRECTORY_ENTRY_IAT: usize = 12;
/// Delay Load Import Descriptors directory index.
pub const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: usize = 13;
/// COM Runtime Descriptor directory index.
pub const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: usize = 14;

// ---------------------------------------------------------------------------
// DataDirectoryEntry
// ---------------------------------------------------------------------------

/// A single `IMAGE_DATA_DIRECTORY` entry consisting of a virtual address and size.
///
/// ```text
/// typedef struct _IMAGE_DATA_DIRECTORY {
///     DWORD   VirtualAddress;
///     DWORD   Size;
/// } IMAGE_DATA_DIRECTORY;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDirectoryEntry {
    /// The relative virtual address of the data directory.
    pub virtual_address: u32,
    /// The size of the data directory, in bytes.
    pub size: u32,
}

impl DataDirectoryEntry {
    /// Returns `true` if this entry is non-null (has a non-zero address or size).
    pub fn is_present(&self) -> bool {
        self.virtual_address != 0 || self.size != 0
    }

    /// Returns `true` if this entry appears valid (non-zero address with positive size).
    pub fn is_valid(&self) -> bool {
        self.virtual_address != 0 && (self.size as i32) > 0
    }

    /// Parses a `DataDirectoryEntry` from little-endian bytes at the given offset.
    pub fn parse(data: &[u8], offset: usize) -> io::Result<Self> {
        if data.len() < offset + IMAGE_SIZEOF_IMAGE_DIRECTORY_ENTRY {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough data for IMAGE_DATA_DIRECTORY",
            ));
        }
        let virtual_address = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let size = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        Ok(DataDirectoryEntry {
            virtual_address,
            size,
        })
    }

    /// Serializes this entry to 8 bytes (little-endian).
    pub fn to_bytes(&self) -> [u8; IMAGE_SIZEOF_IMAGE_DIRECTORY_ENTRY] {
        let mut buf = [0u8; IMAGE_SIZEOF_IMAGE_DIRECTORY_ENTRY];
        buf[0..4].copy_from_slice(&self.virtual_address.to_le_bytes());
        buf[4..8].copy_from_slice(&self.size.to_le_bytes());
        buf
    }
}

impl fmt::Display for DataDirectoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VirtualAddress: 0x{:08X} Size: {} bytes",
            self.virtual_address, self.size
        )
    }
}

// ---------------------------------------------------------------------------
// Data directory name helper
// ---------------------------------------------------------------------------

/// Returns the name of the data directory at the given index.
pub fn data_directory_name(index: usize) -> &'static str {
    match index {
        IMAGE_DIRECTORY_ENTRY_EXPORT => "Export Directory",
        IMAGE_DIRECTORY_ENTRY_IMPORT => "Import Directory",
        IMAGE_DIRECTORY_ENTRY_RESOURCE => "Resource Directory",
        IMAGE_DIRECTORY_ENTRY_EXCEPTION => "Exception Directory",
        IMAGE_DIRECTORY_ENTRY_SECURITY => "Security Directory",
        IMAGE_DIRECTORY_ENTRY_BASERELOC => "Base Relocation Directory",
        IMAGE_DIRECTORY_ENTRY_DEBUG => "Debug Directory",
        IMAGE_DIRECTORY_ENTRY_ARCHITECTURE => "Architecture Directory",
        IMAGE_DIRECTORY_ENTRY_GLOBALPTR => "Global Pointer Directory",
        IMAGE_DIRECTORY_ENTRY_TLS => "TLS Directory",
        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG => "Load Config Directory",
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT => "Bound Import Directory",
        IMAGE_DIRECTORY_ENTRY_IAT => "Import Address Table",
        IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT => "Delay Import Directory",
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR => "COM Descriptor",
        15 => "Reserved",
        _ => "Unknown",
    }
}

// ---------------------------------------------------------------------------
// OptionalHeader
// ---------------------------------------------------------------------------

/// Represents the PE optional header (`IMAGE_OPTIONAL_HEADER32` or
/// `IMAGE_OPTIONAL_HEADER64`).
///
/// The optional header follows the file header in the NT headers. It contains
/// information needed by the loader, including the image base, section/file
/// alignment, subsystem, and an array of data directory entries.
#[derive(Debug, Clone)]
pub struct OptionalHeader {
    /// The magic number identifying this as PE32, PE32+, or ROM.
    magic: u16,
    /// The major version number of the linker.
    major_linker_version: u8,
    /// The minor version number of the linker.
    minor_linker_version: u8,
    /// The combined total size of all sections with IMAGE_SCN_CNT_CODE.
    size_of_code: u32,
    /// The combined size of all initialized data sections.
    size_of_initialized_data: u32,
    /// The combined size of all uninitialized data sections.
    size_of_uninitialized_data: u32,
    /// The RVA of the entry point.
    address_of_entry_point: u32,
    /// The RVA of the first byte of code when loaded.
    base_of_code: u32,
    /// The RVA of the first byte of data when loaded (32-bit only).
    base_of_data: u32,
    /// The preferred load address of the image.
    image_base: u64,
    /// The alignment of sections when loaded into memory.
    section_alignment: u32,
    /// The alignment of sections in the raw file.
    file_alignment: u32,
    /// The major version of the required OS.
    major_operating_system_version: u16,
    /// The minor version of the required OS.
    minor_operating_system_version: u16,
    /// The major version of the image.
    major_image_version: u16,
    /// The minor version of the image.
    minor_image_version: u16,
    /// The major version of the subsystem.
    major_subsystem_version: u16,
    /// The minor version of the subsystem.
    minor_subsystem_version: u16,
    /// Reserved, must be zero.
    win32_version_value: u32,
    /// The RVA that would be assigned to the next section.
    size_of_image: u32,
    /// The combined size of all headers.
    size_of_headers: u32,
    /// The image file checksum.
    checksum: u32,
    /// The subsystem required to run this image.
    subsystem: u16,
    /// DLL characteristic flags.
    dll_characteristics: u16,
    /// The size of the stack reservation.
    size_of_stack_reserve: u64,
    /// The size of the stack to commit.
    size_of_stack_commit: u64,
    /// The size of the heap reservation.
    size_of_heap_reserve: u64,
    /// The size of the heap to commit.
    size_of_heap_commit: u64,
    /// Reserved loader flags (obsolete).
    loader_flags: u32,
    /// The number of data directory entries.
    number_of_rva_and_sizes: u32,
    /// The array of data directory entries.
    data_directory: Vec<DataDirectoryEntry>,
}

impl OptionalHeader {
    /// Parses an optional header from the given data at the specified offset.
    ///
    /// The reader should be positioned at the start of the optional header
    /// (right after the file header).
    pub fn parse(data: &[u8], offset: usize) -> io::Result<Self> {
        if data.len() < offset + 2 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough data for optional header magic",
            ));
        }

        let magic = u16::from_le_bytes([data[offset], data[offset + 1]]);
        if magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC {
            Self::parse_64(data, offset)
        } else {
            Self::parse_32(data, offset)
        }
    }

    /// Parses a 32-bit optional header (`IMAGE_OPTIONAL_HEADER32`).
    fn parse_32(data: &[u8], offset: usize) -> io::Result<Self> {
        // Minimum size: 28 (fixed fields before ImageBase) + 4 (ImageBase)
        // + 68 (rest of fixed fields) + 8*16 (data dirs) = 224 bytes
        let min_size = offset + 96 + IMAGE_NUMBEROF_DIRECTORY_ENTRIES * IMAGE_SIZEOF_IMAGE_DIRECTORY_ENTRY;
        if data.len() < min_size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough data for IMAGE_OPTIONAL_HEADER32",
            ));
        }

        let mut pos = offset;
        let magic = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let major_linker_version = data[pos]; pos += 1;
        let minor_linker_version = data[pos]; pos += 1;
        let size_of_code = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let size_of_initialized_data = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let size_of_uninitialized_data = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let address_of_entry_point = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let base_of_code = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let base_of_data = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let image_base = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64; pos += 4;
        let section_alignment = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let file_alignment = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let major_operating_system_version = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let minor_operating_system_version = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let major_image_version = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let minor_image_version = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let major_subsystem_version = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let minor_subsystem_version = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let win32_version_value = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let size_of_image = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let size_of_headers = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let checksum = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let subsystem = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let dll_characteristics = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let size_of_stack_reserve = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64; pos += 4;
        let size_of_stack_commit = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64; pos += 4;
        let size_of_heap_reserve = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64; pos += 4;
        let size_of_heap_commit = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as u64; pos += 4;
        let loader_flags = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let number_of_rva_and_sizes = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;

        let num_dirs = number_of_rva_and_sizes.min(IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32) as usize;
        let mut data_directory = Vec::with_capacity(num_dirs);
        for _ in 0..num_dirs {
            data_directory.push(DataDirectoryEntry::parse(data, pos)?);
            pos += IMAGE_SIZEOF_IMAGE_DIRECTORY_ENTRY;
        }

        Ok(OptionalHeader {
            magic,
            major_linker_version,
            minor_linker_version,
            size_of_code,
            size_of_initialized_data,
            size_of_uninitialized_data,
            address_of_entry_point,
            base_of_code,
            base_of_data,
            image_base,
            section_alignment,
            file_alignment,
            major_operating_system_version,
            minor_operating_system_version,
            major_image_version,
            minor_image_version,
            major_subsystem_version,
            minor_subsystem_version,
            win32_version_value,
            size_of_image,
            size_of_headers,
            checksum,
            subsystem,
            dll_characteristics,
            size_of_stack_reserve,
            size_of_stack_commit,
            size_of_heap_reserve,
            size_of_heap_commit,
            loader_flags,
            number_of_rva_and_sizes,
            data_directory,
        })
    }

    /// Parses a 64-bit optional header (`IMAGE_OPTIONAL_HEADER64`).
    fn parse_64(data: &[u8], offset: usize) -> io::Result<Self> {
        // 64-bit layout: same fields but ImageBase and heap/stack sizes are 8 bytes.
        // BaseOfData is absent. Fixed fields = 112 bytes + data dirs.
        let min_size = offset + 112 + IMAGE_NUMBEROF_DIRECTORY_ENTRIES * IMAGE_SIZEOF_IMAGE_DIRECTORY_ENTRY;
        if data.len() < min_size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough data for IMAGE_OPTIONAL_HEADER64",
            ));
        }

        let mut pos = offset;
        let magic = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let major_linker_version = data[pos]; pos += 1;
        let minor_linker_version = data[pos]; pos += 1;
        let size_of_code = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let size_of_initialized_data = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let size_of_uninitialized_data = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let address_of_entry_point = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let base_of_code = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        // No BaseOfData in 64-bit
        let base_of_data = 0;
        let image_base = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()); pos += 8;
        let section_alignment = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let file_alignment = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let major_operating_system_version = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let minor_operating_system_version = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let major_image_version = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let minor_image_version = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let major_subsystem_version = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let minor_subsystem_version = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let win32_version_value = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let size_of_image = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let size_of_headers = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let checksum = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let subsystem = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let dll_characteristics = u16::from_le_bytes([data[pos], data[pos + 1]]); pos += 2;
        let size_of_stack_reserve = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()); pos += 8;
        let size_of_stack_commit = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()); pos += 8;
        let size_of_heap_reserve = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()); pos += 8;
        let size_of_heap_commit = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap()); pos += 8;
        let loader_flags = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;
        let number_of_rva_and_sizes = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()); pos += 4;

        let num_dirs = number_of_rva_and_sizes.min(IMAGE_NUMBEROF_DIRECTORY_ENTRIES as u32) as usize;
        let mut data_directory = Vec::with_capacity(num_dirs);
        for _ in 0..num_dirs {
            data_directory.push(DataDirectoryEntry::parse(data, pos)?);
            pos += IMAGE_SIZEOF_IMAGE_DIRECTORY_ENTRY;
        }

        Ok(OptionalHeader {
            magic,
            major_linker_version,
            minor_linker_version,
            size_of_code,
            size_of_initialized_data,
            size_of_uninitialized_data,
            address_of_entry_point,
            base_of_code,
            base_of_data,
            image_base,
            section_alignment,
            file_alignment,
            major_operating_system_version,
            minor_operating_system_version,
            major_image_version,
            minor_image_version,
            major_subsystem_version,
            minor_subsystem_version,
            win32_version_value,
            size_of_image,
            size_of_headers,
            checksum,
            subsystem,
            dll_characteristics,
            size_of_stack_reserve,
            size_of_stack_commit,
            size_of_heap_reserve,
            size_of_heap_commit,
            loader_flags,
            number_of_rva_and_sizes,
            data_directory,
        })
    }

    /// Returns `true` if this is a 64-bit optional header.
    pub fn is_64bit(&self) -> bool {
        self.magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC
    }

    /// Returns `true` if this is a ROM image header.
    pub fn is_rom(&self) -> bool {
        self.magic == IMAGE_ROM_OPTIONAL_HDR_MAGIC
    }

    /// Returns the magic number.
    pub fn magic(&self) -> u16 {
        self.magic
    }

    /// Returns the major linker version.
    pub fn major_linker_version(&self) -> u8 {
        self.major_linker_version
    }

    /// Returns the minor linker version.
    pub fn minor_linker_version(&self) -> u8 {
        self.minor_linker_version
    }

    /// Returns the combined total size of all code sections.
    pub fn size_of_code(&self) -> u32 {
        self.size_of_code
    }

    /// Returns the combined size of all initialized data sections.
    pub fn size_of_initialized_data(&self) -> u32 {
        self.size_of_initialized_data
    }

    /// Returns the combined size of all uninitialized data sections.
    pub fn size_of_uninitialized_data(&self) -> u32 {
        self.size_of_uninitialized_data
    }

    /// Returns the RVA of the entry point.
    pub fn address_of_entry_point(&self) -> u32 {
        self.address_of_entry_point
    }

    /// Returns the RVA of the first byte of code.
    pub fn base_of_code(&self) -> u32 {
        self.base_of_code
    }

    /// Returns the RVA of the first byte of data (32-bit only, 0 for 64-bit).
    pub fn base_of_data(&self) -> u32 {
        self.base_of_data
    }

    /// Returns the preferred image base address.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Returns the section alignment.
    pub fn section_alignment(&self) -> u32 {
        self.section_alignment
    }

    /// Returns the file alignment.
    pub fn file_alignment(&self) -> u32 {
        self.file_alignment
    }

    /// Returns the major OS version.
    pub fn major_operating_system_version(&self) -> u16 {
        self.major_operating_system_version
    }

    /// Returns the minor OS version.
    pub fn minor_operating_system_version(&self) -> u16 {
        self.minor_operating_system_version
    }

    /// Returns the major image version.
    pub fn major_image_version(&self) -> u16 {
        self.major_image_version
    }

    /// Returns the minor image version.
    pub fn minor_image_version(&self) -> u16 {
        self.minor_image_version
    }

    /// Returns the major subsystem version.
    pub fn major_subsystem_version(&self) -> u16 {
        self.major_subsystem_version
    }

    /// Returns the minor subsystem version.
    pub fn minor_subsystem_version(&self) -> u16 {
        self.minor_subsystem_version
    }

    /// Returns the Win32 version value (reserved, usually 0).
    pub fn win32_version_value(&self) -> u32 {
        self.win32_version_value
    }

    /// Returns the size of the image.
    pub fn size_of_image(&self) -> u32 {
        self.size_of_image
    }

    /// Returns the combined size of all headers.
    pub fn size_of_headers(&self) -> u32 {
        self.size_of_headers
    }

    /// Returns the image checksum.
    pub fn checksum(&self) -> u32 {
        self.checksum
    }

    /// Returns the subsystem type.
    pub fn subsystem(&self) -> u16 {
        self.subsystem
    }

    /// Returns the DLL characteristics flags.
    pub fn dll_characteristics(&self) -> u16 {
        self.dll_characteristics
    }

    /// Returns the stack reservation size.
    pub fn size_of_stack_reserve(&self) -> u64 {
        self.size_of_stack_reserve
    }

    /// Returns the stack commit size.
    pub fn size_of_stack_commit(&self) -> u64 {
        self.size_of_stack_commit
    }

    /// Returns the heap reservation size.
    pub fn size_of_heap_reserve(&self) -> u64 {
        self.size_of_heap_reserve
    }

    /// Returns the heap commit size.
    pub fn size_of_heap_commit(&self) -> u64 {
        self.size_of_heap_commit
    }

    /// Returns the loader flags (obsolete).
    pub fn loader_flags(&self) -> u32 {
        self.loader_flags
    }

    /// Returns the number of RVA and size entries.
    pub fn number_of_rva_and_sizes(&self) -> u32 {
        self.number_of_rva_and_sizes
    }

    /// Returns a reference to the data directory entries.
    pub fn data_directory(&self) -> &[DataDirectoryEntry] {
        &self.data_directory
    }

    /// Returns a specific data directory entry by index, or `None` if out of bounds.
    pub fn data_directory_at(&self, index: usize) -> Option<&DataDirectoryEntry> {
        self.data_directory.get(index)
    }

    /// Returns the file size of this optional header in bytes.
    pub fn header_size(&self) -> usize {
        if self.is_64bit() {
            // 112 fixed bytes + data directories
            112 + self.data_directory.len() * IMAGE_SIZEOF_IMAGE_DIRECTORY_ENTRY
        } else {
            // 96 fixed bytes + data directories
            96 + self.data_directory.len() * IMAGE_SIZEOF_IMAGE_DIRECTORY_ENTRY
        }
    }

    /// Returns the expected size of the optional header based on the magic value.
    pub fn expected_size(is_64bit: bool) -> usize {
        if is_64bit {
            super::pe_constants::IMAGE_SIZEOF_NT_OPTIONAL64_HEADER
        } else {
            super::pe_constants::IMAGE_SIZEOF_NT_OPTIONAL32_HEADER
        }
    }
}

impl fmt::Display for OptionalHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bitness = if self.is_64bit() { "64" } else { "32" };
        writeln!(f, "IMAGE_OPTIONAL_HEADER{}:", bitness)?;
        writeln!(f, "  Magic:                0x{:04X}", self.magic)?;
        writeln!(
            f,
            "  LinkerVersion:        {}.{}",
            self.major_linker_version, self.minor_linker_version
        )?;
        writeln!(f, "  SizeOfCode:           0x{:X}", self.size_of_code)?;
        writeln!(f, "  SizeOfInitializedData: 0x{:X}", self.size_of_initialized_data)?;
        writeln!(f, "  SizeOfUninitializedData: 0x{:X}", self.size_of_uninitialized_data)?;
        writeln!(f, "  AddressOfEntryPoint:  0x{:08X}", self.address_of_entry_point)?;
        writeln!(f, "  BaseOfCode:           0x{:08X}", self.base_of_code)?;
        if !self.is_64bit() {
            writeln!(f, "  BaseOfData:           0x{:08X}", self.base_of_data)?;
        }
        if self.is_64bit() {
            writeln!(f, "  ImageBase:            0x{:016X}", self.image_base)?;
        } else {
            writeln!(f, "  ImageBase:            0x{:08X}", self.image_base)?;
        }
        writeln!(f, "  SectionAlignment:     0x{:X}", self.section_alignment)?;
        writeln!(f, "  FileAlignment:        0x{:X}", self.file_alignment)?;
        writeln!(
            f,
            "  OSVersion:            {}.{}",
            self.major_operating_system_version, self.minor_operating_system_version
        )?;
        writeln!(
            f,
            "  ImageVersion:         {}.{}",
            self.major_image_version, self.minor_image_version
        )?;
        writeln!(
            f,
            "  SubsystemVersion:     {}.{}",
            self.major_subsystem_version, self.minor_subsystem_version
        )?;
        writeln!(f, "  SizeOfImage:          0x{:X}", self.size_of_image)?;
        writeln!(f, "  SizeOfHeaders:        0x{:X}", self.size_of_headers)?;
        writeln!(f, "  CheckSum:             0x{:08X}", self.checksum)?;
        writeln!(f, "  Subsystem:            0x{:04X}", self.subsystem)?;
        writeln!(f, "  DllCharacteristics:   0x{:04X}", self.dll_characteristics)?;
        writeln!(f, "  SizeOfStackReserve:   0x{:X}", self.size_of_stack_reserve)?;
        writeln!(f, "  SizeOfStackCommit:    0x{:X}", self.size_of_stack_commit)?;
        writeln!(f, "  SizeOfHeapReserve:    0x{:X}", self.size_of_heap_reserve)?;
        writeln!(f, "  SizeOfHeapCommit:     0x{:X}", self.size_of_heap_commit)?;
        writeln!(f, "  NumberOfRvaAndSizes:  {}", self.number_of_rva_and_sizes)?;
        for (i, dd) in self.data_directory.iter().enumerate() {
            if dd.is_present() {
                writeln!(
                    f,
                    "  DataDirectory[{}] ({}): {}",
                    i,
                    data_directory_name(i),
                    dd
                )?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal 32-bit optional header byte sequence.
    fn make_optional_header_32(
        entry_point: u32,
        image_base: u32,
        section_align: u32,
        file_align: u32,
        num_data_dirs: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&IMAGE_NT_OPTIONAL_HDR32_MAGIC.to_le_bytes()); // Magic
        data.push(14); data.push(0); // LinkerVersion
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfCode
        data.extend_from_slice(&0u32.to_le_bytes()); // SizeOfInitializedData
        data.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
        data.extend_from_slice(&entry_point.to_le_bytes()); // AddressOfEntryPoint
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
        data.extend_from_slice(&0x2000u32.to_le_bytes()); // BaseOfData
        data.extend_from_slice(&image_base.to_le_bytes()); // ImageBase (32-bit)
        data.extend_from_slice(&section_align.to_le_bytes()); // SectionAlignment
        data.extend_from_slice(&file_align.to_le_bytes()); // FileAlignment
        data.extend_from_slice(&6u16.to_le_bytes()); // MajorOperatingSystemVersion
        data.extend_from_slice(&0u16.to_le_bytes()); // MinorOperatingSystemVersion
        data.extend_from_slice(&0u16.to_le_bytes()); // MajorImageVersion
        data.extend_from_slice(&0u16.to_le_bytes()); // MinorImageVersion
        data.extend_from_slice(&6u16.to_le_bytes()); // MajorSubsystemVersion
        data.extend_from_slice(&0u16.to_le_bytes()); // MinorSubsystemVersion
        data.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
        data.extend_from_slice(&0x5000u32.to_le_bytes()); // SizeOfImage
        data.extend_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
        data.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        data.extend_from_slice(&3u16.to_le_bytes()); // Subsystem (CONSOLE)
        data.extend_from_slice(&0x8160u16.to_le_bytes()); // DllCharacteristics
        data.extend_from_slice(&0x100000u32.to_le_bytes()); // SizeOfStackReserve
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfStackCommit
        data.extend_from_slice(&0x100000u32.to_le_bytes()); // SizeOfHeapReserve
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfHeapCommit
        data.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
        data.extend_from_slice(&num_data_dirs.to_le_bytes()); // NumberOfRvaAndSizes

        // Data directories (zeroed entries)
        for _ in 0..num_data_dirs {
            data.extend_from_slice(&0u32.to_le_bytes()); // VirtualAddress
            data.extend_from_slice(&0u32.to_le_bytes()); // Size
        }

        data
    }

    /// Build a minimal 64-bit optional header byte sequence.
    fn make_optional_header_64(
        entry_point: u32,
        image_base: u64,
        section_align: u32,
        file_align: u32,
        num_data_dirs: u32,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&IMAGE_NT_OPTIONAL_HDR64_MAGIC.to_le_bytes()); // Magic
        data.push(14); data.push(0); // LinkerVersion
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfCode
        data.extend_from_slice(&0u32.to_le_bytes()); // SizeOfInitializedData
        data.extend_from_slice(&0u32.to_le_bytes()); // SizeOfUninitializedData
        data.extend_from_slice(&entry_point.to_le_bytes()); // AddressOfEntryPoint
        data.extend_from_slice(&0x1000u32.to_le_bytes()); // BaseOfCode
        // No BaseOfData in 64-bit
        data.extend_from_slice(&image_base.to_le_bytes()); // ImageBase (64-bit)
        data.extend_from_slice(&section_align.to_le_bytes()); // SectionAlignment
        data.extend_from_slice(&file_align.to_le_bytes()); // FileAlignment
        data.extend_from_slice(&6u16.to_le_bytes()); // MajorOperatingSystemVersion
        data.extend_from_slice(&0u16.to_le_bytes()); // MinorOperatingSystemVersion
        data.extend_from_slice(&0u16.to_le_bytes()); // MajorImageVersion
        data.extend_from_slice(&0u16.to_le_bytes()); // MinorImageVersion
        data.extend_from_slice(&6u16.to_le_bytes()); // MajorSubsystemVersion
        data.extend_from_slice(&0u16.to_le_bytes()); // MinorSubsystemVersion
        data.extend_from_slice(&0u32.to_le_bytes()); // Win32VersionValue
        data.extend_from_slice(&0x5000u32.to_le_bytes()); // SizeOfImage
        data.extend_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
        data.extend_from_slice(&0u32.to_le_bytes()); // CheckSum
        data.extend_from_slice(&3u16.to_le_bytes()); // Subsystem
        data.extend_from_slice(&0x8160u16.to_le_bytes()); // DllCharacteristics
        data.extend_from_slice(&0x400000u64.to_le_bytes()); // SizeOfStackReserve
        data.extend_from_slice(&0x4000u64.to_le_bytes()); // SizeOfStackCommit
        data.extend_from_slice(&0x400000u64.to_le_bytes()); // SizeOfHeapReserve
        data.extend_from_slice(&0x2000u64.to_le_bytes()); // SizeOfHeapCommit
        data.extend_from_slice(&0u32.to_le_bytes()); // LoaderFlags
        data.extend_from_slice(&num_data_dirs.to_le_bytes()); // NumberOfRvaAndSizes

        // Data directories (zeroed entries)
        for _ in 0..num_data_dirs {
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&0u32.to_le_bytes());
        }

        data
    }

    #[test]
    fn test_parse_optional_header_32() {
        let data = make_optional_header_32(0x1000, 0x0040_0000, 0x1000, 0x200, 16);
        let hdr = OptionalHeader::parse(&data, 0).unwrap();
        assert!(!hdr.is_64bit());
        assert_eq!(hdr.magic(), IMAGE_NT_OPTIONAL_HDR32_MAGIC);
        assert_eq!(hdr.address_of_entry_point(), 0x1000);
        assert_eq!(hdr.image_base(), 0x0040_0000);
        assert_eq!(hdr.section_alignment(), 0x1000);
        assert_eq!(hdr.file_alignment(), 0x200);
        assert_eq!(hdr.subsystem(), 3);
        assert_eq!(hdr.number_of_rva_and_sizes(), 16);
        assert_eq!(hdr.data_directory().len(), 16);
        assert_eq!(hdr.base_of_data(), 0x2000);
    }

    #[test]
    fn test_parse_optional_header_64() {
        let data = make_optional_header_64(0x1000, 0x0001_4000_0000, 0x1000, 0x200, 16);
        let hdr = OptionalHeader::parse(&data, 0).unwrap();
        assert!(hdr.is_64bit());
        assert_eq!(hdr.magic(), IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        assert_eq!(hdr.address_of_entry_point(), 0x1000);
        assert_eq!(hdr.image_base(), 0x0001_4000_0000);
        assert_eq!(hdr.size_of_stack_reserve(), 0x400000);
        assert_eq!(hdr.size_of_heap_commit(), 0x2000);
        assert_eq!(hdr.base_of_data(), 0); // Not used in 64-bit
    }

    #[test]
    fn test_optional_header_insufficient_data() {
        let data = [0u8; 10];
        assert!(OptionalHeader::parse(&data, 0).is_err());
    }

    #[test]
    fn test_data_directory_entry_parse() {
        let mut data = [0u8; 8];
        data[0..4].copy_from_slice(&0x1234u32.to_le_bytes());
        data[4..8].copy_from_slice(&0x5678u32.to_le_bytes());
        let entry = DataDirectoryEntry::parse(&data, 0).unwrap();
        assert_eq!(entry.virtual_address, 0x1234);
        assert_eq!(entry.size, 0x5678);
        assert!(entry.is_present());
        assert!(entry.is_valid());
    }

    #[test]
    fn test_data_directory_entry_zero() {
        let data = [0u8; 8];
        let entry = DataDirectoryEntry::parse(&data, 0).unwrap();
        assert!(!entry.is_present());
        assert!(!entry.is_valid());
    }

    #[test]
    fn test_data_directory_entry_to_bytes() {
        let entry = DataDirectoryEntry {
            virtual_address: 0xABCD,
            size: 0x1234,
        };
        let bytes = entry.to_bytes();
        assert_eq!(&bytes[0..4], &0xABCDu32.to_le_bytes());
        assert_eq!(&bytes[4..8], &0x1234u32.to_le_bytes());
    }

    #[test]
    fn test_data_directory_name() {
        assert_eq!(data_directory_name(0), "Export Directory");
        assert_eq!(data_directory_name(1), "Import Directory");
        assert_eq!(data_directory_name(5), "Base Relocation Directory");
        assert_eq!(data_directory_name(14), "COM Descriptor");
        assert_eq!(data_directory_name(15), "Reserved");
        assert_eq!(data_directory_name(99), "Unknown");
    }

    #[test]
    fn test_optional_header_display_32() {
        let data = make_optional_header_32(0x1000, 0x0040_0000, 0x1000, 0x200, 16);
        let hdr = OptionalHeader::parse(&data, 0).unwrap();
        let display = format!("{}", hdr);
        assert!(display.contains("IMAGE_OPTIONAL_HEADER32"));
        assert!(display.contains("0x00400000"));
        assert!(display.contains("BaseOfData"));
    }

    #[test]
    fn test_optional_header_display_64() {
        let data = make_optional_header_64(0x1000, 0x0001_4000_0000, 0x1000, 0x200, 16);
        let hdr = OptionalHeader::parse(&data, 0).unwrap();
        let display = format!("{}", hdr);
        assert!(display.contains("IMAGE_OPTIONAL_HEADER64"));
        // 64-bit should not contain BaseOfData
        assert!(!display.contains("BaseOfData"));
    }

    #[test]
    fn test_optional_header_data_directory_at() {
        let mut data = make_optional_header_32(0x1000, 0x0040_0000, 0x1000, 0x200, 16);
        // Write a non-zero export directory entry at offset 96+0
        let dd_offset = 96;
        data[dd_offset..dd_offset + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        data[dd_offset + 4..dd_offset + 8].copy_from_slice(&0x100u32.to_le_bytes());

        let hdr = OptionalHeader::parse(&data, 0).unwrap();
        let export = hdr.data_directory_at(0).unwrap();
        assert_eq!(export.virtual_address, 0x2000);
        assert_eq!(export.size, 0x100);
        assert!(export.is_present());

        assert_eq!(hdr.data_directory_at(99), None);
    }

    #[test]
    fn test_optional_header_header_size() {
        let data32 = make_optional_header_32(0x1000, 0x0040_0000, 0x1000, 0x200, 16);
        let hdr32 = OptionalHeader::parse(&data32, 0).unwrap();
        assert_eq!(hdr32.header_size(), 96 + 16 * 8);

        let data64 = make_optional_header_64(0x1000, 0x0001_4000_0000, 0x1000, 0x200, 16);
        let hdr64 = OptionalHeader::parse(&data64, 0).unwrap();
        assert_eq!(hdr64.header_size(), 112 + 16 * 8);
    }
}
