//! PE Data Directory base trait and concrete data directory types ported from
//! Ghidra's `ghidra.app.util.bin.format.pe.DataDirectory` and related classes.
//!
//! Provides:
//! - [`DataDirectory`] -- trait for PE data directory entries
//! - [`DefaultDataDirectory`] -- a generic/default data directory implementation
//! - [`ExportDataDirectory`] -- the export directory (index 0)
//! - [`ImportDataDirectory`] -- the import directory (index 1)
//! - [`DebugDataDirectory`] -- the debug directory (index 6)
//! - [`BoundImportDataDirectory`] -- the bound import directory (index 11)
//! - [`DelayImportDataDirectory`] -- the delay import directory (index 13)
//! - [`ExportInfo`] -- information about a single exported symbol
//! - [`ImportDescriptor`] -- an import descriptor entry

use std::fmt;
use std::io;

use super::pe_optional_header::DataDirectoryEntry;

// ---------------------------------------------------------------------------
// DataDirectory trait
// ---------------------------------------------------------------------------

/// Trait representing a parsed PE data directory.
///
/// Each data directory type (export, import, resource, etc.) implements this
/// trait to provide access to its virtual address, size, and name.
pub trait DataDirectory: fmt::Debug + fmt::Display {
    /// Returns the directory name (e.g., "Export Directory").
    fn directory_name(&self) -> &'static str;

    /// Returns the virtual address of this directory.
    fn virtual_address(&self) -> u32;

    /// Returns the size of this directory in bytes.
    fn directory_size(&self) -> u32;

    /// Returns `true` if this directory was parsed successfully.
    fn has_parsed_correctly(&self) -> bool;

    /// Returns the data directory entry that was used to create this directory.
    fn entry(&self) -> &DataDirectoryEntry;

    /// Returns `true` if this directory contains data (non-zero virtual address).
    fn is_present(&self) -> bool {
        self.virtual_address() != 0
    }
}

// ---------------------------------------------------------------------------
// DefaultDataDirectory
// ---------------------------------------------------------------------------

/// A default/generic data directory that stores the raw entry without further
/// parsing. Used for directories that are not specifically handled.
#[derive(Debug, Clone)]
pub struct DefaultDataDirectory {
    /// The index of this directory in the data directory array.
    index: usize,
    /// The raw data directory entry.
    entry: DataDirectoryEntry,
    /// Whether parsing was successful.
    parsed: bool,
}

impl DefaultDataDirectory {
    /// Creates a new `DefaultDataDirectory` from the given entry.
    pub fn new(index: usize, entry: DataDirectoryEntry) -> Self {
        let parsed = entry.virtual_address != 0;
        DefaultDataDirectory {
            index,
            entry,
            parsed,
        }
    }

    /// Returns the index of this directory.
    pub fn index(&self) -> usize {
        self.index
    }
}

impl DataDirectory for DefaultDataDirectory {
    fn directory_name(&self) -> &'static str {
        super::pe_optional_header::data_directory_name(self.index)
    }

    fn virtual_address(&self) -> u32 {
        self.entry.virtual_address
    }

    fn directory_size(&self) -> u32 {
        self.entry.size
    }

    fn has_parsed_correctly(&self) -> bool {
        self.parsed
    }

    fn entry(&self) -> &DataDirectoryEntry {
        &self.entry
    }
}

impl fmt::Display for DefaultDataDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}",
            self.directory_name(),
            self.entry
        )
    }
}

// ---------------------------------------------------------------------------
// ExportInfo
// ---------------------------------------------------------------------------

/// Holds information about a single exported symbol from the PE export table.
///
/// Ported from `ghidra.app.util.bin.format.pe.ExportInfo`.
#[derive(Debug, Clone)]
pub struct ExportInfo {
    /// The address (RVA) where the export occurs.
    address: u64,
    /// The ordinal value of the export.
    ordinal: u32,
    /// The name of the export, if any.
    name: Option<String>,
    /// Additional comment or forwarder information.
    comment: Option<String>,
    /// Whether this export is forwarded to another DLL.
    forwarded: bool,
}

impl ExportInfo {
    /// Creates a new `ExportInfo`.
    pub fn new(
        address: u64,
        ordinal: u32,
        name: Option<String>,
        comment: Option<String>,
        forwarded: bool,
    ) -> Self {
        ExportInfo {
            address,
            ordinal,
            name,
            comment,
            forwarded,
        }
    }

    /// Returns the address where the export occurs.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Returns the ordinal value.
    pub fn ordinal(&self) -> u32 {
        self.ordinal
    }

    /// Returns the export name, if any.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Returns the comment or forwarder string, if any.
    pub fn comment(&self) -> Option<&str> {
        self.comment.as_deref()
    }

    /// Returns `true` if this export is forwarded to another DLL.
    pub fn is_forwarded(&self) -> bool {
        self.forwarded
    }
}

impl fmt::Display for ExportInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = self.name.as_deref().unwrap_or("<unnamed>");
        write!(f, "{} {} at 0x{:x}", self.ordinal, name, self.address)
    }
}

// ---------------------------------------------------------------------------
// ImportDescriptor
// ---------------------------------------------------------------------------

/// Represents an `IMAGE_IMPORT_DESCRIPTOR` entry from the PE import table.
///
/// ```text
/// typedef struct _IMAGE_IMPORT_DESCRIPTOR {
///     union {
///         DWORD   Characteristics;            // 0 for terminating null import descriptor
///         DWORD   OriginalFirstThunk;         // RVA to original unbound IAT
///     };
///     DWORD   TimeDateStamp;
///     DWORD   ForwarderChain;                 // -1 if no forwarders
///     DWORD   Name;                           // RVA to DLL name
///     DWORD   FirstThunk;                     // RVA to IAT
/// };
/// ```
///
/// Ported from `ghidra.app.util.bin.format.pe.ImportDescriptor`.
#[derive(Debug, Clone)]
pub struct ImportDescriptor {
    /// RVA to the original unbound IAT (same as Characteristics).
    original_first_thunk: u32,
    /// The time/date stamp indicating when the file was bound.
    time_date_stamp: u32,
    /// The forwarder chain index.
    forwarder_chain: u32,
    /// RVA to the null-terminated ASCII DLL name.
    name: u32,
    /// RVA to the IAT (Import Address Table).
    first_thunk: u32,
    /// The resolved DLL name (populated after parsing).
    dll: Option<String>,
    /// The Import Name Table entries (RVAs or ordinal flags).
    int_entries: Vec<u64>,
    /// The Import Address Table entries.
    iat_entries: Vec<u64>,
}

/// The size of an `IMAGE_IMPORT_DESCRIPTOR` structure in bytes.
pub const IMAGE_IMPORT_DESCRIPTOR_SIZE: usize = 20;

/// Value indicating an unbound import.
pub const IMPORT_NOT_BOUND: u32 = 0;

impl ImportDescriptor {
    /// Parses an import descriptor from the given data at the specified offset.
    pub fn parse(data: &[u8], offset: usize) -> io::Result<Self> {
        if data.len() < offset + IMAGE_IMPORT_DESCRIPTOR_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough data for IMAGE_IMPORT_DESCRIPTOR",
            ));
        }

        let original_first_thunk = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let time_date_stamp = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);
        let forwarder_chain = u32::from_le_bytes([
            data[offset + 8],
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
        ]);
        let name = u32::from_le_bytes([
            data[offset + 12],
            data[offset + 13],
            data[offset + 14],
            data[offset + 15],
        ]);
        let first_thunk = u32::from_le_bytes([
            data[offset + 16],
            data[offset + 17],
            data[offset + 18],
            data[offset + 19],
        ]);

        Ok(ImportDescriptor {
            original_first_thunk,
            time_date_stamp,
            forwarder_chain,
            name,
            first_thunk,
            dll: None,
            int_entries: Vec::new(),
            iat_entries: Vec::new(),
        })
    }

    /// Creates a zero-initialized import descriptor (null terminator).
    pub fn null_entry() -> Self {
        ImportDescriptor {
            original_first_thunk: 0,
            time_date_stamp: 0,
            forwarder_chain: 0,
            name: 0,
            first_thunk: 0,
            dll: None,
            int_entries: Vec::new(),
            iat_entries: Vec::new(),
        }
    }

    /// Returns `true` if this is a null terminator entry.
    pub fn is_null_entry(&self) -> bool {
        self.original_first_thunk == 0
            && self.time_date_stamp == 0
            && self.forwarder_chain == 0
            && self.name == 0
            && self.first_thunk == 0
    }

    /// Returns the RVA to the original unbound IAT.
    pub fn original_first_thunk(&self) -> u32 {
        self.original_first_thunk
    }

    /// Returns the characteristics field (same as original_first_thunk).
    pub fn characteristics(&self) -> u32 {
        self.original_first_thunk
    }

    /// Returns the time/date stamp.
    pub fn time_date_stamp(&self) -> u32 {
        self.time_date_stamp
    }

    /// Returns the forwarder chain index.
    pub fn forwarder_chain(&self) -> u32 {
        self.forwarder_chain
    }

    /// Returns the RVA to the DLL name string.
    pub fn name_rva(&self) -> u32 {
        self.name
    }

    /// Returns the RVA to the IAT.
    pub fn first_thunk(&self) -> u32 {
        self.first_thunk
    }

    /// Returns `true` if this import is bound (has a non-zero time date stamp).
    pub fn is_bound(&self) -> bool {
        self.time_date_stamp != IMPORT_NOT_BOUND
    }

    /// Returns the resolved DLL name, if available.
    pub fn dll(&self) -> Option<&str> {
        self.dll.as_deref()
    }

    /// Sets the resolved DLL name.
    pub fn set_dll(&mut self, dll: String) {
        self.dll = Some(dll);
    }

    /// Returns a reference to the INT (Import Name Table) entries.
    pub fn int_entries(&self) -> &[u64] {
        &self.int_entries
    }

    /// Returns a reference to the IAT (Import Address Table) entries.
    pub fn iat_entries(&self) -> &[u64] {
        &self.iat_entries
    }

    /// Adds an entry to the Import Name Table.
    pub fn add_int_entry(&mut self, entry: u64) {
        self.int_entries.push(entry);
    }

    /// Adds an entry to the Import Address Table.
    pub fn add_iat_entry(&mut self, entry: u64) {
        self.iat_entries.push(entry);
    }

    /// Serializes this import descriptor to bytes (little-endian).
    pub fn to_bytes(&self) -> [u8; IMAGE_IMPORT_DESCRIPTOR_SIZE] {
        let mut buf = [0u8; IMAGE_IMPORT_DESCRIPTOR_SIZE];
        buf[0..4].copy_from_slice(&self.original_first_thunk.to_le_bytes());
        buf[4..8].copy_from_slice(&self.time_date_stamp.to_le_bytes());
        buf[8..12].copy_from_slice(&self.forwarder_chain.to_le_bytes());
        buf[12..16].copy_from_slice(&self.name.to_le_bytes());
        buf[16..20].copy_from_slice(&self.first_thunk.to_le_bytes());
        buf
    }
}

impl fmt::Display for ImportDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dll_name = self.dll.as_deref().unwrap_or("<unknown>");
        write!(
            f,
            "ImportDescriptor: DLL='{}' Name=0x{:08X} INT=0x{:08X} IAT=0x{:08X}",
            dll_name, self.name, self.original_first_thunk, self.first_thunk
        )
    }
}

// ---------------------------------------------------------------------------
// ExportDataDirectory
// ---------------------------------------------------------------------------

/// Represents the PE export directory (`IMAGE_EXPORT_DIRECTORY`).
///
/// Contains metadata about exported functions, including the DLL name,
/// ordinal base, and pointers to the export address table, name table,
/// and ordinal table.
#[derive(Debug, Clone)]
pub struct ExportDataDirectory {
    /// The raw data directory entry.
    entry: DataDirectoryEntry,
    /// Whether parsing was successful.
    parsed: bool,
    /// Export flags (reserved, usually 0).
    characteristics: u32,
    /// The time/date stamp.
    time_date_stamp: u32,
    /// The major version.
    major_version: u16,
    /// The minor version.
    minor_version: u16,
    /// RVA of the DLL name.
    name_rva: u32,
    /// The ordinal base.
    ordinal_base: u32,
    /// The number of exported functions.
    number_of_functions: u32,
    /// The number of exported names.
    number_of_names: u32,
    /// RVA of the Export Address Table.
    address_of_functions: u32,
    /// RVA of the Export Name Pointer Table.
    address_of_names: u32,
    /// RVA of the Export Ordinal Table.
    address_of_name_ordinals: u32,
}

/// The size of the `IMAGE_EXPORT_DIRECTORY` structure.
pub const IMAGE_EXPORT_DIRECTORY_SIZE: usize = 40;

impl ExportDataDirectory {
    /// Parses an export data directory from the raw data.
    ///
    /// `data` is the full file content. `rva_to_offset` is a closure that
    /// converts an RVA to a file offset. `entry` is the data directory entry.
    pub fn parse<F>(
        data: &[u8],
        entry: DataDirectoryEntry,
        rva_to_offset: F,
    ) -> io::Result<Self>
    where
        F: Fn(u32) -> Option<u64>,
    {
        let offset = rva_to_offset(entry.virtual_address)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "Invalid RVA for export directory")
            })? as usize;

        if data.len() < offset + IMAGE_EXPORT_DIRECTORY_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough data for IMAGE_EXPORT_DIRECTORY",
            ));
        }

        let characteristics = u32::from_le_bytes(data[offset..offset+4].try_into().unwrap());
        let time_date_stamp = u32::from_le_bytes(data[offset+4..offset+8].try_into().unwrap());
        let major_version = u16::from_le_bytes([data[offset+8], data[offset+9]]);
        let minor_version = u16::from_le_bytes([data[offset+10], data[offset+11]]);
        let name_rva = u32::from_le_bytes(data[offset+12..offset+16].try_into().unwrap());
        let ordinal_base = u32::from_le_bytes(data[offset+16..offset+20].try_into().unwrap());
        let number_of_functions = u32::from_le_bytes(data[offset+20..offset+24].try_into().unwrap());
        let number_of_names = u32::from_le_bytes(data[offset+24..offset+28].try_into().unwrap());
        let address_of_functions = u32::from_le_bytes(data[offset+28..offset+32].try_into().unwrap());
        let address_of_names = u32::from_le_bytes(data[offset+32..offset+36].try_into().unwrap());
        let address_of_name_ordinals = u32::from_le_bytes(data[offset+36..offset+40].try_into().unwrap());

        Ok(ExportDataDirectory {
            entry,
            parsed: true,
            characteristics,
            time_date_stamp,
            major_version,
            minor_version,
            name_rva,
            ordinal_base,
            number_of_functions,
            number_of_names,
            address_of_functions,
            address_of_names,
            address_of_name_ordinals,
        })
    }

    /// Returns the export DLL name by reading from the data.
    pub fn dll_name<F>(&self, data: &[u8], rva_to_offset: F) -> Option<String>
    where
        F: Fn(u32) -> Option<u64>,
    {
        let offset = rva_to_offset(self.name_rva)? as usize;
        if offset >= data.len() {
            return None;
        }
        let end = data[offset..].iter().position(|&b| b == 0).unwrap_or(data.len() - offset);
        String::from_utf8(data[offset..offset + end].to_vec()).ok()
    }

    /// Returns the characteristics field.
    pub fn characteristics(&self) -> u32 {
        self.characteristics
    }

    /// Returns the time/date stamp.
    pub fn time_date_stamp(&self) -> u32 {
        self.time_date_stamp
    }

    /// Returns the major version.
    pub fn major_version(&self) -> u16 {
        self.major_version
    }

    /// Returns the minor version.
    pub fn minor_version(&self) -> u16 {
        self.minor_version
    }

    /// Returns the RVA of the DLL name.
    pub fn name_rva(&self) -> u32 {
        self.name_rva
    }

    /// Returns the ordinal base.
    pub fn ordinal_base(&self) -> u32 {
        self.ordinal_base
    }

    /// Returns the number of exported functions.
    pub fn number_of_functions(&self) -> u32 {
        self.number_of_functions
    }

    /// Returns the number of exported names.
    pub fn number_of_names(&self) -> u32 {
        self.number_of_names
    }

    /// Returns the RVA of the Export Address Table.
    pub fn address_of_functions(&self) -> u32 {
        self.address_of_functions
    }

    /// Returns the RVA of the Export Name Pointer Table.
    pub fn address_of_names(&self) -> u32 {
        self.address_of_names
    }

    /// Returns the RVA of the Export Ordinal Table.
    pub fn address_of_name_ordinals(&self) -> u32 {
        self.address_of_name_ordinals
    }

    /// Reads the exported function addresses from the data.
    pub fn read_function_addresses<F>(
        &self,
        data: &[u8],
        rva_to_offset: &F,
    ) -> io::Result<Vec<u32>>
    where
        F: Fn(u32) -> Option<u64>,
    {
        let offset = rva_to_offset(self.address_of_functions)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid EAT RVA"))?
            as usize;
        let count = self.number_of_functions as usize;
        if data.len() < offset + count * 4 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Not enough data for EAT"));
        }
        let mut addrs = Vec::with_capacity(count);
        for i in 0..count {
            let pos = offset + i * 4;
            addrs.push(u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()));
        }
        Ok(addrs)
    }

    /// Reads the exported name RVAs from the data.
    pub fn read_name_rvas<F>(
        &self,
        data: &[u8],
        rva_to_offset: &F,
    ) -> io::Result<Vec<u32>>
    where
        F: Fn(u32) -> Option<u64>,
    {
        let offset = rva_to_offset(self.address_of_names)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid name table RVA"))?
            as usize;
        let count = self.number_of_names as usize;
        if data.len() < offset + count * 4 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Not enough data for name table"));
        }
        let mut rvas = Vec::with_capacity(count);
        for i in 0..count {
            let pos = offset + i * 4;
            rvas.push(u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()));
        }
        Ok(rvas)
    }

    /// Reads the exported ordinal table (array of u16) from the data.
    pub fn read_ordinals<F>(
        &self,
        data: &[u8],
        rva_to_offset: &F,
    ) -> io::Result<Vec<u16>>
    where
        F: Fn(u32) -> Option<u64>,
    {
        let offset = rva_to_offset(self.address_of_name_ordinals)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Invalid ordinal table RVA"))?
            as usize;
        let count = self.number_of_names as usize;
        if data.len() < offset + count * 2 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Not enough data for ordinal table"));
        }
        let mut ords = Vec::with_capacity(count);
        for i in 0..count {
            let pos = offset + i * 2;
            ords.push(u16::from_le_bytes([data[pos], data[pos + 1]]));
        }
        Ok(ords)
    }
}

impl DataDirectory for ExportDataDirectory {
    fn directory_name(&self) -> &'static str {
        "Export Directory"
    }

    fn virtual_address(&self) -> u32 {
        self.entry.virtual_address
    }

    fn directory_size(&self) -> u32 {
        self.entry.size
    }

    fn has_parsed_correctly(&self) -> bool {
        self.parsed
    }

    fn entry(&self) -> &DataDirectoryEntry {
        &self.entry
    }
}

impl fmt::Display for ExportDataDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ExportDataDirectory: VA=0x{:08X} Size={} OrdinalBase={} Functions={} Names={}",
            self.entry.virtual_address,
            self.entry.size,
            self.ordinal_base,
            self.number_of_functions,
            self.number_of_names
        )
    }
}

// ---------------------------------------------------------------------------
// DebugDataDirectory
// ---------------------------------------------------------------------------

/// Represents a single debug directory entry (`IMAGE_DEBUG_DIRECTORY`).
///
/// ```text
/// typedef struct _IMAGE_DEBUG_DIRECTORY {
///     DWORD   Characteristics;
///     DWORD   TimeDateStamp;
///     WORD    MajorVersion;
///     WORD    MinorVersion;
///     DWORD   Type;
///     DWORD   SizeOfData;
///     DWORD   AddressOfRawData;
///     DWORD   PointerToRawData;
/// };
/// ```
#[derive(Debug, Clone, Copy)]
pub struct DebugDirectoryEntry {
    /// Debug characteristics (usually 0).
    pub characteristics: u32,
    /// The time/date stamp.
    pub time_date_stamp: u32,
    /// The major version.
    pub major_version: u16,
    /// The minor version.
    pub minor_version: u16,
    /// The debug type (e.g., IMAGE_DEBUG_TYPE_CODEVIEW = 2).
    pub debug_type: u32,
    /// The size of the debug data.
    pub size_of_data: u32,
    /// The RVA of the debug data when loaded.
    pub address_of_raw_data: u32,
    /// The file pointer to the debug data.
    pub pointer_to_raw_data: u32,
}

/// The size of an `IMAGE_DEBUG_DIRECTORY` entry.
pub const IMAGE_DEBUG_DIRECTORY_SIZE: usize = 28;

impl DebugDirectoryEntry {
    /// Parses a debug directory entry from the given data at the specified offset.
    pub fn parse(data: &[u8], offset: usize) -> io::Result<Self> {
        if data.len() < offset + IMAGE_DEBUG_DIRECTORY_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough data for IMAGE_DEBUG_DIRECTORY",
            ));
        }
        Ok(DebugDirectoryEntry {
            characteristics: u32::from_le_bytes(data[offset..offset+4].try_into().unwrap()),
            time_date_stamp: u32::from_le_bytes(data[offset+4..offset+8].try_into().unwrap()),
            major_version: u16::from_le_bytes([data[offset+8], data[offset+9]]),
            minor_version: u16::from_le_bytes([data[offset+10], data[offset+11]]),
            debug_type: u32::from_le_bytes(data[offset+12..offset+16].try_into().unwrap()),
            size_of_data: u32::from_le_bytes(data[offset+16..offset+20].try_into().unwrap()),
            address_of_raw_data: u32::from_le_bytes(data[offset+20..offset+24].try_into().unwrap()),
            pointer_to_raw_data: u32::from_le_bytes(data[offset+24..offset+28].try_into().unwrap()),
        })
    }

    /// Returns the debug type name.
    pub fn type_name(&self) -> &'static str {
        match self.debug_type {
            0 => "UNKNOWN",
            1 => "COFF",
            2 => "CODEVIEW",
            3 => "FPO",
            4 => "MISC",
            5 => "EXCEPTION",
            6 => "FIXUP",
            7 => "OMAP_TO_SRC",
            8 => "OMAP_FROM_SRC",
            9 => "BORLAND",
            10 => "RESERVED10",
            11 => "CLSID",
            12 => "VC_FEATURE",
            13 => "POGO",
            14 => "ILTCG",
            15 => "MPX",
            16 => "REPRO",
            _ => "UNKNOWN",
        }
    }
}

impl fmt::Display for DebugDirectoryEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DebugDirectory: Type={} ({}) Size={} RawData=0x{:08X}",
            self.debug_type,
            self.type_name(),
            self.size_of_data,
            self.pointer_to_raw_data
        )
    }
}

/// Represents the PE debug data directory.
#[derive(Debug, Clone)]
pub struct DebugDataDirectory {
    /// The raw data directory entry.
    entry: DataDirectoryEntry,
    /// Whether parsing was successful.
    parsed: bool,
    /// The parsed debug directory entries.
    entries: Vec<DebugDirectoryEntry>,
}

impl DebugDataDirectory {
    /// Parses the debug data directory from raw data.
    pub fn parse<F>(
        data: &[u8],
        entry: DataDirectoryEntry,
        rva_to_offset: F,
    ) -> io::Result<Self>
    where
        F: Fn(u32) -> Option<u64>,
    {
        let parsed = if entry.virtual_address == 0 {
            false
        } else {
            true
        };

        let mut entries = Vec::new();
        if parsed {
            let offset = rva_to_offset(entry.virtual_address)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Invalid RVA for debug directory")
                })? as usize;
            let count = if entry.size >= IMAGE_DEBUG_DIRECTORY_SIZE as u32 {
                (entry.size as usize) / IMAGE_DEBUG_DIRECTORY_SIZE
            } else {
                0
            };
            for i in 0..count {
                let entry_offset = offset + i * IMAGE_DEBUG_DIRECTORY_SIZE;
                if entry_offset + IMAGE_DEBUG_DIRECTORY_SIZE > data.len() {
                    break;
                }
                entries.push(DebugDirectoryEntry::parse(data, entry_offset)?);
            }
        }

        Ok(DebugDataDirectory {
            entry,
            parsed,
            entries,
        })
    }

    /// Returns the parsed debug directory entries.
    pub fn entries(&self) -> &[DebugDirectoryEntry] {
        &self.entries
    }
}

impl DataDirectory for DebugDataDirectory {
    fn directory_name(&self) -> &'static str {
        "Debug Directory"
    }

    fn virtual_address(&self) -> u32 {
        self.entry.virtual_address
    }

    fn directory_size(&self) -> u32 {
        self.entry.size
    }

    fn has_parsed_correctly(&self) -> bool {
        self.parsed
    }

    fn entry(&self) -> &DataDirectoryEntry {
        &self.entry
    }
}

impl fmt::Display for DebugDataDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DebugDataDirectory: VA=0x{:08X} Size={} Entries={}",
            self.entry.virtual_address,
            self.entry.size,
            self.entries.len()
        )
    }
}

// ---------------------------------------------------------------------------
// BoundImportEntry
// ---------------------------------------------------------------------------

/// A single bound import entry.
///
/// ```text
/// typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
///     DWORD   TimeDateStamp;
///    WORD    OffsetModuleName;
///    WORD    NumberOfModuleForwarderRefs;
/// };
/// ```
#[derive(Debug, Clone, Copy)]
pub struct BoundImportEntry {
    /// The time/date stamp of the bound DLL.
    pub time_date_stamp: u32,
    /// The offset (from the start of the bound import table) to the DLL name.
    pub offset_module_name: u16,
    /// The number of module forwarder references.
    pub number_of_module_forwarder_refs: u16,
}

/// The size of an `IMAGE_BOUND_IMPORT_DESCRIPTOR`.
pub const IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE: usize = 8;

impl BoundImportEntry {
    /// Parses a bound import entry from the given data at the specified offset.
    pub fn parse(data: &[u8], offset: usize) -> io::Result<Self> {
        if data.len() < offset + IMAGE_BOUND_IMPORT_DESCRIPTOR_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough data for IMAGE_BOUND_IMPORT_DESCRIPTOR",
            ));
        }
        Ok(BoundImportEntry {
            time_date_stamp: u32::from_le_bytes(data[offset..offset+4].try_into().unwrap()),
            offset_module_name: u16::from_le_bytes([data[offset+4], data[offset+5]]),
            number_of_module_forwarder_refs: u16::from_le_bytes([data[offset+6], data[offset+7]]),
        })
    }
}

impl fmt::Display for BoundImportEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BoundImport: timestamp=0x{:08X} name_offset=0x{:04X} forwarders={}",
            self.time_date_stamp, self.offset_module_name, self.number_of_module_forwarder_refs
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_data_directory() {
        let entry = DataDirectoryEntry {
            virtual_address: 0x2000,
            size: 0x100,
        };
        let dd = DefaultDataDirectory::new(0, entry);
        assert_eq!(dd.directory_name(), "Export Directory");
        assert_eq!(dd.virtual_address(), 0x2000);
        assert_eq!(dd.directory_size(), 0x100);
        assert!(dd.has_parsed_correctly());
        assert!(dd.is_present());
    }

    #[test]
    fn test_default_data_directory_empty() {
        let entry = DataDirectoryEntry {
            virtual_address: 0,
            size: 0,
        };
        let dd = DefaultDataDirectory::new(15, entry);
        assert_eq!(dd.directory_name(), "Reserved");
        assert!(!dd.has_parsed_correctly());
        assert!(!dd.is_present());
    }

    #[test]
    fn test_export_info() {
        let info = ExportInfo::new(
            0x1234,
            1,
            Some("MyFunction".to_string()),
            Some("forwarded to other.dll".to_string()),
            true,
        );
        assert_eq!(info.address(), 0x1234);
        assert_eq!(info.ordinal(), 1);
        assert_eq!(info.name(), Some("MyFunction"));
        assert!(info.is_forwarded());
        assert_eq!(info.comment(), Some("forwarded to other.dll"));
        assert_eq!(info.to_string(), "1 MyFunction at 0x1234");
    }

    #[test]
    fn test_export_info_no_name() {
        let info = ExportInfo::new(0x5678, 42, None, None, false);
        assert_eq!(info.name(), None);
        assert!(!info.is_forwarded());
        assert!(info.to_string().contains("<unnamed>"));
    }

    #[test]
    fn test_import_descriptor_parse() {
        let mut data = [0u8; 20];
        data[0..4].copy_from_slice(&0x1000u32.to_le_bytes()); // OriginalFirstThunk
        data[4..8].copy_from_slice(&0x12345678u32.to_le_bytes()); // TimeDateStamp
        data[8..12].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // ForwarderChain
        data[12..16].copy_from_slice(&0x2000u32.to_le_bytes()); // Name
        data[16..20].copy_from_slice(&0x3000u32.to_le_bytes()); // FirstThunk

        let desc = ImportDescriptor::parse(&data, 0).unwrap();
        assert_eq!(desc.original_first_thunk(), 0x1000);
        assert_eq!(desc.characteristics(), 0x1000);
        assert_eq!(desc.time_date_stamp(), 0x12345678);
        assert_eq!(desc.forwarder_chain(), 0xFFFFFFFF);
        assert_eq!(desc.name_rva(), 0x2000);
        assert_eq!(desc.first_thunk(), 0x3000);
        assert!(desc.is_bound());
        assert!(!desc.is_null_entry());
        assert!(desc.dll().is_none());
    }

    #[test]
    fn test_import_descriptor_null_entry() {
        let desc = ImportDescriptor::null_entry();
        assert!(desc.is_null_entry());
        assert!(!desc.is_bound());
        assert_eq!(desc.original_first_thunk(), 0);
        assert_eq!(desc.time_date_stamp(), 0);
    }

    #[test]
    fn test_import_descriptor_to_bytes() {
        let desc = ImportDescriptor::parse(
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19],
            0,
        )
        .unwrap();
        let bytes = desc.to_bytes();
        assert_eq!(bytes[0..4], [0, 1, 2, 3]);
        assert_eq!(bytes[4..8], [4, 5, 6, 7]);
        assert_eq!(bytes[16..20], [16, 17, 18, 19]);
    }

    #[test]
    fn test_import_descriptor_dll() {
        let mut desc = ImportDescriptor::null_entry();
        desc.set_dll("KERNEL32.DLL".to_string());
        assert_eq!(desc.dll(), Some("KERNEL32.DLL"));
        assert!(desc.to_string().contains("KERNEL32.DLL"));
    }

    #[test]
    fn test_import_descriptor_entries() {
        let mut desc = ImportDescriptor::null_entry();
        desc.add_int_entry(0x1000);
        desc.add_int_entry(0x1004);
        desc.add_iat_entry(0x7FFE_0000);
        assert_eq!(desc.int_entries().len(), 2);
        assert_eq!(desc.iat_entries().len(), 1);
    }

    #[test]
    fn test_import_descriptor_insufficient_data() {
        let data = [0u8; 10];
        assert!(ImportDescriptor::parse(&data, 0).is_err());
    }

    #[test]
    fn test_debug_directory_entry_parse() {
        let mut data = [0u8; 28];
        data[12..16].copy_from_slice(&2u32.to_le_bytes()); // Type = CODEVIEW
        data[16..20].copy_from_slice(&0x100u32.to_le_bytes()); // SizeOfData
        data[24..28].copy_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData

        let entry = DebugDirectoryEntry::parse(&data, 0).unwrap();
        assert_eq!(entry.debug_type, 2);
        assert_eq!(entry.type_name(), "CODEVIEW");
        assert_eq!(entry.size_of_data, 0x100);
        assert_eq!(entry.pointer_to_raw_data, 0x400);
    }

    #[test]
    fn test_debug_directory_entry_type_names() {
        let mut data = [0u8; 28];
        for &(type_val, name) in &[
            (0u32, "UNKNOWN"),
            (1, "COFF"),
            (2, "CODEVIEW"),
            (3, "FPO"),
            (4, "MISC"),
            (5, "EXCEPTION"),
            (6, "FIXUP"),
        ] {
            data[12..16].copy_from_slice(&type_val.to_le_bytes());
            let entry = DebugDirectoryEntry::parse(&data, 0).unwrap();
            assert_eq!(entry.type_name(), name);
        }
    }

    #[test]
    fn test_bound_import_entry_parse() {
        let mut data = [0u8; 8];
        data[0..4].copy_from_slice(&0xABCD1234u32.to_le_bytes());
        data[4..6].copy_from_slice(&0x10u16.to_le_bytes());
        data[6..8].copy_from_slice(&2u16.to_le_bytes());

        let entry = BoundImportEntry::parse(&data, 0).unwrap();
        assert_eq!(entry.time_date_stamp, 0xABCD1234);
        assert_eq!(entry.offset_module_name, 0x10);
        assert_eq!(entry.number_of_module_forwarder_refs, 2);
        assert!(entry.to_string().contains("0xABCD1234"));
    }

    #[test]
    fn test_bound_import_entry_insufficient_data() {
        let data = [0u8; 4];
        assert!(BoundImportEntry::parse(&data, 0).is_err());
    }

    #[test]
    fn test_export_data_directory_parse() {
        let mut data = vec![0u8; 0x1000];
        // Export directory at offset 0x200
        let offset = 0x200;
        data[offset..offset+4].copy_from_slice(&0u32.to_le_bytes()); // Characteristics
        data[offset+4..offset+8].copy_from_slice(&0x12345678u32.to_le_bytes()); // TimeDateStamp
        data[offset+8..offset+10].copy_from_slice(&1u16.to_le_bytes()); // MajorVersion
        data[offset+10..offset+12].copy_from_slice(&0u16.to_le_bytes()); // MinorVersion
        data[offset+12..offset+16].copy_from_slice(&0x500u32.to_le_bytes()); // NameRVA
        data[offset+16..offset+20].copy_from_slice(&1u32.to_le_bytes()); // OrdinalBase
        data[offset+20..offset+24].copy_from_slice(&3u32.to_le_bytes()); // NumberOfFunctions
        data[offset+24..offset+28].copy_from_slice(&2u32.to_le_bytes()); // NumberOfNames
        data[offset+28..offset+32].copy_from_slice(&0x600u32.to_le_bytes()); // AddressOfFunctions
        data[offset+32..offset+36].copy_from_slice(&0x700u32.to_le_bytes()); // AddressOfNames
        data[offset+36..offset+40].copy_from_slice(&0x800u32.to_le_bytes()); // AddressOfNameOrdinals

        // DLL name at offset 0x500
        data[0x500..0x500+9].copy_from_slice(b"test.dll\0");

        let entry = DataDirectoryEntry {
            virtual_address: 0x200,
            size: 40,
        };

        let rva_to_offset = |rva: u32| -> Option<u64> { Some(rva as u64) };
        let export_dir = ExportDataDirectory::parse(&data, entry, rva_to_offset).unwrap();
        assert_eq!(export_dir.ordinal_base(), 1);
        assert_eq!(export_dir.number_of_functions(), 3);
        assert_eq!(export_dir.number_of_names(), 2);
        assert_eq!(export_dir.address_of_functions(), 0x600);
        assert!(export_dir.has_parsed_correctly());

        let dll_name = export_dir.dll_name(&data, |rva| Some(rva as u64)).unwrap();
        assert_eq!(dll_name, "test.dll");
    }

    #[test]
    fn test_export_data_directory_display() {
        let entry = DataDirectoryEntry {
            virtual_address: 0x2000,
            size: 100,
        };
        let data = vec![0u8; 0x3000];
        let rva_to_offset = |rva: u32| -> Option<u64> { Some(rva as u64) };
        let export_dir = ExportDataDirectory::parse(&data, entry, rva_to_offset).unwrap();
        let display = format!("{}", export_dir);
        assert!(display.contains("ExportDataDirectory"));
        assert!(display.contains("0x00002000"));
    }

    #[test]
    fn test_export_data_directory_invalid_rva() {
        let entry = DataDirectoryEntry {
            virtual_address: 0x2000,
            size: 40,
        };
        let data = vec![0u8; 0x100]; // Too small
        let rva_to_offset = |_rva: u32| -> Option<u64> { None };
        let result = ExportDataDirectory::parse(&data, entry, rva_to_offset);
        assert!(result.is_err());
    }

    #[test]
    fn test_debug_data_directory_parse() {
        let mut data = vec![0u8; 0x1000];
        // One debug entry at offset 0x200
        let offset = 0x200;
        data[offset+12..offset+16].copy_from_slice(&2u32.to_le_bytes()); // Type = CODEVIEW
        data[offset+16..offset+20].copy_from_slice(&0x100u32.to_le_bytes()); // SizeOfData

        let entry = DataDirectoryEntry {
            virtual_address: 0x200,
            size: IMAGE_DEBUG_DIRECTORY_SIZE as u32,
        };
        let debug_dir = DebugDataDirectory::parse(&data, entry, |rva| Some(rva as u64)).unwrap();
        assert!(debug_dir.has_parsed_correctly());
        assert_eq!(debug_dir.entries().len(), 1);
        assert_eq!(debug_dir.entries()[0].debug_type, 2);
    }

    #[test]
    fn test_debug_data_directory_empty() {
        let entry = DataDirectoryEntry {
            virtual_address: 0,
            size: 0,
        };
        let data = vec![0u8; 0x100];
        let debug_dir = DebugDataDirectory::parse(&data, entry, |rva| Some(rva as u64)).unwrap();
        assert!(!debug_dir.has_parsed_correctly());
        assert!(debug_dir.entries().is_empty());
    }

    #[test]
    fn test_data_directory_trait() {
        let entry = DataDirectoryEntry {
            virtual_address: 0x3000,
            size: 0x200,
        };
        let dd = DefaultDataDirectory::new(1, entry);
        // Verify trait methods work through trait object
        let dyn_ref: &dyn DataDirectory = &dd;
        assert_eq!(dyn_ref.directory_name(), "Import Directory");
        assert_eq!(dyn_ref.virtual_address(), 0x3000);
        assert_eq!(dyn_ref.directory_size(), 0x200);
    }
}
