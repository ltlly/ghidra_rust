//! PE Import Thunk Data and Import-by-Name ported from Ghidra's
//! `ghidra.app.util.bin.format.pe.ThunkData` and
//! `ghidra.app.util.bin.format.pe.ImportByName`.
//!
//! Provides:
//! - [`ImportByName`] -- represents `IMAGE_IMPORT_BY_NAME` (hint + name)
//! - [`ThunkData`] -- represents `IMAGE_THUNK_DATA32` / `IMAGE_THUNK_DATA64`
//! - [`OrdinalOrName`] -- resolved import (ordinal or named)
//!
//! These structures are used when parsing the PE import table to resolve
//! imported function names and ordinals.

use std::fmt;
use std::io;

use super::pe_constants::{IMAGE_ORDINAL_FLAG32, IMAGE_ORDINAL_FLAG64};

// ---------------------------------------------------------------------------
// ImportByName
// ---------------------------------------------------------------------------

/// Represents `IMAGE_IMPORT_BY_NAME`.
///
/// ```text
/// typedef struct _IMAGE_IMPORT_BY_NAME {
///     WORD    Hint;
///     BYTE    Name[1];   // variable-length null-terminated
/// };
/// ```
///
/// The `Hint` field is an index into the export table that is used to
/// speed up the import lookup. The `Name` field is the null-terminated
/// ASCII name of the imported function.
///
/// Ported from `ghidra.app.util.bin.format.pe.ImportByName`.
#[derive(Debug, Clone)]
pub struct ImportByName {
    /// The hint/index into the export table.
    hint: u16,
    /// The null-terminated name of the imported function.
    name: String,
}

impl ImportByName {
    /// Parses an `ImportByName` structure from the given data at the specified offset.
    ///
    /// Reads the 2-byte hint, then reads a null-terminated ASCII string for the name.
    pub fn parse(data: &[u8], offset: usize) -> io::Result<Self> {
        if data.len() < offset + 2 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough data for ImportByName hint",
            ));
        }

        let hint = u16::from_le_bytes([data[offset], data[offset + 1]]);

        // Read null-terminated ASCII string starting at offset + 2
        let name_start = offset + 2;
        let name_end = data[name_start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_start + p)
            .unwrap_or(data.len());

        let name = String::from_utf8_lossy(&data[name_start..name_end]).into_owned();

        Ok(ImportByName { hint, name })
    }

    /// Creates a new `ImportByName` with the given hint and name.
    pub fn new(hint: u16, name: String) -> Self {
        ImportByName { hint, name }
    }

    /// Returns the hint value.
    pub fn hint(&self) -> u16 {
        self.hint
    }

    /// Returns the function name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the actual size of this structure in bytes
    /// (2 bytes for hint + name length + 1 for null terminator).
    pub fn size_of(&self) -> usize {
        2 + self.name.len() + 1
    }

    /// Serializes this structure to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size_of());
        buf.extend_from_slice(&self.hint.to_le_bytes());
        buf.extend_from_slice(self.name.as_bytes());
        buf.push(0); // null terminator
        buf
    }
}

impl fmt::Display for ImportByName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hint: 0x{:04X} Name: {}", self.hint, self.name)
    }
}

// ---------------------------------------------------------------------------
// ThunkData
// ---------------------------------------------------------------------------

/// Represents `IMAGE_THUNK_DATA32` or `IMAGE_THUNK_DATA64`.
///
/// ```text
/// typedef struct _IMAGE_THUNK_DATA32 {
///     union {
///         DWORD ForwarderString;
///         DWORD Function;
///         DWORD Ordinal;
///         DWORD AddressOfData;    // PIMAGE_IMPORT_BY_NAME
///     } u1;
/// } IMAGE_THUNK_DATA32;
///
/// typedef struct _IMAGE_THUNK_DATA64 {
///     union {
///         PBYTE  ForwarderString;
///         PDWORD Function;
///         ULONGLONG Ordinal;
///         PIMAGE_IMPORT_BY_NAME AddressOfData;
///     } u1;
/// } IMAGE_THUNK_DATA64;
/// ```
///
/// Ported from `ghidra.app.util.bin.format.pe.ThunkData`.
#[derive(Debug, Clone)]
pub struct ThunkData {
    /// Whether this is a 64-bit thunk.
    is_64bit: bool,
    /// The raw value (32 or 64 bit).
    value: u64,
    /// The resolved ImportByName structure, if this is a named import.
    import_by_name: Option<ImportByName>,
}

impl ThunkData {
    /// Parses a thunk data entry from the given data at the specified offset.
    ///
    /// `is_64bit` controls whether 4 or 8 bytes are read.
    pub fn parse(data: &[u8], offset: usize, is_64bit: bool) -> io::Result<Self> {
        let size = if is_64bit { 8 } else { 4 };
        if data.len() < offset + size {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "Not enough data for IMAGE_THUNK_DATA",
            ));
        }

        let value = if is_64bit {
            u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
        } else {
            u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as u64
        };

        Ok(ThunkData {
            is_64bit,
            value,
            import_by_name: None,
        })
    }

    /// Creates a new 32-bit thunk data with the specified value.
    pub fn new_32(value: u32) -> Self {
        ThunkData {
            is_64bit: false,
            value: value as u64,
            import_by_name: None,
        }
    }

    /// Creates a new 64-bit thunk data with the specified value.
    pub fn new_64(value: u64) -> Self {
        ThunkData {
            is_64bit: true,
            value,
            import_by_name: None,
        }
    }

    /// Returns the struct size (4 for 32-bit, 8 for 64-bit).
    pub fn struct_size(&self) -> usize {
        if self.is_64bit { 8 } else { 4 }
    }

    /// Returns the struct name.
    pub fn struct_name(&self) -> &'static str {
        if self.is_64bit {
            "IMAGE_THUNK_DATA64"
        } else {
            "IMAGE_THUNK_DATA32"
        }
    }

    /// Returns whether this is a 64-bit thunk.
    pub fn is_64bit(&self) -> bool {
        self.is_64bit
    }

    /// Returns the raw value.
    pub fn value(&self) -> u64 {
        self.value
    }

    /// Returns the forwarder string pointer.
    pub fn forwarder_string(&self) -> u64 {
        self.value
    }

    /// Returns the function pointer.
    pub fn function(&self) -> u64 {
        self.value
    }

    /// Returns the ordinal value (masked to 16 bits).
    pub fn ordinal(&self) -> u16 {
        (self.value & 0xFFFF) as u16
    }

    /// Returns `true` if this thunk represents an ordinal import.
    pub fn is_ordinal(&self) -> bool {
        if self.is_64bit {
            (self.value & IMAGE_ORDINAL_FLAG64) != 0
        } else {
            (self.value & IMAGE_ORDINAL_FLAG32 as u64) != 0
        }
    }

    /// Returns `true` if this is the null terminator entry.
    pub fn is_null(&self) -> bool {
        self.value == 0
    }

    /// Returns the address of data (RVA to `IMAGE_IMPORT_BY_NAME`).
    pub fn address_of_data(&self) -> u64 {
        self.value
    }

    /// Sets the resolved `ImportByName` structure.
    pub fn set_import_by_name(&mut self, ibn: ImportByName) {
        self.import_by_name = Some(ibn);
    }

    /// Returns a reference to the resolved `ImportByName`, if any.
    pub fn import_by_name(&self) -> Option<&ImportByName> {
        self.import_by_name.as_ref()
    }

    /// Returns the resolved import as an `OrdinalOrName`.
    pub fn resolved(&self) -> OrdinalOrName {
        if self.is_ordinal() {
            OrdinalOrName::Ordinal(self.ordinal())
        } else if let Some(ref ibn) = self.import_by_name {
            OrdinalOrName::Name {
                hint: ibn.hint(),
                name: ibn.name().to_string(),
            }
        } else {
            OrdinalOrName::Unresolved(self.value)
        }
    }

    /// Serializes this thunk data to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.is_64bit {
            self.value.to_le_bytes().to_vec()
        } else {
            (self.value as u32).to_le_bytes().to_vec()
        }
    }
}

impl fmt::Display for ThunkData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.resolved() {
            OrdinalOrName::Ordinal(ord) => {
                write!(f, "{} Ordinal: {}", self.struct_name(), ord)
            }
            OrdinalOrName::Name { hint, ref name } => {
                write!(f, "{} Hint: 0x{:04X} Name: {}", self.struct_name(), hint, name)
            }
            OrdinalOrName::Unresolved(val) => {
                write!(f, "{} Value: 0x{:X}", self.struct_name(), val)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// OrdinalOrName
// ---------------------------------------------------------------------------

/// Resolved import information: either an ordinal or a named import.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OrdinalOrName {
    /// Import by ordinal number.
    Ordinal(u16),
    /// Import by name (with hint).
    Name {
        /// The hint/index into the export table.
        hint: u16,
        /// The function name.
        name: String,
    },
    /// The import could not be resolved (still points to raw data).
    Unresolved(u64),
}

impl OrdinalOrName {
    /// Returns `true` if this is an ordinal import.
    pub fn is_ordinal(&self) -> bool {
        matches!(self, OrdinalOrName::Ordinal(_))
    }

    /// Returns `true` if this is a named import.
    pub fn is_name(&self) -> bool {
        matches!(self, OrdinalOrName::Name { .. })
    }

    /// Returns the ordinal, if this is an ordinal import.
    pub fn ordinal(&self) -> Option<u16> {
        match self {
            OrdinalOrName::Ordinal(ord) => Some(*ord),
            _ => None,
        }
    }

    /// Returns the name, if this is a named import.
    pub fn name(&self) -> Option<&str> {
        match self {
            OrdinalOrName::Name { name, .. } => Some(name),
            _ => None,
        }
    }

    /// Returns the hint, if this is a named import.
    pub fn hint(&self) -> Option<u16> {
        match self {
            OrdinalOrName::Name { hint, .. } => Some(*hint),
            _ => None,
        }
    }
}

impl fmt::Display for OrdinalOrName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OrdinalOrName::Ordinal(ord) => write!(f, "Ordinal({})", ord),
            OrdinalOrName::Name { hint, name } => {
                write!(f, "{} (hint: 0x{:04X})", name, hint)
            }
            OrdinalOrName::Unresolved(val) => write!(f, "Unresolved(0x{:X})", val),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_import_by_name_parse() {
        let mut data = vec![0u8; 20];
        // Hint = 0x0042
        data[0] = 0x42;
        data[1] = 0x00;
        // Name = "CreateFileA\0"
        let name_bytes = b"CreateFileA\0";
        data[2..2 + name_bytes.len()].copy_from_slice(name_bytes);

        let ibn = ImportByName::parse(&data, 0).unwrap();
        assert_eq!(ibn.hint(), 0x0042);
        assert_eq!(ibn.name(), "CreateFileA");
        assert_eq!(ibn.size_of(), 2 + 11 + 1); // hint + "CreateFileA" + null
    }

    #[test]
    fn test_import_by_name_new() {
        let ibn = ImportByName::new(0x100, "GetProcAddress".to_string());
        assert_eq!(ibn.hint(), 0x100);
        assert_eq!(ibn.name(), "GetProcAddress");
        assert_eq!(ibn.size_of(), 2 + 14 + 1);
    }

    #[test]
    fn test_import_by_name_to_bytes() {
        let ibn = ImportByName::new(0x10, "Test".to_string());
        let bytes = ibn.to_bytes();
        assert_eq!(bytes.len(), 2 + 4 + 1);
        assert_eq!(bytes[0], 0x10);
        assert_eq!(bytes[1], 0x00);
        assert_eq!(&bytes[2..6], b"Test");
        assert_eq!(bytes[6], 0);
    }

    #[test]
    fn test_import_by_name_display() {
        let ibn = ImportByName::new(0x42, "CreateFileA".to_string());
        assert_eq!(ibn.to_string(), "Hint: 0x0042 Name: CreateFileA");
    }

    #[test]
    fn test_import_by_name_insufficient_data() {
        let data = [0u8; 1];
        assert!(ImportByName::parse(&data, 0).is_err());
    }

    #[test]
    fn test_thunk_data_parse_32() {
        let mut data = [0u8; 4];
        data[0..4].copy_from_slice(&0x0000_2000u32.to_le_bytes());

        let thunk = ThunkData::parse(&data, 0, false).unwrap();
        assert!(!thunk.is_64bit());
        assert_eq!(thunk.value(), 0x2000);
        assert_eq!(thunk.struct_size(), 4);
        assert_eq!(thunk.struct_name(), "IMAGE_THUNK_DATA32");
        assert!(!thunk.is_ordinal());
        assert!(!thunk.is_null());
    }

    #[test]
    fn test_thunk_data_parse_64() {
        let mut data = [0u8; 8];
        data[0..8].copy_from_slice(&0x0001_4000_2000u64.to_le_bytes());

        let thunk = ThunkData::parse(&data, 0, true).unwrap();
        assert!(thunk.is_64bit());
        assert_eq!(thunk.value(), 0x0001_4000_2000);
        assert_eq!(thunk.struct_size(), 8);
        assert_eq!(thunk.struct_name(), "IMAGE_THUNK_DATA64");
    }

    #[test]
    fn test_thunk_data_ordinal_flag_32() {
        let thunk = ThunkData::new_32(IMAGE_ORDINAL_FLAG32 | 42);
        assert!(thunk.is_ordinal());
        assert_eq!(thunk.ordinal(), 42);
    }

    #[test]
    fn test_thunk_data_ordinal_flag_64() {
        let thunk = ThunkData::new_64(IMAGE_ORDINAL_FLAG64 | 100);
        assert!(thunk.is_ordinal());
        assert_eq!(thunk.ordinal(), 100);
    }

    #[test]
    fn test_thunk_data_not_ordinal() {
        let thunk = ThunkData::new_32(0x2000); // Regular RVA
        assert!(!thunk.is_ordinal());
    }

    #[test]
    fn test_thunk_data_null() {
        let thunk = ThunkData::new_32(0);
        assert!(thunk.is_null());
    }

    #[test]
    fn test_thunk_data_import_by_name() {
        let mut thunk = ThunkData::new_32(0x2000);
        assert!(thunk.import_by_name().is_none());

        let ibn = ImportByName::new(0x10, "MyFunc".to_string());
        thunk.set_import_by_name(ibn);
        assert!(thunk.import_by_name().is_some());
        assert_eq!(thunk.import_by_name().unwrap().name(), "MyFunc");
    }

    #[test]
    fn test_thunk_data_resolved_ordinal() {
        let thunk = ThunkData::new_32(IMAGE_ORDINAL_FLAG32 | 5);
        match thunk.resolved() {
            OrdinalOrName::Ordinal(ord) => assert_eq!(ord, 5),
            _ => panic!("Expected ordinal"),
        }
    }

    #[test]
    fn test_thunk_data_resolved_name() {
        let mut thunk = ThunkData::new_32(0x2000);
        thunk.set_import_by_name(ImportByName::new(0x42, "CreateFileW".to_string()));
        match thunk.resolved() {
            OrdinalOrName::Name { hint, name } => {
                assert_eq!(hint, 0x42);
                assert_eq!(name, "CreateFileW");
            }
            _ => panic!("Expected name"),
        }
    }

    #[test]
    fn test_thunk_data_resolved_unresolved() {
        let thunk = ThunkData::new_32(0x2000);
        match thunk.resolved() {
            OrdinalOrName::Unresolved(val) => assert_eq!(val, 0x2000),
            _ => panic!("Expected unresolved"),
        }
    }

    #[test]
    fn test_thunk_data_to_bytes_32() {
        let thunk = ThunkData::new_32(0xABCD1234);
        let bytes = thunk.to_bytes();
        assert_eq!(bytes.len(), 4);
        assert_eq!(&bytes, &0xABCD1234u32.to_le_bytes());
    }

    #[test]
    fn test_thunk_data_to_bytes_64() {
        let thunk = ThunkData::new_64(0x0001_4000_0000_2000);
        let bytes = thunk.to_bytes();
        assert_eq!(bytes.len(), 8);
        assert_eq!(&bytes, &0x0001_4000_0000_2000u64.to_le_bytes());
    }

    #[test]
    fn test_thunk_data_display_ordinal() {
        let thunk = ThunkData::new_32(IMAGE_ORDINAL_FLAG32 | 42);
        let display = format!("{}", thunk);
        assert!(display.contains("Ordinal: 42"));
    }

    #[test]
    fn test_thunk_data_display_name() {
        let mut thunk = ThunkData::new_32(0x2000);
        thunk.set_import_by_name(ImportByName::new(0x10, "MyFunc".to_string()));
        let display = format!("{}", thunk);
        assert!(display.contains("MyFunc"));
        assert!(display.contains("0x0010"));
    }

    #[test]
    fn test_thunk_data_display_unresolved() {
        let thunk = ThunkData::new_32(0x5000);
        let display = format!("{}", thunk);
        assert!(display.contains("0x5000"));
    }

    #[test]
    fn test_thunk_data_insufficient_data() {
        let data = [0u8; 2];
        assert!(ThunkData::parse(&data, 0, false).is_err());
        assert!(ThunkData::parse(&data, 0, true).is_err());
    }

    #[test]
    fn test_ordinal_or_name_equality() {
        assert_eq!(OrdinalOrName::Ordinal(5), OrdinalOrName::Ordinal(5));
        assert_ne!(OrdinalOrName::Ordinal(5), OrdinalOrName::Ordinal(6));
        assert_eq!(
            OrdinalOrName::Name {
                hint: 1,
                name: "foo".to_string()
            },
            OrdinalOrName::Name {
                hint: 1,
                name: "foo".to_string()
            }
        );
    }

    #[test]
    fn test_ordinal_or_name_accessors() {
        let ord = OrdinalOrName::Ordinal(42);
        assert!(ord.is_ordinal());
        assert!(!ord.is_name());
        assert_eq!(ord.ordinal(), Some(42));
        assert_eq!(ord.name(), None);
        assert_eq!(ord.hint(), None);

        let named = OrdinalOrName::Name {
            hint: 0x10,
            name: "Func".to_string(),
        };
        assert!(!named.is_ordinal());
        assert!(named.is_name());
        assert_eq!(named.ordinal(), None);
        assert_eq!(named.name(), Some("Func"));
        assert_eq!(named.hint(), Some(0x10));
    }

    #[test]
    fn test_ordinal_or_name_display() {
        assert_eq!(OrdinalOrName::Ordinal(42).to_string(), "Ordinal(42)");
        assert_eq!(
            OrdinalOrName::Name {
                hint: 0x10,
                name: "Func".to_string()
            }
            .to_string(),
            "Func (hint: 0x0010)"
        );
        assert_eq!(
            OrdinalOrName::Unresolved(0x5000).to_string(),
            "Unresolved(0x5000)"
        );
    }

    #[test]
    fn test_thunk_data_address_of_data() {
        let thunk = ThunkData::new_32(0x3000);
        assert_eq!(thunk.address_of_data(), 0x3000);
        assert_eq!(thunk.forwarder_string(), 0x3000);
        assert_eq!(thunk.function(), 0x3000);
    }
}
