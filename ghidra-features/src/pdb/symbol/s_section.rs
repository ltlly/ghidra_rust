//! S_SECTION and S_PECOFF_SECTION -- Section symbols.
//!
//! Ports Ghidra's:
//! - `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.SectionMsSymbol` (S_SECTION, 0x1029)
//! - `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.PeCoffSectionMsSymbol` (0x1136)
//!
//! This module provides:
//! - [`SSection`] -- A PE section symbol (`S_SECTION`, 0x1029).
//! - [`SPeCoffSection`] -- A PE COFF section symbol (`S_PECOFF_SECTION`, 0x1136).
//! - [`SectionCharacteristics`] -- Decoded PE section characteristic flags.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;
use super::name_ms_symbol::NameMsSymbol;

/// A section symbol (`S_SECTION`).
///
/// This symbol describes a PE section from the final linked image. It provides
/// the section number, alignment, RVA (relative virtual address), size,
/// characteristics, and name. Debuggers use this information to map between
/// file offsets, virtual addresses, and section-relative offsets.
///
/// # PDB Binary Layout
///
/// ```text
/// section_number  : u16
/// alignment       : u8
/// (padding)       : u8
/// rva             : u32
/// size            : u32
/// characteristics : u32
/// name            : NT string
/// ```
///
/// This corresponds to `S_SECTION` (0x1029) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SSection {
    /// The 1-based PE section number.
    pub section_number: u16,

    /// Log2 of the section alignment (e.g., 4 = 16-byte alignment).
    pub alignment: u8,

    /// Relative virtual address of the section start.
    pub rva: u32,

    /// Size of the section in bytes.
    pub size: u32,

    /// PE section characteristics flags (e.g., `IMAGE_SCN_MEM_READ`).
    pub characteristics: u32,

    /// The section name (e.g., `.text`, `.data`, `.rdata`).
    pub name: String,
}

impl SSection {
    /// Create a new section symbol.
    pub fn new(
        section_number: u16,
        alignment: u8,
        rva: u32,
        size: u32,
        characteristics: u32,
        name: String,
    ) -> Self {
        Self {
            section_number,
            alignment,
            rva,
            size,
            characteristics,
            name,
        }
    }

    /// Parse an S_SECTION symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `section_number(u16) + alignment(u8) + padding(u8) + rva(u32) + size(u32)
    /// + characteristics(u32) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let section_number = u16::from_le_bytes([data[0], data[1]]);
        let alignment = data[2];
        // data[3] is padding
        let rva = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let characteristics = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let name = parse_nt_string(&data[16..]);
        Some(Self {
            section_number,
            alignment,
            rva,
            size,
            characteristics,
            name,
        })
    }

    /// Return the alignment as a power of 2.
    pub fn alignment_bytes(&self) -> u32 {
        1u32 << self.alignment
    }

    /// Decode the characteristics flags.
    pub fn characteristics_flags(&self) -> SectionCharacteristics {
        SectionCharacteristics::from_u32(self.characteristics)
    }
}

impl AbstractMsSymbol for SSection {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_SECTION
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_SECTION"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Section: {}, RVA: {:08X}, Size: {:08X}, Align: 2^{}, Characteristics: {:08X}",
            self.name, self.rva, self.size, self.alignment, self.characteristics,
        )
    }
}

impl NameMsSymbol for SSection {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

/// Parse a null-terminated UTF-8 string from a byte slice.
fn parse_nt_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).to_string()
}

/// PE section characteristics flags.
///
/// Decoded from the `characteristics` field of [`SSection`] and
/// [`SPeCoffSection`]. These correspond to the `IMAGE_SCN_*` constants
/// from the PE/COFF specification.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SectionCharacteristics {
    /// Section contains executable code.
    pub cnt_code: bool,
    /// Section contains initialized data.
    pub cnt_initialized_data: bool,
    /// Section contains uninitialized data.
    pub cnt_uninitialized_data: bool,
    /// Section can be discarded.
    pub lnk_info: bool,
    /// Section will not become part of the image.
    pub lnk_remove: bool,
    /// Section contains COMDAT data.
    pub lnk_comdat: bool,
    /// Section contains extended relocations.
    pub lnk_nreloc_ovfl: bool,
    /// Section is not cacheable.
    pub mem_not_cached: bool,
    /// Section is not pageable.
    pub mem_not_paged: bool,
    /// Section is shared in memory.
    pub mem_shared: bool,
    /// Section is executable.
    pub mem_execute: bool,
    /// Section is readable.
    pub mem_read: bool,
    /// Section is writable.
    pub mem_write: bool,
}

impl SectionCharacteristics {
    /// Decode characteristics from a raw 32-bit value.
    pub fn from_u32(raw: u32) -> Self {
        Self {
            cnt_code:                   (raw & 0x00000020) != 0,  // IMAGE_SCN_CNT_CODE
            cnt_initialized_data:       (raw & 0x00000040) != 0,  // IMAGE_SCN_CNT_INITIALIZED_DATA
            cnt_uninitialized_data:     (raw & 0x00000080) != 0,  // IMAGE_SCN_CNT_UNINITIALIZED_DATA
            lnk_info:                   (raw & 0x00000200) != 0,  // IMAGE_SCN_LNK_INFO
            lnk_remove:                 (raw & 0x00000800) != 0,  // IMAGE_SCN_LNK_REMOVE
            lnk_comdat:                 (raw & 0x00001000) != 0,  // IMAGE_SCN_LNK_COMDAT
            lnk_nreloc_ovfl:            (raw & 0x01000000) != 0,  // IMAGE_SCN_LNK_NRELOC_OVFL
            mem_not_cached:             (raw & 0x04000000) != 0,  // IMAGE_SCN_MEM_NOT_CACHED
            mem_not_paged:              (raw & 0x08000000) != 0,  // IMAGE_SCN_MEM_NOT_PAGED
            mem_shared:                 (raw & 0x10000000) != 0,  // IMAGE_SCN_MEM_SHARED
            mem_execute:                (raw & 0x20000000) != 0,  // IMAGE_SCN_MEM_EXECUTE
            mem_read:                   (raw & 0x40000000) != 0,  // IMAGE_SCN_MEM_READ
            mem_write:                  (raw & 0x80000000) != 0,  // IMAGE_SCN_MEM_WRITE
        }
    }

    /// Return a human-readable summary of the characteristics.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if self.mem_execute { parts.push("X"); }
        if self.mem_read { parts.push("R"); }
        if self.mem_write { parts.push("W"); }
        if self.cnt_code { parts.push("CODE"); }
        if self.cnt_initialized_data { parts.push("IDATA"); }
        if self.cnt_uninitialized_data { parts.push("UDATA"); }
        parts.join("|")
    }
}

/// A PE COFF section symbol (0x1136).
///
/// This symbol is similar to [`SSection`] but uses the newer `S_PECOFF_SECTION`
/// PDB ID (0x1136). It includes a reserved field and uses `pdb.parseSegment`
/// for the section number rather than a raw `u16`.
///
/// # PDB Binary Layout
///
/// ```text
/// section_number  : u16
/// alignment       : u8
/// reserved        : u8
/// rva             : u32
/// size            : u32
/// characteristics : u32
/// name            : NT string
/// ```
///
/// This corresponds to `S_PECOFF_SECTION` (0x1136) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SPeCoffSection {
    /// The 1-based PE section number.
    pub section_number: u16,

    /// Log2 of the section alignment (e.g., 4 = 16-byte alignment).
    pub alignment: u8,

    /// Reserved byte (must be 0).
    pub reserved: u8,

    /// Relative virtual address of the section start.
    pub rva: u32,

    /// Size of the section in bytes.
    pub size: u32,

    /// PE section characteristics flags.
    pub characteristics: u32,

    /// The section name (e.g., `.text`, `.data`, `.rdata`).
    pub name: String,
}

impl SPeCoffSection {
    /// Create a new PE COFF section symbol.
    pub fn new(
        section_number: u16,
        alignment: u8,
        reserved: u8,
        rva: u32,
        size: u32,
        characteristics: u32,
        name: String,
    ) -> Self {
        Self {
            section_number,
            alignment,
            reserved,
            rva,
            size,
            characteristics,
            name,
        }
    }

    /// Parse an S_PECOFF_SECTION symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `section_number(u16) + alignment(u8) + reserved(u8) + rva(u32) + size(u32)
    /// + characteristics(u32) + name(NT)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let section_number = u16::from_le_bytes([data[0], data[1]]);
        let alignment = data[2];
        let reserved = data[3];
        let rva = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let size = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let characteristics = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let name = parse_nt_string(&data[16..]);
        Some(Self {
            section_number,
            alignment,
            reserved,
            rva,
            size,
            characteristics,
            name,
        })
    }

    /// Return the alignment as a power of 2.
    pub fn alignment_bytes(&self) -> u32 {
        1u32 << self.alignment
    }

    /// Decode the characteristics flags.
    pub fn characteristics_flags(&self) -> SectionCharacteristics {
        SectionCharacteristics::from_u32(self.characteristics)
    }
}

impl AbstractMsSymbol for SPeCoffSection {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_PECOFF_SECTION
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_PECOFF_SECTION"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SECTION: [{:04X}], RVA = {:08x}, Length = {:08X}, Align = {:08X}, Characteristics = {:08X}, {}",
            self.section_number, self.rva, self.size, self.alignment, self.characteristics, self.name,
        )
    }
}

impl NameMsSymbol for SPeCoffSection {
    fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for SPeCoffSection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_section_bytes(
        section_number: u16,
        alignment: u8,
        rva: u32,
        size: u32,
        characteristics: u32,
        name: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&section_number.to_le_bytes());
        data.push(alignment);
        data.push(0); // padding
        data.extend_from_slice(&rva.to_le_bytes());
        data.extend_from_slice(&size.to_le_bytes());
        data.extend_from_slice(&characteristics.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_section_bytes(1, 4, 0x1000, 0x5000, 0x60000020, b".text");
        let sym = SSection::parse(&data).unwrap();
        assert_eq!(sym.section_number, 1);
        assert_eq!(sym.alignment, 4);
        assert_eq!(sym.rva, 0x1000);
        assert_eq!(sym.size, 0x5000);
        assert_eq!(sym.characteristics, 0x60000020);
        assert_eq!(sym.name, ".text");
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SSection::parse(&data).is_none());
    }

    #[test]
    fn test_parse_data_section() {
        let data = make_section_bytes(2, 4, 0x6000, 0x1000, 0xC0000040, b".data");
        let sym = SSection::parse(&data).unwrap();
        assert_eq!(sym.name, ".data");
        assert_eq!(sym.characteristics, 0xC0000040);
    }

    #[test]
    fn test_parse_rdata_section() {
        let data = make_section_bytes(3, 4, 0x8000, 0x2000, 0x40000040, b".rdata");
        let sym = SSection::parse(&data).unwrap();
        assert_eq!(sym.name, ".rdata");
    }

    #[test]
    fn test_trait_impls() {
        let sym = SSection::new(1, 4, 0x1000, 0x5000, 0x60000020, ".text".to_string());
        assert_eq!(sym.pdb_id(), 0x1029);
        assert_eq!(sym.symbol_type_name(), "S_SECTION");
        assert_eq!(sym.name(), ".text");
    }

    #[test]
    fn test_display() {
        let sym = SSection::new(1, 4, 0x1000, 0x5000, 0x60000020, ".text".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("Section"));
        assert!(s.contains(".text"));
        assert!(s.contains("1000"));
        assert!(s.contains("5000"));
    }

    #[test]
    fn test_name_trait() {
        let sym = SSection::new(2, 4, 0x2000, 0x1000, 0, ".bss".to_string());
        assert_eq!(sym.name(), ".bss");
    }

    #[test]
    fn test_clone_eq() {
        let a = SSection::new(1, 4, 0x1000, 0x5000, 0x60000020, ".text".to_string());
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- SPeCoffSection tests --

    fn make_pecoff_section_bytes(
        section_number: u16,
        alignment: u8,
        reserved: u8,
        rva: u32,
        size: u32,
        characteristics: u32,
        name: &[u8],
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&section_number.to_le_bytes());
        data.push(alignment);
        data.push(reserved);
        data.extend_from_slice(&rva.to_le_bytes());
        data.extend_from_slice(&size.to_le_bytes());
        data.extend_from_slice(&characteristics.to_le_bytes());
        data.extend_from_slice(name);
        data.push(0); // null terminator
        data
    }

    #[test]
    fn test_pecoff_parse_basic() {
        let data = make_pecoff_section_bytes(1, 4, 0, 0x1000, 0x5000, 0x60000020, b".text");
        let sym = SPeCoffSection::parse(&data).unwrap();
        assert_eq!(sym.section_number, 1);
        assert_eq!(sym.alignment, 4);
        assert_eq!(sym.reserved, 0);
        assert_eq!(sym.rva, 0x1000);
        assert_eq!(sym.size, 0x5000);
        assert_eq!(sym.characteristics, 0x60000020);
        assert_eq!(sym.name, ".text");
    }

    #[test]
    fn test_pecoff_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(SPeCoffSection::parse(&data).is_none());
    }

    #[test]
    fn test_pecoff_trait_impls() {
        let sym = SPeCoffSection::new(1, 4, 0, 0x1000, 0x5000, 0x60000020, ".text".to_string());
        assert_eq!(sym.pdb_id(), 0x1136);
        assert_eq!(sym.symbol_type_name(), "S_PECOFF_SECTION");
        assert_eq!(sym.name(), ".text");
    }

    #[test]
    fn test_pecoff_display() {
        let sym = SPeCoffSection::new(1, 4, 0, 0x1000, 0x5000, 0x60000020, ".text".to_string());
        let s = format!("{}", sym);
        assert!(s.contains("SECTION"));
        assert!(s.contains(".text"));
        assert!(s.contains("1000"));
        assert!(s.contains("5000"));
    }

    #[test]
    fn test_pecoff_clone_eq() {
        let a = SPeCoffSection::new(1, 4, 0, 0x1000, 0x5000, 0x60000020, ".text".to_string());
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn test_pecoff_with_reserved() {
        let data = make_pecoff_section_bytes(3, 4, 0xFF, 0x8000, 0x2000, 0x40000040, b".rdata");
        let sym = SPeCoffSection::parse(&data).unwrap();
        assert_eq!(sym.reserved, 0xFF);
        assert_eq!(sym.name, ".rdata");
    }

    // -- characteristics tests --

    #[test]
    fn test_characteristics_text() {
        // .text: 0x60000020 = MEM_EXECUTE | MEM_READ | CNT_CODE
        let sym = SSection::new(1, 4, 0x1000, 0x5000, 0x60000020, ".text".to_string());
        let flags = sym.characteristics_flags();
        assert!(flags.mem_execute);
        assert!(flags.mem_read);
        assert!(!flags.mem_write);
        assert!(flags.cnt_code);
        assert!(!flags.cnt_initialized_data);
    }

    #[test]
    fn test_characteristics_data() {
        // .data: 0xC0000040 = MEM_READ | MEM_WRITE | CNT_INITIALIZED_DATA
        let sym = SSection::new(2, 4, 0x6000, 0x1000, 0xC0000040, ".data".to_string());
        let flags = sym.characteristics_flags();
        assert!(!flags.mem_execute);
        assert!(flags.mem_read);
        assert!(flags.mem_write);
        assert!(flags.cnt_initialized_data);
        assert!(!flags.cnt_code);
    }

    #[test]
    fn test_characteristics_bss() {
        // .bss: 0xC0000080 = MEM_READ | MEM_WRITE | CNT_UNINITIALIZED_DATA
        let sym = SSection::new(3, 4, 0x8000, 0x2000, 0xC0000080, ".bss".to_string());
        let flags = sym.characteristics_flags();
        assert!(flags.cnt_uninitialized_data);
        assert!(flags.mem_read);
        assert!(flags.mem_write);
    }

    #[test]
    fn test_characteristics_summary() {
        let sym = SSection::new(1, 4, 0x1000, 0x5000, 0x60000020, ".text".to_string());
        let summary = sym.characteristics_flags().summary();
        assert!(summary.contains("X"));
        assert!(summary.contains("R"));
        assert!(summary.contains("CODE"));
    }

    #[test]
    fn test_alignment_bytes() {
        let sym = SSection::new(1, 4, 0x1000, 0x5000, 0, ".text".to_string());
        assert_eq!(sym.alignment_bytes(), 16); // 2^4 = 16

        let sym2 = SSection::new(1, 12, 0x1000, 0x5000, 0, ".text".to_string());
        assert_eq!(sym2.alignment_bytes(), 4096); // 2^12 = 4096
    }

    #[test]
    fn test_pecoff_alignment_bytes() {
        let sym = SPeCoffSection::new(1, 4, 0, 0x1000, 0x5000, 0, ".text".to_string());
        assert_eq!(sym.alignment_bytes(), 16);
    }

    #[test]
    fn test_pecoff_characteristics() {
        let sym = SPeCoffSection::new(1, 4, 0, 0x1000, 0x5000, 0x60000020, ".text".to_string());
        let flags = sym.characteristics_flags();
        assert!(flags.mem_execute);
        assert!(flags.mem_read);
        assert!(flags.cnt_code);
    }

    #[test]
    fn test_default_characteristics() {
        let flags = SectionCharacteristics::default();
        assert!(!flags.mem_execute);
        assert!(!flags.mem_read);
        assert!(!flags.mem_write);
        assert!(!flags.cnt_code);
    }
}
