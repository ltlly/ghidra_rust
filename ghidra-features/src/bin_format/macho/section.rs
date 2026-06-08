//! Mach-O section structure ported from Ghidra's
//! `ghidra.app.util.bin.format.macho.Section`.
//!
//! Represents a `section` / `section_64` structure.
//!
//! Reference: <https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h>

use super::mach_constants::NAME_LENGTH;
use super::mach_exception::MachException;
use super::relocation_info::RelocationInfo;
use super::section_types;

/// Represents a Mach-O section (`section` or `section_64`).
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name (16 bytes, null-padded).
    sectname: String,
    /// Segment name (16 bytes, null-padded).
    segname: String,
    /// Memory address of the section.
    addr: u64,
    /// Size of the section in bytes.
    size: u64,
    /// File offset to the section data.
    offset: u32,
    /// Section alignment (power of 2).
    align: u32,
    /// File offset to the relocation entries.
    reloff: u32,
    /// Number of relocation entries.
    nrelocs: u32,
    /// Section flags (type + attributes).
    flags: u32,
    /// Reserved field 1.
    reserved1: u32,
    /// Reserved field 2.
    reserved2: u32,
    /// Reserved field 3 (64-bit only).
    reserved3: u32,
    /// Relocations for this section.
    relocations: Vec<RelocationInfo>,
}

impl Section {
    /// Parses a section from the given data.
    ///
    /// `data` is the full binary data, `pos` is the current read position.
    /// `is_32bit` controls whether addr/size are 32-bit or 64-bit.
    /// `base_offset` is the start offset for resolving relocation offsets.
    /// `is_le` indicates the byte order.
    pub fn parse(
        data: &[u8],
        pos: &mut usize,
        is_32bit: bool,
        base_offset: u64,
        is_le: bool,
    ) -> Result<Self, MachException> {
        if data.len() < *pos + NAME_LENGTH * 2 {
            return Err(MachException::new("Not enough data for section name fields"));
        }

        // Read 16-byte section name and segment name (null-terminated C strings)
        let sectname = read_fixed_string(data, pos, NAME_LENGTH);
        let segname = read_fixed_string(data, pos, NAME_LENGTH);

        let addr;
        let size;
        if is_32bit {
            addr = read_u32_at(data, pos, is_le) as u64;
            size = read_u32_at(data, pos, is_le) as u64;
        } else {
            addr = read_u64_at(data, pos, is_le);
            size = read_u64_at(data, pos, is_le);
        }

        let offset = read_u32_at(data, pos, is_le);
        let align = read_u32_at(data, pos, is_le);
        let reloff = read_u32_at(data, pos, is_le);
        let nrelocs = read_u32_at(data, pos, is_le);
        let flags = read_u32_at(data, pos, is_le);
        let reserved1 = read_u32_at(data, pos, is_le);
        let reserved2 = read_u32_at(data, pos, is_le);

        let reserved3 = if !is_32bit {
            read_u32_at(data, pos, is_le)
        } else {
            0
        };

        // Parse relocations
        let mut relocations = Vec::new();
        let reloc_start = (base_offset + reloff as u64) as usize;
        if reloc_start + (nrelocs as usize * 8) <= data.len() {
            let mut reloc_pos = reloc_start;
            for _ in 0..nrelocs {
                let i1 = read_u32_at(data, &mut reloc_pos, is_le);
                let i2 = read_u32_at(data, &mut reloc_pos, is_le);
                relocations.push(RelocationInfo::new(i1, i2, !is_le));
            }
        }

        Ok(Section {
            sectname,
            segname,
            addr,
            size,
            offset,
            align,
            reloff,
            nrelocs,
            flags,
            reserved1,
            reserved2,
            reserved3,
            relocations,
        })
    }

    /// Returns the section name.
    pub fn section_name(&self) -> &str {
        &self.sectname
    }

    /// Sets the section name (for sanitization).
    pub fn set_section_name(&mut self, name: String) {
        self.sectname = name;
    }

    /// Returns the segment name.
    pub fn segment_name(&self) -> &str {
        &self.segname
    }

    /// Sets the segment name (for sanitization).
    pub fn set_segment_name(&mut self, name: String) {
        self.segname = name;
    }

    /// Returns the memory address of the section.
    ///
    /// Handles chained fixup addresses found in kernelcache section addresses.
    pub fn address(&self) -> u64 {
        if (self.addr & 0xFFF0_0000_0000) == 0xFFF0_0000_0000 {
            self.addr | 0xFFFF_0000_0000_0000
        } else {
            self.addr
        }
    }

    /// Returns the raw address without chained fixup masking.
    pub fn raw_address(&self) -> u64 {
        self.addr
    }

    /// Returns the size of the section in bytes.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Returns the file offset to the section data.
    pub fn offset(&self) -> u32 {
        self.offset
    }

    /// Returns the section alignment.
    pub fn align(&self) -> u32 {
        self.align
    }

    /// Returns the file offset to the relocation entries.
    pub fn relocation_offset(&self) -> u32 {
        self.reloff
    }

    /// Returns the number of relocation entries.
    pub fn number_of_relocations(&self) -> u32 {
        self.nrelocs
    }

    /// Returns the raw flags field.
    pub fn flags(&self) -> u32 {
        self.flags
    }

    /// Returns the section type (lower 8 bits of flags).
    pub fn section_type(&self) -> u32 {
        self.flags & section_types::SECTION_TYPE_MASK
    }

    /// Returns the section attributes (upper 24 bits of flags).
    pub fn attributes(&self) -> u32 {
        self.flags & section_types::SECTION_ATTRIBUTES_MASK
    }

    /// Returns reserved field 1.
    pub fn reserved1(&self) -> u32 {
        self.reserved1
    }

    /// Returns reserved field 2.
    pub fn reserved2(&self) -> u32 {
        self.reserved2
    }

    /// Returns reserved field 3 (64-bit only).
    pub fn reserved3(&self) -> u32 {
        self.reserved3
    }

    /// Returns the relocations for this section.
    pub fn relocations(&self) -> &[RelocationInfo] {
        &self.relocations
    }

    /// Returns `true` if the section is readable (all sections are readable).
    pub fn is_read(&self) -> bool {
        true
    }

    /// Returns `true` if the section is writable.
    ///
    /// Sections in __TEXT, __TEXT_EXEC, and __PRELINK_TEXT segments are read-only,
    /// except for the __got section. The __const section in the data segment is
    /// also treated as read-only.
    pub fn is_write(&self) -> bool {
        if self.sectname.starts_with(section_types::SECT_GOT) {
            return true;
        }
        self.segname != section_types::SEG_TEXT
            && self.segname != section_types::SEG_TEXT_EXEC
            && self.segname != section_types::SEG_PRELINK_TEXT
            && self.sectname != section_types::SECT_DATA_CONST
    }

    /// Returns `true` if the section is executable.
    pub fn is_execute(&self) -> bool {
        if self.sectname == section_types::SECT_TEXT
            || self.segname == section_types::SEG_TEXT_EXEC
        {
            return true;
        }
        let attrs = self.attributes();
        (attrs & section_types::S_ATTR_PURE_INSTRUCTIONS) != 0
            || (attrs & section_types::S_ATTR_SOME_INSTRUCTIONS) != 0
    }

    /// Returns `true` if the section contains the given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.addr && address < self.addr.wrapping_add(self.size)
    }

    /// Returns a human-readable string representation.
    pub fn description(&self) -> String {
        let type_name = section_types::section_type_name(self.section_type())
            .unwrap_or("Unknown");
        let attr_names = section_types::get_attribute_names(self.attributes());

        let mut s = format!(
            "      Name: {}\n   Address: 0x{:x}\n    Length: 0x{:x}\n      Type: 0x{:x} ({})\n    Offset: 0x{:x}\nAttributes: 0x{:x}\n",
            self.sectname,
            self.addr,
            self.size,
            self.section_type(),
            type_name,
            self.offset,
            self.attributes(),
        );
        for attr in attr_names {
            s.push_str(&format!("            {}\n", attr));
        }
        s
    }
}

impl std::fmt::Display for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn read_fixed_string(data: &[u8], pos: &mut usize, len: usize) -> String {
    let end = (*pos + len).min(data.len());
    let slice = &data[*pos..end];
    *pos += len;
    // Take up to the first null byte, or the full slice
    let null_pos = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..null_pos]).into_owned()
}

fn read_u32_at(data: &[u8], pos: &mut usize, le: bool) -> u32 {
    let val = if le {
        u32::from_le_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]])
    } else {
        u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]])
    };
    *pos += 4;
    val
}

fn read_u64_at(data: &[u8], pos: &mut usize, le: bool) -> u64 {
    let val = if le {
        u64::from_le_bytes([
            data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3],
            data[*pos + 4], data[*pos + 5], data[*pos + 6], data[*pos + 7],
        ])
    } else {
        u64::from_be_bytes([
            data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3],
            data[*pos + 4], data[*pos + 5], data[*pos + 6], data[*pos + 7],
        ])
    };
    *pos += 8;
    val
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_section_32_le() -> Vec<u8> {
        let mut data = Vec::new();
        // sectname: "__text\0\0\0\0\0\0\0\0\0\0"
        data.extend_from_slice(b"__text\0\0\0\0\0\0\0\0\0\0");
        // segname: "__TEXT\0\0\0\0\0\0\0\0\0\0"
        data.extend_from_slice(b"__TEXT\0\0\0\0\0\0\0\0\0\0");
        // addr (32-bit)
        data.extend_from_slice(&0x1000u32.to_le_bytes());
        // size (32-bit)
        data.extend_from_slice(&0x500u32.to_le_bytes());
        // offset
        data.extend_from_slice(&0x200u32.to_le_bytes());
        // align
        data.extend_from_slice(&2u32.to_le_bytes());
        // reloff
        data.extend_from_slice(&0u32.to_le_bytes());
        // nrelocs
        data.extend_from_slice(&0u32.to_le_bytes());
        // flags: S_REGULAR | S_ATTR_PURE_INSTRUCTIONS
        data.extend_from_slice(&(0x0 | 0x8000_0000u32).to_le_bytes());
        // reserved1
        data.extend_from_slice(&0u32.to_le_bytes());
        // reserved2
        data.extend_from_slice(&0u32.to_le_bytes());
        data
    }

    fn make_section_64_le() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(b"__data\0\0\0\0\0\0\0\0\0\0");
        data.extend_from_slice(b"__DATA\0\0\0\0\0\0\0\0\0\0");
        // addr (64-bit)
        data.extend_from_slice(&0x2000u64.to_le_bytes());
        // size (64-bit)
        data.extend_from_slice(&0x100u64.to_le_bytes());
        // offset
        data.extend_from_slice(&0x300u32.to_le_bytes());
        // align
        data.extend_from_slice(&3u32.to_le_bytes());
        // reloff
        data.extend_from_slice(&0u32.to_le_bytes());
        // nrelocs
        data.extend_from_slice(&0u32.to_le_bytes());
        // flags: S_REGULAR
        data.extend_from_slice(&0u32.to_le_bytes());
        // reserved1
        data.extend_from_slice(&0u32.to_le_bytes());
        // reserved2
        data.extend_from_slice(&0u32.to_le_bytes());
        // reserved3 (64-bit only)
        data.extend_from_slice(&0u32.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_32bit_section() {
        let data = make_section_32_le();
        let mut pos = 0;
        let section = Section::parse(&data, &mut pos, true, 0, true).unwrap();
        assert_eq!(section.section_name(), "__text");
        assert_eq!(section.segment_name(), "__TEXT");
        assert_eq!(section.address(), 0x1000);
        assert_eq!(section.size(), 0x500);
        assert_eq!(section.offset(), 0x200);
        assert!(section.is_execute());
        assert!(section.is_read());
        assert!(!section.is_write()); // __TEXT segment is read-only
    }

    #[test]
    fn test_parse_64bit_section() {
        let data = make_section_64_le();
        let mut pos = 0;
        let section = Section::parse(&data, &mut pos, false, 0, true).unwrap();
        assert_eq!(section.section_name(), "__data");
        assert_eq!(section.segment_name(), "__DATA");
        assert_eq!(section.address(), 0x2000);
        assert_eq!(section.size(), 0x100);
        assert!(section.is_write()); // __DATA segment is writable
        assert!(!section.is_execute());
    }

    #[test]
    fn test_contains_address() {
        let data = make_section_32_le();
        let mut pos = 0;
        let section = Section::parse(&data, &mut pos, true, 0, true).unwrap();
        assert!(section.contains(0x1000));
        assert!(section.contains(0x14FF));
        assert!(!section.contains(0x1500));
        assert!(!section.contains(0x0FFF));
    }

    #[test]
    fn test_section_type_and_attributes() {
        let data = make_section_32_le();
        let mut pos = 0;
        let section = Section::parse(&data, &mut pos, true, 0, true).unwrap();
        assert_eq!(section.section_type(), section_types::S_REGULAR);
        assert_ne!(
            section.attributes() & section_types::S_ATTR_PURE_INSTRUCTIONS,
            0
        );
    }

    #[test]
    fn test_got_section_is_writable() {
        let mut data = Vec::new();
        data.extend_from_slice(b"__got\0\0\0\0\0\0\0\0\0\0\0");
        data.extend_from_slice(b"__DATA\0\0\0\0\0\0\0\0\0\0");
        data.extend_from_slice(&0x3000u32.to_le_bytes());
        data.extend_from_slice(&0x10u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        let mut pos = 0;
        let section = Section::parse(&data, &mut pos, true, 0, true).unwrap();
        assert!(section.is_write()); // __got is writable
    }

    #[test]
    fn test_display() {
        let data = make_section_32_le();
        let mut pos = 0;
        let section = Section::parse(&data, &mut pos, true, 0, true).unwrap();
        let s = format!("{}", section);
        assert!(s.contains("__text"));
        assert!(s.contains("__TEXT"));
        assert!(s.contains("REGULAR"));
    }
}
