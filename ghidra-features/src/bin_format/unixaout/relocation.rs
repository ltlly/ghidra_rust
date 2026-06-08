//! Unix a.out relocation entry ported from Ghidra's `UnixAoutRelocation.java`.

use std::fmt;

/// Represents a single entry in the UNIX a.out relocation table.
///
/// Ported from `ghidra.app.util.bin.format.unixaout.UnixAoutRelocation`. Each
/// entry consists of a 32-bit address and a 32-bit flags word containing
/// several bitfields.
///
/// The flags word layout depends on endianness:
///
/// Big-endian:
/// ```text
/// [31:8] r_symbolnum  (24 bits)
/// [7]    r_pcrel      (1 bit)
/// [6:5]  r_length     (2 bits)
/// [4]    r_extern     (1 bit)
/// [3]    r_baserel    (1 bit)
/// [2]    r_jmptable   (1 bit)
/// [1]    r_relative   (1 bit)
/// [0]    r_copy       (1 bit)
/// ```
///
/// Little-endian (bit positions reversed within the byte):
/// ```text
/// [31:8] r_symbolnum  (24 bits)
/// [7]    r_copy       (1 bit)
/// [6]    r_relative   (1 bit)
/// [5]    r_jmptable   (1 bit)
/// [4]    r_baserel    (1 bit)
/// [3]    r_extern     (1 bit)
/// [2:1]  r_length     (2 bits)
/// [0]    r_pcrel      (1 bit)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnixAoutRelocation {
    /// The 32-bit address of the relocation target.
    pub address: u32,
    /// The raw symbol number (24-bit field).
    pub symbol_num: u32,
    /// The raw flags byte (low 8 bits of the flags word).
    pub flags: u8,
    /// True if this is a PC-relative relocation.
    pub pc_relative: bool,
    /// Pointer length in bytes (1, 2, or 4).
    pub pointer_length: u8,
    /// True if the symbol is external (references the symbol table).
    pub is_extern: bool,
    /// True if base-relative addressing is used.
    pub base_relative: bool,
    /// True if this relocation is for a jump table.
    pub jmp_table: bool,
    /// True if this is a relative relocation.
    pub is_relative: bool,
    /// True if this is a copy relocation.
    pub is_copy: bool,
}

impl UnixAoutRelocation {
    /// Size of a relocation entry in bytes (two 32-bit words).
    pub const SIZE: usize = 8;

    /// Parse a relocation entry from the given address and flags words.
    ///
    /// The `address` is always the first word. The `flags` word is the second
    /// word, and its interpretation depends on `big_endian`.
    pub fn new(address: u32, flags: u32, big_endian: bool) -> Self {
        let address = address & 0xFFFF_FFFF;

        if big_endian {
            let symbol_num = (flags & 0xFFFF_FF00) >> 8;
            let flags_byte = (flags & 0xFF) as u8;
            let pc_relative = (flags & 0x80) != 0;
            let pointer_length = 1u8 << (((flags & 0x60) >> 5) as u32);
            let is_extern = (flags & 0x10) != 0;
            let base_relative = (flags & 0x08) != 0;
            let jmp_table = (flags & 0x04) != 0;
            let is_relative = (flags & 0x02) != 0;
            let is_copy = (flags & 0x01) != 0;

            Self {
                address,
                symbol_num,
                flags: flags_byte,
                pc_relative,
                pointer_length,
                is_extern,
                base_relative,
                jmp_table,
                is_relative,
                is_copy,
            }
        } else {
            let symbol_num = flags & 0x00FF_FFFF;
            let flags_byte = ((flags & 0xFF00_0000) >> 24) as u8;
            let pc_relative = (flags_byte & 0x01) != 0;
            let pointer_length = 1u8 << (((flags_byte & 0x06) >> 1) as u32);
            let is_extern = (flags_byte & 0x08) != 0;
            let base_relative = (flags_byte & 0x10) != 0;
            let jmp_table = (flags_byte & 0x20) != 0;
            let is_relative = (flags_byte & 0x40) != 0;
            let is_copy = (flags_byte & 0x80) != 0;

            Self {
                address,
                symbol_num,
                flags: flags_byte,
                pc_relative,
                pointer_length,
                is_extern,
                base_relative,
                jmp_table,
                is_relative,
                is_copy,
            }
        }
    }

    /// Returns the symbol name for this relocation, if it references an
    /// external symbol in the given symbol table.
    pub fn symbol_name<'a>(
        &self,
        symtab: &'a [Option<String>],
    ) -> Option<&'a str> {
        if self.is_extern {
            let idx = self.symbol_num as usize;
            if idx < symtab.len() {
                return symtab[idx].as_deref();
            }
        } else {
            // Internal references use the symbol number to identify the segment
            return match self.symbol_num {
                4 => Some(".text"),
                6 => Some(".data"),
                8 => Some(".bss"),
                _ => None,
            };
        }
        None
    }
}

impl fmt::Display for UnixAoutRelocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UnixAoutRelocation {{ addr=0x{:08X}, sym={}, pcrel={}, len={}, \
             extern={}, baserel={}, jmp={}, rel={}, copy={} }}",
            self.address,
            self.symbol_num,
            self.pc_relative,
            self.pointer_length,
            self.is_extern,
            self.base_relative,
            self.jmp_table,
            self.is_relative,
            self.is_copy
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
    fn test_big_endian_relocation() {
        // address = 0x00001000
        // flags = 0x00000083 -> symbol_num=0, flags=0x83
        //   0x83 = 10000011 -> pcrel=1, len=0 (1 byte), extern=0, baserel=0,
        //          jmp=0, rel=1, copy=1
        let reloc = UnixAoutRelocation::new(0x00001000, 0x00000083, true);

        assert_eq!(reloc.address, 0x00001000);
        assert_eq!(reloc.symbol_num, 0);
        assert!(reloc.pc_relative);
        assert_eq!(reloc.pointer_length, 1);
        assert!(!reloc.is_extern);
        assert!(reloc.is_relative);
        assert!(reloc.is_copy);
    }

    #[test]
    fn test_big_endian_with_symbol() {
        // flags = 0x00000310 -> symbol_num=3, flags=0x10 (extern)
        let reloc = UnixAoutRelocation::new(0x00002000, 0x00000310, true);

        assert_eq!(reloc.symbol_num, 3);
        assert!(reloc.is_extern);
        assert!(!reloc.pc_relative);
        assert_eq!(reloc.pointer_length, 1);
    }

    #[test]
    fn test_little_endian_relocation() {
        // LE flags: symbol_num in low 24 bits, flags in high byte
        // flags = 0x81000001 -> symbol_num=1, flags_byte=0x81
        //   0x81 = 10000001 -> pcrel=1, len=0 (1 byte), extern=0, ...
        let reloc = UnixAoutRelocation::new(0x00003000, 0x81000001, false);

        assert_eq!(reloc.address, 0x00003000);
        assert_eq!(reloc.symbol_num, 1);
        assert!(reloc.pc_relative);
        assert_eq!(reloc.pointer_length, 1);
        assert!(!reloc.is_extern);
    }

    #[test]
    fn test_little_endian_extern() {
        // LE flags = 0x08000005 -> symbol_num=5, flags_byte=0x08 (extern)
        let reloc = UnixAoutRelocation::new(0x00004000, 0x08000005, false);

        assert_eq!(reloc.symbol_num, 5);
        assert!(reloc.is_extern);
        assert!(!reloc.pc_relative);
    }

    #[test]
    fn test_pointer_length_4() {
        // BE flags: r_length=2 (4 bytes) -> bits [6:5] = 10 -> 0x40
        // flags = 0x00000040
        let reloc = UnixAoutRelocation::new(0, 0x00000040, true);
        assert_eq!(reloc.pointer_length, 4);
    }

    #[test]
    fn test_pointer_length_2() {
        // BE flags: r_length=1 (2 bytes) -> bits [6:5] = 01 -> 0x20
        let reloc = UnixAoutRelocation::new(0, 0x00000020, true);
        assert_eq!(reloc.pointer_length, 2);
    }

    #[test]
    fn test_symbol_name_internal() {
        let reloc = UnixAoutRelocation::new(0, 4 << 8, true); // symbol_num=4
        assert_eq!(reloc.symbol_name(&[]), Some(".text"));

        let reloc = UnixAoutRelocation::new(0, 6 << 8, true); // symbol_num=6
        assert_eq!(reloc.symbol_name(&[]), Some(".data"));

        let reloc = UnixAoutRelocation::new(0, 8 << 8, true); // symbol_num=8
        assert_eq!(reloc.symbol_name(&[]), Some(".bss"));
    }

    #[test]
    fn test_symbol_name_external() {
        let symtab = vec![
            Some("main".to_string()),
            Some("foo".to_string()),
            None,
            Some("bar".to_string()),
        ];

        // extern relocation referencing symbol 1
        let reloc = UnixAoutRelocation::new(0, 0x00000110, true); // sym=1, extern
        assert_eq!(reloc.symbol_name(&symtab), Some("foo"));

        // extern relocation referencing symbol 3
        let reloc = UnixAoutRelocation::new(0, 0x00000310, true); // sym=3, extern
        assert_eq!(reloc.symbol_name(&symtab), Some("bar"));
    }

    #[test]
    fn test_display() {
        let reloc = UnixAoutRelocation::new(0x12345678, 0x00010010, true);
        let s = format!("{}", reloc);
        assert!(s.contains("0x12345678"));
        assert!(s.contains("extern=true"));
    }
}
