//! S_ENTRYTHIS -- Entry "this" pointer descriptor symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.EntryThisMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// An entry "this" pointer descriptor symbol (`S_ENTRYTHIS`).
///
/// This symbol describes where the `this` pointer can be found at the entry
/// point of a member function. It records the register holding the `this`
/// pointer and a flags byte with additional metadata. This is used by the
/// debugger to locate the object instance when stepping into C++ member
/// functions.
///
/// # PDB Binary Layout
///
/// ```text
/// flags         : u8
/// this_register : u16
/// ```
///
/// This corresponds to `S_ENTRYTHIS` (0x000E) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SEntryThis {
    /// Flags describing the `this` pointer location.
    pub flags: u8,

    /// The register index holding the `this` pointer at entry.
    pub this_register: u16,
}

impl SEntryThis {
    /// Create a new S_ENTRYTHIS symbol.
    pub fn new(flags: u8, this_register: u16) -> Self {
        Self {
            flags,
            this_register,
        }
    }

    /// Parse an S_ENTRYTHIS symbol from a byte slice.
    ///
    /// Expects the layout: `flags(u8) + this_register(u16)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 3 {
            return None;
        }
        let flags = data[0];
        let this_register = u16::from_le_bytes([data[1], data[2]]);
        Some(Self {
            flags,
            this_register,
        })
    }
}

impl AbstractMsSymbol for SEntryThis {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_ENTRYTHIS
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_ENTRYTHIS"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EntryThis: Flags: 0x{:02X}, ThisRegister: {:#X}",
            self.flags, self.this_register
        )
    }
}

impl fmt::Display for SEntryThis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entrythis_bytes(flags: u8, this_register: u16) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(flags);
        data.extend_from_slice(&this_register.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_entrythis_bytes(0x01, 20);
        let sym = SEntryThis::parse(&data).unwrap();
        assert_eq!(sym.flags, 0x01);
        assert_eq!(sym.this_register, 20);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00]; // too short
        assert!(SEntryThis::parse(&data).is_none());
    }

    #[test]
    fn test_parse_ecx_register() {
        // ECX is register 17 on x86, commonly used for `this` in MSVC
        let data = make_entrythis_bytes(0x00, 17);
        let sym = SEntryThis::parse(&data).unwrap();
        assert_eq!(sym.this_register, 17);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SEntryThis::new(0x01, 20);
        assert_eq!(sym.pdb_id(), 0x000E);
        assert_eq!(sym.symbol_type_name(), "S_ENTRYTHIS");
        assert_eq!(sym.flags, 0x01);
        assert_eq!(sym.this_register, 20);
    }

    #[test]
    fn test_display() {
        let sym = SEntryThis::new(0x02, 17);
        let s = format!("{}", sym);
        assert!(s.contains("EntryThis"));
        assert!(s.contains("0x02"));
        assert!(s.contains("11")); // 0x11 = 17
    }

    #[test]
    fn test_display_zero_flags() {
        let sym = SEntryThis::new(0x00, 0);
        let s = format!("{}", sym);
        assert!(s.contains("EntryThis"));
        assert!(s.contains("0x00"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SEntryThis::new(0x01, 17);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
