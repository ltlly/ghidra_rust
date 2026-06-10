//! S_ENTRYTHIS -- Entry "this" pointer descriptor symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.EntryThisMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// An entry "this" pointer descriptor symbol (`S_ENTRYTHIS`).
///
/// This symbol describes where the `this` pointer can be found at the entry
/// point of a member function. It records a single byte value identifying the
/// `this` symbol and tracks any remaining unknown data bytes. This is used by
/// the debugger to locate the object instance when stepping into C++ member
/// functions.
///
/// # PDB Binary Layout
///
/// ```text
/// this_sym      : u8   (unsigned byte identifying the 'this' symbol)
/// remaining     : variable (unknown remaining data)
/// ```
///
/// This corresponds to `S_ENTRYTHIS` (0x000E) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SEntryThis {
    /// The 'this' symbol identifier (unsigned byte).
    pub this_sym: u8,

    /// Byte length of remaining data after `this_sym`.
    pub bytes_remaining: u32,
}

impl SEntryThis {
    /// Create a new S_ENTRYTHIS symbol.
    pub fn new(this_sym: u8, bytes_remaining: u32) -> Self {
        Self {
            this_sym,
            bytes_remaining,
        }
    }

    /// Parse an S_ENTRYTHIS symbol from a byte slice.
    ///
    /// Expects the layout: `this_sym(u8) + remaining_data(...)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let this_sym = data[0];
        let bytes_remaining = if data.len() > 1 {
            (data.len() - 1) as u32
        } else {
            0
        };
        Some(Self {
            this_sym,
            bytes_remaining,
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
            "ENTRYTHIS, 'this' symbol: {:02x}; byte length of remaining data = {}",
            self.this_sym, self.bytes_remaining
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

    #[test]
    fn test_parse_basic() {
        let data = [0x01u8];
        let sym = SEntryThis::parse(&data).unwrap();
        assert_eq!(sym.this_sym, 0x01);
        assert_eq!(sym.bytes_remaining, 0);
    }

    #[test]
    fn test_parse_with_remaining() {
        let data = [0x12u8, 0xAA, 0xBB];
        let sym = SEntryThis::parse(&data).unwrap();
        assert_eq!(sym.this_sym, 0x12);
        assert_eq!(sym.bytes_remaining, 2);
    }

    #[test]
    fn test_parse_empty() {
        let data: [u8; 0] = [];
        assert!(SEntryThis::parse(&data).is_none());
    }

    #[test]
    fn test_parse_ecx_register() {
        // ECX is register 17 on x86, commonly used for `this` in MSVC
        let data = [17u8];
        let sym = SEntryThis::parse(&data).unwrap();
        assert_eq!(sym.this_sym, 17);
    }

    #[test]
    fn test_trait_impls() {
        let sym = SEntryThis::new(0x01, 0);
        assert_eq!(sym.pdb_id(), 0x000E);
        assert_eq!(sym.symbol_type_name(), "S_ENTRYTHIS");
        assert_eq!(sym.this_sym, 0x01);
        assert_eq!(sym.bytes_remaining, 0);
    }

    #[test]
    fn test_display() {
        let sym = SEntryThis::new(0x11, 4);
        let s = format!("{}", sym);
        assert!(s.contains("ENTRYTHIS"));
        assert!(s.contains("11"));
        assert!(s.contains("4"));
    }

    #[test]
    fn test_display_zero() {
        let sym = SEntryThis::new(0x00, 0);
        let s = format!("{}", sym);
        assert!(s.contains("ENTRYTHIS"));
        assert!(s.contains("00"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SEntryThis::new(0x11, 2);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
