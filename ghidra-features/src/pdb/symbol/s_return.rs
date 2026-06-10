//! S_RETURN -- Return value descriptor symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.S_ReturnMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// A return value descriptor symbol (`S_RETURN`).
///
/// This symbol describes how a function returns its value. It records a set
/// of flags describing the return convention and the register(s) used to
/// return the value. This is typically emitted within a procedure's scope
/// to describe the return mechanism.
///
/// # PDB Binary Layout
///
/// ```text
/// flags                 : u32
/// return_value_register : u16
/// ```
///
/// The flags field encodes:
/// - Bits 0-7: Return style (0 = void, 1 = register, 2 = memory, etc.)
/// - Additional bits may encode modifier information.
///
/// This corresponds to `S_RETURN` (0x000D) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SReturn {
    /// Return value flags encoding the return convention.
    pub flags: u32,

    /// The register index used for the return value (meaningful when the
    /// return style indicates register return).
    pub return_value_register: u16,
}

impl SReturn {
    /// Create a new S_RETURN symbol.
    pub fn new(flags: u32, return_value_register: u16) -> Self {
        Self {
            flags,
            return_value_register,
        }
    }

    /// Parse an S_RETURN symbol from a byte slice.
    ///
    /// Expects the layout: `flags(u32) + return_value_register(u16)`.
    /// The register field is optional; if the data is only 4 bytes long, the
    /// register defaults to 0.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let flags = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let return_value_register = if data.len() >= 6 {
            u16::from_le_bytes([data[4], data[5]])
        } else {
            0
        };
        Some(Self {
            flags,
            return_value_register,
        })
    }
}

impl AbstractMsSymbol for SReturn {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_RETURN
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_RETURN"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Return: Flags: 0x{:08X}, ReturnReg: {:#X}",
            self.flags, self.return_value_register
        )
    }
}

impl fmt::Display for SReturn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_return_bytes(flags: u32, reg: u16) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&flags.to_le_bytes());
        data.extend_from_slice(&reg.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_return_bytes(0x01, 20);
        let sym = SReturn::parse(&data).unwrap();
        assert_eq!(sym.flags, 0x01);
        assert_eq!(sym.return_value_register, 20);
    }

    #[test]
    fn test_parse_flags_only() {
        // Only 4 bytes, register should default to 0
        let data = [0x01, 0x00, 0x00, 0x00];
        let sym = SReturn::parse(&data).unwrap();
        assert_eq!(sym.flags, 1);
        assert_eq!(sym.return_value_register, 0);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01]; // too short
        assert!(SReturn::parse(&data).is_none());
    }

    #[test]
    fn test_trait_impls() {
        let sym = SReturn::new(0x02, 17);
        assert_eq!(sym.pdb_id(), 0x000D);
        assert_eq!(sym.symbol_type_name(), "S_RETURN");
        assert_eq!(sym.flags, 0x02);
        assert_eq!(sym.return_value_register, 17);
    }

    #[test]
    fn test_display() {
        let sym = SReturn::new(0x01, 20);
        let s = format!("{}", sym);
        assert!(s.contains("Return"));
        assert!(s.contains("0x00000001"));
        assert!(s.contains("14")); // 0x14 = 20
    }

    #[test]
    fn test_display_void_return() {
        let sym = SReturn::new(0, 0);
        let s = format!("{}", sym);
        assert!(s.contains("Return"));
        assert!(s.contains("0x00000000"));
    }

    #[test]
    fn test_clone_eq() {
        let a = SReturn::new(0x03, 18);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
