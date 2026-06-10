//! S_TRAMPOLINE -- Trampoline symbol.
//!
//! Ports Ghidra's `ghidra.app.util.bin.format.pdb2.pdbreader.symbol.TrampolineMsSymbol`.

use std::fmt;

use super::abstract_ms_symbol::AbstractMsSymbol;

/// A trampoline symbol (`S_TRAMPOLINE`).
///
/// This symbol describes a trampoline -- a small stub of code used for
/// incremental linking. When incremental linking is enabled, calls to
/// functions are redirected through trampolines so that the linker can
/// move function bodies without rewriting every call site.
///
/// # PDB Binary Layout
///
/// ```text
/// trampoline_type : u16
/// size            : u16
/// thunk_offset    : u32
/// target_offset   : u32
/// thunk_section   : u16
/// target_section  : u16
/// ```
///
/// This corresponds to `S_TRAMPOLINE` (0x101F) in the CodeView symbol set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct STrampoline {
    /// The type of trampoline (e.g., 0 = standard, 1 = thunk-to-import).
    pub trampoline_type: u16,

    /// Size of the trampoline code in bytes.
    pub size: u16,

    /// Offset of the thunk within its section.
    pub thunk_offset: u32,

    /// Offset of the target within its section.
    pub target_offset: u32,

    /// Section index containing the thunk.
    pub thunk_section: u16,

    /// Section index containing the target.
    pub target_section: u16,
}

impl STrampoline {
    /// Create a new trampoline symbol.
    pub fn new(
        trampoline_type: u16,
        size: u16,
        thunk_offset: u32,
        target_offset: u32,
        thunk_section: u16,
        target_section: u16,
    ) -> Self {
        Self {
            trampoline_type,
            size,
            thunk_offset,
            target_offset,
            thunk_section,
            target_section,
        }
    }

    /// Parse an S_TRAMPOLINE symbol from a byte slice.
    ///
    /// Expects the layout:
    /// `trampoline_type(u16) + size(u16) + thunk_offset(u32) + target_offset(u32)
    /// + thunk_section(u16) + target_section(u16)`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let trampoline_type = u16::from_le_bytes([data[0], data[1]]);
        let size = u16::from_le_bytes([data[2], data[3]]);
        let thunk_offset = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let target_offset = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let thunk_section = u16::from_le_bytes([data[12], data[13]]);
        let target_section = u16::from_le_bytes([data[14], data[15]]);
        Some(Self {
            trampoline_type,
            size,
            thunk_offset,
            target_offset,
            thunk_section,
            target_section,
        })
    }
}

impl AbstractMsSymbol for STrampoline {
    fn pdb_id(&self) -> u16 {
        super::super::symbol_kind::S_TRAMPOLINE
    }

    fn symbol_type_name(&self) -> &'static str {
        "S_TRAMPOLINE"
    }

    fn emit(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Trampoline: Type: {}, Size: {}, Thunk: [{:04X}:{:08X}], Target: [{:04X}:{:08X}]",
            self.trampoline_type, self.size,
            self.thunk_section, self.thunk_offset,
            self.target_section, self.target_offset,
        )
    }
}

impl fmt::Display for STrampoline {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.emit(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trampoline_bytes(
        trampoline_type: u16,
        size: u16,
        thunk_offset: u32,
        target_offset: u32,
        thunk_section: u16,
        target_section: u16,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&trampoline_type.to_le_bytes());
        data.extend_from_slice(&size.to_le_bytes());
        data.extend_from_slice(&thunk_offset.to_le_bytes());
        data.extend_from_slice(&target_offset.to_le_bytes());
        data.extend_from_slice(&thunk_section.to_le_bytes());
        data.extend_from_slice(&target_section.to_le_bytes());
        data
    }

    #[test]
    fn test_parse_basic() {
        let data = make_trampoline_bytes(1, 5, 0x1000, 0x2000, 1, 2);
        let sym = STrampoline::parse(&data).unwrap();
        assert_eq!(sym.trampoline_type, 1);
        assert_eq!(sym.size, 5);
        assert_eq!(sym.thunk_offset, 0x1000);
        assert_eq!(sym.target_offset, 0x2000);
        assert_eq!(sym.thunk_section, 1);
        assert_eq!(sym.target_section, 2);
    }

    #[test]
    fn test_parse_truncated() {
        let data = [0x00, 0x01, 0x02]; // too short
        assert!(STrampoline::parse(&data).is_none());
    }

    #[test]
    fn test_parse_exact_minimum() {
        let data = make_trampoline_bytes(0, 0, 0, 0, 0, 0);
        assert_eq!(data.len(), 16);
        let sym = STrampoline::parse(&data).unwrap();
        assert_eq!(sym.trampoline_type, 0);
        assert_eq!(sym.size, 0);
    }

    #[test]
    fn test_trait_impls() {
        let sym = STrampoline::new(1, 6, 0x3000, 0x4000, 2, 3);
        assert_eq!(sym.pdb_id(), 0x101F);
        assert_eq!(sym.symbol_type_name(), "S_TRAMPOLINE");
        assert_eq!(sym.thunk_offset, 0x3000);
        assert_eq!(sym.target_section, 3);
    }

    #[test]
    fn test_display() {
        let sym = STrampoline::new(0, 5, 0x1000, 0x2000, 1, 2);
        let s = format!("{}", sym);
        assert!(s.contains("Trampoline"));
        assert!(s.contains("1000"));
        assert!(s.contains("2000"));
    }

    #[test]
    fn test_clone_eq() {
        let a = STrampoline::new(1, 5, 0x1000, 0x2000, 1, 2);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
