//! x64dbg architecture and language mapping.
//!
//! Maps x64dbg target architecture to Ghidra language/compiler spec IDs.
//! x64dbg supports x86 (32-bit) and x86-64 (64-bit) Windows targets.

use serde::{Deserialize, Serialize};

/// Endianness is always little-endian for x64dbg targets.
pub const ENDIAN: &str = "little";

/// OS is always Windows for x64dbg targets.
pub const OS: &str = "Windows";

/// x64dbg architecture mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X64DbgArchMapping {
    /// Architecture name.
    pub arch: String,
    /// Ghidra language ID.
    pub ghidra_lang_id: String,
    /// Ghidra compiler spec ID.
    pub ghidra_comp_id: String,
    /// Description.
    pub description: String,
    /// Whether 64-bit.
    pub is_64bit: bool,
    /// Pointer size in bytes.
    pub pointer_size: usize,
}

/// Get the architecture mapping for a given bitness.
pub fn get_mapping(is_64bit: bool) -> X64DbgArchMapping {
    if is_64bit {
        X64DbgArchMapping {
            arch: "x86_64".to_string(),
            ghidra_lang_id: "x86:LE:64:default".to_string(),
            ghidra_comp_id: "VS".to_string(),
            description: "x86-64 Windows".to_string(),
            is_64bit: true,
            pointer_size: 8,
        }
    } else {
        X64DbgArchMapping {
            arch: "x86".to_string(),
            ghidra_lang_id: "x86:LE:32:Protected".to_string(),
            ghidra_comp_id: "VS".to_string(),
            description: "x86 32-bit Windows".to_string(),
            is_64bit: false,
            pointer_size: 4,
        }
    }
}

/// Compute the x64dbg version string from debugee bitness.
pub fn compute_arch_string(bitness: u32) -> String {
    if bitness == 64 {
        "x64".to_string()
    } else {
        "x86".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapping_64bit() {
        let m = get_mapping(true);
        assert!(m.is_64bit);
        assert_eq!(m.ghidra_lang_id, "x86:LE:64:default");
        assert_eq!(m.pointer_size, 8);
    }

    #[test]
    fn test_mapping_32bit() {
        let m = get_mapping(false);
        assert!(!m.is_64bit);
        assert_eq!(m.ghidra_lang_id, "x86:LE:32:Protected");
        assert_eq!(m.pointer_size, 4);
    }

    #[test]
    fn test_compute_arch_string() {
        assert_eq!(compute_arch_string(64), "x64");
        assert_eq!(compute_arch_string(32), "x86");
    }

    #[test]
    fn test_constants() {
        assert_eq!(ENDIAN, "little");
        assert_eq!(OS, "Windows");
    }
}
