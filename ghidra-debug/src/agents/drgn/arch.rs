//! drgn architecture and language mapping.
//!
//! Maps drgn program architecture to Ghidra language/compiler spec IDs.
//! The drgn architecture is derived from the target's ELF headers.
//!
//! Ported from `arch.py` in the drgn agent.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A drgn architecture mapping entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrgnArchMapping {
    /// drgn architecture name (from ELF e_machine).
    pub drgn_arch: String,
    /// Ghidra language ID.
    pub ghidra_lang_id: String,
    /// Ghidra compiler spec ID.
    pub ghidra_comp_id: String,
    /// Description.
    pub description: String,
    /// Endianness.
    pub endian: Endianness,
    /// Pointer size in bytes.
    pub pointer_size: usize,
}

/// Endianness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
}

impl Endianness {
    /// Convert to trace string.
    pub fn as_trace_str(&self) -> &'static str {
        match self {
            Self::Little => "little",
            Self::Big => "big",
        }
    }
}

/// drgn architecture registry.
pub struct DrgnArchRegistry {
    mappings: HashMap<String, DrgnArchMapping>,
}

impl DrgnArchRegistry {
    /// Create a new registry with default mappings.
    pub fn new() -> Self {
        let mut registry = Self {
            mappings: HashMap::new(),
        };
        registry.register_defaults();
        registry
    }

    /// Register a mapping.
    pub fn register(&mut self, mapping: DrgnArchMapping) {
        self.mappings.insert(mapping.drgn_arch.clone(), mapping);
    }

    /// Look up by architecture name.
    pub fn lookup(&self, arch: &str) -> Option<&DrgnArchMapping> {
        self.mappings.get(arch)
    }

    /// Register default mappings based on ELF e_machine values.
    fn register_defaults(&mut self) {
        // EM_386
        self.register(DrgnArchMapping {
            drgn_arch: "i386".to_string(),
            ghidra_lang_id: "x86:LE:32:Protected".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "x86 32-bit".to_string(),
            endian: Endianness::Little,
            pointer_size: 4,
        });

        // EM_X86_64
        self.register(DrgnArchMapping {
            drgn_arch: "x86_64".to_string(),
            ghidra_lang_id: "x86:LE:64:default".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "x86-64".to_string(),
            endian: Endianness::Little,
            pointer_size: 8,
        });

        // EM_AARCH64
        self.register(DrgnArchMapping {
            drgn_arch: "aarch64".to_string(),
            ghidra_lang_id: "AARCH64:LE:64:v8A".to_string(),
            ghidra_comp_id: "default".to_string(),
            description: "AArch64".to_string(),
            endian: Endianness::Little,
            pointer_size: 8,
        });

        // EM_ARM
        self.register(DrgnArchMapping {
            drgn_arch: "arm".to_string(),
            ghidra_lang_id: "ARM:LE:32:v8".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "ARM 32-bit".to_string(),
            endian: Endianness::Little,
            pointer_size: 4,
        });

        // EM_MIPS
        self.register(DrgnArchMapping {
            drgn_arch: "mips".to_string(),
            ghidra_lang_id: "MIPS:BE:32:default".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "MIPS 32-bit BE".to_string(),
            endian: Endianness::Big,
            pointer_size: 4,
        });

        // EM_PPC64
        self.register(DrgnArchMapping {
            drgn_arch: "powerpc64".to_string(),
            ghidra_lang_id: "PowerPC:BE:64:64-32addr".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "PowerPC 64-bit".to_string(),
            endian: Endianness::Big,
            pointer_size: 8,
        });

        // EM_RISCV
        self.register(DrgnArchMapping {
            drgn_arch: "riscv".to_string(),
            ghidra_lang_id: "RISCV:LE:64:default".to_string(),
            ghidra_comp_id: "default".to_string(),
            description: "RISC-V 64-bit".to_string(),
            endian: Endianness::Little,
            pointer_size: 8,
        });

        // EM_S390
        self.register(DrgnArchMapping {
            drgn_arch: "s390x".to_string(),
            ghidra_lang_id: "zSeries:BE:64:default".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "s390x (IBM System z)".to_string(),
            endian: Endianness::Big,
            pointer_size: 8,
        });
    }
}

impl Default for DrgnArchRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Detect OS from drgn target info.
pub fn detect_os(is_kernel: bool) -> &'static str {
    if is_kernel {
        "Linux"
    } else {
        "Linux"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_registry_x86_64() {
        let registry = DrgnArchRegistry::new();
        let mapping = registry.lookup("x86_64").unwrap();
        assert_eq!(mapping.ghidra_lang_id, "x86:LE:64:default");
        assert_eq!(mapping.pointer_size, 8);
    }

    #[test]
    fn test_arch_registry_aarch64() {
        let registry = DrgnArchRegistry::new();
        let mapping = registry.lookup("aarch64").unwrap();
        assert_eq!(mapping.endian, Endianness::Little);
    }

    #[test]
    fn test_arch_registry_s390x() {
        let registry = DrgnArchRegistry::new();
        let mapping = registry.lookup("s390x").unwrap();
        assert_eq!(mapping.endian, Endianness::Big);
        assert_eq!(mapping.pointer_size, 8);
    }

    #[test]
    fn test_detect_os() {
        assert_eq!(detect_os(true), "Linux");
        assert_eq!(detect_os(false), "Linux");
    }

    #[test]
    fn test_endian_str() {
        assert_eq!(Endianness::Little.as_trace_str(), "little");
        assert_eq!(Endianness::Big.as_trace_str(), "big");
    }
}
