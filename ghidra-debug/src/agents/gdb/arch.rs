//! GDB architecture and language mapping.
//!
//! Maps GDB architecture identifiers to Ghidra language/compiler spec IDs.
//! GDB identifies architectures by its internal `gdbarch` info, which we
//! must translate to Ghidra's language ID scheme.
//!
//! The GDB platform opinion (`GdbDebuggerPlatformOpinion`) handles the
//! Ghidra-side of this mapping. Here we provide the agent-side mapping
//! for the trace object `Environment`.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A GDB architecture mapping entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GdbArchMapping {
    /// GDB architecture name (e.g. "i386:x86-64", "aarch64").
    pub gdb_arch: String,
    /// Ghidra language ID (e.g. "x86:LE:64:default", "AARCH64:LE:64:v8A").
    pub ghidra_lang_id: String,
    /// Ghidra compiler spec ID (e.g. "default", "gcc", "VS").
    pub ghidra_comp_id: String,
    /// Description.
    pub description: String,
    /// Endianness.
    pub endian: Endianness,
    /// Pointer size in bytes.
    pub pointer_size: usize,
}

/// Endianness of a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Endianness {
    /// Little-endian.
    Little,
    /// Big-endian.
    Big,
}

impl Endianness {
    /// Convert to the trace object value.
    pub fn as_trace_str(&self) -> &'static str {
        match self {
            Self::Little => "little",
            Self::Big => "big",
        }
    }
}

/// GDB architecture registry.
///
/// Maintains the mapping from GDB architecture names to Ghidra
/// language/compiler spec IDs.
pub struct GdbArchRegistry {
    mappings: HashMap<String, GdbArchMapping>,
}

impl GdbArchRegistry {
    /// Create a new registry with default mappings.
    pub fn new() -> Self {
        let mut registry = Self {
            mappings: HashMap::new(),
        };
        registry.register_defaults();
        registry
    }

    /// Register a mapping.
    pub fn register(&mut self, mapping: GdbArchMapping) {
        self.mappings.insert(mapping.gdb_arch.clone(), mapping);
    }

    /// Look up a mapping by GDB architecture name.
    pub fn lookup(&self, gdb_arch: &str) -> Option<&GdbArchMapping> {
        self.mappings.get(gdb_arch)
    }

    /// Get all registered mappings.
    pub fn all_mappings(&self) -> Vec<&GdbArchMapping> {
        self.mappings.values().collect()
    }

    /// Register the default architecture mappings.
    fn register_defaults(&mut self) {
        // x86-64 (Linux)
        self.register(GdbArchMapping {
            gdb_arch: "i386:x86-64".to_string(),
            ghidra_lang_id: "x86:LE:64:default".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "x86-64 Linux".to_string(),
            endian: Endianness::Little,
            pointer_size: 8,
        });

        // x86-64 (Windows/MinGW)
        self.register(GdbArchMapping {
            gdb_arch: "i386:x86-64".to_string(),
            ghidra_lang_id: "x86:LE:64:default".to_string(),
            ghidra_comp_id: "windows".to_string(),
            description: "x86-64 Windows".to_string(),
            endian: Endianness::Little,
            pointer_size: 8,
        });

        // x86 (32-bit)
        self.register(GdbArchMapping {
            gdb_arch: "i386".to_string(),
            ghidra_lang_id: "x86:LE:32:Protected".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "x86 32-bit".to_string(),
            endian: Endianness::Little,
            pointer_size: 4,
        });

        // ARM (32-bit)
        self.register(GdbArchMapping {
            gdb_arch: "arm".to_string(),
            ghidra_lang_id: "ARM:LE:32:v8".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "ARM 32-bit".to_string(),
            endian: Endianness::Little,
            pointer_size: 4,
        });

        // AArch64
        self.register(GdbArchMapping {
            gdb_arch: "aarch64".to_string(),
            ghidra_lang_id: "AARCH64:LE:64:v8A".to_string(),
            ghidra_comp_id: "default".to_string(),
            description: "AArch64".to_string(),
            endian: Endianness::Little,
            pointer_size: 8,
        });

        // MIPS (32-bit, big-endian)
        self.register(GdbArchMapping {
            gdb_arch: "mips".to_string(),
            ghidra_lang_id: "MIPS:BE:32:default".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "MIPS 32-bit Big-Endian".to_string(),
            endian: Endianness::Big,
            pointer_size: 4,
        });

        // MIPS (32-bit, little-endian)
        self.register(GdbArchMapping {
            gdb_arch: "mipsel".to_string(),
            ghidra_lang_id: "MIPS:LE:32:default".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "MIPS 32-bit Little-Endian".to_string(),
            endian: Endianness::Little,
            pointer_size: 4,
        });

        // PowerPC (32-bit)
        self.register(GdbArchMapping {
            gdb_arch: "powerpc".to_string(),
            ghidra_lang_id: "PowerPC:BE:32:default".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "PowerPC 32-bit".to_string(),
            endian: Endianness::Big,
            pointer_size: 4,
        });

        // PowerPC (64-bit)
        self.register(GdbArchMapping {
            gdb_arch: "powerpc:common64".to_string(),
            ghidra_lang_id: "PowerPC:BE:64:64-32addr".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "PowerPC 64-bit".to_string(),
            endian: Endianness::Big,
            pointer_size: 8,
        });

        // RISC-V (64-bit)
        self.register(GdbArchMapping {
            gdb_arch: "riscv:rv64".to_string(),
            ghidra_lang_id: "RISCV:LE:64:default".to_string(),
            ghidra_comp_id: "default".to_string(),
            description: "RISC-V 64-bit".to_string(),
            endian: Endianness::Little,
            pointer_size: 8,
        });
    }
}

impl Default for GdbArchRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse GDB's `show architecture` output to extract the architecture name.
pub fn parse_gdb_arch(arch_output: &str) -> Option<String> {
    // GDB output format: "The target architecture is set to \"i386:x86-64\"."
    if let Some(start) = arch_output.find('"') {
        if let Some(end) = arch_output[start + 1..].find('"') {
            return Some(arch_output[start + 1..start + 1 + end].to_string());
        }
    }
    // Also handle direct arch name
    let trimmed = arch_output.trim();
    if !trimmed.is_empty() && !trimmed.contains(' ') {
        return Some(trimmed.to_string());
    }
    None
}

/// Parse GDB's `show endian` output.
pub fn parse_gdb_endian(endian_output: &str) -> Endianness {
    let lower = endian_output.to_lowercase();
    if lower.contains("big") {
        Endianness::Big
    } else {
        Endianness::Little
    }
}

/// Determine OS from GDB's target triple or info.
pub fn detect_os_from_gdb(info_os: &str) -> &'static str {
    let lower = info_os.to_lowercase();
    if lower.contains("linux") || lower.contains("gnu") {
        "Linux"
    } else if lower.contains("windows") || lower.contains("mingw") || lower.contains("cygwin") {
        "Windows"
    } else if lower.contains("darwin") || lower.contains("macos") {
        "Darwin"
    } else if lower.contains("freebsd") {
        "FreeBSD"
    } else {
        "Unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_registry() {
        let registry = GdbArchRegistry::new();
        let mapping = registry.lookup("i386:x86-64");
        assert!(mapping.is_some());
        let m = mapping.unwrap();
        assert_eq!(m.ghidra_lang_id, "x86:LE:64:default");
        assert_eq!(m.pointer_size, 8);
    }

    #[test]
    fn test_arch_registry_aarch64() {
        let registry = GdbArchRegistry::new();
        let mapping = registry.lookup("aarch64").unwrap();
        assert_eq!(mapping.ghidra_lang_id, "AARCH64:LE:64:v8A");
        assert_eq!(mapping.endian, Endianness::Little);
    }

    #[test]
    fn test_arch_registry_unknown() {
        let registry = GdbArchRegistry::new();
        assert!(registry.lookup("unknown_arch").is_none());
    }

    #[test]
    fn test_parse_gdb_arch() {
        assert_eq!(
            parse_gdb_arch("The target architecture is set to \"i386:x86-64\"."),
            Some("i386:x86-64".to_string())
        );
        assert_eq!(
            parse_gdb_arch("aarch64"),
            Some("aarch64".to_string())
        );
        assert_eq!(parse_gdb_arch(""), None);
    }

    #[test]
    fn test_parse_gdb_endian() {
        assert_eq!(parse_gdb_endian("The target endianness is set automatically (currently little endian)."), Endianness::Little);
        assert_eq!(parse_gdb_endian("big endian"), Endianness::Big);
    }

    #[test]
    fn test_detect_os() {
        assert_eq!(detect_os_from_gdb("GNU/Linux"), "Linux");
        assert_eq!(detect_os_from_gdb("mingw64"), "Windows");
        assert_eq!(detect_os_from_gdb("darwin21"), "Darwin");
        assert_eq!(detect_os_from_gdb("unknown"), "Unknown");
    }

    #[test]
    fn test_endian_trace_str() {
        assert_eq!(Endianness::Little.as_trace_str(), "little");
        assert_eq!(Endianness::Big.as_trace_str(), "big");
    }
}
