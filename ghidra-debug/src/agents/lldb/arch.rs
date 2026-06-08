//! LLDB architecture and language mapping.
//!
//! Maps LLDB target triple and architecture information to Ghidra
//! language/compiler spec IDs. LLDB uses target triples like
//! "x86_64-apple-macosx12.0.0" or "aarch64-linux-gnu".

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// An LLDB architecture mapping entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LldbArchMapping {
    /// LLDB architecture name (from target triple).
    pub lldb_arch: String,
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

/// LLDB architecture registry.
pub struct LldbArchRegistry {
    mappings: HashMap<String, LldbArchMapping>,
}

impl LldbArchRegistry {
    /// Create a new registry with default mappings.
    pub fn new() -> Self {
        let mut registry = Self {
            mappings: HashMap::new(),
        };
        registry.register_defaults();
        registry
    }

    /// Register a mapping.
    pub fn register(&mut self, mapping: LldbArchMapping) {
        self.mappings.insert(mapping.lldb_arch.clone(), mapping);
    }

    /// Look up by architecture name.
    pub fn lookup(&self, arch: &str) -> Option<&LldbArchMapping> {
        self.mappings.get(arch)
    }

    /// Register default mappings.
    fn register_defaults(&mut self) {
        self.register(LldbArchMapping {
            lldb_arch: "x86_64".to_string(),
            ghidra_lang_id: "x86:LE:64:default".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "x86-64".to_string(),
            endian: Endianness::Little,
            pointer_size: 8,
        });

        self.register(LldbArchMapping {
            lldb_arch: "x86_64-apple-macosx".to_string(),
            ghidra_lang_id: "x86:LE:64:default".to_string(),
            ghidra_comp_id: "clang".to_string(),
            description: "x86-64 macOS".to_string(),
            endian: Endianness::Little,
            pointer_size: 8,
        });

        self.register(LldbArchMapping {
            lldb_arch: "aarch64".to_string(),
            ghidra_lang_id: "AARCH64:LE:64:v8A".to_string(),
            ghidra_comp_id: "default".to_string(),
            description: "AArch64".to_string(),
            endian: Endianness::Little,
            pointer_size: 8,
        });

        self.register(LldbArchMapping {
            lldb_arch: "aarch64-apple-macosx".to_string(),
            ghidra_lang_id: "AARCH64:LE:64:v8A".to_string(),
            ghidra_comp_id: "clang".to_string(),
            description: "AArch64 macOS (Apple Silicon)".to_string(),
            endian: Endianness::Little,
            pointer_size: 8,
        });

        self.register(LldbArchMapping {
            lldb_arch: "aarch64-linux-gnu".to_string(),
            ghidra_lang_id: "AARCH64:LE:64:v8A".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "AArch64 Linux".to_string(),
            endian: Endianness::Little,
            pointer_size: 8,
        });

        self.register(LldbArchMapping {
            lldb_arch: "arm".to_string(),
            ghidra_lang_id: "ARM:LE:32:v8".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "ARM 32-bit".to_string(),
            endian: Endianness::Little,
            pointer_size: 4,
        });

        self.register(LldbArchMapping {
            lldb_arch: "armv7".to_string(),
            ghidra_lang_id: "ARM:LE:32:v8".to_string(),
            ghidra_comp_id: "gcc".to_string(),
            description: "ARMv7".to_string(),
            endian: Endianness::Little,
            pointer_size: 4,
        });
    }
}

impl Default for LldbArchRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse an LLDB target triple to extract the architecture.
pub fn parse_target_triple(triple: &str) -> Option<String> {
    // Format: arch-vendor-os[-env]
    triple.split('-').next().map(|s| s.to_string())
}

/// Detect OS from a target triple.
pub fn detect_os_from_triple(triple: &str) -> &'static str {
    let lower = triple.to_lowercase();
    if lower.contains("macos") || lower.contains("darwin") || lower.contains("apple") {
        "Darwin"
    } else if lower.contains("linux") || lower.contains("gnu") {
        "Linux"
    } else if lower.contains("windows") || lower.contains("mingw") {
        "Windows"
    } else if lower.contains("android") {
        "Android"
    } else {
        "Unknown"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_registry_x86_64() {
        let registry = LldbArchRegistry::new();
        let mapping = registry.lookup("x86_64").unwrap();
        assert_eq!(mapping.ghidra_lang_id, "x86:LE:64:default");
    }

    #[test]
    fn test_arch_registry_aarch64_macos() {
        let registry = LldbArchRegistry::new();
        let mapping = registry.lookup("aarch64-apple-macosx").unwrap();
        assert_eq!(mapping.ghidra_comp_id, "clang");
    }

    #[test]
    fn test_parse_target_triple() {
        assert_eq!(
            parse_target_triple("x86_64-apple-macosx12.0.0"),
            Some("x86_64".to_string())
        );
        assert_eq!(
            parse_target_triple("aarch64-linux-gnu"),
            Some("aarch64".to_string())
        );
    }

    #[test]
    fn test_detect_os() {
        assert_eq!(detect_os_from_triple("x86_64-apple-macosx12.0.0"), "Darwin");
        assert_eq!(detect_os_from_triple("aarch64-linux-gnu"), "Linux");
        assert_eq!(detect_os_from_triple("armv7-android"), "Android");
    }
}
