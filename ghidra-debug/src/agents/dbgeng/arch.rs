//! Dbgeng architecture and language mapping.
//!
//! Maps Windows Debugging Engine architecture information to Ghidra
//! language/compiler spec IDs. The dbgeng agent primarily targets
//! x86-64 Windows targets, with WoW64 support for 32-bit modules.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A dbgeng architecture mapping entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DbgEngArchMapping {
    /// Architecture name (e.g. "x86_64", "x86").
    pub arch: String,
    /// Ghidra language ID.
    pub ghidra_lang_id: String,
    /// Ghidra compiler spec ID.
    pub ghidra_comp_id: String,
    /// Description.
    pub description: String,
    /// Endianness (always little-endian for Windows).
    pub is_64bit: bool,
    /// Whether this is a WoW64 mapping.
    pub is_wow64: bool,
}

/// Endianness is always little-endian for dbgeng targets.
pub const ENDIAN: &str = "little";

/// Dbgeng architecture registry.
pub struct DbgEngArchRegistry {
    mappings: HashMap<String, DbgEngArchMapping>,
}

impl DbgEngArchRegistry {
    /// Create a new registry with default mappings.
    pub fn new() -> Self {
        let mut registry = Self {
            mappings: HashMap::new(),
        };
        registry.register_defaults();
        registry
    }

    /// Register a mapping.
    pub fn register(&mut self, mapping: DbgEngArchMapping) {
        self.mappings.insert(mapping.arch.clone(), mapping);
    }

    /// Look up by architecture name.
    pub fn lookup(&self, arch: &str) -> Option<&DbgEngArchMapping> {
        self.mappings.get(arch)
    }

    /// Get all registered mappings.
    pub fn all_mappings(&self) -> Vec<&DbgEngArchMapping> {
        self.mappings.values().collect()
    }

    /// Register default mappings.
    fn register_defaults(&mut self) {
        // x86-64 (native 64-bit)
        self.register(DbgEngArchMapping {
            arch: "x86_64".to_string(),
            ghidra_lang_id: "x86:LE:64:default".to_string(),
            ghidra_comp_id: "windows".to_string(),
            description: "x86-64 Windows".to_string(),
            is_64bit: true,
            is_wow64: false,
        });

        // x64_32 (32-bit module in 64-bit process)
        self.register(DbgEngArchMapping {
            arch: "x64_32".to_string(),
            ghidra_lang_id: "x86:LE:64:default".to_string(),
            ghidra_comp_id: "VS".to_string(),
            description: "x86-64 Windows (32-bit module)".to_string(),
            is_64bit: true,
            is_wow64: false,
        });

        // WoW64 (32-bit process on 64-bit Windows)
        self.register(DbgEngArchMapping {
            arch: "wow64".to_string(),
            ghidra_lang_id: "x86:LE:32:Protected".to_string(),
            ghidra_comp_id: "VS".to_string(),
            description: "WoW64 (32-bit on 64-bit Windows)".to_string(),
            is_64bit: false,
            is_wow64: true,
        });

        // ARM64 (Windows on ARM)
        self.register(DbgEngArchMapping {
            arch: "arm64".to_string(),
            ghidra_lang_id: "AARCH64:LE:64:v8A".to_string(),
            ghidra_comp_id: "windows".to_string(),
            description: "ARM64 Windows".to_string(),
            is_64bit: true,
            is_wow64: false,
        });
    }
}

impl Default for DbgEngArchRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Detect whether a target is 64-bit from its architecture string.
pub fn is_64bit_arch(arch: &str) -> bool {
    let lower = arch.to_lowercase();
    lower.contains("x86_64") || lower.contains("x64") || lower.contains("arm64")
        || lower.contains("aarch64")
}

/// Detect whether a target is WoW64.
pub fn is_wow64(arch: &str) -> bool {
    arch.to_lowercase().contains("wow64")
}

/// Map a dbgeng architecture to the OS string.
pub fn detect_os() -> &'static str {
    "Windows"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_arch_registry_x86_64() {
        let registry = DbgEngArchRegistry::new();
        let mapping = registry.lookup("x86_64").unwrap();
        assert_eq!(mapping.ghidra_lang_id, "x86:LE:64:default");
        assert!(mapping.is_64bit);
        assert!(!mapping.is_wow64);
    }

    #[test]
    fn test_arch_registry_wow64() {
        let registry = DbgEngArchRegistry::new();
        let mapping = registry.lookup("wow64").unwrap();
        assert_eq!(mapping.ghidra_lang_id, "x86:LE:32:Protected");
        assert!(!mapping.is_64bit);
        assert!(mapping.is_wow64);
    }

    #[test]
    fn test_arch_registry_arm64() {
        let registry = DbgEngArchRegistry::new();
        let mapping = registry.lookup("arm64").unwrap();
        assert_eq!(mapping.ghidra_lang_id, "AARCH64:LE:64:v8A");
    }

    #[test]
    fn test_is_64bit() {
        assert!(is_64bit_arch("x86_64"));
        assert!(is_64bit_arch("x64"));
        assert!(is_64bit_arch("arm64"));
        assert!(!is_64bit_arch("x86"));
        assert!(!is_64bit_arch("wow64"));
    }

    #[test]
    fn test_is_wow64() {
        assert!(is_wow64("wow64"));
        assert!(is_wow64("WoW64"));
        assert!(!is_wow64("x86_64"));
    }

    #[test]
    fn test_detect_os() {
        assert_eq!(detect_os(), "Windows");
    }
}
