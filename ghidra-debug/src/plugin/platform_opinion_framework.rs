//! Platform opinion framework for debugger backends.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.platform`:
//! - `DebuggerPlatformOpinion`: Extension point for back-end platform opinions.
//! - `AbstractDebuggerPlatformOpinion`: Base for platform opinions.
//! - `HostDebuggerPlatformOpinion`: Default opinion for host platform.
//! - `OverrideDebuggerPlatformOpinion`: User override opinion.
//! - `DebuggerPlatformOffer`: A platform mapping offer.
//! - `AbstractDebuggerPlatformOffer`: Base for platform offers.
//!
//! Platform opinions allow debug backends (GDB, LLDB, Dbgeng, etc.) to suggest
//! how to map a target's architecture to Ghidra's language/compiler spec system.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The type of debugger backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DebuggerBackend {
    /// GNU Debugger (GDB).
    Gdb,
    /// LLVM Debugger (LLDB).
    Lldb,
    /// Windows Debugger Engine (DbgEng/WinDbg).
    DbgEng,
    /// Frida dynamic instrumentation.
    Frida,
    /// Java Debug Interface (JDI).
    Jdi,
    /// Custom/unknown backend.
    Custom,
}

impl DebuggerBackend {
    /// Get the string identifier for this backend.
    pub fn id(&self) -> &'static str {
        match self {
            Self::Gdb => "gdb",
            Self::Lldb => "lldb",
            Self::DbgEng => "dbgeng",
            Self::Frida => "frida",
            Self::Jdi => "jdi",
            Self::Custom => "custom",
        }
    }

    /// Parse a backend from its string identifier.
    pub fn from_id(id: &str) -> Option<Self> {
        match id.to_lowercase().as_str() {
            "gdb" => Some(Self::Gdb),
            "lldb" => Some(Self::Lldb),
            "dbgeng" | "windbg" => Some(Self::DbgEng),
            "frida" => Some(Self::Frida),
            "jdi" => Some(Self::Jdi),
            _ => None,
        }
    }
}

/// Configuration for an architecture-to-platform mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchPlatformMapping {
    /// The architecture identifier (e.g., "x86", "ARM", "MIPS").
    pub architecture: String,
    /// The language ID for this architecture.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// The endianness.
    pub little_endian: bool,
    /// The pointer size in bytes.
    pub pointer_size: u32,
    /// Whether this is a 64-bit architecture.
    pub is_64bit: bool,
}

impl ArchPlatformMapping {
    /// Create a new mapping.
    pub fn new(
        architecture: &str,
        language_id: &str,
        compiler_spec_id: &str,
        little_endian: bool,
        pointer_size: u32,
        is_64bit: bool,
    ) -> Self {
        Self {
            architecture: architecture.to_string(),
            language_id: language_id.to_string(),
            compiler_spec_id: compiler_spec_id.to_string(),
            little_endian,
            pointer_size,
            is_64bit,
        }
    }
}

/// Known platform opinions for GDB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GdbPlatformOpinion {
    /// The backend type.
    pub backend: DebuggerBackend,
    /// Architecture-to-platform mappings.
    pub mappings: Vec<ArchPlatformMapping>,
}

impl GdbPlatformOpinion {
    /// Create the default GDB platform opinion.
    pub fn default_opinion() -> Self {
        Self {
            backend: DebuggerBackend::Gdb,
            mappings: vec![
                ArchPlatformMapping::new("i386", "x86:LE:32:default", "default", true, 4, false),
                ArchPlatformMapping::new("i386:x86-64", "x86:LE:64:default", "default", true, 8, true),
                ArchPlatformMapping::new("aarch64", "AARCH64:LE:64:v8A", "default", true, 8, true),
                ArchPlatformMapping::new("arm", "ARM:LE:32:v8", "default", true, 4, false),
                ArchPlatformMapping::new("mips", "MIPS:BE:32:default", "default", false, 4, false),
                ArchPlatformMapping::new("mipsel", "MIPS:LE:32:default", "default", true, 4, false),
                ArchPlatformMapping::new("powerpc", "PowerPC:BE:32:default", "default", false, 4, false),
                ArchPlatformMapping::new("sparc", "sparc:BE:32:default", "default", false, 4, false),
                ArchPlatformMapping::new("riscv:rv64", "RISCV:LE:64:default", "default", true, 8, true),
                ArchPlatformMapping::new("riscv:rv32", "RISCV:LE:32:default", "default", true, 4, false),
            ],
        }
    }

    /// Look up a platform for the given architecture.
    pub fn lookup(&self, arch: &str) -> Option<&ArchPlatformMapping> {
        self.mappings.iter().find(|m| m.architecture == arch)
    }
}

/// Known platform opinions for LLDB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LldbPlatformOpinion {
    /// The backend type.
    pub backend: DebuggerBackend,
    /// Architecture-to-platform mappings.
    pub mappings: Vec<ArchPlatformMapping>,
}

impl LldbPlatformOpinion {
    /// Create the default LLDB platform opinion.
    pub fn default_opinion() -> Self {
        Self {
            backend: DebuggerBackend::Lldb,
            mappings: vec![
                ArchPlatformMapping::new("x86_64", "x86:LE:64:default", "default", true, 8, true),
                ArchPlatformMapping::new("i386", "x86:LE:32:default", "default", true, 4, false),
                ArchPlatformMapping::new("arm64", "AARCH64:LE:64:v8A", "default", true, 8, true),
                ArchPlatformMapping::new("armv7", "ARM:LE:32:v8", "default", true, 4, false),
                ArchPlatformMapping::new("mips64", "MIPS:BE:64:64-32R6", "default", false, 8, true),
            ],
        }
    }

    /// Look up a platform for the given architecture.
    pub fn lookup(&self, arch: &str) -> Option<&ArchPlatformMapping> {
        self.mappings.iter().find(|m| m.architecture == arch)
    }
}

/// Known platform opinions for DbgEng (Windows Debugger).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbgEngPlatformOpinion {
    /// The backend type.
    pub backend: DebuggerBackend,
    /// Architecture-to-platform mappings.
    pub mappings: Vec<ArchPlatformMapping>,
}

impl DbgEngPlatformOpinion {
    /// Create the default DbgEng platform opinion.
    pub fn default_opinion() -> Self {
        Self {
            backend: DebuggerBackend::DbgEng,
            mappings: vec![
                ArchPlatformMapping::new("x86_64", "x86:LE:64:default", "windows", true, 8, true),
                ArchPlatformMapping::new("i386", "x86:LE:32:default", "windows", true, 4, false),
                ArchPlatformMapping::new("arm64", "AARCH64:LE:64:v8A", "windows", true, 8, true),
            ],
        }
    }

    /// Look up a platform for the given architecture.
    pub fn lookup(&self, arch: &str) -> Option<&ArchPlatformMapping> {
        self.mappings.iter().find(|m| m.architecture == arch)
    }
}

/// User override for platform mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverridePlatformOpinion {
    /// The language ID override.
    pub language_id: String,
    /// The compiler spec ID override.
    pub compiler_spec_id: String,
    /// The reason for the override.
    pub reason: Option<String>,
}

impl OverridePlatformOpinion {
    /// Create a new override.
    pub fn new(language_id: &str, compiler_spec_id: &str) -> Self {
        Self {
            language_id: language_id.to_string(),
            compiler_spec_id: compiler_spec_id.to_string(),
            reason: None,
        }
    }
}

/// The host platform opinion (always available).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostPlatformOpinion {
    /// The language ID of the host platform.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
}

impl HostPlatformOpinion {
    /// Create the host platform opinion.
    pub fn new(language_id: &str, compiler_spec_id: &str) -> Self {
        Self {
            language_id: language_id.to_string(),
            compiler_spec_id: compiler_spec_id.to_string(),
        }
    }
}

/// Disassembly inject configuration for platform-specific disassembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyInjectConfig {
    /// The language ID this inject applies to.
    pub language_id: String,
    /// Instructions to inject before disassembly.
    pub pre_instructions: Vec<String>,
    /// Instructions to inject after disassembly.
    pub post_instructions: Vec<String>,
    /// Register mappings for the inject.
    pub register_mappings: BTreeMap<String, String>,
}

impl DisassemblyInjectConfig {
    /// Create a new inject config.
    pub fn new(language_id: &str) -> Self {
        Self {
            language_id: language_id.to_string(),
            pre_instructions: Vec::new(),
            post_instructions: Vec::new(),
            register_mappings: BTreeMap::new(),
        }
    }

    /// Add a register mapping.
    pub fn with_register_mapping(mut self, from: &str, to: &str) -> Self {
        self.register_mappings.insert(from.to_string(), to.to_string());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debugger_backend_id() {
        assert_eq!(DebuggerBackend::Gdb.id(), "gdb");
        assert_eq!(DebuggerBackend::Lldb.id(), "lldb");
        assert_eq!(DebuggerBackend::DbgEng.id(), "dbgeng");
        assert_eq!(DebuggerBackend::Frida.id(), "frida");
        assert_eq!(DebuggerBackend::Jdi.id(), "jdi");
    }

    #[test]
    fn test_debugger_backend_from_id() {
        assert_eq!(DebuggerBackend::from_id("gdb"), Some(DebuggerBackend::Gdb));
        assert_eq!(DebuggerBackend::from_id("LLDB"), Some(DebuggerBackend::Lldb));
        assert_eq!(DebuggerBackend::from_id("windbg"), Some(DebuggerBackend::DbgEng));
        assert_eq!(DebuggerBackend::from_id("unknown"), None);
    }

    #[test]
    fn test_gdb_platform_opinion() {
        let opinion = GdbPlatformOpinion::default_opinion();
        assert_eq!(opinion.backend, DebuggerBackend::Gdb);
        assert!(!opinion.mappings.is_empty());

        let x86_64 = opinion.lookup("i386:x86-64");
        assert!(x86_64.is_some());
        let mapping = x86_64.unwrap();
        assert_eq!(mapping.language_id, "x86:LE:64:default");
        assert!(mapping.is_64bit);
        assert!(mapping.little_endian);
    }

    #[test]
    fn test_lldb_platform_opinion() {
        let opinion = LldbPlatformOpinion::default_opinion();
        assert_eq!(opinion.backend, DebuggerBackend::Lldb);

        let arm64 = opinion.lookup("arm64");
        assert!(arm64.is_some());
        assert_eq!(arm64.unwrap().language_id, "AARCH64:LE:64:v8A");
    }

    #[test]
    fn test_dbgeng_platform_opinion() {
        let opinion = DbgEngPlatformOpinion::default_opinion();
        assert_eq!(opinion.backend, DebuggerBackend::DbgEng);

        let x64 = opinion.lookup("x86_64");
        assert!(x64.is_some());
        assert_eq!(x64.unwrap().compiler_spec_id, "windows");
    }

    #[test]
    fn test_override_platform_opinion() {
        let override_op = OverridePlatformOpinion::new(
            "ARM:LE:32:v8",
            "default",
        );
        assert_eq!(override_op.language_id, "ARM:LE:32:v8");
    }

    #[test]
    fn test_host_platform_opinion() {
        let host = HostPlatformOpinion::new("x86:LE:64:default", "default");
        assert_eq!(host.language_id, "x86:LE:64:default");
    }

    #[test]
    fn test_arch_platform_mapping() {
        let mapping = ArchPlatformMapping::new(
            "x86_64",
            "x86:LE:64:default",
            "default",
            true,
            8,
            true,
        );
        assert_eq!(mapping.architecture, "x86_64");
        assert!(mapping.is_64bit);
        assert!(mapping.little_endian);
        assert_eq!(mapping.pointer_size, 8);
    }

    #[test]
    fn test_disassembly_inject_config() {
        let config = DisassemblyInjectConfig::new("x86:LE:64:default")
            .with_register_mapping("rax", "RAX")
            .with_register_mapping("rbx", "RBX");

        assert_eq!(config.register_mappings.len(), 2);
        assert_eq!(config.language_id, "x86:LE:64:default");
    }

    #[test]
    fn test_lookup_missing_arch() {
        let opinion = GdbPlatformOpinion::default_opinion();
        assert!(opinion.lookup("nonexistent_arch").is_none());
    }
}
