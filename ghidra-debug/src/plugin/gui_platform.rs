//! Platform plugin data model.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.platform` package.
//! Provides data model types for the platform panel that shows the
//! currently connected debugger platform and its configuration.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Platform info display
// ---------------------------------------------------------------------------

/// Display information about a connected debugger platform.
///
/// Ported from Ghidra's `DebuggerPlatformPlugin` provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformDisplayInfo {
    /// The platform name.
    pub name: String,
    /// The language ID (e.g., "x86:LE:64:default").
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// The tool name (e.g., "gdb", "lldb", "dbgeng").
    pub tool: String,
    /// The OS name.
    pub os: String,
    /// The architecture name.
    pub architecture: String,
    /// The endianness.
    pub endian: Endianness,
    /// Whether the platform is currently connected.
    pub connected: bool,
}

/// Endianness of the platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Endianness {
    /// Little-endian.
    Little,
    /// Big-endian.
    Big,
}

impl std::fmt::Display for Endianness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endianness::Little => write!(f, "Little-Endian"),
            Endianness::Big => write!(f, "Big-Endian"),
        }
    }
}

// ---------------------------------------------------------------------------
// Platform mapper data
// ---------------------------------------------------------------------------

/// Data about a platform mapper that maps trace data to program data.
///
/// Ported from Ghidra's `DebuggerPlatformMapper` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformMapperData {
    /// The mapper name.
    pub name: String,
    /// The source language ID.
    pub source_language_id: String,
    /// The destination language ID.
    pub dest_language_id: String,
    /// Whether register mapping is available.
    pub has_register_mapping: bool,
    /// Whether memory mapping is available.
    pub has_memory_mapping: bool,
}

/// A register mapping entry.
///
/// Ported from Ghidra's register mapping in `DebuggerPlatformMapper`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterMappingEntry {
    /// The source register name.
    pub source_register: String,
    /// The destination register name.
    pub dest_register: String,
    /// The size in bytes.
    pub size: u32,
}

// ---------------------------------------------------------------------------
// Disassembly result
// ---------------------------------------------------------------------------

/// Result of a disassembly operation on a trace.
///
/// Ported from Ghidra's `DisassemblyResult`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassemblyResult {
    /// The address that was disassembled.
    pub address: u64,
    /// The instruction mnemonic.
    pub mnemonic: String,
    /// The full disassembly text.
    pub text: String,
    /// The instruction length in bytes.
    pub length: u32,
    /// Whether the instruction was successfully decoded.
    pub success: bool,
    /// Error message (if decoding failed).
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// Platform plugin event
// ---------------------------------------------------------------------------

/// Event emitted when the debugger platform changes.
///
/// Ported from Ghidra's `DebuggerPlatformPluginEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformChangedEvent {
    /// The trace ID.
    pub trace_id: String,
    /// The new platform info (if connected).
    pub platform: Option<PlatformDisplayInfo>,
}

// ---------------------------------------------------------------------------
// Platform provider model
// ---------------------------------------------------------------------------

/// The data model for the platform provider panel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformProviderModel {
    /// The current platform info.
    pub current_platform: Option<PlatformDisplayInfo>,
    /// The platform mapper data.
    pub mapper: Option<PlatformMapperData>,
    /// Register mappings.
    pub register_mappings: Vec<RegisterMappingEntry>,
    /// The trace ID.
    pub trace_id: Option<String>,
}

impl PlatformProviderModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self {
            current_platform: None,
            mapper: None,
            register_mappings: Vec::new(),
            trace_id: None,
        }
    }

    /// Set the platform.
    pub fn set_platform(&mut self, info: PlatformDisplayInfo) {
        self.current_platform = Some(info);
    }

    /// Clear the platform.
    pub fn clear(&mut self) {
        self.current_platform = None;
        self.mapper = None;
        self.register_mappings.clear();
        self.trace_id = None;
    }

    /// Whether a platform is connected.
    pub fn is_connected(&self) -> bool {
        self.current_platform
            .as_ref()
            .map(|p| p.connected)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endianness_display() {
        assert_eq!(Endianness::Little.to_string(), "Little-Endian");
        assert_eq!(Endianness::Big.to_string(), "Big-Endian");
    }

    #[test]
    fn test_platform_display_info() {
        let info = PlatformDisplayInfo {
            name: "Windows x64".into(),
            language_id: "x86:LE:64:default".into(),
            compiler_spec_id: "windows".into(),
            tool: "dbgeng".into(),
            os: "windows".into(),
            architecture: "x86_64".into(),
            endian: Endianness::Little,
            connected: true,
        };
        assert_eq!(info.endian, Endianness::Little);
        assert!(info.connected);
    }

    #[test]
    fn test_platform_provider_model() {
        let mut model = PlatformProviderModel::new();
        assert!(!model.is_connected());
        assert!(model.current_platform.is_none());

        model.set_platform(PlatformDisplayInfo {
            name: "Linux x64".into(),
            language_id: "x86:LE:64:default".into(),
            compiler_spec_id: "gcc".into(),
            tool: "gdb".into(),
            os: "linux".into(),
            architecture: "x86_64".into(),
            endian: Endianness::Little,
            connected: true,
        });
        assert!(model.is_connected());

        model.clear();
        assert!(!model.is_connected());
    }

    #[test]
    fn test_register_mapping_entry() {
        let entry = RegisterMappingEntry {
            source_register: "RAX".into(),
            dest_register: "rax".into(),
            size: 8,
        };
        assert_eq!(entry.size, 8);
    }

    #[test]
    fn test_disassembly_result() {
        let result = DisassemblyResult {
            address: 0x400000,
            mnemonic: "mov".into(),
            text: "mov eax, 1".into(),
            length: 5,
            success: true,
            error: None,
        };
        assert!(result.success);
        assert_eq!(result.length, 5);
    }

    #[test]
    fn test_platform_mapper_data() {
        let mapper = PlatformMapperData {
            name: "x86-64 to x86-64".into(),
            source_language_id: "x86:LE:64:default".into(),
            dest_language_id: "x86:LE:64:default".into(),
            has_register_mapping: true,
            has_memory_mapping: true,
        };
        assert!(mapper.has_register_mapping);
        assert!(mapper.has_memory_mapping);
    }
}
