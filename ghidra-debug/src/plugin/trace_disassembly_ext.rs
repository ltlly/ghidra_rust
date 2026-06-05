//! Extended trace disassembly types ported from Java.
//!
//! Ported from the Debugger module's `disassemble` package. Provides
//! the core data types and extension traits for trace disassembly
//! operations, including platform-aware disassembly, patching, and
//! injection.

use crate::model::address_snap::TraceAddressSnapRange;
use crate::model::Lifespan;

/// The result of a disassembly operation on a trace.
#[derive(Debug, Clone)]
pub struct TraceDisassemblyResult {
    /// The platform/language used for disassembly.
    pub language_id: String,
    /// The address range that was disassembled.
    pub address_range: (u64, u64),
    /// Number of instructions disassembled.
    pub instruction_count: usize,
    /// Whether the disassembly completed successfully.
    pub success: bool,
    /// Error message if disassembly failed.
    pub error: Option<String>,
}

/// Configuration for a trace disassembly operation.
#[derive(Debug, Clone)]
pub struct TraceDisassemblyConfig {
    /// The starting address for disassembly.
    pub start_address: u64,
    /// Maximum number of bytes to disassemble.
    pub max_bytes: usize,
    /// Whether to use the current platform or a specific one.
    pub use_current_platform: bool,
    /// Override language ID (if not using current platform).
    pub override_language_id: Option<String>,
}

impl TraceDisassemblyConfig {
    /// Create a new config for disassembly at the given address.
    pub fn at_address(start_address: u64) -> Self {
        Self {
            start_address,
            max_bytes: 1024,
            use_current_platform: true,
            override_language_id: None,
        }
    }

    /// Set the maximum number of bytes to disassemble.
    pub fn with_max_bytes(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Use a specific language for disassembly instead of the current platform.
    pub fn with_language(mut self, language_id: impl Into<String>) -> Self {
        self.override_language_id = Some(language_id.into());
        self.use_current_platform = false;
        self
    }
}

/// Information about a disassembly injection point.
///
/// Ported from `DisassemblyInjectInfo`. When a trace needs disassembly
/// at a particular platform, injection providers can supply custom
/// disassembly logic.
#[derive(Debug, Clone)]
pub struct DisassemblyInjectInfo {
    /// Platform information for the injection.
    pub platform_info: PlatformInjectInfo,
    /// Whether this injection is the default fallback.
    pub is_default: bool,
}

/// Platform-specific information for disassembly injection.
#[derive(Debug, Clone)]
pub struct PlatformInjectInfo {
    /// The language ID this injection applies to.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// Human-readable description.
    pub description: String,
}

/// Trait for disassembly injection providers.
///
/// Ported from `DisassemblyInject`. Extension points that provide
/// custom disassembly for specific platforms implement this trait.
pub trait DisassemblyInject: Send + Sync {
    /// Get the injection info, if available.
    fn inject_info(&self) -> Option<&DisassemblyInjectInfo>;

    /// Whether this injection applies to the given language.
    fn applies_to(&self, language_id: &str) -> bool {
        self.inject_info()
            .map(|info| info.platform_info.language_id == language_id)
            .unwrap_or(false)
    }

    /// Perform disassembly on the given memory bytes.
    fn disassemble(&self, bytes: &[u8], address: u64) -> TraceDisassemblyResult;
}

/// A trace disassemble action that targets a specific platform.
#[derive(Debug, Clone)]
pub struct TraceDisassembleAction {
    /// The action name.
    pub name: String,
    /// The target language ID.
    pub language_id: String,
    /// The action group for menu placement.
    pub group: String,
    /// Whether this is for the current platform.
    pub is_current_platform: bool,
}

impl TraceDisassembleAction {
    /// Create a new disassemble action for a fixed platform.
    pub fn for_platform(name: impl Into<String>, language_id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            language_id: language_id.into(),
            group: "Disassembly".into(),
            is_current_platform: false,
        }
    }

    /// Create a disassemble action for the current platform.
    pub fn for_current_platform(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            language_id: String::new(),
            group: "Disassembly".into(),
            is_current_platform: true,
        }
    }
}

/// A trace patch instruction action for modifying trace memory.
#[derive(Debug, Clone)]
pub struct TracePatchAction {
    /// The action name.
    pub name: String,
    /// The target language ID for patching.
    pub language_id: String,
}

impl TracePatchAction {
    /// Create a new patch action.
    pub fn new(name: impl Into<String>, language_id: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            language_id: language_id.into(),
        }
    }
}

/// A trace patch data action for modifying raw bytes in a trace.
#[derive(Debug, Clone)]
pub struct TracePatchDataAction {
    /// The action name.
    pub name: String,
    /// The target address range.
    pub target_range: (u64, u64),
    /// The replacement bytes.
    pub patch_bytes: Vec<u8>,
}

impl TracePatchDataAction {
    /// Create a new patch data action.
    pub fn new(name: impl Into<String>, target_range: (u64, u64), patch_bytes: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            target_range,
            patch_bytes,
        }
    }

    /// Get the patch size in bytes.
    pub fn patch_size(&self) -> usize {
        self.patch_bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disassembly_config() {
        let config = TraceDisassemblyConfig::at_address(0x400000)
            .with_max_bytes(2048)
            .with_language("x86:LE:64:default");
        assert_eq!(config.start_address, 0x400000);
        assert_eq!(config.max_bytes, 2048);
        assert!(!config.use_current_platform);
        assert_eq!(config.override_language_id.as_deref(), Some("x86:LE:64:default"));
    }

    #[test]
    fn test_disassembly_result() {
        let result = TraceDisassemblyResult {
            language_id: "x86:LE:64:default".into(),
            address_range: (0x400000, 0x400100),
            instruction_count: 64,
            success: true,
            error: None,
        };
        assert!(result.success);
        assert_eq!(result.instruction_count, 64);
    }

    #[test]
    fn test_disassemble_action() {
        let action = TraceDisassembleAction::for_platform("Disassemble as ARM", "ARM:LE:32:v8");
        assert_eq!(action.language_id, "ARM:LE:32:v8");
        assert!(!action.is_current_platform);

        let current = TraceDisassembleAction::for_current_platform("Disassemble");
        assert!(current.is_current_platform);
    }

    #[test]
    fn test_patch_data_action() {
        let action = TracePatchDataAction::new("NOP sled", (0x400000, 0x400010), vec![0x90; 16]);
        assert_eq!(action.patch_size(), 16);
    }

    #[test]
    fn test_inject_info() {
        let info = DisassemblyInjectInfo {
            platform_info: PlatformInjectInfo {
                language_id: "x86:LE:64:default".into(),
                compiler_spec_id: "default".into(),
                description: "x86-64".into(),
            },
            is_default: true,
        };
        assert!(info.is_default);
        assert_eq!(info.platform_info.language_id, "x86:LE:64:default");
    }
}
