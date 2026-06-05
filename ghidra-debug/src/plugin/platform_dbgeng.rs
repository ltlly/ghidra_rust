//! Windows DbgEng (debugger engine) platform support.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.platform.dbgeng` package.
//! Provides platform opinion and disassembly injection for Windows debugging
//! via the DbgEng API (WinDbg, cdb, ntsd).

use serde::{Deserialize, Serialize};

use super::platform_opinion::{OpinionContext, PlatformOpinion, PlatformOpinionProvider};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The x86 32-bit language ID.
pub const LANG_ID_X86: &str = "x86:LE:32:default";

/// The x86-64 language ID.
pub const LANG_ID_X86_64: &str = "x86:LE:64:default";

/// The x86-64 in 32-bit compatibility mode language ID.
pub const LANG_ID_X86_64_32: &str = "x86:LE:64:compat32";

/// The Windows compiler spec ID.
pub const COMP_ID_WINDOWS: &str = "windows";

/// The DbgEng tool identifier.
pub const DBGENG_TOOL: &str = "dbgeng";

// ---------------------------------------------------------------------------
// DbgEng mode detection
// ---------------------------------------------------------------------------

/// x86/x64 mode detection for DbgEng targets.
///
/// Ported from Ghidra's `DbgengDebuggerPlatformOpinion.Mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DbgengMode {
    /// 64-bit mode.
    X64,
    /// 32-bit mode (either native x86 or WoW64).
    X86,
    /// Unknown mode.
    Unknown,
}

impl DbgengMode {
    /// Attempt to determine the mode from PE headers.
    ///
    /// Reads the PE header from the module at the given address to
    /// determine if the process is 32-bit or 64-bit.
    pub fn from_pe_header(is_64bit: bool) -> Self {
        if is_64bit {
            DbgengMode::X64
        } else {
            DbgengMode::X86
        }
    }

    /// Get the appropriate language ID for this mode.
    pub fn language_id(&self) -> &'static str {
        match self {
            DbgengMode::X64 => LANG_ID_X86_64,
            DbgengMode::X86 => LANG_ID_X86,
            DbgengMode::Unknown => LANG_ID_X86_64, // default to x64
        }
    }

    /// Get the compiler spec ID for this mode.
    pub fn compiler_spec_id(&self) -> &'static str {
        COMP_ID_WINDOWS
    }
}

// ---------------------------------------------------------------------------
// DbgEng disassembly inject
// ---------------------------------------------------------------------------

/// x86-64 specific disassembly injection for DbgEng targets.
///
/// Ported from Ghidra's `DbgengX64DisassemblyInject`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbgengX64DisassemblyInject {
    /// The detected mode (x86 vs x64).
    pub mode: DbgengMode,
    /// Whether the PE header was successfully read.
    pub pe_header_read: bool,
    /// Whether the module is a PE file.
    pub is_pe: bool,
}

impl DbgengX64DisassemblyInject {
    /// Create a new inject.
    pub fn new() -> Self {
        Self {
            mode: DbgengMode::Unknown,
            pe_header_read: false,
            is_pe: false,
        }
    }

    /// Update the mode from detected information.
    pub fn update_mode(&mut self, mode: DbgengMode) {
        self.mode = mode;
    }

    /// Whether the current mode is 64-bit.
    pub fn is_64bit(&self) -> bool {
        matches!(self.mode, DbgengMode::X64)
    }
}

impl Default for DbgengX64DisassemblyInject {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PE module analysis
// ---------------------------------------------------------------------------

/// Information extracted from a PE (Portable Executable) module.
///
/// Used by DbgEng to determine x86 vs x64 mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeModuleInfo {
    /// The module name.
    pub name: String,
    /// The base address.
    pub base_address: u64,
    /// Whether this is a 64-bit PE.
    pub is_64bit: bool,
    /// The PE machine type.
    pub machine_type: PeMachineType,
    /// Whether this is a DLL.
    pub is_dll: bool,
    /// The image size.
    pub image_size: u64,
}

/// PE machine type values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PeMachineType {
    /// Unknown machine.
    Unknown,
    /// x86 (I386).
    I386,
    /// x86-64 (AMD64).
    AMD64,
    /// ARM.
    ARM,
    /// ARM64 (AArch64).
    ARM64,
}

impl PeMachineType {
    /// Parse from the PE machine type field value.
    pub fn from_raw(value: u16) -> Self {
        match value {
            0x014C => PeMachineType::I386,
            0x8664 => PeMachineType::AMD64,
            0x01C0 => PeMachineType::ARM,
            0xAA64 => PeMachineType::ARM64,
            _ => PeMachineType::Unknown,
        }
    }

    /// Get the corresponding DbgEng mode.
    pub fn to_dbgeng_mode(&self) -> DbgengMode {
        match self {
            PeMachineType::AMD64 => DbgengMode::X64,
            PeMachineType::I386 => DbgengMode::X86,
            _ => DbgengMode::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// DbgEng platform opinion
// ---------------------------------------------------------------------------

/// DbgEng platform opinion provider.
///
/// Ported from Ghidra's `DbgengDebuggerPlatformOpinion`. Maps Windows
/// debugger information to Ghidra platform specs.
#[derive(Debug, Clone)]
pub struct DbgengPlatformOpinion;

impl PlatformOpinionProvider for DbgengPlatformOpinion {
    fn name(&self) -> &str {
        "DbgEng"
    }

    fn debugger_types(&self) -> &[&str] {
        &["dbgeng", "windbg", "cdb", "ntsd"]
    }

    fn get_opinions(&self, context: &OpinionContext) -> Vec<PlatformOpinion> {
        if context.debugger_type != "dbgeng"
            && context.debugger_type != "windbg"
            && context.debugger_type != "cdb"
            && context.debugger_type != "ntsd"
        {
            return Vec::new();
        }

        let os = context.os.to_lowercase();
        if os != "windows" && !os.is_empty() {
            return Vec::new();
        }

        let mut opinions = Vec::new();

        if context.pointer_size >= 8 {
            opinions.push(PlatformOpinion::new(
                "dbgeng",
                LANG_ID_X86_64,
                COMP_ID_WINDOWS,
                "x86-64",
                0.95,
            ));
            // Also provide 32-bit compat opinion
            opinions.push(PlatformOpinion::new(
                "dbgeng",
                LANG_ID_X86_64_32,
                COMP_ID_WINDOWS,
                "x86-64:compat32",
                0.5,
            ));
        } else {
            opinions.push(PlatformOpinion::new(
                "dbgeng",
                LANG_ID_X86,
                COMP_ID_WINDOWS,
                "x86",
                0.9,
            ));
        }

        opinions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dbgeng_mode() {
        assert_eq!(DbgengMode::from_pe_header(true), DbgengMode::X64);
        assert_eq!(DbgengMode::from_pe_header(false), DbgengMode::X86);
    }

    #[test]
    fn test_dbgeng_mode_language_id() {
        assert_eq!(DbgengMode::X64.language_id(), LANG_ID_X86_64);
        assert_eq!(DbgengMode::X86.language_id(), LANG_ID_X86);
        assert_eq!(DbgengMode::Unknown.language_id(), LANG_ID_X86_64);
    }

    #[test]
    fn test_dbgeng_mode_compiler_spec() {
        assert_eq!(DbgengMode::X64.compiler_spec_id(), COMP_ID_WINDOWS);
        assert_eq!(DbgengMode::X86.compiler_spec_id(), COMP_ID_WINDOWS);
    }

    #[test]
    fn test_pe_machine_type() {
        assert_eq!(PeMachineType::from_raw(0x8664), PeMachineType::AMD64);
        assert_eq!(PeMachineType::from_raw(0x014C), PeMachineType::I386);
        assert_eq!(PeMachineType::from_raw(0xAA64), PeMachineType::ARM64);
        assert_eq!(PeMachineType::from_raw(0x0000), PeMachineType::Unknown);
    }

    #[test]
    fn test_pe_machine_to_dbgeng_mode() {
        assert_eq!(
            PeMachineType::AMD64.to_dbgeng_mode(),
            DbgengMode::X64
        );
        assert_eq!(
            PeMachineType::I386.to_dbgeng_mode(),
            DbgengMode::X86
        );
        assert_eq!(
            PeMachineType::ARM64.to_dbgeng_mode(),
            DbgengMode::Unknown
        );
    }

    #[test]
    fn test_dbgeng_x64_inject() {
        let mut inject = DbgengX64DisassemblyInject::new();
        assert_eq!(inject.mode, DbgengMode::Unknown);
        assert!(!inject.is_64bit());

        inject.update_mode(DbgengMode::X64);
        assert!(inject.is_64bit());
    }

    #[test]
    fn test_pe_module_info() {
        let info = PeModuleInfo {
            name: "ntdll.dll".into(),
            base_address: 0x7FFE0000,
            is_64bit: true,
            machine_type: PeMachineType::AMD64,
            is_dll: true,
            image_size: 0x200000,
        };
        assert!(info.is_64bit);
        assert!(info.is_dll);
        assert_eq!(info.machine_type, PeMachineType::AMD64);
    }

    #[test]
    fn test_dbgeng_platform_opinion_64bit() {
        let opinion = DbgengPlatformOpinion;
        let context = OpinionContext {
            debugger_type: "dbgeng".into(),
            architecture: "x86_64".into(),
            os: "windows".into(),
            big_endian: false,
            pointer_size: 8,
            ..Default::default()
        };
        let results = opinion.get_opinions(&context);
        assert!(!results.is_empty());
        assert_eq!(results[0].language_id, LANG_ID_X86_64);
        assert_eq!(results[0].compiler_spec_id, COMP_ID_WINDOWS);
    }

    #[test]
    fn test_dbgeng_platform_opinion_32bit() {
        let opinion = DbgengPlatformOpinion;
        let context = OpinionContext {
            debugger_type: "dbgeng".into(),
            architecture: "x86".into(),
            os: "windows".into(),
            big_endian: false,
            pointer_size: 4,
            ..Default::default()
        };
        let results = opinion.get_opinions(&context);
        assert!(!results.is_empty());
        assert_eq!(results[0].language_id, LANG_ID_X86);
    }

    #[test]
    fn test_dbgeng_platform_opinion_no_match() {
        let opinion = DbgengPlatformOpinion;
        let context = OpinionContext {
            debugger_type: "gdb".into(),
            architecture: "x86_64".into(),
            os: "linux".into(),
            big_endian: false,
            pointer_size: 8,
            ..Default::default()
        };
        let results = opinion.get_opinions(&context);
        assert!(results.is_empty());
    }
}
