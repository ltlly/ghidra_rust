//! Emulation utility types and the emulation schema context.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.service.emulation` package.
//!
//! Provides:
//! - `EmulationMode`: Write flag for target-associated emulator states (RW/RO).
//! - `EmulatorOutOfMemoryException`: Error when the emulator cannot locate a
//!   suitable address in the trace's memory map.
//! - `ProgramEmulationUtils`: Constants and utilities for emulating programs
//!   without necessarily having a debugger connection, including the standard
//!   emulation schema context XML.
//! - `DefaultEmulatorFactory`: The default emulator factory.
//! - `DefaultPcodeDebuggerMemoryAccess`: Default memory access for pcode emulation.
//! - `DefaultPcodeDebuggerRegistersAccess`: Default register access for pcode emulation.

use serde::{Deserialize, Serialize};

use crate::target::schema_context::DefaultSchemaContext;

/// A write flag for target-associated emulator states.
///
/// Ported from Ghidra's `Mode` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EmulationMode {
    /// The state can write the target directly.
    Rw,
    /// The state will never write the target.
    Ro,
}

impl EmulationMode {
    /// Check if the mode permits writing the target.
    pub fn is_write_target(&self) -> bool {
        matches!(self, Self::Rw)
    }

    /// Whether this mode is read-only.
    pub fn is_read_only(&self) -> bool {
        matches!(self, Self::Ro)
    }
}

impl std::fmt::Display for EmulationMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rw => write!(f, "RW"),
            Self::Ro => write!(f, "RO"),
        }
    }
}

/// Some emulator-related operation was unable to locate a suitable address
/// in the trace's memory map.
///
/// Ported from Ghidra's `EmulatorOutOfMemoryException`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Emulator out of memory: no suitable address found in the trace memory map")]
pub struct EmulatorOutOfMemoryException;

/// Conventional block name for the emulated stack.
///
/// Ported from Ghidra's `EmulatorUtilities.BLOCK_NAME_STACK`.
pub const BLOCK_NAME_STACK: &str = "stack";

/// Conventional prefix for the first snapshot to identify "pure emulation" traces.
pub const EMULATION_STARTED_AT: &str = "Emulation started at ";

/// The standard emulation schema context XML.
///
/// Defines the schema tree used by the emulation system:
/// - `EmuSession`: The root session (Process + Aggregate).
/// - `BreakpointContainer` / `Breakpoint`: Breakpoints.
/// - `RegionContainer` / `Region`: Memory regions.
/// - `ModuleContainer` / `Module` / `SectionContainer` / `Section`: Modules and sections.
/// - `ThreadContainer` / `Thread`: Threads with Stack, Frame, Registers.
/// - `Stack` / `Frame`: Call stacks and stack frames.
/// - `RegisterContainer` / `Register`: Register values.
pub const EMU_CTX_XML: &str = r#"<context>
    <schema name="EmuSession">
        <interface name="Process" />
        <interface name="Aggregate" />
        <attribute name="Breakpoints" schema="BreakpointContainer" />
        <attribute name="Memory" schema="RegionContainer" />
        <attribute name="Modules" schema="ModuleContainer" />
        <attribute name="Threads" schema="ThreadContainer" />
    </schema>
    <schema name="BreakpointContainer" canonical="yes">
        <element schema="Breakpoint" />
    </schema>
    <schema name="Breakpoint">
        <interface name="BreakpointSpec" />
        <interface name="BreakpointLocation" />
    </schema>
    <schema name="RegionContainer" canonical="yes">
        <element schema="Region" />
    </schema>
    <schema name="Region">
        <interface name="MemoryRegion" />
    </schema>
    <schema name="ModuleContainer" canonical="yes">
        <element schema="Module" />
    </schema>
    <schema name="Module">
        <interface name="Module" />
        <attribute name="Sections" schema="SectionContainer" />
    </schema>
    <schema name="SectionContainer" canonical="yes">
        <element schema="Section" />
    </schema>
    <schema name="Section">
        <interface name="Section" />
    </schema>
    <schema name="ThreadContainer" canonical="yes">
        <element schema="Thread" />
    </schema>
    <schema name="Thread">
        <interface name="Thread" />
        <interface name="Activatable" />
        <interface name="Aggregate" />
        <attribute name="Stack" schema="Stack" />
        <attribute name="Registers" schema="RegisterContainer" />
    </schema>
    <schema name="Stack" canonical="yes">
        <interface name="Stack" />
        <element schema="Frame" />
    </schema>
    <schema name="Frame">
        <interface name="StackFrame" />
    </schema>
    <schema name="RegisterContainer" canonical="yes">
        <interface name="RegisterContainer" />
        <element schema="Register" />
    </schema>
    <schema name="Register">
        <interface name="Register" />
    </schema>
</context>"#;

/// Utilities for emulating programs without necessarily having a debugger connection.
///
/// Ported from Ghidra's `ProgramEmulationUtils`.
pub struct ProgramEmulationUtils;

impl ProgramEmulationUtils {
    /// Get the emulation schema context XML.
    pub fn emu_ctx_xml() -> &'static str {
        EMU_CTX_XML
    }

    /// Parse the emulation schema context.
    pub fn emu_ctx() -> Result<DefaultSchemaContext, String> {
        crate::target::schema_context::XmlSchemaContext::from_xml(EMU_CTX_XML)
    }

    /// Suggest a name for a new trace for emulation of the given program.
    ///
    /// Uses the program's domain file name or the program name.
    pub fn get_trace_name(program_name: &str) -> String {
        format!("Emulate {}", program_name)
    }

    /// Suggest the initial module name for loading a program into an emulated trace.
    ///
    /// Uses the executable path if available, otherwise the program name.
    pub fn get_module_name(program_name: &str, executable_path: Option<&str>) -> String {
        if let Some(path) = executable_path {
            return path.to_string();
        }
        program_name.to_string()
    }

    /// Get the schema name for the emulation session.
    pub fn emu_session_schema_name() -> &'static str {
        "EmuSession"
    }
}

/// The default emulator factory.
///
/// Ported from Ghidra's `DefaultEmulatorFactory`.
#[derive(Debug, Clone)]
pub struct DefaultEmulatorFactory {
    /// The title of this factory.
    pub title: String,
}

impl DefaultEmulatorFactory {
    /// The default title.
    pub const TITLE: &'static str = "Default Concrete P-code Emulator";

    /// Create a new default emulator factory.
    pub fn new() -> Self {
        Self {
            title: Self::TITLE.to_string(),
        }
    }

    /// Get the title.
    pub fn title(&self) -> &str {
        &self.title
    }
}

impl Default for DefaultEmulatorFactory {
    fn default() -> Self {
        Self::new()
    }
}

/// A default memory access implementation for pcode emulation.
///
/// Ported from Ghidra's `DefaultPcodeDebuggerMemoryAccess`.
#[derive(Debug, Clone)]
pub struct DefaultPcodeDebuggerMemoryAccess {
    /// The language ID for the emulation target.
    pub language_id: String,
    /// Whether writes are permitted.
    pub write_enabled: bool,
}

impl DefaultPcodeDebuggerMemoryAccess {
    /// Create a new default memory access.
    pub fn new(language_id: impl Into<String>) -> Self {
        Self {
            language_id: language_id.into(),
            write_enabled: true,
        }
    }

    /// Get the language ID.
    pub fn language_id(&self) -> &str {
        &self.language_id
    }

    /// Check if writes are enabled.
    pub fn is_write_enabled(&self) -> bool {
        self.write_enabled
    }

    /// Enable or disable writes.
    pub fn set_write_enabled(&mut self, enabled: bool) {
        self.write_enabled = enabled;
    }
}

/// A default register access implementation for pcode emulation.
///
/// Ported from Ghidra's `DefaultPcodeDebuggerRegistersAccess`.
#[derive(Debug, Clone)]
pub struct DefaultPcodeDebuggerRegistersAccess {
    /// The language ID for the emulation target.
    pub language_id: String,
}

impl DefaultPcodeDebuggerRegistersAccess {
    /// Create a new default register access.
    pub fn new(language_id: impl Into<String>) -> Self {
        Self {
            language_id: language_id.into(),
        }
    }

    /// Get the language ID.
    pub fn language_id(&self) -> &str {
        &self.language_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulation_mode_rw() {
        let mode = EmulationMode::Rw;
        assert!(mode.is_write_target());
        assert!(!mode.is_read_only());
        assert_eq!(mode.to_string(), "RW");
    }

    #[test]
    fn test_emulation_mode_ro() {
        let mode = EmulationMode::Ro;
        assert!(!mode.is_write_target());
        assert!(mode.is_read_only());
        assert_eq!(mode.to_string(), "RO");
    }

    #[test]
    fn test_emulation_mode_serde() {
        let mode = EmulationMode::Rw;
        let json = serde_json::to_string(&mode).unwrap();
        let back: EmulationMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, EmulationMode::Rw);
    }

    #[test]
    fn test_emulator_out_of_memory_display() {
        let err = EmulatorOutOfMemoryException;
        assert!(err.to_string().contains("no suitable address"));
    }

    #[test]
    fn test_constants() {
        assert_eq!(BLOCK_NAME_STACK, "stack");
        assert!(EMULATION_STARTED_AT.starts_with("Emulation"));
    }

    #[test]
    fn test_program_emulation_utils_trace_name() {
        let name = ProgramEmulationUtils::get_trace_name("test_binary");
        assert_eq!(name, "Emulate test_binary");
    }

    #[test]
    fn test_program_emulation_utils_module_name() {
        let name = ProgramEmulationUtils::get_module_name("prog", Some("/usr/bin/prog"));
        assert_eq!(name, "/usr/bin/prog");

        let name = ProgramEmulationUtils::get_module_name("prog", None);
        assert_eq!(name, "prog");
    }

    #[test]
    fn test_program_emulation_utils_schema_name() {
        assert_eq!(
            ProgramEmulationUtils::emu_session_schema_name(),
            "EmuSession"
        );
    }

    #[test]
    fn test_program_emulation_utils_ctx_xml() {
        let xml = ProgramEmulationUtils::emu_ctx_xml();
        assert!(xml.contains("EmuSession"));
        assert!(xml.contains("ThreadContainer"));
        assert!(xml.contains("RegisterContainer"));
    }

    #[test]
    fn test_program_emulation_utils_parse_ctx() {
        let ctx = ProgramEmulationUtils::emu_ctx();
        assert!(ctx.is_ok(), "Failed to parse emulation context: {:?}", ctx.err());
        let ctx = ctx.unwrap();
        assert!(ctx.has_schema(&crate::model::target_schema::SchemaName::new("EmuSession")));
        assert!(ctx.has_schema(&crate::model::target_schema::SchemaName::new("Thread")));
        assert!(ctx.has_schema(&crate::model::target_schema::SchemaName::new("Register")));
    }

    #[test]
    fn test_default_emulator_factory() {
        let factory = DefaultEmulatorFactory::new();
        assert_eq!(factory.title(), DefaultEmulatorFactory::TITLE);
    }

    #[test]
    fn test_default_emulator_factory_default() {
        let factory = DefaultEmulatorFactory::default();
        assert_eq!(factory.title(), "Default Concrete P-code Emulator");
    }

    #[test]
    fn test_default_pcode_memory_access() {
        let mut access = DefaultPcodeDebuggerMemoryAccess::new("x86:LE:64:default");
        assert_eq!(access.language_id(), "x86:LE:64:default");
        assert!(access.is_write_enabled());

        access.set_write_enabled(false);
        assert!(!access.is_write_enabled());
    }

    #[test]
    fn test_default_pcode_registers_access() {
        let access = DefaultPcodeDebuggerRegistersAccess::new("ARM:LE:32:v8");
        assert_eq!(access.language_id(), "ARM:LE:32:v8");
    }
}
