//! Program emulation utilities.
//!
//! Ported from Ghidra's `ProgramEmulationUtils` (725 lines).
//!
//! Utilities for emulating programs without necessarily having a debugger
//! connection. These are integrated via the DebuggerEmulationService.

use serde::{Deserialize, Serialize};

use crate::model::TraceExecutionState;

/// The emulation context XML schema for creating emu sessions.
pub const EMU_CTX_XML: &str = r#"<context>
    <schema name='EmuSession' elementResync='NEVER' attributeResync='NEVER'>
        <interface name='Process' />
        <interface name='Aggregate' />
        <attribute name='Breakpoints' schema='BreakpointContainer' />
        <attribute name='Memory' schema='RegionContainer' />
        <attribute name='Modules' schema='ModuleContainer' />
        <attribute name='Threads' schema='ThreadContainer' />
    </schema>
    <schema name='BreakpointContainer' canonical='yes' elementResync='NEVER'
            attributeResync='NEVER'>
        <element schema='Breakpoint' />
    </schema>
    <schema name='Breakpoint' elementResync='NEVER' attributeResync='NEVER'>
        <interface name='BreakpointSpec' />
        <interface name='BreakpointLocation' />
    </schema>
    <schema name='RegionContainer' canonical='yes' elementResync='NEVER'
            attributeResync='NEVER'>
        <element schema='Region' />
    </schema>
    <schema name='Region' elementResync='NEVER' attributeResync='NEVER'>
        <interface name='MemoryRegion' />
    </schema>
    <schema name='ModuleContainer' canonical='yes' elementResync='NEVER'
            attributeResync='NEVER'>
        <element schema='Module' />
    </schema>
    <schema name='Module' elementResync='NEVER' attributeResync='NEVER'>
        <interface name='Module' />
        <attribute name='Sections' schema='SectionContainer' />
    </schema>
    <schema name='SectionContainer' canonical='yes' elementResync='NEVER'
            attributeResync='NEVER'>
        <element schema='Section' />
    </schema>
    <schema name='Section' elementResync='NEVER' attributeResync='NEVER'>
        <interface name='Section' />
    </schema>
    <schema name='ThreadContainer' canonical='yes' elementResync='NEVER'
            attributeResync='NEVER'>
        <element schema='Thread' />
    </schema>
    <schema name='Thread' elementResync='NEVER' attributeResync='NEVER'>
        <interface name='Thread' />
        <interface name='ExecutionStateful' />
    </schema>
</context>"#;

/// The name of the emulation stack memory block.
pub const BLOCK_NAME_STACK: &str = "emu_stack";

/// The attribute name for the emulation start address.
pub const EMULATION_STARTED_AT: &str = "EmulationStartedAt";

/// Memory block information for an emulated program.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationMemoryBlock {
    /// The block name.
    pub name: String,
    /// Start address.
    pub start_address: u64,
    /// Size in bytes.
    pub size: u64,
    /// Whether the block is readable.
    pub readable: bool,
    /// Whether the block is writable.
    pub writable: bool,
    /// Whether the block is executable.
    pub executable: bool,
    /// The initial bytes (if any).
    pub initial_bytes: Option<Vec<u8>>,
}

impl EmulationMemoryBlock {
    /// Create a new memory block.
    pub fn new(
        name: impl Into<String>,
        start_address: u64,
        size: u64,
        readable: bool,
        writable: bool,
        executable: bool,
    ) -> Self {
        Self {
            name: name.into(),
            start_address,
            size,
            readable,
            writable,
            executable,
            initial_bytes: None,
        }
    }

    /// Create an initialized block.
    pub fn initialized(
        name: impl Into<String>,
        start_address: u64,
        bytes: Vec<u8>,
        readable: bool,
        writable: bool,
        executable: bool,
    ) -> Self {
        let size = bytes.len() as u64;
        Self {
            name: name.into(),
            start_address,
            size,
            readable,
            writable,
            executable,
            initial_bytes: Some(bytes),
        }
    }

    /// The end address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.start_address + self.size
    }

    /// Whether an address falls within this block.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start_address && address < self.end_address()
    }
}

/// A register definition for emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationRegister {
    /// Register name.
    pub name: String,
    /// Register offset in the register space.
    pub offset: u64,
    /// Register size in bytes.
    pub size: usize,
    /// Initial value (if any).
    pub initial_value: Option<Vec<u8>>,
}

impl EmulationRegister {
    /// Create a new register definition.
    pub fn new(name: impl Into<String>, offset: u64, size: usize) -> Self {
        Self {
            name: name.into(),
            offset,
            size,
            initial_value: None,
        }
    }

    /// Set the initial value.
    pub fn with_initial_value(mut self, value: Vec<u8>) -> Self {
        self.initial_value = Some(value);
        self
    }
}

/// A snapshot in an emulation session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationSnapshot {
    /// The snap number.
    pub snap: i64,
    /// The execution state at this snap.
    pub execution_state: TraceExecutionState,
    /// The program counter value at this snap.
    pub pc: Option<u64>,
    /// Thread ID associated with this snapshot.
    pub thread_id: Option<i64>,
    /// A description of the event that caused this snapshot.
    pub event_description: Option<String>,
}

impl EmulationSnapshot {
    /// Create a new snapshot.
    pub fn new(snap: i64, execution_state: TraceExecutionState) -> Self {
        Self {
            snap,
            execution_state,
            pc: None,
            thread_id: None,
            event_description: None,
        }
    }

    /// Set the program counter.
    pub fn with_pc(mut self, pc: u64) -> Self {
        self.pc = Some(pc);
        self
    }

    /// Set the thread ID.
    pub fn with_thread_id(mut self, thread_id: i64) -> Self {
        self.thread_id = Some(thread_id);
        self
    }

    /// Set an event description.
    pub fn with_event(mut self, description: impl Into<String>) -> Self {
        self.event_description = Some(description.into());
        self
    }
}

/// Configuration for setting up a program emulation session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationConfig {
    /// The language ID (architecture).
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// Memory blocks to create.
    pub memory_blocks: Vec<EmulationMemoryBlock>,
    /// Registers to initialize.
    pub registers: Vec<EmulationRegister>,
    /// The entry point address.
    pub entry_point: Option<u64>,
    /// The stack base address.
    pub stack_base: Option<u64>,
    /// The stack size.
    pub stack_size: Option<u64>,
    /// Maximum number of emulation steps.
    pub max_steps: Option<u64>,
}

impl EmulationConfig {
    /// Create a new emulation config.
    pub fn new(
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            memory_blocks: Vec::new(),
            registers: Vec::new(),
            entry_point: None,
            stack_base: None,
            stack_size: None,
            max_steps: None,
        }
    }

    /// Add a memory block.
    pub fn add_memory_block(&mut self, block: EmulationMemoryBlock) {
        self.memory_blocks.push(block);
    }

    /// Add a register.
    pub fn add_register(&mut self, register: EmulationRegister) {
        self.registers.push(register);
    }

    /// Set the entry point.
    pub fn with_entry_point(mut self, address: u64) -> Self {
        self.entry_point = Some(address);
        self
    }

    /// Configure a stack.
    pub fn with_stack(mut self, base: u64, size: u64) -> Self {
        self.stack_base = Some(base);
        self.stack_size = Some(size);
        self
    }

    /// Set maximum steps.
    pub fn with_max_steps(mut self, max: u64) -> Self {
        self.max_steps = Some(max);
        self
    }

    /// Get the stack memory block name.
    pub fn stack_block_name(&self) -> &str {
        BLOCK_NAME_STACK
    }
}

/// Represents the result of a program emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationResult {
    /// The final execution state.
    pub state: TraceExecutionState,
    /// The number of steps executed.
    pub steps_executed: u64,
    /// All snapshots taken during emulation.
    pub snapshots: Vec<EmulationSnapshot>,
    /// Error message, if any.
    pub error: Option<String>,
    /// The final program counter.
    pub final_pc: Option<u64>,
}

impl EmulationResult {
    /// Create a successful result.
    pub fn success(steps: u64, final_pc: u64) -> Self {
        Self {
            state: TraceExecutionState::Stopped,
            steps_executed: steps,
            snapshots: Vec::new(),
            error: None,
            final_pc: Some(final_pc),
        }
    }

    /// Create an error result.
    pub fn error(steps: u64, error: impl Into<String>) -> Self {
        Self {
            state: TraceExecutionState::Stopped,
            steps_executed: steps,
            snapshots: Vec::new(),
            error: Some(error.into()),
            final_pc: None,
        }
    }

    /// Whether the emulation completed successfully.
    pub fn is_success(&self) -> bool {
        self.error.is_none()
    }
}

/// Trait for program emulation engines.
pub trait ProgramEmulator {
    /// Initialize the emulator with the given configuration.
    fn initialize(&mut self, config: &EmulationConfig) -> Result<(), String>;

    /// Execute one step.
    fn step(&mut self) -> Result<EmulationSnapshot, String>;

    /// Execute multiple steps.
    fn step_n(&mut self, n: u64) -> Result<Vec<EmulationSnapshot>, String>;

    /// Run until a breakpoint or termination.
    fn run(&mut self) -> Result<EmulationResult, String>;

    /// Read memory at the given address.
    fn read_memory(&self, address: u64, length: usize) -> Result<Vec<u8>, String>;

    /// Write memory at the given address.
    fn write_memory(&mut self, address: u64, data: &[u8]) -> Result<(), String>;

    /// Read a register value.
    fn read_register(&self, name: &str) -> Result<Vec<u8>, String>;

    /// Write a register value.
    fn write_register(&mut self, name: &str, value: &[u8]) -> Result<(), String>;

    /// Get the current program counter.
    fn program_counter(&self) -> Result<u64, String>;

    /// Get the current execution state.
    fn execution_state(&self) -> TraceExecutionState;

    /// Get the number of steps executed.
    fn steps_executed(&self) -> u64;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulation_memory_block() {
        let block = EmulationMemoryBlock::new(".text", 0x401000, 0x1000, true, false, true);
        assert_eq!(block.name, ".text");
        assert!(block.contains(0x401000));
        assert!(block.contains(0x401FFF));
        assert!(!block.contains(0x402000));
        assert_eq!(block.end_address(), 0x402000);
    }

    #[test]
    fn test_emulation_memory_block_initialized() {
        let bytes = vec![0x90, 0xC3]; // NOP, RET
        let block = EmulationMemoryBlock::initialized(".text", 0x400000, bytes, true, false, true);
        assert_eq!(block.size, 2);
        assert!(block.initial_bytes.is_some());
    }

    #[test]
    fn test_emulation_register() {
        let reg = EmulationRegister::new("EAX", 0, 4).with_initial_value(vec![0, 0, 0, 0]);
        assert_eq!(reg.name, "EAX");
        assert_eq!(reg.size, 4);
        assert!(reg.initial_value.is_some());
    }

    #[test]
    fn test_emulation_snapshot() {
        let snap = EmulationSnapshot::new(0, TraceExecutionState::Running)
            .with_pc(0x401000)
            .with_thread_id(1)
            .with_event("step");

        assert_eq!(snap.snap, 0);
        assert_eq!(snap.pc, Some(0x401000));
        assert_eq!(snap.thread_id, Some(1));
    }

    #[test]
    fn test_emulation_config() {
        let config = EmulationConfig::new("x86:LE:64:default", "default")
            .with_entry_point(0x401000)
            .with_stack(0x7FFF0000, 0x10000)
            .with_max_steps(1000);

        assert_eq!(config.entry_point, Some(0x401000));
        assert_eq!(config.stack_base, Some(0x7FFF0000));
        assert_eq!(config.stack_size, Some(0x10000));
        assert_eq!(config.max_steps, Some(1000));
    }

    #[test]
    fn test_emulation_config_blocks_and_registers() {
        let mut config = EmulationConfig::new("ARM:LE:32:v7", "default");
        config.add_memory_block(EmulationMemoryBlock::new(".text", 0x8000, 0x1000, true, false, true));
        config.add_register(EmulationRegister::new("R0", 0, 4));

        assert_eq!(config.memory_blocks.len(), 1);
        assert_eq!(config.registers.len(), 1);
    }

    #[test]
    fn test_emulation_result() {
        let result = EmulationResult::success(100, 0x401050);
        assert!(result.is_success());
        assert_eq!(result.steps_executed, 100);
        assert_eq!(result.final_pc, Some(0x401050));

        let err_result = EmulationResult::error(50, "segfault");
        assert!(!err_result.is_success());
        assert_eq!(err_result.error, Some("segfault".into()));
    }

    #[test]
    fn test_emu_ctx_xml_not_empty() {
        assert!(!EMU_CTX_XML.is_empty());
        assert!(EMU_CTX_XML.contains("EmuSession"));
        assert!(EMU_CTX_XML.contains("Thread"));
    }

    #[test]
    fn test_constants() {
        assert_eq!(BLOCK_NAME_STACK, "emu_stack");
        assert_eq!(EMULATION_STARTED_AT, "EmulationStartedAt");
    }
}
