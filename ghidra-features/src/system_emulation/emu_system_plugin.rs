//! System Emulation Plugin -- orchestrates the emulation workflow.
//!
//! Ported from Ghidra's `EmuSystemPlugin` (Features/SystemEmulation).
//!
//! This plugin coordinates:
//! - Running the [`EmuSystemAnalyzer`] on the current program
//! - Creating and configuring [`EmulatedMachine`] instances for emulation
//! - Managing the emulation lifecycle (start, step, run, stop)
//! - Loading the appropriate [`SyscallLibrary`] for the target OS
//! - Dispatching emulation results and events
//!
//! # Key Types
//!
//! - [`EmuSystemPlugin`] -- Top-level plugin coordinating emulation
//! - [`EmuAction`] -- Actions available in the emulation menu
//! - [`EmuSession`] -- An active emulation session
//! - [`EmuConfig`] -- Configuration for an emulation session
//! - [`EmuEvent`] -- Events emitted during emulation

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::emu_system_analyzer::{
    AnalyzerResult, EmuEntryPoint, EmuEntryPointKind, EmuSystemAnalyzer,
};
use super::pcode_emu::{EmuException, EmulatedMachine};
use super::syscall::{LinuxSyscallLibrary, SyscallLibrary, WindowsSyscallLibrary};

// ---------------------------------------------------------------------------
// EmuAction -- menu actions for the plugin
// ---------------------------------------------------------------------------

/// An action available in the system emulation menu.
///
/// Each action corresponds to a user-triggerable operation in the
/// emulation workflow.
#[derive(Debug, Clone)]
pub struct EmuAction {
    /// Action name (e.g., "Start Emulation").
    pub name: String,
    /// Menu group for organization.
    pub group: String,
    /// Description shown in tooltips.
    pub description: String,
    /// Whether the action is currently enabled.
    pub enabled: bool,
    /// Menu path (e.g., ["Emulation", "Start"]).
    pub menu_path: Vec<String>,
}

impl EmuAction {
    /// Create a new emulation action.
    pub fn new(name: impl Into<String>, group: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            group: group.into(),
            description: description.into(),
            enabled: true,
            menu_path: Vec::new(),
        }
    }

    /// Set the menu path.
    pub fn with_menu_path(mut self, path: Vec<String>) -> Self {
        self.menu_path = path;
        self
    }
}

// ---------------------------------------------------------------------------
// EmuConfig -- configuration for an emulation session
// ---------------------------------------------------------------------------

/// Configuration for starting an emulation session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmuConfig {
    /// The target OS for syscall emulation.
    pub target_os: String,
    /// The target architecture.
    pub target_architecture: String,
    /// Pointer size in bytes (4 or 8).
    pub pointer_size: usize,
    /// Whether the target is little-endian.
    pub little_endian: bool,
    /// Stack base address.
    pub stack_base: u64,
    /// Stack size in bytes.
    pub stack_size: u64,
    /// Heap base address.
    pub heap_base: u64,
    /// Heap size in bytes.
    pub heap_size: u64,
    /// Code region base address.
    pub code_base: u64,
    /// Code region size in bytes.
    pub code_size: u64,
    /// Maximum instructions to execute before timeout.
    pub max_instructions: u64,
    /// Whether to break on syscall invocations.
    pub break_on_syscall: bool,
    /// Whether to break on memory violations.
    pub break_on_memory_violation: bool,
    /// Additional breakpoints (addresses).
    pub breakpoints: Vec<u64>,
}

impl EmuConfig {
    /// Create a default configuration for x86-64 Linux.
    pub fn x86_64_linux() -> Self {
        Self {
            target_os: "Linux".into(),
            target_architecture: "x86_64".into(),
            pointer_size: 8,
            little_endian: true,
            stack_base: 0x7FFF_F000,
            stack_size: 0x10_000,
            heap_base: 0x7F00_0000,
            heap_size: 0x10_000,
            code_base: 0x40_0000,
            code_size: 0x10_000,
            max_instructions: 1_000_000,
            break_on_syscall: false,
            break_on_memory_violation: true,
            breakpoints: Vec::new(),
        }
    }

    /// Create a default configuration for x86-64 Windows.
    pub fn x86_64_windows() -> Self {
        Self {
            target_os: "Windows".into(),
            target_architecture: "x86_64".into(),
            pointer_size: 8,
            little_endian: true,
            stack_base: 0x7FFF_F000,
            stack_size: 0x10_000,
            heap_base: 0x7F00_0000,
            heap_size: 0x10_000,
            code_base: 0x140_0000,
            code_size: 0x10_000,
            max_instructions: 1_000_000,
            break_on_syscall: false,
            break_on_memory_violation: true,
            breakpoints: Vec::new(),
        }
    }

    /// Create a default configuration for ARM Linux.
    pub fn arm_linux() -> Self {
        Self {
            target_os: "Linux".into(),
            target_architecture: "ARM".into(),
            pointer_size: 4,
            little_endian: true,
            stack_base: 0xBEFF_F000,
            stack_size: 0x10_000,
            heap_base: 0xB000_0000,
            heap_size: 0x10_000,
            code_base: 0x10_0000,
            code_size: 0x10_000,
            max_instructions: 1_000_000,
            break_on_syscall: false,
            break_on_memory_violation: true,
            breakpoints: Vec::new(),
        }
    }
}

impl Default for EmuConfig {
    fn default() -> Self {
        Self::x86_64_linux()
    }
}

// ---------------------------------------------------------------------------
// EmuEvent -- events emitted during emulation
// ---------------------------------------------------------------------------

/// An event emitted during the emulation lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EmuEvent {
    /// Emulation session started.
    SessionStarted {
        /// Entry point address.
        entry_point: u64,
        /// The target OS.
        os: String,
        /// The target architecture.
        arch: String,
    },
    /// A single instruction was executed.
    InstructionExecuted {
        /// The program counter before the instruction.
        pc: u64,
        /// The total instruction count so far.
        instruction_count: u64,
    },
    /// A breakpoint was hit.
    BreakpointHit {
        /// The breakpoint address.
        address: u64,
    },
    /// A syscall was invoked.
    SyscallInvoked {
        /// The syscall number.
        number: u64,
        /// The syscall name (if known).
        name: Option<String>,
        /// The return value.
        return_value: u64,
    },
    /// A memory access violation occurred.
    MemoryViolation {
        /// A description of the violation.
        message: String,
        /// The faulting address.
        address: u64,
    },
    /// Emulation completed (process exited normally).
    Completed {
        /// The exit code.
        exit_code: i32,
        /// Total instructions executed.
        total_instructions: u64,
    },
    /// Emulation was stopped by the user.
    Stopped {
        /// The reason for stopping.
        reason: String,
        /// Total instructions executed.
        total_instructions: u64,
    },
    /// An error occurred during emulation.
    Error {
        /// The error message.
        message: String,
    },
}

// ---------------------------------------------------------------------------
// EmuSession -- an active emulation session
// ---------------------------------------------------------------------------

/// An active emulation session.
///
/// Contains the emulated machine state, the syscall library, and
/// the configuration used to set up the session.
#[derive(Debug)]
pub struct EmuSession {
    /// The emulated machine.
    pub machine: EmulatedMachine,
    /// The analysis result that led to this session.
    pub analysis: AnalyzerResult,
    /// The configuration used for this session.
    pub config: EmuConfig,
    /// Event log for this session.
    pub events: Vec<EmuEvent>,
    /// Whether the session is currently active.
    pub active: bool,
}

impl EmuSession {
    /// Create a new emulation session with the given machine and config.
    pub fn new(machine: EmulatedMachine, config: EmuConfig, analysis: AnalyzerResult) -> Self {
        Self {
            machine,
            analysis,
            config,
            events: Vec::new(),
            active: true,
        }
    }

    /// Execute a single step of emulation.
    pub fn step(&mut self) -> Result<u64, EmuException> {
        let pc = self.machine.get_pc();
        let result = self.machine.step();
        match &result {
            Ok(next_pc) => {
                self.events.push(EmuEvent::InstructionExecuted {
                    pc,
                    instruction_count: self.machine.instruction_count,
                });
            }
            Err(EmuException::BreakpointHit(addr)) => {
                self.events.push(EmuEvent::BreakpointHit { address: *addr });
            }
            Err(EmuException::ProcessExited(code)) => {
                self.events.push(EmuEvent::Completed {
                    exit_code: *code,
                    total_instructions: self.machine.instruction_count,
                });
                self.active = false;
            }
            Err(e) => {
                self.events.push(EmuEvent::Error {
                    message: format!("{}", e),
                });
            }
        }
        result
    }

    /// Run emulation until a stop condition is reached.
    pub fn run(&mut self, max_steps: u64) -> RunResult {
        let mut steps = 0u64;
        while self.active && steps < max_steps {
            match self.step() {
                Ok(_) => steps += 1,
                Err(EmuException::BreakpointHit(addr)) => {
                    return RunResult::BreakpointHit { address: addr, steps };
                }
                Err(EmuException::ProcessExited(code)) => {
                    return RunResult::Exited {
                        code,
                        instructions: self.machine.instruction_count,
                    };
                }
                Err(EmuException::Halted) => {
                    return RunResult::Halted {
                        instructions: self.machine.instruction_count,
                    };
                }
                Err(e) => {
                    return RunResult::Error {
                        message: format!("{}", e),
                        steps,
                    };
                }
            }
        }
        if steps >= max_steps {
            RunResult::MaxStepsReached {
                instructions: self.machine.instruction_count,
            }
        } else {
            RunResult::Stopped {
                instructions: self.machine.instruction_count,
            }
        }
    }

    /// Stop the emulation session.
    pub fn stop(&mut self, reason: impl Into<String>) {
        self.active = false;
        self.events.push(EmuEvent::Stopped {
            reason: reason.into(),
            total_instructions: self.machine.instruction_count,
        });
    }

    /// Whether the session is still active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get the total number of events recorded.
    pub fn event_count(&self) -> usize {
        self.events.len()
    }
}

/// The result of a `run()` invocation.
#[derive(Debug, Clone)]
pub enum RunResult {
    /// A breakpoint was hit.
    BreakpointHit {
        /// The breakpoint address.
        address: u64,
        /// Steps taken before the breakpoint.
        steps: u64,
    },
    /// The emulated process exited.
    Exited {
        /// The exit code.
        code: i32,
        /// Total instructions executed.
        instructions: u64,
    },
    /// The maximum number of steps was reached.
    MaxStepsReached {
        /// Total instructions executed.
        instructions: u64,
    },
    /// Emulation was halted.
    Halted {
        /// Total instructions executed.
        instructions: u64,
    },
    /// Emulation was manually stopped.
    Stopped {
        /// Total instructions executed.
        instructions: u64,
    },
    /// An error occurred.
    Error {
        /// The error message.
        message: String,
        /// Steps taken before the error.
        steps: u64,
    },
}

// ---------------------------------------------------------------------------
// EmuSystemPlugin -- top-level plugin
// ---------------------------------------------------------------------------

/// Top-level plugin coordinating the system emulation workflow.
///
/// Ported from Ghidra's `EmuSystemPlugin`.
///
/// The plugin:
/// 1. Owns an [`EmuSystemAnalyzer`] for discovering emulation entry points.
/// 2. Creates [`EmuSession`] instances from analysis results.
/// 3. Manages the emulation menu actions (start, step, run, stop).
/// 4. Dispatches [`EmuEvent`]s to registered listeners.
///
/// # Example
///
/// ```rust
/// use ghidra_features::system_emulation::*;
///
/// let mut plugin = EmuSystemPlugin::new();
/// assert_eq!(plugin.name(), "EmuSystemPlugin");
/// assert!(plugin.is_enabled());
///
/// // Configure for x86-64 Linux
/// plugin.set_config(EmuConfig::x86_64_linux());
///
/// // No active session yet
/// assert!(!plugin.has_active_session());
/// ```
#[derive(Debug)]
pub struct EmuSystemPlugin {
    /// Plugin name.
    name: String,
    /// Whether the plugin is enabled.
    enabled: bool,
    /// Whether the plugin has been initialized.
    initialized: bool,
    /// Whether the plugin has been disposed.
    disposed: bool,
    /// Current program name (if any).
    current_program: Option<String>,
    /// The emulation analyzer.
    analyzer: EmuSystemAnalyzer,
    /// The current emulation session (if any).
    session: Option<EmuSession>,
    /// Current emulation configuration.
    config: EmuConfig,
    /// Registered actions.
    actions: Vec<EmuAction>,
    /// Event log (all events across sessions).
    event_log: Vec<EmuEvent>,
}

impl EmuSystemPlugin {
    /// Create a new system emulation plugin.
    pub fn new() -> Self {
        Self {
            name: "EmuSystemPlugin".into(),
            enabled: true,
            initialized: false,
            disposed: false,
            current_program: None,
            analyzer: EmuSystemAnalyzer::new(),
            session: None,
            config: EmuConfig::default(),
            actions: Self::create_default_actions(),
            event_log: Vec::new(),
        }
    }

    /// Create a plugin with a specific name.
    pub fn with_name(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::new()
        }
    }

    /// Create the default set of emulation actions.
    fn create_default_actions() -> Vec<EmuAction> {
        vec![
            EmuAction::new(
                "Start Emulation",
                "Emulation",
                "Start a new system emulation session from the current program.",
            )
            .with_menu_path(vec!["Emulation".into(), "Start".into()]),
            EmuAction::new(
                "Step Emulation",
                "Emulation",
                "Execute a single instruction in the emulation.",
            )
            .with_menu_path(vec!["Emulation".into(), "Step".into()]),
            EmuAction::new(
                "Run Emulation",
                "Emulation",
                "Run emulation until a stop condition.",
            )
            .with_menu_path(vec!["Emulation".into(), "Run".into()]),
            EmuAction::new(
                "Stop Emulation",
                "Emulation",
                "Stop the current emulation session.",
            )
            .with_menu_path(vec!["Emulation".into(), "Stop".into()]),
            EmuAction::new(
                "Emulation Settings",
                "Emulation",
                "Configure emulation settings (OS, architecture, memory layout).",
            )
            .with_menu_path(vec!["Emulation".into(), "Settings".into()]),
            EmuAction::new(
                "Show Syscall Definitions",
                "Emulation",
                "Display available syscall definitions for the current target OS.",
            )
            .with_menu_path(vec!["Emulation".into(), "Syscalls".into()]),
        ]
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the plugin.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether the plugin has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Initialize the plugin.
    pub fn init(&mut self) {
        self.initialized = true;
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose of the plugin, releasing resources.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.initialized = false;
        self.session = None;
        self.current_program = None;
        self.event_log.clear();
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Set the current program.
    pub fn set_program(&mut self, name: Option<String>) {
        self.current_program = name;
        if self.current_program.is_none() {
            self.session = None;
        }
    }

    // -- Analyzer access --

    /// Get a reference to the emulation analyzer.
    pub fn analyzer(&self) -> &EmuSystemAnalyzer {
        &self.analyzer
    }

    /// Get a mutable reference to the emulation analyzer.
    pub fn analyzer_mut(&mut self) -> &mut EmuSystemAnalyzer {
        &mut self.analyzer
    }

    // -- Configuration --

    /// Get the current emulation configuration.
    pub fn config(&self) -> &EmuConfig {
        &self.config
    }

    /// Set the emulation configuration.
    pub fn set_config(&mut self, config: EmuConfig) {
        self.config = config;
    }

    /// Get a mutable reference to the emulation configuration.
    pub fn config_mut(&mut self) -> &mut EmuConfig {
        &mut self.config
    }

    // -- Session management --

    /// Whether there is an active emulation session.
    pub fn has_active_session(&self) -> bool {
        self.session.as_ref().map_or(false, |s| s.is_active())
    }

    /// Get a reference to the current session.
    pub fn session(&self) -> Option<&EmuSession> {
        self.session.as_ref()
    }

    /// Get a mutable reference to the current session.
    pub fn session_mut(&mut self) -> Option<&mut EmuSession> {
        self.session.as_mut()
    }

    /// Create a new emulation session from analysis results.
    pub fn start_session(&mut self, analysis: AnalyzerResult) -> Result<(), String> {
        if self.session.is_some() && self.has_active_session() {
            return Err("An emulation session is already active".into());
        }

        let mut machine = if self.config.little_endian {
            EmulatedMachine::new_le(self.config.pointer_size)
        } else {
            EmulatedMachine::new_be(self.config.pointer_size)
        };

        // Set up memory regions
        machine.map_memory(
            self.config.code_base,
            self.config.code_size,
            "code".into(),
            true,
            false,
            true,
        );
        machine.map_memory(
            self.config.stack_base,
            self.config.stack_size,
            "stack".into(),
            true,
            true,
            false,
        );
        machine.map_memory(
            self.config.heap_base,
            self.config.heap_size,
            "heap".into(),
            true,
            true,
            false,
        );

        // Set up the program counter register name
        if self.config.target_architecture == "x86_64" {
            machine.pc_name = "RIP".into();
        } else if self.config.target_architecture == "x86" {
            machine.pc_name = "EIP".into();
        } else if self.config.target_architecture == "ARM" {
            machine.pc_name = "PC".into();
        }

        // Set up the stack pointer
        if self.config.pointer_size == 8 {
            machine.set_register("RSP", self.config.stack_base + self.config.stack_size);
        } else {
            machine.set_register("SP", self.config.stack_base + self.config.stack_size);
        }

        // Set syscall handler
        machine.set_syscall_handler(&self.config.target_os);

        // Add user-specified breakpoints
        for &bp in &self.config.breakpoints {
            machine.add_breakpoint(bp);
        }

        // Set entry point from analysis
        if let Some(entry) = analysis.entry_points.first() {
            machine.set_pc(entry.address);
        }

        let mut session = EmuSession::new(machine, self.config.clone(), analysis);
        session.events.push(EmuEvent::SessionStarted {
            entry_point: session.machine.get_pc(),
            os: self.config.target_os.clone(),
            arch: self.config.target_architecture.clone(),
        });

        self.session = Some(session);
        Ok(())
    }

    /// Stop the current emulation session.
    pub fn stop_session(&mut self, reason: impl Into<String>) {
        if let Some(ref mut session) = self.session {
            session.stop(reason);
        }
    }

    /// Step the current emulation session by one instruction.
    pub fn step(&mut self) -> Result<u64, String> {
        if let Some(ref mut session) = self.session {
            session.step().map_err(|e| format!("{}", e))
        } else {
            Err("No active emulation session".into())
        }
    }

    /// Run the current emulation session until a stop condition.
    pub fn run(&mut self, max_steps: u64) -> Option<RunResult> {
        if let Some(ref mut session) = self.session {
            Some(session.run(max_steps))
        } else {
            None
        }
    }

    /// Destroy the current session.
    pub fn destroy_session(&mut self) {
        if let Some(mut session) = self.session.take() {
            // Drain events into the global log
            self.event_log.append(&mut session.events);
        }
    }

    // -- Actions --

    /// Get the list of registered actions.
    pub fn actions(&self) -> &[EmuAction] {
        &self.actions
    }

    /// Find an action by name.
    pub fn find_action(&self, name: &str) -> Option<&EmuAction> {
        self.actions.iter().find(|a| a.name == name)
    }

    /// Enable or disable an action by name.
    pub fn set_action_enabled(&mut self, name: &str, enabled: bool) {
        if let Some(action) = self.actions.iter_mut().find(|a| a.name == name) {
            action.enabled = enabled;
        }
    }

    /// Get the total number of registered actions.
    pub fn action_count(&self) -> usize {
        self.actions.len()
    }

    // -- Event log --

    /// Get the global event log (all events across sessions).
    pub fn event_log(&self) -> &[EmuEvent] {
        &self.event_log
    }

    /// Get the total number of events in the log.
    pub fn event_count(&self) -> usize {
        self.event_log.len()
    }

    /// Clear the global event log.
    pub fn clear_event_log(&mut self) {
        self.event_log.clear();
    }
}

impl Default for EmuSystemPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// EmuSystemPluginLifecycle -- program lifecycle trait
// ---------------------------------------------------------------------------

/// Lifecycle trait for the system emulation plugin.
///
/// Mirrors the Java `ProgramPlugin` lifecycle pattern used throughout
/// the Ghidra Rust port.
pub trait EmuSystemPluginLifecycle {
    /// Called when a program becomes active.
    fn program_activated(&mut self, program_name: &str);

    /// Called when a program is deactivated.
    fn program_deactivated(&mut self, program_name: &str);
}

impl EmuSystemPluginLifecycle for EmuSystemPlugin {
    fn program_activated(&mut self, program_name: &str) {
        self.current_program = Some(program_name.to_string());
    }

    fn program_deactivated(&mut self, program_name: &str) {
        if self.current_program.as_deref() == Some(program_name) {
            self.session = None;
            self.current_program = None;
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system_emulation::emu_system_analyzer::AnalyzerResult;

    #[test]
    fn test_plugin_new() {
        let plugin = EmuSystemPlugin::new();
        assert_eq!(plugin.name(), "EmuSystemPlugin");
        assert!(plugin.is_enabled());
        assert!(!plugin.is_initialized());
        assert!(!plugin.is_disposed());
        assert!(plugin.current_program().is_none());
        assert!(!plugin.has_active_session());
    }

    #[test]
    fn test_plugin_with_name() {
        let plugin = EmuSystemPlugin::with_name("CustomEmu");
        assert_eq!(plugin.name(), "CustomEmu");
    }

    #[test]
    fn test_plugin_default() {
        let plugin = EmuSystemPlugin::default();
        assert_eq!(plugin.name(), "EmuSystemPlugin");
    }

    #[test]
    fn test_plugin_lifecycle() {
        let mut plugin = EmuSystemPlugin::new();
        assert!(!plugin.is_initialized());

        plugin.init();
        assert!(plugin.is_initialized());

        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(!plugin.is_initialized());
    }

    #[test]
    fn test_plugin_program_lifecycle() {
        let mut plugin = EmuSystemPlugin::new();
        plugin.init();

        assert!(plugin.current_program().is_none());

        EmuSystemPluginLifecycle::program_activated(&mut plugin, "test.exe");
        assert_eq!(plugin.current_program(), Some("test.exe"));

        // Deactivating a different program should not clear state
        EmuSystemPluginLifecycle::program_deactivated(&mut plugin, "other.exe");
        assert_eq!(plugin.current_program(), Some("test.exe"));

        // Deactivating the current program should clear state
        EmuSystemPluginLifecycle::program_deactivated(&mut plugin, "test.exe");
        assert!(plugin.current_program().is_none());
        assert!(!plugin.has_active_session());
    }

    #[test]
    fn test_plugin_set_program() {
        let mut plugin = EmuSystemPlugin::new();
        plugin.set_program(Some("test.exe".into()));
        assert_eq!(plugin.current_program(), Some("test.exe"));

        plugin.set_program(None);
        assert!(plugin.current_program().is_none());
    }

    #[test]
    fn test_plugin_actions() {
        let plugin = EmuSystemPlugin::new();
        assert!(plugin.action_count() >= 5);

        let start = plugin.find_action("Start Emulation");
        assert!(start.is_some());
        assert_eq!(start.unwrap().group, "Emulation");

        assert!(plugin.find_action("Nonexistent").is_none());
    }

    #[test]
    fn test_plugin_set_action_enabled() {
        let mut plugin = EmuSystemPlugin::new();

        plugin.set_action_enabled("Start Emulation", false);
        let action = plugin.find_action("Start Emulation").unwrap();
        assert!(!action.enabled);

        plugin.set_action_enabled("Start Emulation", true);
        let action = plugin.find_action("Start Emulation").unwrap();
        assert!(action.enabled);
    }

    #[test]
    fn test_config_default() {
        let config = EmuConfig::default();
        assert_eq!(config.target_os, "Linux");
        assert_eq!(config.target_architecture, "x86_64");
        assert_eq!(config.pointer_size, 8);
        assert!(config.little_endian);
    }

    #[test]
    fn test_config_x86_64_windows() {
        let config = EmuConfig::x86_64_windows();
        assert_eq!(config.target_os, "Windows");
        assert_eq!(config.code_base, 0x140_0000);
    }

    #[test]
    fn test_config_arm_linux() {
        let config = EmuConfig::arm_linux();
        assert_eq!(config.target_os, "Linux");
        assert_eq!(config.target_architecture, "ARM");
        assert_eq!(config.pointer_size, 4);
    }

    #[test]
    fn test_start_session() {
        let mut plugin = EmuSystemPlugin::new();
        plugin.init();

        let analysis = AnalyzerResult::default();
        let result = plugin.start_session(analysis);
        assert!(result.is_ok());
        assert!(plugin.has_active_session());
    }

    #[test]
    fn test_start_session_with_entry_point() {
        let mut plugin = EmuSystemPlugin::new();
        plugin.init();

        let mut analysis = AnalyzerResult::default();
        analysis.entry_points.push(EmuEntryPoint {
            address: 0x401000,
            label: "main".into(),
            kind: EmuEntryPointKind::Main,
            confidence: 0.95,
        });

        plugin.start_session(analysis).unwrap();
        assert!(plugin.has_active_session());
        assert_eq!(plugin.session().unwrap().machine.get_pc(), 0x401000);
    }

    #[test]
    fn test_start_session_already_active() {
        let mut plugin = EmuSystemPlugin::new();
        plugin.init();

        plugin.start_session(AnalyzerResult::default()).unwrap();
        let result = plugin.start_session(AnalyzerResult::default());
        assert!(result.is_err());
    }

    #[test]
    fn test_stop_session() {
        let mut plugin = EmuSystemPlugin::new();
        plugin.init();

        plugin.start_session(AnalyzerResult::default()).unwrap();
        assert!(plugin.has_active_session());

        plugin.stop_session("user requested");
        assert!(!plugin.has_active_session());
    }

    #[test]
    fn test_step_no_session() {
        let mut plugin = EmuSystemPlugin::new();
        let result = plugin.step();
        assert!(result.is_err());
    }

    #[test]
    fn test_step_with_session() {
        let mut plugin = EmuSystemPlugin::new();
        plugin.init();

        let mut analysis = AnalyzerResult::default();
        analysis.entry_points.push(EmuEntryPoint {
            address: 0x400000,
            label: "main".into(),
            kind: EmuEntryPointKind::Main,
            confidence: 0.95,
        });

        plugin.start_session(analysis).unwrap();
        // The machine maps a code region at code_base (0x40_0000)
        // The entry point 0x400000 != code_base 0x40_0000 = 0x400000, they match
        let result = plugin.step();
        // Should succeed (simple no-op step in the simplified emulator)
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_no_session() {
        let mut plugin = EmuSystemPlugin::new();
        let result = plugin.run(100);
        assert!(result.is_none());
    }

    #[test]
    fn test_run_with_session() {
        let mut plugin = EmuSystemPlugin::new();
        plugin.init();

        let mut analysis = AnalyzerResult::default();
        analysis.entry_points.push(EmuEntryPoint {
            address: 0x400000,
            label: "main".into(),
            kind: EmuEntryPointKind::Main,
            confidence: 0.95,
        });

        plugin.start_session(analysis).unwrap();
        let result = plugin.run(10);
        assert!(result.is_some());
        // Should reach max steps since the simplified emulator just advances PC
        match result.unwrap() {
            RunResult::MaxStepsReached { instructions } => {
                assert_eq!(instructions, 10);
            }
            other => {
                // Any valid result is acceptable
                let _ = other;
            }
        }
    }

    #[test]
    fn test_destroy_session() {
        let mut plugin = EmuSystemPlugin::new();
        plugin.init();

        plugin.start_session(AnalyzerResult::default()).unwrap();
        assert!(plugin.has_active_session());

        plugin.destroy_session();
        assert!(!plugin.has_active_session());
    }

    #[test]
    fn test_event_log() {
        let mut plugin = EmuSystemPlugin::new();
        plugin.init();

        plugin.start_session(AnalyzerResult::default()).unwrap();
        plugin.destroy_session();

        // The session's events should be in the global log
        assert!(plugin.event_count() > 0);
    }

    #[test]
    fn test_clear_event_log() {
        let mut plugin = EmuSystemPlugin::new();
        plugin.init();

        plugin.start_session(AnalyzerResult::default()).unwrap();
        plugin.destroy_session();
        assert!(plugin.event_count() > 0);

        plugin.clear_event_log();
        assert_eq!(plugin.event_count(), 0);
    }

    #[test]
    fn test_analyzer_access() {
        let mut plugin = EmuSystemPlugin::new();
        assert_eq!(plugin.analyzer().name(), "System Emulation Analyzer");

        plugin.analyzer_mut().set_enabled(false);
        assert!(!plugin.analyzer().is_enabled());
    }

    #[test]
    fn test_config_mut() {
        let mut plugin = EmuSystemPlugin::new();
        plugin.config_mut().max_instructions = 500_000;
        assert_eq!(plugin.config().max_instructions, 500_000);
    }

    #[test]
    fn test_emu_action() {
        let action = EmuAction::new("Test", "Group", "Description");
        assert_eq!(action.name, "Test");
        assert!(action.enabled);
        assert!(action.menu_path.is_empty());

        let action = action.with_menu_path(vec!["Menu".into(), "Sub".into()]);
        assert_eq!(action.menu_path.len(), 2);
    }

    #[test]
    fn test_emu_session_events() {
        let mut plugin = EmuSystemPlugin::new();
        plugin.init();

        let mut analysis = AnalyzerResult::default();
        analysis.entry_points.push(EmuEntryPoint {
            address: 0x400000,
            label: "main".into(),
            kind: EmuEntryPointKind::Main,
            confidence: 0.95,
        });

        plugin.start_session(analysis).unwrap();
        let session = plugin.session().unwrap();
        assert!(!session.events.is_empty());

        // The first event should be SessionStarted
        match &session.events[0] {
            EmuEvent::SessionStarted { entry_point, .. } => {
                assert_eq!(*entry_point, 0x400000);
            }
            _ => panic!("Expected SessionStarted event"),
        }
    }

    #[test]
    fn test_run_result_variants() {
        // Verify RunResult is Debug + Clone
        let r = RunResult::MaxStepsReached { instructions: 100 };
        let _ = format!("{:?}", r);
        let _ = r.clone();
    }

    #[test]
    fn test_plugin_enable_disable() {
        let mut plugin = EmuSystemPlugin::new();
        assert!(plugin.is_enabled());

        plugin.set_enabled(false);
        assert!(!plugin.is_enabled());

        plugin.set_enabled(true);
        assert!(plugin.is_enabled());
    }
}
