//! Emulation service implementation.
//!
//! Ported from Ghidra's `DebuggerEmulationServicePlugin` and associated
//! emulation data access types. Provides the concrete implementation of
//! the emulation service for running p-code emulators within a debug session.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use crate::api::emulation::{
    EmulationConfig, EmulationState, EmulationWriter, EmulatorFactoryDescriptor,
    EmulatorFactoryRegistry, PcodeDebuggerAccessConfig,
};
use crate::model::Lifespan;

/// The emulation mode for p-code execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EmulationMode {
    /// Interpret p-code instructions one at a time.
    Interpret,
    /// Compile p-code to native code for faster execution.
    Compile,
    /// Hybrid: compile hot paths, interpret cold paths.
    Hybrid,
}

impl Default for EmulationMode {
    fn default() -> Self {
        Self::Interpret
    }
}

/// A write flag for target-associated emulator states.
///
/// Ported from Ghidra's `Mode` enum in `ghidra.app.plugin.core.debug.service.emulation`.
/// Controls whether an emulated state can write back to the live target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WriteMode {
    /// The state can write the target directly.
    Rw,
    /// The state will never write the target.
    Ro,
}

impl WriteMode {
    /// Check if the mode permits writing the target.
    pub fn is_write_target(&self) -> bool {
        matches!(self, Self::Rw)
    }
}

impl Default for WriteMode {
    fn default() -> Self {
        Self::Rw
    }
}

/// An out-of-memory exception during emulation.
///
/// Ported from Ghidra's `EmulatorOutOfMemoryException`.
#[derive(Debug, Clone)]
pub struct EmulatorOutOfMemoryError {
    /// The address that was accessed.
    pub address: u64,
    /// Whether this was a write (vs. read).
    pub is_write: bool,
    /// A description of the error.
    pub message: String,
}

impl EmulatorOutOfMemoryError {
    /// Create a new out-of-memory error.
    pub fn new(address: u64, is_write: bool, message: impl Into<String>) -> Self {
        Self {
            address,
            is_write,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for EmulatorOutOfMemoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let op = if self.is_write { "write" } else { "read" };
        write!(
            f,
            "Emulator out-of-memory {} at 0x{:x}: {}",
            op, self.address, self.message
        )
    }
}

impl std::error::Error for EmulatorOutOfMemoryError {}

/// The default emulator factory for the debugger.
///
/// Ported from Ghidra's `DefaultEmulatorFactory`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultEmulatorFactory {
    /// The title.
    pub title: String,
    /// The language ID.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
}

impl DefaultEmulatorFactory {
    /// The title of the default concrete P-code emulator.
    pub const TITLE: &'static str = "Default Concrete P-code Emulator";

    /// Create a new default emulator factory.
    pub fn new(
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            title: Self::TITLE.into(),
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
        }
    }
}

/// Debugger emulation integration utilities.
///
/// Ported from Ghidra's `DebuggerEmulationIntegration`.
#[derive(Debug)]
pub struct DebuggerEmulationIntegration;

impl DebuggerEmulationIntegration {
    /// Compute the initial emulation state from a trace snapshot.
    ///
    /// Sets up memory and register state from the trace at the given snap.
    pub fn compute_initial_state(
        trace_id: &str,
        snap: i64,
        thread_key: Option<i64>,
    ) -> EmulationSession {
        let session = EmulationSession::new(0, trace_id, snap);
        if let Some(tk) = thread_key {
            session.with_thread(tk)
        } else {
            session
        }
    }

    /// Check whether emulation should write back to the trace.
    pub fn should_write_back(mode: WriteMode) -> bool {
        mode.is_write_target()
    }
}

/// Configuration for p-code emulation execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationExecutionConfig {
    /// The emulation mode.
    pub mode: EmulationMode,
    /// The maximum number of instructions to execute.
    pub max_instructions: u64,
    /// The maximum number of memory reads.
    pub max_memory_reads: u64,
    /// The maximum number of memory writes.
    pub max_memory_writes: u64,
    /// Whether to record memory state changes.
    pub record_memory_changes: bool,
    /// Whether to record register state changes.
    pub record_register_changes: bool,
    /// The time limit in milliseconds (0 = no limit).
    pub time_limit_ms: u64,
}

impl Default for EmulationExecutionConfig {
    fn default() -> Self {
        Self {
            mode: EmulationMode::Interpret,
            max_instructions: 10_000,
            max_memory_reads: 100_000,
            max_memory_writes: 100_000,
            record_memory_changes: true,
            record_register_changes: true,
            time_limit_ms: 0,
        }
    }
}

impl EmulationExecutionConfig {
    /// Create a new config with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the emulation mode.
    pub fn with_mode(mut self, mode: EmulationMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set the maximum number of instructions.
    pub fn with_max_instructions(mut self, max: u64) -> Self {
        self.max_instructions = max;
        self
    }

    /// Set the time limit.
    pub fn with_time_limit_ms(mut self, ms: u64) -> Self {
        self.time_limit_ms = ms;
        self
    }
}

/// An emulation session representing an active p-code emulator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationSession {
    /// The session ID.
    pub id: u64,
    /// The trace ID.
    pub trace_id: String,
    /// The current state.
    pub state: EmulationState,
    /// The current snap.
    pub snap: i64,
    /// The thread key.
    pub thread_key: Option<i64>,
    /// The number of instructions executed so far.
    pub instructions_executed: u64,
    /// The configuration.
    pub config: EmulationExecutionConfig,
    /// The emulation writer for recording state changes.
    pub writer: EmulationWriter,
}

impl EmulationSession {
    /// Create a new emulation session.
    pub fn new(id: u64, trace_id: impl Into<String>, snap: i64) -> Self {
        let trace_id_str = trace_id.into();
        Self {
            id,
            trace_id: trace_id_str.clone(),
            state: EmulationState::Idle,
            snap,
            thread_key: None,
            instructions_executed: 0,
            config: EmulationExecutionConfig::default(),
            writer: EmulationWriter::new(trace_id_str, snap),
        }
    }

    /// Set the thread key.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self.writer = self.writer.with_thread(thread_key);
        self
    }

    /// Set the configuration.
    pub fn with_config(mut self, config: EmulationExecutionConfig) -> Self {
        self.config = config;
        self
    }

    /// Whether this session is active (running or paused).
    pub fn is_active(&self) -> bool {
        self.state.is_active()
    }
}

/// A p-code debugger data access implementation.
///
/// Ported from Ghidra's `DefaultPcodeDebuggerAccess`. Provides the bridge
/// between the p-code emulator and the trace data (memory, registers, properties).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeDebuggerDataAccess {
    /// The access configuration.
    pub config: PcodeDebuggerAccessConfig,
    /// The trace ID.
    pub trace_id: String,
    /// The snap.
    pub snap: i64,
    /// The thread key (for local state).
    pub thread_key: Option<i64>,
    /// The frame number (for local state).
    pub frame: i32,
}

impl PcodeDebuggerDataAccess {
    /// Create a data access for shared state (memory).
    pub fn for_shared_state(trace_id: impl Into<String>, snap: i64) -> Self {
        let trace_id_str = trace_id.into();
        Self {
            config: PcodeDebuggerAccessConfig::for_shared_state(&trace_id_str, snap),
            trace_id: trace_id_str,
            snap,
            thread_key: None,
            frame: 0,
        }
    }

    /// Create a data access for local state (registers).
    pub fn for_local_state(
        trace_id: impl Into<String>,
        snap: i64,
        thread_key: i64,
        frame: i32,
    ) -> Self {
        let trace_id_str = trace_id.into();
        Self {
            config: PcodeDebuggerAccessConfig::for_local_state(&trace_id_str, snap, thread_key, frame),
            trace_id: trace_id_str,
            snap,
            thread_key: Some(thread_key),
            frame,
        }
    }
}

/// A p-code debugger memory access implementation.
///
/// Ported from Ghidra's `DefaultPcodeDebuggerMemoryAccess`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeDebuggerMemoryAccess {
    /// The trace ID.
    pub trace_id: String,
    /// The snap.
    pub snap: i64,
    /// The language ID.
    pub language_id: String,
    /// Memory reads performed.
    pub reads: Vec<MemoryRead>,
    /// Memory writes performed.
    pub writes: Vec<MemoryWrite>,
}

/// A record of a memory read operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRead {
    /// The address.
    pub address: u64,
    /// The number of bytes.
    pub length: usize,
    /// The data read (if successful).
    pub data: Option<Vec<u8>>,
}

/// A record of a memory write operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryWrite {
    /// The address.
    pub address: u64,
    /// The data written.
    pub data: Vec<u8>,
}

impl PcodeDebuggerMemoryAccess {
    /// Create a new memory access.
    pub fn new(trace_id: impl Into<String>, snap: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            language_id: String::new(),
            reads: Vec::new(),
            writes: Vec::new(),
        }
    }

    /// Set the language ID.
    pub fn with_language_id(mut self, id: impl Into<String>) -> Self {
        self.language_id = id.into();
        self
    }

    /// Record a memory read.
    pub fn record_read(&mut self, address: u64, length: usize, data: Option<Vec<u8>>) {
        self.reads.push(MemoryRead {
            address,
            length,
            data,
        });
    }

    /// Record a memory write.
    pub fn record_write(&mut self, address: u64, data: Vec<u8>) {
        self.writes.push(MemoryWrite { address, data });
    }

    /// Get the total number of operations.
    pub fn operation_count(&self) -> usize {
        self.reads.len() + self.writes.len()
    }
}

/// A p-code debugger register access implementation.
///
/// Ported from Ghidra's `DefaultPcodeDebuggerRegistersAccess`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeDebuggerRegistersAccess {
    /// The trace ID.
    pub trace_id: String,
    /// The snap.
    pub snap: i64,
    /// The thread key.
    pub thread_key: Option<i64>,
    /// The frame.
    pub frame: i32,
    /// Register reads performed.
    pub reads: Vec<RegisterRead>,
    /// Register writes performed.
    pub writes: Vec<RegisterWrite>,
}

/// A record of a register read operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRead {
    /// The register name.
    pub register_name: String,
    /// The value read (if successful).
    pub value: Option<Vec<u8>>,
}

/// A record of a register write operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterWrite {
    /// The register name.
    pub register_name: String,
    /// The value written.
    pub value: Vec<u8>,
}

impl PcodeDebuggerRegistersAccess {
    /// Create a new register access.
    pub fn new(trace_id: impl Into<String>, snap: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            thread_key: None,
            frame: 0,
            reads: Vec::new(),
            writes: Vec::new(),
        }
    }

    /// Set the thread.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }

    /// Set the frame.
    pub fn with_frame(mut self, frame: i32) -> Self {
        self.frame = frame;
        self
    }

    /// Record a register read.
    pub fn record_read(&mut self, name: impl Into<String>, value: Option<Vec<u8>>) {
        self.reads.push(RegisterRead {
            register_name: name.into(),
            value,
        });
    }

    /// Record a register write.
    pub fn record_write(&mut self, name: impl Into<String>, value: Vec<u8>) {
        self.writes.push(RegisterWrite {
            register_name: name.into(),
            value,
        });
    }
}

/// A p-code debugger property access implementation.
///
/// Ported from Ghidra's `DefaultPcodeDebuggerPropertyAccess`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeDebuggerPropertyAccess {
    /// The trace ID.
    pub trace_id: String,
    /// The snap.
    pub snap: i64,
    /// Property entries.
    pub properties: HashMap<String, Vec<u8>>,
}

impl PcodeDebuggerPropertyAccess {
    /// Create a new property access.
    pub fn new(trace_id: impl Into<String>, snap: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            properties: HashMap::new(),
        }
    }

    /// Get a property value.
    pub fn get(&self, key: &str) -> Option<&Vec<u8>> {
        self.properties.get(key)
    }

    /// Set a property value.
    pub fn set(&mut self, key: impl Into<String>, value: Vec<u8>) {
        self.properties.insert(key.into(), value);
    }
}

/// The emulation service manager.
///
/// Manages emulation sessions and their lifecycle.
#[derive(Debug, Default)]
pub struct EmulationServiceManager {
    /// Registered emulator factories.
    pub factories: EmulatorFactoryRegistry,
    /// Active emulation sessions.
    sessions: HashMap<u64, EmulationSession>,
    /// Next session ID.
    next_session_id: u64,
}

impl EmulationServiceManager {
    /// Create a new emulation service manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an emulator factory.
    pub fn register_factory(&mut self, factory: EmulatorFactoryDescriptor) {
        self.factories.register(factory);
    }

    /// Create a new emulation session.
    pub fn create_session(
        &mut self,
        trace_id: impl Into<String>,
        snap: i64,
    ) -> u64 {
        let id = self.next_session_id;
        self.next_session_id += 1;
        let session = EmulationSession::new(id, trace_id, snap);
        self.sessions.insert(id, session);
        id
    }

    /// Get a session by ID.
    pub fn get_session(&self, id: u64) -> Option<&EmulationSession> {
        self.sessions.get(&id)
    }

    /// Get a mutable session by ID.
    pub fn get_session_mut(&mut self, id: u64) -> Option<&mut EmulationSession> {
        self.sessions.get_mut(&id)
    }

    /// Remove a session.
    pub fn remove_session(&mut self, id: u64) -> Option<EmulationSession> {
        self.sessions.remove(&id)
    }

    /// Get all active sessions.
    pub fn active_sessions(&self) -> Vec<&EmulationSession> {
        self.sessions.values().filter(|s| s.is_active()).collect()
    }

    /// Get the number of sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Update the state of a session.
    pub fn set_session_state(&mut self, id: u64, state: EmulationState) -> bool {
        if let Some(session) = self.sessions.get_mut(&id) {
            session.state = state;
            true
        } else {
            false
        }
    }

    /// Increment the instruction count of a session.
    pub fn increment_instructions(&mut self, id: u64, count: u64) -> bool {
        if let Some(session) = self.sessions.get_mut(&id) {
            session.instructions_executed += count;
            true
        } else {
            false
        }
    }
}

/// Program emulation utilities.
///
/// Ported from Ghidra's `ProgramEmulationUtils`.
#[derive(Debug)]
pub struct ProgramEmulationUtils;

impl ProgramEmulationUtils {
    /// Check if a program is suitable for emulation.
    pub fn is_emulatable(language_id: &str) -> bool {
        // Check if we have a registered factory for this language.
        // This is a simplified check; real implementation would verify
        // that the language has a p-code model.
        !language_id.is_empty()
    }

    /// Get the default emulation config for a language.
    pub fn default_config_for_language(language_id: &str) -> EmulationExecutionConfig {
        let mut config = EmulationExecutionConfig::default();
        // Adjust defaults based on language
        if language_id.contains("x86") {
            config.max_instructions = 100_000;
        } else if language_id.contains("ARM") {
            config.max_instructions = 50_000;
        }
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulation_mode_default() {
        assert_eq!(EmulationMode::default(), EmulationMode::Interpret);
    }

    #[test]
    fn test_emulation_execution_config() {
        let config = EmulationExecutionConfig::new()
            .with_mode(EmulationMode::Compile)
            .with_max_instructions(50000)
            .with_time_limit_ms(5000);
        assert_eq!(config.mode, EmulationMode::Compile);
        assert_eq!(config.max_instructions, 50000);
        assert_eq!(config.time_limit_ms, 5000);
    }

    #[test]
    fn test_emulation_session() {
        let session = EmulationSession::new(1, "trace1", 0)
            .with_thread(42)
            .with_config(EmulationExecutionConfig::new().with_max_instructions(1000));
        assert_eq!(session.id, 1);
        assert_eq!(session.trace_id, "trace1");
        assert_eq!(session.thread_key, Some(42));
        assert_eq!(session.instructions_executed, 0);
        assert!(!session.is_active());
    }

    #[test]
    fn test_pcode_debugger_data_access() {
        let shared = PcodeDebuggerDataAccess::for_shared_state("trace1", 5);
        assert!(shared.thread_key.is_none());
        assert_eq!(shared.snap, 5);

        let local = PcodeDebuggerDataAccess::for_local_state("trace1", 5, 42, 0);
        assert_eq!(local.thread_key, Some(42));
        assert_eq!(local.frame, 0);
    }

    #[test]
    fn test_memory_access() {
        let mut access = PcodeDebuggerMemoryAccess::new("trace1", 0)
            .with_language_id("x86:LE:64:default");
        assert_eq!(access.language_id, "x86:LE:64:default");

        access.record_read(0x400000, 4, Some(vec![0x01, 0x02, 0x03, 0x04]));
        access.record_write(0x400004, vec![0x05, 0x06]);

        assert_eq!(access.reads.len(), 1);
        assert_eq!(access.writes.len(), 1);
        assert_eq!(access.operation_count(), 2);
    }

    #[test]
    fn test_registers_access() {
        let mut access = PcodeDebuggerRegistersAccess::new("trace1", 0)
            .with_thread(42)
            .with_frame(1);

        access.record_read("RIP", Some(vec![0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]));
        access.record_write("RSP", vec![0x00, 0x20, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00]);

        assert_eq!(access.reads.len(), 1);
        assert_eq!(access.writes.len(), 1);
        assert_eq!(access.reads[0].register_name, "RIP");
    }

    #[test]
    fn test_property_access() {
        let mut access = PcodeDebuggerPropertyAccess::new("trace1", 0);
        assert!(access.get("key").is_none());

        access.set("key", vec![1, 2, 3]);
        assert_eq!(access.get("key"), Some(&vec![1, 2, 3]));
    }

    #[test]
    fn test_emulation_service_manager() {
        let mut manager = EmulationServiceManager::new();
        assert_eq!(manager.session_count(), 0);

        let id = manager.create_session("trace1", 0);
        assert_eq!(manager.session_count(), 1);
        assert!(manager.get_session(id).is_some());

        manager.set_session_state(id, EmulationState::Running);
        assert_eq!(manager.get_session(id).unwrap().state, EmulationState::Running);

        manager.increment_instructions(id, 100);
        assert_eq!(manager.get_session(id).unwrap().instructions_executed, 100);

        let active = manager.active_sessions();
        assert_eq!(active.len(), 1);

        manager.remove_session(id);
        assert_eq!(manager.session_count(), 0);
    }

    #[test]
    fn test_program_emulation_utils() {
        assert!(ProgramEmulationUtils::is_emulatable("x86:LE:64:default"));
        assert!(!ProgramEmulationUtils::is_emulatable(""));

        let config = ProgramEmulationUtils::default_config_for_language("x86:LE:64:default");
        assert_eq!(config.max_instructions, 100_000);

        let config = ProgramEmulationUtils::default_config_for_language("ARM:LE:32:v8");
        assert_eq!(config.max_instructions, 50_000);
    }

    #[test]
    fn test_emulation_session_serde() {
        let session = EmulationSession::new(1, "trace1", 0);
        let json = serde_json::to_string(&session).unwrap();
        let back: EmulationSession = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, 1);
        assert_eq!(back.trace_id, "trace1");
    }

    #[test]
    fn test_emulation_config_serde() {
        let config = EmulationExecutionConfig::new()
            .with_mode(EmulationMode::Hybrid);
        let json = serde_json::to_string(&config).unwrap();
        let back: EmulationExecutionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.mode, EmulationMode::Hybrid);
    }

    #[test]
    fn test_write_mode() {
        assert!(WriteMode::Rw.is_write_target());
        assert!(!WriteMode::Ro.is_write_target());
        assert_eq!(WriteMode::default(), WriteMode::Rw);
    }

    #[test]
    fn test_write_mode_serde() {
        let mode = WriteMode::Ro;
        let json = serde_json::to_string(&mode).unwrap();
        let back: WriteMode = serde_json::from_str(&json).unwrap();
        assert_eq!(back, WriteMode::Ro);
    }

    #[test]
    fn test_emulator_out_of_memory_error() {
        let err = EmulatorOutOfMemoryError::new(0xdeadbeef, true, "unmapped address");
        assert_eq!(err.address, 0xdeadbeef);
        assert!(err.is_write);
        assert!(err.to_string().contains("write"));
        assert!(err.to_string().contains("deadbeef"));
    }

    #[test]
    fn test_default_emulator_factory() {
        let factory = DefaultEmulatorFactory::new("x86:LE:64:default", "default");
        assert_eq!(factory.title, DefaultEmulatorFactory::TITLE);
        assert_eq!(factory.language_id, "x86:LE:64:default");
    }

    #[test]
    fn test_default_emulator_factory_serde() {
        let factory = DefaultEmulatorFactory::new("x86:LE:64:default", "default");
        let json = serde_json::to_string(&factory).unwrap();
        let back: DefaultEmulatorFactory = serde_json::from_str(&json).unwrap();
        assert_eq!(back.title, DefaultEmulatorFactory::TITLE);
    }

    #[test]
    fn test_debugger_emulation_integration() {
        let session = DebuggerEmulationIntegration::compute_initial_state("trace1", 0, Some(42));
        assert_eq!(session.trace_id, "trace1");
        assert_eq!(session.thread_key, Some(42));

        let session = DebuggerEmulationIntegration::compute_initial_state("trace1", 5, None);
        assert!(session.thread_key.is_none());
        assert_eq!(session.snap, 5);
    }

    #[test]
    fn test_should_write_back() {
        assert!(DebuggerEmulationIntegration::should_write_back(WriteMode::Rw));
        assert!(!DebuggerEmulationIntegration::should_write_back(WriteMode::Ro));
    }
}
