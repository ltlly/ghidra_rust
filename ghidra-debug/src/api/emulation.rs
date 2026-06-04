//! Emulation API types: emulator factory, pcode debugger access.
//!
//! Ported from Ghidra's `ghidra.debug.api.emulation` package.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A factory for configuring and creating a debugger-integrated emulator.
///
/// Ported from Ghidra's `EmulatorFactory` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulatorFactoryDescriptor {
    /// The title, to appear in menus and dialogs.
    pub title: String,
    /// The language ID this factory supports.
    pub language_id: String,
    /// The compiler spec ID.
    pub compiler_spec_id: String,
    /// Description.
    pub description: String,
}

impl EmulatorFactoryDescriptor {
    /// Create a new descriptor.
    pub fn new(
        title: impl Into<String>,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            language_id: language_id.into(),
            compiler_spec_id: compiler_spec_id.into(),
            description: String::new(),
        }
    }

    /// Set the description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }
}

/// Emulation state during trace integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EmulationState {
    /// Not emulating.
    Idle,
    /// Emulation is running.
    Running,
    /// Emulation is paused (breakpoint hit).
    Paused,
    /// Emulation completed (end of trace).
    Completed,
    /// Emulation encountered an error.
    Error,
}

impl EmulationState {
    /// Whether emulation is active (running or paused).
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Running | Self::Paused)
    }
}

/// Configuration for a pcode emulation session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationConfig {
    /// The trace ID.
    pub trace_id: String,
    /// The starting snap.
    pub start_snap: i64,
    /// The maximum number of steps.
    pub max_steps: u64,
    /// Whether to write results back to the trace.
    pub write_back: bool,
    /// The lifespan for emulated data.
    pub lifespan: Lifespan,
}

impl EmulationConfig {
    /// Create a new emulation config.
    pub fn new(trace_id: impl Into<String>, start_snap: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            start_snap,
            max_steps: 1000,
            write_back: true,
            lifespan: Lifespan::now_on(start_snap),
        }
    }

    /// Set the maximum number of steps.
    pub fn with_max_steps(mut self, max_steps: u64) -> Self {
        self.max_steps = max_steps;
        self
    }

    /// Set whether to write results back.
    pub fn with_write_back(mut self, write_back: bool) -> Self {
        self.write_back = write_back;
        self
    }
}

/// Access shim for pcode execution against a trace and debugger session.
///
/// Ported from Ghidra's `PcodeDebuggerAccess` interface. Encapsulates the
/// tool controlling a session and the session's target, permitting pcode
/// executor/emulator states to access target data and session data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeDebuggerAccessConfig {
    /// The trace ID.
    pub trace_id: String,
    /// The snap.
    pub snap: i64,
    /// The thread key.
    pub thread_key: Option<i64>,
    /// The frame number.
    pub frame: i32,
    /// The language ID for the emulator.
    pub language_id: String,
}

impl PcodeDebuggerAccessConfig {
    /// Create a new config for shared state access.
    pub fn for_shared_state(trace_id: impl Into<String>, snap: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            thread_key: None,
            frame: 0,
            language_id: String::new(),
        }
    }

    /// Create a new config for local (thread) state access.
    pub fn for_local_state(
        trace_id: impl Into<String>,
        snap: i64,
        thread_key: i64,
        frame: i32,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            thread_key: Some(thread_key),
            frame,
            language_id: String::new(),
        }
    }

    /// Set the language ID.
    pub fn with_language_id(mut self, id: impl Into<String>) -> Self {
        self.language_id = id.into();
        self
    }
}

/// A writer for emulation callbacks that update the trace.
///
/// Ported from Ghidra's `TraceEmulationIntegration.Writer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationWriter {
    /// The target trace ID.
    pub trace_id: String,
    /// The snap to write at.
    pub snap: i64,
    /// The thread key.
    pub thread_key: Option<i64>,
    /// Whether to record memory writes.
    pub record_memory: bool,
    /// Whether to record register writes.
    pub record_registers: bool,
}

impl EmulationWriter {
    /// Create a new emulation writer.
    pub fn new(trace_id: impl Into<String>, snap: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            thread_key: None,
            record_memory: true,
            record_registers: true,
        }
    }

    /// Set the thread key.
    pub fn with_thread(mut self, thread_key: i64) -> Self {
        self.thread_key = Some(thread_key);
        self
    }
}

/// Registry of emulator factories.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmulatorFactoryRegistry {
    factories: Vec<EmulatorFactoryDescriptor>,
}

impl EmulatorFactoryRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a factory.
    pub fn register(&mut self, factory: EmulatorFactoryDescriptor) {
        self.factories.push(factory);
    }

    /// Get all factories.
    pub fn factories(&self) -> &[EmulatorFactoryDescriptor] {
        &self.factories
    }

    /// Find factories for a given language ID.
    pub fn for_language(&self, language_id: &str) -> Vec<&EmulatorFactoryDescriptor> {
        self.factories
            .iter()
            .filter(|f| f.language_id == language_id)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulator_factory_descriptor() {
        let factory = EmulatorFactoryDescriptor::new("x86 Emulator", "x86:LE:64:default", "default")
            .with_description("Emulates x86_64 instructions");
        assert_eq!(factory.title, "x86 Emulator");
        assert_eq!(factory.language_id, "x86:LE:64:default");
    }

    #[test]
    fn test_emulation_state() {
        assert!(EmulationState::Running.is_active());
        assert!(EmulationState::Paused.is_active());
        assert!(!EmulationState::Idle.is_active());
        assert!(!EmulationState::Completed.is_active());
        assert!(!EmulationState::Error.is_active());
    }

    #[test]
    fn test_emulation_config() {
        let config = EmulationConfig::new("trace1", 0)
            .with_max_steps(5000)
            .with_write_back(false);
        assert_eq!(config.trace_id, "trace1");
        assert_eq!(config.max_steps, 5000);
        assert!(!config.write_back);
    }

    #[test]
    fn test_pcode_debugger_access_config() {
        let config = PcodeDebuggerAccessConfig::for_shared_state("trace1", 5);
        assert!(config.thread_key.is_none());

        let config = PcodeDebuggerAccessConfig::for_local_state("trace1", 5, 42, 0)
            .with_language_id("x86:LE:64:default");
        assert_eq!(config.thread_key, Some(42));
        assert_eq!(config.language_id, "x86:LE:64:default");
    }

    #[test]
    fn test_emulation_writer() {
        let writer = EmulationWriter::new("trace1", 0).with_thread(42);
        assert_eq!(writer.trace_id, "trace1");
        assert_eq!(writer.thread_key, Some(42));
        assert!(writer.record_memory);
    }

    #[test]
    fn test_emulator_factory_registry() {
        let mut reg = EmulatorFactoryRegistry::new();
        reg.register(EmulatorFactoryDescriptor::new("x86", "x86:LE:64:default", "default"));
        reg.register(EmulatorFactoryDescriptor::new("ARM", "ARM:LE:32:v8", "default"));

        assert_eq!(reg.factories().len(), 2);
        let x86 = reg.for_language("x86:LE:64:default");
        assert_eq!(x86.len(), 1);
        assert!(reg.for_language("missing").is_empty());
    }

    #[test]
    fn test_emulation_config_serde() {
        let config = EmulationConfig::new("trace1", 0);
        let json = serde_json::to_string(&config).unwrap();
        let back: EmulationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.trace_id, "trace1");
    }
}
