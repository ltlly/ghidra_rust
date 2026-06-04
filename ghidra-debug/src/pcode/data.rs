//! Pcode trace data access interfaces.
//!
//! Ported from Ghidra's `ghidra.pcode.exec.trace.data` package. These
//! interfaces provide the bridge between pcode execution and trace data,
//! allowing the emulator to read/write memory, registers, and properties.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// Schema name for a trace data type used in pcode operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PcodeSchemaName(pub String);

impl PcodeSchemaName {
    /// Create a new schema name.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Primitive byte type.
    pub fn byte() -> Self {
        Self("byte".into())
    }

    /// Primitive long type.
    pub fn long() -> Self {
        Self("long".into())
    }
}

/// Access to trace data for pcode execution on shared (memory) state.
///
/// Ported from Ghidra's `PcodeTraceMemoryAccess`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeTraceMemoryAccess {
    /// The trace ID.
    pub trace_id: String,
    /// The snap to read/write at.
    pub snap: i64,
    /// The lifespan for writes.
    pub write_lifespan: Lifespan,
    /// The language ID for the emulator's address space mapping.
    pub language_id: String,
}

impl PcodeTraceMemoryAccess {
    /// Create a new memory access.
    pub fn new(trace_id: impl Into<String>, snap: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            write_lifespan: Lifespan::now_on(snap),
            language_id: String::new(),
        }
    }

    /// Set the language ID.
    pub fn with_language_id(mut self, id: impl Into<String>) -> Self {
        self.language_id = id.into();
        self
    }
}

/// Access to trace data for pcode execution on local (register) state.
///
/// Ported from Ghidra's `PcodeTraceRegistersAccess`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeTraceRegistersAccess {
    /// The trace ID.
    pub trace_id: String,
    /// The snap.
    pub snap: i64,
    /// The thread key.
    pub thread_key: i64,
    /// The frame number.
    pub frame: i32,
    /// The write lifespan.
    pub write_lifespan: Lifespan,
}

impl PcodeTraceRegistersAccess {
    /// Create a new registers access.
    pub fn new(trace_id: impl Into<String>, snap: i64, thread_key: i64, frame: i32) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            thread_key,
            frame,
            write_lifespan: Lifespan::now_on(snap),
        }
    }
}

/// Access to trace data for pcode execution on thread state.
///
/// Ported from Ghidra's `PcodeTraceThreadAccess`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeTraceThreadAccess {
    /// The trace ID.
    pub trace_id: String,
    /// The snap.
    pub snap: i64,
    /// The thread key.
    pub thread_key: i64,
}

impl PcodeTraceThreadAccess {
    /// Create a new thread access.
    pub fn new(trace_id: impl Into<String>, snap: i64, thread_key: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            thread_key,
        }
    }
}

/// Access to trace data for pcode execution on properties.
///
/// Ported from Ghidra's `PcodeTracePropertyAccess`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeTracePropertyAccess {
    /// The trace ID.
    pub trace_id: String,
    /// The snap.
    pub snap: i64,
    /// The property name.
    pub property_name: String,
}

impl PcodeTracePropertyAccess {
    /// Create a new property access.
    pub fn new(trace_id: impl Into<String>, snap: i64, property_name: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            property_name: property_name.into(),
        }
    }
}

/// Combined data access for pcode execution against a trace.
///
/// Ported from Ghidra's `PcodeTraceDataAccess`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeTraceDataAccess {
    /// The trace ID.
    pub trace_id: String,
    /// The snap.
    pub snap: i64,
    /// The language ID.
    pub language_id: String,
}

impl PcodeTraceDataAccess {
    /// Create a new data access.
    pub fn new(trace_id: impl Into<String>, snap: i64) -> Self {
        Self {
            trace_id: trace_id.into(),
            snap,
            language_id: String::new(),
        }
    }

    /// Get memory access for shared state.
    pub fn memory_access(&self) -> PcodeTraceMemoryAccess {
        PcodeTraceMemoryAccess::new(&self.trace_id, self.snap)
            .with_language_id(&self.language_id)
    }

    /// Get registers access for a thread.
    pub fn registers_access(&self, thread_key: i64, frame: i32) -> PcodeTraceRegistersAccess {
        PcodeTraceRegistersAccess::new(&self.trace_id, self.snap, thread_key, frame)
    }

    /// Get thread access.
    pub fn thread_access(&self, thread_key: i64) -> PcodeTraceThreadAccess {
        PcodeTraceThreadAccess::new(&self.trace_id, self.snap, thread_key)
    }

    /// Get property access.
    pub fn property_access(&self, property_name: impl Into<String>) -> PcodeTracePropertyAccess {
        PcodeTracePropertyAccess::new(&self.trace_id, self.snap, property_name)
    }
}

/// Top-level trace access interface for pcode execution.
///
/// Ported from Ghidra's `PcodeTraceAccess` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeTraceAccess {
    /// The data access.
    pub data: PcodeTraceDataAccess,
}

impl PcodeTraceAccess {
    /// Create a new trace access.
    pub fn new(trace_id: impl Into<String>, snap: i64) -> Self {
        Self {
            data: PcodeTraceDataAccess::new(trace_id, snap),
        }
    }

    /// Get data access for shared state (memory).
    pub fn get_data_for_shared_state(&self) -> PcodeTraceMemoryAccess {
        self.data.memory_access()
    }

    /// Get data access for local state (registers).
    pub fn get_data_for_local_state(&self, thread_key: i64, frame: i32) -> PcodeTraceRegistersAccess {
        self.data.registers_access(thread_key, frame)
    }

    /// Set the language ID.
    pub fn with_language_id(mut self, id: impl Into<String>) -> Self {
        self.data.language_id = id.into();
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pcode_memory_access() {
        let access = PcodeTraceMemoryAccess::new("trace1", 5)
            .with_language_id("x86:LE:64:default");
        assert_eq!(access.trace_id, "trace1");
        assert_eq!(access.snap, 5);
        assert_eq!(access.language_id, "x86:LE:64:default");
    }

    #[test]
    fn test_pcode_registers_access() {
        let access = PcodeTraceRegistersAccess::new("trace1", 5, 42, 0);
        assert_eq!(access.thread_key, 42);
        assert_eq!(access.frame, 0);
    }

    #[test]
    fn test_pcode_thread_access() {
        let access = PcodeTraceThreadAccess::new("trace1", 5, 42);
        assert_eq!(access.thread_key, 42);
    }

    #[test]
    fn test_pcode_property_access() {
        let access = PcodeTracePropertyAccess::new("trace1", 5, "DisassemblyColorModel");
        assert_eq!(access.property_name, "DisassemblyColorModel");
    }

    #[test]
    fn test_pcode_data_access() {
        let data = PcodeTraceDataAccess::new("trace1", 5);

        let mem = data.memory_access();
        assert_eq!(mem.trace_id, "trace1");

        let regs = data.registers_access(42, 0);
        assert_eq!(regs.thread_key, 42);

        let thread = data.thread_access(42);
        assert_eq!(thread.thread_key, 42);

        let prop = data.property_access("TestProp");
        assert_eq!(prop.property_name, "TestProp");
    }

    #[test]
    fn test_pcode_trace_access() {
        let access = PcodeTraceAccess::new("trace1", 5)
            .with_language_id("x86:LE:64:default");

        let shared = access.get_data_for_shared_state();
        assert_eq!(shared.language_id, "x86:LE:64:default");

        let local = access.get_data_for_local_state(42, 0);
        assert_eq!(local.thread_key, 42);
    }

    #[test]
    fn test_pcode_schema_name() {
        assert_eq!(PcodeSchemaName::byte().0, "byte");
        assert_eq!(PcodeSchemaName::long().0, "long");
    }

    #[test]
    fn test_pcode_data_access_serde() {
        let access = PcodeTraceAccess::new("trace1", 0);
        let json = serde_json::to_string(&access).unwrap();
        let back: PcodeTraceAccess = serde_json::from_str(&json).unwrap();
        assert_eq!(back.data.trace_id, "trace1");
    }
}
