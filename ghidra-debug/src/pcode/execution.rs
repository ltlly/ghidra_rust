//! Pcode execution state pieces and trace emulation integration.
//!
//! Ported from Ghidra's `ghidra.pcode.exec.trace` execution classes
//! in Framework-TraceModeling.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Error when a pcode operation hits unknown/uninitialized trace state.
///
/// Ported from Ghidra's `UnknownStatePcodeExecutionException`.
#[derive(Debug, Error)]
#[error("unknown state at {space}:{offset} ({message})")]
pub struct UnknownStateError {
    /// The address space name.
    pub space: String,
    /// The offset within that space.
    pub offset: u64,
    /// A descriptive message.
    pub message: String,
}

impl UnknownStateError {
    /// Create a new unknown state error.
    pub fn new(
        space: impl Into<String>,
        offset: u64,
        message: impl Into<String>,
    ) -> Self {
        Self {
            space: space.into(),
            offset,
            message: message.into(),
        }
    }
}

/// A piece of the pcode executor state that corresponds to a specific
/// trace data view (memory, registers, etc.).
///
/// Ported from Ghidra's `PcodeExecutorStatePiece` interface specialized
/// for trace data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StatePieceKind {
    /// Memory state (shared across threads).
    Memory,
    /// Register state (local to a thread/frame).
    Register,
    /// Property state (key-value store).
    Property,
    /// Thread state.
    Thread,
}

/// Behavior for how to handle unknown state during pcode execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnknownStatePolicy {
    /// Raise an error on unknown state.
    Error,
    /// Return zero for unknown state.
    ZeroFill,
    /// Skip operations that touch unknown state.
    Skip,
}

impl Default for UnknownStatePolicy {
    fn default() -> Self {
        Self::Error
    }
}

/// A state piece that tracks which addresses have been read.
///
/// Ported from Ghidra's `AddressesReadTracePcodeExecutorStatePiece`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddressesReadState {
    /// Set of (space, offset) pairs that have been read.
    pub read_addresses: Vec<(String, u64)>,
}

impl AddressesReadState {
    /// Create a new empty tracking state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a read at the given address.
    pub fn record_read(&mut self, space: impl Into<String>, offset: u64) {
        let entry = (space.into(), offset);
        if !self.read_addresses.contains(&entry) {
            self.read_addresses.push(entry);
        }
    }

    /// Check if an address was read.
    pub fn was_read(&self, space: &str, offset: u64) -> bool {
        self.read_addresses
            .iter()
            .any(|(s, o)| s == space && *o == offset)
    }

    /// Number of unique addresses read.
    pub fn len(&self) -> usize {
        self.read_addresses.len()
    }

    /// Whether no addresses were read.
    pub fn is_empty(&self) -> bool {
        self.read_addresses.is_empty()
    }

    /// Clear the read tracking.
    pub fn clear(&mut self) {
        self.read_addresses.clear();
    }
}

/// Arithmetic operations on trace memory state.
///
/// Ported from Ghidra's `TraceMemoryStatePcodeArithmetic`. Handles how
/// values are combined when the trace memory contains unknown regions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMemoryStateArithmetic {
    /// The policy for unknown state.
    pub unknown_policy: UnknownStatePolicy,
}

impl Default for TraceMemoryStateArithmetic {
    fn default() -> Self {
        Self {
            unknown_policy: UnknownStatePolicy::default(),
        }
    }
}

impl TraceMemoryStateArithmetic {
    /// Create with a specific unknown state policy.
    pub fn new(unknown_policy: UnknownStatePolicy) -> Self {
        Self { unknown_policy }
    }

    /// Combine two values, applying the unknown state policy.
    pub fn combine(&self, known: Option<u8>, value: u8) -> Result<u8, UnknownStateError> {
        match known {
            Some(k) => Ok(k & value),
            None => match self.unknown_policy {
                UnknownStatePolicy::ZeroFill => Ok(0),
                UnknownStatePolicy::Skip => Ok(value),
                UnknownStatePolicy::Error => Err(UnknownStateError::new(
                    "memory",
                    0,
                    "attempted to combine with unknown state",
                )),
            },
        }
    }
}

/// Callbacks for trace emulation integration.
///
/// Ported from Ghidra's `TraceEmulationIntegration.Writer`. These callbacks
/// are invoked during emulation to record state changes into the trace.
pub trait TraceEmulationCallbacks: Send + Sync {
    /// Called when a memory write occurs during emulation.
    fn on_memory_write(&self, space: &str, offset: u64, data: &[u8]);

    /// Called when a register write occurs during emulation.
    fn on_register_write(&self, thread_key: i64, register: &str, value: &[u8]);

    /// Called when the execution state changes.
    fn on_state_change(&self, thread_key: i64, state: &str);

    /// Called when a breakpoint is hit during emulation.
    fn on_breakpoint_hit(&self, offset: u64);

    /// Called when emulation completes.
    fn on_emulation_complete(&self);

    /// Called when emulation encounters an error.
    fn on_emulation_error(&self, message: &str);
}

/// Configuration for pcode executor state piece.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcodeExecutorStatePiece {
    /// The kind of state piece.
    pub kind: StatePieceKind,
    /// The trace ID.
    pub trace_id: String,
    /// The snap.
    pub snap: i64,
    /// The thread key (for register/thread state).
    pub thread_key: Option<i64>,
    /// The frame (for register state).
    pub frame: i32,
    /// Unknown state handling policy.
    pub unknown_policy: UnknownStatePolicy,
}

impl PcodeExecutorStatePiece {
    /// Create a memory state piece.
    pub fn memory(trace_id: impl Into<String>, snap: i64) -> Self {
        Self {
            kind: StatePieceKind::Memory,
            trace_id: trace_id.into(),
            snap,
            thread_key: None,
            frame: 0,
            unknown_policy: UnknownStatePolicy::default(),
        }
    }

    /// Create a register state piece.
    pub fn register(
        trace_id: impl Into<String>,
        snap: i64,
        thread_key: i64,
        frame: i32,
    ) -> Self {
        Self {
            kind: StatePieceKind::Register,
            trace_id: trace_id.into(),
            snap,
            thread_key: Some(thread_key),
            frame,
            unknown_policy: UnknownStatePolicy::default(),
        }
    }

    /// Set the unknown state policy.
    pub fn with_unknown_policy(mut self, policy: UnknownStatePolicy) -> Self {
        self.unknown_policy = policy;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_state_error() {
        let err = UnknownStateError::new("ram", 0x400000, "uninitialized");
        assert_eq!(err.space, "ram");
        assert_eq!(err.offset, 0x400000);
        assert!(err.to_string().contains("ram"));
        assert!(err.to_string().contains("uninitialized"));
    }

    #[test]
    fn test_addresses_read_state() {
        let mut state = AddressesReadState::new();
        assert!(state.is_empty());

        state.record_read("ram", 0x400000);
        state.record_read("ram", 0x400004);
        state.record_read("ram", 0x400000); // duplicate
        assert_eq!(state.len(), 2);
        assert!(state.was_read("ram", 0x400000));
        assert!(!state.was_read("ram", 0x500000));

        state.clear();
        assert!(state.is_empty());
    }

    #[test]
    fn test_trace_memory_state_arithmetic() {
        let arith = TraceMemoryStateArithmetic::new(UnknownStatePolicy::ZeroFill);
        assert_eq!(arith.combine(Some(0xff), 0x0f).unwrap(), 0x0f);
        assert_eq!(
            arith.combine(None, 0x0f).unwrap(),
            0
        ); // ZeroFill policy

        let arith = TraceMemoryStateArithmetic::new(UnknownStatePolicy::Error);
        assert!(arith.combine(None, 0x0f).is_err());

        let arith = TraceMemoryStateArithmetic::new(UnknownStatePolicy::Skip);
        assert_eq!(arith.combine(None, 0x0f).unwrap(), 0x0f);
    }

    #[test]
    fn test_pcode_executor_state_piece() {
        let mem = PcodeExecutorStatePiece::memory("trace1", 0);
        assert_eq!(mem.kind, StatePieceKind::Memory);
        assert!(mem.thread_key.is_none());

        let regs = PcodeExecutorStatePiece::register("trace1", 0, 42, 0)
            .with_unknown_policy(UnknownStatePolicy::ZeroFill);
        assert_eq!(regs.kind, StatePieceKind::Register);
        assert_eq!(regs.thread_key, Some(42));
        assert_eq!(regs.unknown_policy, UnknownStatePolicy::ZeroFill);
    }

    #[test]
    fn test_unknown_state_policy_default() {
        assert_eq!(UnknownStatePolicy::default(), UnknownStatePolicy::Error);
    }

    #[test]
    fn test_state_piece_serde() {
        let piece = PcodeExecutorStatePiece::memory("trace1", 0);
        let json = serde_json::to_string(&piece).unwrap();
        let back: PcodeExecutorStatePiece = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, StatePieceKind::Memory);
    }
}
