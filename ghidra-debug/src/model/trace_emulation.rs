//! Trace emulation integration model.
//!
//! Ported from Ghidra's `TraceEmulationIntegration`.
//!
//! Provides the model types for integrating p-code emulation with
//! trace recording, including state snapshots and emulation callbacks.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// The mode of emulation integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EmulationMode {
    /// Emulate forward from the current state.
    Forward,
    /// Emulate backward (reverse execution).
    Backward,
    /// Record emulation state into trace.
    Record,
    /// Replay recorded trace without modifying.
    Replay,
}

/// The status of an emulation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EmulationStatus {
    /// Emulation has not started.
    NotStarted,
    /// Emulation is currently running.
    Running,
    /// Emulation is paused (e.g., at a breakpoint).
    Paused,
    /// Emulation completed successfully.
    Completed,
    /// Emulation was terminated (e.g., user action).
    Terminated,
    /// Emulation encountered an error.
    Error,
}

/// A snapshot of emulation state at a specific point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmulationStateSnapshot {
    /// The snap (time step) of this snapshot.
    pub snap: i64,
    /// The program counter value at this snapshot.
    pub program_counter: u64,
    /// The thread ID.
    pub thread_id: u64,
    /// Register name-value pairs (name -> bytes).
    pub register_values: Vec<(String, Vec<u8>)>,
    /// Memory regions that were written since last snapshot.
    pub modified_memory: Vec<(u64, Vec<u8>)>,
    /// The status of emulation at this point.
    pub status: EmulationStatus,
}

impl EmulationStateSnapshot {
    /// Create a new emulation state snapshot.
    pub fn new(snap: i64, program_counter: u64, thread_id: u64) -> Self {
        Self {
            snap,
            program_counter,
            thread_id,
            register_values: Vec::new(),
            modified_memory: Vec::new(),
            status: EmulationStatus::Running,
        }
    }

    /// Add a register value.
    pub fn add_register(&mut self, name: impl Into<String>, value: Vec<u8>) {
        self.register_values.push((name.into(), value));
    }

    /// Add modified memory.
    pub fn add_modified_memory(&mut self, offset: u64, data: Vec<u8>) {
        self.modified_memory.push((offset, data));
    }

    /// Get a register value by name.
    pub fn get_register(&self, name: &str) -> Option<&[u8]> {
        self.register_values
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    }
}

/// Integration configuration for emulation with trace recording.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEmulationIntegration {
    /// The emulation mode.
    pub mode: EmulationMode,
    /// The lifespan of the emulation.
    pub lifespan: Lifespan,
    /// Whether to take snapshots at each step.
    pub snapshot_every_step: bool,
    /// Maximum number of snapshots to keep.
    pub max_snapshots: usize,
    /// Whether to record memory writes.
    pub record_memory_writes: bool,
    /// Whether to record register changes.
    pub record_register_changes: bool,
    /// The collected snapshots.
    snapshots: Vec<EmulationStateSnapshot>,
    /// Current emulation status.
    status: EmulationStatus,
}

impl TraceEmulationIntegration {
    /// Create a new emulation integration.
    pub fn new(mode: EmulationMode) -> Self {
        Self {
            mode,
            lifespan: Lifespan::ALL,
            snapshot_every_step: true,
            max_snapshots: 10000,
            record_memory_writes: true,
            record_register_changes: true,
            snapshots: Vec::new(),
            status: EmulationStatus::NotStarted,
        }
    }

    /// Set the lifespan.
    pub fn with_lifespan(mut self, lifespan: Lifespan) -> Self {
        self.lifespan = lifespan;
        self
    }

    /// Set the maximum number of snapshots.
    pub fn with_max_snapshots(mut self, max: usize) -> Self {
        self.max_snapshots = max;
        self
    }

    /// Get the current emulation status.
    pub fn status(&self) -> EmulationStatus {
        self.status
    }

    /// Set the emulation status.
    pub fn set_status(&mut self, status: EmulationStatus) {
        self.status = status;
    }

    /// Record a state snapshot.
    pub fn record_snapshot(&mut self, snapshot: EmulationStateSnapshot) {
        if self.snapshots.len() >= self.max_snapshots {
            self.snapshots.remove(0);
        }
        self.snapshots.push(snapshot);
    }

    /// Get all recorded snapshots.
    pub fn snapshots(&self) -> &[EmulationStateSnapshot] {
        &self.snapshots
    }

    /// Get the number of recorded snapshots.
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Get the last snapshot.
    pub fn last_snapshot(&self) -> Option<&EmulationStateSnapshot> {
        self.snapshots.last()
    }

    /// Clear all snapshots.
    pub fn clear_snapshots(&mut self) {
        self.snapshots.clear();
    }

    /// Check if emulation is active (running or paused).
    pub fn is_active(&self) -> bool {
        matches!(
            self.status,
            EmulationStatus::Running | EmulationStatus::Paused
        )
    }

    /// Check if emulation has finished (completed, terminated, or error).
    pub fn is_finished(&self) -> bool {
        matches!(
            self.status,
            EmulationStatus::Completed | EmulationStatus::Terminated | EmulationStatus::Error
        )
    }
}

/// Error type for unknown pcode execution state.
#[derive(Debug, Clone, thiserror::Error)]
#[error("Unknown pcode execution state: {message}")]
pub struct UnknownStatePcodeExecutionException {
    /// Description of the unknown state.
    pub message: String,
    /// The address where the error occurred.
    pub address: Option<u64>,
    /// The snap where the error occurred.
    pub snap: Option<i64>,
}

impl UnknownStatePcodeExecutionException {
    /// Create a new exception.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            address: None,
            snap: None,
        }
    }

    /// Set the address context.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.address = Some(addr);
        self
    }

    /// Set the snap context.
    pub fn with_snap(mut self, snap: i64) -> Self {
        self.snap = Some(snap);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emulation_state_snapshot() {
        let mut snap = EmulationStateSnapshot::new(0, 0x400000, 1);
        snap.add_register("RAX", vec![0x42, 0, 0, 0, 0, 0, 0, 0]);
        snap.add_register("RSP", vec![0, 0, 0xF0, 0x7F, 0, 0, 0, 0]);
        snap.add_modified_memory(0x400000, vec![0x90]);

        assert_eq!(snap.snap, 0);
        assert_eq!(snap.program_counter, 0x400000);
        assert_eq!(snap.thread_id, 1);
        assert_eq!(snap.register_values.len(), 2);
        assert_eq!(snap.modified_memory.len(), 1);
        assert_eq!(snap.get_register("RAX"), Some([0x42, 0, 0, 0, 0, 0, 0, 0].as_slice()));
        assert_eq!(snap.get_register("RBX"), None);
    }

    #[test]
    fn test_trace_emulation_integration() {
        let mut integration = TraceEmulationIntegration::new(EmulationMode::Record);
        assert_eq!(integration.status(), EmulationStatus::NotStarted);
        assert!(!integration.is_active());
        assert!(!integration.is_finished());

        integration.set_status(EmulationStatus::Running);
        assert!(integration.is_active());
        assert!(!integration.is_finished());

        integration.set_status(EmulationStatus::Paused);
        assert!(integration.is_active());

        integration.set_status(EmulationStatus::Completed);
        assert!(!integration.is_active());
        assert!(integration.is_finished());
    }

    #[test]
    fn test_snapshot_recording() {
        let mut integration = TraceEmulationIntegration::new(EmulationMode::Forward)
            .with_max_snapshots(3);

        for i in 0..5 {
            let snap = EmulationStateSnapshot::new(i, 0x400000 + i as u64, 1);
            integration.record_snapshot(snap);
        }

        // Only last 3 should remain
        assert_eq!(integration.snapshot_count(), 3);
        assert_eq!(integration.snapshots()[0].snap, 2);
        assert_eq!(integration.last_snapshot().unwrap().snap, 4);
    }

    #[test]
    fn test_clear_snapshots() {
        let mut integration = TraceEmulationIntegration::new(EmulationMode::Forward);
        integration.record_snapshot(EmulationStateSnapshot::new(0, 0, 1));
        assert_eq!(integration.snapshot_count(), 1);
        integration.clear_snapshots();
        assert_eq!(integration.snapshot_count(), 0);
    }

    #[test]
    fn test_emulation_modes() {
        assert_ne!(EmulationMode::Forward, EmulationMode::Backward);
        assert_ne!(EmulationMode::Record, EmulationMode::Replay);
    }

    #[test]
    fn test_emulation_status() {
        assert_ne!(EmulationStatus::Running, EmulationStatus::Paused);
        assert_ne!(EmulationStatus::Completed, EmulationStatus::Error);
    }

    #[test]
    fn test_unknown_state_exception() {
        let exc = UnknownStatePcodeExecutionException::new("register unknown")
            .with_address(0x400000)
            .with_snap(5);
        assert!(exc.message.contains("register unknown"));
        assert_eq!(exc.address, Some(0x400000));
        assert_eq!(exc.snap, Some(5));
        assert!(format!("{}", exc).contains("register unknown"));
    }

    #[test]
    fn test_unknown_state_exception_minimal() {
        let exc = UnknownStatePcodeExecutionException::new("test");
        assert!(exc.address.is_none());
        assert!(exc.snap.is_none());
    }
}
