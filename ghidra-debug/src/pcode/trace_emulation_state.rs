//! Trace emulation state pieces and execution state management.
//!
//! Ported from Ghidra's `TraceMemoryStatePcodeExecutorStatePiece`,
//! `AddressesReadTracePcodeExecutorStatePiece`, and related types.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::model::TraceMemoryState;

/// A pcode state piece that tracks memory state during trace emulation.
///
/// This represents the abstract state of a pcode executor piece
/// (memory, register, etc.) during trace emulation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceMemoryStatePcodeExecutorStatePiece {
    /// Known bytes by (space, address).
    bytes: BTreeMap<(String, u64), u8>,
    /// State tracking by (space, address).
    states: BTreeMap<(String, u64), TraceMemoryState>,
    /// The set of addresses that were read during emulation.
    addresses_read: BTreeSet<(String, u64)>,
    /// The set of addresses that were written during emulation.
    addresses_written: BTreeSet<(String, u64)>,
}

impl TraceMemoryStatePcodeExecutorStatePiece {
    /// Create a new empty state piece.
    pub fn new() -> Self {
        Self::default()
    }

    /// Write a byte to the state.
    pub fn set_byte(&mut self, space: &str, addr: u64, val: u8) {
        let key = (space.to_string(), addr);
        self.bytes.insert(key.clone(), val);
        self.states.insert(key, TraceMemoryState::Known);
        self.addresses_written.insert((space.to_string(), addr));
    }

    /// Read a byte from the state.
    pub fn get_byte(&self, space: &str, addr: u64) -> (Option<u8>, TraceMemoryState) {
        let key = (space.to_string(), addr);
        let state = self.states.get(&key).copied().unwrap_or(TraceMemoryState::Unknown);
        (self.bytes.get(&key).copied(), state)
    }

    /// Mark an address as read.
    pub fn mark_read(&mut self, space: &str, addr: u64) {
        self.addresses_read.insert((space.to_string(), addr));
    }

    /// Get all addresses that were read.
    pub fn addresses_read(&self) -> &BTreeSet<(String, u64)> {
        &self.addresses_read
    }

    /// Get all addresses that were written.
    pub fn addresses_written(&self) -> &BTreeSet<(String, u64)> {
        &self.addresses_written
    }

    /// Number of known bytes.
    pub fn known_byte_count(&self) -> usize {
        self.bytes.len()
    }
}

/// Tracks which addresses were read during pcode trace execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddressesReadTracePcodeExecutorStatePiece {
    /// The set of addresses that were read, grouped by space.
    reads: BTreeMap<String, BTreeSet<u64>>,
}

impl AddressesReadTracePcodeExecutorStatePiece {
    /// Create a new address tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a read at the given address.
    pub fn record_read(&mut self, space: &str, addr: u64) {
        self.reads
            .entry(space.to_string())
            .or_default()
            .insert(addr);
    }

    /// Check if an address was read.
    pub fn was_read(&self, space: &str, addr: u64) -> bool {
        self.reads
            .get(space)
            .map(|addrs| addrs.contains(&addr))
            .unwrap_or(false)
    }

    /// Get all addresses read in a space.
    pub fn reads_in_space(&self, space: &str) -> Option<&BTreeSet<u64>> {
        self.reads.get(space)
    }

    /// Total number of unique addresses read.
    pub fn total_reads(&self) -> usize {
        self.reads.values().map(|s| s.len()).sum()
    }

    /// All space names that had reads.
    pub fn spaces_with_reads(&self) -> impl Iterator<Item = &String> {
        self.reads.keys()
    }
}

/// An exception for unknown state during pcode execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnknownStatePcodeExecutionException {
    /// The space where the unknown state was encountered.
    pub space: String,
    /// The address where the unknown state was encountered.
    pub address: u64,
    /// A human-readable message.
    pub message: String,
}

impl UnknownStatePcodeExecutionException {
    /// Create a new exception.
    pub fn new(space: impl Into<String>, address: u64, message: impl Into<String>) -> Self {
        Self {
            space: space.into(),
            address,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for UnknownStatePcodeExecutionException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Unknown state at {}:{:#x}: {}",
            self.space, self.address, self.message
        )
    }
}

impl std::error::Error for UnknownStatePcodeExecutionException {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_piece_rw() {
        let mut piece = TraceMemoryStatePcodeExecutorStatePiece::new();
        piece.set_byte("ram", 0x100, 0x42);
        let (val, state) = piece.get_byte("ram", 0x100);
        assert_eq!(val, Some(0x42));
        assert_eq!(state, TraceMemoryState::Known);
        assert_eq!(piece.known_byte_count(), 1);
    }

    #[test]
    fn test_addresses_read_tracker() {
        let mut tracker = AddressesReadTracePcodeExecutorStatePiece::new();
        tracker.record_read("ram", 0x100);
        tracker.record_read("ram", 0x200);
        tracker.record_read("register", 0x0);
        assert!(tracker.was_read("ram", 0x100));
        assert!(!tracker.was_read("ram", 0x300));
        assert_eq!(tracker.total_reads(), 3);
    }

    #[test]
    fn test_unknown_state_exception() {
        let e = UnknownStatePcodeExecutionException::new("ram", 0x100, "byte not observed");
        assert_eq!(e.space, "ram");
        assert_eq!(e.address, 0x100);
        let display = format!("{}", e);
        assert!(display.contains("ram:0x100"));
    }
}
