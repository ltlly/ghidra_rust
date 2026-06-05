//! TraceConflictedMappingException - exception for conflicting static mappings.
//!
//! Ported from Ghidra's `TraceConflictedMappingException` in
//! `ghidra.trace.model.modules`.
//!
//! Thrown when an attempt to create a static mapping would conflict with
//! existing mappings in the trace.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// An error indicating that a proposed static mapping conflicts with existing mappings.
///
/// Thrown when adding a mapping that would overlap existing mappings
/// in the same address range and lifespan.
#[derive(Debug, Clone, Error, Serialize, Deserialize)]
#[error("conflicted mapping: {message}")]
pub struct TraceConflictedMappingException {
    /// A human-readable message describing the conflict.
    pub message: String,
    /// The trace-side minimum address of the conflicting mapping.
    pub trace_min_addr: u64,
    /// The trace-side maximum address of the conflicting mapping.
    pub trace_max_addr: u64,
    /// The program-side minimum address of the conflicting mapping.
    pub program_min_addr: u64,
    /// The program-side maximum address of the conflicting mapping.
    pub program_max_addr: u64,
    /// The lifespan of the conflicting mapping.
    pub from_snap: i64,
    /// The end snap of the conflicting mapping.
    pub to_snap: i64,
}

impl TraceConflictedMappingException {
    /// Create a new conflict exception.
    pub fn new(
        message: impl Into<String>,
        trace_min_addr: u64,
        trace_max_addr: u64,
        program_min_addr: u64,
        program_max_addr: u64,
        from_snap: i64,
        to_snap: i64,
    ) -> Self {
        Self {
            message: message.into(),
            trace_min_addr,
            trace_max_addr,
            program_min_addr,
            program_max_addr,
            from_snap,
            to_snap,
        }
    }

    /// Create a simple conflict exception with a message only.
    pub fn with_message(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            trace_min_addr: 0,
            trace_max_addr: 0,
            program_min_addr: 0,
            program_max_addr: 0,
            from_snap: 0,
            to_snap: 0,
        }
    }

    /// Get the trace-side address range as (min, max).
    pub fn trace_range(&self) -> (u64, u64) {
        (self.trace_min_addr, self.trace_max_addr)
    }

    /// Get the program-side address range as (min, max).
    pub fn program_range(&self) -> (u64, u64) {
        (self.program_min_addr, self.program_max_addr)
    }

    /// Get the length of the conflicting range on the trace side.
    pub fn trace_length(&self) -> u64 {
        self.trace_max_addr.saturating_sub(self.trace_min_addr).saturating_add(1)
    }
}

/// A snapshot of a mapping conflict for serialization/display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingConflictInfo {
    /// The trace address range start.
    pub trace_start: u64,
    /// The trace address range length.
    pub trace_length: u64,
    /// The program address range start.
    pub program_start: u64,
    /// The program address range length.
    pub program_length: u64,
    /// The start snap.
    pub from_snap: i64,
    /// The end snap.
    pub to_snap: i64,
    /// Description of the conflict.
    pub description: String,
}

impl MappingConflictInfo {
    /// Create from a conflict exception.
    pub fn from_exception(exc: &TraceConflictedMappingException) -> Self {
        Self {
            trace_start: exc.trace_min_addr,
            trace_length: exc.trace_length(),
            program_start: exc.program_min_addr,
            program_length: exc.program_max_addr.saturating_sub(exc.program_min_addr).saturating_add(1),
            from_snap: exc.from_snap,
            to_snap: exc.to_snap,
            description: exc.message.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conflict_exception_display() {
        let exc = TraceConflictedMappingException::new(
            "overlapping mapping",
            0x1000, 0x1FFF,
            0x400000, 0x400FFF,
            0, 10,
        );
        let msg = format!("{}", exc);
        assert!(msg.contains("overlapping mapping"));
    }

    #[test]
    fn test_conflict_exception_ranges() {
        let exc = TraceConflictedMappingException::new(
            "conflict",
            0x1000, 0x1FFF,
            0x400000, 0x400FFF,
            0, 10,
        );
        assert_eq!(exc.trace_range(), (0x1000, 0x1FFF));
        assert_eq!(exc.program_range(), (0x400000, 0x400FFF));
        assert_eq!(exc.trace_length(), 0x1000);
    }

    #[test]
    fn test_conflict_with_message_only() {
        let exc = TraceConflictedMappingException::with_message("simple conflict");
        assert_eq!(exc.message, "simple conflict");
        assert_eq!(exc.trace_min_addr, 0);
    }

    #[test]
    fn test_mapping_conflict_info() {
        let exc = TraceConflictedMappingException::new(
            "test",
            0x1000, 0x1FFF,
            0x400000, 0x400FFF,
            5, 15,
        );
        let info = MappingConflictInfo::from_exception(&exc);
        assert_eq!(info.trace_start, 0x1000);
        assert_eq!(info.trace_length, 0x1000);
        assert_eq!(info.from_snap, 5);
        assert_eq!(info.to_snap, 15);
    }

    #[test]
    fn test_conflict_is_clone() {
        let exc = TraceConflictedMappingException::with_message("cloneable");
        let exc2 = exc.clone();
        assert_eq!(exc.message, exc2.message);
    }
}
