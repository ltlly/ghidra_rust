//! TraceMemoryState pcode executor state piece.
//!
//! Ported from Ghidra's `TraceMemoryStatePcodeExecutorStatePiece` and
//! `TraceMemoryStatePcodeArithmetic` from Framework-TraceModeling.
//! This module provides a state piece that tracks the known/unknown
//! status of memory regions during pcode emulation.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::TraceMemoryState;

/// Arithmetic operations on `TraceMemoryState` values.
///
/// Ported from Ghidra's `TraceMemoryStatePcodeArithmetic`. This arithmetic
/// treats memory states as a simple taint propagation: if any input is
/// `UNKNOWN`, the result is `UNKNOWN`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct TraceMemoryStateArithmetic;

impl TraceMemoryStateArithmetic {
    /// The singleton instance.
    pub const INSTANCE: Self = Self;

    /// Combine two states: if both are known, result is known; otherwise unknown.
    pub fn combine(a: TraceMemoryState, b: TraceMemoryState) -> TraceMemoryState {
        if a == TraceMemoryState::Known && b == TraceMemoryState::Known {
            TraceMemoryState::Known
        } else {
            TraceMemoryState::Unknown
        }
    }

    /// Combine an iterator of states.
    pub fn combine_all<'a, I: IntoIterator<Item = &'a TraceMemoryState>>(
        states: I,
    ) -> TraceMemoryState {
        for state in states {
            if *state != TraceMemoryState::Known {
                return TraceMemoryState::Unknown;
            }
        }
        TraceMemoryState::Known
    }

    /// Check if a state is known.
    pub fn is_known(state: TraceMemoryState) -> bool {
        state == TraceMemoryState::Known
    }

    /// Check if a state is unknown.
    pub fn is_unknown(state: TraceMemoryState) -> bool {
        state == TraceMemoryState::Unknown
    }
}

/// A sparse interval map tracking memory state (known/unknown) over
/// address ranges.
///
/// Used by the trace memory state piece to track which address ranges
/// have known state in the unique (scratch) space.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StateSpanMap {
    /// Maps (start_offset, length) to state.
    entries: Vec<(u64, u64, TraceMemoryState)>,
}

impl StateSpanMap {
    /// Create an empty span map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the state for a given range.
    pub fn set(&mut self, offset: u64, size: u64, state: TraceMemoryState) {
        // Remove overlapping entries
        self.entries.retain(|(o, s, _)| {
            let end = o + s;
            let new_end = offset + size;
            // Keep if no overlap
            *o >= new_end || end <= offset
        });
        self.entries.push((offset, size, state));
        self.entries.sort_by_key(|(o, _, _)| *o);
    }

    /// Get the composite state for a given range.
    ///
    /// Returns `Known` only if the entire range is covered by `Known`
    /// entries. Otherwise returns `Unknown`.
    pub fn get(&self, offset: u64, size: u64) -> TraceMemoryState {
        let end = offset + size;
        let mut covered_start = offset;

        for &(entry_offset, entry_size, ref entry_state) in &self.entries {
            let entry_end = entry_offset + entry_size;

            if entry_end <= offset || entry_offset >= end {
                continue; // No overlap with our range
            }

            // If any overlapping entry is unknown, the result is unknown
            if *entry_state != TraceMemoryState::Known {
                return TraceMemoryState::Unknown;
            }

            // Track coverage
            if entry_offset <= covered_start {
                covered_start = covered_start.max(entry_end);
            }
        }

        if covered_start >= end {
            TraceMemoryState::Known
        } else {
            TraceMemoryState::Unknown
        }
    }

    /// Remove all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// A pcode executor state piece for `TraceMemoryState`.
///
/// Ported from Ghidra's `TraceMemoryStatePcodeExecutorStatePiece`.
/// This piece tracks the known/unknown status of memory and register
/// addresses. It is used as an auxiliary to a concrete trace-bound state
/// to implement taint-like analysis during emulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceMemoryStatePiece {
    /// The trace ID.
    pub trace_id: String,
    /// State tracking for the unique address space.
    pub unique_state: StateSpanMap,
    /// State tracking per address space (by space name).
    pub space_states: BTreeMap<String, StateSpanMap>,
    /// Default state for uninitialized addresses.
    pub default_state: TraceMemoryState,
}

impl TraceMemoryStatePiece {
    /// Create a new trace memory state piece.
    pub fn new(trace_id: impl Into<String>) -> Self {
        Self {
            trace_id: trace_id.into(),
            unique_state: StateSpanMap::new(),
            space_states: BTreeMap::new(),
            default_state: TraceMemoryState::Unknown,
        }
    }

    /// Set the state for an address range in the unique space.
    pub fn set_unique(&mut self, offset: u64, size: u64, state: TraceMemoryState) {
        self.unique_state.set(offset, size, state);
    }

    /// Get the state for an address range in the unique space.
    pub fn get_unique(&self, offset: u64, size: u64) -> TraceMemoryState {
        self.unique_state.get(offset, size)
    }

    /// Set the state for an address range in a named space.
    pub fn set_in_space(
        &mut self,
        space: &str,
        offset: u64,
        size: u64,
        state: TraceMemoryState,
    ) {
        self.space_states
            .entry(space.to_string())
            .or_default()
            .set(offset, size, state);
    }

    /// Get the state for an address range in a named space.
    pub fn get_in_space(&self, space: &str, offset: u64, size: u64) -> TraceMemoryState {
        match self.space_states.get(space) {
            Some(map) => map.get(offset, size),
            None => self.default_state,
        }
    }

    /// Get the composite state across all known spaces.
    pub fn get_composite(&self, space: &str, offset: u64, size: u64) -> TraceMemoryState {
        if space == "unique" {
            self.get_unique(offset, size)
        } else {
            self.get_in_space(space, offset, size)
        }
    }

    /// Clear all state.
    pub fn clear(&mut self) {
        self.unique_state.clear();
        self.space_states.clear();
    }

    /// Fork this state piece (create a copy for branching emulation).
    pub fn fork(&self) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_arithmetic_combine() {
        assert_eq!(
            TraceMemoryStateArithmetic::combine(TraceMemoryState::Known, TraceMemoryState::Known),
            TraceMemoryState::Known
        );
        assert_eq!(
            TraceMemoryStateArithmetic::combine(
                TraceMemoryState::Known,
                TraceMemoryState::Unknown
            ),
            TraceMemoryState::Unknown
        );
        assert_eq!(
            TraceMemoryStateArithmetic::combine(
                TraceMemoryState::Unknown,
                TraceMemoryState::Unknown
            ),
            TraceMemoryState::Unknown
        );
    }

    #[test]
    fn test_state_arithmetic_combine_all() {
        let known = TraceMemoryState::Known;
        let unknown = TraceMemoryState::Unknown;

        assert_eq!(
            TraceMemoryStateArithmetic::combine_all(&[known, known, known]),
            TraceMemoryState::Known
        );
        assert_eq!(
            TraceMemoryStateArithmetic::combine_all(&[known, unknown, known]),
            TraceMemoryState::Unknown
        );
    }

    #[test]
    fn test_state_span_map_basic() {
        let mut map = StateSpanMap::new();
        assert_eq!(map.get(0, 100), TraceMemoryState::Unknown);

        map.set(0, 100, TraceMemoryState::Known);
        assert_eq!(map.get(0, 100), TraceMemoryState::Known);
        assert_eq!(map.get(0, 200), TraceMemoryState::Unknown);
    }

    #[test]
    fn test_state_span_map_partial() {
        let mut map = StateSpanMap::new();
        map.set(0, 50, TraceMemoryState::Known);
        map.set(50, 50, TraceMemoryState::Known);

        // Range spanning both entries
        assert_eq!(map.get(0, 100), TraceMemoryState::Known);
    }

    #[test]
    fn test_state_span_map_overlap() {
        let mut map = StateSpanMap::new();
        map.set(0, 100, TraceMemoryState::Known);
        map.set(50, 100, TraceMemoryState::Unknown);

        // The second set overwrites the overlapping portion
        assert_eq!(map.get(0, 50), TraceMemoryState::Known);
        assert_eq!(map.get(50, 50), TraceMemoryState::Unknown);
    }

    #[test]
    fn test_trace_memory_state_piece() {
        let mut piece = TraceMemoryStatePiece::new("test");
        assert_eq!(
            piece.get_composite("ram", 0x400000, 4),
            TraceMemoryState::Unknown
        );

        piece.set_in_space("ram", 0x400000, 4, TraceMemoryState::Known);
        assert_eq!(
            piece.get_composite("ram", 0x400000, 4),
            TraceMemoryState::Known
        );
        // Outside the known range
        assert_eq!(
            piece.get_composite("ram", 0x500000, 4),
            TraceMemoryState::Unknown
        );
    }

    #[test]
    fn test_trace_memory_state_piece_unique() {
        let mut piece = TraceMemoryStatePiece::new("test");
        piece.set_unique(0x100, 8, TraceMemoryState::Known);
        assert_eq!(piece.get_unique(0x100, 8), TraceMemoryState::Known);
        assert_eq!(piece.get_unique(0x200, 8), TraceMemoryState::Unknown);
    }

    #[test]
    fn test_trace_memory_state_piece_fork() {
        let mut piece = TraceMemoryStatePiece::new("test");
        piece.set_in_space("ram", 0x400000, 4, TraceMemoryState::Known);

        let mut forked = piece.fork();
        forked.set_in_space("ram", 0x500000, 4, TraceMemoryState::Known);

        // Original should not be affected
        assert_eq!(
            piece.get_composite("ram", 0x500000, 4),
            TraceMemoryState::Unknown
        );
        // Forked should have both
        assert_eq!(
            forked.get_composite("ram", 0x400000, 4),
            TraceMemoryState::Known
        );
        assert_eq!(
            forked.get_composite("ram", 0x500000, 4),
            TraceMemoryState::Known
        );
    }

    #[test]
    fn test_trace_memory_state_piece_clear() {
        let mut piece = TraceMemoryStatePiece::new("test");
        piece.set_in_space("ram", 0x400000, 4, TraceMemoryState::Known);
        piece.set_unique(0x100, 8, TraceMemoryState::Known);

        piece.clear();
        assert_eq!(
            piece.get_composite("ram", 0x400000, 4),
            TraceMemoryState::Unknown
        );
        assert_eq!(piece.get_unique(0x100, 8), TraceMemoryState::Unknown);
    }

    #[test]
    fn test_state_arithmetic_is_known() {
        assert!(TraceMemoryStateArithmetic::is_known(TraceMemoryState::Known));
        assert!(!TraceMemoryStateArithmetic::is_known(TraceMemoryState::Unknown));
        assert!(TraceMemoryStateArithmetic::is_unknown(TraceMemoryState::Unknown));
    }
}
