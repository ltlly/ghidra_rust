//! Extended trace emulation state types ported from Java.
//!
//! Ported from `TraceMemoryStatePcodeExecutorStatePiece` and
//! `TraceMemoryStatePcodeArithmetic` in Framework-TraceModeling.
//! Provides the state piece and arithmetic for pcode emulation
//! backed by trace memory.

use std::collections::BTreeMap;

/// The state of a single memory byte during trace emulation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceByteState {
    /// Byte value is known (concrete).
    Known(u8),
    /// Byte value is unknown (not recorded in trace).
    Unknown,
    /// Byte is from a different snap (not the current context).
    DifferentSnap,
}

impl TraceByteState {
    /// Check if the byte state is known.
    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known(_))
    }

    /// Get the byte value if known.
    pub fn value(&self) -> Option<u8> {
        match self {
            Self::Known(v) => Some(*v),
            _ => None,
        }
    }

    /// Create a known byte state.
    pub fn known(value: u8) -> Self {
        Self::Known(value)
    }

    /// The unknown singleton.
    pub fn unknown() -> Self {
        Self::Unknown
    }
}

/// A state piece for trace-backed memory during pcode execution.
///
/// Tracks the state of memory bytes at a given snap, distinguishing
/// between known (written), unknown (never written), and stale
/// (from different snap) values.
#[derive(Debug, Clone, Default)]
pub struct TraceMemoryStatePiece {
    /// Memory state keyed by (space_name, offset).
    state: BTreeMap<(String, u64), TraceByteState>,
    /// The snap this state is evaluated at.
    pub snap: i64,
    /// Whether this piece has been modified from the trace.
    dirty: bool,
}

impl TraceMemoryStatePiece {
    /// Create a new state piece for the given snap.
    pub fn new(snap: i64) -> Self {
        Self {
            state: BTreeMap::new(),
            snap,
            dirty: false,
        }
    }

    /// Set the state of a byte at the given address.
    pub fn set_state(&mut self, space: &str, offset: u64, state: TraceByteState) {
        self.state.insert((space.to_string(), offset), state);
        self.dirty = true;
    }

    /// Get the state of a byte at the given address.
    pub fn get_state(&self, space: &str, offset: u64) -> TraceByteState {
        self.state
            .get(&(space.to_string(), offset))
            .copied()
            .unwrap_or(TraceByteState::Unknown)
    }

    /// Write a concrete byte value.
    pub fn write_byte(&mut self, space: &str, offset: u64, value: u8) {
        self.set_state(space, offset, TraceByteState::Known(value));
    }

    /// Write a sequence of bytes starting at the given offset.
    pub fn write_bytes(&mut self, space: &str, start_offset: u64, bytes: &[u8]) {
        for (i, &byte) in bytes.iter().enumerate() {
            self.write_byte(space, start_offset + i as u64, byte);
        }
    }

    /// Read a byte value.
    pub fn read_byte(&self, space: &str, offset: u64) -> TraceByteState {
        self.get_state(space, offset)
    }

    /// Read a sequence of bytes.
    pub fn read_bytes(&self, space: &str, start_offset: u64, count: usize) -> Vec<TraceByteState> {
        (0..count)
            .map(|i| self.read_byte(space, start_offset + i as u64))
            .collect()
    }

    /// Check if all bytes in a range are known.
    pub fn all_known(&self, space: &str, offset: u64, count: usize) -> bool {
        (0..count).all(|i| {
            self.get_state(space, offset + i as u64).is_known()
        })
    }

    /// Check if this piece has been modified.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Clear the dirty flag.
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }

    /// Get the number of tracked bytes.
    pub fn len(&self) -> usize {
        self.state.len()
    }

    /// Check if this piece has no tracked bytes.
    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }

    /// Get all known offsets in a given space.
    pub fn known_offsets(&self, space: &str) -> Vec<u64> {
        self.state
            .iter()
            .filter(|((s, _), state)| s == space && state.is_known())
            .map(|((_, offset), _)| *offset)
            .collect()
    }

    /// Merge another state piece into this one (other takes precedence).
    pub fn merge_from(&mut self, other: &TraceMemoryStatePiece) {
        for ((space, offset), state) in &other.state {
            self.state.insert((space.clone(), *offset), *state);
        }
        self.dirty = true;
    }
}

/// Arithmetic operations on trace memory state.
///
/// Ported from `TraceMemoryStatePcodeArithmetic`. Provides pcode
/// arithmetic operations that work with trace-backed memory state,
/// handling both known and unknown byte values.
pub struct TraceMemoryStateArithmetic;

impl TraceMemoryStateArithmetic {
    /// Add two byte values, returning Unknown if either is unknown.
    pub fn add(a: TraceByteState, b: TraceByteState) -> TraceByteState {
        match (a, b) {
            (TraceByteState::Known(a), TraceByteState::Known(b)) => {
                TraceByteState::Known(a.wrapping_add(b))
            }
            _ => TraceByteState::Unknown,
        }
    }

    /// Subtract two byte values.
    pub fn sub(a: TraceByteState, b: TraceByteState) -> TraceByteState {
        match (a, b) {
            (TraceByteState::Known(a), TraceByteState::Known(b)) => {
                TraceByteState::Known(a.wrapping_sub(b))
            }
            _ => TraceByteState::Unknown,
        }
    }

    /// Bitwise AND of two byte values.
    pub fn and(a: TraceByteState, b: TraceByteState) -> TraceByteState {
        match (a, b) {
            (TraceByteState::Known(a), TraceByteState::Known(b)) => {
                TraceByteState::Known(a & b)
            }
            _ => TraceByteState::Unknown,
        }
    }

    /// Bitwise OR of two byte values.
    pub fn or(a: TraceByteState, b: TraceByteState) -> TraceByteState {
        match (a, b) {
            (TraceByteState::Known(a), TraceByteState::Known(b)) => {
                TraceByteState::Known(a | b)
            }
            _ => TraceByteState::Unknown,
        }
    }

    /// Bitwise XOR of two byte values.
    pub fn xor(a: TraceByteState, b: TraceByteState) -> TraceByteState {
        match (a, b) {
            (TraceByteState::Known(a), TraceByteState::Known(b)) => {
                TraceByteState::Known(a ^ b)
            }
            _ => TraceByteState::Unknown,
        }
    }

    /// Bitwise NOT of a byte value.
    pub fn not(a: TraceByteState) -> TraceByteState {
        match a {
            TraceByteState::Known(v) => TraceByteState::Known(!v),
            _ => TraceByteState::Unknown,
        }
    }

    /// Multi-byte addition (little-endian).
    pub fn add_multibyte(a: &[TraceByteState], b: &[TraceByteState]) -> Vec<TraceByteState> {
        let len = a.len().max(b.len());
        let mut result = Vec::with_capacity(len);
        let mut carry = false;

        for i in 0..len {
            let av = a.get(i).copied().unwrap_or(TraceByteState::Known(0));
            let bv = b.get(i).copied().unwrap_or(TraceByteState::Known(0));

            match (av, bv) {
                (TraceByteState::Known(av), TraceByteState::Known(bv)) => {
                    let sum = (av as u16) + (bv as u16) + if carry { 1 } else { 0 };
                    result.push(TraceByteState::Known(sum as u8));
                    carry = sum > 0xFF;
                }
                _ => {
                    result.push(TraceByteState::Unknown);
                    carry = false;
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_state() {
        assert!(TraceByteState::known(0x42).is_known());
        assert!(!TraceByteState::Unknown.is_known());
        assert_eq!(TraceByteState::known(0x42).value(), Some(0x42));
        assert_eq!(TraceByteState::Unknown.value(), None);
    }

    #[test]
    fn test_state_piece_basic() {
        let mut piece = TraceMemoryStatePiece::new(0);
        piece.write_byte("ram", 0x1000, 0x55);
        assert_eq!(piece.read_byte("ram", 0x1000), TraceByteState::Known(0x55));
        assert_eq!(piece.read_byte("ram", 0x2000), TraceByteState::Unknown);
    }

    #[test]
    fn test_write_read_bytes() {
        let mut piece = TraceMemoryStatePiece::new(0);
        piece.write_bytes("ram", 0x1000, &[0x01, 0x02, 0x03]);

        let states = piece.read_bytes("ram", 0x1000, 3);
        assert_eq!(states.len(), 3);
        assert_eq!(states[0], TraceByteState::Known(0x01));
        assert_eq!(states[2], TraceByteState::Known(0x03));

        assert!(piece.all_known("ram", 0x1000, 3));
        assert!(!piece.all_known("ram", 0x1000, 4));
    }

    #[test]
    fn test_arithmetic() {
        let a = TraceByteState::Known(10);
        let b = TraceByteState::Known(20);
        assert_eq!(TraceMemoryStateArithmetic::add(a, b), TraceByteState::Known(30));
        assert_eq!(TraceMemoryStateArithmetic::sub(b, a), TraceByteState::Known(10));
        assert_eq!(
            TraceMemoryStateArithmetic::and(TraceByteState::Known(0xFF), TraceByteState::Known(0x0F)),
            TraceByteState::Known(0x0F)
        );

        // Unknown propagation
        assert_eq!(
            TraceMemoryStateArithmetic::add(a, TraceByteState::Unknown),
            TraceByteState::Unknown
        );
    }

    #[test]
    fn test_multibyte_add() {
        let a = vec![TraceByteState::Known(0xFF), TraceByteState::Known(0x00)];
        let b = vec![TraceByteState::Known(0x01), TraceByteState::Known(0x00)];
        let result = TraceMemoryStateArithmetic::add_multibyte(&a, &b);
        assert_eq!(result[0], TraceByteState::Known(0x00));
        assert_eq!(result[1], TraceByteState::Known(0x01)); // carry
    }

    #[test]
    fn test_merge() {
        let mut piece1 = TraceMemoryStatePiece::new(0);
        piece1.write_byte("ram", 0x1000, 0x11);

        let mut piece2 = TraceMemoryStatePiece::new(1);
        piece2.write_byte("ram", 0x1000, 0x22);
        piece2.write_byte("ram", 0x2000, 0x33);

        piece1.merge_from(&piece2);
        assert_eq!(piece1.read_byte("ram", 0x1000), TraceByteState::Known(0x22));
        assert_eq!(piece1.read_byte("ram", 0x2000), TraceByteState::Known(0x33));
    }
}
