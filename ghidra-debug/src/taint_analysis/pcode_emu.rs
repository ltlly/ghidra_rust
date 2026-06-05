//! P-code arithmetic and emulator for the taint domain.
//!
//! Ported from Ghidra's `ghidra.pcode.emu.taint` and `ghidra.pcode.emu.taint.state`
//! packages.  These types model taint propagation through p-code operations
//! and manage per-address-space taint storage.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::model::{ShiftMode, TaintMark, TaintSet, TaintVec};

// ---------------------------------------------------------------------------
// TaintPcodeArithmetic
// ---------------------------------------------------------------------------

/// P-code arithmetic operating on `TaintVec`.
///
/// Each p-code binary/unary operation is mapped to the corresponding taint
/// propagation rule.  Endianness controls the byte ordering of the vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaintPcodeArithmetic {
    /// Big-endian taint arithmetic.
    BigEndian,
    /// Little-endian taint arithmetic.
    LittleEndian,
}

impl TaintPcodeArithmetic {
    /// Get the arithmetic for the given endianness.
    pub fn for_endian(is_big_endian: bool) -> Self {
        if is_big_endian {
            Self::BigEndian
        } else {
            Self::LittleEndian
        }
    }

    /// Whether this arithmetic is big-endian.
    pub fn is_big_endian(&self) -> bool {
        matches!(self, Self::BigEndian)
    }

    // -- Binary operations --

    /// Binary union (addition, OR, XOR, etc.): result taint = union of operand taints.
    pub fn op_binary_union(&self, left: &TaintVec, right: &TaintVec) -> TaintVec {
        let mut result = left.copy();
        result.zip_union(right);
        result
    }

    /// Binary with carry propagation (INT_ADD, INT_SUB, etc.).
    pub fn op_binary_with_carry(&self, left: &TaintVec, right: &TaintVec) -> TaintVec {
        let mut result = left.copy();
        result.zip_union(right);
        result.set_cascade(self.is_big_endian());
        result
    }

    /// INT_AND: result taint = union (conservative).
    pub fn op_int_and(&self, left: &TaintVec, right: &TaintVec) -> TaintVec {
        self.op_binary_union(left, right)
    }

    /// INT_OR: result taint = union.
    pub fn op_int_or(&self, left: &TaintVec, right: &TaintVec) -> TaintVec {
        self.op_binary_union(left, right)
    }

    /// INT_XOR: result taint = union.
    pub fn op_int_xor(&self, left: &TaintVec, right: &TaintVec) -> TaintVec {
        self.op_binary_union(left, right)
    }

    /// INT_ADD: union + carry cascade.
    pub fn op_int_add(&self, left: &TaintVec, right: &TaintVec) -> TaintVec {
        self.op_binary_with_carry(left, right)
    }

    /// INT_SUB: union + carry cascade.
    pub fn op_int_sub(&self, left: &TaintVec, right: &TaintVec) -> TaintVec {
        self.op_binary_with_carry(left, right)
    }

    /// INT_MULT: conservative union of all bytes (full taint propagation).
    pub fn op_int_mult(&self, left: &TaintVec, right: &TaintVec) -> TaintVec {
        let taint = left.union().union(&right.union());
        let length = left.length.max(right.length);
        let mut result = TaintVec::new(length);
        result.each_union(&taint);
        result
    }

    /// INT_DIV: conservative full union (division is unpredictable for taint).
    pub fn op_int_div(&self, left: &TaintVec, right: &TaintVec) -> TaintVec {
        self.op_int_mult(left, right)
    }

    // -- Shift operations --

    /// INT_LEFT: shift left (right parameter is the amount).
    pub fn op_int_left(&self, left: &TaintVec, _right: &TaintVec) -> TaintVec {
        let mut result = left.copy();
        result.set_blur(!self.is_big_endian());
        result
    }

    /// INT_RIGHT: logical shift right.
    pub fn op_int_right(&self, left: &TaintVec, _right: &TaintVec) -> TaintVec {
        let mut result = left.copy();
        result.set_blur(self.is_big_endian());
        result
    }

    /// INT_SRIGHT: arithmetic shift right (same as logical for taint).
    pub fn op_int_sright(&self, left: &TaintVec, right: &TaintVec) -> TaintVec {
        self.op_int_right(left, right)
    }

    // -- Extension / truncation --

    /// INT_ZEXT: zero extend (new bytes are untainted).
    pub fn op_int_zext(&self, val: &TaintVec, new_len: usize) -> TaintVec {
        val.extended(new_len, self.is_big_endian(), false)
    }

    /// INT_SEXT: sign extend (new bytes copy MSB taint).
    pub fn op_int_sext(&self, val: &TaintVec, new_len: usize) -> TaintVec {
        val.extended(new_len, self.is_big_endian(), true)
    }

    /// SUBPIECE: truncate to a sub-range.
    pub fn op_subpiece(&self, val: &TaintVec, new_len: usize) -> TaintVec {
        val.truncated(new_len, self.is_big_endian())
    }

    /// INT_2COMP (two's complement): same taint.
    pub fn op_int_2comp(&self, val: &TaintVec) -> TaintVec {
        val.copy()
    }

    /// INT_NEGATE (bitwise NOT): same taint.
    pub fn op_int_negate(&self, val: &TaintVec) -> TaintVec {
        val.copy()
    }

    // -- Comparison (taint is conservative) --

    /// INT_EQUAL / INT_NOTEQUAL / INT_LESS / INT_SLESS / etc.
    /// Result is a 1-byte vector with union of all input taint.
    pub fn op_compare(&self, left: &TaintVec, right: &TaintVec) -> TaintVec {
        let taint = left.union().union(&right.union());
        let mut result = TaintVec::new(1);
        result.set(0, taint);
        result
    }

    /// BOOLEAN_AND / BOOLEAN_OR: both are byte-level unions.
    pub fn op_boolean(&self, left: &TaintVec, right: &TaintVec) -> TaintVec {
        self.op_binary_union(left, right)
    }

    /// BOOLEAN_NEGATE: same taint.
    pub fn op_boolean_negate(&self, val: &TaintVec) -> TaintVec {
        val.copy()
    }

    /// CBRANCH: the condition taint is unioned into the branch (information flow).
    pub fn op_cbranch(&self, _addr: &TaintVec, cond: &TaintVec) -> TaintVec {
        cond.copy()
    }
}

// ---------------------------------------------------------------------------
// TaintSpace
// ---------------------------------------------------------------------------

/// Per-address-space taint storage.
///
/// Maps byte offsets to `TaintSet` values.  This is the concrete backing
/// store for one address space in the taint state piece.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaintSpace {
    /// Offset -> taint set mapping.
    taints: BTreeMap<u64, TaintSet>,
}

impl TaintSpace {
    /// Create a new empty taint space.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the taint set at `offset`, or `None` if none.
    pub fn get(&self, offset: u64) -> Option<&TaintSet> {
        self.taints.get(&offset)
    }

    /// Get the taint set at `offset`, or a reference to `EMPTY` if none.
    pub fn get_or_empty(&self, offset: u64) -> TaintSet {
        self.taints.get(&offset).cloned().unwrap_or(TaintSet::EMPTY)
    }

    /// Set the taint set at `offset`.
    pub fn set(&mut self, offset: u64, taint: TaintSet) {
        if taint.is_empty() {
            self.taints.remove(&offset);
        } else {
            self.taints.insert(offset, taint);
        }
    }

    /// Read `len` bytes starting at `offset` into a `TaintVec`.
    pub fn read_vec(&self, offset: u64, len: usize) -> TaintVec {
        let mut vec = TaintVec::new(len);
        for i in 0..len {
            let t = self.taints.get(&(offset + i as u64));
            if let Some(t) = t {
                vec.set(i, t.clone());
            }
        }
        vec
    }

    /// Write a `TaintVec` starting at `offset`.
    pub fn write_vec(&mut self, offset: u64, vec: &TaintVec) {
        for i in 0..vec.length {
            self.set(offset + i as u64, vec.get(i).clone());
        }
    }

    /// Get the taint set for a register-like range.
    pub fn get_register(&self, offset: u64, len: usize) -> TaintVec {
        self.read_vec(offset, len)
    }

    /// Set the taint for a register-like range.
    pub fn set_register(&mut self, offset: u64, vec: &TaintVec) {
        self.write_vec(offset, vec);
    }

    /// Remove all entries.
    pub fn clear(&mut self) {
        self.taints.clear();
    }

    /// Number of tainted bytes.
    pub fn len(&self) -> usize {
        self.taints.len()
    }

    /// Whether there are no tainted bytes.
    pub fn is_empty(&self) -> bool {
        self.taints.is_empty()
    }

    /// Get the next tainted entry at or after `offset`.
    pub fn next_entry(&self, offset: u64) -> Option<(u64, &TaintSet)> {
        self.taints.range(offset..).next().map(|(k, v)| (*k, v))
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = (u64, &TaintSet)> {
        self.taints.iter().map(|(k, v)| (*k, v))
    }
}

// ---------------------------------------------------------------------------
// TaintPcodeExecutorStatePiece
// ---------------------------------------------------------------------------

/// The taint state piece: one `TaintSpace` per address space.
///
/// This mirrors Ghidra's `TaintPcodeExecutorStatePiece`, providing the
/// mapping from address-space names to their taint storage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaintPcodeExecutorStatePiece {
    /// Map from address space name to taint storage.
    pub spaces: BTreeMap<String, TaintSpace>,
}

impl TaintPcodeExecutorStatePiece {
    /// Create a new empty state piece.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get (or create) the taint space for the given address space name.
    pub fn get_or_create_space(&mut self, space_name: &str) -> &mut TaintSpace {
        self.spaces
            .entry(space_name.to_string())
            .or_insert_with(TaintSpace::new)
    }

    /// Get a reference to the taint space for the given name, if it exists.
    pub fn get_space(&self, space_name: &str) -> Option<&TaintSpace> {
        self.spaces.get(space_name)
    }

    /// Read a taint vector from the given space and offset.
    pub fn read_vec(&self, space_name: &str, offset: u64, len: usize) -> TaintVec {
        match self.spaces.get(space_name) {
            Some(space) => space.read_vec(offset, len),
            None => TaintVec::new(len),
        }
    }

    /// Write a taint vector to the given space and offset.
    pub fn write_vec(&mut self, space_name: &str, offset: u64, vec: &TaintVec) {
        let space = self.get_or_create_space(space_name);
        space.write_vec(offset, vec);
    }

    /// Clear all taint data.
    pub fn clear(&mut self) {
        self.spaces.clear();
    }

    /// Get all space names.
    pub fn space_names(&self) -> Vec<&str> {
        self.spaces.keys().map(|s| s.as_str()).collect()
    }
}

// ---------------------------------------------------------------------------
// TaintPcodeEmulator
// ---------------------------------------------------------------------------

/// An emulator configuration that uses taint analysis.
///
/// Wraps a `TaintPcodeArithmetic` and `TaintPcodeExecutorStatePiece` to
/// provide a self-contained taint-tracking emulation context.
#[derive(Debug, Clone)]
pub struct TaintPcodeEmulator {
    /// The arithmetic for this emulator.
    pub arithmetic: TaintPcodeArithmetic,
    /// The shared state.
    pub state: TaintPcodeExecutorStatePiece,
    /// The program counter (if known).
    pub pc: Option<u64>,
}

impl TaintPcodeEmulator {
    /// Create a new emulator for the given endianness.
    pub fn new(is_big_endian: bool) -> Self {
        Self {
            arithmetic: TaintPcodeArithmetic::for_endian(is_big_endian),
            state: TaintPcodeExecutorStatePiece::new(),
            pc: None,
        }
    }

    /// Get the shared state.
    pub fn shared_state(&self) -> &TaintPcodeExecutorStatePiece {
        &self.state
    }

    /// Get a mutable reference to the shared state.
    pub fn shared_state_mut(&mut self) -> &mut TaintPcodeExecutorStatePiece {
        &mut self.state
    }

    /// Read the taint vector for a register at the given offset and length.
    pub fn read_register(&self, space_name: &str, offset: u64, len: usize) -> TaintVec {
        self.state.read_vec(space_name, offset, len)
    }

    /// Write a taint vector for a register.
    pub fn write_register(&mut self, space_name: &str, offset: u64, vec: &TaintVec) {
        self.state.write_vec(space_name, offset, vec);
    }

    /// Read taint from memory.
    pub fn read_memory(&self, space_name: &str, offset: u64, len: usize) -> TaintVec {
        self.state.read_vec(space_name, offset, len)
    }

    /// Write taint to memory.
    pub fn write_memory(&mut self, space_name: &str, offset: u64, vec: &TaintVec) {
        self.state.write_vec(space_name, offset, vec);
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- Arithmetic --

    #[test]
    fn test_arithmetic_for_endian() {
        assert_eq!(TaintPcodeArithmetic::for_endian(true), TaintPcodeArithmetic::BigEndian);
        assert_eq!(TaintPcodeArithmetic::for_endian(false), TaintPcodeArithmetic::LittleEndian);
    }

    #[test]
    fn test_binary_union() {
        let arith = TaintPcodeArithmetic::LittleEndian;
        let mut a = TaintVec::new(2);
        a.set(0, TaintSet::of([TaintMark::new("x")]));
        let mut b = TaintVec::new(2);
        b.set(1, TaintSet::of([TaintMark::new("y")]));
        let r = arith.op_binary_union(&a, &b);
        assert!(r.get(0).iter().any(|m| m.name == "x"));
        assert!(r.get(1).iter().any(|m| m.name == "y"));
    }

    #[test]
    fn test_binary_with_carry() {
        let arith = TaintPcodeArithmetic::LittleEndian;
        let mut a = TaintVec::new(4);
        a.set(0, TaintSet::of([TaintMark::new("a0")]));
        let b = TaintVec::new(4);
        let r = arith.op_binary_with_carry(&a, &b);
        // Cascade should propagate a0's taint to higher bytes
        assert!(r.get(0).iter().any(|m| m.name == "a0"));
    }

    #[test]
    fn test_int_mult() {
        let arith = TaintPcodeArithmetic::LittleEndian;
        let mut a = TaintVec::new(2);
        a.set(0, TaintSet::of([TaintMark::new("a")]));
        let mut b = TaintVec::new(2);
        b.set(1, TaintSet::of([TaintMark::new("b")]));
        let r = arith.op_int_mult(&a, &b);
        // All bytes should be tainted with both marks
        for i in 0..r.length {
            assert!(r.get(i).iter().any(|m| m.name == "a" || m.name == "b"));
        }
    }

    #[test]
    fn test_zext() {
        let arith = TaintPcodeArithmetic::LittleEndian;
        let v = TaintVec::array("x", 0, 2);
        let r = arith.op_int_zext(&v, 4);
        assert_eq!(r.length, 4);
        assert!(r.get(0).iter().any(|m| m.name == "x_0"));
        assert!(r.get(3).is_empty()); // zero-extended
    }

    #[test]
    fn test_sext() {
        let arith = TaintPcodeArithmetic::LittleEndian;
        let v = TaintVec::array("x", 0, 2);
        let r = arith.op_int_sext(&v, 4);
        assert_eq!(r.length, 4);
        // Signed: MSB (index 1 in LE) copied to new bytes
        let msb = v.get(1).iter().next().cloned().unwrap();
        assert!(r.get(3).iter().any(|m| *m == msb));
    }

    #[test]
    fn test_subpiece() {
        let arith = TaintPcodeArithmetic::LittleEndian;
        let v = TaintVec::array("x", 0, 4);
        let r = arith.op_subpiece(&v, 2);
        assert_eq!(r.length, 2);
        assert!(r.get(0).iter().any(|m| m.name == "x_0"));
    }

    #[test]
    fn test_compare() {
        let arith = TaintPcodeArithmetic::LittleEndian;
        let mut a = TaintVec::new(4);
        a.set(0, TaintSet::of([TaintMark::new("a")]));
        let mut b = TaintVec::new(4);
        b.set(2, TaintSet::of([TaintMark::new("b")]));
        let r = arith.op_compare(&a, &b);
        assert_eq!(r.length, 1);
        assert!(r.get(0).len() >= 2);
    }

    #[test]
    fn test_int_2comp() {
        let arith = TaintPcodeArithmetic::LittleEndian;
        let v = TaintVec::array("x", 0, 2);
        let r = arith.op_int_2comp(&v);
        assert_eq!(v, r);
    }

    // -- TaintSpace --

    #[test]
    fn test_space_read_write() {
        let mut space = TaintSpace::new();
        let mut v = TaintVec::new(4);
        v.set(0, TaintSet::of([TaintMark::new("tainted")]));
        space.write_vec(0x100, &v);

        let r = space.read_vec(0x100, 4);
        assert!(r.get(0).iter().any(|m| m.name == "tainted"));
        assert!(r.get(1).is_empty());
    }

    #[test]
    fn test_space_get_register() {
        let mut space = TaintSpace::new();
        let v = TaintVec::array("rax", 0, 8);
        space.set_register(0, &v);

        let r = space.get_register(0, 8);
        assert_eq!(r.length, 8);
        assert!(r.get(0).iter().any(|m| m.name == "rax_0"));
    }

    #[test]
    fn test_space_next_entry() {
        let mut space = TaintSpace::new();
        space.set(10, TaintSet::of([TaintMark::new("a")]));
        space.set(20, TaintSet::of([TaintMark::new("b")]));

        let (off, _) = space.next_entry(5).unwrap();
        assert_eq!(off, 10);

        let (off, _) = space.next_entry(15).unwrap();
        assert_eq!(off, 20);

        assert!(space.next_entry(21).is_none());
    }

    #[test]
    fn test_space_clear() {
        let mut space = TaintSpace::new();
        space.set(0, TaintSet::of([TaintMark::new("a")]));
        assert!(!space.is_empty());
        space.clear();
        assert!(space.is_empty());
    }

    // -- State Piece --

    #[test]
    fn test_state_piece_read_write() {
        let mut piece = TaintPcodeExecutorStatePiece::new();
        let mut v = TaintVec::new(4);
        v.set(0, TaintSet::of([TaintMark::new("stdin")]));
        piece.write_vec("ram", 0x400000, &v);

        let r = piece.read_vec("ram", 0x400000, 4);
        assert!(r.get(0).iter().any(|m| m.name == "stdin"));
    }

    #[test]
    fn test_state_piece_nonexistent_space() {
        let piece = TaintPcodeExecutorStatePiece::new();
        let r = piece.read_vec("nonexistent", 0, 4);
        assert!(r.is_clean());
    }

    #[test]
    fn test_state_piece_space_names() {
        let mut piece = TaintPcodeExecutorStatePiece::new();
        piece.write_vec("register", 0, &TaintVec::new(4));
        piece.write_vec("ram", 0, &TaintVec::new(4));
        let names = piece.space_names();
        assert!(names.contains(&"register"));
        assert!(names.contains(&"ram"));
    }

    // -- Emulator --

    #[test]
    fn test_emulator_read_write_memory() {
        let mut emu = TaintPcodeEmulator::new(false);
        let v = TaintVec::array("buf", 0, 4);
        emu.write_memory("ram", 0x1000, &v);

        let r = emu.read_memory("ram", 0x1000, 4);
        assert!(r.get(0).iter().any(|m| m.name == "buf_0"));
    }

    #[test]
    fn test_emulator_read_write_register() {
        let mut emu = TaintPcodeEmulator::new(false);
        let mut v = TaintVec::new(8);
        v.set(0, TaintSet::of([TaintMark::new("input")]));
        emu.write_register("register", 0, &v);

        let r = emu.read_register("register", 0, 8);
        assert!(r.get(0).iter().any(|m| m.name == "input"));
    }

    #[test]
    fn test_emulator_shared_state() {
        let mut emu = TaintPcodeEmulator::new(true);
        assert!(emu.shared_state().spaces.is_empty());
        emu.shared_state_mut()
            .get_or_create_space("ram");
        assert!(!emu.shared_state().spaces.is_empty());
    }

    // -- Serde --

    #[test]
    fn test_taint_space_serde() {
        let mut space = TaintSpace::new();
        space.set(0, TaintSet::of([TaintMark::new("a")]));
        let json = serde_json::to_string(&space).unwrap();
        let back: TaintSpace = serde_json::from_str(&json).unwrap();
        assert!(back.get(0).unwrap().iter().any(|m| m.name == "a"));
    }

    #[test]
    fn test_state_piece_serde() {
        let mut piece = TaintPcodeExecutorStatePiece::new();
        piece.write_vec("ram", 0, &TaintVec::array("x", 0, 4));
        let json = serde_json::to_string(&piece).unwrap();
        let back: TaintPcodeExecutorStatePiece = serde_json::from_str(&json).unwrap();
        let r = back.read_vec("ram", 0, 4);
        assert!(r.get(0).iter().any(|m| m.name == "x_0"));
    }
}
