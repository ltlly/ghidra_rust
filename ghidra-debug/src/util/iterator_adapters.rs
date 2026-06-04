//! Iterator adapters for traversing trace data.
//!
//! Ported from Ghidra's `ghidra.trace.util.Wrapping*Iterator` classes.
//! These adapters wrap various kinds of trace data iterators to provide
//! uniform iteration over instructions, code units, data, and functions.

use serde::{Deserialize, Serialize};

/// A code unit type, mirroring Ghidra's CodeUnit types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IteratorCodeUnitType {
    /// An instruction.
    Instruction,
    /// A defined data element.
    Data,
    /// An undefined area.
    Undefined,
}

/// An entry returned by an instruction iterator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstructionEntry {
    /// The address of the instruction.
    pub address: u64,
    /// The mnemonic (e.g., "MOV", "ADD").
    pub mnemonic: String,
    /// The length in bytes.
    pub length: u32,
    /// The raw bytes.
    pub bytes: Vec<u8>,
}

impl InstructionEntry {
    /// Create a new instruction entry.
    pub fn new(address: u64, mnemonic: impl Into<String>, length: u32, bytes: Vec<u8>) -> Self {
        Self {
            address,
            mnemonic: mnemonic.into(),
            length,
            bytes,
        }
    }

    /// Get the end address (exclusive).
    pub fn end_address(&self) -> u64 {
        self.address + self.length as u64
    }
}

/// An entry returned by a code unit iterator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeUnitEntry {
    /// The address.
    pub address: u64,
    /// The type of code unit.
    pub unit_type: IteratorCodeUnitType,
    /// The length in bytes.
    pub length: u32,
    /// A display label or mnemonic.
    pub label: String,
}

impl CodeUnitEntry {
    /// Create a new code unit entry.
    pub fn new(address: u64, unit_type: IteratorCodeUnitType, length: u32, label: impl Into<String>) -> Self {
        Self {
            address,
            unit_type,
            length,
            label: label.into(),
        }
    }
}

/// An entry returned by a function iterator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionEntry {
    /// The entry point address.
    pub entry: u64,
    /// The function name.
    pub name: String,
    /// The size in bytes (if known).
    pub size: Option<u32>,
    /// Whether this is a thunk.
    pub is_thunk: bool,
}

impl FunctionEntry {
    /// Create a new function entry.
    pub fn new(entry: u64, name: impl Into<String>) -> Self {
        Self {
            entry,
            name: name.into(),
            size: None,
            is_thunk: false,
        }
    }

    /// Set the function size.
    pub fn with_size(mut self, size: u32) -> Self {
        self.size = Some(size);
        self
    }

    /// Mark as thunk.
    pub fn as_thunk(mut self) -> Self {
        self.is_thunk = true;
        self
    }
}

/// A viewport span iterator that yields addresses within a visible range.
#[derive(Debug, Clone)]
pub struct TraceViewportSpanIterator {
    /// Minimum address (inclusive).
    pub min_address: u64,
    /// Maximum address (exclusive).
    pub max_address: u64,
    /// The snap at which to observe.
    pub snap: i64,
    current: u64,
    step: u64,
}

impl TraceViewportSpanIterator {
    /// Create a new viewport iterator over a range.
    pub fn new(min_address: u64, max_address: u64, snap: i64, step: u64) -> Self {
        Self {
            min_address,
            max_address,
            snap,
            current: min_address,
            step,
        }
    }
}

impl Iterator for TraceViewportSpanIterator {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.max_address {
            None
        } else {
            let addr = self.current;
            self.current = self.current.saturating_add(self.step);
            Some(addr)
        }
    }
}

/// An overlapping object iterator that detects overlaps in address ranges.
#[derive(Debug, Clone)]
pub struct OverlappingObjectIterator<T: Clone> {
    items: Vec<(u64, u64, T)>,
    current: usize,
}

impl<T: Clone> OverlappingObjectIterator<T> {
    /// Create a new overlap-detecting iterator from a sorted list of
    /// (start, end, value) triples.
    pub fn new(mut items: Vec<(u64, u64, T)>) -> Self {
        items.sort_by_key(|&(start, _, _)| start);
        Self { items, current: 0 }
    }
}

impl<T: Clone> Iterator for OverlappingObjectIterator<T> {
    type Item = (u64, u64, T);

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.items.len() {
            return None;
        }
        let item = self.items[self.current].clone();
        self.current += 1;
        Some(item)
    }
}

/// An empty function iterator that yields nothing.
#[derive(Debug, Clone, Default)]
pub struct EmptyFunctionIterator;

impl Iterator for EmptyFunctionIterator {
    type Item = FunctionEntry;

    fn next(&mut self) -> Option<Self::Item> {
        None
    }
}

/// An enumerating iterator that pairs items with their index.
#[derive(Debug, Clone)]
pub struct EnumeratingIterator<I> {
    inner: I,
    index: usize,
}

impl<I> EnumeratingIterator<I> {
    /// Wrap an iterator with enumeration.
    pub fn new(inner: I) -> Self {
        Self { inner, index: 0 }
    }
}

impl<I, T> Iterator for EnumeratingIterator<I>
where
    I: Iterator<Item = T>,
{
    type Item = (usize, T);

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.inner.next()?;
        let idx = self.index;
        self.index += 1;
        Some((idx, item))
    }
}

/// A copy-on-write wrapper for iterators that may need to clone their items.
#[derive(Debug)]
pub struct CopyOnWriteIter<T: Clone> {
    items: Vec<T>,
    current: usize,
}

impl<T: Clone> CopyOnWriteIter<T> {
    /// Create a new copy-on-write iterator from a vector.
    pub fn new(items: Vec<T>) -> Self {
        Self { items, current: 0 }
    }
}

impl<T: Clone> Iterator for CopyOnWriteIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.items.len() {
            None
        } else {
            let item = self.items[self.current].clone();
            self.current += 1;
            Some(item)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_entry() {
        let entry = InstructionEntry::new(0x401000, "NOP", 1, vec![0x90]);
        assert_eq!(entry.end_address(), 0x401001);
    }

    #[test]
    fn test_code_unit_entry() {
        let entry = CodeUnitEntry::new(0x401000, IteratorCodeUnitType::Instruction, 2, "MOV EAX, 0");
        assert_eq!(entry.address, 0x401000);
        assert_eq!(entry.unit_type, IteratorCodeUnitType::Instruction);
    }

    #[test]
    fn test_function_entry() {
        let entry = FunctionEntry::new(0x401000, "main").with_size(0x50);
        assert_eq!(entry.entry, 0x401000);
        assert_eq!(entry.size, Some(0x50));
        assert!(!entry.is_thunk);

        let thunk = FunctionEntry::new(0x402000, "__thunk").as_thunk();
        assert!(thunk.is_thunk);
    }

    #[test]
    fn test_viewport_span_iterator() {
        let mut iter = TraceViewportSpanIterator::new(0x1000, 0x1010, 0, 4);
        assert_eq!(iter.next(), Some(0x1000));
        assert_eq!(iter.next(), Some(0x1004));
        assert_eq!(iter.next(), Some(0x1008));
        assert_eq!(iter.next(), Some(0x100C));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_empty_function_iterator() {
        let mut iter = EmptyFunctionIterator;
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_enumerating_iterator() {
        let data = vec!["a", "b", "c"];
        let mut iter = EnumeratingIterator::new(data.into_iter());
        assert_eq!(iter.next(), Some((0, "a")));
        assert_eq!(iter.next(), Some((1, "b")));
        assert_eq!(iter.next(), Some((2, "c")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_overlapping_object_iterator() {
        let items = vec![
            (0x1000u64, 0x2000u64, "first"),
            (0x1500u64, 0x3000u64, "second"),
            (0x4000u64, 0x5000u64, "third"),
        ];
        let mut iter = OverlappingObjectIterator::new(items);
        assert_eq!(iter.next().unwrap().2, "first");
        assert_eq!(iter.next().unwrap().2, "second");
        assert_eq!(iter.next().unwrap().2, "third");
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_copy_on_write_iter() {
        let data = vec![1, 2, 3];
        let mut iter = CopyOnWriteIter::new(data);
        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), Some(2));
        assert_eq!(iter.next(), Some(3));
        assert_eq!(iter.next(), None);
    }
}
