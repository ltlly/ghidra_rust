//! Taint storage space ported from Java.
//!
//! Ported from `TaintSpace` in the Debugger module's `taint` package.
//! Stores taint marks for a single address space during taint analysis
//! of emulated execution.

use std::collections::BTreeMap;

/// A taint set represents the set of taint marks on a value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaintSet {
    /// The taint mark IDs.
    marks: Vec<u32>,
}

impl TaintSet {
    /// Create an empty taint set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a taint set with a single mark.
    pub fn single(mark: u32) -> Self {
        Self { marks: vec![mark] }
    }

    /// Add a taint mark.
    pub fn add(&mut self, mark: u32) {
        if !self.marks.contains(&mark) {
            self.marks.push(mark);
        }
    }

    /// Remove a taint mark.
    pub fn remove(&mut self, mark: u32) {
        self.marks.retain(|&m| m != mark);
    }

    /// Check if this set contains a mark.
    pub fn contains(&self, mark: u32) -> bool {
        self.marks.contains(&mark)
    }

    /// Check if this set is empty.
    pub fn is_empty(&self) -> bool {
        self.marks.is_empty()
    }

    /// Get the number of marks.
    pub fn len(&self) -> usize {
        self.marks.len()
    }

    /// Compute the union of two taint sets.
    pub fn union(&self, other: &TaintSet) -> TaintSet {
        let mut result = self.clone();
        for &mark in &other.marks {
            result.add(mark);
        }
        result
    }

    /// Compute the intersection of two taint sets.
    pub fn intersection(&self, other: &TaintSet) -> TaintSet {
        let marks: Vec<u32> = self.marks.iter()
            .filter(|m| other.contains(**m))
            .copied()
            .collect();
        TaintSet { marks }
    }

    /// Get all marks as a slice.
    pub fn marks(&self) -> &[u32] {
        &self.marks
    }
}

/// Storage space for taint sets in a single address space.
///
/// Ported from `TaintSpace`. Stores taint marks and associated pcode
/// operations for memory locations in a single address space.
#[derive(Debug, Clone, Default)]
pub struct TaintSpace {
    /// The address space name.
    pub space_name: String,
    /// Taint sets keyed by offset.
    taints: BTreeMap<u64, TaintSet>,
    /// Associated pcode operations keyed by offset.
    ops: BTreeMap<u64, Vec<u8>>,
}

impl TaintSpace {
    /// Create a new taint space.
    pub fn new(space_name: impl Into<String>) -> Self {
        Self {
            space_name: space_name.into(),
            taints: BTreeMap::new(),
            ops: BTreeMap::new(),
        }
    }

    /// Set taint for a byte at the given offset.
    pub fn set_taint(&mut self, offset: u64, taint: TaintSet) {
        self.taints.insert(offset, taint);
    }

    /// Get the taint set for a byte at the given offset.
    pub fn get_taint(&self, offset: u64) -> TaintSet {
        self.taints.get(&offset).cloned().unwrap_or_default()
    }

    /// Mark a vector of bytes starting at offset with taint marks.
    pub fn mark_vector(&mut self, start_offset: u64, taints: &[TaintSet]) {
        for (i, taint) in taints.iter().enumerate() {
            let offset = start_offset + i as u64;
            let existing = self.taints.entry(offset).or_default();
            *existing = existing.union(taint);
        }
    }

    /// Record a pcode operation at the given offset.
    pub fn record_op(&mut self, offset: u64, op_bytes: Vec<u8>) {
        self.ops.insert(offset, op_bytes);
    }

    /// Get the pcode operation at the given offset.
    pub fn get_op(&self, offset: u64) -> Option<&[u8]> {
        self.ops.get(&offset).map(|v| v.as_slice())
    }

    /// Get all tainted offsets.
    pub fn tainted_offsets(&self) -> Vec<u64> {
        self.taints.keys().copied().collect()
    }

    /// Get the number of tainted locations.
    pub fn tainted_count(&self) -> usize {
        self.taints.len()
    }

    /// Clear all taints in this space.
    pub fn clear(&mut self) {
        self.taints.clear();
        self.ops.clear();
    }

    /// Get all taints as a reference to the internal map.
    pub fn all_taints(&self) -> &BTreeMap<u64, TaintSet> {
        &self.taints
    }

    /// Merge taints from another space into this one.
    pub fn merge_from(&mut self, other: &TaintSpace) {
        for (offset, taint) in &other.taints {
            let existing = self.taints.entry(*offset).or_default();
            *existing = existing.union(taint);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_taint_set() {
        let mut ts = TaintSet::new();
        assert!(ts.is_empty());

        ts.add(1);
        ts.add(2);
        ts.add(3);
        ts.add(2); // duplicate
        assert_eq!(ts.len(), 3);
        assert!(ts.contains(2));
    }

    #[test]
    fn test_taint_set_union() {
        let mut a = TaintSet::new();
        a.add(1);
        a.add(2);

        let mut b = TaintSet::new();
        b.add(2);
        b.add(3);

        let u = a.union(&b);
        assert_eq!(u.len(), 3);
        assert!(u.contains(1));
        assert!(u.contains(2));
        assert!(u.contains(3));
    }

    #[test]
    fn test_taint_set_intersection() {
        let mut a = TaintSet::new();
        a.add(1);
        a.add(2);
        a.add(3);

        let mut b = TaintSet::new();
        b.add(2);
        b.add(3);
        b.add(4);

        let i = a.intersection(&b);
        assert_eq!(i.len(), 2);
        assert!(i.contains(2));
        assert!(i.contains(3));
    }

    #[test]
    fn test_taint_space() {
        let mut space = TaintSpace::new("ram");
        assert_eq!(space.space_name, "ram");

        space.set_taint(0x1000, TaintSet::single(1));
        space.set_taint(0x1001, TaintSet::single(2));

        assert!(space.get_taint(0x1000).contains(1));
        assert!(space.get_taint(0x2000).is_empty());
        assert_eq!(space.tainted_count(), 2);
    }

    #[test]
    fn test_mark_vector() {
        let mut space = TaintSpace::new("ram");
        let taints = vec![
            TaintSet::single(1),
            TaintSet::single(1),
            TaintSet::single(2),
        ];
        space.mark_vector(0x1000, &taints);

        assert!(space.get_taint(0x1000).contains(1));
        assert!(space.get_taint(0x1002).contains(2));
    }

    #[test]
    fn test_merge() {
        let mut space1 = TaintSpace::new("ram");
        space1.set_taint(0x1000, TaintSet::single(1));

        let mut space2 = TaintSpace::new("ram");
        space2.set_taint(0x1000, TaintSet::single(2));
        space2.set_taint(0x2000, TaintSet::single(3));

        space1.merge_from(&space2);
        let taint = space1.get_taint(0x1000);
        assert!(taint.contains(1));
        assert!(taint.contains(2));
        assert!(space1.get_taint(0x2000).contains(3));
    }
}
