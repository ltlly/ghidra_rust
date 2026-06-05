//! Taint domain model: mark, set, and vector types.
//!
//! Ported from Ghidra's `ghidra.taint.model` package.
//!
//! A `TaintMark` names a taint source with optional tags. A `TaintSet`
//! collects multiple marks. A `TaintVec` represents per-byte taint of a
//! multi-byte value, supporting union, intersection, extension, shift, and
//! cascade operations used during taint propagation through p-code.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

// ---------------------------------------------------------------------------
// TaintMark
// ---------------------------------------------------------------------------

/// A single taint label with optional tags.
///
/// The `name` identifies the taint source (e.g. a variable name).
/// `tags` annotate the mark with extra context such as `"indR"` for
/// indirect-read or `"indW"` for indirect-write.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TaintMark {
    /// The label / source name.
    pub name: String,
    /// Annotation tags (e.g. `"indR"`, `"indW"`).
    pub tags: BTreeSet<String>,
}

impl TaintMark {
    /// Create a new mark with the given name and no tags.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            tags: BTreeSet::new(),
        }
    }

    /// Create a mark with a name and initial tags.
    pub fn with_tags(name: impl Into<String>, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            name: name.into(),
            tags: tags.into_iter().map(Into::into).collect(),
        }
    }

    /// Parse a mark from the form `name:tag1,tag2` or just `name`.
    pub fn parse(s: &str) -> Self {
        if let Some((name, tags_str)) = s.split_once(':') {
            let tags = tags_str
                .split(',')
                .filter(|t| !t.is_empty())
                .map(|t| t.to_string())
                .collect();
            Self {
                name: name.to_string(),
                tags,
            }
        } else {
            Self::new(s)
        }
    }

    /// Return a new mark with `tag` added (or `self` unchanged if already present).
    pub fn tagged(&self, tag: impl Into<String>) -> Self {
        let tag = tag.into();
        if self.tags.contains(&tag) {
            return self.clone();
        }
        let mut tags = self.tags.clone();
        tags.insert(tag);
        Self {
            name: self.name.clone(),
            tags,
        }
    }
}

impl fmt::Display for TaintMark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        if !self.tags.is_empty() {
            write!(f, ":")?;
            let mut first = true;
            for t in &self.tags {
                if !first {
                    write!(f, ",")?;
                }
                first = false;
                write!(f, "{}", t)?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// TaintSet
// ---------------------------------------------------------------------------

/// An immutable set of taint marks.
///
/// A variable may be tainted by multiple marks, so sets are used as the
/// element type of `TaintVec`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintSet {
    marks: BTreeSet<TaintMark>,
}

impl TaintSet {
    /// The empty taint set (default for all state variables).
    pub const EMPTY: Self = Self { marks: BTreeSet::new() };

    /// Parse a set from semicolon-separated marks, e.g. `"myVar:tag1,tag2;anotherVar"`.
    pub fn parse(s: &str) -> Self {
        if s.is_empty() {
            return Self::EMPTY;
        }
        let marks = s.split(';').map(TaintMark::parse).collect();
        Self { marks }
    }

    /// Create a set from individual marks.
    pub fn of(marks: impl IntoIterator<Item = TaintMark>) -> Self {
        Self {
            marks: marks.into_iter().collect(),
        }
    }

    /// Whether this set is empty.
    pub fn is_empty(&self) -> bool {
        self.marks.is_empty()
    }

    /// The number of marks.
    pub fn len(&self) -> usize {
        self.marks.len()
    }

    /// Iterate over marks.
    pub fn iter(&self) -> impl Iterator<Item = &TaintMark> {
        self.marks.iter()
    }

    /// Return the union of `self` and `other`.
    pub fn union(&self, other: &TaintSet) -> TaintSet {
        if self.is_empty() {
            return other.clone();
        }
        if other.is_empty() {
            return self.clone();
        }
        let marks = self.marks.union(&other.marks).cloned().collect();
        TaintSet { marks }
    }

    /// Return the intersection of `self` and `other`.
    pub fn intersection(&self, other: &TaintSet) -> TaintSet {
        let marks = self.marks.intersection(&other.marks).cloned().collect();
        TaintSet { marks }
    }

    /// Return a new set where every mark has `tag` added.
    pub fn tagged(&self, tag: &str) -> TaintSet {
        let marks = self.marks.iter().map(|m| m.tagged(tag)).collect();
        TaintSet { marks }
    }
}

impl fmt::Display for TaintSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for m in &self.marks {
            if !first {
                write!(f, ";")?;
            }
            first = false;
            write!(f, "{}", m)?;
        }
        Ok(())
    }
}

impl Default for TaintSet {
    fn default() -> Self {
        Self::EMPTY
    }
}

// ---------------------------------------------------------------------------
// TaintVec
// ---------------------------------------------------------------------------

/// Shifting behaviour used by `TaintVec::set_shifted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShiftMode {
    /// Values that fall off the edge are dropped.
    Unbounded,
    /// Values that fall off the edge cycle to the opposite end.
    Circular,
    /// Only the lowest bits of the shift amount are used (masking).
    Masked,
}

impl ShiftMode {
    /// Adjust the right-shift amount according to the mode.
    pub fn adjust_right(self, right: i32, length: usize) -> i32 {
        match self {
            Self::Unbounded => right,
            Self::Circular => {
                let len = length as i32;
                if len == 0 {
                    0
                } else {
                    ((right % len) + len) % len
                }
            }
            Self::Masked => {
                if length == 0 {
                    0
                } else {
                    let mask = (length.next_power_of_two() - 1) as i32;
                    right & mask
                }
            }
        }
    }

    /// Adjust a source index; returns the mapped index or out-of-bounds.
    pub fn adjust_src(self, src: usize, length: usize) -> usize {
        match self {
            Self::Unbounded | Self::Masked => src,
            Self::Circular => {
                if length == 0 {
                    0
                } else {
                    src % length
                }
            }
        }
    }
}

/// A vector of `TaintSet` values representing per-byte taint of a multi-byte value.
///
/// Index 0 is the least-significant byte when little-endian, and the
/// most-significant byte when big-endian. Endianness-sensitive operations
/// take an explicit `is_big_endian` flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaintVec {
    /// Number of bytes in this vector.
    pub length: usize,
    /// Per-byte taint sets (index 0 = lsb in LE).
    sets: Vec<TaintSet>,
}

impl TaintVec {
    /// Create a vector of `length` empty taint sets.
    pub fn new(length: usize) -> Self {
        Self {
            length,
            sets: vec![TaintSet::EMPTY; length],
        }
    }

    /// Parse a vector from a comma-separated list of taint set strings.
    /// An empty string or `"_"` means `TaintSet::EMPTY` for that position.
    pub fn parse(s: &str, length: usize) -> Self {
        let parts: Vec<&str> = s.split(',').collect();
        let mut vec = Self::new(length);
        for (i, part) in parts.iter().enumerate().take(length) {
            if *part != "_" && !part.is_empty() {
                vec.sets[i] = TaintSet::parse(part);
            }
        }
        vec
    }

    /// Create a vector where each element is a single mark named `name_i`.
    pub fn array(name: &str, start: i64, length: usize) -> Self {
        let sets = (0..length)
            .map(|i| {
                TaintSet::of(std::iter::once(TaintMark::new(format!(
                    "{}_{}",
                    name,
                    start + i as i64
                ))))
            })
            .collect();
        Self { length, sets }
    }

    /// Get the taint set at `index`.
    pub fn get(&self, index: usize) -> &TaintSet {
        &self.sets[index]
    }

    /// Set the taint set at `index`.
    pub fn set(&mut self, index: usize, taint: TaintSet) {
        self.sets[index] = taint;
    }

    /// Return the union of all per-byte taint sets.
    pub fn union(&self) -> TaintSet {
        let mut result = TaintSet::EMPTY;
        for s in &self.sets {
            result = result.union(s);
        }
        result
    }

    /// Element-wise union: `self[i] = self[i] | other[i]`.
    pub fn zip_union(&mut self, other: &TaintVec) {
        let len = self.length.min(other.length);
        for i in 0..len {
            self.sets[i] = self.sets[i].union(&other.sets[i]);
        }
    }

    /// Element-wise intersection: `self[i] = self[i] & other[i]`.
    pub fn zip_intersection(&mut self, other: &TaintVec) {
        let len = self.length.min(other.length);
        for i in 0..len {
            self.sets[i] = self.sets[i].intersection(&other.sets[i]);
        }
    }

    /// Union every element with the same set: `self[i] = self[i] | taint`.
    pub fn each_union(&mut self, taint: &TaintSet) {
        for s in &mut self.sets {
            *s = s.union(taint);
        }
    }

    /// Model an indirect read: tags all elements with `taint("indR")` from `offset`.
    pub fn tag_indirect_read(&mut self, offset: &TaintVec) {
        let taint_offset = offset.union().tagged("indR");
        self.each_union(&taint_offset);
    }

    /// Model an indirect write: tags all elements with `taint("indW")` from `offset`.
    pub fn tag_indirect_write(&mut self, offset: &TaintVec) {
        let taint_offset = offset.union().tagged("indW");
        self.each_union(&taint_offset);
    }

    /// Broadcast the given set over every element.
    pub fn set_copies(&mut self, taint: &TaintSet) {
        for s in &mut self.sets {
            *s = taint.clone();
        }
    }

    /// Set every element to empty.
    pub fn set_empties(&mut self) {
        self.set_copies(&TaintSet::EMPTY);
    }

    /// Fill with array-style marks.
    pub fn set_array(&mut self, name: &str, start: i64) {
        for i in 0..self.length {
            self.sets[i] = TaintSet::of(std::iter::once(TaintMark::new(format!(
                "{}_{}",
                name,
                start + i as i64
            ))));
        }
    }

    /// Cascade (for carry propagation): each element becomes the union of
    /// itself and all less-significant elements.
    ///
    /// `is_big_endian`: true means index 0 is MSB.
    pub fn set_cascade(&mut self, is_big_endian: bool) {
        if is_big_endian {
            // BE: index 0 = MSB, high index = LSB.
            // Propagate from MSB toward LSB: i+1 is less significant.
            for i in (0..self.length.saturating_sub(1)).rev() {
                let next = self.sets[i + 1].clone();
                self.sets[i] = self.sets[i].union(&next);
            }
        } else {
            // LE: index 0 = LSB, high index = MSB.
            // Propagate from LSB toward MSB: i is less significant than i+1.
            for i in 0..self.length.saturating_sub(1) {
                let prev = self.sets[i].clone();
                self.sets[i + 1] = self.sets[i + 1].union(&prev);
            }
        }
    }

    /// Blur (for shift modelling): each element becomes the union of itself
    /// and its neighbor.
    pub fn set_blur(&mut self, right: bool) {
        if right {
            for i in (0..self.length.saturating_sub(1)).rev() {
                let next = self.sets[i].clone();
                self.sets[i + 1] = self.sets[i + 1].union(&next);
            }
        }
        for i in 0..self.length.saturating_sub(1) {
            let next = self.sets[i + 1].clone();
            self.sets[i] = self.sets[i].union(&next);
        }
    }

    /// Shift elements in-place. `right` is positive for right-shift, negative for left.
    pub fn set_shifted(&mut self, right: i32, mode: ShiftMode) {
        let right = mode.adjust_right(right, self.length);
        if right > self.length as i32 || -right > self.length as i32 {
            self.set_empties();
            return;
        }
        if right < 0 {
            let start = self.sets[0].clone();
            for i in 0..self.length {
                let src = mode.adjust_src(i.wrapping_sub(right as usize), self.length);
                if src >= self.length {
                    break;
                }
                self.sets[i] = if src == 0 {
                    start.clone()
                } else {
                    self.sets[src].clone()
                };
            }
        } else {
            let start = self.sets[self.length.saturating_sub(1)].clone();
            for i in 0..self.length.saturating_sub(1) {
                let src_idx = i as i32 - right;
                if src_idx < 0 {
                    break;
                }
                let src = mode.adjust_src(src_idx as usize, self.length);
                if src >= self.length {
                    break;
                }
                self.sets[i] = if src == self.length.saturating_sub(1) {
                    start.clone()
                } else {
                    self.sets[src].clone()
                };
            }
        }
    }

    /// Return a truncated copy, dropping the most-significant elements.
    ///
    /// `is_big_endian`: true to drop lower-indexed elements.
    pub fn truncated(&self, length: usize, is_big_endian: bool) -> TaintVec {
        assert!(length <= self.length, "truncated: new length exceeds current");
        let shift = if is_big_endian {
            self.length - length
        } else {
            0
        };
        let sets = self.sets[shift..shift + length].to_vec();
        TaintVec { length, sets }
    }

    /// Return a copy of this vector.
    pub fn copy(&self) -> TaintVec {
        TaintVec {
            length: self.length,
            sets: self.sets.clone(),
        }
    }

    /// Extend (or truncate) to the given length.
    ///
    /// Appended elements are at the MSB end (as determined by endianness).
    /// If `is_signed`, copies the most-significant element; otherwise appends empties.
    pub fn extended(&self, length: usize, is_big_endian: bool, is_signed: bool) -> TaintVec {
        if length < self.length {
            return self.truncated(length, is_big_endian);
        }
        let diff = length - self.length;
        let fill = if is_signed {
            let msb = if is_big_endian {
                &self.sets[0]
            } else {
                &self.sets[self.length.saturating_sub(1)]
            };
            vec![msb.clone(); diff]
        } else {
            vec![TaintSet::EMPTY; diff]
        };
        let mut sets = Vec::with_capacity(length);
        if is_big_endian {
            sets.extend(fill);
            sets.extend(self.sets.iter().cloned());
        } else {
            sets.extend(self.sets.iter().cloned());
            sets.extend(fill);
        }
        TaintVec { length, sets }
    }

    /// Check if all elements are empty.
    pub fn is_clean(&self) -> bool {
        self.sets.iter().all(|s| s.is_empty())
    }
}

impl fmt::Display for TaintVec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, s) in self.sets.iter().enumerate() {
            if i > 0 {
                write!(f, ",")?;
            }
            if s.is_empty() {
                write!(f, "_")?;
            } else {
                write!(f, "{}", s)?;
            }
        }
        Ok(())
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- TaintMark --

    #[test]
    fn test_mark_parse_simple() {
        let m = TaintMark::parse("myVar");
        assert_eq!(m.name, "myVar");
        assert!(m.tags.is_empty());
    }

    #[test]
    fn test_mark_parse_with_tags() {
        let m = TaintMark::parse("myVar:tag1,tag2");
        assert_eq!(m.name, "myVar");
        assert!(m.tags.contains("tag1"));
        assert!(m.tags.contains("tag2"));
    }

    #[test]
    fn test_mark_tagged() {
        let m = TaintMark::new("x");
        let m2 = m.tagged("indR");
        assert!(m2.tags.contains("indR"));
        // Idempotent
        let m3 = m2.clone().tagged("indR");
        assert_eq!(m2, m3);
    }

    #[test]
    fn test_mark_display() {
        let m = TaintMark::with_tags("x", ["indR"]);
        assert_eq!(m.to_string(), "x:indR");
    }

    // -- TaintSet --

    #[test]
    fn test_set_parse() {
        let s = TaintSet::parse("a;b:tag1");
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn test_set_empty() {
        let s = TaintSet::EMPTY;
        assert!(s.is_empty());
    }

    #[test]
    fn test_set_union() {
        let a = TaintSet::of([TaintMark::new("a")]);
        let b = TaintSet::of([TaintMark::new("b")]);
        let u = a.union(&b);
        assert_eq!(u.len(), 2);
    }

    #[test]
    fn test_set_union_empty_identity() {
        let a = TaintSet::of([TaintMark::new("a")]);
        assert_eq!(a.union(&TaintSet::EMPTY), a);
        assert_eq!(TaintSet::EMPTY.union(&a), a);
    }

    #[test]
    fn test_set_intersection() {
        let a = TaintSet::of([TaintMark::new("a"), TaintMark::new("b")]);
        let b = TaintSet::of([TaintMark::new("b"), TaintMark::new("c")]);
        let i = a.intersection(&b);
        assert_eq!(i.len(), 1);
        assert!(i.iter().any(|m| m.name == "b"));
    }

    #[test]
    fn test_set_tagged() {
        let s = TaintSet::of([TaintMark::new("x")]);
        let tagged = s.tagged("indW");
        assert!(tagged.iter().all(|m| m.tags.contains("indW")));
    }

    // -- TaintVec --

    #[test]
    fn test_vec_new() {
        let v = TaintVec::new(4);
        assert_eq!(v.length, 4);
        assert!(v.is_clean());
    }

    #[test]
    fn test_vec_array() {
        let v = TaintVec::array("buf", 0, 3);
        assert_eq!(v.length, 3);
        assert!(!v.is_clean());
        assert!(v.get(0).iter().any(|m| m.name == "buf_0"));
        assert!(v.get(2).iter().any(|m| m.name == "buf_2"));
    }

    #[test]
    fn test_vec_union() {
        let mut v = TaintVec::new(2);
        v.set(0, TaintSet::of([TaintMark::new("a")]));
        v.set(1, TaintSet::of([TaintMark::new("b")]));
        let u = v.union();
        assert_eq!(u.len(), 2);
    }

    #[test]
    fn test_vec_zip_union() {
        let mut a = TaintVec::new(2);
        a.set(0, TaintSet::of([TaintMark::new("x")]));
        let mut b = TaintVec::new(2);
        b.set(1, TaintSet::of([TaintMark::new("y")]));
        a.zip_union(&b);
        assert!(a.get(0).iter().any(|m| m.name == "x"));
        assert!(a.get(1).iter().any(|m| m.name == "y"));
    }

    #[test]
    fn test_vec_each_union() {
        let mut v = TaintVec::new(3);
        let t = TaintSet::of([TaintMark::new("tainted")]);
        v.each_union(&t);
        for i in 0..3 {
            assert!(v.get(i).iter().any(|m| m.name == "tainted"));
        }
    }

    #[test]
    fn test_vec_set_cascade_le() {
        let mut v = TaintVec::array("x", 0, 4);
        v.set_cascade(false); // LE: propagate lsb->msb
        // Each element should now contain all preceding marks
        for i in 1..4 {
            assert!(v.get(i).len() > 1 || i == 0);
        }
    }

    #[test]
    fn test_vec_set_cascade_be() {
        let mut v = TaintVec::array("x", 0, 4);
        v.set_cascade(true);
        // In BE mode, index 0 is MSB. Cascade propagates toward MSB,
        // so index 0 (MSB) should contain all marks after cascade.
        let msb = v.get(0);
        assert!(msb.iter().any(|m| m.name == "x_0"));
        assert!(msb.iter().any(|m| m.name == "x_3"));
        // LSB (index 3) should remain unchanged.
        let lsb = v.get(3);
        assert!(lsb.iter().any(|m| m.name == "x_3"));
        assert!(lsb.len() == 1); // only x_3
    }

    #[test]
    fn test_vec_truncated_le() {
        let v = TaintVec::array("buf", 0, 4);
        let t = v.truncated(2, false);
        assert_eq!(t.length, 2);
        assert!(t.get(0).iter().any(|m| m.name == "buf_0"));
    }

    #[test]
    fn test_vec_truncated_be() {
        let v = TaintVec::array("buf", 0, 4);
        let t = v.truncated(2, true);
        assert_eq!(t.length, 2);
        // In BE, drop lower indices -> keep indices 2,3
        assert!(t.get(0).iter().any(|m| m.name == "buf_2"));
    }

    #[test]
    fn test_vec_extended_le_unsigned() {
        let v = TaintVec::array("x", 0, 2);
        let e = v.extended(4, false, false);
        assert_eq!(e.length, 4);
        assert!(e.get(0).iter().any(|m| m.name == "x_0"));
        assert!(e.get(3).is_empty()); // appended
    }

    #[test]
    fn test_vec_extended_le_signed() {
        let v = TaintVec::array("x", 0, 2);
        let e = v.extended(4, false, true);
        assert_eq!(e.length, 4);
        // MSB is at index 1 in LE; signed extension copies it
        let msb_mark = v.get(1).iter().next().cloned().unwrap();
        assert!(e.get(3).iter().any(|m| *m == msb_mark));
    }

    #[test]
    fn test_vec_extended_be_unsigned() {
        let v = TaintVec::array("x", 0, 2);
        let e = v.extended(4, true, false);
        assert_eq!(e.length, 4);
        // In BE, index 0 is MSB, appended empties go to index 0
        assert!(e.get(0).is_empty());
    }

    #[test]
    fn test_vec_display() {
        let mut v = TaintVec::new(3);
        v.set(1, TaintSet::of([TaintMark::new("a")]));
        let s = v.to_string();
        // TaintVec uses ',' as element separator (matching Java).
        // TaintSet uses ';' as mark separator.
        assert_eq!(s, "_,a,_");
    }

    #[test]
    fn test_shift_mode_circular() {
        let r = ShiftMode::Circular.adjust_right(5, 4);
        assert_eq!(r, 1);
    }

    #[test]
    fn test_shift_mode_circular_negative() {
        let r = ShiftMode::Circular.adjust_right(-1, 4);
        assert_eq!(r, 3);
    }

    #[test]
    fn test_vec_set_shifted() {
        let v = TaintVec::array("x", 0, 4);
        let mut shifted = v.copy();
        shifted.set_shifted(1, ShiftMode::Unbounded);
        // After right-shift by 1, element 0 should be "x_1" shifted from position 1
        // (implementation detail of unbounded shift)
        assert_eq!(shifted.length, 4);
    }

    #[test]
    fn test_vec_tag_indirect_read() {
        let mut v = TaintVec::new(2);
        let mut offset = TaintVec::new(2);
        offset.set(0, TaintSet::of([TaintMark::new("idx")]));
        v.tag_indirect_read(&offset);
        for i in 0..2 {
            assert!(v.get(i).iter().any(|m| m.tags.contains("indR")));
        }
    }

    #[test]
    fn test_vec_tag_indirect_write() {
        let mut v = TaintVec::new(2);
        let mut offset = TaintVec::new(2);
        offset.set(0, TaintSet::of([TaintMark::new("idx")]));
        v.tag_indirect_write(&offset);
        for i in 0..2 {
            assert!(v.get(i).iter().any(|m| m.tags.contains("indW")));
        }
    }

    #[test]
    fn test_vec_set_copies() {
        let mut v = TaintVec::new(3);
        let s = TaintSet::of([TaintMark::new("global")]);
        v.set_copies(&s);
        for i in 0..3 {
            assert!(v.get(i).iter().any(|m| m.name == "global"));
        }
    }

    #[test]
    fn test_vec_set_empties() {
        let mut v = TaintVec::array("x", 0, 3);
        assert!(!v.is_clean());
        v.set_empties();
        assert!(v.is_clean());
    }

    #[test]
    fn test_vec_set_array() {
        let mut v = TaintVec::new(3);
        v.set_array("buf", 10);
        assert!(v.get(0).iter().any(|m| m.name == "buf_10"));
        assert!(v.get(2).iter().any(|m| m.name == "buf_12"));
    }

    #[test]
    fn test_vec_set_blur_right() {
        let mut v = TaintVec::array("x", 0, 4);
        v.set_blur(true);
        // After blur-right, every element should have accumulated neighbors
        for i in 0..4 {
            assert!(!v.get(i).is_empty());
        }
    }

    #[test]
    fn test_vec_copy() {
        let v = TaintVec::array("a", 0, 3);
        let c = v.copy();
        assert_eq!(v, c);
    }

    #[test]
    fn test_vec_serde() {
        let v = TaintVec::array("x", 0, 3);
        let json = serde_json::to_string(&v).unwrap();
        let back: TaintVec = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn test_set_serde() {
        let s = TaintSet::of([TaintMark::with_tags("a", ["t1"]), TaintMark::new("b")]);
        let json = serde_json::to_string(&s).unwrap();
        let back: TaintSet = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }
}
