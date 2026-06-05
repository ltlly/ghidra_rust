//! Per-space reference storage for the trace database.
//!
//! Ported from Ghidra's `DBTraceReferenceSpace` in
//! `ghidra.trace.database.symbol`. Manages references within a single
//! address space, with snap-based indexing.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;
use crate::db::trace_db_reference_manager::TraceReferenceKind;

/// A reference within a specific address space.
///
/// This is a more compact representation than `TraceReferenceEntry`,
/// scoped to a single address space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceReference {
    /// From offset within the space.
    pub from_offset: u64,
    /// To offset (may be in a different space, encoded as a relative ref).
    pub to_offset: u64,
    /// The reference kind.
    pub kind: TraceReferenceKind,
    /// Whether this is primary.
    pub is_primary: bool,
    /// Operand index.
    pub operand_index: i32,
    /// Snap range.
    pub min_snap: i64,
    pub max_snap: i64,
}

impl SpaceReference {
    /// Whether this reference is active at the given snap.
    pub fn is_active_at(&self, snap: i64) -> bool {
        snap >= self.min_snap && snap <= self.max_snap
    }

    /// Get the lifespan.
    pub fn lifespan(&self) -> Lifespan {
        Lifespan::span(self.min_snap, self.max_snap)
    }
}

/// Per-address-space reference storage.
///
/// Ported from Ghidra's `DBTraceReferenceSpace`.
#[derive(Debug)]
pub struct DbTraceReferenceSpace {
    /// The address space name.
    pub space: String,
    /// References indexed by from-offset.
    from_refs: BTreeMap<u64, Vec<SpaceReference>>,
    /// References indexed by to-offset.
    to_refs: BTreeMap<u64, Vec<SpaceReference>>,
}

impl DbTraceReferenceSpace {
    /// Create a new reference space.
    pub fn new(space: impl Into<String>) -> Self {
        Self {
            space: space.into(),
            from_refs: BTreeMap::new(),
            to_refs: BTreeMap::new(),
        }
    }

    /// Add a reference.
    pub fn add(&mut self, reference: SpaceReference) {
        self.from_refs
            .entry(reference.from_offset)
            .or_default()
            .push(reference.clone());
        self.to_refs
            .entry(reference.to_offset)
            .or_default()
            .push(reference);
    }

    /// Get references from an offset.
    pub fn get_from(&self, offset: u64) -> Option<&Vec<SpaceReference>> {
        self.from_refs.get(&offset)
    }

    /// Get references to an offset.
    pub fn get_to(&self, offset: u64) -> Option<&Vec<SpaceReference>> {
        self.to_refs.get(&offset)
    }

    /// Get references from an offset that are active at a given snap.
    pub fn get_from_at(&self, offset: u64, snap: i64) -> Vec<&SpaceReference> {
        self.from_refs
            .get(&offset)
            .map(|refs| refs.iter().filter(|r| r.is_active_at(snap)).collect())
            .unwrap_or_default()
    }

    /// Get references to an offset that are active at a given snap.
    pub fn get_to_at(&self, offset: u64, snap: i64) -> Vec<&SpaceReference> {
        self.to_refs
            .get(&offset)
            .map(|refs| refs.iter().filter(|r| r.is_active_at(snap)).collect())
            .unwrap_or_default()
    }

    /// Get all offsets that have references from them.
    pub fn from_offsets(&self) -> impl Iterator<Item = &u64> {
        self.from_refs.keys()
    }

    /// Get all offsets that have references to them.
    pub fn to_offsets(&self) -> impl Iterator<Item = &u64> {
        self.to_refs.keys()
    }

    /// Total number of references.
    pub fn count(&self) -> usize {
        self.from_refs.values().map(|v| v.len()).sum()
    }

    /// Clear all references.
    pub fn clear(&mut self) {
        self.from_refs.clear();
        self.to_refs.clear();
    }
}

/// A snap-selected view of references for a particular time.
#[derive(Debug)]
pub struct DbTraceSnapSelectedReferenceSpace<'a> {
    space: &'a DbTraceReferenceSpace,
    snap: i64,
}

impl<'a> DbTraceSnapSelectedReferenceSpace<'a> {
    /// Create a new snap-selected reference space.
    pub fn new(space: &'a DbTraceReferenceSpace, snap: i64) -> Self {
        Self { space, snap }
    }

    /// Get references from an offset at the selected snap.
    pub fn get_from(&self, offset: u64) -> Vec<&SpaceReference> {
        self.space.get_from_at(offset, self.snap)
    }

    /// Get references to an offset at the selected snap.
    pub fn get_to(&self, offset: u64) -> Vec<&SpaceReference> {
        self.space.get_to_at(offset, self.snap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ref(from: u64, to: u64, min_snap: i64, max_snap: i64) -> SpaceReference {
        SpaceReference {
            from_offset: from,
            to_offset: to,
            kind: TraceReferenceKind::Flow,
            is_primary: true,
            operand_index: -1,
            min_snap,
            max_snap,
        }
    }

    #[test]
    fn test_reference_space_add_and_get() {
        let mut space = DbTraceReferenceSpace::new("ram");
        space.add(make_ref(0x1000, 0x2000, 0, 100));
        space.add(make_ref(0x1000, 0x3000, 0, 100));
        let from = space.get_from(0x1000).unwrap();
        assert_eq!(from.len(), 2);
    }

    #[test]
    fn test_reference_space_get_to() {
        let mut space = DbTraceReferenceSpace::new("ram");
        space.add(make_ref(0x1000, 0x2000, 0, 100));
        let to = space.get_to(0x2000).unwrap();
        assert_eq!(to.len(), 1);
        assert_eq!(to[0].from_offset, 0x1000);
    }

    #[test]
    fn test_reference_space_snap_filter() {
        let mut space = DbTraceReferenceSpace::new("ram");
        space.add(make_ref(0x1000, 0x2000, 0, 50));
        space.add(make_ref(0x1000, 0x3000, 60, 100));
        let at_25 = space.get_from_at(0x1000, 25);
        assert_eq!(at_25.len(), 1);
        let at_75 = space.get_from_at(0x1000, 75);
        assert_eq!(at_75.len(), 1);
        assert_eq!(at_75[0].to_offset, 0x3000);
    }

    #[test]
    fn test_snap_selected_reference_space() {
        let mut space = DbTraceReferenceSpace::new("ram");
        space.add(make_ref(0x1000, 0x2000, 0, 50));
        space.add(make_ref(0x1000, 0x3000, 60, 100));
        let selected = DbTraceSnapSelectedReferenceSpace::new(&space, 25);
        let refs = selected.get_from(0x1000);
        assert_eq!(refs.len(), 1);
    }

    #[test]
    fn test_reference_space_count() {
        let mut space = DbTraceReferenceSpace::new("ram");
        space.add(make_ref(0x1000, 0x2000, 0, 100));
        space.add(make_ref(0x1000, 0x3000, 0, 100));
        space.add(make_ref(0x2000, 0x4000, 0, 100));
        assert_eq!(space.count(), 3);
    }

    #[test]
    fn test_reference_space_clear() {
        let mut space = DbTraceReferenceSpace::new("ram");
        space.add(make_ref(0x1000, 0x2000, 0, 100));
        assert_eq!(space.count(), 1);
        space.clear();
        assert_eq!(space.count(), 0);
    }
}
