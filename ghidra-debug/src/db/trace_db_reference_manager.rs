//! Reference manager for the trace database.
//!
//! Ported from Ghidra's `DBTraceReferenceManager` in
//! `ghidra.trace.database.symbol`. Manages code references (from-address
//! to to-address) across all address spaces and time snaps.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// The kind of reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TraceReferenceKind {
    /// Unconditional flow (jump, call).
    Flow,
    /// Read access.
    Read,
    /// Write access.
    Write,
    /// Read-write access.
    ReadWrite,
    /// Conditional flow.
    ConditionalFlow,
}

impl TraceReferenceKind {
    /// Parse from string representation.
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "flow" => TraceReferenceKind::Flow,
            "read" => TraceReferenceKind::Read,
            "write" => TraceReferenceKind::Write,
            "readwrite" | "read_write" => TraceReferenceKind::ReadWrite,
            "conditionalflow" | "conditional_flow" => TraceReferenceKind::ConditionalFlow,
            _ => TraceReferenceKind::Flow,
        }
    }

    /// Get string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            TraceReferenceKind::Flow => "flow",
            TraceReferenceKind::Read => "read",
            TraceReferenceKind::Write => "write",
            TraceReferenceKind::ReadWrite => "readwrite",
            TraceReferenceKind::ConditionalFlow => "conditionalflow",
        }
    }
}

/// A code reference entry in the trace database.
///
/// Ported from Ghidra's `DBTraceReference` and its subclasses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceReferenceEntry {
    /// Database row ID.
    pub id: i64,
    /// From address space.
    pub from_space: String,
    /// From address offset.
    pub from_offset: u64,
    /// To address space.
    pub to_space: String,
    /// To address offset.
    pub to_offset: u64,
    /// The reference kind.
    pub kind: TraceReferenceKind,
    /// Whether this is the primary reference at the from-address.
    pub is_primary: bool,
    /// The operand index (-1 for address-level).
    pub operand_index: i32,
    /// The snap range.
    pub min_snap: i64,
    pub max_snap: i64,
}

impl TraceReferenceEntry {
    /// Create a new reference entry.
    pub fn new(
        id: i64,
        from_space: impl Into<String>,
        from_offset: u64,
        to_space: impl Into<String>,
        to_offset: u64,
        kind: TraceReferenceKind,
        is_primary: bool,
        operand_index: i32,
        min_snap: i64,
        max_snap: i64,
    ) -> Self {
        Self {
            id,
            from_space: from_space.into(),
            from_offset,
            to_space: to_space.into(),
            to_offset,
            kind,
            is_primary,
            operand_index,
            min_snap,
            max_snap,
        }
    }

    /// Get the from-address as (space, offset).
    pub fn from_address(&self) -> (&str, u64) {
        (&self.from_space, self.from_offset)
    }

    /// Get the to-address as (space, offset).
    pub fn to_address(&self) -> (&str, u64) {
        (&self.to_space, self.to_offset)
    }

    /// Get the lifespan of this reference.
    pub fn lifespan(&self) -> Lifespan {
        Lifespan::span(self.min_snap, self.max_snap)
    }

    /// Whether this reference is active at the given snap.
    pub fn is_active_at(&self, snap: i64) -> bool {
        snap >= self.min_snap && snap <= self.max_snap
    }
}

/// A memory address reference (offset-based, for the common case).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceOffsetReference {
    /// Database row ID.
    pub id: i64,
    /// From address offset.
    pub from_offset: u64,
    /// To address offset.
    pub to_offset: u64,
    /// The reference kind.
    pub kind: TraceReferenceKind,
    /// Whether this is the primary reference.
    pub is_primary: bool,
    /// The operand index.
    pub operand_index: i32,
    /// The snap range.
    pub min_snap: i64,
    pub max_snap: i64,
}

/// A shifted reference (to a register or stack offset).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceShiftedReference {
    /// Database row ID.
    pub id: i64,
    /// From address offset.
    pub from_offset: u64,
    /// To address offset.
    pub to_offset: u64,
    /// The shift amount applied to the to-address.
    pub shift: i64,
    /// The reference kind.
    pub kind: TraceReferenceKind,
    /// The operand index.
    pub operand_index: i32,
    /// The snap range.
    pub min_snap: i64,
    pub max_snap: i64,
}

/// A stack reference (relative to stack pointer).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DBTraceStackReference {
    /// Database row ID.
    pub id: i64,
    /// From address offset.
    pub from_offset: u64,
    /// Stack offset (relative to frame base).
    pub stack_offset: i64,
    /// The reference kind.
    pub kind: TraceReferenceKind,
    /// The operand index.
    pub operand_index: i32,
    /// The snap range.
    pub min_snap: i64,
    pub max_snap: i64,
}

/// The trace reference manager.
///
/// Ported from Ghidra's `DBTraceReferenceManager`.
#[derive(Debug)]
pub struct TraceDbReferenceManager {
    /// All references indexed by ID.
    references: HashMap<i64, TraceReferenceEntry>,
    /// Index: from-address -> reference IDs.
    from_index: HashMap<(String, u64), Vec<i64>>,
    /// Index: to-address -> reference IDs.
    to_index: HashMap<(String, u64), Vec<i64>>,
    /// Next available reference ID.
    next_id: i64,
}

impl TraceDbReferenceManager {
    /// Create a new reference manager.
    pub fn new() -> Self {
        Self {
            references: HashMap::new(),
            from_index: HashMap::new(),
            to_index: HashMap::new(),
            next_id: 1,
        }
    }

    /// Add a reference.
    pub fn add_reference(
        &mut self,
        from_space: impl Into<String>,
        from_offset: u64,
        to_space: impl Into<String>,
        to_offset: u64,
        kind: TraceReferenceKind,
        is_primary: bool,
        operand_index: i32,
        min_snap: i64,
        max_snap: i64,
    ) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        let fs = from_space.into();
        let ts = to_space.into();

        let entry = TraceReferenceEntry::new(
            id,
            &fs,
            from_offset,
            &ts,
            to_offset,
            kind,
            is_primary,
            operand_index,
            min_snap,
            max_snap,
        );
        self.references.insert(id, entry);

        self.from_index
            .entry((fs, from_offset))
            .or_default()
            .push(id);
        self.to_index
            .entry((ts, to_offset))
            .or_default()
            .push(id);

        id
    }

    /// Get references from a specific address.
    pub fn get_references_from(&self, space: &str, offset: u64) -> Vec<&TraceReferenceEntry> {
        self.from_index
            .get(&(space.to_string(), offset))
            .map(|ids| ids.iter().filter_map(|id| self.references.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get references to a specific address.
    pub fn get_references_to(&self, space: &str, offset: u64) -> Vec<&TraceReferenceEntry> {
        self.to_index
            .get(&(space.to_string(), offset))
            .map(|ids| ids.iter().filter_map(|id| self.references.get(id)).collect())
            .unwrap_or_default()
    }

    /// Delete a reference by ID.
    pub fn delete_reference(&mut self, id: i64) -> bool {
        if let Some(entry) = self.references.remove(&id) {
            let from_key = (entry.from_space, entry.from_offset);
            if let Some(ids) = self.from_index.get_mut(&from_key) {
                ids.retain(|&x| x != id);
            }
            let to_key = (entry.to_space, entry.to_offset);
            if let Some(ids) = self.to_index.get_mut(&to_key) {
                ids.retain(|&x| x != id);
            }
            true
        } else {
            false
        }
    }

    /// Get the total number of references.
    pub fn reference_count(&self) -> usize {
        self.references.len()
    }

    /// Get a reference by ID.
    pub fn get_reference(&self, id: i64) -> Option<&TraceReferenceEntry> {
        self.references.get(&id)
    }

    /// Clear all references.
    pub fn clear(&mut self) {
        self.references.clear();
        self.from_index.clear();
        self.to_index.clear();
    }
}

impl Default for TraceDbReferenceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reference_kind_from_str() {
        assert_eq!(TraceReferenceKind::from_str("flow"), TraceReferenceKind::Flow);
        assert_eq!(TraceReferenceKind::from_str("READ"), TraceReferenceKind::Read);
        assert_eq!(TraceReferenceKind::from_str("write"), TraceReferenceKind::Write);
    }

    #[test]
    fn test_reference_kind_as_str() {
        assert_eq!(TraceReferenceKind::Flow.as_str(), "flow");
        assert_eq!(TraceReferenceKind::Read.as_str(), "read");
        assert_eq!(TraceReferenceKind::Write.as_str(), "write");
    }

    #[test]
    fn test_reference_manager_add() {
        let mut mgr = TraceDbReferenceManager::new();
        let id = mgr.add_reference(
            "ram", 0x1000, "ram", 0x2000,
            TraceReferenceKind::Flow, true, -1, 0, 100,
        );
        assert_eq!(id, 1);
        assert_eq!(mgr.reference_count(), 1);
    }

    #[test]
    fn test_reference_manager_get_from() {
        let mut mgr = TraceDbReferenceManager::new();
        mgr.add_reference(
            "ram", 0x1000, "ram", 0x2000,
            TraceReferenceKind::Flow, true, -1, 0, 100,
        );
        mgr.add_reference(
            "ram", 0x1000, "ram", 0x3000,
            TraceReferenceKind::Flow, false, 0, 0, 100,
        );
        let refs = mgr.get_references_from("ram", 0x1000);
        assert_eq!(refs.len(), 2);
    }

    #[test]
    fn test_reference_manager_get_to() {
        let mut mgr = TraceDbReferenceManager::new();
        mgr.add_reference(
            "ram", 0x1000, "ram", 0x2000,
            TraceReferenceKind::Flow, true, -1, 0, 100,
        );
        let refs = mgr.get_references_to("ram", 0x2000);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].from_offset, 0x1000);
    }

    #[test]
    fn test_reference_manager_delete() {
        let mut mgr = TraceDbReferenceManager::new();
        let id = mgr.add_reference(
            "ram", 0x1000, "ram", 0x2000,
            TraceReferenceKind::Flow, true, -1, 0, 100,
        );
        assert!(mgr.delete_reference(id));
        assert_eq!(mgr.reference_count(), 0);
        assert!(mgr.get_references_from("ram", 0x1000).is_empty());
    }

    #[test]
    fn test_reference_entry_lifecycle() {
        let entry = TraceReferenceEntry::new(
            1, "ram", 0x1000, "ram", 0x2000,
            TraceReferenceKind::Read, true, 0, 10, 50,
        );
        assert_eq!(entry.from_address(), ("ram", 0x1000));
        assert_eq!(entry.to_address(), ("ram", 0x2000));
        assert_eq!(entry.lifespan(), Lifespan::span(10, 50));
        assert!(entry.is_active_at(25));
        assert!(!entry.is_active_at(5));
    }
}
