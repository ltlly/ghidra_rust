//! Reference manager view for trace program views.
//!
//! Ported from Ghidra's `DBTraceProgramViewReferenceManager` and
//! `AbstractDBTraceProgramViewReferenceManager` in
//! `ghidra.trace.database.program`. Provides memory reference management
//! for a single snapshot of a trace program view.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Types of memory references in a trace program view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReferenceType {
    /// A plain (unconditional) reference.
    Plain,
    /// A conditional reference.
    Conditional,
    /// A call reference.
    Call,
    /// A jump reference.
    Jump,
    /// A data reference.
    Data,
    /// An external reference.
    External,
    /// An offset reference.
    Offset,
    /// A shifted reference.
    Shifted,
    /// A stack reference.
    Stack,
}

/// A memory reference in a trace program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewReference {
    /// Unique key.
    pub key: i64,
    /// The source address.
    pub from_address: u64,
    /// The source address space.
    pub from_space: String,
    /// The destination address.
    pub to_address: u64,
    /// The destination address space.
    pub to_space: String,
    /// The reference type.
    pub ref_type: ReferenceType,
    /// Whether this is a primary reference from its source.
    pub is_primary: bool,
    /// The operand index (if applicable).
    pub operand_index: i32,
    /// The user-defined reference (vs. analysis-computed).
    pub is_user_defined: bool,
}

impl ProgramViewReference {
    /// Create a new reference.
    pub fn new(
        key: i64,
        from_address: u64,
        from_space: impl Into<String>,
        to_address: u64,
        to_space: impl Into<String>,
        ref_type: ReferenceType,
    ) -> Self {
        Self {
            key,
            from_address,
            from_space: from_space.into(),
            to_address,
            to_space: to_space.into(),
            ref_type,
            is_primary: false,
            operand_index: -1,
            is_user_defined: false,
        }
    }

    /// Mark as primary reference.
    pub fn as_primary(mut self) -> Self {
        self.is_primary = true;
        self
    }

    /// Set operand index.
    pub fn with_operand_index(mut self, index: i32) -> Self {
        self.operand_index = index;
        self
    }
}

/// Reference manager view for a trace program view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewReferenceManager {
    /// All references.
    references: Vec<ProgramViewReference>,
    /// Index: from_address -> reference keys.
    from_index: BTreeMap<u64, Vec<usize>>,
    /// Index: to_address -> reference keys.
    to_index: BTreeMap<u64, Vec<usize>>,
    /// Next key.
    next_key: i64,
    /// The snap this view is for.
    snap: i64,
}

impl ProgramViewReferenceManager {
    /// Create a new reference manager.
    pub fn new(snap: i64) -> Self {
        Self {
            references: Vec::new(),
            from_index: BTreeMap::new(),
            to_index: BTreeMap::new(),
            next_key: 1,
            snap,
        }
    }

    /// Add a reference.
    pub fn add_reference(&mut self, mut r#ref: ProgramViewReference) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        r#ref.key = key;
        let idx = self.references.len();
        self.from_index
            .entry(r#ref.from_address)
            .or_default()
            .push(idx);
        self.to_index
            .entry(r#ref.to_address)
            .or_default()
            .push(idx);
        self.references.push(r#ref);
        key
    }

    /// Get references from a given address.
    pub fn get_references_from(&self, address: u64) -> Vec<&ProgramViewReference> {
        self.from_index
            .get(&address)
            .map(|idxs| idxs.iter().filter_map(|&i| self.references.get(i)).collect())
            .unwrap_or_default()
    }

    /// Get references to a given address.
    pub fn get_references_to(&self, address: u64) -> Vec<&ProgramViewReference> {
        self.to_index
            .get(&address)
            .map(|idxs| idxs.iter().filter_map(|&i| self.references.get(i)).collect())
            .unwrap_or_default()
    }

    /// Get the primary reference from a given address.
    pub fn get_primary_reference_from(&self, address: u64) -> Option<&ProgramViewReference> {
        self.get_references_from(address)
            .into_iter()
            .find(|r| r.is_primary)
    }

    /// Get the reference count from a given address.
    pub fn get_reference_count_from(&self, address: u64) -> usize {
        self.from_index.get(&address).map_or(0, |v| v.len())
    }

    /// Get the reference count to a given address.
    pub fn get_reference_count_to(&self, address: u64) -> usize {
        self.to_index.get(&address).map_or(0, |v| v.len())
    }

    /// Get the total number of references.
    pub fn total_references(&self) -> usize {
        self.references.len()
    }

    /// Remove a reference by key.
    pub fn remove_reference(&mut self, key: i64) -> bool {
        if let Some(idx) = self.references.iter().position(|r| r.key == key) {
            let _ref = self.references.remove(idx);
            // Rebuild indices (simplistic approach)
            self.rebuild_indices();
            true
        } else {
            false
        }
    }

    fn rebuild_indices(&mut self) {
        self.from_index.clear();
        self.to_index.clear();
        for (idx, r#ref) in self.references.iter().enumerate() {
            self.from_index
                .entry(r#ref.from_address)
                .or_default()
                .push(idx);
            self.to_index
                .entry(r#ref.to_address)
                .or_default()
                .push(idx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reference_new() {
        let r = ProgramViewReference::new(1, 0x1000, "ram", 0x2000, "ram", ReferenceType::Call);
        assert_eq!(r.from_address, 0x1000);
        assert_eq!(r.to_address, 0x2000);
        assert_eq!(r.ref_type, ReferenceType::Call);
    }

    #[test]
    fn test_reference_builder() {
        let r = ProgramViewReference::new(1, 0x1000, "ram", 0x2000, "ram", ReferenceType::Plain)
            .as_primary()
            .with_operand_index(1);
        assert!(r.is_primary);
        assert_eq!(r.operand_index, 1);
    }

    #[test]
    fn test_ref_manager_add_and_get_from() {
        let mut mgr = ProgramViewReferenceManager::new(0);
        mgr.add_reference(ProgramViewReference::new(0, 0x1000, "ram", 0x2000, "ram", ReferenceType::Jump));
        mgr.add_reference(ProgramViewReference::new(0, 0x1000, "ram", 0x3000, "ram", ReferenceType::Data));
        let refs = mgr.get_references_from(0x1000);
        assert_eq!(refs.len(), 2);
    }

    #[test]
    fn test_ref_manager_get_to() {
        let mut mgr = ProgramViewReferenceManager::new(0);
        mgr.add_reference(ProgramViewReference::new(0, 0x1000, "ram", 0x2000, "ram", ReferenceType::Call));
        let refs = mgr.get_references_to(0x2000);
        assert_eq!(refs.len(), 1);
    }

    #[test]
    fn test_ref_manager_primary() {
        let mut mgr = ProgramViewReferenceManager::new(0);
        mgr.add_reference(
            ProgramViewReference::new(0, 0x1000, "ram", 0x2000, "ram", ReferenceType::Jump).as_primary(),
        );
        let primary = mgr.get_primary_reference_from(0x1000);
        assert!(primary.is_some());
        assert!(primary.unwrap().is_primary);
    }

    #[test]
    fn test_ref_manager_count() {
        let mut mgr = ProgramViewReferenceManager::new(0);
        assert_eq!(mgr.get_reference_count_from(0x1000), 0);
        mgr.add_reference(ProgramViewReference::new(0, 0x1000, "ram", 0x2000, "ram", ReferenceType::Plain));
        assert_eq!(mgr.get_reference_count_from(0x1000), 1);
        assert_eq!(mgr.get_reference_count_to(0x2000), 1);
    }

    #[test]
    fn test_ref_manager_remove() {
        let mut mgr = ProgramViewReferenceManager::new(0);
        let key = mgr.add_reference(ProgramViewReference::new(0, 0x1000, "ram", 0x2000, "ram", ReferenceType::Plain));
        assert_eq!(mgr.total_references(), 1);
        assert!(mgr.remove_reference(key));
        assert_eq!(mgr.total_references(), 0);
    }

    #[test]
    fn test_ref_manager_cross_space() {
        let mut mgr = ProgramViewReferenceManager::new(0);
        mgr.add_reference(ProgramViewReference::new(0, 0x1000, "ram", 0, "external", ReferenceType::External));
        let refs = mgr.get_references_from(0x1000);
        assert_eq!(refs[0].to_space, "external");
    }
}
