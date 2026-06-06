//! Database-backed equate manager for traces.
//!
//! Ported from Ghidra's `DBTraceEquateManager`, `DBTraceEquate`, `DBTraceEquateSpace`.
//!
//! Equates are symbolic names for constant values. They are associated with
//! addresses and snap ranges in the trace, allowing users to assign
//! meaningful names to constant operands in instructions and data.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A unique identifier for an equate.
pub type EquateId = u64;

/// An equate mapping a name to a numeric value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEquate {
    /// The unique ID of this equate.
    pub id: EquateId,
    /// The name of the equate.
    pub name: String,
    /// The numeric value this equate represents.
    pub value: i64,
    /// The reference count (how many locations use this equate).
    pub ref_count: u32,
}

impl TraceEquate {
    /// Create a new equate.
    pub fn new(id: EquateId, name: impl Into<String>, value: i64) -> Self {
        Self {
            id,
            name: name.into(),
            value,
            ref_count: 0,
        }
    }
}

/// A reference to an equate at a specific location.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEquateReference {
    /// The equate ID being referenced.
    pub equate_id: EquateId,
    /// The address where the equate is applied.
    pub address: u64,
    /// The address space name.
    pub space: String,
    /// The operand index within the instruction/data.
    pub operand_index: i32,
    /// The sub-operand index.
    pub sub_operand_index: i32,
    /// The lifespan of this reference.
    pub lifespan: Lifespan,
}

impl TraceEquateReference {
    /// Create a new equate reference.
    pub fn new(
        equate_id: EquateId,
        address: u64,
        space: impl Into<String>,
        operand_index: i32,
        sub_operand_index: i32,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            equate_id,
            address,
            space: space.into(),
            operand_index,
            sub_operand_index,
            lifespan,
        }
    }
}

/// The equate space manages equates within a specific address space.
#[derive(Debug)]
pub struct TraceEquateSpace {
    /// The name of the address space.
    space_name: String,
    /// Equates by ID.
    equates: HashMap<EquateId, TraceEquate>,
    /// References by address.
    references_by_addr: HashMap<u64, Vec<TraceEquateReference>>,
    /// References by equate ID.
    references_by_equate: HashMap<EquateId, Vec<TraceEquateReference>>,
    /// Next equate ID.
    next_id: EquateId,
}

impl TraceEquateSpace {
    /// Create a new equate space.
    pub fn new(space_name: impl Into<String>) -> Self {
        Self {
            space_name: space_name.into(),
            equates: HashMap::new(),
            references_by_addr: HashMap::new(),
            references_by_equate: HashMap::new(),
            next_id: 1,
        }
    }

    /// Get the space name.
    pub fn space_name(&self) -> &str {
        &self.space_name
    }

    /// Create a new equate.
    pub fn create_equate(&mut self, name: impl Into<String>, value: i64) -> EquateId {
        let name = name.into();
        // Check if an equate with this name already exists
        for eq in self.equates.values() {
            if eq.name == name {
                return eq.id;
            }
        }
        let id = self.next_id;
        self.next_id += 1;
        self.equates.insert(id, TraceEquate::new(id, name, value));
        id
    }

    /// Get an equate by ID.
    pub fn get_equate(&self, id: EquateId) -> Option<&TraceEquate> {
        self.equates.get(&id)
    }

    /// Find an equate by name.
    pub fn find_equate_by_name(&self, name: &str) -> Option<&TraceEquate> {
        self.equates.values().find(|eq| eq.name == name)
    }

    /// Find equates by value.
    pub fn find_equates_by_value(&self, value: i64) -> Vec<&TraceEquate> {
        self.equates.values().filter(|eq| eq.value == value).collect()
    }

    /// Add a reference to an equate at an address.
    pub fn add_reference(&mut self, reference: TraceEquateReference) -> bool {
        if !self.equates.contains_key(&reference.equate_id) {
            return false;
        }
        if let Some(eq) = self.equates.get_mut(&reference.equate_id) {
            eq.ref_count += 1;
        }
        self.references_by_addr
            .entry(reference.address)
            .or_default()
            .push(reference.clone());
        self.references_by_equate
            .entry(reference.equate_id)
            .or_default()
            .push(reference);
        true
    }

    /// Remove references at a specific address.
    pub fn remove_references_at(&mut self, address: u64) -> Vec<TraceEquateReference> {
        let refs = self.references_by_addr.remove(&address).unwrap_or_default();
        for r in &refs {
            if let Some(eq) = self.equates.get_mut(&r.equate_id) {
                eq.ref_count = eq.ref_count.saturating_sub(1);
            }
            if let Some(list) = self.references_by_equate.get_mut(&r.equate_id) {
                list.retain(|x| x.address != address);
            }
        }
        refs
    }

    /// Get all references at an address.
    pub fn get_references_at(&self, address: u64) -> &[TraceEquateReference] {
        static EMPTY: Vec<TraceEquateReference> = Vec::new();
        self.references_by_addr
            .get(&address)
            .map(|v| v.as_slice())
            .unwrap_or(&EMPTY)
    }

    /// Get all references for an equate.
    pub fn get_references_for_equate(&self, equate_id: EquateId) -> &[TraceEquateReference] {
        static EMPTY: Vec<TraceEquateReference> = Vec::new();
        self.references_by_equate
            .get(&equate_id)
            .map(|v| v.as_slice())
            .unwrap_or(&EMPTY)
    }

    /// Get all equates.
    pub fn all_equates(&self) -> Vec<&TraceEquate> {
        self.equates.values().collect()
    }

    /// Delete an equate and all its references.
    pub fn delete_equate(&mut self, id: EquateId) -> bool {
        if let Some(_eq) = self.equates.remove(&id) {
            // Remove all references
            if let Some(refs) = self.references_by_equate.remove(&id) {
                for r in refs {
                    if let Some(list) = self.references_by_addr.get_mut(&r.address) {
                        list.retain(|x| x.equate_id != id);
                    }
                }
            }
            true
        } else {
            false
        }
    }

    /// Get the total number of equates.
    pub fn equate_count(&self) -> usize {
        self.equates.len()
    }
}

/// The database-backed equate manager.
///
/// Manages equate spaces across all address spaces in the trace.
#[derive(Debug)]
pub struct DBTraceEquateManager {
    /// Equate spaces by space name.
    spaces: HashMap<String, TraceEquateSpace>,
}

impl DBTraceEquateManager {
    /// Create a new equate manager.
    pub fn new() -> Self {
        Self {
            spaces: HashMap::new(),
        }
    }

    /// Get or create an equate space for the given address space name.
    pub fn get_or_create_space(&mut self, space_name: &str) -> &mut TraceEquateSpace {
        self.spaces
            .entry(space_name.to_string())
            .or_insert_with(|| TraceEquateSpace::new(space_name))
    }

    /// Get an equate space by name.
    pub fn get_space(&self, space_name: &str) -> Option<&TraceEquateSpace> {
        self.spaces.get(space_name)
    }

    /// Get all space names.
    pub fn space_names(&self) -> Vec<&str> {
        self.spaces.keys().map(|s| s.as_str()).collect()
    }

    /// Get the total number of equates across all spaces.
    pub fn total_equate_count(&self) -> usize {
        self.spaces.values().map(|s| s.equate_count()).sum()
    }
}

impl Default for DBTraceEquateManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_equate_creation() {
        let eq = TraceEquate::new(1, "MY_CONSTANT", 42);
        assert_eq!(eq.id, 1);
        assert_eq!(eq.name, "MY_CONSTANT");
        assert_eq!(eq.value, 42);
        assert_eq!(eq.ref_count, 0);
    }

    #[test]
    fn test_equate_space_create_equate() {
        let mut space = TraceEquateSpace::new("ram");
        let id1 = space.create_equate("CONST_A", 10);
        let id2 = space.create_equate("CONST_B", 20);
        assert_ne!(id1, id2);
        assert_eq!(space.equate_count(), 2);

        // Duplicate name returns same ID
        let id3 = space.create_equate("CONST_A", 10);
        assert_eq!(id1, id3);
        assert_eq!(space.equate_count(), 2);
    }

    #[test]
    fn test_equate_space_find_by_name() {
        let mut space = TraceEquateSpace::new("ram");
        space.create_equate("MY_CONST", 42);

        let eq = space.find_equate_by_name("MY_CONST");
        assert!(eq.is_some());
        assert_eq!(eq.unwrap().value, 42);

        assert!(space.find_equate_by_name("NONEXISTENT").is_none());
    }

    #[test]
    fn test_equate_space_find_by_value() {
        let mut space = TraceEquateSpace::new("ram");
        space.create_equate("A", 42);
        space.create_equate("B", 42);
        space.create_equate("C", 100);

        let equates = space.find_equates_by_value(42);
        assert_eq!(equates.len(), 2);
    }

    #[test]
    fn test_equate_space_references() {
        let mut space = TraceEquateSpace::new("ram");
        let id = space.create_equate("MY_CONST", 42);

        let reference = TraceEquateReference::new(id, 0x400000, "ram", 0, 0, Lifespan::ALL);
        assert!(space.add_reference(reference));
        assert_eq!(space.get_references_at(0x400000).len(), 1);
        assert_eq!(space.get_references_for_equate(id).len(), 1);

        // Remove references
        let removed = space.remove_references_at(0x400000);
        assert_eq!(removed.len(), 1);
        assert_eq!(space.get_references_at(0x400000).len(), 0);
    }

    #[test]
    fn test_equate_space_references_invalid() {
        let mut space = TraceEquateSpace::new("ram");
        let reference = TraceEquateReference::new(999, 0x400000, "ram", 0, 0, Lifespan::ALL);
        // Should fail - equate doesn't exist
        assert!(!space.add_reference(reference));
    }

    #[test]
    fn test_equate_space_delete() {
        let mut space = TraceEquateSpace::new("ram");
        let id = space.create_equate("MY_CONST", 42);
        space.add_reference(TraceEquateReference::new(id, 0x400000, "ram", 0, 0, Lifespan::ALL));

        assert!(space.delete_equate(id));
        assert_eq!(space.equate_count(), 0);
        assert_eq!(space.get_references_at(0x400000).len(), 0);
        assert!(!space.delete_equate(id)); // Already deleted
    }

    #[test]
    fn test_equate_manager() {
        let mut mgr = DBTraceEquateManager::new();
        assert_eq!(mgr.total_equate_count(), 0);

        mgr.get_or_create_space("ram").create_equate("A", 1);
        mgr.get_or_create_space("ram").create_equate("B", 2);
        mgr.get_or_create_space("stack").create_equate("C", 3);

        assert_eq!(mgr.total_equate_count(), 3);
        assert_eq!(mgr.space_names().len(), 2);
    }

    #[test]
    fn test_equate_reference_creation() {
        let reference = TraceEquateReference::new(1, 0x400000, "ram", 0, 0, Lifespan::now_on(5));
        assert_eq!(reference.equate_id, 1);
        assert_eq!(reference.address, 0x400000);
        assert_eq!(reference.space, "ram");
        assert_eq!(reference.operand_index, 0);
    }
}

