//! Equate operations and space for trace symbols.
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol.TraceEquateOperations`
//! and `TraceEquateSpace`.
//!
//! Equates are symbolic names for constant values. They are associated with
//! addresses and snap ranges in the trace, allowing users to assign
//! meaningful names to constant operands.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use super::symbol::{TraceEquate, TraceEquateReference};
use super::Lifespan;

/// Operations for adding and retrieving equates in a trace.
///
/// Ported from Ghidra's `TraceEquateOperations` interface.
/// This trait provides the interface for equate management without
/// being tied to a specific address space.
pub trait TraceEquateOperations {
    /// Get the referring addresses for all equates in the given lifespan.
    fn get_referring_addresses(&self, span: &Lifespan) -> Vec<u64>;

    /// Clear equate references in the given lifespan and address set.
    fn clear_references(&mut self, span: &Lifespan, addresses: &[u64]);

    /// Get the equate referenced by value at a specific location.
    fn get_referenced_by_value(
        &self,
        snap: i64,
        address: u64,
        operand_index: i32,
        value: i64,
    ) -> Option<&TraceEquate>;

    /// Get all equates referenced at a specific address and operand.
    fn get_referenced(
        &self,
        snap: i64,
        address: u64,
        operand_index: i32,
    ) -> Vec<&TraceEquate>;

    /// Get all equates referenced at a specific address (any operand).
    fn get_referenced_at(&self, snap: i64, address: u64) -> Vec<&TraceEquate>;
}

/// An equate space that ties equate operations to a specific address space.
///
/// Ported from Ghidra's `TraceEquateSpace` interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEquateSpace {
    /// The address space name this equate space operates on.
    pub address_space: String,
    /// The equates in this space, keyed by equate key.
    pub equates: HashMap<i64, TraceEquate>,
    /// The references in this space.
    pub references: Vec<TraceEquateReference>,
}

impl TraceEquateSpace {
    /// Create a new equate space for the given address space.
    pub fn new(address_space: impl Into<String>) -> Self {
        Self {
            address_space: address_space.into(),
            equates: HashMap::new(),
            references: Vec::new(),
        }
    }

    /// Get the address space name.
    pub fn address_space(&self) -> &str {
        &self.address_space
    }

    /// Get the total number of equates in this space.
    pub fn equate_count(&self) -> usize {
        self.equates.len()
    }

    /// Get an equate by key.
    pub fn get_equate(&self, key: i64) -> Option<&TraceEquate> {
        self.equates.get(&key)
    }

    /// Get an equate by name.
    pub fn get_equate_by_name(&self, name: &str) -> Option<&TraceEquate> {
        self.equates.values().find(|e| e.name == name)
    }

    /// Add an equate to this space.
    pub fn add_equate(&mut self, equate: TraceEquate) -> i64 {
        let key = equate.key;
        self.equates.insert(key, equate);
        key
    }

    /// Remove an equate by key.
    pub fn remove_equate(&mut self, key: i64) -> Option<TraceEquate> {
        self.equates.remove(&key)
    }

    /// Add a reference to an equate.
    pub fn add_reference(&mut self, reference: TraceEquateReference) {
        self.references.push(reference);
    }

    /// Get all references for an equate by key.
    pub fn get_references_for(&self, equate_key: i64) -> Vec<&TraceEquateReference> {
        self.references
            .iter()
            .filter(|r| r.equate_key == equate_key)
            .collect()
    }

    /// Get references at a specific address.
    pub fn get_references_at(&self, address: u64) -> Vec<&TraceEquateReference> {
        self.references
            .iter()
            .filter(|r| r.address == address)
            .collect()
    }

    /// Get references at a specific address and operand index.
    pub fn get_references_at_operand(
        &self,
        address: u64,
        operand_index: i32,
    ) -> Vec<&TraceEquateReference> {
        self.references
            .iter()
            .filter(|r| r.address == address && r.operand_index == operand_index)
            .collect()
    }

    /// Clear all references in the given lifespan and address set.
    pub fn clear_references(&mut self, span: &Lifespan, addresses: &[u64]) {
        self.references.retain(|r| {
            let address_match = addresses.is_empty() || addresses.contains(&r.address);
            let span_match = r.lifespan.intersects(span);
            !(address_match && span_match)
        });
    }

    /// Get all equate names.
    pub fn equate_names(&self) -> Vec<&str> {
        self.equates.values().map(|e| e.name.as_str()).collect()
    }
}

/// Builder for constructing an equate space.
pub struct EquateSpaceBuilder {
    space: TraceEquateSpace,
    next_key: i64,
}

impl EquateSpaceBuilder {
    /// Create a new builder for the given address space.
    pub fn new(address_space: impl Into<String>) -> Self {
        Self {
            space: TraceEquateSpace::new(address_space),
            next_key: 1,
        }
    }

    /// Add an equate with the given name and value.
    pub fn add_equate(mut self, name: impl Into<String>, value: i64) -> Self {
        let key = self.next_key;
        self.next_key += 1;
        let equate = TraceEquate::new(key, name, value, Lifespan::span(0, i64::MAX));
        self.space.add_equate(equate);
        self
    }

    /// Build the equate space.
    pub fn build(self) -> TraceEquateSpace {
        self.space
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equate_space_creation() {
        let space = TraceEquateSpace::new("ram");
        assert_eq!(space.address_space(), "ram");
        assert_eq!(space.equate_count(), 0);
    }

    #[test]
    fn test_equate_space_builder() {
        let space = EquateSpaceBuilder::new("ram")
            .add_equate("MY_CONST", 42)
            .add_equate("OTHER", 100)
            .build();

        assert_eq!(space.equate_count(), 2);
        assert_eq!(space.get_equate_by_name("MY_CONST").unwrap().value, 42);
        assert_eq!(space.get_equate_by_name("OTHER").unwrap().value, 100);
    }

    #[test]
    fn test_equate_add_remove() {
        let mut space = TraceEquateSpace::new("ram");
        let equate = TraceEquate::new(1, "TEST", 99, Lifespan::span(0, 100));
        space.add_equate(equate);
        assert_eq!(space.equate_count(), 1);

        let removed = space.remove_equate(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().name, "TEST");
        assert_eq!(space.equate_count(), 0);
    }

    #[test]
    fn test_equate_references() {
        let mut space = TraceEquateSpace::new("ram");
        space.add_equate(TraceEquate::new(1, "MY_CONST", 42, Lifespan::span(0, 100)));

        let reference = TraceEquateReference {
            equate_key: 1,
            address: 0x1000,
            operand_index: 0,
            lifespan: Lifespan::span(0, 10),
        };
        space.add_reference(reference);

        let refs = space.get_references_for(1);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].address, 0x1000);

        let refs_at = space.get_references_at(0x1000);
        assert_eq!(refs_at.len(), 1);

        let refs_empty = space.get_references_at(0x2000);
        assert!(refs_empty.is_empty());
    }

    #[test]
    fn test_equate_references_at_operand() {
        let mut space = TraceEquateSpace::new("ram");
        space.add_equate(TraceEquate::new(1, "MY_CONST", 42, Lifespan::span(0, 100)));

        space.add_reference(TraceEquateReference {
            equate_key: 1,
            address: 0x1000,
            operand_index: 0,
            lifespan: Lifespan::span(0, 10),
        });
        space.add_reference(TraceEquateReference {
            equate_key: 1,
            address: 0x1000,
            operand_index: 1,
            lifespan: Lifespan::span(0, 10),
        });

        let refs_op0 = space.get_references_at_operand(0x1000, 0);
        assert_eq!(refs_op0.len(), 1);

        let refs_op1 = space.get_references_at_operand(0x1000, 1);
        assert_eq!(refs_op1.len(), 1);
    }

    #[test]
    fn test_clear_references() {
        let mut space = TraceEquateSpace::new("ram");
        space.add_equate(TraceEquate::new(1, "MY_CONST", 42, Lifespan::span(0, 100)));
        space.add_reference(TraceEquateReference {
            equate_key: 1,
            address: 0x1000,
            operand_index: 0,
            lifespan: Lifespan::span(0, 10),
        });
        space.add_reference(TraceEquateReference {
            equate_key: 1,
            address: 0x2000,
            operand_index: 0,
            lifespan: Lifespan::span(0, 10),
        });

        assert_eq!(space.references.len(), 2);
        space.clear_references(&Lifespan::span(5, 8), &[0x1000]);
        assert_eq!(space.references.len(), 1);
    }

    #[test]
    fn test_equate_names() {
        let space = EquateSpaceBuilder::new("ram")
            .add_equate("A", 1)
            .add_equate("B", 2)
            .add_equate("C", 3)
            .build();

        let mut names: Vec<&str> = space.equate_names();
        names.sort();
        assert_eq!(names, vec!["A", "B", "C"]);
    }
}
