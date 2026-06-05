//! TraceEquateOperations - operations for managing equates (named constants).
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol.TraceEquateOperations`.

use super::Lifespan;
use super::trace_equate_reference::TraceEquateReference;
use std::collections::HashSet;

/// The set of operations available on an equate space or manager.
///
/// Equates are named constants that can be associated with instruction operands.
/// This trait defines the query operations for retrieving equate references.
pub trait TraceEquateOperations {
    /// Get the equate type (for error messages / display).
    fn equate_type_name(&self) -> &str;

    /// Get the referring addresses (addresses that reference equates) in the given lifespan.
    fn get_referring_addresses(&self, span: &Lifespan) -> HashSet<u64>;

    /// Clear equate references in the given lifespan and address set.
    fn clear_references(&self, span: &Lifespan, addresses: &HashSet<u64>);

    /// Get the equate referenced at a specific snap, address, and operand index by value.
    fn get_referenced_by_value(
        &self,
        snap: i64,
        address: u64,
        operand_index: i32,
        value: i64,
    ) -> Option<String>;

    /// Get all equates referenced at a specific snap and address.
    fn get_referenced(&self, snap: i64, address: u64) -> Vec<String>;

    /// Get all equates referenced at a specific snap, address, and operand index.
    fn get_referenced_at_operand(
        &self,
        snap: i64,
        address: u64,
        operand_index: i32,
    ) -> Vec<String>;

    /// Check if there are any equate references at a snap and address.
    fn has_references(&self, snap: i64, address: u64) -> bool {
        !self.get_referenced(snap, address).is_empty()
    }

    /// Get the count of equate references at a snap and address.
    fn reference_count(&self, snap: i64, address: u64) -> usize {
        self.get_referenced(snap, address).len()
    }
}

/// In-memory implementation of equate operations for testing.
#[derive(Debug, Clone, Default)]
pub struct InMemoryEquateOps {
    /// Stored equate references.
    pub references: Vec<TraceEquateReference>,
    /// Equate name-to-value mapping.
    pub equates: Vec<(String, i64)>,
}

impl InMemoryEquateOps {
    /// Create a new in-memory equate operations store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an equate.
    pub fn add_equate(&mut self, name: impl Into<String>, value: i64) {
        let name = name.into();
        if !self.equates.iter().any(|(n, _)| n == &name) {
            self.equates.push((name, value));
        }
    }

    /// Add a reference.
    pub fn add_reference(&mut self, r#ref: TraceEquateReference) {
        self.references.push(r#ref);
    }

    /// Get all references for a given equate.
    pub fn get_references_for(&self, equate_key: i64) -> Vec<&TraceEquateReference> {
        self.references
            .iter()
            .filter(|r| r.equate_key == equate_key)
            .collect()
    }

    /// Delete all references for a given equate.
    pub fn delete_references(&mut self, equate_key: i64) {
        self.references.retain(|r| r.equate_key != equate_key);
    }
}

impl TraceEquateOperations for InMemoryEquateOps {
    fn equate_type_name(&self) -> &str {
        "Equate"
    }

    fn get_referring_addresses(&self, span: &Lifespan) -> HashSet<u64> {
        self.references
            .iter()
            .filter(|r| r.lifespan.intersects(span))
            .map(|r| r.address)
            .collect()
    }

    fn clear_references(&self, _span: &Lifespan, _addresses: &HashSet<u64>) {
        // In a real implementation, this would truncate lifespans
    }

    fn get_referenced_by_value(
        &self,
        snap: i64,
        address: u64,
        operand_index: i32,
        value: i64,
    ) -> Option<String> {
        self.references
            .iter()
            .find(|r| {
                r.lifespan.contains(snap)
                    && r.address == address
                    && r.operand_index == operand_index
            })
            .and_then(|r| {
                self.equates
                    .iter()
                    .find(|(name, v)| {
                        // Key-based matching: equate_key in real impl, name here
                        *v == value
                    })
                    .map(|(name, _)| name.clone())
            })
    }

    fn get_referenced(&self, snap: i64, address: u64) -> Vec<String> {
        self.references
            .iter()
            .filter(|r| r.lifespan.contains(snap) && r.address == address)
            .filter_map(|r| {
                self.equates
                    .iter()
                    .find(|(_, _)| true) // Simplified: in real impl would use equate_key
                    .map(|(n, _)| n.clone())
            })
            .collect()
    }

    fn get_referenced_at_operand(
        &self,
        snap: i64,
        address: u64,
        operand_index: i32,
    ) -> Vec<String> {
        self.references
            .iter()
            .filter(|r| {
                r.lifespan.contains(snap)
                    && r.address == address
                    && r.operand_index == operand_index
            })
            .filter_map(|r| {
                self.equates
                    .iter()
                    .find(|(_, _)| true)
                    .map(|(n, _)| n.clone())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_equate_ops() {
        let mut ops = InMemoryEquateOps::new();
        ops.add_equate("MY_CONST", 42);
        assert_eq!(ops.equates.len(), 1);

        // Adding duplicate should be ignored
        ops.add_equate("MY_CONST", 99);
        assert_eq!(ops.equates.len(), 1);
    }

    #[test]
    fn test_referring_addresses() {
        let mut ops = InMemoryEquateOps::new();
        ops.add_reference(TraceEquateReference::new(1, 10, Lifespan::span(0, 100), 0x1000, "ram", 0));
        ops.add_reference(TraceEquateReference::new(2, 10, Lifespan::span(0, 100), 0x2000, "ram", 0));

        let addrs = ops.get_referring_addresses(&Lifespan::span(50, 50));
        assert_eq!(addrs.len(), 2);
    }

    #[test]
    fn test_get_references_for() {
        let mut ops = InMemoryEquateOps::new();
        ops.add_reference(TraceEquateReference::new(1, 10, Lifespan::span(0, 100), 0x1000, "ram", 0));
        ops.add_reference(TraceEquateReference::new(2, 10, Lifespan::span(0, 100), 0x2000, "ram", 1));
        ops.add_reference(TraceEquateReference::new(3, 20, Lifespan::span(0, 100), 0x3000, "ram", 0));

        let refs = ops.get_references_for(10);
        assert_eq!(refs.len(), 2);
    }

    #[test]
    fn test_delete_references() {
        let mut ops = InMemoryEquateOps::new();
        ops.add_reference(TraceEquateReference::new(1, 10, Lifespan::span(0, 100), 0x1000, "ram", 0));
        ops.add_reference(TraceEquateReference::new(2, 20, Lifespan::span(0, 100), 0x2000, "ram", 0));

        ops.delete_references(10);
        assert_eq!(ops.references.len(), 1);
        assert_eq!(ops.references[0].equate_key, 20);
    }
}
