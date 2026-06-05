//! TraceReferenceOperations - operations for managing cross-references (xrefs).
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol.TraceReferenceOperations`.

use super::Lifespan;
use super::symbol::{TraceReference, TraceReferenceKind};
use std::collections::HashSet;

/// Sort direction for spatial reference queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceQueryOrder {
    /// No particular order.
    None,
    /// Most recent (latest snapshot) first.
    TopMost,
    /// Least recent (earliest snapshot) first.
    BottomMost,
    /// Smallest address first.
    LeftMost,
    /// Largest address first.
    RightMost,
}

/// The set of operations available for managing trace references (xrefs).
///
/// References in traces differ from static program references because they
/// include a lifespan (snap range) and support address ranges for the "to" side.
pub trait TraceReferenceOperations {
    /// Add a memory reference.
    fn add_memory_reference(
        &mut self,
        lifespan: Lifespan,
        from_address: u64,
        from_space: &str,
        to_address: u64,
        to_space: &str,
        ref_type: TraceReferenceKind,
        operand_index: i32,
    ) -> i64;

    /// Add an offset memory reference.
    fn add_offset_reference(
        &mut self,
        lifespan: Lifespan,
        from_address: u64,
        to_address: u64,
        to_is_base: bool,
        offset: i64,
        ref_type: TraceReferenceKind,
        operand_index: i32,
    ) -> i64;

    /// Add a shifted memory reference.
    fn add_shifted_reference(
        &mut self,
        lifespan: Lifespan,
        from_address: u64,
        to_address: u64,
        shift: i32,
        ref_type: TraceReferenceKind,
        operand_index: i32,
    ) -> i64;

    /// Add a stack reference.
    fn add_stack_reference(
        &mut self,
        lifespan: Lifespan,
        from_address: u64,
        stack_offset: i32,
        ref_type: TraceReferenceKind,
        operand_index: i32,
    ) -> i64;

    /// Find a specific reference.
    fn get_reference(
        &self,
        snap: i64,
        from_address: u64,
        to_address: u64,
        operand_index: i32,
    ) -> Option<&TraceReference>;

    /// Get all references from a given snap and address.
    fn get_references_from(&self, snap: i64, from_address: u64) -> Vec<&TraceReference>;

    /// Get all references from a given snap, address, and operand index.
    fn get_references_from_operand(
        &self,
        snap: i64,
        from_address: u64,
        operand_index: i32,
    ) -> Vec<&TraceReference>;

    /// Get all references from addresses in a given lifespan and range.
    fn get_references_from_range(
        &self,
        span: &Lifespan,
        min_addr: u64,
        max_addr: u64,
    ) -> Vec<&TraceReference>;

    /// Get the primary reference from a snap, address, and operand.
    fn get_primary_reference_from(
        &self,
        snap: i64,
        from_address: u64,
        operand_index: i32,
    ) -> Option<&TraceReference>;

    /// Get all flow references from a snap and address.
    fn get_flow_references_from(&self, snap: i64, from_address: u64) -> Vec<&TraceReference>;

    /// Clear references from a lifespan and address range.
    fn clear_references_from(&mut self, span: &Lifespan, min_addr: u64, max_addr: u64);

    /// Get all references to a given snap and address.
    fn get_references_to(&self, snap: i64, to_address: u64) -> Vec<&TraceReference>;

    /// Clear references to a lifespan and address range.
    fn clear_references_to(&mut self, span: &Lifespan, min_addr: u64, max_addr: u64);

    /// Get references to addresses in a range, with optional ordering.
    fn get_references_to_range(
        &self,
        span: &Lifespan,
        min_addr: u64,
        max_addr: u64,
        order: ReferenceQueryOrder,
    ) -> Vec<&TraceReference>;

    /// Check if references exist from a snap and address.
    fn has_references_from(&self, snap: i64, from_address: u64) -> bool {
        !self.get_references_from(snap, from_address).is_empty()
    }

    /// Check if references exist to a snap and address.
    fn has_references_to(&self, snap: i64, to_address: u64) -> bool {
        !self.get_references_to(snap, to_address).is_empty()
    }

    /// Get all source addresses that have references in a lifespan.
    fn get_reference_sources(&self, span: &Lifespan) -> HashSet<u64>;

    /// Get all destination addresses that have references in a lifespan.
    fn get_reference_destinations(&self, span: &Lifespan) -> HashSet<u64>;

    /// Count references from a snap and address.
    fn reference_count_from(&self, snap: i64, from_address: u64) -> usize {
        self.get_references_from(snap, from_address).len()
    }

    /// Count references to a snap and address.
    fn reference_count_to(&self, snap: i64, to_address: u64) -> usize {
        self.get_references_to(snap, to_address).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reference_query_order() {
        let order = ReferenceQueryOrder::TopMost;
        assert_eq!(order, ReferenceQueryOrder::TopMost);
        assert_ne!(order, ReferenceQueryOrder::BottomMost);
    }
}
