//! Reference operations for trace symbols.
//!
//! Ported from Ghidra's `ghidra.trace.model.symbol.TraceReferenceOperations`.
//!
//! Provides the comprehensive interface for adding and retrieving references
//! (memory, offset, shifted, register, stack) in a trace, including
//! source and destination queries.

use serde::{Deserialize, Serialize};

use super::reference_ext::{TraceOffsetReference, TraceShiftedReference, TraceStackReference};
use super::symbol::{TraceReference, TraceReferenceKind};
use super::Lifespan;

/// The sort order for reference queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReferenceOrder {
    /// No particular order (cheapest).
    None,
    /// Most-recent (latest snapshot) first.
    TopMost,
    /// Least-recent (earliest including scratch snapshot) first.
    BottomMost,
    /// Smallest address first.
    LeftMost,
    /// Largest address first.
    RightMost,
}

/// Operations for adding and retrieving references in a trace.
///
/// Ported from Ghidra's `TraceReferenceOperations` interface.
pub trait TraceReferenceOperations {
    /// Add a memory reference.
    fn add_memory_reference(
        &mut self,
        lifespan: Lifespan,
        from_address: u64,
        to_min: u64,
        to_max: u64,
        ref_type: TraceReferenceKind,
        is_primary: bool,
        operand_index: i32,
    ) -> i64;

    /// Add an offset memory reference.
    fn add_offset_reference(
        &mut self,
        lifespan: Lifespan,
        from_address: u64,
        to_address: u64,
        to_addr_is_base: bool,
        offset: i64,
        ref_type: TraceReferenceKind,
        is_primary: bool,
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
        is_primary: bool,
        operand_index: i32,
    ) -> i64;

    /// Add a stack reference.
    fn add_stack_reference(
        &mut self,
        lifespan: Lifespan,
        from_address: u64,
        to_stack_offset: i32,
        ref_type: TraceReferenceKind,
        is_primary: bool,
        operand_index: i32,
    ) -> i64;

    /// Find the reference that matches the given parameters.
    fn get_reference(
        &self,
        snap: i64,
        from_address: u64,
        to_min: u64,
        to_max: u64,
        operand_index: i32,
    ) -> Option<&TraceReference>;

    /// Find all references from the given snapshot and address.
    fn get_references_from(&self, snap: i64, from_address: u64) -> Vec<&TraceReference>;

    /// Find all references from the given snapshot, address, and operand index.
    fn get_references_from_operand(
        &self,
        snap: i64,
        from_address: u64,
        operand_index: i32,
    ) -> Vec<&TraceReference>;

    /// Find all references with from addresses contained in the given span and range.
    fn get_references_from_range(
        &self,
        span: &Lifespan,
        min_address: u64,
        max_address: u64,
    ) -> Vec<&TraceReference>;

    /// Get the primary reference from the given snapshot, address, and operand index.
    fn get_primary_reference_from(
        &self,
        snap: i64,
        from_address: u64,
        operand_index: i32,
    ) -> Option<&TraceReference>;

    /// Get all flow references from the given snapshot and address.
    fn get_flow_references_from(&self, snap: i64, from_address: u64) -> Vec<&TraceReference>;

    /// Clear all references from the given lifespan and address range.
    fn clear_references_from(&mut self, span: &Lifespan, min_address: u64, max_address: u64);

    /// Get all references whose to address contains the given snapshot and address.
    fn get_references_to(&self, snap: i64, to_address: u64) -> Vec<&TraceReference>;

    /// Clear all references to the given lifespan and address range.
    fn clear_references_to(&mut self, span: &Lifespan, min_address: u64, max_address: u64);

    /// Get all references whose to address range intersects the given span and range.
    fn get_references_to_range(
        &self,
        span: &Lifespan,
        min_address: u64,
        max_address: u64,
        order: Option<ReferenceOrder>,
    ) -> Vec<&TraceReference>;

    /// Check if there exists a reference from the given snapshot and address.
    fn has_references_from(&self, snap: i64, from_address: u64) -> bool;

    /// Check if there exists a flow reference from the given snapshot and address.
    fn has_flow_references_from(&self, snap: i64, from_address: u64) -> bool;

    /// Check if there exists a reference to the given snapshot and address.
    fn has_references_to(&self, snap: i64, to_address: u64) -> bool;

    /// Get all "from" addresses in any reference intersecting the given lifespan.
    fn get_reference_sources(&self, span: &Lifespan) -> Vec<u64>;

    /// Get all "to" addresses in any reference intersecting the given lifespan.
    fn get_reference_destinations(&self, span: &Lifespan) -> Vec<u64>;

    /// Count the number of references from the given snapshot and address.
    fn get_reference_count_from(&self, snap: i64, from_address: u64) -> usize;

    /// Count the number of references to the given snapshot and address.
    fn get_reference_count_to(&self, snap: i64, to_address: u64) -> usize;
}

/// A reference store that implements reference operations for a specific address space.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TraceReferenceSpace {
    /// The address space name.
    pub address_space: String,
    /// The references stored in this space.
    pub references: Vec<TraceReference>,
    /// The offset references.
    pub offset_references: Vec<TraceOffsetReference>,
    /// The shifted references.
    pub shifted_references: Vec<TraceShiftedReference>,
    /// The stack references.
    pub stack_references: Vec<TraceStackReference>,
    /// Next available reference key.
    next_key: i64,
}

impl TraceReferenceSpace {
    /// Create a new reference space.
    pub fn new(address_space: impl Into<String>) -> Self {
        Self {
            address_space: address_space.into(),
            references: Vec::new(),
            offset_references: Vec::new(),
            shifted_references: Vec::new(),
            stack_references: Vec::new(),
            next_key: 1,
        }
    }

    /// Get the address space name.
    pub fn address_space(&self) -> &str {
        &self.address_space
    }

    /// Get the total number of references (all types).
    pub fn total_reference_count(&self) -> usize {
        self.references.len()
            + self.offset_references.len()
            + self.shifted_references.len()
            + self.stack_references.len()
    }

    fn next_key(&mut self) -> i64 {
        let key = self.next_key;
        self.next_key += 1;
        key
    }
}

impl TraceReferenceOperations for TraceReferenceSpace {
    fn add_memory_reference(
        &mut self,
        lifespan: Lifespan,
        from_address: u64,
        to_min: u64,
        _to_max: u64,
        ref_type: TraceReferenceKind,
        is_primary: bool,
        _operand_index: i32,
    ) -> i64 {
        let key = self.next_key();
        self.references.push(TraceReference {
            key,
            from_address,
            to_address: to_min,
            kind: ref_type,
            lifespan,
            is_primary,
        });
        key
    }

    fn add_offset_reference(
        &mut self,
        lifespan: Lifespan,
        from_address: u64,
        to_address: u64,
        _to_addr_is_base: bool,
        _offset: i64,
        _ref_type: TraceReferenceKind,
        _is_primary: bool,
        _operand_index: i32,
    ) -> i64 {
        let key = self.next_key();
        self.offset_references.push(TraceOffsetReference::new(
            key,
            from_address,
            to_address,
            lifespan,
        ));
        key
    }

    fn add_shifted_reference(
        &mut self,
        lifespan: Lifespan,
        from_address: u64,
        to_address: u64,
        shift: i32,
        _ref_type: TraceReferenceKind,
        _is_primary: bool,
        _operand_index: i32,
    ) -> i64 {
        let key = self.next_key();
        self.shifted_references.push(TraceShiftedReference::new(
            key,
            from_address,
            to_address,
            shift,
            lifespan,
        ));
        key
    }

    fn add_stack_reference(
        &mut self,
        lifespan: Lifespan,
        from_address: u64,
        to_stack_offset: i32,
        _ref_type: TraceReferenceKind,
        _is_primary: bool,
        _operand_index: i32,
    ) -> i64 {
        let key = self.next_key();
        self.stack_references.push(TraceStackReference::new(
            key,
            from_address,
            to_stack_offset,
            lifespan,
        ));
        key
    }

    fn get_reference(
        &self,
        snap: i64,
        from_address: u64,
        to_min: u64,
        _to_max: u64,
        _operand_index: i32,
    ) -> Option<&TraceReference> {
        self.references.iter().find(|r| {
            r.from_address == from_address
                && r.to_address == to_min
                && r.lifespan.contains(snap)
        })
    }

    fn get_references_from(&self, snap: i64, from_address: u64) -> Vec<&TraceReference> {
        self.references
            .iter()
            .filter(|r| r.from_address == from_address && r.lifespan.contains(snap))
            .collect()
    }

    fn get_references_from_operand(
        &self,
        snap: i64,
        from_address: u64,
        _operand_index: i32,
    ) -> Vec<&TraceReference> {
        self.get_references_from(snap, from_address)
    }

    fn get_references_from_range(
        &self,
        span: &Lifespan,
        min_address: u64,
        max_address: u64,
    ) -> Vec<&TraceReference> {
        self.references
            .iter()
            .filter(|r| {
                r.lifespan.intersects(span)
                    && r.from_address >= min_address
                    && r.from_address <= max_address
            })
            .collect()
    }

    fn get_primary_reference_from(
        &self,
        snap: i64,
        from_address: u64,
        _operand_index: i32,
    ) -> Option<&TraceReference> {
        self.references.iter().find(|r| {
            r.from_address == from_address && r.lifespan.contains(snap) && r.is_primary
        })
    }

    fn get_flow_references_from(&self, snap: i64, from_address: u64) -> Vec<&TraceReference> {
        self.references
            .iter()
            .filter(|r| {
                r.from_address == from_address
                    && r.lifespan.contains(snap)
                    && r.kind.is_flow()
            })
            .collect()
    }

    fn clear_references_from(&mut self, span: &Lifespan, min_address: u64, max_address: u64) {
        self.references.retain(|r| {
            !(r.lifespan.intersects(span)
                && r.from_address >= min_address
                && r.from_address <= max_address)
        });
    }

    fn get_references_to(&self, snap: i64, to_address: u64) -> Vec<&TraceReference> {
        self.references
            .iter()
            .filter(|r| r.to_address == to_address && r.lifespan.contains(snap))
            .collect()
    }

    fn clear_references_to(&mut self, span: &Lifespan, min_address: u64, max_address: u64) {
        self.references.retain(|r| {
            !(r.lifespan.intersects(span)
                && r.to_address >= min_address
                && r.to_address <= max_address)
        });
    }

    fn get_references_to_range(
        &self,
        span: &Lifespan,
        min_address: u64,
        max_address: u64,
        _order: Option<ReferenceOrder>,
    ) -> Vec<&TraceReference> {
        let mut result: Vec<&TraceReference> = self
            .references
            .iter()
            .filter(|r| {
                r.lifespan.intersects(span)
                    && r.to_address >= min_address
                    && r.to_address <= max_address
            })
            .collect();

        match _order {
            Some(ReferenceOrder::LeftMost) => {
                result.sort_by_key(|r| r.to_address);
            }
            Some(ReferenceOrder::RightMost) => {
                result.sort_by(|a, b| b.to_address.cmp(&a.to_address));
            }
            Some(ReferenceOrder::TopMost) => {
                result.sort_by(|a, b| b.lifespan.lmin().cmp(&a.lifespan.lmin()));
            }
            Some(ReferenceOrder::BottomMost) => {
                result.sort_by_key(|r| r.lifespan.lmin());
            }
            _ => {}
        }
        result
    }

    fn has_references_from(&self, snap: i64, from_address: u64) -> bool {
        self.references
            .iter()
            .any(|r| r.from_address == from_address && r.lifespan.contains(snap))
    }

    fn has_flow_references_from(&self, snap: i64, from_address: u64) -> bool {
        self.references.iter().any(|r| {
            r.from_address == from_address && r.lifespan.contains(snap) && r.kind.is_flow()
        })
    }

    fn has_references_to(&self, snap: i64, to_address: u64) -> bool {
        self.references
            .iter()
            .any(|r| r.to_address == to_address && r.lifespan.contains(snap))
    }

    fn get_reference_sources(&self, span: &Lifespan) -> Vec<u64> {
        let mut sources: Vec<u64> = self
            .references
            .iter()
            .filter(|r| r.lifespan.intersects(span))
            .map(|r| r.from_address)
            .collect();
        sources.sort();
        sources.dedup();
        sources
    }

    fn get_reference_destinations(&self, span: &Lifespan) -> Vec<u64> {
        let mut dests: Vec<u64> = self
            .references
            .iter()
            .filter(|r| r.lifespan.intersects(span))
            .map(|r| r.to_address)
            .collect();
        dests.sort();
        dests.dedup();
        dests
    }

    fn get_reference_count_from(&self, snap: i64, from_address: u64) -> usize {
        self.references
            .iter()
            .filter(|r| r.from_address == from_address && r.lifespan.contains(snap))
            .count()
    }

    fn get_reference_count_to(&self, snap: i64, to_address: u64) -> usize {
        self.references
            .iter()
            .filter(|r| r.to_address == to_address && r.lifespan.contains(snap))
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ref_space() -> TraceReferenceSpace {
        TraceReferenceSpace::new("ram")
    }

    #[test]
    fn test_reference_space_basic() {
        let space = make_ref_space();
        assert_eq!(space.address_space(), "ram");
        assert_eq!(space.total_reference_count(), 0);
    }

    #[test]
    fn test_add_memory_reference() {
        let mut space = make_ref_space();
        let key = space.add_memory_reference(
            Lifespan::span(0, 10),
            0x1000,
            0x2000,
            0x2000,
            TraceReferenceKind::Memory,
            true,
            0,
        );
        assert_eq!(key, 1);
        assert_eq!(space.references.len(), 1);
    }

    #[test]
    fn test_get_references_from() {
        let mut space = make_ref_space();
        space.add_memory_reference(
            Lifespan::span(0, 10),
            0x1000,
            0x2000,
            0x2000,
            TraceReferenceKind::Memory,
            true,
            0,
        );
        space.add_memory_reference(
            Lifespan::span(0, 10),
            0x1000,
            0x3000,
            0x3000,
            TraceReferenceKind::Memory,
            false,
            0,
        );

        let refs = space.get_references_from(5, 0x1000);
        assert_eq!(refs.len(), 2);

        let refs_empty = space.get_references_from(15, 0x1000);
        assert!(refs_empty.is_empty());
    }

    #[test]
    fn test_get_references_to() {
        let mut space = make_ref_space();
        space.add_memory_reference(
            Lifespan::span(0, 10),
            0x1000,
            0x2000,
            0x2000,
            TraceReferenceKind::Memory,
            true,
            0,
        );

        let refs = space.get_references_to(5, 0x2000);
        assert_eq!(refs.len(), 1);
    }

    #[test]
    fn test_has_references() {
        let mut space = make_ref_space();
        space.add_memory_reference(
            Lifespan::span(0, 10),
            0x1000,
            0x2000,
            0x2000,
            TraceReferenceKind::Memory,
            true,
            0,
        );

        assert!(space.has_references_from(5, 0x1000));
        assert!(!space.has_references_from(15, 0x1000));
        assert!(space.has_references_to(5, 0x2000));
        assert!(!space.has_references_to(5, 0x3000));
    }

    #[test]
    fn test_clear_references() {
        let mut space = make_ref_space();
        space.add_memory_reference(
            Lifespan::span(0, 10),
            0x1000,
            0x2000,
            0x2000,
            TraceReferenceKind::Memory,
            true,
            0,
        );

        space.clear_references_from(&Lifespan::span(5, 8), 0x500, 0x1500);
        assert!(space.references.is_empty());
    }

    #[test]
    fn test_reference_sources_destinations() {
        let mut space = make_ref_space();
        space.add_memory_reference(
            Lifespan::span(0, 10),
            0x1000,
            0x2000,
            0x2000,
            TraceReferenceKind::Memory,
            true,
            0,
        );
        space.add_memory_reference(
            Lifespan::span(0, 10),
            0x1004,
            0x3000,
            0x3000,
            TraceReferenceKind::Memory,
            false,
            0,
        );

        let sources = space.get_reference_sources(&Lifespan::span(0, 10));
        assert_eq!(sources, vec![0x1000, 0x1004]);

        let dests = space.get_reference_destinations(&Lifespan::span(0, 10));
        assert_eq!(dests, vec![0x2000, 0x3000]);
    }

    #[test]
    fn test_reference_count() {
        let mut space = make_ref_space();
        space.add_memory_reference(
            Lifespan::span(0, 10),
            0x1000,
            0x2000,
            0x2000,
            TraceReferenceKind::Memory,
            true,
            0,
        );
        space.add_memory_reference(
            Lifespan::span(0, 10),
            0x1000,
            0x3000,
            0x3000,
            TraceReferenceKind::Memory,
            false,
            0,
        );

        assert_eq!(space.get_reference_count_from(5, 0x1000), 2);
        assert_eq!(space.get_reference_count_to(5, 0x2000), 1);
    }

    #[test]
    fn test_offset_reference() {
        let mut space = make_ref_space();
        let key = space.add_offset_reference(
            Lifespan::span(0, 10),
            0x1000,
            0x2000,
            true,
            0x10,
            TraceReferenceKind::Memory,
            true,
            0,
        );
        assert_eq!(key, 1);
        assert_eq!(space.offset_references.len(), 1);
        assert_eq!(space.offset_references[0].from_address(), 0x1000);
    }

    #[test]
    fn test_stack_reference() {
        let mut space = make_ref_space();
        let key = space.add_stack_reference(
            Lifespan::span(0, 10),
            0x1000,
            -8,
            TraceReferenceKind::Memory,
            true,
            0,
        );
        assert_eq!(key, 1);
        assert_eq!(space.stack_references.len(), 1);
        assert_eq!(space.stack_references[0].stack_offset, -8);
    }

    #[test]
    fn test_shifted_reference() {
        let mut space = make_ref_space();
        let key = space.add_shifted_reference(
            Lifespan::span(0, 10),
            0x1000,
            0x2000,
            2,
            TraceReferenceKind::Memory,
            true,
            0,
        );
        assert_eq!(key, 1);
        assert_eq!(space.shifted_references.len(), 1);
        assert_eq!(space.shifted_references[0].shift, 2);
    }

    #[test]
    fn test_get_references_to_range_ordered() {
        let mut space = make_ref_space();
        space.add_memory_reference(
            Lifespan::span(0, 10),
            0x1000,
            0x3000,
            0x3000,
            TraceReferenceKind::Memory,
            true,
            0,
        );
        space.add_memory_reference(
            Lifespan::span(0, 10),
            0x2000,
            0x1000,
            0x1000,
            TraceReferenceKind::Memory,
            false,
            0,
        );

        let refs = space.get_references_to_range(
            &Lifespan::span(0, 10),
            0x500,
            0x5000,
            Some(ReferenceOrder::LeftMost),
        );
        assert_eq!(refs.len(), 2);
        assert_eq!(refs[0].to_address, 0x1000);
        assert_eq!(refs[1].to_address, 0x3000);
    }
}
