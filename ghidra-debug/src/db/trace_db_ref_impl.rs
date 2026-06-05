//! DBTraceReference and related reference storage implementations.
//!
//! Ported from `ghidra/trace/database/symbol/DBTraceReference.java`,
//! `DBTraceOffsetReference.java`, `DBTraceShiftedReference.java`,
//! `DBTraceStackReference.java`, `DBTraceReferenceSpace.java`, and
//! `DBTraceReferenceManager.java`.
//!
//! These implement the storage and querying of cross-references in a
//! trace database.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

use crate::model::Lifespan;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur when working with trace references.
#[derive(Debug, Error)]
pub enum TraceRefError {
    /// The reference type is not allowed in traces.
    #[error("External references are not allowed in traces")]
    ExternalRefNotAllowed,

    /// The symbol associated with this reference does not exist.
    #[error("Symbol not found: {0}")]
    SymbolNotFound(u64),

    /// Address mismatch between symbol and reference target.
    #[error("Symbol address ({symbol_addr}) must match reference to-address ({ref_addr})")]
    AddressMismatch {
        /// The symbol's address.
        symbol_addr: u64,
        /// The reference's to-address.
        ref_addr: u64,
    },

    /// The associated symbol and reference do not have connected lifespans.
    #[error("Associated symbol and reference must have connected lifespans")]
    LifespanMismatch,

    /// The referenced space does not exist.
    #[error("Address space not found: {0}")]
    SpaceNotFound(String),

    /// A generic reference error.
    #[error("Reference error: {0}")]
    Other(String),
}

/// Result type for reference operations.
pub type TraceRefResult<T> = Result<T, TraceRefError>;

// ============================================================================
// Reference Type
// ============================================================================

/// The type of a reference (flow, data, etc.).
///
/// Ported from Ghidra's `RefType` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum RefType {
    /// Unconditional jump/call.
    Unconditional = 0,
    /// Conditional jump/call.
    Conditional = 1,
    /// Fall-through (sequential flow).
    FallThrough = 2,
    /// Data read.
    Read = 3,
    /// Data write.
    Write = 4,
    /// Data read/write.
    ReadWrite = 5,
    /// Indirection.
    Indirection = 6,
    /// Call.
    Call = 7,
    /// Jump.
    Jump = 8,
    /// No type.
    None = 255,
}

impl RefType {
    /// Whether this is a flow reference (jump or call).
    pub fn is_flow(&self) -> bool {
        matches!(
            self,
            RefType::Unconditional
                | RefType::Conditional
                | RefType::FallThrough
                | RefType::Call
                | RefType::Jump
        )
    }

    /// Whether this is a data reference.
    pub fn is_data(&self) -> bool {
        matches!(
            self,
            RefType::Read | RefType::Write | RefType::ReadWrite
        )
    }
}

impl Default for RefType {
    fn default() -> Self {
        RefType::None
    }
}

// ============================================================================
// Source Type
// ============================================================================

/// The source of a symbol or reference (user-defined, analysis, etc.).
///
/// Ported from Ghidra's `SourceType` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum SourceType {
    /// User-defined.
    UserDefined = 0,
    /// Analysis-generated.
    Analysis = 1,
    /// Default (imported/library).
    Default = 2,
}

impl Default for SourceType {
    fn default() -> Self {
        SourceType::Analysis
    }
}

// ============================================================================
// Reference Entry
// ============================================================================

/// A stored reference entry in the database.
///
/// Ported from `DBTraceReferenceEntry` inner class in
/// `DBTraceReferenceSpace.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceEntry {
    /// Unique ID for this reference.
    pub id: u64,
    /// The "from" address offset.
    pub from_offset: u64,
    /// The "to" address minimum offset.
    pub to_offset_min: u64,
    /// The "to" address maximum offset.
    pub to_offset_max: u64,
    /// The reference type.
    pub ref_type: RefType,
    /// The operand index.
    pub operand_index: u32,
    /// Source type.
    pub source: SourceType,
    /// Whether this is the primary reference.
    pub is_primary: bool,
    /// Associated symbol ID (-1 if none).
    pub symbol_id: i64,
    /// Minimum snap (inclusive).
    pub snap_min: i64,
    /// Maximum snap (inclusive).
    pub snap_max: i64,
    /// For offset references: the base address.
    pub to_base_offset: Option<u64>,
    /// For offset references: the offset from base.
    pub offset_value: Option<i64>,
    /// For shifted references: the shift amount.
    pub shift_value: Option<u32>,
    /// For stack references: the stack offset.
    pub stack_offset: Option<i32>,
    /// For register references: the register name.
    pub register_name: Option<String>,
}

impl ReferenceEntry {
    /// Get the lifespan of this reference.
    pub fn lifespan(&self) -> Lifespan {
        Lifespan::span(self.snap_min, self.snap_max)
    }

    /// Get the source type.
    pub fn source_type(&self) -> SourceType {
        self.source
    }

    /// Whether this is the primary reference from its source.
    pub fn is_primary(&self) -> bool {
        self.is_primary
    }

    /// Set the primary flag.
    pub fn set_primary(&mut self, primary: bool) {
        self.is_primary = primary;
    }

    /// Set the reference type.
    pub fn set_ref_type(&mut self, ref_type: RefType) {
        self.ref_type = ref_type;
    }

    /// Set the associated symbol ID.
    pub fn set_symbol_id(&mut self, id: i64) {
        self.symbol_id = id;
    }

    /// Set the lifespan.
    pub fn set_lifespan(&mut self, snap_min: i64, snap_max: i64) {
        self.snap_min = snap_min;
        self.snap_max = snap_max;
    }
}

// ============================================================================
// DBTraceReference
// ============================================================================

/// A trace reference wrapping a `ReferenceEntry`.
///
/// Ported from `DBTraceReference.java`.
#[derive(Debug, Clone)]
pub struct DbTraceReference {
    /// The underlying entry.
    pub entry: ReferenceEntry,
}

impl DbTraceReference {
    /// Create a new reference from an entry.
    pub fn new(entry: ReferenceEntry) -> Self {
        Self { entry }
    }

    /// Get the lifespan.
    pub fn lifespan(&self) -> Lifespan {
        self.entry.lifespan()
    }

    /// Get the start snap.
    pub fn start_snap(&self) -> i64 {
        self.entry.snap_min
    }

    /// Get the from address offset.
    pub fn from_offset(&self) -> u64 {
        self.entry.from_offset
    }

    /// Get the to address range (min, max).
    pub fn to_range(&self) -> (u64, u64) {
        (self.entry.to_offset_min, self.entry.to_offset_max)
    }

    /// Get the reference type.
    pub fn ref_type(&self) -> RefType {
        self.entry.ref_type
    }

    /// Get the operand index.
    pub fn operand_index(&self) -> u32 {
        self.entry.operand_index
    }

    /// Get the source type.
    pub fn source(&self) -> SourceType {
        self.entry.source
    }

    /// Whether this is the primary reference.
    pub fn is_primary(&self) -> bool {
        self.entry.is_primary()
    }

    /// Set the primary flag.
    pub fn set_primary(&mut self, primary: bool) {
        self.entry.set_primary(primary);
    }

    /// Set the reference type.
    pub fn set_ref_type(&mut self, ref_type: RefType) {
        self.entry.set_ref_type(ref_type);
    }

    /// Set the associated symbol.
    pub fn set_associated_symbol(&mut self, symbol_id: u64) -> TraceRefResult<()> {
        self.entry.set_symbol_id(symbol_id as i64);
        Ok(())
    }

    /// Clear the associated symbol.
    pub fn clear_associated_symbol(&mut self) {
        self.entry.set_symbol_id(-1);
    }

    /// Get the symbol ID.
    pub fn symbol_id(&self) -> i64 {
        self.entry.symbol_id
    }

    /// Delete this reference.
    pub fn delete(&self) -> TraceRefResult<()> {
        // In the full implementation, this would:
        // 1. Acquire write lock
        // 2. Delete from the entry
        // 3. Fire REFERENCE_DELETED event
        // 4. If primary, promote another reference
        Ok(())
    }
}

/// An offset reference.
///
/// Ported from `DBTraceOffsetReference.java`.
#[derive(Debug, Clone)]
pub struct DbTraceOffsetReference {
    /// The base reference.
    pub reference: DbTraceReference,
}

impl DbTraceOffsetReference {
    /// Whether the to-address is the base of the offset.
    pub fn to_addr_is_base(&self) -> bool {
        self.reference.entry.to_base_offset.is_some()
    }

    /// Get the offset value.
    pub fn offset_value(&self) -> i64 {
        self.reference.entry.offset_value.unwrap_or(0)
    }
}

/// A shifted reference.
///
/// Ported from `DBTraceShiftedReference.java`.
#[derive(Debug, Clone)]
pub struct DbTraceShiftedReference {
    /// The base reference.
    pub reference: DbTraceReference,
}

impl DbTraceShiftedReference {
    /// Get the shift value.
    pub fn shift_value(&self) -> u32 {
        self.reference.entry.shift_value.unwrap_or(0)
    }
}

/// A stack reference.
///
/// Ported from `DBTraceStackReference.java`.
#[derive(Debug, Clone)]
pub struct DbTraceStackReference {
    /// The base reference.
    pub reference: DbTraceReference,
}

impl DbTraceStackReference {
    /// Get the stack offset.
    pub fn stack_offset(&self) -> i32 {
        self.reference.entry.stack_offset.unwrap_or(0)
    }
}

// ============================================================================
// DBTraceReferenceSpace
// ============================================================================

/// A reference space storing references for a specific address space.
///
/// Ported from `DBTraceReferenceSpace.java`.
#[derive(Debug)]
pub struct DbTraceReferenceSpace {
    /// The space name.
    pub space_name: String,
    /// The next reference ID.
    next_id: u64,
    /// Stored references, indexed by ID.
    references: BTreeMap<u64, ReferenceEntry>,
    /// Forward references: from_offset -> vec of reference IDs.
    forward_refs: BTreeMap<u64, Vec<u64>>,
    /// Backward references: to_offset -> vec of reference IDs.
    backward_refs: BTreeMap<u64, Vec<u64>>,
}

impl DbTraceReferenceSpace {
    /// Create a new reference space.
    pub fn new(space_name: String) -> Self {
        Self {
            space_name,
            next_id: 1,
            references: BTreeMap::new(),
            forward_refs: BTreeMap::new(),
            backward_refs: BTreeMap::new(),
        }
    }

    /// Add a reference entry.
    pub fn add_reference(&mut self, mut entry: ReferenceEntry) -> TraceRefResult<u64> {
        let id = self.next_id;
        self.next_id += 1;
        entry.id = id;

        // Index forward references
        self.forward_refs
            .entry(entry.from_offset)
            .or_default()
            .push(id);

        // Index backward references
        self.backward_refs
            .entry(entry.to_offset_min)
            .or_default()
            .push(id);

        self.references.insert(id, entry);
        Ok(id)
    }

    /// Delete a reference by ID.
    pub fn delete_reference(&mut self, id: u64) -> TraceRefResult<()> {
        if let Some(entry) = self.references.remove(&id) {
            if let Some(refs) = self.forward_refs.get_mut(&entry.from_offset) {
                refs.retain(|&r| r != id);
            }
            if let Some(refs) = self.backward_refs.get_mut(&entry.to_offset_min) {
                refs.retain(|&r| r != id);
            }
        }
        Ok(())
    }

    /// Get a reference by ID.
    pub fn get_reference(&self, id: u64) -> Option<&ReferenceEntry> {
        self.references.get(&id)
    }

    /// Get all references from a given address at a given snap.
    pub fn get_references_from(&self, _snap: i64, from_offset: u64) -> Vec<&ReferenceEntry> {
        self.forward_refs
            .get(&from_offset)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.references.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all references from a given address and operand.
    pub fn get_references_from_operand(
        &self,
        _snap: i64,
        from_offset: u64,
        operand_index: u32,
    ) -> Vec<&ReferenceEntry> {
        self.get_references_from(_snap, from_offset)
            .into_iter()
            .filter(|r| r.operand_index == operand_index)
            .collect()
    }

    /// Get flow references from a given address.
    pub fn get_flow_references_from(&self, snap: i64, from_offset: u64) -> Vec<&ReferenceEntry> {
        self.get_references_from(snap, from_offset)
            .into_iter()
            .filter(|r| r.ref_type.is_flow())
            .collect()
    }

    /// Get the primary reference from a given address and operand.
    pub fn get_primary_reference_from(
        &self,
        snap: i64,
        from_offset: u64,
        operand_index: u32,
    ) -> Option<&ReferenceEntry> {
        self.get_references_from_operand(snap, from_offset, operand_index)
            .into_iter()
            .find(|r| r.is_primary())
    }

    /// Get all references to a given address.
    pub fn get_references_to(&self, _snap: i64, to_offset: u64) -> Vec<&ReferenceEntry> {
        self.backward_refs
            .get(&to_offset)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.references.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Clear all references from a range.
    pub fn clear_references_from(
        &mut self,
        _span: &Lifespan,
        from_offset_min: u64,
        from_offset_max: u64,
    ) {
        let ids_to_remove: Vec<u64> = self
            .forward_refs
            .range(from_offset_min..=from_offset_max)
            .flat_map(|(_, ids)| ids.clone())
            .collect();

        for id in ids_to_remove {
            self.delete_reference(id).ok();
        }
    }

    /// Get reference count from an address.
    pub fn reference_count_from(&self, _snap: i64, from_offset: u64) -> usize {
        self.forward_refs
            .get(&from_offset)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Get reference count to an address.
    pub fn reference_count_to(&self, _snap: i64, to_offset: u64) -> usize {
        self.backward_refs
            .get(&to_offset)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Get references by associated symbol ID.
    pub fn get_references_by_symbol_id(&self, symbol_id: u64) -> Vec<&ReferenceEntry> {
        self.references
            .values()
            .filter(|r| r.symbol_id == symbol_id as i64)
            .collect()
    }

    /// Get all source address offsets (address set view).
    pub fn reference_sources(&self) -> Vec<u64> {
        self.forward_refs.keys().copied().collect()
    }

    /// Get all destination address offsets (address set view).
    pub fn reference_destinations(&self) -> Vec<u64> {
        self.backward_refs.keys().copied().collect()
    }

    /// Add xref to the backward index.
    pub fn do_add_xref(&mut self, entry: &ReferenceEntry) {
        self.backward_refs
            .entry(entry.to_offset_min)
            .or_default()
            .push(entry.id);
    }

    /// Delete xref from the backward index.
    pub fn do_del_xref(&mut self, entry: &ReferenceEntry) {
        if let Some(refs) = self.backward_refs.get_mut(&entry.to_offset_min) {
            refs.retain(|&r| r != entry.id);
        }
    }

    /// Get total number of references.
    pub fn len(&self) -> usize {
        self.references.len()
    }

    /// Check if this space is empty.
    pub fn is_empty(&self) -> bool {
        self.references.is_empty()
    }
}

// ============================================================================
// DBTraceReferenceManager
// ============================================================================

/// Manager for all reference spaces in a trace.
///
/// Ported from `DBTraceReferenceManager.java`.
#[derive(Debug)]
pub struct DbTraceReferenceManager {
    /// Reference spaces keyed by space name.
    spaces: BTreeMap<String, DbTraceReferenceSpace>,
    /// The next reference ID counter.
    next_id: u64,
}

impl DbTraceReferenceManager {
    /// Create a new reference manager.
    pub fn new() -> Self {
        Self {
            spaces: BTreeMap::new(),
            next_id: 1,
        }
    }

    /// Get or create a reference space.
    pub fn get_or_create_space(&mut self, space_name: &str) -> &mut DbTraceReferenceSpace {
        self.spaces
            .entry(space_name.to_string())
            .or_insert_with(|| DbTraceReferenceSpace::new(space_name.to_string()))
    }

    /// Get a reference space if it exists.
    pub fn get_space(&self, space_name: &str) -> Option<&DbTraceReferenceSpace> {
        self.spaces.get(space_name)
    }

    /// Add a memory reference.
    pub fn add_memory_reference(
        &mut self,
        space_name: &str,
        lifespan: &Lifespan,
        from_offset: u64,
        to_offset_min: u64,
        to_offset_max: u64,
        ref_type: RefType,
        source: SourceType,
        operand_index: u32,
    ) -> TraceRefResult<u64> {
        let id = self.next_id;
        self.next_id += 1;

        let entry = ReferenceEntry {
            id,
            from_offset,
            to_offset_min,
            to_offset_max,
            ref_type,
            operand_index,
            source,
            is_primary: false,
            symbol_id: -1,
            snap_min: lifespan.lmin(),
            snap_max: lifespan.lmax(),
            to_base_offset: None,
            offset_value: None,
            shift_value: None,
            stack_offset: None,
            register_name: None,
        };

        let space = self.get_or_create_space(space_name);
        space.add_reference(entry)
    }

    /// Add an offset reference.
    pub fn add_offset_reference(
        &mut self,
        space_name: &str,
        lifespan: &Lifespan,
        from_offset: u64,
        to_offset: u64,
        to_addr_is_base: bool,
        offset: i64,
        ref_type: RefType,
        source: SourceType,
        operand_index: u32,
    ) -> TraceRefResult<u64> {
        let id = self.next_id;
        self.next_id += 1;

        let entry = ReferenceEntry {
            id,
            from_offset,
            to_offset_min: to_offset,
            to_offset_max: to_offset,
            ref_type,
            operand_index,
            source,
            is_primary: false,
            symbol_id: -1,
            snap_min: lifespan.lmin(),
            snap_max: lifespan.lmax(),
            to_base_offset: if to_addr_is_base {
                Some(to_offset)
            } else {
                None
            },
            offset_value: Some(offset),
            shift_value: None,
            stack_offset: None,
            register_name: None,
        };

        let space = self.get_or_create_space(space_name);
        space.add_reference(entry)
    }

    /// Add a shifted reference.
    pub fn add_shifted_reference(
        &mut self,
        space_name: &str,
        lifespan: &Lifespan,
        from_offset: u64,
        to_offset: u64,
        shift: u32,
        ref_type: RefType,
        source: SourceType,
        operand_index: u32,
    ) -> TraceRefResult<u64> {
        let id = self.next_id;
        self.next_id += 1;

        let entry = ReferenceEntry {
            id,
            from_offset,
            to_offset_min: to_offset,
            to_offset_max: to_offset,
            ref_type,
            operand_index,
            source,
            is_primary: false,
            symbol_id: -1,
            snap_min: lifespan.lmin(),
            snap_max: lifespan.lmax(),
            to_base_offset: None,
            offset_value: None,
            shift_value: Some(shift),
            stack_offset: None,
            register_name: None,
        };

        let space = self.get_or_create_space(space_name);
        space.add_reference(entry)
    }

    /// Add a stack reference.
    pub fn add_stack_reference(
        &mut self,
        space_name: &str,
        lifespan: &Lifespan,
        from_offset: u64,
        stack_offset: i32,
        ref_type: RefType,
        source: SourceType,
        operand_index: u32,
    ) -> TraceRefResult<u64> {
        let id = self.next_id;
        self.next_id += 1;

        let entry = ReferenceEntry {
            id,
            from_offset,
            to_offset_min: 0,
            to_offset_max: 0,
            ref_type,
            operand_index,
            source,
            is_primary: false,
            symbol_id: -1,
            snap_min: lifespan.lmin(),
            snap_max: lifespan.lmax(),
            to_base_offset: None,
            offset_value: None,
            shift_value: None,
            stack_offset: Some(stack_offset),
            register_name: None,
        };

        let space = self.get_or_create_space(space_name);
        space.add_reference(entry)
    }

    /// Add a register reference.
    pub fn add_register_reference(
        &mut self,
        space_name: &str,
        lifespan: &Lifespan,
        from_offset: u64,
        register_name: String,
        ref_type: RefType,
        source: SourceType,
        operand_index: u32,
    ) -> TraceRefResult<u64> {
        let id = self.next_id;
        self.next_id += 1;

        let entry = ReferenceEntry {
            id,
            from_offset,
            to_offset_min: 0,
            to_offset_max: 0,
            ref_type,
            operand_index,
            source,
            is_primary: false,
            symbol_id: -1,
            snap_min: lifespan.lmin(),
            snap_max: lifespan.lmax(),
            to_base_offset: None,
            offset_value: None,
            shift_value: None,
            stack_offset: None,
            register_name: Some(register_name),
        };

        let space = self.get_or_create_space(space_name);
        space.add_reference(entry)
    }

    /// Get references from an address.
    pub fn get_references_from(
        &self,
        space_name: &str,
        snap: i64,
        from_offset: u64,
    ) -> Vec<&ReferenceEntry> {
        self.spaces
            .get(space_name)
            .map(|s| s.get_references_from(snap, from_offset))
            .unwrap_or_default()
    }

    /// Get references to an address.
    pub fn get_references_to(
        &self,
        space_name: &str,
        snap: i64,
        to_offset: u64,
    ) -> Vec<&ReferenceEntry> {
        self.spaces
            .get(space_name)
            .map(|s| s.get_references_to(snap, to_offset))
            .unwrap_or_default()
    }

    /// Get total number of references across all spaces.
    pub fn total_references(&self) -> usize {
        self.spaces.values().map(|s| s.len()).sum()
    }

    /// Get all space names.
    pub fn space_names(&self) -> Vec<&str> {
        self.spaces.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for DbTraceReferenceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_lifespan() -> Lifespan {
        Lifespan::span(0, 100)
    }

    #[test]
    fn test_ref_type_classification() {
        assert!(RefType::Jump.is_flow());
        assert!(RefType::Call.is_flow());
        assert!(!RefType::Read.is_flow());
        assert!(RefType::Read.is_data());
        assert!(RefType::Write.is_data());
    }

    #[test]
    fn test_reference_space_add_and_get() {
        let mut space = DbTraceReferenceSpace::new("ram".into());
        let entry = ReferenceEntry {
            id: 0,
            from_offset: 0x1000,
            to_offset_min: 0x2000,
            to_offset_max: 0x2000,
            ref_type: RefType::Jump,
            operand_index: 0,
            source: SourceType::Analysis,
            is_primary: true,
            symbol_id: -1,
            snap_min: 0,
            snap_max: 100,
            to_base_offset: None,
            offset_value: None,
            shift_value: None,
            stack_offset: None,
            register_name: None,
        };
        let id = space.add_reference(entry).unwrap();
        assert_eq!(id, 1);

        let ref_from = space.get_references_from(0, 0x1000);
        assert_eq!(ref_from.len(), 1);
        assert_eq!(ref_from[0].to_offset_min, 0x2000);

        let ref_to = space.get_references_to(0, 0x2000);
        assert_eq!(ref_to.len(), 1);
    }

    #[test]
    fn test_reference_space_delete() {
        let mut space = DbTraceReferenceSpace::new("ram".into());
        let entry = ReferenceEntry {
            id: 0,
            from_offset: 0x1000,
            to_offset_min: 0x2000,
            to_offset_max: 0x2000,
            ref_type: RefType::Jump,
            operand_index: 0,
            source: SourceType::Analysis,
            is_primary: true,
            symbol_id: -1,
            snap_min: 0,
            snap_max: 100,
            to_base_offset: None,
            offset_value: None,
            shift_value: None,
            stack_offset: None,
            register_name: None,
        };
        let id = space.add_reference(entry).unwrap();
        assert_eq!(space.len(), 1);

        space.delete_reference(id).unwrap();
        assert_eq!(space.len(), 0);
        assert!(space.get_references_from(0, 0x1000).is_empty());
    }

    #[test]
    fn test_reference_manager_memory_ref() {
        let mut mgr = DbTraceReferenceManager::new();
        let id = mgr
            .add_memory_reference(
                "ram",
                &test_lifespan(),
                0x1000,
                0x2000,
                0x2000,
                RefType::Jump,
                SourceType::Analysis,
                0,
            )
            .unwrap();
        assert!(id > 0);

        let refs = mgr.get_references_from("ram", 0, 0x1000);
        assert_eq!(refs.len(), 1);
    }

    #[test]
    fn test_reference_manager_offset_ref() {
        let mut mgr = DbTraceReferenceManager::new();
        let id = mgr
            .add_offset_reference(
                "ram",
                &test_lifespan(),
                0x1000,
                0x2000,
                true,
                0x100,
                RefType::Read,
                SourceType::UserDefined,
                1,
            )
            .unwrap();
        assert!(id > 0);
    }

    #[test]
    fn test_reference_manager_stack_ref() {
        let mut mgr = DbTraceReferenceManager::new();
        let id = mgr
            .add_stack_reference(
                "register",
                &test_lifespan(),
                0x1000,
                -8,
                RefType::Read,
                SourceType::Analysis,
                0,
            )
            .unwrap();
        assert!(id > 0);
    }

    #[test]
    fn test_reference_manager_total() {
        let mut mgr = DbTraceReferenceManager::new();
        mgr.add_memory_reference(
            "ram",
            &test_lifespan(),
            0x1000,
            0x2000,
            0x2000,
            RefType::Jump,
            SourceType::Analysis,
            0,
        )
        .unwrap();
        mgr.add_memory_reference(
            "ram",
            &test_lifespan(),
            0x1100,
            0x3000,
            0x3000,
            RefType::Call,
            SourceType::Analysis,
            0,
        )
        .unwrap();

        assert_eq!(mgr.total_references(), 2);
        assert_eq!(mgr.space_names(), vec!["ram"]);
    }

    #[test]
    fn test_reference_count_from() {
        let mut space = DbTraceReferenceSpace::new("ram".into());
        for i in 0..5 {
            let entry = ReferenceEntry {
                id: 0,
                from_offset: 0x1000,
                to_offset_min: 0x2000 + i * 0x100,
                to_offset_max: 0x2000 + i * 0x100,
                ref_type: RefType::Jump,
                operand_index: 0,
                source: SourceType::Analysis,
                is_primary: i == 0,
                symbol_id: -1,
                snap_min: 0,
                snap_max: 100,
                to_base_offset: None,
                offset_value: None,
                shift_value: None,
                stack_offset: None,
                register_name: None,
            };
            space.add_reference(entry).unwrap();
        }

        assert_eq!(space.reference_count_from(0, 0x1000), 5);
        assert_eq!(space.reference_count_to(0, 0x2000), 1);
    }
}
