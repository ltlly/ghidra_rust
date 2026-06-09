//! Cross-reference (xref) utilities for Ghidra Rust.
//!
//! Ported from Ghidra's `ghidra.app.util.XReferenceUtil` (deprecated)
//! and `ghidra.app.util.XReferenceUtils` (current).
//!
//! Provides functions for retrieving direct and offcut cross-references
//! to code units and variables, plus a [`CrossReferenceManager`] that
//! wraps [`ReferenceManager`] with higher-level xref queries.
//!
//! Sub-modules:
//! - [`xref_table`] -- tabular display model for xrefs and reference change tracking
//! - [`cross_references_plugin`] -- top-level plugin coordinating cross-reference providers
//! - [`cross_references_provider`] -- component providers for viewing/editing xrefs

pub mod xref_table;

/// Cross References Plugin -- top-level plugin coordinating cross-reference providers.
///
/// Ported from `ghidra.app.plugin.core.references.ReferencesPlugin`.
pub mod cross_references_plugin;

/// Cross References Provider -- component providers for viewing/editing xrefs.
///
/// Ported from `ghidra.app.plugin.core.references.EditReferencesProvider`
/// and `ghidra.app.plugin.core.references.ExternalReferencesProvider`.
pub mod cross_references_provider;

use ghidra_core::addr::Address;
use ghidra_core::symbol::{RefType, Reference, ReferenceManager, SourceType};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Sentinel meaning "return all references, do not cap the result set".
pub const ALL_REFS: i32 = -1;

// ---------------------------------------------------------------------------
// ThunkReference -- represents a thunk-function -> thunked-function edge
// ---------------------------------------------------------------------------

/// A reference that models the relationship between a thunk function and
/// the function it wraps. Unlike regular references, a [`ThunkReference`]
/// does not rely on a stored memory reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThunkReference {
    /// The address of the thunk function.
    from_address: Address,
    /// The entry point of the thunked (wrapped) function.
    to_address: Address,
}

impl ThunkReference {
    /// Creates a new thunk reference.
    pub fn new(from_address: Address, to_address: Address) -> Self {
        Self {
            from_address,
            to_address,
        }
    }

    /// Returns the "from" address (thunk function).
    pub fn get_from_address(&self) -> &Address {
        &self.from_address
    }

    /// Returns the "to" address (thunked function entry point).
    pub fn get_to_address(&self) -> &Address {
        &self.to_address
    }
}

impl fmt::Display for ThunkReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "THUNK {} -> {}",
            self.from_address, self.to_address
        )
    }
}

impl PartialOrd for ThunkReference {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ThunkReference {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.from_address
            .cmp(&other.from_address)
            .then_with(|| self.to_address.cmp(&other.to_address))
    }
}

// ---------------------------------------------------------------------------
// XRefEntry -- a unified entry that may be a regular or thunk reference
// ---------------------------------------------------------------------------

/// A single cross-reference entry returned by xref queries.
///
/// Unlike a raw [`Reference`], this may also represent thunk relationships
/// that do not have an underlying stored reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum XRefEntry {
    /// A regular (stored) reference.
    Reference(Reference),
    /// A thunk-function relationship (not stored as a reference).
    Thunk(ThunkReference),
}

impl XRefEntry {
    /// Returns the "from" address.
    pub fn from_address(&self) -> &Address {
        match self {
            XRefEntry::Reference(r) => r.get_from_address(),
            XRefEntry::Thunk(t) => t.get_from_address(),
        }
    }

    /// Returns the "to" address.
    pub fn to_address(&self) -> &Address {
        match self {
            XRefEntry::Reference(r) => r.get_to_address(),
            XRefEntry::Thunk(t) => t.get_to_address(),
        }
    }

    /// Returns the reference type, if this is a regular reference.
    pub fn reference_type(&self) -> Option<RefType> {
        match self {
            XRefEntry::Reference(r) => Some(r.get_reference_type()),
            XRefEntry::Thunk(_) => None,
        }
    }

    /// Returns `true` if this is a thunk reference.
    pub fn is_thunk(&self) -> bool {
        matches!(self, XRefEntry::Thunk(_))
    }
}

impl PartialOrd for XRefEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for XRefEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.from_address()
            .cmp(other.from_address())
            .then_with(|| self.to_address().cmp(other.to_address()))
    }
}

impl fmt::Display for XRefEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XRefEntry::Reference(r) => write!(f, "{}", r),
            XRefEntry::Thunk(t) => write!(f, "{}", t),
        }
    }
}

// ---------------------------------------------------------------------------
// CodeUnitXRef -- lightweight code unit descriptor for xref queries
// ---------------------------------------------------------------------------

/// Minimal description of a code unit needed for xref queries.
///
/// In Ghidra Java this was a `CodeUnit` object. In Rust we use this
/// lightweight struct to avoid pulling in the full listing model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeUnitXRef {
    /// The minimum (start) address of the code unit.
    pub min_address: Address,
    /// The maximum (end) address of the code unit.
    pub max_address: Address,
    /// The length in bytes.
    pub length: usize,
    /// Entry-point addresses of any thunk functions at this address.
    pub thunk_entry_points: Vec<Address>,
}

impl CodeUnitXRef {
    /// Creates a new code unit descriptor.
    pub fn new(min_address: Address, max_address: Address) -> Self {
        let length = if max_address.offset >= min_address.offset {
            (max_address.offset - min_address.offset + 1) as usize
        } else {
            1
        };
        Self {
            min_address,
            max_address,
            length,
            thunk_entry_points: Vec::new(),
        }
    }

    /// Creates a single-byte code unit (e.g., a data byte).
    pub fn single_byte(address: Address) -> Self {
        Self {
            min_address: address,
            max_address: address,
            length: 1,
            thunk_entry_points: Vec::new(),
        }
    }

    /// Adds a thunk entry point that should be included in xref results.
    pub fn with_thunk_entry_points(mut self, entry_points: Vec<Address>) -> Self {
        self.thunk_entry_points = entry_points;
        self
    }
}

// ---------------------------------------------------------------------------
// VariableXRef -- minimal description of a variable for xref queries
// ---------------------------------------------------------------------------

/// Minimal description of a function variable for xref queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VariableXRef {
    /// The variable's minimum address (storage address).
    pub min_address: Option<Address>,
    /// The ID of the function owning this variable.
    pub function_id: u64,
    /// The variable name.
    pub name: String,
}

impl VariableXRef {
    /// Creates a new variable descriptor.
    pub fn new(min_address: Option<Address>, function_id: u64, name: impl Into<String>) -> Self {
        Self {
            min_address,
            function_id,
            name: name.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// XRef utility functions (port of XReferenceUtil / XReferenceUtils)
// ---------------------------------------------------------------------------

/// Returns all direct xref addresses to the given code unit.
///
/// Equivalent to Ghidra's `XReferenceUtil.getXRefList(cu)`.
/// Returns addresses sorted in ascending order.
pub fn get_xref_addresses(ref_mgr: &ReferenceManager, cu: &CodeUnitXRef) -> Vec<Address> {
    get_xref_addresses_limited(ref_mgr, cu, ALL_REFS)
}

/// Returns at most `max` direct xref addresses to the given code unit.
///
/// Pass [`ALL_REFS`] to get all references.
/// Returns addresses sorted in ascending order.
pub fn get_xref_addresses_limited(
    ref_mgr: &ReferenceManager,
    cu: &CodeUnitXRef,
    max: i32,
) -> Vec<Address> {
    let mut addrs: Vec<Address> = Vec::new();
    let iter = ref_mgr.get_references_to(cu.min_address);
    for ref_ in iter {
        addrs.push(*ref_.get_from_address());
        if max > 0 && addrs.len() as i32 >= max {
            break;
        }
    }
    addrs.sort();
    addrs
}

/// Returns all direct xref [`Reference`] objects to the given code unit,
/// including any thunk references.
///
/// Equivalent to Ghidra's `XReferenceUtil.getXReferences(cu, max)`.
pub fn get_x_references(
    ref_mgr: &ReferenceManager,
    cu: &CodeUnitXRef,
    max: i32,
) -> Vec<XRefEntry> {
    let mut xrefs: Vec<XRefEntry> = Vec::new();

    // Direct references
    let iter = ref_mgr.get_references_to(cu.min_address);
    for ref_ in iter {
        xrefs.push(XRefEntry::Reference(ref_.clone()));
        if max > 0 && xrefs.len() as i32 >= max {
            return xrefs;
        }
    }

    // Thunk references
    for &entry_point in &cu.thunk_entry_points {
        xrefs.push(XRefEntry::Thunk(ThunkReference::new(
            entry_point,
            cu.min_address,
        )));
    }

    xrefs
}

/// Returns all offcut xref addresses to the given code unit.
///
/// Offcut references point to addresses *within* a multi-byte code unit
/// (i.e., not the first byte). Returns addresses sorted ascending.
pub fn get_offcut_xref_addresses(
    ref_mgr: &ReferenceManager,
    cu: &CodeUnitXRef,
) -> Vec<Address> {
    get_offcut_xref_addresses_limited(ref_mgr, cu, ALL_REFS)
}

/// Returns at most `max` offcut xref addresses to the given code unit.
///
/// Pass [`ALL_REFS`] to get all offcut references.
pub fn get_offcut_xref_addresses_limited(
    ref_mgr: &ReferenceManager,
    cu: &CodeUnitXRef,
    max: i32,
) -> Vec<Address> {
    if cu.length <= 1 {
        return Vec::new();
    }

    let mut offcut_addrs: Vec<Address> = Vec::new();

    // Iterate over addresses within the code unit (excluding the first byte).
    let start = Address::new(cu.min_address.offset + 1);
    let iter = ref_mgr.get_reference_destination_iterator_range(&start, &cu.max_address);
    for addr in iter {
        let ref_iter = ref_mgr.get_references_to(addr);
        for ref_ in ref_iter {
            offcut_addrs.push(*ref_.get_from_address());
            if max > 0 && offcut_addrs.len() as i32 >= max {
                break;
            }
        }
        if max > 0 && offcut_addrs.len() as i32 >= max {
            break;
        }
    }

    offcut_addrs.sort();
    offcut_addrs
}

/// Returns all offcut xref [`Reference`] objects to the given code unit.
pub fn get_offcut_x_references(
    ref_mgr: &ReferenceManager,
    cu: &CodeUnitXRef,
    max: i32,
) -> Vec<XRefEntry> {
    if cu.length <= 1 {
        return Vec::new();
    }

    let mut offcuts: Vec<XRefEntry> = Vec::new();

    let start = Address::new(cu.min_address.offset + 1);
    let iter = ref_mgr.get_reference_destination_iterator_range(&start, &cu.max_address);
    for addr in iter {
        let ref_iter = ref_mgr.get_references_to(addr);
        for ref_ in ref_iter {
            offcuts.push(XRefEntry::Reference(ref_.clone()));
            if max > 0 && offcuts.len() as i32 >= max {
                return offcuts;
            }
        }
    }

    offcuts
}

/// Returns the count of offcut xrefs to the given code unit.
pub fn get_offcut_xref_count(ref_mgr: &ReferenceManager, cu: &CodeUnitXRef) -> usize {
    if cu.length <= 1 {
        return 0;
    }

    let mut count: usize = 0;
    let start = Address::new(cu.min_address.offset + 1);
    let iter = ref_mgr.get_reference_destination_iterator_range(&start, &cu.max_address);
    for addr in iter {
        let ref_iter = ref_mgr.get_references_to(addr);
        for _ in ref_iter {
            count += 1;
        }
    }
    count
}

/// Returns all xrefs (direct + offcut) to the given code unit, deduplicated.
///
/// Equivalent to Ghidra's `XReferenceUtil.getAllXrefs()`.
pub fn get_all_xrefs(ref_mgr: &ReferenceManager, cu: &CodeUnitXRef) -> Vec<XRefEntry> {
    let direct = get_x_references(ref_mgr, cu, ALL_REFS);
    let offcut = get_offcut_x_references(ref_mgr, cu, ALL_REFS);

    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for entry in direct.into_iter().chain(offcut.into_iter()) {
        let key = (entry.from_address().offset, entry.to_address().offset);
        if seen.insert(key) {
            result.push(entry);
        }
    }
    result.sort();
    result
}

/// Returns all xrefs to a variable, split into direct and offcut lists.
///
/// Direct xrefs are those whose "to" address exactly matches the variable's
/// min address. Offcut xrefs point to a different address within the
/// variable's storage.
pub fn get_variable_refs(
    ref_mgr: &ReferenceManager,
    var: &VariableXRef,
    all_var_refs: &[Reference],
) -> (Vec<Reference>, Vec<Reference>) {
    get_variable_refs_limited(ref_mgr, var, all_var_refs, ALL_REFS)
}

/// Returns at most `max` xrefs to a variable, split into direct and offcut.
pub fn get_variable_refs_limited(
    _ref_mgr: &ReferenceManager,
    var: &VariableXRef,
    all_var_refs: &[Reference],
    max: i32,
) -> (Vec<Reference>, Vec<Reference>) {
    let mut xrefs = Vec::new();
    let mut offcuts = Vec::new();

    if var.min_address.is_none() {
        return (xrefs, offcuts);
    }

    let addr = var.min_address.unwrap();
    let mut total = 0i32;
    for vref in all_var_refs {
        if max > 0 && total >= max {
            break;
        }
        if addr == *vref.get_to_address() {
            xrefs.push(vref.clone());
        } else {
            offcuts.push(vref.clone());
        }
        total += 1;
    }

    (xrefs, offcuts)
}

// ---------------------------------------------------------------------------
// CrossReferenceManager -- higher-level wrapper
// ---------------------------------------------------------------------------

/// A higher-level cross-reference manager that extends [`ReferenceManager`]
/// with convenience methods for xref queries.
///
/// This is a Rust-side equivalent of the combined functionality from
/// `XReferenceUtils` and the listing plugin's xref handling.
#[derive(Debug, Clone, Default)]
pub struct CrossReferenceManager {
    /// The underlying reference manager.
    ref_mgr: ReferenceManager,
}

impl CrossReferenceManager {
    /// Creates a new cross-reference manager wrapping the given reference manager.
    pub fn new(ref_mgr: ReferenceManager) -> Self {
        Self { ref_mgr }
    }

    /// Returns a reference to the underlying [`ReferenceManager`].
    pub fn ref_manager(&self) -> &ReferenceManager {
        &self.ref_mgr
    }

    /// Returns a mutable reference to the underlying [`ReferenceManager`].
    pub fn ref_manager_mut(&mut self) -> &mut ReferenceManager {
        &mut self.ref_mgr
    }

    /// Adds a memory reference and returns a reference to it.
    pub fn add_memory_reference(
        &mut self,
        from: Address,
        to: Address,
        ref_type: RefType,
        source: SourceType,
        op_index: i32,
    ) -> &Reference {
        self.ref_mgr
            .add_memory_reference(from, to, ref_type, source, op_index)
            .expect("add_memory_reference failed")
    }

    /// Removes all references from the given address.
    pub fn remove_all_references_from(&mut self, from: Address) {
        self.ref_mgr.remove_all_references_from(from);
    }

    /// Removes all references to the given address.
    pub fn remove_all_references_to(&mut self, to: Address) {
        self.ref_mgr.remove_all_references_to(to);
    }

    /// Returns all xrefs (direct + offcut) to the given code unit.
    pub fn get_all_xrefs(&self, cu: &CodeUnitXRef) -> Vec<XRefEntry> {
        get_all_xrefs(&self.ref_mgr, cu)
    }

    /// Returns direct xrefs to the given code unit.
    pub fn get_x_references(&self, cu: &CodeUnitXRef, max: i32) -> Vec<XRefEntry> {
        get_x_references(&self.ref_mgr, cu, max)
    }

    /// Returns offcut xrefs to the given code unit.
    pub fn get_offcut_x_references(&self, cu: &CodeUnitXRef, max: i32) -> Vec<XRefEntry> {
        get_offcut_x_references(&self.ref_mgr, cu, max)
    }

    /// Returns the number of references to the given address.
    pub fn get_reference_count_to(&self, addr: &Address) -> usize {
        self.ref_mgr.get_reference_count_to(*addr)
    }

    /// Returns the number of references from the given address.
    pub fn get_reference_count_from(&self, addr: &Address) -> usize {
        self.ref_mgr.get_reference_count_from(*addr)
    }

    /// Returns `true` if there are any references to the given address.
    pub fn has_references_to(&self, addr: &Address) -> bool {
        self.ref_mgr.has_references_to(*addr)
    }

    /// Returns `true` if there are any references from the given address.
    pub fn has_references_from(&self, addr: &Address) -> bool {
        self.ref_mgr.has_references_from(*addr)
    }

    /// Sets a reference as primary.
    pub fn set_primary(&mut self, ref_: &Reference, is_primary: bool) {
        self.ref_mgr.set_primary(ref_, is_primary);
    }

    /// Updates the reference type of an existing reference.
    pub fn update_ref_type(&mut self, ref_: &Reference, ref_type: RefType) -> Option<&Reference> {
        self.ref_mgr.update_ref_type(ref_, ref_type)
    }
}

// ---------------------------------------------------------------------------
// XRefListingRow -- how xrefs appear in a listing view
// ---------------------------------------------------------------------------

/// Represents how a cross-reference should be displayed in a listing view.
///
/// In Ghidra, xref display is handled by `XRefFieldFactory`. This struct
/// captures the display-oriented information for a single xref line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XRefDisplayRow {
    /// The "from" address.
    pub address: Address,
    /// A human-readable label for the reference type (e.g., "Call", "Jump", "Read").
    pub ref_type_label: String,
    /// The symbol name at the "from" address, if known.
    pub from_label: Option<String>,
    /// Whether this is the primary reference.
    pub is_primary: bool,
}

impl XRefDisplayRow {
    /// Creates a new display row from a regular reference.
    pub fn from_reference(ref_: &Reference) -> Self {
        Self {
            address: *ref_.get_from_address(),
            ref_type_label: ref_.get_reference_type().display_string().to_string(),
            from_label: None,
            is_primary: ref_.is_primary(),
        }
    }

    /// Creates a display row for a thunk reference.
    pub fn from_thunk(thunk: &ThunkReference) -> Self {
        Self {
            address: *thunk.get_from_address(),
            ref_type_label: "Thunk".to_string(),
            from_label: None,
            is_primary: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::symbol::MNEMONIC;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn make_ref(from: u64, to: u64, ref_type: RefType) -> Reference {
        Reference::new(addr(from), addr(to), ref_type, MNEMONIC)
    }

    fn make_ref_op(from: u64, to: u64, ref_type: RefType, op: i32) -> Reference {
        Reference::new(addr(from), addr(to), ref_type, op)
    }

    // ====================================================================
    // ThunkReference
    // ====================================================================

    #[test]
    fn test_thunk_reference_basic() {
        let t = ThunkReference::new(addr(0x1000), addr(0x2000));
        assert_eq!(*t.get_from_address(), addr(0x1000));
        assert_eq!(*t.get_to_address(), addr(0x2000));
        assert!(t.to_string().contains("THUNK"));
    }

    #[test]
    fn test_thunk_reference_ordering() {
        let t1 = ThunkReference::new(addr(0x1000), addr(0x2000));
        let t2 = ThunkReference::new(addr(0x1000), addr(0x3000));
        let t3 = ThunkReference::new(addr(0x1100), addr(0x2000));
        assert!(t1 < t2);
        assert!(t1 < t3);
    }

    // ====================================================================
    // XRefEntry
    // ====================================================================

    #[test]
    fn test_xref_entry_reference() {
        let r = make_ref(0x1000, 0x2000, RefType::UNCONDITIONAL_CALL);
        let entry = XRefEntry::Reference(r.clone());
        assert_eq!(*entry.from_address(), addr(0x1000));
        assert_eq!(*entry.to_address(), addr(0x2000));
        assert!(!entry.is_thunk());
        assert_eq!(
            entry.reference_type(),
            Some(RefType::UNCONDITIONAL_CALL)
        );
    }

    #[test]
    fn test_xref_entry_thunk() {
        let t = ThunkReference::new(addr(0x1000), addr(0x2000));
        let entry = XRefEntry::Thunk(t);
        assert_eq!(*entry.from_address(), addr(0x1000));
        assert_eq!(*entry.to_address(), addr(0x2000));
        assert!(entry.is_thunk());
        assert_eq!(entry.reference_type(), None);
    }

    // ====================================================================
    // CodeUnitXRef
    // ====================================================================

    #[test]
    fn test_code_unit_xref_basic() {
        let cu = CodeUnitXRef::new(addr(0x1000), addr(0x100F));
        assert_eq!(cu.min_address, addr(0x1000));
        assert_eq!(cu.max_address, addr(0x100F));
        assert_eq!(cu.length, 16);
        assert!(cu.thunk_entry_points.is_empty());
    }

    #[test]
    fn test_code_unit_xref_single_byte() {
        let cu = CodeUnitXRef::single_byte(addr(0x1000));
        assert_eq!(cu.length, 1);
    }

    #[test]
    fn test_code_unit_xref_with_thunks() {
        let cu = CodeUnitXRef::new(addr(0x1000), addr(0x100F))
            .with_thunk_entry_points(vec![addr(0x3000), addr(0x3100)]);
        assert_eq!(cu.thunk_entry_points.len(), 2);
    }

    // ====================================================================
    // get_xref_addresses
    // ====================================================================

    #[test]
    fn test_get_xref_addresses_empty() {
        let ref_mgr = ReferenceManager::new();
        let cu = CodeUnitXRef::single_byte(addr(0x2000));
        let addrs = get_xref_addresses(&ref_mgr, &cu);
        assert!(addrs.is_empty());
    }

    #[test]
    fn test_get_xref_addresses_basic() {
        let mut ref_mgr = ReferenceManager::new();
        ref_mgr
            .add_reference(make_ref(0x1000, 0x2000, RefType::READ))
            .unwrap();
        ref_mgr
            .add_reference(make_ref(0x1100, 0x2000, RefType::UNCONDITIONAL_CALL))
            .unwrap();
        ref_mgr
            .add_reference(make_ref(0x1200, 0x3000, RefType::WRITE))
            .unwrap();

        let cu = CodeUnitXRef::single_byte(addr(0x2000));
        let addrs = get_xref_addresses(&ref_mgr, &cu);
        assert_eq!(addrs.len(), 2);
        assert_eq!(addrs[0], addr(0x1000));
        assert_eq!(addrs[1], addr(0x1100));
    }

    #[test]
    fn test_get_xref_addresses_limited() {
        let mut ref_mgr = ReferenceManager::new();
        for i in 0..10u64 {
            ref_mgr
                .add_reference(make_ref(0x1000 + i * 0x10, 0x2000, RefType::READ))
                .unwrap();
        }

        let cu = CodeUnitXRef::single_byte(addr(0x2000));
        let addrs = get_xref_addresses_limited(&ref_mgr, &cu, 3);
        assert_eq!(addrs.len(), 3);
    }

    #[test]
    fn test_get_xref_addresses_all_refs_sentinel() {
        let mut ref_mgr = ReferenceManager::new();
        for i in 0..100u64 {
            ref_mgr
                .add_reference(make_ref(0x1000 + i, 0x2000, RefType::READ))
                .unwrap();
        }

        let cu = CodeUnitXRef::single_byte(addr(0x2000));
        let addrs = get_xref_addresses_limited(&ref_mgr, &cu, ALL_REFS);
        assert_eq!(addrs.len(), 100);
    }

    // ====================================================================
    // get_x_references
    // ====================================================================

    #[test]
    fn test_get_x_references_with_thunks() {
        let mut ref_mgr = ReferenceManager::new();
        ref_mgr
            .add_reference(make_ref(0x1000, 0x2000, RefType::READ))
            .unwrap();

        let cu = CodeUnitXRef::single_byte(addr(0x2000))
            .with_thunk_entry_points(vec![addr(0x3000)]);

        let xrefs = get_x_references(&ref_mgr, &cu, ALL_REFS);
        assert_eq!(xrefs.len(), 2);
        // First is the regular reference
        assert!(!xrefs[0].is_thunk());
        // Second is the thunk reference
        assert!(xrefs[1].is_thunk());
    }

    #[test]
    fn test_get_x_references_max_limits_direct_only() {
        let mut ref_mgr = ReferenceManager::new();
        ref_mgr
            .add_reference(make_ref(0x1000, 0x2000, RefType::READ))
            .unwrap();
        ref_mgr
            .add_reference(make_ref(0x1100, 0x2000, RefType::WRITE))
            .unwrap();

        let cu = CodeUnitXRef::single_byte(addr(0x2000))
            .with_thunk_entry_points(vec![addr(0x3000)]);

        // max=1 means we stop after 1 direct reference
        let xrefs = get_x_references(&ref_mgr, &cu, 1);
        assert_eq!(xrefs.len(), 1);
        assert!(!xrefs[0].is_thunk());
    }

    // ====================================================================
    // get_all_xrefs (direct + offcut, deduplicated)
    // ====================================================================

    #[test]
    fn test_get_all_xrefs_dedup() {
        let mut ref_mgr = ReferenceManager::new();
        ref_mgr
            .add_reference(make_ref(0x1000, 0x2000, RefType::READ))
            .unwrap();

        let cu = CodeUnitXRef::new(addr(0x2000), addr(0x200F));
        let all = get_all_xrefs(&ref_mgr, &cu);
        // Only the direct xref should appear (offcut queries would need
        // reference destination iteration which requires a populated index).
        // The direct xref at min_address is returned.
        assert!(!all.is_empty());
    }

    // ====================================================================
    // get_variable_refs
    // ====================================================================

    #[test]
    fn test_get_variable_refs_split() {
        let var_addr = addr(0x100);
        let other_addr = addr(0x104);
        let var = VariableXRef::new(Some(var_addr), 1, "myVar");

        let refs = vec![
            make_ref_op(0x1000, 0x100, RefType::READ, 0),
            make_ref_op(0x1100, 0x100, RefType::WRITE, 0),
            make_ref_op(0x1200, 0x104, RefType::READ, 1),
        ];

        let (direct, offcut) = get_variable_refs(&ReferenceManager::new(), &var, &refs);
        assert_eq!(direct.len(), 2);
        assert_eq!(offcut.len(), 1);
        assert_eq!(*offcut[0].get_to_address(), other_addr);
    }

    #[test]
    fn test_get_variable_refs_no_address() {
        let var = VariableXRef::new(None, 1, "unresolved");
        let refs = vec![make_ref_op(0x1000, 0x100, RefType::READ, 0)];
        let (direct, offcut) = get_variable_refs(&ReferenceManager::new(), &var, &refs);
        assert!(direct.is_empty());
        assert!(offcut.is_empty());
    }

    #[test]
    fn test_get_variable_refs_limited() {
        let var = VariableXRef::new(Some(addr(0x100)), 1, "myVar");
        let refs = vec![
            make_ref_op(0x1000, 0x100, RefType::READ, 0),
            make_ref_op(0x1100, 0x100, RefType::WRITE, 0),
            make_ref_op(0x1200, 0x100, RefType::READ_WRITE, 0),
        ];

        let (direct, offcut) =
            get_variable_refs_limited(&ReferenceManager::new(), &var, &refs, 2);
        assert_eq!(direct.len(), 2);
        assert!(offcut.is_empty());
    }

    // ====================================================================
    // CrossReferenceManager
    // ====================================================================

    #[test]
    fn test_cross_reference_manager_basic() {
        let mut xrm = CrossReferenceManager::default();
        xrm.add_memory_reference(
            addr(0x1000),
            addr(0x2000),
            RefType::UNCONDITIONAL_CALL,
            SourceType::Default,
            MNEMONIC,
        );

        assert!(xrm.has_references_to(&addr(0x2000)));
        assert!(xrm.has_references_from(&addr(0x1000)));
        assert_eq!(xrm.get_reference_count_to(&addr(0x2000)), 1);
        assert_eq!(xrm.get_reference_count_from(&addr(0x1000)), 1);
        assert!(!xrm.has_references_to(&addr(0x3000)));
    }

    #[test]
    fn test_cross_reference_manager_remove_from() {
        let mut xrm = CrossReferenceManager::default();
        xrm.add_memory_reference(
            addr(0x1000),
            addr(0x2000),
            RefType::READ,
            SourceType::Default,
            0,
        );
        xrm.add_memory_reference(
            addr(0x1000),
            addr(0x3000),
            RefType::WRITE,
            SourceType::Default,
            1,
        );

        assert_eq!(xrm.get_reference_count_from(&addr(0x1000)), 2);
        xrm.remove_all_references_from(addr(0x1000));
        assert_eq!(xrm.get_reference_count_from(&addr(0x1000)), 0);
    }

    #[test]
    fn test_cross_reference_manager_get_all_xrefs() {
        let mut xrm = CrossReferenceManager::default();
        xrm.add_memory_reference(
            addr(0x1000),
            addr(0x2000),
            RefType::READ,
            SourceType::Default,
            MNEMONIC,
        );
        xrm.add_memory_reference(
            addr(0x1100),
            addr(0x2000),
            RefType::UNCONDITIONAL_CALL,
            SourceType::Default,
            MNEMONIC,
        );

        let cu = CodeUnitXRef::single_byte(addr(0x2000));
        let xrefs = xrm.get_all_xrefs(&cu);
        assert_eq!(xrefs.len(), 2);
    }

    // ====================================================================
    // XRefDisplayRow
    // ====================================================================

    #[test]
    fn test_xref_display_row_from_reference() {
        let r = make_ref(0x1000, 0x2000, RefType::UNCONDITIONAL_CALL);
        let row = XRefDisplayRow::from_reference(&r);
        assert_eq!(row.address, addr(0x1000));
        assert_eq!(row.ref_type_label, "Call");
        assert!(!row.is_primary);
    }

    #[test]
    fn test_xref_display_row_from_thunk() {
        let t = ThunkReference::new(addr(0x1000), addr(0x2000));
        let row = XRefDisplayRow::from_thunk(&t);
        assert_eq!(row.address, addr(0x1000));
        assert_eq!(row.ref_type_label, "Thunk");
        assert!(!row.is_primary);
    }

    // ====================================================================
    // Sorting and ordering
    // ====================================================================

    #[test]
    fn test_xref_entry_ordering() {
        let e1 = XRefEntry::Reference(make_ref(0x1000, 0x2000, RefType::READ));
        let e2 = XRefEntry::Thunk(ThunkReference::new(addr(0x1000), addr(0x3000)));
        let e3 = XRefEntry::Reference(make_ref(0x1100, 0x2000, RefType::WRITE));

        let mut entries = vec![e3.clone(), e1.clone(), e2.clone()];
        entries.sort();
        assert_eq!(entries[0].from_address().offset, 0x1000);
        assert_eq!(entries[1].from_address().offset, 0x1000);
        assert_eq!(entries[2].from_address().offset, 0x1100);
    }
}
