//! Symbol model for the Debug framework.
//!
//! Ported from `ghidra.trace.model.symbol` — includes [`TraceSymbolKind`],
//! [`TraceSymbol`], [`TraceLabelSymbol`], [`TraceNamespaceSymbol`],
//! [`TraceClassSymbol`], [`TraceReference`], [`TraceEquate`],
//! and [`TraceSymbolManager`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use super::core_types::Lifespan;

// ---------------------------------------------------------------------------
// TraceSymbolKind
// ---------------------------------------------------------------------------

/// The kind of a trace symbol.
///
/// Ported from `ghidra.trace.model.symbol` — simplified from Ghidra's
/// multi-class hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TraceSymbolKind {
    /// A label (named address).
    Label,
    /// A namespace (a named container for other symbols).
    Namespace,
    /// A class (a namespace that represents a class).
    Class,
}

impl fmt::Display for TraceSymbolKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TraceSymbolKind::Label => write!(f, "Label"),
            TraceSymbolKind::Namespace => write!(f, "Namespace"),
            TraceSymbolKind::Class => write!(f, "Class"),
        }
    }
}

// ---------------------------------------------------------------------------
// ReferenceType
// ---------------------------------------------------------------------------

/// The type of a reference.
///
/// Ported from `ghidra.program.model.symbol.RefType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ReferenceType {
    /// Unconditional flow (e.g., jump, call).
    Flow,
    /// Read access.
    Read,
    /// Write access.
    Write,
    /// Data reference (not read or write).
    Data,
    /// Indirect reference.
    Indirect,
    /// External reference.
    External,
    /// Call reference.
    Call,
    /// Conditional flow.
    Conditional,
}

impl fmt::Display for ReferenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReferenceType::Flow => write!(f, "Flow"),
            ReferenceType::Read => write!(f, "Read"),
            ReferenceType::Write => write!(f, "Write"),
            ReferenceType::Data => write!(f, "Data"),
            ReferenceType::Indirect => write!(f, "Indirect"),
            ReferenceType::External => write!(f, "External"),
            ReferenceType::Call => write!(f, "Call"),
            ReferenceType::Conditional => write!(f, "Conditional"),
        }
    }
}

// ---------------------------------------------------------------------------
// TraceSymbol (unified)
// ---------------------------------------------------------------------------

/// A symbol in the trace.
///
/// Ported from `ghidra.trace.model.symbol.TraceSymbol`. This is a unified
/// representation covering labels, namespaces, and classes.
#[derive(Debug, Clone)]
pub struct TraceSymbol {
    /// Unique symbol ID.
    id: u64,
    /// The kind of symbol.
    kind: TraceSymbolKind,
    /// The symbol name.
    name: String,
    /// The parent namespace ID (0 for global namespace).
    parent_id: u64,
    /// The address space name (for labels).
    space_name: Option<String>,
    /// The address offset (for labels).
    offset: Option<u64>,
    /// The lifespan of this symbol.
    pub lifespan: Lifespan,
    /// Whether the symbol is primary (the "main" symbol at an address).
    primary: bool,
    /// Whether deleted.
    deleted: bool,
}

impl TraceSymbol {
    /// Create a label symbol.
    pub fn new_label(
        id: u64,
        name: impl Into<String>,
        parent_id: u64,
        space_name: impl Into<String>,
        offset: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            id,
            kind: TraceSymbolKind::Label,
            name: name.into(),
            parent_id,
            space_name: Some(space_name.into()),
            offset: Some(offset),
            lifespan,
            primary: false,
            deleted: false,
        }
    }

    /// Create a namespace symbol.
    pub fn new_namespace(
        id: u64,
        name: impl Into<String>,
        parent_id: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            id,
            kind: TraceSymbolKind::Namespace,
            name: name.into(),
            parent_id,
            space_name: None,
            offset: None,
            lifespan,
            primary: false,
            deleted: false,
        }
    }

    /// Create a class symbol.
    pub fn new_class(
        id: u64,
        name: impl Into<String>,
        parent_id: u64,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            id,
            kind: TraceSymbolKind::Class,
            name: name.into(),
            parent_id,
            space_name: None,
            offset: None,
            lifespan,
            primary: false,
            deleted: false,
        }
    }

    /// Returns the unique ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Returns the symbol kind.
    pub fn kind(&self) -> TraceSymbolKind {
        self.kind
    }

    /// Returns the symbol name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the symbol name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// Returns the parent namespace ID.
    pub fn parent_id(&self) -> u64 {
        self.parent_id
    }

    /// Returns the address space name (for labels).
    pub fn space_name(&self) -> Option<&str> {
        self.space_name.as_deref()
    }

    /// Returns the address offset (for labels).
    pub fn offset(&self) -> Option<u64> {
        self.offset
    }

    /// Returns `true` if this is a label.
    pub fn is_label(&self) -> bool {
        self.kind == TraceSymbolKind::Label
    }

    /// Returns `true` if this is a namespace (including class).
    pub fn is_namespace(&self) -> bool {
        matches!(
            self.kind,
            TraceSymbolKind::Namespace | TraceSymbolKind::Class
        )
    }

    /// Returns `true` if this is a class.
    pub fn is_class(&self) -> bool {
        self.kind == TraceSymbolKind::Class
    }

    /// Returns `true` if this is the primary symbol at its address.
    pub fn is_primary(&self) -> bool {
        self.primary
    }

    /// Set whether this is the primary symbol.
    pub fn set_primary(&mut self, primary: bool) {
        self.primary = primary;
    }

    /// Check if valid at the given snapshot.
    pub fn is_valid(&self, snap: i64) -> bool {
        !self.deleted && self.lifespan.contains(snap)
    }

    /// Delete this symbol.
    pub fn delete(&mut self) {
        self.deleted = true;
    }
}

impl fmt::Display for TraceSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            TraceSymbolKind::Label => {
                if let (Some(space), Some(off)) = (&self.space_name, self.offset) {
                    write!(f, "Label({}:{}, 0x{:x})", self.name, space, off)
                } else {
                    write!(f, "Label({})", self.name)
                }
            }
            TraceSymbolKind::Namespace => write!(f, "Namespace({})", self.name),
            TraceSymbolKind::Class => write!(f, "Class({})", self.name),
        }
    }
}

// ---------------------------------------------------------------------------
// TraceReference
// ---------------------------------------------------------------------------

/// A reference between two addresses in the trace.
///
/// Ported from `ghidra.trace.model.symbol.TraceReference`.
#[derive(Debug, Clone)]
pub struct TraceReference {
    /// Unique key for this reference.
    key: u64,
    /// The "from" address (the address containing the reference).
    pub from_address: u64,
    /// The "to" address (the target of the reference).
    pub to_address: u64,
    /// The reference type.
    pub ref_type: ReferenceType,
    /// The operand index (if applicable).
    pub operand_index: i32,
    /// The lifespan of this reference.
    pub lifespan: Lifespan,
    /// Whether deleted.
    deleted: bool,
}

impl TraceReference {
    /// Create a new reference.
    pub fn new(
        key: u64,
        from_address: u64,
        to_address: u64,
        ref_type: ReferenceType,
        operand_index: i32,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            from_address,
            to_address,
            ref_type,
            operand_index,
            lifespan,
            deleted: false,
        }
    }

    /// Returns the unique key.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Check if valid at the given snapshot.
    pub fn is_valid(&self, snap: i64) -> bool {
        !self.deleted && self.lifespan.contains(snap)
    }

    /// Delete this reference.
    pub fn delete(&mut self) {
        self.deleted = true;
    }
}

impl fmt::Display for TraceReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Ref(0x{:x} -> 0x{:x}, {})",
            self.from_address, self.to_address, self.ref_type
        )
    }
}

// ---------------------------------------------------------------------------
// TraceEquate
// ---------------------------------------------------------------------------

/// An equate (named constant) in the trace.
///
/// Ported from `ghidra.trace.model.symbol.TraceEquate`.
#[derive(Debug, Clone)]
pub struct TraceEquate {
    /// Unique key for this equate.
    key: u64,
    /// The equate name.
    name: String,
    /// The numeric value.
    value: i64,
    /// The address where this equate is applied.
    pub address: u64,
    /// The operand index (if applicable).
    pub operand_index: i32,
    /// The lifespan of this equate.
    pub lifespan: Lifespan,
    /// Whether deleted.
    deleted: bool,
}

impl TraceEquate {
    /// Create a new equate.
    pub fn new(
        key: u64,
        name: impl Into<String>,
        value: i64,
        address: u64,
        operand_index: i32,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            key,
            name: name.into(),
            value,
            address,
            operand_index,
            lifespan,
            deleted: false,
        }
    }

    /// Returns the unique key.
    pub fn key(&self) -> u64 {
        self.key
    }

    /// Returns the equate name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the equate value.
    pub fn value(&self) -> i64 {
        self.value
    }

    /// Check if valid at the given snapshot.
    pub fn is_valid(&self, snap: i64) -> bool {
        !self.deleted && self.lifespan.contains(snap)
    }

    /// Delete this equate.
    pub fn delete(&mut self) {
        self.deleted = true;
    }
}

impl fmt::Display for TraceEquate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Equate({}, 0x{:x})", self.name, self.value)
    }
}

// ---------------------------------------------------------------------------
// TraceSymbolManager
// ---------------------------------------------------------------------------

/// Manages symbols, references, and equates within a trace.
///
/// Ported from `ghidra.trace.model.symbol.TraceSymbolManager`.
#[derive(Debug)]
pub struct TraceSymbolManager {
    next_id: AtomicU64,
    next_ref_key: AtomicU64,
    next_equate_key: AtomicU64,
    symbols: BTreeMap<u64, TraceSymbol>,
    references: BTreeMap<u64, TraceReference>,
    equates: BTreeMap<u64, TraceEquate>,
    /// Global namespace ID (always 0).
    global_ns_id: u64,
}

impl TraceSymbolManager {
    /// Create a new symbol manager with a global namespace.
    pub fn new() -> Self {
        let mut symbols = BTreeMap::new();
        symbols.insert(
            0,
            TraceSymbol::new_namespace(0, "::", 0, Lifespan::now_on(0)),
        );
        Self {
            next_id: AtomicU64::new(1),
            next_ref_key: AtomicU64::new(1),
            next_equate_key: AtomicU64::new(1),
            symbols,
            references: BTreeMap::new(),
            equates: BTreeMap::new(),
            global_ns_id: 0,
        }
    }

    fn alloc_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn alloc_ref_key(&self) -> u64 {
        self.next_ref_key.fetch_add(1, Ordering::Relaxed)
    }

    fn alloc_equate_key(&self) -> u64 {
        self.next_equate_key.fetch_add(1, Ordering::Relaxed)
    }

    /// Returns the global namespace ID.
    pub fn global_namespace_id(&self) -> u64 {
        self.global_ns_id
    }

    /// Get the global namespace symbol.
    pub fn get_global_namespace(&self) -> Option<&TraceSymbol> {
        self.symbols.get(&self.global_ns_id)
    }

    // --- Symbol CRUD ---

    /// Create a label symbol.
    pub fn create_label(
        &mut self,
        name: impl Into<String>,
        parent_id: u64,
        space_name: impl Into<String>,
        offset: u64,
        lifespan: Lifespan,
    ) -> u64 {
        let id = self.alloc_id();
        self.symbols.insert(
            id,
            TraceSymbol::new_label(id, name, parent_id, space_name, offset, lifespan),
        );
        id
    }

    /// Create a namespace symbol.
    pub fn create_namespace(
        &mut self,
        name: impl Into<String>,
        parent_id: u64,
        lifespan: Lifespan,
    ) -> u64 {
        let id = self.alloc_id();
        self.symbols.insert(
            id,
            TraceSymbol::new_namespace(id, name, parent_id, lifespan),
        );
        id
    }

    /// Create a class symbol.
    pub fn create_class(
        &mut self,
        name: impl Into<String>,
        parent_id: u64,
        lifespan: Lifespan,
    ) -> u64 {
        let id = self.alloc_id();
        self.symbols.insert(
            id,
            TraceSymbol::new_class(id, name, parent_id, lifespan),
        );
        id
    }

    /// Get a symbol by ID.
    pub fn get_symbol(&self, id: u64) -> Option<&TraceSymbol> {
        self.symbols.get(&id)
    }

    /// Get a mutable symbol by ID.
    pub fn get_symbol_mut(&mut self, id: u64) -> Option<&mut TraceSymbol> {
        self.symbols.get_mut(&id)
    }

    /// Get all labels valid at the given snapshot.
    pub fn get_labels(&self, snap: i64) -> Vec<&TraceSymbol> {
        self.symbols
            .values()
            .filter(|s| s.is_label() && s.is_valid(snap))
            .collect()
    }

    /// Get the label at a specific address.
    pub fn get_label_at(
        &self,
        space_name: &str,
        offset: u64,
        snap: i64,
    ) -> Option<&TraceSymbol> {
        self.symbols.values().find(|s| {
            s.is_label()
                && s.is_valid(snap)
                && s.space_name.as_deref() == Some(space_name)
                && s.offset == Some(offset)
                && s.is_primary()
        })
    }

    /// Get all namespaces valid at the given snapshot.
    pub fn get_namespaces(&self, snap: i64) -> Vec<&TraceSymbol> {
        self.symbols
            .values()
            .filter(|s| s.is_namespace() && s.is_valid(snap))
            .collect()
    }

    /// Get all classes valid at the given snapshot.
    pub fn get_classes(&self, snap: i64) -> Vec<&TraceSymbol> {
        self.symbols
            .values()
            .filter(|s| s.is_class() && s.is_valid(snap))
            .collect()
    }

    /// Get all symbols valid at the given snapshot.
    pub fn get_all_symbols(&self, snap: i64) -> Vec<&TraceSymbol> {
        self.symbols
            .values()
            .filter(|s| s.is_valid(snap))
            .collect()
    }

    /// Get the children of a namespace.
    pub fn get_children_of(&self, parent_id: u64, snap: i64) -> Vec<&TraceSymbol> {
        self.symbols
            .values()
            .filter(|s| s.parent_id == parent_id && s.is_valid(snap))
            .collect()
    }

    /// Iterate over all symbols.
    pub fn symbols(&self) -> impl Iterator<Item = &TraceSymbol> {
        self.symbols.values()
    }

    /// Remove a symbol by ID.
    pub fn remove_symbol(&mut self, id: u64) -> Option<TraceSymbol> {
        if id == self.global_ns_id {
            return None; // Cannot remove global namespace
        }
        self.symbols.remove(&id)
    }

    // --- Reference CRUD ---

    /// Add a reference.
    pub fn add_reference(
        &mut self,
        from_address: u64,
        to_address: u64,
        ref_type: ReferenceType,
        operand_index: i32,
        lifespan: Lifespan,
    ) -> u64 {
        let key = self.alloc_ref_key();
        self.references.insert(
            key,
            TraceReference::new(key, from_address, to_address, ref_type, operand_index, lifespan),
        );
        key
    }

    /// Get a reference by key.
    pub fn get_reference(&self, key: u64) -> Option<&TraceReference> {
        self.references.get(&key)
    }

    /// Get all references from a given address.
    pub fn get_references_from(&self, from_address: u64, snap: i64) -> Vec<&TraceReference> {
        self.references
            .values()
            .filter(|r| r.from_address == from_address && r.is_valid(snap))
            .collect()
    }

    /// Get all references to a given address.
    pub fn get_references_to(&self, to_address: u64, snap: i64) -> Vec<&TraceReference> {
        self.references
            .values()
            .filter(|r| r.to_address == to_address && r.is_valid(snap))
            .collect()
    }

    /// Iterate over all references.
    pub fn references(&self) -> impl Iterator<Item = &TraceReference> {
        self.references.values()
    }

    /// Remove a reference.
    pub fn remove_reference(&mut self, key: u64) -> Option<TraceReference> {
        self.references.remove(&key)
    }

    // --- Equate CRUD ---

    /// Add an equate.
    pub fn add_equate(
        &mut self,
        name: impl Into<String>,
        value: i64,
        address: u64,
        operand_index: i32,
        lifespan: Lifespan,
    ) -> u64 {
        let key = self.alloc_equate_key();
        self.equates.insert(
            key,
            TraceEquate::new(key, name, value, address, operand_index, lifespan),
        );
        key
    }

    /// Get an equate by key.
    pub fn get_equate(&self, key: u64) -> Option<&TraceEquate> {
        self.equates.get(&key)
    }

    /// Get all equates at a given address.
    pub fn get_equates_at(&self, address: u64, snap: i64) -> Vec<&TraceEquate> {
        self.equates
            .values()
            .filter(|e| e.address == address && e.is_valid(snap))
            .collect()
    }

    /// Iterate over all equates.
    pub fn equates(&self) -> impl Iterator<Item = &TraceEquate> {
        self.equates.values()
    }

    /// Remove an equate.
    pub fn remove_equate(&mut self, key: u64) -> Option<TraceEquate> {
        self.equates.remove(&key)
    }

    /// Get IDs added between two snapshots.
    pub fn get_ids_added(&self, from: i64, to: i64) -> BTreeSet<u64> {
        self.symbols
            .values()
            .filter(|s| !s.deleted && s.lifespan.min() >= from && s.lifespan.min() <= to)
            .map(|s| s.id)
            .collect()
    }

    /// Get IDs removed between two snapshots.
    pub fn get_ids_removed(&self, from: i64, to: i64) -> BTreeSet<u64> {
        self.symbols
            .values()
            .filter(|s| !s.deleted && s.lifespan.max() >= from && s.lifespan.max() <= to)
            .map(|s| s.id)
            .collect()
    }
}

impl Default for TraceSymbolManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_label() {
        let sym = TraceSymbol::new_label(
            1,
            "main",
            0,
            "ram",
            0x400000,
            Lifespan::now_on(0),
        );
        assert_eq!(sym.id(), 1);
        assert_eq!(sym.kind(), TraceSymbolKind::Label);
        assert_eq!(sym.name(), "main");
        assert_eq!(sym.space_name(), Some("ram"));
        assert_eq!(sym.offset(), Some(0x400000));
        assert!(sym.is_label());
        assert!(!sym.is_namespace());
        assert!(!sym.is_class());
    }

    #[test]
    fn test_symbol_namespace() {
        let sym = TraceSymbol::new_namespace(2, "libc", 0, Lifespan::now_on(0));
        assert!(sym.is_namespace());
        assert!(!sym.is_class());
        assert!(!sym.is_label());
    }

    #[test]
    fn test_symbol_class() {
        let sym = TraceSymbol::new_class(3, "MyClass", 0, Lifespan::now_on(0));
        assert!(sym.is_class());
        assert!(sym.is_namespace()); // Class extends Namespace
    }

    #[test]
    fn test_reference() {
        let r = TraceReference::new(
            1,
            0x400000,
            0x400100,
            ReferenceType::Flow,
            -1,
            Lifespan::now_on(0),
        );
        assert_eq!(r.key(), 1);
        assert_eq!(r.from_address, 0x400000);
        assert_eq!(r.to_address, 0x400100);
        assert_eq!(r.ref_type, ReferenceType::Flow);
        assert!(r.is_valid(0));
    }

    #[test]
    fn test_equate() {
        let e = TraceEquate::new(1, "SYS_WRITE", 1, 0x400000, 0, Lifespan::now_on(0));
        assert_eq!(e.key(), 1);
        assert_eq!(e.name(), "SYS_WRITE");
        assert_eq!(e.value(), 1);
        assert_eq!(e.address, 0x400000);
    }

    #[test]
    fn test_symbol_manager_create() {
        let mut mgr = TraceSymbolManager::new();

        // Global namespace exists
        let gns = mgr.get_global_namespace().unwrap();
        assert_eq!(gns.name(), "::");
        assert_eq!(gns.id(), 0);

        // Create labels
        let l1 = mgr.create_label("main", 0, "ram", 0x400000, Lifespan::now_on(0));
        let l2 = mgr.create_label("helper", 0, "ram", 0x400100, Lifespan::now_on(0));

        // Create namespace
        let ns = mgr.create_namespace("libc", 0, Lifespan::now_on(0));

        assert!(mgr.get_symbol(l1).is_some());
        assert!(mgr.get_symbol(l2).is_some());
        assert!(mgr.get_symbol(ns).is_some());
    }

    #[test]
    fn test_symbol_manager_labels() {
        let mut mgr = TraceSymbolManager::new();
        let _l1 = mgr.create_label("main", 0, "ram", 0x400000, Lifespan::now_on(0));
        let _l2 = mgr.create_label("helper", 0, "ram", 0x400100, Lifespan::now_on(5));

        // At snap 0, only main is valid
        let labels_at_0 = mgr.get_labels(0);
        assert_eq!(labels_at_0.len(), 1);
        assert_eq!(labels_at_0[0].name(), "main");

        // At snap 10, both are valid
        let labels_at_10 = mgr.get_labels(10);
        assert_eq!(labels_at_10.len(), 2);
    }

    #[test]
    fn test_symbol_manager_namespaces() {
        let mut mgr = TraceSymbolManager::new();
        let _ns1 = mgr.create_namespace("libc", 0, Lifespan::now_on(0));
        let _ns2 = mgr.create_class("MyClass", 0, Lifespan::now_on(0));

        let namespaces = mgr.get_namespaces(0);
        assert_eq!(namespaces.len(), 3); // global + libc + MyClass

        let classes = mgr.get_classes(0);
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].name(), "MyClass");
    }

    #[test]
    fn test_symbol_manager_children() {
        let mut mgr = TraceSymbolManager::new();
        let ns = mgr.create_namespace("libc", 0, Lifespan::now_on(0));
        let _l1 = mgr.create_label("printf", ns, "ram", 0x7F0000, Lifespan::now_on(0));
        let _l2 = mgr.create_label("malloc", ns, "ram", 0x7F0100, Lifespan::now_on(0));

        let children = mgr.get_children_of(ns, 0);
        assert_eq!(children.len(), 2);
    }

    #[test]
    fn test_symbol_manager_references() {
        let mut mgr = TraceSymbolManager::new();
        let r1 = mgr.add_reference(
            0x400000,
            0x400100,
            ReferenceType::Call,
            -1,
            Lifespan::now_on(0),
        );
        let _r2 = mgr.add_reference(
            0x400004,
            0x400100,
            ReferenceType::Flow,
            -1,
            Lifespan::now_on(0),
        );

        assert_eq!(mgr.references().count(), 2);

        let refs_to = mgr.get_references_to(0x400100, 0);
        assert_eq!(refs_to.len(), 2);

        let refs_from = mgr.get_references_from(0x400000, 0);
        assert_eq!(refs_from.len(), 1);
        assert_eq!(refs_from[0].ref_type, ReferenceType::Call);

        mgr.remove_reference(r1);
        assert_eq!(mgr.references().count(), 1);
    }

    #[test]
    fn test_symbol_manager_equates() {
        let mut mgr = TraceSymbolManager::new();
        let e1 = mgr.add_equate("SYS_WRITE", 1, 0x400000, 0, Lifespan::now_on(0));
        let e2 = mgr.add_equate("SYS_READ", 0, 0x400004, 0, Lifespan::now_on(0));

        assert_eq!(mgr.equates().count(), 2);

        let equates_at = mgr.get_equates_at(0x400000, 0);
        assert_eq!(equates_at.len(), 1);
        assert_eq!(equates_at[0].name(), "SYS_WRITE");

        mgr.remove_equate(e1);
        mgr.remove_equate(e2);
        assert_eq!(mgr.equates().count(), 0);
    }

    #[test]
    fn test_symbol_manager_remove() {
        let mut mgr = TraceSymbolManager::new();
        let l1 = mgr.create_label("temp", 0, "ram", 0x400000, Lifespan::now_on(0));
        assert!(mgr.get_symbol(l1).is_some());
        mgr.remove_symbol(l1);
        assert!(mgr.get_symbol(l1).is_none());

        // Cannot remove global namespace
        assert!(mgr.remove_symbol(0).is_none());
        assert!(mgr.get_global_namespace().is_some());
    }

    #[test]
    fn test_symbol_display() {
        let label = TraceSymbol::new_label(1, "main", 0, "ram", 0x400000, Lifespan::now_on(0));
        assert_eq!(format!("{label}"), "Label(main:ram, 0x400000)");

        let ns = TraceSymbol::new_namespace(2, "libc", 0, Lifespan::now_on(0));
        assert_eq!(format!("{ns}"), "Namespace(libc)");
    }

    #[test]
    fn test_reference_type_display() {
        assert_eq!(format!("{}", ReferenceType::Flow), "Flow");
        assert_eq!(format!("{}", ReferenceType::Call), "Call");
        assert_eq!(format!("{}", ReferenceType::Read), "Read");
    }
}
