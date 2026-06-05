//! DBTraceSymbol and DBTraceSymbolManager implementations.
//!
//! Ported from `ghidra/trace/database/symbol/AbstractDBTraceSymbol.java`,
//! `DBTraceSymbolManager.java`, `DBTraceLabelSymbol.java`,
//! `DBTraceNamespaceSymbol.java`, `DBTraceClassSymbol.java`, and
//! view types for multi-type symbol queries.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

use super::trace_db_ref_impl::SourceType;
use crate::model::Lifespan;

// ============================================================================
// Error Types
// ============================================================================

/// Errors from symbol operations.
#[derive(Debug, Error)]
pub enum SymbolError {
    /// Duplicate symbol name.
    #[error("Duplicate symbol name: {0}")]
    DuplicateName(String),

    /// Symbol not found.
    #[error("Symbol not found: {0}")]
    NotFound(u64),

    /// Invalid input for symbol creation.
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Namespace not found.
    #[error("Namespace not found: {0}")]
    NamespaceNotFound(u64),

    /// Circular namespace dependency.
    #[error("Circular dependency in namespace hierarchy")]
    CircularDependency,

    /// Parent belongs to a different trace.
    #[error("Parent does not belong to this trace")]
    ParentMismatch,
}

/// Result type for symbol operations.
pub type SymbolResult<T> = Result<T, SymbolError>;

// ============================================================================
// Symbol Kind
// ============================================================================

/// The kind of a symbol in a trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TraceSymbolKind {
    /// A label (named address).
    Label = 0,
    /// A function.
    Function = 1,
    /// A namespace.
    Namespace = 2,
    /// A class.
    Class = 3,
    /// An external library.
    Library = 4,
    /// A global namespace.
    Global = 5,
    /// A local variable.
    LocalVar = 6,
    /// A parameter.
    Parameter = 7,
}

impl Default for TraceSymbolKind {
    fn default() -> Self {
        TraceSymbolKind::Label
    }
}

// ============================================================================
// Symbol Entry (DB record)
// ============================================================================

/// A stored symbol entry in the database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolEntry {
    /// Unique symbol ID.
    pub id: u64,
    /// Symbol name.
    pub name: String,
    /// Parent namespace symbol ID (0 for global).
    pub parent_id: u64,
    /// Flags byte (source type in low nibble, primary flag in bit 4).
    pub flags: u8,
    /// The kind of symbol.
    pub kind: TraceSymbolKind,
    /// The address offset.
    pub address_offset: u64,
    /// The address space name.
    pub space_name: String,
    /// Minimum snap (inclusive).
    pub snap_min: i64,
    /// Maximum snap (inclusive).
    pub snap_max: i64,
}

const SOURCE_MASK: u8 = 0x0F;
const SOURCE_SHIFT: u8 = 0;
const PRIMARY_MASK: u8 = 0x10;

impl SymbolEntry {
    /// Get the source type.
    pub fn source_type(&self) -> SourceType {
        match (self.flags >> SOURCE_SHIFT) & SOURCE_MASK {
            0 => SourceType::UserDefined,
            1 => SourceType::Analysis,
            _ => SourceType::Default,
        }
    }

    /// Set the source type.
    pub fn set_source_type(&mut self, source: SourceType) {
        self.flags = (self.flags & !SOURCE_MASK) | ((source as u8) << SOURCE_SHIFT);
    }

    /// Whether this is the primary symbol at its address.
    pub fn is_primary(&self) -> bool {
        (self.flags & PRIMARY_MASK) != 0
    }

    /// Set the primary flag.
    pub fn set_primary(&mut self, primary: bool) {
        if primary {
            self.flags |= PRIMARY_MASK;
        } else {
            self.flags &= !PRIMARY_MASK;
        }
    }

    /// Get the lifespan.
    pub fn lifespan(&self) -> Lifespan {
        Lifespan::span(self.snap_min, self.snap_max)
    }

    /// Set the lifespan.
    pub fn set_lifespan(&mut self, snap_min: i64, snap_max: i64) {
        self.snap_min = snap_min;
        self.snap_max = snap_max;
    }
}

// ============================================================================
// Abstract DBTraceSymbol (base)
// ============================================================================

/// Base trace symbol with common fields.
///
/// Ported from `AbstractDBTraceSymbol.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceSymbolBase {
    /// The underlying entry.
    pub entry: SymbolEntry,
}

impl DbTraceSymbolBase {
    /// Create a new base symbol.
    pub fn new(entry: SymbolEntry) -> Self {
        Self { entry }
    }

    /// Get the symbol ID.
    pub fn id(&self) -> u64 {
        self.entry.id
    }

    /// Get the symbol name.
    pub fn name(&self) -> &str {
        &self.entry.name
    }

    /// Get the parent namespace ID.
    pub fn parent_id(&self) -> u64 {
        self.entry.parent_id
    }

    /// Get the kind.
    pub fn kind(&self) -> TraceSymbolKind {
        self.entry.kind
    }

    /// Get the source type.
    pub fn source(&self) -> SourceType {
        self.entry.source_type()
    }

    /// Whether this is the primary symbol.
    pub fn is_primary(&self) -> bool {
        self.entry.is_primary()
    }

    /// Get the address offset.
    pub fn address_offset(&self) -> u64 {
        self.entry.address_offset
    }

    /// Get the space name.
    pub fn space_name(&self) -> &str {
        &self.entry.space_name
    }

    /// Get the lifespan.
    pub fn lifespan(&self) -> Lifespan {
        self.entry.lifespan()
    }

    /// Set the name.
    pub fn set_name(&mut self, name: String) {
        self.entry.name = name;
    }

    /// Set the parent namespace.
    pub fn set_parent_id(&mut self, parent_id: u64) {
        self.entry.parent_id = parent_id;
    }

    /// Set the lifespan.
    pub fn set_lifespan(&mut self, snap_min: i64, snap_max: i64) {
        self.entry.set_lifespan(snap_min, snap_max);
    }
}

// ============================================================================
// Specialized Symbol Types
// ============================================================================

/// A label symbol (named address).
///
/// Ported from `DBTraceLabelSymbol.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceLabelSymbol {
    /// Base symbol.
    pub base: DbTraceSymbolBase,
}

impl DbTraceLabelSymbol {
    /// Create a new label symbol.
    pub fn new(entry: SymbolEntry) -> Self {
        Self {
            base: DbTraceSymbolBase::new(entry),
        }
    }
}

/// A namespace symbol.
///
/// Ported from `DBTraceNamespaceSymbol.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceNamespaceSymbol {
    /// Base symbol.
    pub base: DbTraceSymbolBase,
}

impl DbTraceNamespaceSymbol {
    /// Create a new namespace symbol.
    pub fn new(entry: SymbolEntry) -> Self {
        Self {
            base: DbTraceSymbolBase::new(entry),
        }
    }

    /// Whether this is the global namespace.
    pub fn is_global(&self) -> bool {
        self.base.id() == 0
    }
}

/// A class symbol.
///
/// Ported from `DBTraceClassSymbol.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbTraceClassSymbol {
    /// Base symbol.
    pub base: DbTraceSymbolBase,
}

impl DbTraceClassSymbol {
    /// Create a new class symbol.
    pub fn new(entry: SymbolEntry) -> Self {
        Self {
            base: DbTraceSymbolBase::new(entry),
        }
    }
}

// ============================================================================
// Symbol Manager
// ============================================================================

/// Manager for all symbols in a trace.
///
/// Ported from `DBTraceSymbolManager.java`.
#[derive(Debug)]
pub struct DbTraceSymbolManager {
    /// All symbols indexed by ID.
    symbols: BTreeMap<u64, SymbolEntry>,
    /// The next symbol ID.
    next_id: u64,
    /// Index: (space_name, address_offset, snap) -> symbol IDs.
    address_index: BTreeMap<(String, u64, i64), Vec<u64>>,
    /// Index: (parent_id, name) -> symbol IDs for name lookups.
    name_index: BTreeMap<(u64, String), Vec<u64>>,
}

impl DbTraceSymbolManager {
    /// Create a new symbol manager.
    pub fn new() -> Self {
        let mut mgr = Self {
            symbols: BTreeMap::new(),
            next_id: 1, // 0 is reserved for global namespace
            address_index: BTreeMap::new(),
            name_index: BTreeMap::new(),
        };
        // Create the global namespace
        let global = SymbolEntry {
            id: 0,
            name: "Global".to_string(),
            parent_id: 0,
            flags: 0,
            kind: TraceSymbolKind::Global,
            address_offset: 0,
            space_name: String::new(),
            snap_min: i64::MIN,
            snap_max: i64::MAX,
        };
        mgr.symbols.insert(0, global);
        mgr
    }

    /// Create a label symbol.
    pub fn create_label(
        &mut self,
        name: &str,
        space_name: &str,
        address_offset: u64,
        lifespan: &Lifespan,
        parent_id: u64,
        source: SourceType,
    ) -> SymbolResult<u64> {
        // Check for duplicate name in the same namespace
        if self
            .name_index
            .contains_key(&(parent_id, name.to_string()))
        {
            return Err(SymbolError::DuplicateName(name.to_string()));
        }

        let id = self.next_id;
        self.next_id += 1;

        let mut entry = SymbolEntry {
            id,
            name: name.to_string(),
            parent_id,
            flags: 0,
            kind: TraceSymbolKind::Label,
            address_offset,
            space_name: space_name.to_string(),
            snap_min: lifespan.lmin(),
            snap_max: lifespan.lmax(),
        };
        entry.set_source_type(source);
        entry.set_primary(true);

        self.address_index
            .entry((space_name.to_string(), address_offset, lifespan.lmin()))
            .or_default()
            .push(id);
        self.name_index
            .entry((parent_id, name.to_string()))
            .or_default()
            .push(id);
        self.symbols.insert(id, entry);
        Ok(id)
    }

    /// Create a namespace.
    pub fn create_namespace(
        &mut self,
        name: &str,
        parent_id: u64,
        lifespan: &Lifespan,
        source: SourceType,
    ) -> SymbolResult<u64> {
        if !self.symbols.contains_key(&parent_id) {
            return Err(SymbolError::NamespaceNotFound(parent_id));
        }

        let id = self.next_id;
        self.next_id += 1;

        let mut entry = SymbolEntry {
            id,
            name: name.to_string(),
            parent_id,
            flags: 0,
            kind: TraceSymbolKind::Namespace,
            address_offset: 0,
            space_name: String::new(),
            snap_min: lifespan.lmin(),
            snap_max: lifespan.lmax(),
        };
        entry.set_source_type(source);

        self.name_index
            .entry((parent_id, name.to_string()))
            .or_default()
            .push(id);
        self.symbols.insert(id, entry);
        Ok(id)
    }

    /// Create a class symbol.
    pub fn create_class(
        &mut self,
        name: &str,
        parent_id: u64,
        lifespan: &Lifespan,
        source: SourceType,
    ) -> SymbolResult<u64> {
        if !self.symbols.contains_key(&parent_id) {
            return Err(SymbolError::NamespaceNotFound(parent_id));
        }

        let id = self.next_id;
        self.next_id += 1;

        let mut entry = SymbolEntry {
            id,
            name: name.to_string(),
            parent_id,
            flags: 0,
            kind: TraceSymbolKind::Class,
            address_offset: 0,
            space_name: String::new(),
            snap_min: lifespan.lmin(),
            snap_max: lifespan.lmax(),
        };
        entry.set_source_type(source);

        self.name_index
            .entry((parent_id, name.to_string()))
            .or_default()
            .push(id);
        self.symbols.insert(id, entry);
        Ok(id)
    }

    /// Get a symbol by ID.
    pub fn get_symbol(&self, id: u64) -> Option<&SymbolEntry> {
        self.symbols.get(&id)
    }

    /// Get a mutable symbol by ID.
    pub fn get_symbol_mut(&mut self, id: u64) -> Option<&mut SymbolEntry> {
        self.symbols.get_mut(&id)
    }

    /// Delete a symbol by ID.
    pub fn delete_symbol(&mut self, id: u64) -> SymbolResult<()> {
        if id == 0 {
            return Err(SymbolError::InvalidInput(
                "Cannot delete global namespace".into(),
            ));
        }
        let entry = self
            .symbols
            .remove(&id)
            .ok_or(SymbolError::NotFound(id))?;

        // Remove from indices
        self.address_index
            .get_mut(&(
                entry.space_name.clone(),
                entry.address_offset,
                entry.snap_min,
            ))
            .map(|v| v.retain(|&x| x != id));
        self.name_index
            .get_mut(&(entry.parent_id, entry.name.clone()))
            .map(|v| v.retain(|&x| x != id));

        Ok(())
    }

    /// Get symbols at an address.
    pub fn get_symbols_at(
        &self,
        snap: i64,
        space_name: &str,
        address_offset: u64,
    ) -> Vec<&SymbolEntry> {
        // Search all snaps <= the given snap
        self.address_index
            .range(
                (space_name.to_string(), address_offset, i64::MIN)
                    ..=(space_name.to_string(), address_offset, snap),
            )
            .flat_map(|(_, ids)| ids.iter())
            .filter_map(|id| self.symbols.get(id))
            .filter(|e| e.snap_min <= snap && e.snap_max >= snap)
            .collect()
    }

    /// Get symbols by name in a namespace.
    pub fn get_symbols_by_name(
        &self,
        parent_id: u64,
        name: &str,
    ) -> Vec<&SymbolEntry> {
        self.name_index
            .get(&(parent_id, name.to_string()))
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.symbols.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get all children of a namespace.
    pub fn get_children(&self, parent_id: u64) -> Vec<&SymbolEntry> {
        self.symbols
            .values()
            .filter(|e| e.parent_id == parent_id)
            .collect()
    }

    /// Get all symbols in a given space and snap range.
    pub fn get_symbols_in_range(
        &self,
        snap: i64,
        space_name: &str,
        offset_min: u64,
        offset_max: u64,
    ) -> Vec<&SymbolEntry> {
        self.symbols
            .values()
            .filter(|e| {
                e.space_name == space_name
                    && e.address_offset >= offset_min
                    && e.address_offset <= offset_max
                    && e.snap_min <= snap
                    && e.snap_max >= snap
            })
            .collect()
    }

    /// Get the global namespace ID.
    pub fn global_namespace_id(&self) -> u64 {
        0
    }

    /// Get total number of symbols.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Get all symbol IDs.
    pub fn all_ids(&self) -> Vec<u64> {
        self.symbols.keys().copied().collect()
    }
}

impl Default for DbTraceSymbolManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Multi-Type Symbol Views
// ============================================================================

/// A view of symbols of multiple types.
///
/// Ported from `DBTraceSymbolMultipleTypesView.java`.
#[derive(Debug)]
pub struct SymbolMultipleTypesView<'a> {
    manager: &'a DbTraceSymbolManager,
    kinds: Vec<TraceSymbolKind>,
}

impl<'a> SymbolMultipleTypesView<'a> {
    /// Create a new view filtering by kinds.
    pub fn new(manager: &'a DbTraceSymbolManager, kinds: Vec<TraceSymbolKind>) -> Self {
        Self { manager, kinds }
    }

    /// Get all symbols matching the type filter at the given snap.
    pub fn all(&self, snap: i64) -> Vec<&SymbolEntry> {
        self.manager
            .symbols
            .values()
            .filter(|e| self.kinds.contains(&e.kind) && e.snap_min <= snap && e.snap_max >= snap)
            .collect()
    }
}

/// A view of symbols with address, deduplicated.
///
/// Ported from `DBTraceSymbolMultipleTypesWithAddressView.java`.
#[derive(Debug)]
pub struct SymbolWithAddressView<'a> {
    manager: &'a DbTraceSymbolManager,
    kinds: Vec<TraceSymbolKind>,
}

impl<'a> SymbolWithAddressView<'a> {
    /// Create a new view.
    pub fn new(manager: &'a DbTraceSymbolManager, kinds: Vec<TraceSymbolKind>) -> Self {
        Self { manager, kinds }
    }

    /// Get symbols at a specific address.
    pub fn at_address(&self, snap: i64, space: &str, offset: u64) -> Vec<&SymbolEntry> {
        self.manager
            .get_symbols_at(snap, space, offset)
            .into_iter()
            .filter(|e| self.kinds.contains(&e.kind))
            .collect()
    }

    /// Get all symbols in an offset range.
    pub fn in_range(
        &self,
        snap: i64,
        space: &str,
        offset_min: u64,
        offset_max: u64,
    ) -> Vec<&SymbolEntry> {
        self.manager
            .get_symbols_in_range(snap, space, offset_min, offset_max)
            .into_iter()
            .filter(|e| self.kinds.contains(&e.kind))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_lifespan() -> Lifespan {
        Lifespan::span(0, 100)
    }

    #[test]
    fn test_symbol_manager_create_label() {
        let mut mgr = DbTraceSymbolManager::new();
        let id = mgr
            .create_label(
                "main",
                "ram",
                0x400000,
                &test_lifespan(),
                0,
                SourceType::UserDefined,
            )
            .unwrap();
        assert!(id > 0);

        let sym = mgr.get_symbol(id).unwrap();
        assert_eq!(sym.name, "main");
        assert_eq!(sym.address_offset, 0x400000);
        assert_eq!(sym.kind, TraceSymbolKind::Label);
    }

    #[test]
    fn test_symbol_manager_create_namespace() {
        let mut mgr = DbTraceSymbolManager::new();
        let ns_id = mgr
            .create_namespace("libc", 0, &test_lifespan(), SourceType::Analysis)
            .unwrap();
        assert!(ns_id > 0);

        let children = mgr.get_children(0);
        // Has libc plus global itself is at 0
        assert!(children.iter().any(|e| e.name == "libc"));
    }

    #[test]
    fn test_symbol_manager_duplicate_name() {
        let mut mgr = DbTraceSymbolManager::new();
        mgr.create_label(
            "main",
            "ram",
            0x400000,
            &test_lifespan(),
            0,
            SourceType::UserDefined,
        )
        .unwrap();
        let result = mgr.create_label(
            "main",
            "ram",
            0x400000,
            &test_lifespan(),
            0,
            SourceType::UserDefined,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_symbol_manager_delete() {
        let mut mgr = DbTraceSymbolManager::new();
        let id = mgr
            .create_label(
                "main",
                "ram",
                0x400000,
                &test_lifespan(),
                0,
                SourceType::UserDefined,
            )
            .unwrap();
        assert!(mgr.get_symbol(id).is_some());

        mgr.delete_symbol(id).unwrap();
        assert!(mgr.get_symbol(id).is_none());
    }

    #[test]
    fn test_symbol_manager_delete_global() {
        let mut mgr = DbTraceSymbolManager::new();
        let result = mgr.delete_symbol(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_symbols_at_address() {
        let mut mgr = DbTraceSymbolManager::new();
        mgr.create_label(
            "func1",
            "ram",
            0x400000,
            &test_lifespan(),
            0,
            SourceType::Analysis,
        )
        .unwrap();
        mgr.create_label(
            "func2",
            "ram",
            0x400100,
            &test_lifespan(),
            0,
            SourceType::Analysis,
        )
        .unwrap();

        let at = mgr.get_symbols_at(0, "ram", 0x400000);
        assert_eq!(at.len(), 1);
        assert_eq!(at[0].name, "func1");
    }

    #[test]
    fn test_symbol_manager_by_name() {
        let mut mgr = DbTraceSymbolManager::new();
        mgr.create_label(
            "printf",
            "ram",
            0x1000,
            &test_lifespan(),
            0,
            SourceType::Default,
        )
        .unwrap();

        let found = mgr.get_symbols_by_name(0, "printf");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].address_offset, 0x1000);
    }

    #[test]
    fn test_multi_type_view() {
        let mut mgr = DbTraceSymbolManager::new();
        mgr.create_label(
            "main",
            "ram",
            0x400000,
            &test_lifespan(),
            0,
            SourceType::UserDefined,
        )
        .unwrap();
        mgr.create_namespace("ns", 0, &test_lifespan(), SourceType::Analysis)
            .unwrap();

        let view = SymbolMultipleTypesView::new(&mgr, vec![TraceSymbolKind::Label]);
        let labels = view.all(0);
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].name, "main");
    }

    #[test]
    fn test_with_address_view() {
        let mut mgr = DbTraceSymbolManager::new();
        mgr.create_label(
            "main",
            "ram",
            0x400000,
            &test_lifespan(),
            0,
            SourceType::UserDefined,
        )
        .unwrap();

        let view = SymbolWithAddressView::new(&mgr, vec![TraceSymbolKind::Label]);
        let at = view.at_address(0, "ram", 0x400000);
        assert_eq!(at.len(), 1);

        let in_range = view.in_range(0, "ram", 0, 0x500000);
        assert_eq!(in_range.len(), 1);
    }

    #[test]
    fn test_symbol_entry_source_type() {
        let mut entry = SymbolEntry {
            id: 1,
            name: "test".into(),
            parent_id: 0,
            flags: 0,
            kind: TraceSymbolKind::Label,
            address_offset: 0x100,
            space_name: "ram".into(),
            snap_min: 0,
            snap_max: 100,
        };
        entry.set_source_type(SourceType::UserDefined);
        assert_eq!(entry.source_type(), SourceType::UserDefined);

        entry.set_source_type(SourceType::Analysis);
        assert_eq!(entry.source_type(), SourceType::Analysis);
    }

    #[test]
    fn test_symbol_entry_primary() {
        let mut entry = SymbolEntry {
            id: 1,
            name: "test".into(),
            parent_id: 0,
            flags: 0,
            kind: TraceSymbolKind::Label,
            address_offset: 0x100,
            space_name: "ram".into(),
            snap_min: 0,
            snap_max: 100,
        };
        assert!(!entry.is_primary());
        entry.set_primary(true);
        assert!(entry.is_primary());
        entry.set_primary(false);
        assert!(!entry.is_primary());
    }
}
