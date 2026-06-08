//! Symbol Table plugin -- ported from `ghidra.app.plugin.core.symtable`.
//!
//! Provides the symbol table view that shows all symbols in a program
//! as a flat, sortable, filterable table.  This is complementary to
//! the hierarchical symbol tree in [`super::base::symbol`].
//!
//! # Architecture
//!
//! The Ghidra Java implementation uses a Swing `GTable` with a custom
//! `AbstractSymbolTableModel`.  In Rust we keep the data model and
//! logic, deferring any actual rendering to the `ghidra-gui` crate.
//!
//! # Modules
//!
//! | Rust module          | Java class(es)                                |
//! |----------------------|-----------------------------------------------|
//! | `filter`             | `SymbolFilter`, `NewSymbolFilter`, `FilterDialog` |
//! | `model`              | `AbstractSymbolTableModel`, `SymbolRowObject`, `DeletedSymbolRowObject` |
//! | `plugin`             | `SymbolTablePlugin`                           |
//! | `provider`           | `SymbolProvider`, `SymbolPanel`               |
//! | `editor`             | `SymbolEditor`                                |
//! | `reference`          | `SymbolReferenceModel`, `ReferencePanel`, `ReferenceProvider` |
//! | `dnd`                | `SymbolDataFlavor`, `SymbolTransferable`, `SymbolTransferData` |

pub mod filter;
pub mod model;
pub mod plugin;
pub mod provider;
pub mod editor;
pub mod reference;
pub mod row_object;
pub mod dnd;

/// Symbol renderer, transient table model, and row-object mappers.
///
/// Ported from `SymbolRenderer`, `TransientSymbolTableModel`,
/// `SymbolRowObjectToAddressTableRowMapper`, and
/// `SymbolRowObjectToProgramLocationTableRowMapper`.
pub mod renderer;

pub use filter::*;
pub use model::*;
pub use plugin::*;
pub use provider::*;
pub use editor::*;
pub use reference::*;
pub use dnd::*;

use ghidra_core::{Address, SymbolType, SourceType};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// SymbolTableService -- service interface
// ---------------------------------------------------------------------------

/// Service interface provided by the symbol table plugin.
///
/// Ported from `ghidra.app.plugin.core.symtable.SymbolTableService`.
pub trait SymbolTableService {
    /// Get the number of visible (filtered) symbols.
    fn visible_count(&self) -> usize;
    /// Navigate to a symbol by ID.
    fn go_to_symbol(&self, symbol_id: u64);
    /// Refresh the symbol table.
    fn refresh(&mut self);
}

// ---------------------------------------------------------------------------
// NavigateOnEvent -- cursor behavior
// ---------------------------------------------------------------------------

/// Configuration for whether to navigate on incoming/outgoing GoTo events.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct NavigateOnEvent {
    /// Navigate when receiving an incoming GoTo event.
    pub on_incoming: bool,
    /// Navigate when receiving an outgoing GoTo event.
    pub on_outgoing: bool,
}

impl Default for NavigateOnEvent {
    fn default() -> Self {
        Self {
            on_incoming: true,
            on_outgoing: false,
        }
    }
}

// ---------------------------------------------------------------------------
// SymbolDisplayInfo -- summary for display
// ---------------------------------------------------------------------------

/// Summary information for displaying a symbol in the table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolDisplayInfo {
    /// Symbol ID.
    pub id: u64,
    /// Address of the symbol.
    pub address: Address,
    /// Symbol name.
    pub name: String,
    /// Symbol type.
    pub symbol_type: SymbolType,
    /// Symbol kind.
    pub kind: SymbolType,
    /// Source of the symbol.
    pub source: SourceType,
    /// Namespace path.
    pub namespace: String,
    /// Number of references.
    pub ref_count: usize,
    /// Whether this is the primary symbol at its address.
    pub is_primary: bool,
}

impl SymbolDisplayInfo {
    /// Get fully qualified name.
    pub fn qualified_name(&self) -> String {
        if self.namespace.is_empty() || self.namespace == "Global" {
            self.name.clone()
        } else {
            format!("{}::{}", self.namespace, self.name)
        }
    }
}

// ---------------------------------------------------------------------------
// ReferenceTableContext
// ---------------------------------------------------------------------------

/// Context for the reference table in the symbol table.
///
/// Ported from `ghidra.app.plugin.core.symtable.ReferenceTableContext`.
#[derive(Debug, Clone)]
pub struct ReferenceTableContext {
    /// The selected symbol name.
    pub symbol_name: String,
    /// The selected symbol address.
    pub address: u64,
    /// Whether the context has a selection.
    pub has_selection: bool,
    /// Selected reference addresses.
    pub selected_references: Vec<u64>,
}

impl ReferenceTableContext {
    /// Create a new reference table context.
    pub fn new(symbol_name: impl Into<String>, address: u64) -> Self {
        Self {
            symbol_name: symbol_name.into(),
            address,
            has_selection: false,
            selected_references: Vec::new(),
        }
    }

    /// Add a selected reference.
    pub fn select_reference(&mut self, address: u64) {
        self.selected_references.push(address);
        self.has_selection = true;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_navigate_on_event_default() {
        let nav = NavigateOnEvent::default();
        assert!(nav.on_incoming);
        assert!(!nav.on_outgoing);
    }

    #[test]
    fn test_symbol_display_info_qualified_name() {
        let info = SymbolDisplayInfo {
            id: 1,
            address: Address::new(0x4000),
            name: "main".to_string(),
            symbol_type: SymbolType::Function,
            kind: SymbolType::Function,
            source: SourceType::Default,
            namespace: "Global".to_string(),
            ref_count: 5,
            is_primary: true,
        };
        assert_eq!(info.qualified_name(), "main");

        let info2 = SymbolDisplayInfo {
            namespace: "libc".to_string(),
            ..info.clone()
        };
        assert_eq!(info2.qualified_name(), "libc::main");
    }

    #[test]
    fn test_symbol_display_info_creation() {
        let info = SymbolDisplayInfo {
            id: 42,
            address: Address::new(0x1000),
            name: "printf".to_string(),
            symbol_type: SymbolType::Function,
            kind: SymbolType::Function,
            source: SourceType::Imported,
            namespace: "libc".to_string(),
            ref_count: 100,
            is_primary: true,
        };
        assert_eq!(info.id, 42);
        assert_eq!(info.ref_count, 100);
        assert!(info.is_primary);
    }

    // -- SymbolTableDnDAdapter tests --

    #[test]
    fn test_symbol_table_dnd_adapter() {
        let mut adapter = SymbolTableDnDAdapter::new();
        assert!(adapter.is_empty());

        adapter.add_draggable_symbol(DraggableSymbol {
            id: 1,
            name: "main".to_string(),
            address: Address::new(0x401000),
        });
        adapter.add_draggable_symbol(DraggableSymbol {
            id: 2,
            name: "init".to_string(),
            address: Address::new(0x402000),
        });
        assert_eq!(adapter.symbol_count(), 2);
    }

    #[test]
    fn test_symbol_table_dnd_adapter_get_symbol() {
        let mut adapter = SymbolTableDnDAdapter::new();
        adapter.add_draggable_symbol(DraggableSymbol {
            id: 1,
            name: "main".to_string(),
            address: Address::new(0x401000),
        });
        let sym = adapter.get_symbol(1);
        assert!(sym.is_some());
        assert_eq!(sym.unwrap().name, "main");
    }

    #[test]
    fn test_symbol_table_drag_provider() {
        let mut provider = SymbolTableDragProvider::new();
        assert!(!provider.is_dragging());

        provider.begin_drag(vec![1, 2, 3]);
        assert!(provider.is_dragging());
        assert_eq!(provider.dragged_ids().len(), 3);

        provider.end_drag();
        assert!(!provider.is_dragging());
    }

    #[test]
    fn test_transient_symbol_table_dnd_adapter() {
        let mut adapter = TransientSymbolTableDnDAdapter::new();
        adapter.set_transient_symbols(vec![
            DraggableSymbol { id: 10, name: "temp".to_string(), address: Address::new(0x5000) },
        ]);
        assert_eq!(adapter.symbol_count(), 1);

        adapter.clear();
        assert!(adapter.is_empty());
    }

    // -- ProgramTreeActionContext tests --

    #[test]
    fn test_program_tree_action_context() {
        let ctx = ProgramTreeActionContext::new("MyTree", Some(42));
        assert_eq!(ctx.tree_name(), "MyTree");
        assert_eq!(ctx.selected_module_id(), Some(42));
    }

    #[test]
    fn test_program_tree_action_context_no_selection() {
        let ctx = ProgramTreeActionContext::new("MyTree", None);
        assert!(ctx.selected_module_id().is_none());
        assert!(!ctx.has_selection());
    }
}

// ---------------------------------------------------------------------------
// SymbolTableDnDAdapter, SymbolTableDragProvider, TransientSymbolTableDnDAdapter
//
// Ported from `SymbolTableDnDAdapter.java`, `SymbolTableDragProvider.java`,
// and `TransientSymbolTableDnDAdapter.java` in `ghidra.app.plugin.core.symtable`.
//
// These provide drag-and-drop support for symbols from the symbol table.
// ---------------------------------------------------------------------------

/// A draggable symbol used for DnD operations.
#[derive(Debug, Clone)]
pub struct DraggableSymbol {
    /// Symbol ID.
    pub id: u64,
    /// Symbol name.
    pub name: String,
    /// Symbol address.
    pub address: Address,
}

/// Adapter for dragging symbols from the symbol table.
#[derive(Debug, Clone, Default)]
pub struct SymbolTableDnDAdapter {
    symbols: Vec<DraggableSymbol>,
}

impl SymbolTableDnDAdapter {
    /// Create a new empty adapter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether the adapter has no symbols.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Number of draggable symbols.
    pub fn symbol_count(&self) -> usize {
        self.symbols.len()
    }

    /// Add a draggable symbol.
    pub fn add_draggable_symbol(&mut self, symbol: DraggableSymbol) {
        self.symbols.push(symbol);
    }

    /// Get a symbol by ID.
    pub fn get_symbol(&self, id: u64) -> Option<&DraggableSymbol> {
        self.symbols.iter().find(|s| s.id == id)
    }

    /// Get all draggable symbols.
    pub fn symbols(&self) -> &[DraggableSymbol] {
        &self.symbols
    }

    /// Clear all symbols.
    pub fn clear(&mut self) {
        self.symbols.clear();
    }
}

/// Provider that manages drag operations from the symbol table.
#[derive(Debug, Clone, Default)]
pub struct SymbolTableDragProvider {
    /// IDs of symbols currently being dragged.
    dragged_ids: Vec<u64>,
    /// Whether a drag operation is in progress.
    is_dragging: bool,
}

impl SymbolTableDragProvider {
    /// Create a new drag provider.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether a drag operation is in progress.
    pub fn is_dragging(&self) -> bool {
        self.is_dragging
    }

    /// Begin a drag operation with the given symbol IDs.
    pub fn begin_drag(&mut self, ids: Vec<u64>) {
        self.dragged_ids = ids;
        self.is_dragging = true;
    }

    /// End the current drag operation.
    pub fn end_drag(&mut self) {
        self.dragged_ids.clear();
        self.is_dragging = false;
    }

    /// Get the IDs of the symbols being dragged.
    pub fn dragged_ids(&self) -> &[u64] {
        &self.dragged_ids
    }
}

/// Adapter for transient (temporary) symbol DnD operations.
#[derive(Debug, Clone, Default)]
pub struct TransientSymbolTableDnDAdapter {
    adapter: SymbolTableDnDAdapter,
}

impl TransientSymbolTableDnDAdapter {
    /// Create a new transient adapter.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the transient symbols.
    pub fn set_transient_symbols(&mut self, symbols: Vec<DraggableSymbol>) {
        self.adapter.clear();
        for sym in symbols {
            self.adapter.add_draggable_symbol(sym);
        }
    }

    /// Number of transient symbols.
    pub fn symbol_count(&self) -> usize {
        self.adapter.symbol_count()
    }

    /// Whether there are no transient symbols.
    pub fn is_empty(&self) -> bool {
        self.adapter.is_empty()
    }

    /// Clear all transient symbols.
    pub fn clear(&mut self) {
        self.adapter.clear();
    }
}

// ---------------------------------------------------------------------------
// ProgramTreeActionContext
//
// Ported from `ProgramTreeActionContext.java` in `ghidra.app.plugin.core.programtree`.
// ---------------------------------------------------------------------------

/// Action context for the program tree.
///
/// Captures the current tree name and selected module ID for action dispatch.
#[derive(Debug, Clone)]
pub struct ProgramTreeActionContext {
    /// The name of the program tree.
    tree_name: String,
    /// The ID of the selected module, if any.
    selected_module_id: Option<u64>,
}

impl ProgramTreeActionContext {
    /// Create a new action context.
    pub fn new(tree_name: impl Into<String>, selected_module_id: Option<u64>) -> Self {
        Self {
            tree_name: tree_name.into(),
            selected_module_id,
        }
    }

    /// Get the tree name.
    pub fn tree_name(&self) -> &str {
        &self.tree_name
    }

    /// Get the selected module ID.
    pub fn selected_module_id(&self) -> Option<u64> {
        self.selected_module_id
    }

    /// Whether a module is selected.
    pub fn has_selection(&self) -> bool {
        self.selected_module_id.is_some()
    }
}

