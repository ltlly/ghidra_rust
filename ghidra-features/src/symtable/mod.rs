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

use ghidra_core::{Address, SymbolKind, SymbolType, SourceType};
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
    pub kind: SymbolKind,
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
}

