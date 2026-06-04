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

pub use filter::*;
pub use model::*;
pub use plugin::*;
pub use provider::*;
pub use editor::*;
pub use reference::*;
pub use dnd::*;
