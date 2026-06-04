//! Symbol tree plugin -- ported from `ghidra.app.plugin.core.symboltree`.
//!
//! Provides the [`SymbolTreePlugin`] that shows program symbols in a
//! hierarchical tree, along with [`SymbolCategory`] for organising symbols
//! into predefined groups, [`SymbolTreeNode`] for the tree nodes, and the
//! [`SymbolTreeService`] trait for external consumers.
//!
//! # Architecture
//!
//! The Ghidra Java implementation uses a Swing `GTree` for display and a
//! `Plugin` subclass for lifecycle management.  In Rust we keep the data
//! model and logic, deferring any actual rendering to the `ghidra-gui`
//! crate.  The types here are therefore backend-agnostic.

pub mod actions;
pub mod category;
pub mod provider;
pub mod service;
pub mod plugin;

pub use actions::*;
pub use category::*;
pub use provider::*;
pub use service::*;
pub use plugin::*;
