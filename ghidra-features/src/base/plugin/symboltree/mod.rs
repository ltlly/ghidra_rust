//! Symbol Tree Plugin -- displays program symbols in a tree hierarchy.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.symboltree` package.
//!
//! This module provides the symbol tree plugin that displays symbols from
//! the program in a tree organized by namespace.
//!
//! # Modules
//!
//! - [`symbol_tree_plugin`] -- The main plugin struct and lifecycle

pub mod symbol_tree_plugin;

pub use symbol_tree_plugin::{
    SymbolCategory, SymbolFilter, SymbolNode, SymbolNodeType, SymbolTreePlugin,
};
