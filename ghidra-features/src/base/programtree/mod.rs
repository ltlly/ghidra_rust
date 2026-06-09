//! Program Tree Plugin -- displays program tree views.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.programtree` package.
//!
//! This module provides the program tree plugin that displays program
//! structure as a tree of modules and fragments, allowing users to
//! organize and navigate the program's address space.
//!
//! # Modules
//!
//! - [`program_tree_plugin`] -- The main plugin struct and lifecycle
//! - [`program_tree_provider`] -- Tree view provider for program trees

pub mod program_tree_plugin;
pub mod program_tree_provider;

pub use program_tree_plugin::{
    ProgramNode, ProgramNodeType, ProgramTreePlugin, TreeViewState,
};
pub use program_tree_provider::{
    ProgramTreeProvider, ViewProviderService,
};
