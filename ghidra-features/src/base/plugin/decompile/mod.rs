//! Decompiler Plugin -- provides the decompiler panel.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.decompile` package.
//!
//! This module provides the decompiler plugin that produces a high-level C
//! interpretation of assembly functions.
//!
//! # Modules
//!
//! - [`decompile_plugin`] -- The main plugin struct and lifecycle

pub mod decompile_plugin;

pub use decompile_plugin::{
    DecompileOption, DecompilePlugin, DecompileResult, DecompileResultCache, DecompileStatus,
    DecompiledToken, DecompiledTokenType,
};
