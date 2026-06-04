//! Ghidra Rust - Base analysis features.
//!
//! This module contains the auto-analysis framework ported from
//! `ghidra.app.plugin.core.analysis` and `ghidra.app.services`.
//!
//! It provides:
//! - The [`Analyzer`] trait for implementing automatic analysis passes
//! - [`AutoAnalysisManager`] for orchestrating analyzer execution
//! - Built-in analyzers (function start, code boundary, references, etc.)
//! - [`memory`] — memory map management (add, expand, move, split, merge blocks)
//! - [`register`] — register value management (tree, value ranges, set/clear commands)
//! - [`property`] — property map management (CRUD, delete commands, table model, plugin)
//! - [`association`] — association management (lifecycle, blocking, table adapter)
//! - [`checksums`] — checksum computation (MD5, SHA, CRC, Adler-32, basic)
//! - [`clipboard`] — clipboard management (copy/paste, content providers)
//! - [`colorizer`] — address-based background color highlighting
//! - [`entropy`] — Shannon entropy analysis for memory blocks
//! - [`marker`] — marker set system for navigation and overview display
//! - [`navigation`] — next/previous navigation actions for code elements
//! - [`reloc`] — relocation fixup handlers for binary rebasing
//! - [`select`] — flow-based code selection actions

pub mod analyzer;
pub mod assembler;
pub mod association;
pub mod bookmark;
pub mod checksums;
pub mod clear;
pub mod clipboard;
pub mod colorizer;
pub mod comments;
pub mod console;
pub mod crossrefs;
pub mod disassembler;
pub mod entropy;
pub mod equate;
pub mod flow;
pub mod function;
pub mod label;
pub mod marker;
pub mod memory;
pub mod merge;
pub mod navigation;
pub mod operand;
pub mod property;
pub mod references;
pub mod register;
pub mod reloc;
pub mod rename;
pub mod select;
pub mod stack;
pub mod subroutine;
pub mod symbol;
