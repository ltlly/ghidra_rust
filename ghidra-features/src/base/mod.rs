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
//! - [`plugin`] — base GUI plugins (codebrowser, listing, symboltree, bytes, comment, decompile, terminal)

pub mod analyzer;
pub mod assembler;
pub mod association;
pub mod bookmark;
pub mod checksums;
pub mod data;
pub mod datamgr;
pub mod clear;
pub mod clipboard;
pub mod colorizer;
pub mod comment;
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
pub mod operandfield;
pub mod properties;
pub mod property;
pub mod references;
pub mod register;
pub mod reloc;
pub mod rename;
pub mod select;
pub mod stack;
pub mod subroutine;
pub mod symbol;
pub mod symboltable;

// -- New modules ported from Ghidra's Features/Base app packages --
/// Plugin events for program lifecycle, location, selection, and highlighting.
/// Ported from `ghidra.app.events`.
pub mod events;

/// Action context types for Ghidra's docking action framework.
/// Ported from `ghidra.app.context`.
pub mod context;

/// Command pattern implementations for undoable program modifications.
/// Ported from `ghidra.app.cmd` (sub-packages: analysis, comments, data,
/// disassemble, equate, formats, function, label, memory, module, refs, register).
pub mod cmd;

/// Service interfaces for Ghidra's plugin framework.
/// Ported from `ghidra.app.services`.
pub mod services;

/// Navigation types for program viewers and navigatables.
/// Ported from `ghidra.app.nav`.
pub mod nav;

/// Table chooser dialog framework.
/// Ported from `ghidra.app.tablechooser`.
pub mod tablechooser;

/// Binary format analyzers that run automatically during import.
/// Ported from `ghidra.app.analyzers`.
pub mod analyzers;

/// Application-level actions.
/// Ported from `ghidra.app.actions`.
pub mod actions;

/// Plugin component factories.
/// Ported from `ghidra.app.factory`.
pub mod factory;

/// Auto-analysis framework with Analyzer trait, priorities, and manager.
/// Ported from `ghidra.framework.analysis` and `ghidra.app.analyzers`.
pub mod analysis;

/// GoTo navigation service trait.
/// Ported from `ghidra.app.services.GoToService`.
pub mod goto;

/// Program tree views for organizing program structure.
/// Ported from `ghidra.app.plugin.core.programtree`.
pub mod programtree;

/// Symbol tree plugin for browsing program symbols in a tree hierarchy.
/// Ported from `ghidra.app.plugin.core.symboltree`.
pub mod symboltree;

/// BytesView feature -- raw memory byte viewer.
/// Ported from `ghidra.app.plugin.core.byteviewer` Java packages.
/// Contains: plugin lifecycle, provider with display, navigation, and clipboard.
pub mod bytes;

/// Base GUI plugins.
/// Ported from `ghidra.app.plugin.core` Java packages.
/// Contains: codebrowser, listing, symboltree, bytes, comment, decompile, terminal.
pub mod plugin;

/// Listing display management.
/// Ported from `ghidra.app.plugin.core.listing` package.
/// Provides: listing plugin, listing provider, field layout, formatting.
pub mod listing;

/// Code browser -- the main program listing display window.
/// Ported from `ghidra.app.plugin.core.codebrowser` package.
/// Provides: code browser plugin (lifecycle, events, navigation, providers),
/// code browser view (cursor, selection, scrolling, fields).
pub mod codebrowser;

/// Program management -- lifecycle, events, and service interface.
/// Ported from `ghidra.app.plugin.ProgramPlugin` and
/// `ghidra.app.services.ProgramManager`.
/// Provides: ProgramPlugin base class, ProgramManager trait, and
/// InMemoryProgramManager implementation.
pub mod program;

/// Composite (struct/union) data type editor.
/// Ported from `ghidra.app.plugin.core.compositeeditor` Java packages.
/// Provides: editor panel with table management, selection, cell editing,
/// drag-and-drop, undo/redo; field list editor; editor provider types
/// (structure, union); structure-specific panel with bit-field and alignment.
pub mod compositeeditor;
