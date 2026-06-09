//! Base GUI plugins for Ghidra Rust.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core` Java packages.
//!
//! This module contains the core GUI plugins that provide the main
//! user-facing functionality of Ghidra:
//!
//! - [`codebrowser`] -- The main program listing display window
//! - [`listing`] -- Program listing display management
//! - [`symboltree`] -- Symbol tree view for browsing program symbols
//! - [`bytes`] -- Raw memory byte viewer
//! - [`comment`] -- Comment management
//! - [`decompile`] -- Decompiler panel
//! - [`terminal`] -- VT100 terminal emulator
//!
//! # Architecture
//!
//! Each plugin follows the same pattern:
//! - A main plugin struct with `new()`, `init()`, `dispose()` lifecycle
//! - Supporting types for the plugin's domain
//! - Plugin options for user configuration
//! - Display components for the UI
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::plugin::codebrowser::CodeBrowserPlugin;
//! use ghidra_features::base::plugin::listing::ListingPlugin;
//! use ghidra_features::base::plugin::symboltree::SymbolTreePlugin;
//! use ghidra_features::base::plugin::bytes::BytesPlugin;
//! use ghidra_features::base::plugin::comment::CommentPlugin;
//! use ghidra_features::base::plugin::decompile::DecompilePlugin;
//! use ghidra_features::base::plugin::terminal::TerminalPlugin;
//!
//! let mut codebrowser = CodeBrowserPlugin::new("CodeBrowser");
//! codebrowser.init();
//!
//! let mut listing = ListingPlugin::new("Listing");
//! listing.init();
//!
//! let mut symboltree = SymbolTreePlugin::new("SymbolTree");
//! symboltree.init();
//!
//! let mut bytes = BytesPlugin::new("Bytes");
//! bytes.init();
//!
//! let mut comment = CommentPlugin::new("Comments");
//! comment.init();
//!
//! let mut decompile = DecompilePlugin::new("Decompiler");
//! decompile.init();
//!
//! let mut terminal = TerminalPlugin::new("Terminal");
//! terminal.init();
//! ```

/// Code Browser Plugin -- the main program listing display window.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.codebrowser` package.
pub mod codebrowser;

/// Listing Plugin -- manages the program listing display.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.listing` package.
pub mod listing;

/// Symbol Tree Plugin -- displays program symbols in a tree hierarchy.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.symboltree` package.
pub mod symboltree;

/// Bytes Plugin -- displays raw memory bytes in various formats.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.byteviewer` and
/// `ghidra.app.plugin.core.format` packages.
pub mod bytes;

/// Comment Plugin -- manages comments in the program listing.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.comments` package.
pub mod comment;

/// Decompiler Plugin -- provides the decompiler panel.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.decompile` package.
pub mod decompile;

/// Terminal Plugin -- provides a VT100 terminal emulator.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.terminal` package.
pub mod terminal;
