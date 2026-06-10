//! Terminal plugin for the Ghidra VT100 terminal emulator.
//!
//! Port of Ghidra's `ghidra.app.plugin.core.terminal` Java package.
//! Provides:
//!
//! - [`TerminalPlugin`] -- plugin lifecycle, program activation hooks, and
//!   [`TerminalService`] trait delegation
//! - [`TerminalProvider`] -- view-state manager with cell grid, scrollback,
//!   ANSI escape parsing, process attachment, and text search
//! - [`TerminalCell`], [`TerminalColor`] -- low-level display primitives
//! - [`TerminalProviderConfig`] -- display options (dimensions, font, scrollback)
//! - [`ProcessHandle`], [`SearchState`] -- auxiliary types
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::terminal::{TerminalPlugin, TerminalService};
//!
//! let mut plugin = TerminalPlugin::new("MyTerminal");
//! plugin.init();
//! plugin.write("Hello, ");
//! plugin.writeln("terminal!");
//! assert!(plugin.get_screen_text().contains("Hello"));
//! plugin.dispose();
//! ```

pub mod terminal_plugin;
pub mod terminal_provider;

pub use terminal_plugin::{PluginInfo, PluginStatus, TerminalPlugin, TerminalService};
pub use terminal_provider::{
    ProcessHandle, ProcessStatus, SearchState, TerminalCell, TerminalColor, TerminalProvider,
    TerminalProviderConfig, DEFAULT_HEIGHT, DEFAULT_WIDTH, MAX_SCROLLBACK,
};
