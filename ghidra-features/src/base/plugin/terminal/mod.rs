//! Terminal Plugin -- provides a VT100 terminal emulator.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.terminal` package.
//!
//! This module provides the terminal plugin that provides a VT100 terminal
//! emulator embedded in Ghidra. Supports ANSI escape sequences, scrolling,
//! and searching.
//!
//! # Modules
//!
//! - [`terminal_plugin`] -- The main plugin struct and lifecycle

pub mod terminal_plugin;

pub use terminal_plugin::{
    TerminalCell, TerminalColor, TerminalFindOptions, TerminalOption, TerminalPlugin, TerminalState,
    DEFAULT_HEIGHT, DEFAULT_WIDTH, MAX_SCROLLBACK,
};
