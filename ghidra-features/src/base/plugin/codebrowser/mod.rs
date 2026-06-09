//! Code Browser Plugin -- the main program listing display window.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.codebrowser` package.
//!
//! This module provides the primary code listing view where users interact
//! with disassembly, data, and other program information.
//!
//! # Modules
//!
//! - [`code_browser_plugin`] -- The main plugin struct and lifecycle
//! - [`code_browser`] -- The listing view component

pub mod code_browser;
pub mod code_browser_plugin;

pub use code_browser::{
    CodeBrowser, CursorPosition, ListingField, ListingFieldType,
};
pub use code_browser_plugin::{
    CodeBrowserPlugin, CodeBrowserProvider, PluginInfo, PluginOptionValue, PluginStatus,
};
