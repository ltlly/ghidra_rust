//! Code Browser -- the main program listing display window.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.codebrowser` Java package.
//!
//! This module provides the primary code listing view where users interact
//! with disassembly, data, and other program information.  It manages
//! the connected (primary) and disconnected (cloned) providers, handles
//! navigation, selection, highlighting, and event dispatch.
//!
//! # Modules
//!
//! - [`code_browser_plugin`] -- The main plugin struct, lifecycle, and event handling
//! - [`code_browser`] -- The listing view component with cursor, selection, and scrolling
//!
//! # Architecture
//!
//! ```text
//! CodeBrowserPlugin
//!   ├── CodeBrowserProvider (connected / primary)
//!   ├── Vec<CodeBrowserProvider> (disconnected / clones)
//!   ├── EventDispatcher (plugin event bus)
//!   ├── NavigationManager (back/forward/go-to)
//!   └── SelectionManager (address range selection)
//! ```

pub mod code_browser;
pub mod code_browser_plugin;

pub use code_browser::{CodeBrowser, CursorPosition, ListingField, ListingFieldType};
pub use code_browser_plugin::{
    CodeBrowserPlugin, CodeBrowserProvider, PluginEvent, PluginInfo, PluginOptionValue,
    PluginStatus,
};
