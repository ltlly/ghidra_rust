//! Decompiler UI Plugin -- Rust port of Ghidra's
//! `ghidra.app.plugin.core.decompile` package.
//!
//! Provides the user-facing decompiler panel that produces a high-level C
//! interpretation of assembly functions.  This module models the plugin,
//! provider, action context, clipboard provider, overlay painter, and
//! the set of decompiler actions (rename, retype, commit, search, etc.).
//!
//! # Architecture
//!
//! ```text
//! DecompilePlugin
//!   ├── DecompilerProvider (connected)
//!   └── Vec<DecompilerProvider> (disconnected / snapshots)
//!         ├── DecompilerController
//!         ├── DecompilerPanel (renders clang tokens)
//!         ├── DecompilerClipboardProvider
//!         └── OverlayMessagePainter
//! ```

pub mod action_context;
pub mod actions;
pub mod clipboard_provider;
pub mod location_memento;
pub mod overlay_painter;
pub mod plugin;
pub mod provider;

// Re-export the most important public types at the module root.
pub use action_context::DecompilerActionContext;
pub use clipboard_provider::DecompilerClipboardProvider;
pub use location_memento::DecompilerLocationMemento;
pub use overlay_painter::OverlayMessagePainter;
pub use plugin::DecompilePlugin;
pub use provider::{DecompilerProvider, ProviderState};
