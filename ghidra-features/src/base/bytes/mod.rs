//! BytesView feature -- raw memory byte viewer.
//!
//! Ported from Ghidra's `Features/ByteViewer` Java packages:
//! - `ghidra.app.plugin.core.byteviewer.ByteViewerPlugin`
//! - `ghidra.app.plugin.core.byteviewer.AbstractByteViewerPlugin`
//! - `ghidra.app.plugin.core.byteviewer.ProgramByteViewerComponentProvider`
//! - `ghidra.app.plugin.core.byteviewer.ByteViewerComponentProvider`
//!
//! This module provides the BytesView plugin and its component provider
//! for displaying raw memory bytes in various formats (hex, octal, decimal,
//! binary, character) with support for byte editing, navigation, selection,
//! highlight, and clipboard operations.
//!
//! # Modules
//!
//! - [`bytes_plugin`] -- The main plugin struct managing provider lifecycle
//!   and program events
//! - [`bytes_provider`] -- The component provider managing display state,
//!   byte blocks, navigation, and clipboard

pub mod bytes_plugin;
pub mod bytes_provider;

pub use bytes_plugin::{BytesViewPlugin, ConfigValue};
pub use bytes_provider::{
    BytesViewProvider, ClipboardEntry, DisplayFormat, ProviderByteBlock, SelectionRange,
};
