//! Bytes Plugin -- displays raw memory bytes in various formats.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.byteviewer` and
//! `ghidra.app.plugin.core.format` packages.
//!
//! This module provides the bytes plugin that displays raw memory bytes
//! in various formats (hex, octal, decimal, binary, character).
//!
//! # Modules
//!
//! - [`bytes_plugin`] -- The main plugin struct and lifecycle

pub mod bytes_plugin;

pub use bytes_plugin::{ByteBlock, BytesOption, BytesPlugin, DisplayFormat};
