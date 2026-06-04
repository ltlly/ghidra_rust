//! Ghidra Rust - Build support crate.
//!
//! Port of Ghidra's `GhidraBuild` Java source to Rust.
//!
//! This crate provides:
//!
//! - **`launch`** -- Launch infrastructure: Java version parsing, platform-specific
//!   Java installation discovery, launch properties file parsing, and application
//!   configuration management.
//!
//! - **`markdown`** -- Markdown-to-HTML conversion with support for heading anchors,
//!   tables, code blocks, and link fixups.
//!
//! - **`skeleton`** -- Template types modeling Ghidra extension points (Plugin,
//!   Analyzer, Loader, Exporter, FileSystem) for building extensions.
//!
//! - **`doclets`** -- Documentation generation tools: JSON class documentation,
//!   Python type stub (.pyi) generation, and RST table building.
//!
//! Note: The Eclipse plugin source (`GhidraDev`, `GhidraSleighEditor`) and
//! the IDAPro Python scripts are not ported, as they are platform-specific
//! (Eclipse RCP / IDA Python) and not applicable to Rust.

pub mod doclets;
pub mod launch;
pub mod markdown;
pub mod skeleton;
