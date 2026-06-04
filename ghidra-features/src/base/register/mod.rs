//! Register management subsystem.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.register` Java package.
//!
//! This module provides:
//! - [`RegisterManager`] — manages register value display, selection, and modification
//! - [`RegisterValueRange`] — represents a range of addresses with a specific register value
//! - [`RegisterTree`] — hierarchical tree of registers organized by group
//! - [`SetRegisterValueCmd`] — command to set or clear register values over an address range

mod commands;
mod manager;
mod tree;
mod value_range;

pub use commands::{RegisterCommand, SetRegisterValueCmd};
pub use manager::RegisterManager;
pub use tree::{RegisterGroupNode, RegisterNode, RegisterTree};
pub use value_range::RegisterValueRange;
