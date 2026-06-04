//! Memory map management subsystem.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.memory` Java package.
//!
//! This module provides:
//! - [`MemoryMapManager`] — orchestrates split, merge, delete, and rename operations on memory blocks
//! - [`AddBlockModel`] — validates parameters and creates new memory blocks (initialized, uninitialized, bit-mapped, byte-mapped)
//! - [`ExpandBlockModel`] — validates and expands a memory block to a larger address range
//! - [`MoveBlockModel`] — validates and moves a memory block to a new start address
//! - [`MemoryMapModel`] — table-model view of memory blocks for display and editing
//! - Commands: [`SplitBlockCmd`], [`MergeBlocksCmd`], [`UninitializedBlockCmd`]

mod add_block_model;
mod commands;
mod expand_block_model;
mod map_manager;
mod memory_map_model;
mod move_block_model;

pub use add_block_model::{AddBlockModel, InitializedType, ValidationError};
pub use commands::{MergeBlocksCmd, MemoryCommand, SplitBlockCmd, UninitializedBlockCmd};
pub use expand_block_model::ExpandBlockModel;
pub use map_manager::MemoryMapManager;
pub use memory_map_model::{MemoryColumn, MemoryMapModel};
pub use move_block_model::MoveBlockModel;
