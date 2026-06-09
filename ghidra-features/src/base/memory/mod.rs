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
//! - [`SplitBlockModel`] — validation model for the split-block dialog
//! - [`SetBaseCmd`] — command to change the program's image base address
//! - [`MemoryMapPlugin`] — orchestrates the memory map subsystem (plugin lifecycle)
//! - [`MemoryMapProvider`] — view-state management for the memory map panel
//! - [`MemoryMapComponentProvider`] — component provider bridging plugin and models
//! - Commands: [`SplitBlockCmd`], [`MergeBlocksCmd`], [`UninitializedBlockCmd`]

mod add_block_model;
mod commands;
mod expand_block_model;
mod map_manager;
mod memory_map_model;
mod memory_map_plugin;
mod memory_map_provider;
mod memory_plugin;
mod memory_provider;
mod move_block_model;
mod set_base_cmd;
mod split_block_model;

// Re-export from sub-modules that do not have their own `pub use` yet.
mod expand_down_model;
mod expand_up_model;
mod image_base;
mod uninitialized_block;

pub use add_block_model::{AddBlockModel, InitializedType, ValidationError};
pub use commands::{MergeBlocksCmd, MemoryCommand, SplitBlockCmd, UninitializedBlockCmd};
pub use expand_block_model::{ExpandBlockModel, ExpandDirection};
pub use map_manager::MemoryMapManager;
pub use memory_map_model::{MemoryColumn, MemoryMapModel};
pub use memory_map_plugin::{
    ActionDescriptor, GoToService, MemoryMapPlugin, MemoryMapPluginConfig, PluginState,
};
pub use memory_map_provider::{BlockOperation, MemoryMapComponentProvider, OperationResult};
pub use memory_plugin::{MemoryEvent, MemoryMapPlugin as MemoryMapPluginLegacy};
pub use move_block_model::MoveBlockModel;
pub use set_base_cmd::{validate_image_base_change, SetBaseCmd};
pub use split_block_model::{SplitBlockModel, SplitResult, SplitValidationError};
