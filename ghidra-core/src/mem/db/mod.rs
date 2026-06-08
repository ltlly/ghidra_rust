//! Database-backed memory implementation.
//!
//! This module implements the persistent memory subsystem from
//! `ghidra.program.database.mem`, including:
//!
//! * [`MemoryMapDB`] -- the database-backed memory map manager.
//! * [`MemoryBlockDB`] -- a single database-backed memory block.
//! * [`SubMemoryBlock`] -- trait and concrete sub-block implementations
//!   ([`UninitializedSubMemoryBlock`], [`BufferSubMemoryBlock`]).
//! * [`MemoryMapDBAdapter`] -- trait abstracting the database adapter layer.
//! * [`MemoryBlockSourceInfoDB`] -- DB-sourced block source information.
//! * [`AddressSourceInfo`] -- byte source provenance for a given address.

pub mod address_source_info;
pub mod memory_block_db;
pub mod memory_block_source_info_db;
pub mod memory_map_db;
pub mod memory_map_db_adapter;
pub mod sub_memory_block;

pub use address_source_info::AddressSourceInfo;
pub use memory_block_db::MemoryBlockDB;
pub use memory_block_source_info_db::MemoryBlockSourceInfoDB;
pub use memory_map_db::MemoryMapDB;
pub use memory_map_db_adapter::MemoryMapDBAdapter;
pub use sub_memory_block::{
    BufferSubMemoryBlock, SubMemoryBlock, SubMemoryBlockType, UninitializedSubMemoryBlock,
};
