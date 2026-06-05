//! Memory block implementations for trace program views.
//!
//! Ported from Ghidra's `AbstractDBTraceProgramViewMemoryBlock`,
//! `DBTraceProgramViewMemoryRegionBlock`, and
//! `DBTraceProgramViewMemorySpaceBlock` in `ghidra.trace.database.program`.
//!
//! These provide the Ghidra `MemoryBlock` interface for trace program views,
//! where blocks are derived from either memory regions (user-defined) or
//! address spaces (language-defined).

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;
use crate::model::memory_flag::{MemoryFlagSet, TraceMemoryFlag};

/// The type of a memory block in a trace program view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryBlockType {
    /// A block derived from a memory region (user-defined).
    Region,
    /// A block derived from an address space (language-defined).
    Space,
    /// An overlay block.
    Overlay,
    /// A block derived from an external library.
    External,
}

/// A memory block within a trace program view.
///
/// Ported from Ghidra's `AbstractDBTraceProgramViewMemoryBlock`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewMemoryBlock {
    /// The block name.
    pub name: String,
    /// The start address offset.
    pub start: u64,
    /// The end address offset.
    pub end: u64,
    /// The address space name.
    pub space_name: String,
    /// The block type.
    pub block_type: MemoryBlockType,
    /// Whether the block is readable.
    pub readable: bool,
    /// Whether the block is writable.
    pub writable: bool,
    /// Whether the block is executable.
    pub executable: bool,
    /// Whether the block is volatile.
    pub volatile: bool,
    /// The source key (region key or space ID).
    pub source_key: i64,
    /// The lifespan of this block (for region-based blocks).
    pub lifespan: Option<Lifespan>,
}

impl ProgramViewMemoryBlock {
    /// Create a new memory block.
    pub fn new(
        name: impl Into<String>,
        start: u64,
        end: u64,
        space_name: impl Into<String>,
        block_type: MemoryBlockType,
    ) -> Self {
        Self {
            name: name.into(),
            start,
            end,
            space_name: space_name.into(),
            block_type,
            readable: true,
            writable: false,
            executable: false,
            volatile: false,
            source_key: 0,
            lifespan: None,
        }
    }

    /// Create a region-based block.
    pub fn from_region(
        name: impl Into<String>,
        start: u64,
        end: u64,
        space_name: impl Into<String>,
        flags: MemoryFlagSet,
        lifespan: Lifespan,
        source_key: i64,
    ) -> Self {
        Self {
            name: name.into(),
            start,
            end,
            space_name: space_name.into(),
            block_type: MemoryBlockType::Region,
            readable: flags.has(TraceMemoryFlag::Read),
            writable: flags.has(TraceMemoryFlag::Write),
            executable: flags.has(TraceMemoryFlag::Execute),
            volatile: flags.has(TraceMemoryFlag::Volatile),
            source_key,
            lifespan: Some(lifespan),
        }
    }

    /// Create a space-based block.
    pub fn from_space(
        name: impl Into<String>,
        start: u64,
        end: u64,
        space_name: impl Into<String>,
        space_id: u32,
    ) -> Self {
        Self {
            name: name.into(),
            start,
            end,
            space_name: space_name.into(),
            block_type: MemoryBlockType::Space,
            readable: true,
            writable: true,
            executable: true,
            volatile: false,
            source_key: space_id as i64,
            lifespan: None,
        }
    }

    /// Get the size of this block.
    pub fn size(&self) -> u64 {
        if self.end >= self.start {
            self.end - self.start + 1
        } else {
            0
        }
    }

    /// Check if this block contains the given address offset.
    pub fn contains(&self, offset: u64) -> bool {
        offset >= self.start && offset <= self.end
    }

    /// Check if this block is valid at the given snap.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        match &self.lifespan {
            Some(ls) => ls.contains(snap),
            None => true, // Space-based blocks are always valid
        }
    }

    /// Get the permissions as a flag set.
    pub fn permissions(&self) -> MemoryFlagSet {
        let mut flags = MemoryFlagSet::new();
        if self.readable {
            flags.add(TraceMemoryFlag::Read);
        }
        if self.writable {
            flags.add(TraceMemoryFlag::Write);
        }
        if self.executable {
            flags.add(TraceMemoryFlag::Execute);
        }
        if self.volatile {
            flags.add(TraceMemoryFlag::Volatile);
        }
        flags
    }
}

/// Manager for program view memory blocks.
///
/// Maintains the set of memory blocks visible at a given snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramViewMemoryBlockManager {
    /// All blocks in this view.
    blocks: Vec<ProgramViewMemoryBlock>,
    /// The snap this view is for.
    snap: i64,
}

impl ProgramViewMemoryBlockManager {
    /// Create a new block manager for the given snap.
    pub fn new(snap: i64) -> Self {
        Self {
            blocks: Vec::new(),
            snap,
        }
    }

    /// Add a block.
    pub fn add_block(&mut self, block: ProgramViewMemoryBlock) {
        self.blocks.push(block);
    }

    /// Get all blocks valid at this view's snap.
    pub fn blocks(&self) -> Vec<&ProgramViewMemoryBlock> {
        self.blocks
            .iter()
            .filter(|b| b.is_valid_at(self.snap))
            .collect()
    }

    /// Get all blocks (including those not valid at this snap).
    pub fn all_blocks(&self) -> &[ProgramViewMemoryBlock] {
        &self.blocks
    }

    /// Find the block containing the given address.
    pub fn block_containing(&self, offset: u64) -> Option<&ProgramViewMemoryBlock> {
        self.blocks()
            .into_iter()
            .find(|b| b.contains(offset))
    }

    /// Get the number of valid blocks.
    pub fn block_count(&self) -> usize {
        self.blocks().len()
    }

    /// Check if the given address is in an executable block.
    pub fn is_executable(&self, offset: u64) -> bool {
        self.block_containing(offset)
            .map(|b| b.executable)
            .unwrap_or(false)
    }

    /// Get the total size of all valid blocks.
    pub fn total_size(&self) -> u64 {
        self.blocks().iter().map(|b| b.size()).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_block_new() {
        let block = ProgramViewMemoryBlock::new("test", 0x1000, 0x1FFF, "ram", MemoryBlockType::Region);
        assert_eq!(block.name, "test");
        assert_eq!(block.size(), 0x1000);
        assert!(block.contains(0x1500));
        assert!(!block.contains(0x2000));
    }

    #[test]
    fn test_memory_block_from_region() {
        let mut flags = MemoryFlagSet::new();
        flags.add(TraceMemoryFlag::Read);
        flags.add(TraceMemoryFlag::Write);
        flags.add(TraceMemoryFlag::Execute);
        let lifespan = Lifespan::span(0, 10);
        let block = ProgramViewMemoryBlock::from_region("code", 0x100, 0x1FF, "ram", flags, lifespan, 42);
        assert!(block.readable);
        assert!(block.writable);
        assert!(block.executable);
        assert!(!block.volatile);
        assert_eq!(block.source_key, 42);
    }

    #[test]
    fn test_memory_block_from_space() {
        let block = ProgramViewMemoryBlock::from_space("ram", 0, 0xFFFF_FFFF, "ram", 1);
        assert!(block.readable);
        assert!(block.writable);
        assert!(block.executable);
        assert_eq!(block.block_type, MemoryBlockType::Space);
    }

    #[test]
    fn test_memory_block_is_valid_at() {
        let lifespan = Lifespan::span(5, 10);
        let mut flags = MemoryFlagSet::new();
        flags.add(TraceMemoryFlag::Read);
        let block = ProgramViewMemoryBlock::from_region("r", 0, 0xFF, "ram", flags, lifespan, 1);
        assert!(!block.is_valid_at(4));
        assert!(block.is_valid_at(5));
        assert!(block.is_valid_at(10));
        assert!(!block.is_valid_at(11));
    }

    #[test]
    fn test_memory_block_space_always_valid() {
        let block = ProgramViewMemoryBlock::from_space("ram", 0, 0xFFFF, "ram", 1);
        assert!(block.is_valid_at(0));
        assert!(block.is_valid_at(i64::MAX));
    }

    #[test]
    fn test_memory_block_permissions() {
        let mut block = ProgramViewMemoryBlock::new("test", 0, 0xFF, "ram", MemoryBlockType::Region);
        block.readable = true;
        block.executable = true;
        let perms = block.permissions();
        assert!(perms.has(TraceMemoryFlag::Read));
        assert!(!perms.has(TraceMemoryFlag::Write));
        assert!(perms.has(TraceMemoryFlag::Execute));
    }

    #[test]
    fn test_block_manager_add_and_query() {
        let mut mgr = ProgramViewMemoryBlockManager::new(5);
        let lifespan = Lifespan::span(0, 10);
        let mut flags = MemoryFlagSet::new();
        flags.add(TraceMemoryFlag::Read);
        flags.add(TraceMemoryFlag::Execute);
        mgr.add_block(ProgramViewMemoryBlock::from_region("code", 0x100, 0x1FF, "ram", flags, lifespan, 1));
        mgr.add_block(ProgramViewMemoryBlock::from_space("sp", 0, 0xFFFF, "register", 2));

        assert_eq!(mgr.block_count(), 2);
        assert!(mgr.block_containing(0x150).is_some());
        assert!(mgr.is_executable(0x150));
    }

    #[test]
    fn test_block_manager_invalid_at_snap() {
        let mut mgr = ProgramViewMemoryBlockManager::new(20);
        let lifespan = Lifespan::span(0, 10);
        let mut flags = MemoryFlagSet::new();
        flags.add(TraceMemoryFlag::Read);
        mgr.add_block(ProgramViewMemoryBlock::from_region("old", 0, 0xFF, "ram", flags, lifespan, 1));
        assert_eq!(mgr.block_count(), 0);
    }

    #[test]
    fn test_block_manager_total_size() {
        let mut mgr = ProgramViewMemoryBlockManager::new(0);
        mgr.add_block(ProgramViewMemoryBlock::new("a", 0, 0xFF, "ram", MemoryBlockType::Region));
        mgr.add_block(ProgramViewMemoryBlock::new("b", 0x100, 0x1FF, "ram", MemoryBlockType::Region));
        assert_eq!(mgr.total_size(), 0x200);
    }
}
