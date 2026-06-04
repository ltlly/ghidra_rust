//! Memory Map Management -- plugin logic for memory block operations.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.memory` Java package.
//!
//! Provides model-level logic for creating, splitting, merging, and modifying
//! memory blocks in a program's address space. GUI dialogs are omitted.
//!
//! # Architecture
//!
//! - [`MemoryBlockInfo`] -- metadata about a memory block.
//! - [`MemoryMapModel`] -- the business logic for memory map operations.
//! - [`MemoryBlockPermission`] -- permission flags for memory blocks.
//! - [`ImageBaseAction`] -- actions for changing the image base address.

use ghidra_core::Address;
use std::collections::BTreeMap;

// ============================================================================
// MemoryBlockPermission -- permission flags
// ============================================================================

/// Permission flags for memory blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryBlockPermission {
    /// The block is readable.
    pub read: bool,
    /// The block is writable.
    pub write: bool,
    /// The block is executable.
    pub execute: bool,
}

impl MemoryBlockPermission {
    /// Create new permission flags.
    pub fn new(read: bool, write: bool, execute: bool) -> Self {
        Self {
            read,
            write,
            execute,
        }
    }

    /// Read-only permission.
    pub fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            execute: false,
        }
    }

    /// Read + execute permission.
    pub fn read_execute() -> Self {
        Self {
            read: true,
            write: false,
            execute: true,
        }
    }

    /// Read + write permission.
    pub fn read_write() -> Self {
        Self {
            read: true,
            write: true,
            execute: false,
        }
    }

    /// Full permission (read + write + execute).
    pub fn all() -> Self {
        Self {
            read: true,
            write: true,
            execute: true,
        }
    }

    /// No permission.
    pub fn none() -> Self {
        Self {
            read: false,
            write: false,
            execute: false,
        }
    }
}

impl Default for MemoryBlockPermission {
    fn default() -> Self {
        Self::read_only()
    }
}

// ============================================================================
// MemoryBlockType -- the type of memory block
// ============================================================================

/// The type of a memory block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryBlockType {
    /// A block backed by actual bytes.
    Initialized,
    /// A block with no backing bytes (reads return 0).
    Uninitialized,
    /// A block mapped to another block.
    Mapped,
    /// A block overlaying another address range.
    Overlay,
}

// ============================================================================
// MemoryBlockInfo -- metadata about a memory block
// ============================================================================

/// Metadata about a memory block.
#[derive(Debug, Clone)]
pub struct MemoryBlockInfo {
    /// The block name (e.g. `".text"`, `".data"`, `"RAM"`).
    pub name: String,
    /// Start address.
    pub start: Address,
    /// End address (inclusive).
    pub end: Address,
    /// Block type.
    pub block_type: MemoryBlockType,
    /// Permission flags.
    pub permissions: MemoryBlockPermission,
    /// Whether this block is volatile.
    pub volatile: bool,
    /// Whether this block is an overlay block.
    pub overlay: bool,
    /// The source block name (for mapped blocks).
    pub source_name: Option<String>,
}

impl MemoryBlockInfo {
    /// Create a new memory block info.
    pub fn new(
        name: impl Into<String>,
        start: Address,
        end: Address,
        block_type: MemoryBlockType,
    ) -> Self {
        Self {
            name: name.into(),
            start,
            end,
            block_type,
            permissions: MemoryBlockPermission::default(),
            volatile: false,
            overlay: false,
            source_name: None,
        }
    }

    /// The size of this block in bytes.
    pub fn size(&self) -> u64 {
        self.end.offset.saturating_sub(self.start.offset) + 1
    }
}

// ============================================================================
// MemoryMapModel -- memory map operations
// ============================================================================

/// Business logic for memory map operations.
///
/// Provides methods for creating, deleting, splitting, and merging memory
/// blocks. This is the headless (non-GUI) model behind the Memory Map plugin.
#[derive(Debug)]
pub struct MemoryMapModel {
    /// All memory blocks, sorted by start address.
    blocks: BTreeMap<u64, MemoryBlockInfo>,
}

impl MemoryMapModel {
    /// Create a new empty memory map.
    pub fn new() -> Self {
        Self {
            blocks: BTreeMap::new(),
        }
    }

    /// Add a memory block.
    ///
    /// # Errors
    ///
    /// Returns an error if the block overlaps with an existing block.
    pub fn add_block(&mut self, block: MemoryBlockInfo) -> Result<(), String> {
        // Check for overlap
        for (_, existing) in &self.blocks {
            if Self::ranges_overlap(
                block.start.offset,
                block.end.offset,
                existing.start.offset,
                existing.end.offset,
            ) {
                return Err(format!(
                    "Block '{}' overlaps with existing block '{}'",
                    block.name, existing.name
                ));
            }
        }
        self.blocks.insert(block.start.offset, block);
        Ok(())
    }

    /// Remove a block by name.
    pub fn remove_block(&mut self, name: &str) -> Option<MemoryBlockInfo> {
        let key = self
            .blocks
            .iter()
            .find(|(_, b)| b.name == name)
            .map(|(k, _)| *k);
        key.and_then(|k| self.blocks.remove(&k))
    }

    /// Get a block by name.
    pub fn get_block(&self, name: &str) -> Option<&MemoryBlockInfo> {
        self.blocks.values().find(|b| b.name == name)
    }

    /// Get the block containing the given address.
    pub fn get_block_containing(&self, address: Address) -> Option<&MemoryBlockInfo> {
        let offset = address.offset;
        // Find the last block whose start <= offset
        self.blocks
            .range(..=offset)
            .next_back()
            .map(|(_, b)| b)
            .filter(|b| offset <= b.end.offset)
    }

    /// Get all blocks.
    pub fn get_all_blocks(&self) -> Vec<&MemoryBlockInfo> {
        self.blocks.values().collect()
    }

    /// Split a block at the given address.
    ///
    /// Creates two blocks: one from the original start to `split_addr - 1`,
    /// and another from `split_addr` to the original end.
    pub fn split_block(&mut self, name: &str, split_addr: Address) -> Result<(), String> {
        let key = self
            .blocks
            .iter()
            .find(|(_, b)| b.name == name)
            .map(|(k, _)| *k);

        let key = key.ok_or_else(|| format!("Block '{}' not found", name))?;
        let block = self.blocks.remove(&key).unwrap();

        if split_addr.offset <= block.start.offset
            || split_addr.offset > block.end.offset
        {
            self.blocks.insert(key, block);
            return Err("Split address must be within the block".into());
        }

        let block1 = MemoryBlockInfo {
            name: format!("{}_part1", block.name),
            start: block.start,
            end: Address::new(split_addr.offset - 1),
            block_type: block.block_type,
            permissions: block.permissions,
            volatile: block.volatile,
            overlay: block.overlay,
            source_name: block.source_name.clone(),
        };

        let block2 = MemoryBlockInfo {
            name: format!("{}_part2", block.name),
            start: split_addr,
            end: block.end,
            block_type: block.block_type,
            permissions: block.permissions,
            volatile: block.volatile,
            overlay: block.overlay,
            source_name: block.source_name,
        };

        self.blocks.insert(block1.start.offset, block1);
        self.blocks.insert(block2.start.offset, block2);
        Ok(())
    }

    /// Merge two adjacent blocks.
    ///
    /// The first block must end at `second.start - 1`.
    pub fn merge_blocks(&mut self, first_name: &str, second_name: &str) -> Result<(), String> {
        let first_key = self
            .blocks
            .iter()
            .find(|(_, b)| b.name == first_name)
            .map(|(k, _)| *k);
        let second_key = self
            .blocks
            .iter()
            .find(|(_, b)| b.name == second_name)
            .map(|(k, _)| *k);

        let first_key = first_key.ok_or_else(|| format!("Block '{}' not found", first_name))?;
        let second_key = second_key.ok_or_else(|| format!("Block '{}' not found", second_name))?;

        let first = self.blocks.remove(&first_key).unwrap();
        let second = self.blocks.remove(&second_key).unwrap();

        if first.end.offset + 1 != second.start.offset {
            // Restore blocks
            self.blocks.insert(first_key, first);
            self.blocks.insert(second_key, second);
            return Err("Blocks are not adjacent".into());
        }

        let merged = MemoryBlockInfo {
            name: first.name,
            start: first.start,
            end: second.end,
            block_type: first.block_type,
            permissions: first.permissions,
            volatile: first.volatile,
            overlay: first.overlay,
            source_name: first.source_name,
        };

        self.blocks.insert(merged.start.offset, merged);
        Ok(())
    }

    /// Set permissions on a block.
    pub fn set_permissions(
        &mut self,
        name: &str,
        permissions: MemoryBlockPermission,
    ) -> Result<(), String> {
        self.blocks
            .values_mut()
            .find(|b| b.name == name)
            .map(|b| {
                b.permissions = permissions;
            })
            .ok_or_else(|| format!("Block '{}' not found", name))
    }

    /// Change the block name.
    pub fn rename_block(&mut self, old_name: &str, new_name: &str) -> Result<(), String> {
        self.blocks
            .values_mut()
            .find(|b| b.name == old_name)
            .map(|b| {
                b.name = new_name.to_string();
            })
            .ok_or_else(|| format!("Block '{}' not found", old_name))
    }

    /// Return the number of blocks.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    fn ranges_overlap(s1: u64, e1: u64, s2: u64, e2: u64) -> bool {
        s1 <= e2 && s2 <= e1
    }
}

impl Default for MemoryMapModel {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_get_block() {
        let mut model = MemoryMapModel::new();
        let block = MemoryBlockInfo::new(
            ".text",
            Address::new(0x1000),
            Address::new(0x1FFF),
            MemoryBlockType::Initialized,
        );
        model.add_block(block).unwrap();
        assert_eq!(model.block_count(), 1);
        let b = model.get_block(".text").unwrap();
        assert_eq!(b.size(), 0x1000);
    }

    #[test]
    fn test_overlap_rejection() {
        let mut model = MemoryMapModel::new();
        model
            .add_block(MemoryBlockInfo::new(
                ".text",
                Address::new(0x1000),
                Address::new(0x2000),
                MemoryBlockType::Initialized,
            ))
            .unwrap();
        let result = model.add_block(MemoryBlockInfo::new(
            ".data",
            Address::new(0x1500),
            Address::new(0x2500),
            MemoryBlockType::Initialized,
        ));
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_block() {
        let mut model = MemoryMapModel::new();
        model
            .add_block(MemoryBlockInfo::new(
                ".text",
                Address::new(0x1000),
                Address::new(0x1FFF),
                MemoryBlockType::Initialized,
            ))
            .unwrap();
        assert!(model.remove_block(".text").is_some());
        assert_eq!(model.block_count(), 0);
    }

    #[test]
    fn test_split_block() {
        let mut model = MemoryMapModel::new();
        model
            .add_block(MemoryBlockInfo::new(
                ".text",
                Address::new(0x1000),
                Address::new(0x2000),
                MemoryBlockType::Initialized,
            ))
            .unwrap();
        model.split_block(".text", Address::new(0x1800)).unwrap();
        assert_eq!(model.block_count(), 2);
    }

    #[test]
    fn test_merge_blocks() {
        let mut model = MemoryMapModel::new();
        model
            .add_block(MemoryBlockInfo::new(
                "part1",
                Address::new(0x1000),
                Address::new(0x17FF),
                MemoryBlockType::Initialized,
            ))
            .unwrap();
        model
            .add_block(MemoryBlockInfo::new(
                "part2",
                Address::new(0x1800),
                Address::new(0x1FFF),
                MemoryBlockType::Initialized,
            ))
            .unwrap();
        model.merge_blocks("part1", "part2").unwrap();
        assert_eq!(model.block_count(), 1);
        let b = model.get_block("part1").unwrap();
        assert_eq!(b.start.offset, 0x1000);
        assert_eq!(b.end.offset, 0x1FFF);
    }

    #[test]
    fn test_get_block_containing() {
        let mut model = MemoryMapModel::new();
        model
            .add_block(MemoryBlockInfo::new(
                ".text",
                Address::new(0x1000),
                Address::new(0x1FFF),
                MemoryBlockType::Initialized,
            ))
            .unwrap();
        assert!(model.get_block_containing(Address::new(0x1500)).is_some());
        assert!(model.get_block_containing(Address::new(0x2000)).is_none());
    }

    #[test]
    fn test_set_permissions() {
        let mut model = MemoryMapModel::new();
        model
            .add_block(MemoryBlockInfo::new(
                ".text",
                Address::new(0x1000),
                Address::new(0x1FFF),
                MemoryBlockType::Initialized,
            ))
            .unwrap();
        model
            .set_permissions(".text", MemoryBlockPermission::all())
            .unwrap();
        let b = model.get_block(".text").unwrap();
        assert!(b.permissions.read);
        assert!(b.permissions.write);
        assert!(b.permissions.execute);
    }

    #[test]
    fn test_rename_block() {
        let mut model = MemoryMapModel::new();
        model
            .add_block(MemoryBlockInfo::new(
                ".text",
                Address::new(0x1000),
                Address::new(0x1FFF),
                MemoryBlockType::Initialized,
            ))
            .unwrap();
        model.rename_block(".text", ".code").unwrap();
        assert!(model.get_block(".text").is_none());
        assert!(model.get_block(".code").is_some());
    }

    #[test]
    fn test_non_adjacent_merge_rejected() {
        let mut model = MemoryMapModel::new();
        model
            .add_block(MemoryBlockInfo::new(
                "a",
                Address::new(0x1000),
                Address::new(0x1FFF),
                MemoryBlockType::Initialized,
            ))
            .unwrap();
        model
            .add_block(MemoryBlockInfo::new(
                "b",
                Address::new(0x3000),
                Address::new(0x3FFF),
                MemoryBlockType::Initialized,
            ))
            .unwrap();
        assert!(model.merge_blocks("a", "b").is_err());
    }
}
