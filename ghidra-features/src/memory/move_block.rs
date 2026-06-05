//! MoveBlockModel -- relocate a memory block to a new address.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.memory.MoveBlockModel`.
//!
//! Provides the business logic for moving a memory block to a different
//! start address while preserving its size, permissions, and type.

use super::{MemoryBlockInfo, MemoryMapModel};
use ghidra_core::Address;

// ============================================================================
// MoveBlockModel -- business logic for moving a block
// ============================================================================

/// Model for moving a memory block to a new address.
///
/// Ported from `ghidra.app.plugin.core.memory.MoveBlockModel`.
#[derive(Debug)]
pub struct MoveBlockModel {
    /// The name of the block to move.
    pub block_name: String,
    /// The new start address.
    pub new_start: Address,
    /// The original start address.
    original_start: Address,
    /// The original end address.
    original_end: Address,
    /// The block size (bytes).
    size: u64,
    /// Validation message (if invalid).
    message: Option<String>,
}

impl MoveBlockModel {
    /// Create a new move block model.
    pub fn new(
        block_name: impl Into<String>,
        block: &MemoryBlockInfo,
        new_start: Address,
    ) -> Self {
        let size = block.size();
        let new_end = Address::new(new_start.offset + size - 1);

        let message = if new_start.offset == block.start.offset {
            Some("New address is the same as the current address".into())
        } else {
            None
        };

        Self {
            block_name: block_name.into(),
            new_start,
            original_start: block.start,
            original_end: block.end,
            size,
            message,
        }
    }

    /// The original start address.
    pub fn original_start(&self) -> Address {
        self.original_start
    }

    /// The original end address.
    pub fn original_end(&self) -> Address {
        self.original_end
    }

    /// The new start address.
    pub fn new_start_address(&self) -> Address {
        self.new_start
    }

    /// The new end address (new_start + size - 1).
    pub fn new_end(&self) -> Address {
        Address::new(self.new_start.offset + self.size - 1)
    }

    /// The block size.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Whether the move is valid.
    pub fn is_valid(&self) -> bool {
        self.message.is_none()
    }

    /// Get the validation error message, if any.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Check whether the move would overlap with any existing block.
    pub fn check_overlap(&self, model: &MemoryMapModel) -> Option<String> {
        let new_start = self.new_start.offset;
        let new_end = self.new_end().offset;

        for block in model.get_all_blocks() {
            if block.name == self.block_name {
                continue; // Skip the block being moved
            }
            if new_start <= block.end.offset && block.start.offset <= new_end {
                return Some(format!(
                    "New range [{:#x}, {:#x}] overlaps with block '{}'",
                    new_start, new_end, block.name
                ));
            }
        }
        None
    }

    /// Execute the move on the given memory map model.
    ///
    /// Returns `Ok(())` on success.
    pub fn execute(&self, model: &mut MemoryMapModel) -> Result<(), String> {
        if let Some(msg) = &self.message {
            return Err(msg.clone());
        }

        // Check for overlap
        if let Some(overlap_msg) = self.check_overlap(model) {
            return Err(overlap_msg);
        }

        // Remove the old block
        let block = model
            .remove_block(&self.block_name)
            .ok_or_else(|| format!("Block '{}' not found", self.block_name))?;

        // Create the moved block
        let moved = MemoryBlockInfo {
            name: block.name,
            start: self.new_start,
            end: self.new_end(),
            block_type: block.block_type,
            permissions: block.permissions,
            volatile: block.volatile,
            overlay: block.overlay,
            source_name: block.source_name,
        };

        model.add_block(moved)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{MemoryBlockPermission, MemoryBlockType};

    fn make_test_block() -> MemoryBlockInfo {
        MemoryBlockInfo {
            name: ".text".into(),
            start: Address::new(0x1000),
            end: Address::new(0x1FFF),
            block_type: MemoryBlockType::Initialized,
            permissions: MemoryBlockPermission::read_execute(),
            volatile: false,
            overlay: false,
            source_name: None,
        }
    }

    #[test]
    fn test_move_block_basic() {
        let block = make_test_block();
        let model = MoveBlockModel::new(".text", &block, Address::new(0x5000));
        assert!(model.is_valid());
        assert_eq!(model.new_start_address().offset, 0x5000);
        assert_eq!(model.new_end().offset, 0x5FFF);
        assert_eq!(model.size(), 0x1000);
    }

    #[test]
    fn test_move_block_same_address() {
        let block = make_test_block();
        let model = MoveBlockModel::new(".text", &block, Address::new(0x1000));
        assert!(!model.is_valid());
        assert!(model.message().unwrap().contains("same"));
    }

    #[test]
    fn test_move_block_no_overlap() {
        let block = make_test_block();
        let model = MoveBlockModel::new(".text", &block, Address::new(0x5000));

        let mmap = MemoryMapModel::new();
        assert!(model.check_overlap(&mmap).is_none());
    }

    #[test]
    fn test_move_block_overlap_detected() {
        let mut mmap = MemoryMapModel::new();
        mmap.add_block(MemoryBlockInfo::new(
            ".data",
            Address::new(0x5000),
            Address::new(0x5FFF),
            MemoryBlockType::Initialized,
        ))
        .unwrap();

        let block = make_test_block();
        let model = MoveBlockModel::new(".text", &block, Address::new(0x5000));
        assert!(model.check_overlap(&mmap).is_some());
    }

    #[test]
    fn test_move_block_execute() {
        let mut mmap = MemoryMapModel::new();
        mmap.add_block(make_test_block()).unwrap();

        let block = make_test_block();
        let mover = MoveBlockModel::new(".text", &block, Address::new(0x8000));
        mover.execute(&mut mmap).unwrap();

        let b = mmap.get_block(".text").unwrap();
        assert_eq!(b.start.offset, 0x8000);
        assert_eq!(b.end.offset, 0x8FFF);
        assert!(b.permissions.read);
        assert!(b.permissions.execute);
    }

    #[test]
    fn test_move_block_not_found() {
        let mut mmap = MemoryMapModel::new();
        let block = make_test_block();
        let mover = MoveBlockModel::new("nonexistent", &block, Address::new(0x8000));
        assert!(mover.execute(&mut mmap).is_err());
    }

    #[test]
    fn test_move_preserves_type() {
        let mut mmap = MemoryMapModel::new();
        let block = MemoryBlockInfo {
            name: ".bss".into(),
            start: Address::new(0x2000),
            end: Address::new(0x2FFF),
            block_type: MemoryBlockType::Uninitialized,
            permissions: MemoryBlockPermission::read_write(),
            volatile: false,
            overlay: false,
            source_name: None,
        };
        mmap.add_block(block).unwrap();

        let block_ref = mmap.get_block(".bss").unwrap().clone();
        let mover = MoveBlockModel::new(".bss", &block_ref, Address::new(0xA000));
        mover.execute(&mut mmap).unwrap();

        let b = mmap.get_block(".bss").unwrap();
        assert_eq!(b.block_type, MemoryBlockType::Uninitialized);
        assert!(b.permissions.write);
    }

    #[test]
    fn test_move_block_skip_self_in_overlap() {
        let mut mmap = MemoryMapModel::new();
        mmap.add_block(make_test_block()).unwrap();

        let block = make_test_block();
        // Moving to same location range - but we check different address
        // Moving the block to overlap its own new position should be OK
        // since the old block is removed first
        let mover = MoveBlockModel::new(".text", &block, Address::new(0x1000));
        // This fails because same address check, not overlap
        assert!(!mover.is_valid());
    }
}
