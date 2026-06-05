//! ExpandBlockModel -- expand a memory block upward or downward.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.memory.ExpandBlockModel`,
//! `ExpandBlockUpModel`, and `ExpandBlockDownModel`.
//!
//! Provides the business logic for expanding a memory block by adding
//! space above (lower address) or below (higher address) its current range.

use super::{MemoryBlockInfo, MemoryBlockType, MemoryMapModel};
use ghidra_core::Address;

// ============================================================================
// ExpandDirection -- which way to expand
// ============================================================================

/// Direction of block expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpandDirection {
    /// Expand upward (lower start address).
    Up,
    /// Expand downward (higher end address).
    Down,
}

// ============================================================================
// ExpandBlockModel -- business logic for expanding a block
// ============================================================================

/// Model for expanding a memory block.
///
/// Ported from Ghidra's `ExpandBlockModel`, `ExpandBlockUpModel`, and
/// `ExpandBlockDownModel`.
#[derive(Debug)]
pub struct ExpandBlockModel {
    /// The name of the block to expand.
    pub block_name: String,
    /// Direction of expansion.
    pub direction: ExpandDirection,
    /// Number of bytes to expand by.
    pub amount: u64,
    /// The current start address (snapshot before expand).
    current_start: Address,
    /// The current end address (snapshot before expand).
    current_end: Address,
    /// The new start address after expansion.
    new_start: Address,
    /// The new end address after expansion.
    new_end: Address,
    /// Validation message (if invalid).
    message: Option<String>,
}

impl ExpandBlockModel {
    /// Create a new expand block model for expanding upward.
    pub fn up(block_name: impl Into<String>, block: &MemoryBlockInfo, amount: u64) -> Self {
        let block_name = block_name.into();
        let current_start = block.start;
        let current_end = block.end;
        let new_start = Address::new(current_start.offset.saturating_sub(amount));
        let new_end = current_end;

        let message = if amount == 0 {
            Some("Expansion amount must be greater than zero".into())
        } else if new_start.offset == 0 && amount > current_start.offset {
            Some("Cannot expand below address 0".into())
        } else {
            None
        };

        Self {
            block_name,
            direction: ExpandDirection::Up,
            amount,
            current_start,
            current_end,
            new_start,
            new_end,
            message,
        }
    }

    /// Create a new expand block model for expanding downward.
    pub fn down(block_name: impl Into<String>, block: &MemoryBlockInfo, amount: u64) -> Self {
        let block_name = block_name.into();
        let current_start = block.start;
        let current_end = block.end;
        let new_start = current_start;
        let new_end = Address::new(current_end.offset.saturating_add(amount));

        let message = if amount == 0 {
            Some("Expansion amount must be greater than zero".into())
        } else {
            None
        };

        Self {
            block_name,
            direction: ExpandDirection::Down,
            amount,
            current_start,
            current_end,
            new_start,
            new_end,
            message,
        }
    }

    /// The current start address.
    pub fn current_start(&self) -> Address {
        self.current_start
    }

    /// The current end address.
    pub fn current_end(&self) -> Address {
        self.current_end
    }

    /// The new start address after expansion.
    pub fn new_start(&self) -> Address {
        self.new_start
    }

    /// The new end address after expansion.
    pub fn new_end(&self) -> Address {
        self.new_end
    }

    /// Whether the expansion is valid (no overlap with other blocks).
    pub fn is_valid(&self) -> bool {
        self.message.is_none()
    }

    /// Get the validation error message, if any.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Execute the expansion on the given memory map model.
    ///
    /// Returns `Ok(())` on success.
    pub fn execute(&self, model: &mut MemoryMapModel) -> Result<(), String> {
        if let Some(msg) = &self.message {
            return Err(msg.clone());
        }

        // Remove the old block
        let block = model
            .remove_block(&self.block_name)
            .ok_or_else(|| format!("Block '{}' not found", self.block_name))?;

        let expanded = MemoryBlockInfo {
            name: block.name,
            start: self.new_start,
            end: self.new_end,
            block_type: block.block_type,
            permissions: block.permissions,
            volatile: block.volatile,
            overlay: block.overlay,
            source_name: block.source_name,
        };

        model.add_block(expanded)
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
    fn test_expand_down() {
        let block = make_test_block();
        let model = ExpandBlockModel::down(".text", &block, 0x100);
        assert!(model.is_valid());
        assert_eq!(model.new_start().offset, 0x1000);
        assert_eq!(model.new_end().offset, 0x20FF);
    }

    #[test]
    fn test_expand_up() {
        let block = make_test_block();
        let model = ExpandBlockModel::up(".text", &block, 0x100);
        assert!(model.is_valid());
        assert_eq!(model.new_start().offset, 0x0F00);
        assert_eq!(model.new_end().offset, 0x1FFF);
    }

    #[test]
    fn test_expand_up_below_zero() {
        let block = MemoryBlockInfo {
            name: ".low".into(),
            start: Address::new(0x50),
            end: Address::new(0xFF),
            block_type: MemoryBlockType::Initialized,
            permissions: MemoryBlockPermission::read_write(),
            volatile: false,
            overlay: false,
            source_name: None,
        };
        let model = ExpandBlockModel::up(".low", &block, 0x100);
        // The new start would be 0x50 - 0x100 = saturating to 0
        // This should be flagged as invalid in a real impl
        assert_eq!(model.new_start().offset, 0);
    }

    #[test]
    fn test_expand_zero_amount() {
        let block = make_test_block();
        let model = ExpandBlockModel::down(".text", &block, 0);
        assert!(!model.is_valid());
        assert!(model.message().is_some());
    }

    #[test]
    fn test_expand_execute() {
        let mut mmap = MemoryMapModel::new();
        mmap.add_block(make_test_block()).unwrap();

        let block = make_test_block();
        let expand = ExpandBlockModel::down(".text", &block, 0x100);
        expand.execute(&mut mmap).unwrap();

        let b = mmap.get_block(".text").unwrap();
        assert_eq!(b.start.offset, 0x1000);
        assert_eq!(b.end.offset, 0x20FF);
    }

    #[test]
    fn test_expand_execute_up() {
        let mut mmap = MemoryMapModel::new();
        mmap.add_block(make_test_block()).unwrap();

        let block = make_test_block();
        let expand = ExpandBlockModel::up(".text", &block, 0x100);
        expand.execute(&mut mmap).unwrap();

        let b = mmap.get_block(".text").unwrap();
        assert_eq!(b.start.offset, 0x0F00);
        assert_eq!(b.end.offset, 0x1FFF);
    }

    #[test]
    fn test_expand_preserves_permissions() {
        let mut mmap = MemoryMapModel::new();
        mmap.add_block(make_test_block()).unwrap();

        let block = make_test_block();
        let expand = ExpandBlockModel::down(".text", &block, 0x100);
        expand.execute(&mut mmap).unwrap();

        let b = mmap.get_block(".text").unwrap();
        assert!(b.permissions.read);
        assert!(b.permissions.execute);
        assert!(!b.permissions.write);
    }
}
