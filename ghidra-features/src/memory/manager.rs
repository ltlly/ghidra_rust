//! Memory map manager, block models, and plugin logic.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.memory` Java package:
//! `MemoryMapManager`, `MemoryMapPlugin`, `MemoryMapProvider`,
//! `AddBlockModel`, `AddBlockDialog`, `ExpandBlockModel`,
//! `ExpandBlockUpModel`, `ExpandBlockDownModel`, `MoveBlockModel`,
//! `SplitBlockDialog`, `ImageBaseDialog`, `UninitializedBlockCmd`.

use super::{MemoryBlockInfo, MemoryBlockPermission, MemoryBlockType, MemoryMapModel};
use ghidra_core::Address;

// ============================================================================
// Block operation result
// ============================================================================

/// Result of a memory block operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockOperationResult {
    /// Operation succeeded.
    Success(String),
    /// Operation was cancelled.
    Cancelled,
    /// Operation failed.
    Failed(String),
}

// ============================================================================
// AddBlockModel -- model for adding a new block
// ============================================================================

/// Model for adding a new memory block.
///
/// Ported from `ghidra.app.plugin.core.memory.AddBlockModel`.
#[derive(Debug)]
pub struct AddBlockModel {
    /// Name of the new block.
    pub name: String,
    /// Start address.
    pub start_address: u64,
    /// Length in bytes.
    pub length: u64,
    /// Block type.
    pub block_type: MemoryBlockType,
    /// Permissions.
    pub permissions: MemoryBlockPermission,
    /// Whether the block is volatile.
    pub volatile: bool,
    /// Whether the block is an overlay.
    pub overlay: bool,
    /// Source block name (for mapped blocks).
    pub source_name: Option<String>,
    /// Source start address (for mapped blocks).
    pub source_start: Option<u64>,
}

impl AddBlockModel {
    /// Create a new add-block model with defaults.
    pub fn new() -> Self {
        Self {
            name: String::new(),
            start_address: 0,
            length: 0x1000,
            block_type: MemoryBlockType::Initialized,
            permissions: MemoryBlockPermission::read_execute(),
            volatile: false,
            overlay: false,
            source_name: None,
            source_start: None,
        }
    }

    /// Validate the model parameters.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Block name must not be empty".into());
        }
        if self.length == 0 {
            return Err("Block length must be greater than zero".into());
        }
        // Check for overflow
        if self.start_address.checked_add(self.length - 1).is_none() {
            return Err("Block address range overflows".into());
        }
        if self.block_type == MemoryBlockType::Mapped && self.source_name.is_none() {
            return Err("Mapped blocks require a source block".into());
        }
        Ok(())
    }

    /// Build a MemoryBlockInfo from this model.
    pub fn build(&self) -> Result<MemoryBlockInfo, String> {
        self.validate()?;
        Ok(MemoryBlockInfo {
            name: self.name.clone(),
            start: Address::new(self.start_address),
            end: Address::new(self.start_address + self.length - 1),
            block_type: self.block_type,
            permissions: self.permissions,
            volatile: self.volatile,
            overlay: self.overlay,
            source_name: self.source_name.clone(),
        })
    }

    /// Execute: add the block to the model.
    pub fn execute(&self, map_model: &mut MemoryMapModel) -> BlockOperationResult {
        match self.build() {
            Ok(block) => match map_model.add_block(block) {
                Ok(()) => BlockOperationResult::Success(format!(
                    "Block '{}' added successfully",
                    self.name
                )),
                Err(e) => BlockOperationResult::Failed(e),
            },
            Err(e) => BlockOperationResult::Failed(e),
        }
    }
}

impl Default for AddBlockModel {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ExpandBlockModel -- model for expanding a block
// ============================================================================

/// Direction of block expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpandDirection {
    /// Expand the block upward (lower addresses).
    Up,
    /// Expand the block downward (higher addresses).
    Down,
}

/// Model for expanding a memory block.
///
/// Ported from `ghidra.app.plugin.core.memory.ExpandBlockModel` and
/// `ExpandBlockUpModel`/`ExpandBlockDownModel`.
#[derive(Debug)]
pub struct ExpandBlockModel {
    /// The block name to expand.
    pub block_name: String,
    /// The direction of expansion.
    pub direction: ExpandDirection,
    /// The new size in bytes.
    pub new_size: u64,
}

impl ExpandBlockModel {
    /// Create a new expand-block model.
    pub fn new(
        block_name: impl Into<String>,
        direction: ExpandDirection,
        new_size: u64,
    ) -> Self {
        Self {
            block_name: block_name.into(),
            direction,
            new_size,
        }
    }

    /// Execute the expansion.
    pub fn execute(&self, map_model: &mut MemoryMapModel) -> BlockOperationResult {
        let block = match map_model.get_block(&self.block_name) {
            Some(b) => b.clone(),
            None => {
                return BlockOperationResult::Failed(format!(
                    "Block '{}' not found",
                    self.block_name
                ))
            }
        };

        if self.new_size <= block.size() {
            return BlockOperationResult::Failed(
                "New size must be larger than current size".into(),
            );
        }

        let diff = self.new_size - block.size();
        let (new_start, new_end) = match self.direction {
            ExpandDirection::Up => {
                let new_start = block.start.offset.saturating_sub(diff);
                (new_start, block.end.offset)
            }
            ExpandDirection::Down => {
                let new_end = block.end.offset.saturating_add(diff);
                (block.start.offset, new_end)
            }
        };

        // Remove old block and add expanded one
        map_model.remove_block(&self.block_name);
        let expanded = MemoryBlockInfo {
            name: block.name.clone(),
            start: Address::new(new_start),
            end: Address::new(new_end),
            block_type: block.block_type,
            permissions: block.permissions,
            volatile: block.volatile,
            overlay: block.overlay,
            source_name: block.source_name,
        };
        match map_model.add_block(expanded) {
            Ok(()) => BlockOperationResult::Success(format!(
                "Block '{}' expanded to {} bytes",
                self.block_name, self.new_size
            )),
            Err(e) => BlockOperationResult::Failed(e),
        }
    }
}

// ============================================================================
// MoveBlockModel -- model for moving a block
// ============================================================================

/// Model for moving a memory block.
///
/// Ported from `ghidra.app.plugin.core.memory.MoveBlockModel`.
#[derive(Debug)]
pub struct MoveBlockModel {
    /// The block name to move.
    pub block_name: String,
    /// The new start address.
    pub new_start: u64,
}

impl MoveBlockModel {
    /// Create a new move-block model.
    pub fn new(block_name: impl Into<String>, new_start: u64) -> Self {
        Self {
            block_name: block_name.into(),
            new_start,
        }
    }

    /// Execute the move.
    pub fn execute(&self, map_model: &mut MemoryMapModel) -> BlockOperationResult {
        let block = match map_model.get_block(&self.block_name) {
            Some(b) => b.clone(),
            None => {
                return BlockOperationResult::Failed(format!(
                    "Block '{}' not found",
                    self.block_name
                ))
            }
        };

        let size = block.size();
        let new_end = self.new_start + size - 1;

        map_model.remove_block(&self.block_name);
        let moved = MemoryBlockInfo {
            name: block.name.clone(),
            start: Address::new(self.new_start),
            end: Address::new(new_end),
            block_type: block.block_type,
            permissions: block.permissions,
            volatile: block.volatile,
            overlay: block.overlay,
            source_name: block.source_name,
        };
        match map_model.add_block(moved) {
            Ok(()) => BlockOperationResult::Success(format!(
                "Block '{}' moved to 0x{:x}",
                self.block_name, self.new_start
            )),
            Err(e) => BlockOperationResult::Failed(e),
        }
    }
}

// ============================================================================
// UninitializedBlockCmd -- command to create an uninitialized block
// ============================================================================

/// Command to create an uninitialized memory block.
///
/// Ported from `ghidra.app.plugin.core.memory.UninitializedBlockCmd`.
#[derive(Debug)]
pub struct UninitializedBlockCmd {
    /// The block name.
    pub name: String,
    /// Start address.
    pub start: u64,
    /// Size in bytes.
    pub size: u64,
}

impl UninitializedBlockCmd {
    /// Create a new uninitialized block command.
    pub fn new(name: impl Into<String>, start: u64, size: u64) -> Self {
        Self {
            name: name.into(),
            start,
            size,
        }
    }

    /// Execute the command.
    pub fn execute(&self, map_model: &mut MemoryMapModel) -> BlockOperationResult {
        let model = AddBlockModel {
            name: self.name.clone(),
            start_address: self.start,
            length: self.size,
            block_type: MemoryBlockType::Uninitialized,
            permissions: MemoryBlockPermission::read_write(),
            volatile: false,
            overlay: false,
            source_name: None,
            source_start: None,
        };
        model.execute(map_model)
    }
}

// ============================================================================
// ImageBaseDialog -- model for changing the image base
// ============================================================================

/// Model for the "Set Image Base" operation.
///
/// Ported from `ghidra.app.plugin.core.memory.ImageBaseDialog`.
#[derive(Debug)]
pub struct ImageBaseAction {
    /// The new image base address.
    pub new_base: u64,
    /// Whether to move all blocks to reflect the new base.
    pub move_blocks: bool,
}

impl ImageBaseAction {
    /// Create a new image base action.
    pub fn new(new_base: u64, move_blocks: bool) -> Self {
        Self {
            new_base,
            move_blocks,
        }
    }

    /// Execute the image base change.
    pub fn execute(&self, current_base: u64, map_model: &mut MemoryMapModel) -> BlockOperationResult {
        if !self.move_blocks {
            return BlockOperationResult::Success(format!(
                "Image base set to 0x{:x} (blocks not moved)",
                self.new_base
            ));
        }

        let delta = (self.new_base as i64) - (current_base as i64);
        let blocks: Vec<(String, u64, u64, MemoryBlockType, MemoryBlockPermission, bool, bool, Option<String>)> =
            map_model
                .get_all_blocks()
                .iter()
                .map(|b| {
                    (
                        b.name.clone(),
                        b.start.offset,
                        b.end.offset,
                        b.block_type,
                        b.permissions,
                        b.volatile,
                        b.overlay,
                        b.source_name.clone(),
                    )
                })
                .collect();

        for (name, _start, _end, _bt, _perm, _vol, _ovl, _src) in &blocks {
            map_model.remove_block(name);
        }

        for (name, start, end, bt, perm, vol, ovl, src) in &blocks {
            let new_start = (*start as i64 + delta) as u64;
            let new_end = (*end as i64 + delta) as u64;
            let moved = MemoryBlockInfo {
                name: name.clone(),
                start: Address::new(new_start),
                end: Address::new(new_end),
                block_type: *bt,
                permissions: *perm,
                volatile: *vol,
                overlay: *ovl,
                source_name: src.clone(),
            };
            if let Err(e) = map_model.add_block(moved) {
                return BlockOperationResult::Failed(e);
            }
        }

        BlockOperationResult::Success(format!(
            "Image base changed from 0x{:x} to 0x{:x}",
            current_base, self.new_base
        ))
    }
}

// ============================================================================
// MemoryMapManager -- orchestrates memory map operations
// ============================================================================

/// The memory map manager coordinates block operations and manages the provider.
///
/// Ported from `ghidra.app.plugin.core.memory.MemoryMapManager`.
#[derive(Debug)]
pub struct MemoryMapManager {
    /// The underlying memory map model.
    pub map_model: MemoryMapModel,
    /// Whether the provider is visible.
    pub provider_visible: bool,
    /// The current image base.
    pub image_base: u64,
    /// Error messages from the last operation.
    last_error: Option<String>,
}

impl MemoryMapManager {
    /// Create a new memory map manager.
    pub fn new() -> Self {
        Self {
            map_model: MemoryMapModel::new(),
            provider_visible: false,
            image_base: 0,
            last_error: None,
        }
    }

    /// Add a block using the AddBlockModel.
    pub fn add_block(&mut self, model: &AddBlockModel) -> BlockOperationResult {
        let result = model.execute(&mut self.map_model);
        if let BlockOperationResult::Failed(ref e) = result {
            self.last_error = Some(e.clone());
        } else {
            self.last_error = None;
        }
        result
    }

    /// Split a block.
    pub fn split_block(&mut self, name: &str, split_addr: Address) -> BlockOperationResult {
        match self.map_model.split_block(name, split_addr) {
            Ok(()) => BlockOperationResult::Success(format!("Block '{}' split", name)),
            Err(e) => {
                self.last_error = Some(e.clone());
                BlockOperationResult::Failed(e)
            }
        }
    }

    /// Merge two adjacent blocks.
    pub fn merge_blocks(&mut self, first: &str, second: &str) -> BlockOperationResult {
        match self.map_model.merge_blocks(first, second) {
            Ok(()) => BlockOperationResult::Success(format!(
                "Blocks '{}' and '{}' merged",
                first, second
            )),
            Err(e) => {
                self.last_error = Some(e.clone());
                BlockOperationResult::Failed(e)
            }
        }
    }

    /// Delete a block.
    pub fn delete_block(&mut self, name: &str) -> BlockOperationResult {
        match self.map_model.remove_block(name) {
            Some(_) => BlockOperationResult::Success(format!("Block '{}' deleted", name)),
            None => {
                let msg = format!("Block '{}' not found", name);
                self.last_error = Some(msg.clone());
                BlockOperationResult::Failed(msg)
            }
        }
    }

    /// Set permissions on a block.
    pub fn set_permissions(
        &mut self,
        name: &str,
        permissions: MemoryBlockPermission,
    ) -> BlockOperationResult {
        match self.map_model.set_permissions(name, permissions) {
            Ok(()) => BlockOperationResult::Success(format!(
                "Permissions updated for '{}'",
                name
            )),
            Err(e) => {
                self.last_error = Some(e.clone());
                BlockOperationResult::Failed(e)
            }
        }
    }

    /// Change the image base address.
    pub fn set_image_base(&mut self, new_base: u64) -> BlockOperationResult {
        let action = ImageBaseAction::new(new_base, true);
        let result = action.execute(self.image_base, &mut self.map_model);
        if matches!(result, BlockOperationResult::Success(_)) {
            self.image_base = new_base;
        }
        result
    }

    /// Get the last error message.
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Get all block names.
    pub fn block_names(&self) -> Vec<String> {
        self.map_model
            .get_all_blocks()
            .iter()
            .map(|b| b.name.clone())
            .collect()
    }

    /// Total number of blocks.
    pub fn block_count(&self) -> usize {
        self.map_model.block_count()
    }
}

impl Default for MemoryMapManager {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_block_model_validate() {
        let model = AddBlockModel::new();
        assert!(model.validate().is_err()); // empty name

        let mut model = AddBlockModel::new();
        model.name = ".text".into();
        model.length = 0;
        assert!(model.validate().is_err()); // zero length

        model.length = 0x1000;
        assert!(model.validate().is_ok());
    }

    #[test]
    fn test_add_block_model_build() {
        let model = AddBlockModel {
            name: ".text".into(),
            start_address: 0x1000,
            length: 0x1000,
            block_type: MemoryBlockType::Initialized,
            permissions: MemoryBlockPermission::read_execute(),
            volatile: false,
            overlay: false,
            source_name: None,
            source_start: None,
        };
        let block = model.build().unwrap();
        assert_eq!(block.name, ".text");
        assert_eq!(block.start.offset, 0x1000);
        assert_eq!(block.end.offset, 0x1FFF);
        assert_eq!(block.size(), 0x1000);
    }

    #[test]
    fn test_add_block_model_execute() {
        let mut map_model = MemoryMapModel::new();
        let model = AddBlockModel {
            name: ".text".into(),
            start_address: 0x1000,
            length: 0x1000,
            block_type: MemoryBlockType::Initialized,
            permissions: MemoryBlockPermission::read_execute(),
            volatile: false,
            overlay: false,
            source_name: None,
            source_start: None,
        };
        let result = model.execute(&mut map_model);
        assert!(matches!(result, BlockOperationResult::Success(_)));
        assert_eq!(map_model.block_count(), 1);
    }

    #[test]
    fn test_add_block_model_overlap() {
        let mut map_model = MemoryMapModel::new();
        let model1 = AddBlockModel {
            name: ".text".into(),
            start_address: 0x1000,
            length: 0x2000,
            ..AddBlockModel::default()
        };
        model1.execute(&mut map_model);

        let model2 = AddBlockModel {
            name: ".data".into(),
            start_address: 0x1500,
            length: 0x1000,
            ..AddBlockModel::default()
        };
        let result = model2.execute(&mut map_model);
        assert!(matches!(result, BlockOperationResult::Failed(_)));
    }

    #[test]
    fn test_expand_block_model_up() {
        let mut map_model = MemoryMapModel::new();
        map_model
            .add_block(MemoryBlockInfo::new(
                ".text",
                Address::new(0x2000),
                Address::new(0x2FFF),
                MemoryBlockType::Initialized,
            ))
            .unwrap();

        let model = ExpandBlockModel::new(".text", ExpandDirection::Up, 0x2000);
        let result = model.execute(&mut map_model);
        assert!(matches!(result, BlockOperationResult::Success(_)));

        let block = map_model.get_block(".text").unwrap();
        assert_eq!(block.start.offset, 0x1000);
        assert_eq!(block.size(), 0x2000);
    }

    #[test]
    fn test_expand_block_model_down() {
        let mut map_model = MemoryMapModel::new();
        map_model
            .add_block(MemoryBlockInfo::new(
                ".text",
                Address::new(0x1000),
                Address::new(0x1FFF),
                MemoryBlockType::Initialized,
            ))
            .unwrap();

        let model = ExpandBlockModel::new(".text", ExpandDirection::Down, 0x2000);
        let result = model.execute(&mut map_model);
        assert!(matches!(result, BlockOperationResult::Success(_)));

        let block = map_model.get_block(".text").unwrap();
        assert_eq!(block.end.offset, 0x2FFF);
    }

    #[test]
    fn test_expand_block_not_found() {
        let mut map_model = MemoryMapModel::new();
        let model = ExpandBlockModel::new(".missing", ExpandDirection::Up, 0x1000);
        let result = model.execute(&mut map_model);
        assert!(matches!(result, BlockOperationResult::Failed(_)));
    }

    #[test]
    fn test_move_block_model() {
        let mut map_model = MemoryMapModel::new();
        map_model
            .add_block(MemoryBlockInfo::new(
                ".text",
                Address::new(0x1000),
                Address::new(0x1FFF),
                MemoryBlockType::Initialized,
            ))
            .unwrap();

        let model = MoveBlockModel::new(".text", 0x5000);
        let result = model.execute(&mut map_model);
        assert!(matches!(result, BlockOperationResult::Success(_)));

        let block = map_model.get_block(".text").unwrap();
        assert_eq!(block.start.offset, 0x5000);
        assert_eq!(block.end.offset, 0x5FFF);
    }

    #[test]
    fn test_move_block_not_found() {
        let mut map_model = MemoryMapModel::new();
        let model = MoveBlockModel::new(".missing", 0x5000);
        let result = model.execute(&mut map_model);
        assert!(matches!(result, BlockOperationResult::Failed(_)));
    }

    #[test]
    fn test_uninitialized_block_cmd() {
        let mut map_model = MemoryMapModel::new();
        let cmd = UninitializedBlockCmd::new("BSS", 0x8000, 0x2000);
        let result = cmd.execute(&mut map_model);
        assert!(matches!(result, BlockOperationResult::Success(_)));

        let block = map_model.get_block("BSS").unwrap();
        assert_eq!(block.block_type, MemoryBlockType::Uninitialized);
        assert_eq!(block.size(), 0x2000);
    }

    #[test]
    fn test_image_base_action_no_move() {
        let mut map_model = MemoryMapModel::new();
        map_model
            .add_block(MemoryBlockInfo::new(
                ".text",
                Address::new(0x1000),
                Address::new(0x1FFF),
                MemoryBlockType::Initialized,
            ))
            .unwrap();

        let action = ImageBaseAction::new(0x400000, false);
        let result = action.execute(0, &mut map_model);
        assert!(matches!(result, BlockOperationResult::Success(_)));
        // Block not moved
        assert_eq!(map_model.get_block(".text").unwrap().start.offset, 0x1000);
    }

    #[test]
    fn test_image_base_action_move() {
        let mut map_model = MemoryMapModel::new();
        map_model
            .add_block(MemoryBlockInfo::new(
                ".text",
                Address::new(0x1000),
                Address::new(0x1FFF),
                MemoryBlockType::Initialized,
            ))
            .unwrap();

        let action = ImageBaseAction::new(0x401000, true);
        let result = action.execute(0x1000, &mut map_model);
        assert!(matches!(result, BlockOperationResult::Success(_)));

        let block = map_model.get_block(".text").unwrap();
        assert_eq!(block.start.offset, 0x401000);
    }

    #[test]
    fn test_memory_map_manager() {
        let mut mgr = MemoryMapManager::new();
        assert_eq!(mgr.block_count(), 0);

        let model = AddBlockModel {
            name: ".text".into(),
            start_address: 0x1000,
            length: 0x1000,
            ..AddBlockModel::default()
        };
        let result = mgr.add_block(&model);
        assert!(matches!(result, BlockOperationResult::Success(_)));
        assert_eq!(mgr.block_count(), 1);
    }

    #[test]
    fn test_memory_map_manager_split() {
        let mut mgr = MemoryMapManager::new();
        let model = AddBlockModel {
            name: ".text".into(),
            start_address: 0x1000,
            length: 0x2000,
            ..AddBlockModel::default()
        };
        mgr.add_block(&model);

        let result = mgr.split_block(".text", Address::new(0x2000));
        assert!(matches!(result, BlockOperationResult::Success(_)));
        assert_eq!(mgr.block_count(), 2);
    }

    #[test]
    fn test_memory_map_manager_merge() {
        let mut mgr = MemoryMapManager::new();
        let model1 = AddBlockModel {
            name: "p1".into(),
            start_address: 0x1000,
            length: 0x1000,
            ..AddBlockModel::default()
        };
        mgr.add_block(&model1);
        let model2 = AddBlockModel {
            name: "p2".into(),
            start_address: 0x2000,
            length: 0x1000,
            ..AddBlockModel::default()
        };
        mgr.add_block(&model2);

        let result = mgr.merge_blocks("p1", "p2");
        assert!(matches!(result, BlockOperationResult::Success(_)));
        assert_eq!(mgr.block_count(), 1);
    }

    #[test]
    fn test_memory_map_manager_delete() {
        let mut mgr = MemoryMapManager::new();
        let model = AddBlockModel {
            name: ".temp".into(),
            start_address: 0x5000,
            length: 0x1000,
            ..AddBlockModel::default()
        };
        mgr.add_block(&model);
        assert_eq!(mgr.block_count(), 1);

        let result = mgr.delete_block(".temp");
        assert!(matches!(result, BlockOperationResult::Success(_)));
        assert_eq!(mgr.block_count(), 0);
    }

    #[test]
    fn test_memory_map_manager_delete_not_found() {
        let mut mgr = MemoryMapManager::new();
        let result = mgr.delete_block(".missing");
        assert!(matches!(result, BlockOperationResult::Failed(_)));
        assert!(mgr.last_error().is_some());
    }

    #[test]
    fn test_memory_map_manager_permissions() {
        let mut mgr = MemoryMapManager::new();
        let model = AddBlockModel {
            name: ".text".into(),
            start_address: 0x1000,
            length: 0x1000,
            ..AddBlockModel::default()
        };
        mgr.add_block(&model);

        let result = mgr.set_permissions(".text", MemoryBlockPermission::all());
        assert!(matches!(result, BlockOperationResult::Success(_)));

        let block = mgr.map_model.get_block(".text").unwrap();
        assert!(block.permissions.read);
        assert!(block.permissions.write);
        assert!(block.permissions.execute);
    }

    #[test]
    fn test_memory_map_manager_image_base() {
        let mut mgr = MemoryMapManager::new();
        let model = AddBlockModel {
            name: ".text".into(),
            start_address: 0x1000,
            length: 0x1000,
            ..AddBlockModel::default()
        };
        mgr.add_block(&model);

        let result = mgr.set_image_base(0x400000);
        assert!(matches!(result, BlockOperationResult::Success(_)));
        assert_eq!(mgr.image_base, 0x400000);
    }

    #[test]
    fn test_memory_map_manager_block_names() {
        let mut mgr = MemoryMapManager::new();
        let model = AddBlockModel {
            name: ".text".into(),
            start_address: 0x1000,
            length: 0x1000,
            ..AddBlockModel::default()
        };
        mgr.add_block(&model);
        assert_eq!(mgr.block_names(), vec![".text"]);
    }

    #[test]
    fn test_mapped_block_requires_source() {
        let model = AddBlockModel {
            name: ".mapped".into(),
            start_address: 0x1000,
            length: 0x1000,
            block_type: MemoryBlockType::Mapped,
            ..AddBlockModel::default()
        };
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_mapped_block_with_source() {
        let model = AddBlockModel {
            name: ".mapped".into(),
            start_address: 0x1000,
            length: 0x1000,
            block_type: MemoryBlockType::Mapped,
            source_name: Some(".text".into()),
            source_start: Some(0x0),
            ..AddBlockModel::default()
        };
        assert!(model.validate().is_ok());
    }
}
