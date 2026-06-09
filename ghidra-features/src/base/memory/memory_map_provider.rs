//! Memory map provider -- component provider bridging plugin and models.
//!
//! Ported from `MemoryMapProvider` in Ghidra's `ghidra.app.plugin.core.memory`.
//!
//! This module provides [`MemoryMapComponentProvider`], which coordinates
//! the user-facing operations of the memory map: selecting blocks,
//! triggering dialog-driven operations (add, move, split, expand, merge,
//! delete, set-base), and managing navigation to addresses.
//!
//! In the Rust port, Swing-specific UI components (tables, panels, dialogs)
//! are replaced with a command-dispatch model that returns results rather
//! than blocking on modal dialogs.

use ghidra_core::addr::Address;
use ghidra_core::mem::{MemoryBlock, MemoryBlockType};
use ghidra_core::program::program::Program;

use super::commands::MemoryCommand;
use super::expand_block_model::ExpandBlockModel;
use super::map_manager::MemoryMapManager;
use super::memory_provider::MemoryMapProvider;
use super::move_block_model::MoveBlockModel;
use super::set_base_cmd::SetBaseCmd;
use super::split_block_model::SplitBlockModel;

// ============================================================================
// Operation result types
// ============================================================================

/// Result of a memory-map operation initiated through the component provider.
#[derive(Debug, Clone)]
pub enum OperationResult {
    /// The operation succeeded.
    Success {
        /// Human-readable status message.
        message: String,
    },
    /// The operation failed.
    Failure {
        /// Human-readable error message.
        message: String,
    },
    /// The operation was cancelled by the user.
    Cancelled,
}

/// Describes which block operation to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockOperation {
    /// Add a new memory block.
    Add,
    /// Move the selected block to a new address.
    Move,
    /// Split the selected block at an address.
    Split,
    /// Expand the selected block upward (toward lower addresses).
    ExpandUp,
    /// Expand the selected block downward (toward higher addresses).
    ExpandDown,
    /// Merge the selected blocks.
    Merge,
    /// Delete the selected blocks.
    Delete,
    /// Set the program's image base address.
    SetImageBase,
}

// ============================================================================
// MemoryMapComponentProvider
// ============================================================================

/// Component provider for the memory map panel.
///
/// Ported from `MemoryMapProvider` in Java. This struct coordinates:
/// - The [`MemoryMapProvider`] (view state)
/// - The [`MemoryMapManager`] (block operations)
/// - Dialog-model creation for each block operation
/// - Navigation from table selections to addresses
///
/// This is the higher-level bridge that the [`super::memory_plugin::MemoryMapPlugin`]
/// delegates to for user-initiated operations.
///
/// # Usage
///
/// ```ignore
/// let mut provider = MemoryMapComponentProvider::new();
/// provider.set_program(&program);
/// provider.set_visible(true);
/// provider.view_mut().select_block(0);
/// let result = provider.delete_selected_blocks(&mut program);
/// ```
#[derive(Debug)]
pub struct MemoryMapComponentProvider {
    /// The underlying view-state provider.
    view: MemoryMapProvider,
    /// The memory map manager for executing operations.
    manager: MemoryMapManager,
    /// The current program name (for error messages).
    program_name: String,
    /// Last status message from an operation.
    last_status: String,
    /// Whether exclusive access was confirmed before an operation.
    has_exclusive_access: bool,
}

impl MemoryMapComponentProvider {
    /// Create a new component provider.
    pub fn new() -> Self {
        Self {
            view: MemoryMapProvider::new(),
            manager: MemoryMapManager::default(),
            program_name: String::new(),
            last_status: String::new(),
            has_exclusive_access: false,
        }
    }

    // ---- view delegation ----

    /// Get a reference to the underlying view-state provider.
    pub fn view(&self) -> &MemoryMapProvider {
        &self.view
    }

    /// Get a mutable reference to the underlying view-state provider.
    pub fn view_mut(&mut self) -> &mut MemoryMapProvider {
        &mut self.view
    }

    /// Get a reference to the memory map manager.
    pub fn manager(&self) -> &MemoryMapManager {
        &self.manager
    }

    /// Get a mutable reference to the memory map manager.
    pub fn manager_mut(&mut self) -> &mut MemoryMapManager {
        &mut self.manager
    }

    // ---- program lifecycle ----

    /// Set the program whose memory is being displayed.
    pub fn set_program(&mut self, program: &Program) {
        self.program_name = program.get_name().to_string();
        self.manager = MemoryMapManager::new(program.get_name());
        self.view.set_program(program);
    }

    /// Clear the current program.
    pub fn clear_program(&mut self) {
        self.program_name.clear();
        self.view.clear_program();
    }

    // ---- visibility ----

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.view.is_visible()
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.view.set_visible(visible);
    }

    // ---- exclusive access ----

    /// Set whether the user has confirmed exclusive access.
    pub fn set_exclusive_access(&mut self, exclusive: bool) {
        self.has_exclusive_access = exclusive;
    }

    /// Whether the user has confirmed exclusive access.
    pub fn has_exclusive_access(&self) -> bool {
        self.has_exclusive_access
    }

    /// Check exclusive access before performing an operation.
    ///
    /// Returns `true` if access is available. If not, sets the status
    /// text with a message instructing the user to obtain exclusive access.
    fn check_exclusive_access(&mut self) -> bool {
        if self.has_exclusive_access {
            return true;
        }
        self.last_status = "An exclusive checkout is required in order to \
            manipulate memory blocks or change the image base."
            .into();
        false
    }

    // ---- status ----

    /// Get the last status message.
    pub fn last_status(&self) -> &str {
        &self.last_status
    }

    /// Set the status text.
    pub fn set_status_text(&mut self, msg: impl Into<String>) {
        self.last_status = msg.into();
    }

    // ---- selection helpers ----

    /// Get the first selected block, if any.
    pub fn get_selected_block(&self) -> Option<&MemoryBlock> {
        self.view.get_selected_block()
    }

    /// Get all selected blocks.
    pub fn get_selected_blocks(&self) -> Vec<&MemoryBlock> {
        self.view.get_selected_blocks()
    }

    // ---- operation dispatch ----

    /// Check whether a specific operation is currently enabled.
    pub fn is_operation_enabled(&self, op: BlockOperation) -> bool {
        let a = self.view.action_enablement();
        match op {
            BlockOperation::Add => a.add,
            BlockOperation::Move => a.move_block,
            BlockOperation::Split => a.split,
            BlockOperation::ExpandUp => a.expand_up,
            BlockOperation::ExpandDown => a.expand_down,
            BlockOperation::Merge => a.merge,
            BlockOperation::Delete => a.delete,
            BlockOperation::SetImageBase => a.set_base,
        }
    }

    /// Execute a block operation on the given program.
    ///
    /// This is the main entry point for user-initiated operations that
    /// do not require additional parameters (Delete, Merge). For operations
    /// that require an address or other input, use the specific methods
    /// instead.
    pub fn execute_operation(
        &mut self,
        op: BlockOperation,
        program: &mut Program,
    ) -> OperationResult {
        if !self.check_exclusive_access() {
            return OperationResult::Failure {
                message: self.last_status.clone(),
            };
        }

        if !self.is_operation_enabled(op) {
            return OperationResult::Failure {
                message: format!("{:?} operation is not available for current selection", op),
            };
        }

        match op {
            BlockOperation::Delete => self.delete_selected_blocks(program),
            BlockOperation::Merge => self.merge_selected_blocks(program),
            _ => OperationResult::Failure {
                message: format!(
                    "{:?} operation requires additional parameters; \
                     use the specific method instead",
                    op
                ),
            },
        }
    }

    // ---- add block ----

    /// Create a new initialized memory block.
    pub fn add_initialized_block(
        &mut self,
        program: &mut Program,
        name: &str,
        start: Address,
        data: Vec<u8>,
        overlay: bool,
    ) -> OperationResult {
        if !self.check_exclusive_access() {
            return OperationResult::Failure {
                message: self.last_status.clone(),
            };
        }

        match program
            .memory
            .create_initialized_block(name, start, data, overlay)
        {
            Ok(_) => {
                self.view.refresh_map(program);
                OperationResult::Success {
                    message: format!("Block '{}' added successfully", name),
                }
            }
            Err(e) => OperationResult::Failure {
                message: format!("Failed to add block '{}': {}", name, e),
            },
        }
    }

    /// Create a new uninitialized memory block.
    pub fn add_uninitialized_block(
        &mut self,
        program: &mut Program,
        name: &str,
        start: Address,
        length: u64,
        overlay: bool,
    ) -> OperationResult {
        if !self.check_exclusive_access() {
            return OperationResult::Failure {
                message: self.last_status.clone(),
            };
        }

        match program
            .memory
            .create_uninitialized_block(name, start, length, overlay)
        {
            Ok(_) => {
                self.view.refresh_map(program);
                OperationResult::Success {
                    message: format!("Block '{}' added successfully", name),
                }
            }
            Err(e) => OperationResult::Failure {
                message: format!("Failed to add block '{}': {}", name, e),
            },
        }
    }

    // ---- move block ----

    /// Move the selected block to a new start address.
    pub fn move_selected_block(
        &mut self,
        program: &mut Program,
        new_start: Address,
    ) -> OperationResult {
        if !self.check_exclusive_access() {
            return OperationResult::Failure {
                message: self.last_status.clone(),
            };
        }

        let block = match self.view.get_selected_block() {
            Some(b) => b.clone(),
            None => {
                return OperationResult::Failure {
                    message: "No block selected".into(),
                };
            }
        };

        if block.is_overlay() {
            return OperationResult::Failure {
                message: "Overlay blocks cannot be moved.".into(),
            };
        }

        let mut model = MoveBlockModel::new();
        model.initialize(&block);
        model.set_new_start_address(new_start);

        if !model.message().is_empty() {
            return OperationResult::Failure {
                message: model.message().to_string(),
            };
        }

        match model.execute(program) {
            Ok(()) => {
                self.view.refresh_map(program);
                OperationResult::Success {
                    message: format!("Block '{}' moved successfully", block.name),
                }
            }
            Err(e) => OperationResult::Failure {
                message: format!("Failed to move block '{}': {}", block.name, e),
            },
        }
    }

    /// Create a [`MoveBlockModel`] for the currently selected block.
    ///
    /// Returns `None` if no block is selected.
    pub fn create_move_model(&self) -> Option<MoveBlockModel> {
        self.view.get_selected_block().map(|block| {
            let mut model = MoveBlockModel::new();
            model.initialize(block);
            model
        })
    }

    // ---- split block ----

    /// Split the selected block at the given address.
    pub fn split_selected_block(
        &mut self,
        program: &mut Program,
        split_address: Address,
        new_block_name: &str,
    ) -> OperationResult {
        if !self.check_exclusive_access() {
            return OperationResult::Failure {
                message: self.last_status.clone(),
            };
        }

        let block = match self.view.get_selected_block() {
            Some(b) => b.clone(),
            None => {
                return OperationResult::Failure {
                    message: "No block selected".into(),
                };
            }
        };

        if block.is_overlay() {
            return OperationResult::Failure {
                message: "Overlay blocks can not be split.".into(),
            };
        }

        if block.block_type != MemoryBlockType::Default {
            return OperationResult::Failure {
                message: "Only DEFAULT blocks can be split".into(),
            };
        }

        let mut model =
            SplitBlockModel::new(block.start(), block.end(), &block.name);
        model.set_split_address(split_address);
        model.set_new_block_name(new_block_name);

        if let Err(e) = model.validate() {
            return OperationResult::Failure {
                message: format!("Split validation failed: {:?}", e),
            };
        }

        match program.memory.split_block(&block.name, split_address) {
            Ok(()) => {
                self.view.refresh_map(program);
                OperationResult::Success {
                    message: format!(
                        "Block '{}' split at 0x{:x}",
                        block.name, split_address.offset
                    ),
                }
            }
            Err(e) => OperationResult::Failure {
                message: format!("Failed to split block '{}': {}", block.name, e),
            },
        }
    }

    /// Create a [`SplitBlockModel`] for the currently selected block.
    ///
    /// Returns `None` if no block is selected or the block is not splittable.
    pub fn create_split_model(&self) -> Option<SplitBlockModel> {
        self.view.get_selected_block().and_then(|block| {
            if block.block_type != MemoryBlockType::Default {
                return None;
            }
            Some(SplitBlockModel::new(
                block.start(),
                block.end(),
                &block.name,
            ))
        })
    }

    // ---- expand block ----

    /// Expand the selected block upward (toward lower addresses).
    pub fn expand_selected_block_up(
        &mut self,
        program: &mut Program,
        new_start: Address,
    ) -> OperationResult {
        self.expand_selected_block(program, new_start, true)
    }

    /// Expand the selected block downward (toward higher addresses).
    pub fn expand_selected_block_down(
        &mut self,
        program: &mut Program,
        new_end: Address,
    ) -> OperationResult {
        self.expand_selected_block(program, new_end, false)
    }

    /// Check if expanding the selected block would expand file-backed regions.
    ///
    /// Corresponds to the `MemoryBlockSourceInfo.getFileBytes()` check in the
    /// Java `MemoryMapProvider.expandBlock` method. When a block uses file
    /// bytes, expanding it would create a zero-filled region, which may need
    /// user confirmation.
    pub fn would_expand_file_bytes(&self) -> bool {
        self.view
            .get_selected_block()
            .map_or(false, |b| b.has_file_bytes())
    }

    fn expand_selected_block(
        &mut self,
        program: &mut Program,
        address: Address,
        expand_up: bool,
    ) -> OperationResult {
        if !self.check_exclusive_access() {
            return OperationResult::Failure {
                message: self.last_status.clone(),
            };
        }

        let block = match self.view.get_selected_block() {
            Some(b) => b.clone(),
            None => {
                return OperationResult::Failure {
                    message: "No block selected".into(),
                };
            }
        };

        if block.block_type != MemoryBlockType::Default {
            return OperationResult::Failure {
                message: "Only DEFAULT blocks can be expanded".into(),
            };
        }

        let mut model = ExpandBlockModel::new();
        model.initialize(&block);

        if expand_up {
            model.set_start_address(address);
        } else {
            model.set_end_address(address);
        }

        if !model.is_valid_length() {
            return OperationResult::Failure {
                message: model.message().to_string(),
            };
        }

        match model.execute(program) {
            Ok(()) => {
                self.view.refresh_map(program);
                OperationResult::Success {
                    message: format!("Block '{}' expanded", block.name),
                }
            }
            Err(e) => OperationResult::Failure {
                message: format!("Failed to expand block '{}': {}", block.name, e),
            },
        }
    }

    /// Create an [`ExpandBlockModel`] for the currently selected block.
    ///
    /// Returns `None` if no block is selected or the block cannot be expanded.
    pub fn create_expand_model(&self) -> Option<ExpandBlockModel> {
        self.view.get_selected_block().and_then(|block| {
            if block.block_type != MemoryBlockType::Default {
                return None;
            }
            let mut model = ExpandBlockModel::new();
            model.initialize(block);
            Some(model)
        })
    }

    // ---- merge blocks ----

    /// Merge the selected blocks.
    pub fn merge_selected_blocks(&mut self, program: &mut Program) -> OperationResult {
        if !self.check_exclusive_access() {
            return OperationResult::Failure {
                message: self.last_status.clone(),
            };
        }

        let blocks: Vec<MemoryBlock> =
            self.view.get_selected_blocks().into_iter().cloned().collect();
        if blocks.len() < 2 {
            return OperationResult::Failure {
                message: "At least two blocks must be selected for merging".into(),
            };
        }

        let names: Vec<String> = blocks.iter().map(|b| b.name.clone()).collect();

        match self.manager.merge_blocks(program, &names) {
            Ok(()) => {
                self.view.refresh_map(program);
                OperationResult::Success {
                    message: format!("{} blocks merged", blocks.len()),
                }
            }
            Err(e) => OperationResult::Failure {
                message: format!("Failed to merge blocks: {}", e),
            },
        }
    }

    // ---- delete blocks ----

    /// Delete the selected blocks.
    pub fn delete_selected_blocks(&mut self, program: &mut Program) -> OperationResult {
        if !self.check_exclusive_access() {
            return OperationResult::Failure {
                message: self.last_status.clone(),
            };
        }

        let blocks: Vec<MemoryBlock> =
            self.view.get_selected_blocks().into_iter().cloned().collect();
        if blocks.is_empty() {
            return OperationResult::Failure {
                message: "No blocks selected for deletion".into(),
            };
        }

        let names: Vec<String> = blocks.iter().map(|b| b.name.clone()).collect();

        match self.manager.delete_blocks(program, &names) {
            Ok(()) => {
                self.view.clear_selection();
                self.view.refresh_map(program);
                OperationResult::Success {
                    message: format!("{} block(s) deleted", blocks.len()),
                }
            }
            Err(e) => OperationResult::Failure {
                message: format!("Failed to delete blocks: {}", e),
            },
        }
    }

    // ---- set image base ----

    /// Set the program's image base address.
    pub fn set_image_base(
        &mut self,
        program: &mut Program,
        new_base: Address,
    ) -> OperationResult {
        if !self.check_exclusive_access() {
            return OperationResult::Failure {
                message: self.last_status.clone(),
            };
        }

        let cmd = SetBaseCmd::new(new_base);
        if cmd.apply(program) {
            self.view.refresh_map(program);
            OperationResult::Success {
                message: format!("Image base set to 0x{:x}", new_base.offset),
            }
        } else {
            OperationResult::Failure {
                message: cmd
                    .status_msg()
                    .unwrap_or("Failed to set image base")
                    .to_string(),
            }
        }
    }

    /// Validate an image base change.
    pub fn validate_image_base_change(
        &self,
        program: &Program,
        new_base: Address,
    ) -> Result<(), String> {
        super::set_base_cmd::validate_image_base_change(program, new_base)
    }

    // ---- overlay space renaming ----

    /// Rename an overlay address space.
    ///
    /// Corresponds to `MemoryMapProvider.renameOverlaySpace` in Java.
    /// Only works when the selected block is an overlay block.
    ///
    /// In the Java source, the overlay space name is obtained from
    /// `OverlayAddressSpace.getName()`. In the Rust port the overlay space
    /// name is derived from the block name (Ghidra convention: the first
    /// overlay block in a space shares the space name).
    ///
    /// # Returns
    ///
    /// `OperationResult::Success` if renamed, or `Failure` with a message.
    pub fn rename_overlay_space(
        &mut self,
        program: &mut Program,
        new_name: &str,
    ) -> OperationResult {
        if !self.check_exclusive_access() {
            return OperationResult::Failure {
                message: self.last_status.clone(),
            };
        }

        let block = match self.view.get_selected_block() {
            Some(b) => b.clone(),
            None => {
                return OperationResult::Failure {
                    message: "No block selected".into(),
                };
            }
        };

        if !block.is_overlay() {
            return OperationResult::Failure {
                message: "Selected block is not an overlay block".into(),
            };
        }

        if new_name.is_empty() {
            return OperationResult::Failure {
                message: "Overlay space name cannot be empty".into(),
            };
        }

        // In Ghidra's convention, the overlay space name matches the block
        // name for the first block in that overlay space.
        let old_name = block.name.clone();

        match self.manager.rename_block(program, &old_name, new_name) {
            Ok(()) => {
                self.view.refresh_map(program);
                OperationResult::Success {
                    message: format!(
                        "Overlay space '{}' renamed to '{}'",
                        old_name, new_name
                    ),
                }
            }
            Err(e) => OperationResult::Failure {
                message: format!("Failed to rename overlay space: {}", e),
            },
        }
    }

    /// Check whether the selected block is an overlay block (for rename overlay).
    pub fn can_rename_overlay_space(&self) -> bool {
        self.view
            .get_selected_block()
            .map_or(false, |b| b.is_overlay())
    }

    // ---- navigation ----

    /// Navigate to the address of the selected block.
    ///
    /// Returns the address of the selected block's start or end, depending
    /// on which column the user clicked (1 = start, 2 = end).
    pub fn navigate_to_selected_address(&self, column: usize) -> Option<Address> {
        let block = self.view.get_selected_block()?;
        match column {
            1 => Some(block.start()),
            2 => Some(block.end()),
            _ => None,
        }
    }

    /// Handle a location change (e.g., user navigated to an address).
    pub fn on_location_changed(&mut self, address: Option<Address>, program: &Program) {
        self.view.select_block_at_address(address, program);
    }

    // ---- refresh ----

    /// Refresh the entire memory map display.
    pub fn refresh_map(&mut self, program: &Program) {
        self.view.refresh_map(program);
    }

    /// Refresh only the data (non-structural changes).
    pub fn refresh_data(&mut self) {
        self.view.refresh_data();
    }

    // ---- dispose ----

    /// Dispose of this provider, releasing all resources.
    pub fn dispose(&mut self) {
        self.view.dispose();
        self.program_name.clear();
        self.last_status.clear();
    }
}

impl Default for MemoryMapComponentProvider {
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
    use ghidra_core::addr::Address;
    use ghidra_core::mem::MemoryMap;

    fn make_program() -> Program {
        let memory = MemoryMap::new(false);
        let mut p = Program::with_memory("test", Address::new(0x10000), Box::new(memory));
        let _ = p.memory.create_initialized_block(
            ".text",
            Address::new(0x10000),
            vec![0u8; 0x1000],
            false,
        );
        let _ = p.memory.create_initialized_block(
            ".data",
            Address::new(0x11000),
            vec![0u8; 0x800],
            false,
        );
        let _ = p.memory.create_uninitialized_block(
            ".bss",
            Address::new(0x11800),
            0x400,
            false,
        );
        p
    }

    #[test]
    fn test_provider_new() {
        let provider = MemoryMapComponentProvider::new();
        assert!(!provider.is_visible());
        assert!(!provider.has_exclusive_access());
        assert_eq!(provider.view().block_count(), 0);
    }

    #[test]
    fn test_provider_set_program() {
        let program = make_program();
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_program(&program);
        assert_eq!(provider.view().block_count(), 3);
        assert!(provider.view().subtitle().contains("Image Base"));
    }

    #[test]
    fn test_provider_clear_program() {
        let program = make_program();
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_program(&program);
        assert_eq!(provider.view().block_count(), 3);
        provider.clear_program();
        assert_eq!(provider.view().block_count(), 0);
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_visible(true);
        assert!(provider.is_visible());
        provider.set_visible(false);
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_exclusive_access() {
        let mut provider = MemoryMapComponentProvider::new();
        assert!(!provider.has_exclusive_access());
        provider.set_exclusive_access(true);
        assert!(provider.has_exclusive_access());
    }

    #[test]
    fn test_delete_requires_exclusive_access() {
        let program = make_program();
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_program(&program);
        provider.set_visible(true);
        provider.view_mut().select_block(0);

        // Without exclusive access, delete should fail
        let result = provider.delete_selected_blocks(&mut make_program());
        assert!(matches!(result, OperationResult::Failure { .. }));
        assert!(provider.last_status().contains("exclusive"));
    }

    #[test]
    fn test_delete_no_selection() {
        let mut program = make_program();
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_program(&program);
        provider.set_exclusive_access(true);

        let result = provider.delete_selected_blocks(&mut program);
        match result {
            OperationResult::Failure { ref message } => {
                assert!(message.contains("No blocks selected"));
            }
            other => panic!("expected Failure, got {:?}", other),
        }
    }

    #[test]
    fn test_merge_requires_two_blocks() {
        let mut program = make_program();
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_program(&program);
        provider.set_exclusive_access(true);
        provider.view_mut().select_block(0);

        let result = provider.merge_selected_blocks(&mut program);
        match result {
            OperationResult::Failure { ref message } => {
                assert!(message.contains("At least two"));
            }
            other => panic!("expected Failure, got {:?}", other),
        }
    }

    #[test]
    fn test_split_no_selection() {
        let mut program = make_program();
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_program(&program);
        provider.set_exclusive_access(true);

        let result =
            provider.split_selected_block(&mut program, Address::new(0x10800), "new");
        match result {
            OperationResult::Failure { ref message } => {
                assert!(message.contains("No block selected"));
            }
            other => panic!("expected Failure, got {:?}", other),
        }
    }

    #[test]
    fn test_move_no_selection() {
        let mut program = make_program();
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_program(&program);
        provider.set_exclusive_access(true);

        let result = provider.move_selected_block(&mut program, Address::new(0x20000));
        match result {
            OperationResult::Failure { ref message } => {
                assert!(message.contains("No block selected"));
            }
            other => panic!("expected Failure, got {:?}", other),
        }
    }

    #[test]
    fn test_navigate_to_address() {
        let program = make_program();
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_program(&program);
        provider.view_mut().select_block(0);

        // Column 1 = start address
        let addr = provider.navigate_to_selected_address(1);
        assert_eq!(addr, Some(Address::new(0x10000)));

        // Column 2 = end address
        let addr = provider.navigate_to_selected_address(2);
        assert_eq!(addr, Some(Address::new(0x10fff)));

        // Column 3 = not navigable
        let addr = provider.navigate_to_selected_address(3);
        assert_eq!(addr, None);
    }

    #[test]
    fn test_navigate_no_selection() {
        let provider = MemoryMapComponentProvider::new();
        assert_eq!(provider.navigate_to_selected_address(1), None);
    }

    #[test]
    fn test_on_location_changed() {
        let program = make_program();
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_program(&program);
        provider.view_mut().set_follow_location(true);

        provider.on_location_changed(Some(Address::new(0x10500)), &program);
        assert_eq!(provider.view().selected_rows(), &[0]);
    }

    #[test]
    fn test_is_operation_enabled() {
        let program = make_program();
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_program(&program);

        // No selection -- most operations disabled
        assert!(provider.is_operation_enabled(BlockOperation::Add));
        assert!(!provider.is_operation_enabled(BlockOperation::Move));
        assert!(!provider.is_operation_enabled(BlockOperation::Split));
        assert!(!provider.is_operation_enabled(BlockOperation::Delete));
        assert!(!provider.is_operation_enabled(BlockOperation::Merge));

        // Single selection
        provider.view_mut().select_block(0);
        assert!(provider.is_operation_enabled(BlockOperation::Move));
        assert!(provider.is_operation_enabled(BlockOperation::Split));
        assert!(provider.is_operation_enabled(BlockOperation::Delete));
        assert!(!provider.is_operation_enabled(BlockOperation::Merge));

        // Multi selection
        provider.view_mut().select_blocks(&[0, 1]);
        assert!(!provider.is_operation_enabled(BlockOperation::Move));
        assert!(!provider.is_operation_enabled(BlockOperation::Split));
        assert!(provider.is_operation_enabled(BlockOperation::Delete));
        assert!(provider.is_operation_enabled(BlockOperation::Merge));
    }

    #[test]
    fn test_execute_operation_without_exclusive_access() {
        let program = make_program();
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_program(&program);
        provider.view_mut().select_block(0);

        let result = provider.execute_operation(BlockOperation::Delete, &mut make_program());
        assert!(matches!(result, OperationResult::Failure { .. }));
    }

    #[test]
    fn test_execute_operation_not_enabled() {
        let mut program = make_program();
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_program(&program);
        provider.set_exclusive_access(true);

        // No selection -- merge not enabled
        let result = provider.execute_operation(BlockOperation::Merge, &mut program);
        assert!(matches!(result, OperationResult::Failure { .. }));
    }

    #[test]
    fn test_create_move_model_no_selection() {
        let provider = MemoryMapComponentProvider::new();
        assert!(provider.create_move_model().is_none());
    }

    #[test]
    fn test_create_split_model_no_selection() {
        let provider = MemoryMapComponentProvider::new();
        assert!(provider.create_split_model().is_none());
    }

    #[test]
    fn test_create_expand_model_no_selection() {
        let provider = MemoryMapComponentProvider::new();
        assert!(provider.create_expand_model().is_none());
    }

    #[test]
    fn test_status_text() {
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_status_text("hello");
        assert_eq!(provider.last_status(), "hello");
    }

    #[test]
    fn test_dispose() {
        let program = make_program();
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_program(&program);
        provider.set_visible(true);
        provider.dispose();
        assert!(!provider.is_visible());
        assert_eq!(provider.view().block_count(), 0);
    }

    #[test]
    fn test_default() {
        let provider = MemoryMapComponentProvider::default();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_block_operation_equality() {
        assert_eq!(BlockOperation::Add, BlockOperation::Add);
        assert_ne!(BlockOperation::Add, BlockOperation::Delete);
    }

    #[test]
    fn test_add_initialized_block() {
        let mut program = make_program();
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_program(&program);
        provider.set_exclusive_access(true);

        let result = provider.add_initialized_block(
            &mut program,
            ".new",
            Address::new(0x12000),
            vec![0u8; 0x100],
            false,
        );
        assert!(matches!(result, OperationResult::Success { .. }));
        assert_eq!(provider.view().block_count(), 4);
    }

    #[test]
    fn test_add_uninitialized_block() {
        let mut program = make_program();
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_program(&program);
        provider.set_exclusive_access(true);

        let result = provider.add_uninitialized_block(
            &mut program,
            ".heap",
            Address::new(0x13000),
            0x200,
            false,
        );
        assert!(matches!(result, OperationResult::Success { .. }));
        assert_eq!(provider.view().block_count(), 4);
    }

    #[test]
    fn test_can_rename_overlay_space_no_selection() {
        let provider = MemoryMapComponentProvider::new();
        assert!(!provider.can_rename_overlay_space());
    }

    #[test]
    fn test_would_expand_file_bytes_no_selection() {
        let provider = MemoryMapComponentProvider::new();
        assert!(!provider.would_expand_file_bytes());
    }

    #[test]
    fn test_would_expand_file_bytes_default_block() {
        let program = make_program();
        let mut provider = MemoryMapComponentProvider::new();
        provider.set_program(&program);
        provider.view_mut().select_block(0);
        // .text is a plain initialized block, not file-backed
        assert!(!provider.would_expand_file_bytes());
    }
}
