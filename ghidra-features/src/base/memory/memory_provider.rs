//! Memory map provider -- view-state management for the memory map panel.
//!
//! Ported from `MemoryMapProvider` in Ghidra's `ghidra.app.plugin.core.memory`.
//!
//! This module provides [`MemoryMapProvider`], which tracks the visible
//! state of the memory map view, the currently selected block(s), the
//! table model, and the available actions (add, move, split, expand, merge,
//! delete, set image base).
//!
//! In the Rust port, Swing-specific UI components (tables, panels, toolbars)
//! are replaced with a pure-data representation of the view state.

use ghidra_core::addr::Address;
use ghidra_core::mem::MemoryBlock;
use ghidra_core::program::program::Program;

use super::memory_map_model::MemoryMapModel;

// ============================================================================
// Action enablement state
// ============================================================================

/// Which memory-map actions are currently enabled.
///
/// Mirrors the enable/disable logic in `MemoryMapProvider.enableOptions`.
#[derive(Debug, Clone, Default)]
pub struct ActionEnablement {
    /// Whether the "Add Block" action is available.
    pub add: bool,
    /// Whether the "Move Block" action is available (exactly one block selected).
    pub move_block: bool,
    /// Whether the "Split Block" action is available (one DEFAULT block selected).
    pub split: bool,
    /// Whether the "Expand Up" action is available.
    pub expand_up: bool,
    /// Whether the "Expand Down" action is available.
    pub expand_down: bool,
    /// Whether the "Merge Blocks" action is available (more than one selected).
    pub merge: bool,
    /// Whether the "Delete Block" action is available (one or more selected).
    pub delete: bool,
    /// Whether the "Set Image Base" action is available.
    pub set_base: bool,
}

// ============================================================================
// Selection info
// ============================================================================

/// Information about the currently selected memory block.
#[derive(Debug, Clone)]
pub struct BlockSelection {
    /// Index of the selected block in the table model.
    pub row: usize,
    /// The selected block.
    pub block: MemoryBlock,
}

// ============================================================================
// MemoryMapProvider
// ============================================================================

/// View-state manager for the memory map panel.
///
/// Ported from `MemoryMapProvider` in Java. This struct tracks:
/// - Whether the view is visible
/// - The table model backing the memory map table
/// - Which blocks are selected
/// - Which actions are enabled
/// - Navigation state (follow-location-changes toggle)
///
/// # Usage
///
/// ```ignore
/// let mut provider = MemoryMapProvider::new();
/// provider.set_program(&program);
/// provider.set_visible(true);
/// provider.select_block(0);
/// assert!(provider.action_enablement().split);
/// ```
#[derive(Debug)]
pub struct MemoryMapProvider {
    /// Whether the provider's component is currently visible.
    visible: bool,
    /// The table model for the memory map.
    table_model: MemoryMapModel,
    /// Indices of selected rows.
    selected_rows: Vec<usize>,
    /// Current action enablement state.
    actions: ActionEnablement,
    /// Whether to follow incoming location changes.
    follow_location: bool,
    /// Status text to display.
    status_text: String,
    /// Subtitle showing image base address.
    subtitle: String,
}

impl MemoryMapProvider {
    /// Create a new memory map provider.
    pub fn new() -> Self {
        Self {
            visible: false,
            table_model: MemoryMapModel::default(),
            selected_rows: Vec::new(),
            actions: ActionEnablement::default(),
            follow_location: false,
            status_text: String::new(),
            subtitle: String::new(),
        }
    }

    // ---- visibility ----

    /// Whether the provider is currently visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set the visibility of the provider.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    // ---- program management ----

    /// Set the program whose memory blocks are displayed.
    ///
    /// This corresponds to `MemoryMapProvider.setProgram` in Java.
    pub fn set_program(&mut self, program: &Program) {
        self.table_model = MemoryMapModel::new(program);
        self.selected_rows.clear();
        self.update_subtitle(program);
        self.update_actions();
    }

    /// Clear the current program (e.g., on deactivation).
    pub fn clear_program(&mut self) {
        self.table_model = MemoryMapModel::default();
        self.selected_rows.clear();
        self.actions = ActionEnablement::default();
        self.subtitle.clear();
    }

    // ---- refresh ----

    /// Refresh the entire memory map (structural change).
    ///
    /// This corresponds to `MemoryMapProvider.updateMap` in Java.
    pub fn refresh_map(&mut self, program: &Program) {
        self.table_model.set_program(program);
        self.selected_rows.clear();
        self.update_subtitle(program);
        self.update_actions();
    }

    /// Refresh data only (non-structural change like permissions).
    ///
    /// This corresponds to `MemoryMapProvider.updateData` in Java.
    pub fn refresh_data(&mut self) {
        // In a headless port the table model is already up to date;
        // this is a hook for GUI refresh.
    }

    // ---- table model ----

    /// Get a reference to the table model.
    pub fn table_model(&self) -> &MemoryMapModel {
        &self.table_model
    }

    /// Get the number of blocks in the table model.
    pub fn block_count(&self) -> usize {
        self.table_model.row_count()
    }

    // ---- selection ----

    /// Select a single block by row index.
    pub fn select_block(&mut self, row: usize) {
        if row < self.table_model.row_count() {
            self.selected_rows = vec![row];
        } else {
            self.selected_rows.clear();
        }
        self.update_actions();
    }

    /// Select multiple blocks by row indices.
    pub fn select_blocks(&mut self, rows: &[usize]) {
        self.selected_rows = rows
            .iter()
            .copied()
            .filter(|&r| r < self.table_model.row_count())
            .collect();
        self.update_actions();
    }

    /// Clear the current selection.
    pub fn clear_selection(&mut self) {
        self.selected_rows.clear();
        self.update_actions();
    }

    /// Get the currently selected row indices.
    pub fn selected_rows(&self) -> &[usize] {
        &self.selected_rows
    }

    /// Get the first selected block, if any.
    pub fn get_selected_block(&self) -> Option<&MemoryBlock> {
        self.selected_rows.first().and_then(|&row| self.table_model.get_block(row))
    }

    /// Get all selected blocks.
    pub fn get_selected_blocks(&self) -> Vec<&MemoryBlock> {
        self.selected_rows
            .iter()
            .filter_map(|&row| self.table_model.get_block(row))
            .collect()
    }

    /// Select the block containing the given address.
    ///
    /// This corresponds to `MemoryMapProvider.locationChanged` in Java.
    pub fn select_block_at_address(&mut self, address: Option<Address>, program: &Program) {
        if !self.follow_location {
            return;
        }
        let addr = match address {
            Some(a) => a,
            None => return,
        };

        // Find the block containing this address
        for (i, block) in self.table_model.blocks().iter().enumerate() {
            if block.start().offset <= addr.offset && addr.offset <= block.end().offset {
                self.selected_rows = vec![i];
                self.update_actions();
                return;
            }
        }
    }

    // ---- navigation ----

    /// Whether the provider follows location changes.
    pub fn follows_location(&self) -> bool {
        self.follow_location
    }

    /// Set whether the provider follows location changes.
    pub fn set_follow_location(&mut self, follow: bool) {
        self.follow_location = follow;
    }

    // ---- status / subtitle ----

    /// Get the current status text.
    pub fn status_text(&self) -> &str {
        &self.status_text
    }

    /// Set the status text.
    pub fn set_status_text(&mut self, text: impl Into<String>) {
        self.status_text = text.into();
    }

    /// Get the current subtitle (shows image base address).
    pub fn subtitle(&self) -> &str {
        &self.subtitle
    }

    fn update_subtitle(&mut self, program: &Program) {
        self.subtitle = format!("Image Base: 0x{:x}", program.get_image_base().offset);
    }

    // ---- action enablement ----

    /// Get the current action enablement state.
    pub fn action_enablement(&self) -> &ActionEnablement {
        &self.actions
    }

    /// Update which actions are enabled based on the current selection.
    ///
    /// This mirrors `MemoryMapProvider.enableOptions` in Java.
    fn update_actions(&mut self) {
        let num_selected = self.selected_rows.len();

        self.actions.add = self.table_model.row_count() > 0 || true; // always allow add
        self.actions.set_base = self.table_model.row_count() > 0;

        if num_selected == 0 {
            self.actions.move_block = false;
            self.actions.split = false;
            self.actions.expand_up = false;
            self.actions.expand_down = false;
            self.actions.merge = false;
            self.actions.delete = false;
            return;
        }

        self.actions.delete = true;

        if num_selected == 1 {
            self.actions.move_block = true;
            self.actions.merge = false;

            // Extract block info before mutating self.actions to avoid borrow conflict.
            let block_info: Option<(bool, u64)> = self.selected_rows.first().and_then(|&row| {
                self.table_model.get_block(row).map(|block| {
                    let is_default =
                        block.block_type == ghidra_core::mem::MemoryBlockType::Default;
                    (is_default, block.start().offset)
                })
            });

            if let Some((is_default, start_offset)) = block_info {
                self.actions.split = is_default;

                if is_default {
                    self.actions.expand_up = start_offset > 0;
                    // expand_down: not at max address (simplified check)
                    self.actions.expand_down = true;
                } else {
                    self.actions.expand_up = false;
                    self.actions.expand_down = false;
                }
            }
        } else {
            // num_selected >= 2
            self.actions.move_block = false;
            self.actions.split = false;
            self.actions.expand_up = false;
            self.actions.expand_down = false;
            self.actions.merge = true;
        }
    }

    /// Dispose of the provider.
    pub fn dispose(&mut self) {
        self.visible = false;
        self.table_model = MemoryMapModel::default();
        self.selected_rows.clear();
        self.actions = ActionEnablement::default();
    }
}

impl Default for MemoryMapProvider {
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
        let provider = MemoryMapProvider::new();
        assert!(!provider.is_visible());
        assert_eq!(provider.block_count(), 0);
        assert!(provider.selected_rows().is_empty());
    }

    #[test]
    fn test_provider_set_program() {
        let program = make_program();
        let mut provider = MemoryMapProvider::new();
        provider.set_program(&program);
        assert_eq!(provider.block_count(), 3);
        assert!(provider.subtitle().contains("Image Base"));
    }

    #[test]
    fn test_provider_clear_program() {
        let program = make_program();
        let mut provider = MemoryMapProvider::new();
        provider.set_program(&program);
        assert_eq!(provider.block_count(), 3);
        provider.clear_program();
        assert_eq!(provider.block_count(), 0);
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = MemoryMapProvider::new();
        assert!(!provider.is_visible());
        provider.set_visible(true);
        assert!(provider.is_visible());
        provider.set_visible(false);
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_select_block() {
        let program = make_program();
        let mut provider = MemoryMapProvider::new();
        provider.set_program(&program);
        provider.select_block(0);
        assert_eq!(provider.selected_rows(), &[0]);
        assert!(provider.get_selected_block().is_some());
    }

    #[test]
    fn test_provider_select_multiple_blocks() {
        let program = make_program();
        let mut provider = MemoryMapProvider::new();
        provider.set_program(&program);
        provider.select_blocks(&[0, 2]);
        assert_eq!(provider.selected_rows().len(), 2);
        assert_eq!(provider.get_selected_blocks().len(), 2);
    }

    #[test]
    fn test_provider_select_out_of_range() {
        let program = make_program();
        let mut provider = MemoryMapProvider::new();
        provider.set_program(&program);
        provider.select_block(100);
        assert!(provider.selected_rows().is_empty());
    }

    #[test]
    fn test_provider_clear_selection() {
        let program = make_program();
        let mut provider = MemoryMapProvider::new();
        provider.set_program(&program);
        provider.select_block(0);
        provider.clear_selection();
        assert!(provider.selected_rows().is_empty());
    }

    #[test]
    fn test_provider_actions_no_selection() {
        let program = make_program();
        let mut provider = MemoryMapProvider::new();
        provider.set_program(&program);
        let a = provider.action_enablement();
        assert!(a.add);
        assert!(!a.move_block);
        assert!(!a.split);
        assert!(!a.merge);
        assert!(!a.delete);
    }

    #[test]
    fn test_provider_actions_single_selection() {
        let program = make_program();
        let mut provider = MemoryMapProvider::new();
        provider.set_program(&program);
        provider.select_block(0);
        let a = provider.action_enablement();
        assert!(a.add);
        assert!(a.move_block);
        assert!(a.split); // .text is DEFAULT
        assert!(!a.merge);
        assert!(a.delete);
    }

    #[test]
    fn test_provider_actions_multi_selection() {
        let program = make_program();
        let mut provider = MemoryMapProvider::new();
        provider.set_program(&program);
        provider.select_blocks(&[0, 1]);
        let a = provider.action_enablement();
        assert!(a.add);
        assert!(!a.move_block);
        assert!(!a.split);
        assert!(a.merge);
        assert!(a.delete);
    }

    #[test]
    fn test_provider_follow_location() {
        let program = make_program();
        let mut provider = MemoryMapProvider::new();
        provider.set_program(&program);
        provider.set_follow_location(true);
        assert!(provider.follows_location());

        // Select block at address 0x10500 (within .text)
        provider.select_block_at_address(Some(Address::new(0x10500)), &program);
        assert_eq!(provider.selected_rows(), &[0]);
    }

    #[test]
    fn test_provider_follow_location_disabled() {
        let program = make_program();
        let mut provider = MemoryMapProvider::new();
        provider.set_program(&program);
        provider.set_follow_location(false);

        provider.select_block_at_address(Some(Address::new(0x10500)), &program);
        assert!(provider.selected_rows().is_empty());
    }

    #[test]
    fn test_provider_status_text() {
        let mut provider = MemoryMapProvider::new();
        provider.set_status_text("test status");
        assert_eq!(provider.status_text(), "test status");
    }

    #[test]
    fn test_provider_refresh_map() {
        let program = make_program();
        let mut provider = MemoryMapProvider::new();
        provider.set_program(&program);
        provider.select_block(0);
        provider.refresh_map(&program);
        // Selection is cleared after refresh
        assert!(provider.selected_rows().is_empty());
    }

    #[test]
    fn test_provider_dispose() {
        let program = make_program();
        let mut provider = MemoryMapProvider::new();
        provider.set_program(&program);
        provider.set_visible(true);
        provider.dispose();
        assert!(!provider.is_visible());
        assert_eq!(provider.block_count(), 0);
    }

    #[test]
    fn test_provider_default() {
        let provider = MemoryMapProvider::default();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_action_enablement_default() {
        let a = ActionEnablement::default();
        assert!(!a.add);
        assert!(!a.move_block);
        assert!(!a.split);
        assert!(!a.expand_up);
        assert!(!a.expand_down);
        assert!(!a.merge);
        assert!(!a.delete);
        assert!(!a.set_base);
    }

    #[test]
    fn test_get_selected_block_none() {
        let provider = MemoryMapProvider::new();
        assert!(provider.get_selected_block().is_none());
    }
}
