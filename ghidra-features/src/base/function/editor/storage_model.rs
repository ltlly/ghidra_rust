//! Storage address model for the function variable storage editor.
//!
//! Ported from `StorageAddressModel.java` in
//! `ghidra.app.plugin.core.function.editor`.
//!
//! Manages a list of [`VarnodeInfo`] items that together form the
//! variable storage for a function parameter or local variable.  The
//! model supports adding, removing, and reordering varnodes, and
//! notifies a [`ModelChangeListener`] whenever the data changes.

use super::{VarnodeInfo, VarnodeType};

// ---------------------------------------------------------------------------
// StorageAddressModel
// ---------------------------------------------------------------------------

/// Model for editing the storage address of a function variable.
///
/// In Ghidra, a variable's storage can consist of one or more
/// varnodes (e.g., a 16-byte struct stored partly in a register
/// and partly on the stack).  This model tracks the list of varnodes
/// and provides operations for adding, removing, and reordering them.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::editor::*;
///
/// let mut model = StorageAddressModel::new(8);
/// model.add_varnode(VarnodeInfo::register("RAX", 8));
/// assert_eq!(model.varnode_count(), 1);
/// assert_eq!(model.required_size(), 8);
/// ```
#[derive(Debug, Clone)]
pub struct StorageAddressModel {
    /// The varnodes that make up the storage.
    varnodes: Vec<VarnodeInfo>,
    /// The required total size in bytes.
    required_size: usize,
    /// Whether the storage is unconstrained (no required size).
    unconstrained: bool,
    /// The indices of the currently selected varnodes.
    selected_rows: Vec<usize>,
    /// Validation status text.
    status_text: String,
    /// Whether the current configuration is valid.
    is_valid: bool,
    /// Number of auto-parameters to offset ordinals by.
    auto_param_count: usize,
}

impl StorageAddressModel {
    /// Create a new model with the given required size.
    ///
    /// If `required_size` is 0, the storage is considered unconstrained.
    pub fn new(required_size: usize) -> Self {
        let mut model = Self {
            varnodes: Vec::new(),
            required_size,
            unconstrained: required_size == 0,
            selected_rows: Vec::new(),
            status_text: String::new(),
            is_valid: true,
            auto_param_count: 0,
        };
        model.validate();
        model
    }

    /// Create a model from existing varnodes.
    pub fn from_varnodes(varnodes: Vec<VarnodeInfo>, required_size: usize) -> Self {
        let mut model = Self::new(required_size);
        model.varnodes = varnodes;
        model.validate();
        model
    }

    /// Get the list of varnodes.
    pub fn varnodes(&self) -> &[VarnodeInfo] {
        &self.varnodes
    }

    /// Get the number of varnodes.
    pub fn varnode_count(&self) -> usize {
        self.varnodes.len()
    }

    /// Get a specific varnode by index.
    pub fn varnode(&self, index: usize) -> Option<&VarnodeInfo> {
        self.varnodes.get(index)
    }

    /// Get a mutable reference to a specific varnode.
    pub fn varnode_mut(&mut self, index: usize) -> Option<&mut VarnodeInfo> {
        self.varnodes.get_mut(index)
    }

    /// Get the required total size.
    pub fn required_size(&self) -> usize {
        self.required_size
    }

    /// Set the required total size.
    pub fn set_required_size(&mut self, size: usize) {
        self.required_size = size;
        self.unconstrained = size == 0;
        self.validate();
    }

    /// Whether the storage is unconstrained.
    pub fn is_unconstrained(&self) -> bool {
        self.unconstrained
    }

    /// Get the selected row indices.
    pub fn selected_rows(&self) -> &[usize] {
        &self.selected_rows
    }

    /// Set the selected row indices.
    pub fn set_selected_rows(&mut self, rows: Vec<usize>) {
        // Clamp to valid range
        self.selected_rows = rows
            .into_iter()
            .filter(|r| *r < self.varnodes.len())
            .collect();
    }

    /// Get the auto-parameter count.
    pub fn auto_param_count(&self) -> usize {
        self.auto_param_count
    }

    /// Set the auto-parameter count.
    pub fn set_auto_param_count(&mut self, count: usize) {
        self.auto_param_count = count;
    }

    /// Add a new varnode at the end.
    pub fn add_varnode(&mut self, varnode: VarnodeInfo) {
        self.varnodes.push(varnode);
        let new_index = self.varnodes.len() - 1;
        self.selected_rows = vec![new_index];
        self.validate();
    }

    /// Remove the selected varnodes.
    ///
    /// Returns the number of varnodes removed.
    pub fn remove_selected(&mut self) -> usize {
        if !self.can_remove() {
            return 0;
        }

        let mut sorted: Vec<usize> = self.selected_rows.clone();
        sorted.sort_unstable_by(|a, b| b.cmp(a)); // descending

        let count = sorted.len();
        for &idx in &sorted {
            if idx < self.varnodes.len() {
                self.varnodes.remove(idx);
            }
        }

        // Adjust selection
        if self.varnodes.is_empty() {
            self.selected_rows.clear();
        } else {
            let select = self.selected_rows.iter().min().copied().unwrap_or(0);
            let select = select.min(self.varnodes.len() - 1);
            self.selected_rows = vec![select];
        }

        self.validate();
        count
    }

    /// Whether the selected varnodes can be removed.
    pub fn can_remove(&self) -> bool {
        !self.selected_rows.is_empty()
            && self
                .selected_rows
                .iter()
                .all(|r| *r < self.varnodes.len())
    }

    /// Whether the selected varnode can be moved up.
    pub fn can_move_up(&self) -> bool {
        self.selected_rows.len() == 1
            && !self.selected_rows.is_empty()
            && self.selected_rows[0] > 0
    }

    /// Whether the selected varnode can be moved down.
    pub fn can_move_down(&self) -> bool {
        self.selected_rows.len() == 1
            && !self.selected_rows.is_empty()
            && self.selected_rows[0] + 1 < self.varnodes.len()
    }

    /// Move the selected varnode up (swap with previous).
    pub fn move_up(&mut self) -> bool {
        if !self.can_move_up() {
            return false;
        }
        let idx = self.selected_rows[0];
        self.varnodes.swap(idx, idx - 1);
        self.selected_rows = vec![idx - 1];
        self.validate();
        true
    }

    /// Move the selected varnode down (swap with next).
    pub fn move_down(&mut self) -> bool {
        if !self.can_move_down() {
            return false;
        }
        let idx = self.selected_rows[0];
        self.varnodes.swap(idx, idx + 1);
        self.selected_rows = vec![idx + 1];
        self.validate();
        true
    }

    /// Get the total size of all varnodes.
    pub fn total_size(&self) -> usize {
        self.varnodes.iter().map(|v| v.size()).sum()
    }

    /// Get the validation status text.
    pub fn status_text(&self) -> &str {
        &self.status_text
    }

    /// Whether the current configuration is valid.
    pub fn is_valid(&self) -> bool {
        self.is_valid
    }

    /// Validate the current storage configuration.
    fn validate(&mut self) {
        if self.varnodes.is_empty() {
            if self.unconstrained {
                self.is_valid = true;
                self.status_text = "Unconstrained - no storage assigned".to_string();
            } else {
                self.is_valid = false;
                self.status_text = "No storage assigned".to_string();
            }
            return;
        }

        let total = self.total_size();

        if self.unconstrained {
            self.is_valid = true;
            self.status_text = format!("{} byte(s) assigned", total);
            return;
        }

        // Check for overlaps in register storage
        let has_overlap = self.has_register_overlap();
        if has_overlap {
            self.is_valid = false;
            self.status_text = "Register storage overlaps detected".to_string();
            return;
        }

        if total == self.required_size {
            self.is_valid = true;
            self.status_text = format!("Storage matches required size ({} bytes)", total);
        } else if total < self.required_size {
            self.is_valid = false;
            self.status_text = format!(
                "Storage is {} byte(s), needs {} byte(s)",
                total, self.required_size
            );
        } else {
            self.is_valid = false;
            self.status_text = format!(
                "Storage exceeds required size: {} > {} byte(s)",
                total, self.required_size
            );
        }
    }

    /// Check whether any register varnodes overlap.
    fn has_register_overlap(&self) -> bool {
        // Only check register-type varnodes for overlaps
        let registers: Vec<&VarnodeInfo> = self
            .varnodes
            .iter()
            .filter(|v| v.varnode_type() == VarnodeType::Register)
            .collect();

        for i in 0..registers.len() {
            for j in (i + 1)..registers.len() {
                let a = registers[i];
                let b = registers[j];
                // Same register name and overlapping offsets
                if a.name() == b.name() {
                    return true;
                }
            }
        }
        false
    }

    /// Clear all varnodes.
    pub fn clear(&mut self) {
        self.varnodes.clear();
        self.selected_rows.clear();
        self.validate();
    }

    /// Set the storage from a list of varnodes.
    pub fn set_varnodes(&mut self, varnodes: Vec<VarnodeInfo>) {
        self.varnodes = varnodes;
        self.selected_rows.clear();
        if !self.varnodes.is_empty() {
            self.selected_rows.push(0);
        }
        self.validate();
    }
}

impl Default for StorageAddressModel {
    fn default() -> Self {
        Self::new(0)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_model() {
        let model = StorageAddressModel::new(8);
        assert_eq!(model.required_size(), 8);
        assert!(!model.is_unconstrained());
        assert_eq!(model.varnode_count(), 0);
        assert!(!model.is_valid());
    }

    #[test]
    fn test_unconstrained_model() {
        let model = StorageAddressModel::new(0);
        assert!(model.is_unconstrained());
        assert!(model.is_valid());
    }

    #[test]
    fn test_add_varnode() {
        let mut model = StorageAddressModel::new(8);
        model.add_varnode(VarnodeInfo::register("RAX", 8));
        assert_eq!(model.varnode_count(), 1);
        assert!(model.is_valid());
        assert_eq!(model.total_size(), 8);
    }

    #[test]
    fn test_add_multiple_varnodes() {
        let mut model = StorageAddressModel::new(16);
        model.add_varnode(VarnodeInfo::register("RDI", 8));
        model.add_varnode(VarnodeInfo::register("RSI", 8));
        assert_eq!(model.varnode_count(), 2);
        assert_eq!(model.total_size(), 16);
        assert!(model.is_valid());
    }

    #[test]
    fn test_remove_selected() {
        let mut model = StorageAddressModel::new(8);
        model.add_varnode(VarnodeInfo::register("RAX", 8));
        model.set_selected_rows(vec![0]);
        let removed = model.remove_selected();
        assert_eq!(removed, 1);
        assert_eq!(model.varnode_count(), 0);
    }

    #[test]
    fn test_move_up_down() {
        let mut model = StorageAddressModel::new(16);
        model.add_varnode(VarnodeInfo::register("RAX", 8));
        model.add_varnode(VarnodeInfo::register("RBX", 8));
        model.set_selected_rows(vec![1]);

        assert!(model.can_move_up());
        assert!(!model.can_move_down());

        model.move_up();
        assert_eq!(model.selected_rows(), &[0]);
        assert_eq!(model.varnode(0).unwrap().name(), "RBX");
        assert_eq!(model.varnode(1).unwrap().name(), "RAX");
    }

    #[test]
    fn test_size_mismatch() {
        let mut model = StorageAddressModel::new(16);
        model.add_varnode(VarnodeInfo::register("RAX", 8));
        assert!(!model.is_valid());
        assert!(model.status_text().contains("needs"));
    }

    #[test]
    fn test_from_varnodes() {
        let varnodes = vec![
            VarnodeInfo::register("RDI", 8),
            VarnodeInfo::register("RSI", 8),
        ];
        let model = StorageAddressModel::from_varnodes(varnodes, 16);
        assert_eq!(model.varnode_count(), 2);
        assert!(model.is_valid());
    }

    #[test]
    fn test_clear() {
        let mut model = StorageAddressModel::new(8);
        model.add_varnode(VarnodeInfo::register("RAX", 8));
        model.clear();
        assert_eq!(model.varnode_count(), 0);
        assert!(model.selected_rows().is_empty());
    }

    #[test]
    fn test_set_varnodes() {
        let mut model = StorageAddressModel::new(8);
        model.set_varnodes(vec![
            VarnodeInfo::register("RDI", 4),
            VarnodeInfo::stack(0, 4),
        ]);
        assert_eq!(model.varnode_count(), 2);
        assert_eq!(model.total_size(), 8);
    }

    #[test]
    fn test_default() {
        let model = StorageAddressModel::default();
        assert_eq!(model.required_size(), 0);
        assert!(model.is_unconstrained());
    }

    #[test]
    fn test_stack_storage() {
        let mut model = StorageAddressModel::new(4);
        model.add_varnode(VarnodeInfo::stack(-8, 4));
        assert!(model.is_valid());
        assert_eq!(model.total_size(), 4);
    }

    #[test]
    fn test_memory_storage() {
        let mut model = StorageAddressModel::new(8);
        model.add_varnode(VarnodeInfo::memory(0x100000, 8));
        assert!(model.is_valid());
        assert_eq!(model.total_size(), 8);
    }

    #[test]
    fn test_mixed_storage() {
        let mut model = StorageAddressModel::new(12);
        model.add_varnode(VarnodeInfo::register("RDI", 8));
        model.add_varnode(VarnodeInfo::stack(0, 4));
        assert_eq!(model.total_size(), 12);
        assert!(model.is_valid());
    }

    #[test]
    fn test_can_move_up_first() {
        let mut model = StorageAddressModel::new(0);
        model.add_varnode(VarnodeInfo::register("RAX", 8));
        model.set_selected_rows(vec![0]);
        assert!(!model.can_move_up());
    }

    #[test]
    fn test_auto_param_count() {
        let mut model = StorageAddressModel::new(8);
        model.set_auto_param_count(2);
        assert_eq!(model.auto_param_count(), 2);
    }
}
