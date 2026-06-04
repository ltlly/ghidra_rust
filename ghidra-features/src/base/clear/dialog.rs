//! Clear dialog validation model — validates parameters for clear operations.
//!
//! Ported from `ClearDialog` and `ClearFlowDialog` in Ghidra's
//! `ghidra.app.plugin.core.clear`.
//!
//! This module provides [`ClearDialogModel`], which manages the
//! validation logic for the clear-code dialog. The dialog lets the
//! user select which program elements to clear (instructions, data,
//! labels, comments, references, equates, properties) over an address
//! range or selection.
//!
//! GUI code is not ported; only the data model and validation are
//! provided.

/// What to clear in a clear operation.
///
/// Each variant corresponds to a checkbox in the Clear dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClearElementType {
    /// Clear code units (instructions and data).
    CodeUnits,
    /// Clear labels (symbols at addresses).
    Labels,
    /// Clear comments (pre, post, end-of-line, plate).
    Comments,
    /// Clear references (to and from addresses).
    References,
    /// Clear equates.
    Equates,
    /// Clear properties (user-defined property maps).
    Properties,
    /// Clear functions (function definitions).
    Functions,
}

impl ClearElementType {
    /// All clear element types in display order.
    pub const ALL: [ClearElementType; 7] = [
        Self::CodeUnits,
        Self::Labels,
        Self::Comments,
        Self::References,
        Self::Equates,
        Self::Properties,
        Self::Functions,
    ];

    /// Human-readable name for this element type.
    pub fn name(&self) -> &'static str {
        match self {
            Self::CodeUnits => "Code Units",
            Self::Labels => "Labels",
            Self::Comments => "Comments",
            Self::References => "References",
            Self::Equates => "Equates",
            Self::Properties => "Properties",
            Self::Functions => "Functions",
        }
    }
}

/// Model for the clear dialog.
///
/// Manages the set of element types to clear and the address context.
/// Validates that at least one element type is selected before the
/// operation can proceed.
#[derive(Debug, Clone)]
pub struct ClearDialogModel {
    /// Which element types are selected for clearing.
    selected_types: Vec<ClearElementType>,
    /// Whether the clear operation applies to the whole selection.
    apply_to_selection: bool,
    /// Current status message (empty if valid).
    message: String,
}

impl ClearDialogModel {
    /// Create a new clear dialog model with default selections.
    ///
    /// By default, all element types are selected.
    pub fn new() -> Self {
        Self {
            selected_types: ClearElementType::ALL.to_vec(),
            apply_to_selection: true,
            message: String::new(),
        }
    }

    /// Create a model with no elements selected.
    pub fn empty() -> Self {
        Self {
            selected_types: Vec::new(),
            apply_to_selection: true,
            message: String::new(),
        }
    }

    /// Toggle a specific element type on/off.
    pub fn toggle(&mut self, element_type: ClearElementType) {
        if let Some(pos) = self.selected_types.iter().position(|e| *e == element_type) {
            self.selected_types.remove(pos);
        } else {
            self.selected_types.push(element_type);
        }
    }

    /// Select a specific element type.
    pub fn select(&mut self, element_type: ClearElementType) {
        if !self.selected_types.contains(&element_type) {
            self.selected_types.push(element_type);
        }
    }

    /// Deselect a specific element type.
    pub fn deselect(&mut self, element_type: ClearElementType) {
        self.selected_types.retain(|e| *e != element_type);
    }

    /// Whether a specific element type is selected.
    pub fn is_selected(&self, element_type: ClearElementType) -> bool {
        self.selected_types.contains(&element_type)
    }

    /// Get the selected element types.
    pub fn selected_types(&self) -> &[ClearElementType] {
        &self.selected_types
    }

    /// Whether any element type is selected.
    pub fn has_selection(&self) -> bool {
        !self.selected_types.is_empty()
    }

    /// Set whether the operation applies to the selection.
    pub fn set_apply_to_selection(&mut self, apply: bool) {
        self.apply_to_selection = apply;
    }

    /// Whether the operation applies to the selection.
    pub fn applies_to_selection(&self) -> bool {
        self.apply_to_selection
    }

    /// Get the current status message (empty if valid).
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Validate the dialog state.
    ///
    /// Returns `Ok(())` if at least one element type is selected,
    /// or an error message.
    pub fn validate(&mut self) -> Result<(), String> {
        if self.selected_types.is_empty() {
            self.message = "Please select at least one element type to clear".into();
            return Err(self.message.clone());
        }
        self.message.clear();
        Ok(())
    }

    /// Whether the OK button should be enabled.
    pub fn is_ok_enabled(&self) -> bool {
        !self.selected_types.is_empty()
    }
}

impl Default for ClearDialogModel {
    fn default() -> Self {
        Self::new()
    }
}

/// Model for the clear-flow dialog.
///
/// Manages options specific to the "Clear Flow and Repair" dialog,
/// which extends the basic clear with flow repair options.
#[derive(Debug, Clone)]
pub struct ClearFlowDialogModel {
    /// Base clear dialog model.
    base: ClearDialogModel,
    /// Whether to repair disassembly flow after clearing.
    repair_flow: bool,
    /// Whether to clear following instructions (those reached only
    /// from the cleared address).
    clear_following: bool,
}

impl ClearFlowDialogModel {
    /// Create a new clear-flow dialog model.
    pub fn new() -> Self {
        Self {
            base: ClearDialogModel::new(),
            repair_flow: true,
            clear_following: false,
        }
    }

    /// Get the base clear model.
    pub fn base(&self) -> &ClearDialogModel {
        &self.base
    }

    /// Get a mutable reference to the base clear model.
    pub fn base_mut(&mut self) -> &mut ClearDialogModel {
        &mut self.base
    }

    /// Set whether to repair flow.
    pub fn set_repair_flow(&mut self, repair: bool) {
        self.repair_flow = repair;
    }

    /// Whether flow repair is enabled.
    pub fn repair_flow(&self) -> bool {
        self.repair_flow
    }

    /// Set whether to clear following instructions.
    pub fn set_clear_following(&mut self, clear: bool) {
        self.clear_following = clear;
    }

    /// Whether following instructions will be cleared.
    pub fn clear_following(&self) -> bool {
        self.clear_following
    }

    /// Validate the dialog state.
    pub fn validate(&mut self) -> Result<(), String> {
        self.base.validate()
    }
}

impl Default for ClearFlowDialogModel {
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
    fn test_new_model_has_all_selected() {
        let model = ClearDialogModel::new();
        assert_eq!(model.selected_types().len(), ClearElementType::ALL.len());
        for t in &ClearElementType::ALL {
            assert!(model.is_selected(*t));
        }
    }

    #[test]
    fn test_empty_model_has_none_selected() {
        let model = ClearDialogModel::empty();
        assert!(model.selected_types().is_empty());
        assert!(!model.has_selection());
    }

    #[test]
    fn test_toggle_deselects() {
        let mut model = ClearDialogModel::new();
        assert!(model.is_selected(ClearElementType::CodeUnits));
        model.toggle(ClearElementType::CodeUnits);
        assert!(!model.is_selected(ClearElementType::CodeUnits));
    }

    #[test]
    fn test_toggle_selects() {
        let mut model = ClearDialogModel::empty();
        assert!(!model.is_selected(ClearElementType::Labels));
        model.toggle(ClearElementType::Labels);
        assert!(model.is_selected(ClearElementType::Labels));
    }

    #[test]
    fn test_select_and_deselect() {
        let mut model = ClearDialogModel::empty();
        model.select(ClearElementType::Comments);
        assert!(model.is_selected(ClearElementType::Comments));
        model.deselect(ClearElementType::Comments);
        assert!(!model.is_selected(ClearElementType::Comments));
    }

    #[test]
    fn test_select_idempotent() {
        let mut model = ClearDialogModel::empty();
        model.select(ClearElementType::References);
        model.select(ClearElementType::References);
        assert_eq!(model.selected_types().len(), 1);
    }

    #[test]
    fn test_validate_with_selection_succeeds() {
        let mut model = ClearDialogModel::new();
        assert!(model.validate().is_ok());
        assert!(model.message().is_empty());
    }

    #[test]
    fn test_validate_without_selection_fails() {
        let mut model = ClearDialogModel::empty();
        let result = model.validate();
        assert!(result.is_err());
        assert!(!model.message().is_empty());
    }

    #[test]
    fn test_is_ok_enabled() {
        let mut model = ClearDialogModel::new();
        assert!(model.is_ok_enabled());
        model.deselect(ClearElementType::CodeUnits);
        assert!(model.is_ok_enabled()); // still has others
        for t in &ClearElementType::ALL {
            model.deselect(*t);
        }
        assert!(!model.is_ok_enabled());
    }

    #[test]
    fn test_apply_to_selection() {
        let mut model = ClearDialogModel::new();
        assert!(model.applies_to_selection());
        model.set_apply_to_selection(false);
        assert!(!model.applies_to_selection());
    }

    #[test]
    fn test_default_model() {
        let model = ClearDialogModel::default();
        assert!(model.has_selection());
        assert!(model.applies_to_selection());
    }

    #[test]
    fn test_element_type_name() {
        assert_eq!(ClearElementType::CodeUnits.name(), "Code Units");
        assert_eq!(ClearElementType::References.name(), "References");
    }

    #[test]
    fn test_clear_flow_dialog_model() {
        let mut model = ClearFlowDialogModel::new();
        assert!(model.repair_flow());
        assert!(!model.clear_following());
        assert!(model.validate().is_ok());

        model.set_repair_flow(false);
        assert!(!model.repair_flow());

        model.set_clear_following(true);
        assert!(model.clear_following());
    }

    #[test]
    fn test_clear_flow_dialog_base_mut() {
        let mut model = ClearFlowDialogModel::new();
        model.base_mut().deselect(ClearElementType::CodeUnits);
        assert!(!model.base().is_selected(ClearElementType::CodeUnits));
    }

    #[test]
    fn test_clear_flow_dialog_validate_empty() {
        let mut model = ClearFlowDialogModel::new();
        for t in &ClearElementType::ALL {
            model.base_mut().deselect(*t);
        }
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_clear_flow_dialog_default() {
        let model = ClearFlowDialogModel::default();
        assert!(model.repair_flow());
        assert!(model.base().has_selection());
    }
}
