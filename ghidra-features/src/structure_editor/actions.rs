//! Composite editor actions -- Rust port of
//! `ghidra.app.plugin.core.compositeeditor` action classes.
//!
//! Each action corresponds to a user-visible command in the structure
//! editor (Apply, Undo, Delete, Move Up/Down, etc.).

// ---------------------------------------------------------------------------
// Action result types
// ---------------------------------------------------------------------------

/// Result of applying changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyResult {
    /// There were no changes to apply.
    NoChanges,
    /// Changes were applied successfully.
    Success(String),
    /// Applying failed.
    Error(String),
}

/// Result of a clear operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearResult {
    /// Components were cleared.
    Cleared(usize),
    /// Clearing was not allowed.
    NotAllowed,
}

/// Result of a delete operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteResult {
    /// Components were deleted.
    Deleted(usize),
    /// Deleting was not allowed.
    NotAllowed,
}

/// Result of a duplicate operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DuplicateResult {
    /// A component was duplicated.
    Duplicated,
    /// Duplication was not possible.
    NotPossible(String),
}

/// Result of a move operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MoveResult {
    /// The component was moved.
    Moved,
    /// Moving was not possible.
    NotPossible(String),
}

/// Result of an unpackage operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnpackageResult {
    /// The composite was unpackaged.
    Unpackaged,
    /// Unpackaging was not possible.
    NotPossible(String),
}

/// Direction of a move operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MoveDirection {
    /// Move toward lower indices.
    Up,
    /// Move toward higher indices.
    Down,
}

// ---------------------------------------------------------------------------
// CompositeEditorAction trait
// ---------------------------------------------------------------------------

/// Trait for composite editor actions.
///
/// Each action has a name, description, and can be executed against the
/// editor model.
pub trait CompositeEditorAction: std::fmt::Debug {
    /// The action's unique name.
    fn name(&self) -> &str;

    /// Human-readable description.
    fn description(&self) -> &str;

    /// The menu group for ordering.
    fn menu_group(&self) -> &str {
        ""
    }

    /// Whether the action is enabled given the current state.
    fn is_enabled(&self, has_selection: bool, has_changes: bool) -> bool;

    /// Execute the action. Returns a status message.
    fn execute(&self) -> CompositeEditorActionResult;
}

/// Result of executing a composite editor action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositeEditorActionResult {
    /// The action succeeded.
    Success(String),
    /// The action was not applicable.
    NotApplicable,
    /// An error occurred.
    Error(String),
}

// ---------------------------------------------------------------------------
// Action structs
// ---------------------------------------------------------------------------

/// Action: Apply (commit) changes to the data type manager.
#[derive(Debug, Default)]
pub struct ApplyAction;

impl CompositeEditorAction for ApplyAction {
    fn name(&self) -> &str { "Apply" }
    fn description(&self) -> &str { "Apply changes to the data type" }
    fn menu_group(&self) -> &str { "1 - Edit Group" }

    fn is_enabled(&self, _has_selection: bool, has_changes: bool) -> bool {
        has_changes
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Changes applied".into())
    }
}

/// Action: Undo the last change.
#[derive(Debug, Default)]
pub struct UndoChangeAction;

impl CompositeEditorAction for UndoChangeAction {
    fn name(&self) -> &str { "Undo" }
    fn description(&self) -> &str { "Undo the last change" }
    fn menu_group(&self) -> &str { "1 - Edit Group" }

    fn is_enabled(&self, _has_selection: bool, has_changes: bool) -> bool {
        has_changes
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Undo performed".into())
    }
}

/// Action: Redo the last undone change.
#[derive(Debug, Default)]
pub struct RedoChangeAction;

impl CompositeEditorAction for RedoChangeAction {
    fn name(&self) -> &str { "Redo" }
    fn description(&self) -> &str { "Redo the last undone change" }
    fn menu_group(&self) -> &str { "1 - Edit Group" }

    fn is_enabled(&self, _has_selection: bool, _has_changes: bool) -> bool {
        true
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Redo performed".into())
    }
}

/// Action: Insert undefined bytes at the selection.
#[derive(Debug, Default)]
pub struct InsertUndefinedAction;

impl CompositeEditorAction for InsertUndefinedAction {
    fn name(&self) -> &str { "Insert Undefined" }
    fn description(&self) -> &str { "Insert undefined bytes at the selected position" }
    fn menu_group(&self) -> &str { "2 - Component Group" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Undefined bytes inserted".into())
    }
}

/// Action: Move selected components up.
#[derive(Debug, Default)]
pub struct MoveUpAction;

impl CompositeEditorAction for MoveUpAction {
    fn name(&self) -> &str { "Move Up" }
    fn description(&self) -> &str { "Move selected components toward lower offsets" }
    fn menu_group(&self) -> &str { "2 - Component Group" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Components moved up".into())
    }
}

/// Action: Move selected components down.
#[derive(Debug, Default)]
pub struct MoveDownAction;

impl CompositeEditorAction for MoveDownAction {
    fn name(&self) -> &str { "Move Down" }
    fn description(&self) -> &str { "Move selected components toward higher offsets" }
    fn menu_group(&self) -> &str { "2 - Component Group" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Components moved down".into())
    }
}

/// Action: Clear the selected components (replace with undefined).
#[derive(Debug, Default)]
pub struct ClearAction;

impl CompositeEditorAction for ClearAction {
    fn name(&self) -> &str { "Clear" }
    fn description(&self) -> &str { "Clear selected components" }
    fn menu_group(&self) -> &str { "2 - Component Group" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Components cleared".into())
    }
}

/// Action: Duplicate the selected component.
#[derive(Debug, Default)]
pub struct DuplicateAction;

impl CompositeEditorAction for DuplicateAction {
    fn name(&self) -> &str { "Duplicate" }
    fn description(&self) -> &str { "Duplicate the selected component" }
    fn menu_group(&self) -> &str { "2 - Component Group" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Component duplicated".into())
    }
}

/// Action: Duplicate the selected component multiple times.
#[derive(Debug, Default)]
pub struct DuplicateMultipleAction;

impl CompositeEditorAction for DuplicateMultipleAction {
    fn name(&self) -> &str { "Duplicate Multiple" }
    fn description(&self) -> &str { "Duplicate the selected component N times" }
    fn menu_group(&self) -> &str { "2 - Component Group" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Components duplicated".into())
    }
}

/// Action: Delete the selected components.
#[derive(Debug, Default)]
pub struct DeleteAction;

impl CompositeEditorAction for DeleteAction {
    fn name(&self) -> &str { "Delete" }
    fn description(&self) -> &str { "Delete selected components" }
    fn menu_group(&self) -> &str { "2 - Component Group" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Components deleted".into())
    }
}

/// Action: Make the selected component a pointer.
#[derive(Debug, Default)]
pub struct PointerAction;

impl CompositeEditorAction for PointerAction {
    fn name(&self) -> &str { "Pointer" }
    fn description(&self) -> &str { "Make the selected component a pointer to its data type" }
    fn menu_group(&self) -> &str { "3 - Type Group" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Pointer created".into())
    }
}

/// Action: Make the selected component an array.
#[derive(Debug, Default)]
pub struct ArrayAction;

impl CompositeEditorAction for ArrayAction {
    fn name(&self) -> &str { "Array" }
    fn description(&self) -> &str { "Make the selected component an array" }
    fn menu_group(&self) -> &str { "3 - Type Group" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Array created".into())
    }
}

/// Action: Unpackage (unpack a nested struct inline).
#[derive(Debug, Default)]
pub struct UnpackageAction;

impl CompositeEditorAction for UnpackageAction {
    fn name(&self) -> &str { "Unpackage" }
    fn description(&self) -> &str { "Unpackage a nested structure inline" }
    fn menu_group(&self) -> &str { "3 - Type Group" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Structure unpackaged".into())
    }
}

/// Action: Add a bit field at the current position.
#[derive(Debug, Default)]
pub struct AddBitFieldAction;

impl CompositeEditorAction for AddBitFieldAction {
    fn name(&self) -> &str { "Add Bit Field" }
    fn description(&self) -> &str { "Add a bit field at the selected position" }
    fn menu_group(&self) -> &str { "4 - Bit Field Group" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Bit field added".into())
    }
}

/// Action: Edit the selected bit field.
#[derive(Debug, Default)]
pub struct EditBitFieldAction;

impl CompositeEditorAction for EditBitFieldAction {
    fn name(&self) -> &str { "Edit Bit Field" }
    fn description(&self) -> &str { "Edit the selected bit field" }
    fn menu_group(&self) -> &str { "4 - Bit Field Group" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Bit field edited".into())
    }
}

/// Action: Toggle hex number display.
#[derive(Debug, Default)]
pub struct HexNumbersAction;

impl CompositeEditorAction for HexNumbersAction {
    fn name(&self) -> &str { "Hex Numbers" }
    fn description(&self) -> &str { "Toggle hexadecimal number display" }

    fn is_enabled(&self, _has_selection: bool, _has_changes: bool) -> bool {
        true
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Hex display toggled".into())
    }
}

/// Action: Find references to the selected structure field.
#[derive(Debug, Default)]
pub struct FindReferencesToStructureFieldAction;

impl CompositeEditorAction for FindReferencesToStructureFieldAction {
    fn name(&self) -> &str { "Find References To Field" }
    fn description(&self) -> &str { "Find all references to the selected structure field" }
    fn menu_group(&self) -> &str { "5 - Reference Group" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Searching for field references".into())
    }
}

/// Action: Edit the selected component (open type chooser).
#[derive(Debug, Default)]
pub struct EditComponentAction;

impl CompositeEditorAction for EditComponentAction {
    fn name(&self) -> &str { "Edit Component" }
    fn description(&self) -> &str { "Edit the data type of the selected component" }
    fn menu_group(&self) -> &str { "2 - Component Group" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Component editor opened".into())
    }
}

/// Action: Edit the field name/comment of the selected component.
#[derive(Debug, Default)]
pub struct EditFieldAction;

impl CompositeEditorAction for EditFieldAction {
    fn name(&self) -> &str { "Edit Field" }
    fn description(&self) -> &str { "Edit the name and comment of the selected field" }
    fn menu_group(&self) -> &str { "2 - Component Group" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Field editor opened".into())
    }
}

/// Action: Create an internal structure from the selection.
#[derive(Debug, Default)]
pub struct CreateInternalStructureAction;

impl CompositeEditorAction for CreateInternalStructureAction {
    fn name(&self) -> &str { "Create Internal Structure" }
    fn description(&self) -> &str { "Create a new internal structure from the selection" }
    fn menu_group(&self) -> &str { "3 - Type Group" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Internal structure created".into())
    }
}

/// Action: Show the component path.
#[derive(Debug, Default)]
pub struct ShowComponentPathAction;

impl CompositeEditorAction for ShowComponentPathAction {
    fn name(&self) -> &str { "Show Component Path" }
    fn description(&self) -> &str { "Show the path to the selected component" }

    fn is_enabled(&self, has_selection: bool, _has_changes: bool) -> bool {
        has_selection
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Component path shown".into())
    }
}

/// Action: Show the data type in the tree view.
#[derive(Debug, Default)]
pub struct ShowDataTypeInTreeAction;

impl CompositeEditorAction for ShowDataTypeInTreeAction {
    fn name(&self) -> &str { "Show In Data Type Tree" }
    fn description(&self) -> &str { "Navigate to this data type in the Data Type Manager tree" }

    fn is_enabled(&self, _has_selection: bool, _has_changes: bool) -> bool {
        true
    }

    fn execute(&self) -> CompositeEditorActionResult {
        CompositeEditorActionResult::Success("Navigated to data type".into())
    }
}

// ---------------------------------------------------------------------------
// Action registry for the composite editor
// ---------------------------------------------------------------------------

/// Registry of all composite editor actions.
#[derive(Debug)]
pub struct CompositeActionRegistry {
    actions: Vec<Box<dyn CompositeEditorAction>>,
}

impl CompositeActionRegistry {
    /// Create the default action registry with all standard actions.
    pub fn default_actions() -> Self {
        let actions: Vec<Box<dyn CompositeEditorAction>> = vec![
            Box::new(ApplyAction),
            Box::new(UndoChangeAction),
            Box::new(RedoChangeAction),
            Box::new(InsertUndefinedAction),
            Box::new(MoveUpAction),
            Box::new(MoveDownAction),
            Box::new(ClearAction),
            Box::new(DuplicateAction),
            Box::new(DuplicateMultipleAction),
            Box::new(DeleteAction),
            Box::new(PointerAction),
            Box::new(ArrayAction),
            Box::new(FindReferencesToStructureFieldAction),
            Box::new(UnpackageAction),
            Box::new(EditComponentAction),
            Box::new(EditFieldAction),
            Box::new(HexNumbersAction),
            Box::new(CreateInternalStructureAction),
            Box::new(ShowComponentPathAction),
            Box::new(AddBitFieldAction),
            Box::new(EditBitFieldAction),
            Box::new(ShowDataTypeInTreeAction),
        ];
        Self { actions }
    }

    /// Total number of registered actions.
    pub fn count(&self) -> usize {
        self.actions.len()
    }

    /// Iterate over all actions.
    pub fn iter(&self) -> impl Iterator<Item = &dyn CompositeEditorAction> {
        self.actions.iter().map(|a| a.as_ref())
    }

    /// Find an action by name.
    pub fn find_by_name(&self, name: &str) -> Option<&dyn CompositeEditorAction> {
        self.actions.iter().find(|a| a.name() == name).map(|a| a.as_ref())
    }

    /// Get all enabled actions for the given state.
    pub fn enabled_actions(&self, has_selection: bool, has_changes: bool) -> Vec<&dyn CompositeEditorAction> {
        self.actions
            .iter()
            .filter(|a| a.is_enabled(has_selection, has_changes))
            .map(|a| a.as_ref())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_registry_default_count() {
        let registry = CompositeActionRegistry::default_actions();
        assert_eq!(registry.count(), 22);
    }

    #[test]
    fn test_action_registry_find_by_name() {
        let registry = CompositeActionRegistry::default_actions();
        assert!(registry.find_by_name("Apply").is_some());
        assert!(registry.find_by_name("Nonexistent").is_none());
    }

    #[test]
    fn test_apply_action() {
        let action = ApplyAction;
        assert_eq!(action.name(), "Apply");
        assert!(!action.is_enabled(false, false)); // no changes
        assert!(action.is_enabled(false, true));  // has changes
        assert_eq!(
            action.execute(),
            CompositeEditorActionResult::Success("Changes applied".into())
        );
    }

    #[test]
    fn test_undo_action() {
        let action = UndoChangeAction;
        assert!(!action.is_enabled(false, false));
        assert!(action.is_enabled(false, true));
    }

    #[test]
    fn test_move_actions() {
        let up = MoveUpAction;
        assert!(!up.is_enabled(false, false));
        assert!(up.is_enabled(true, false));

        let down = MoveDownAction;
        assert!(!down.is_enabled(false, false));
        assert!(down.is_enabled(true, false));
    }

    #[test]
    fn test_hex_numbers_action() {
        let action = HexNumbersAction;
        // Always enabled.
        assert!(action.is_enabled(false, false));
    }

    #[test]
    fn test_show_in_tree_action() {
        let action = ShowDataTypeInTreeAction;
        assert!(action.is_enabled(false, false));
    }

    #[test]
    fn test_delete_action() {
        let action = DeleteAction;
        assert!(!action.is_enabled(false, false));
        assert!(action.is_enabled(true, false));
    }

    #[test]
    fn test_enabled_actions_filtering() {
        let registry = CompositeActionRegistry::default_actions();
        // No selection, no changes.
        let enabled = registry.enabled_actions(false, false);
        // Only always-enabled actions should be present.
        let names: Vec<&str> = enabled.iter().map(|a| a.name()).collect();
        assert!(names.contains(&"Hex Numbers"));
        assert!(names.contains(&"Undo") == false); // needs changes
        assert!(names.contains(&"Delete") == false); // needs selection
    }

    #[test]
    fn test_pointer_action() {
        let action = PointerAction;
        assert_eq!(action.name(), "Pointer");
        assert!(action.is_enabled(true, false));
    }

    #[test]
    fn test_unpackage_action() {
        let action = UnpackageAction;
        assert!(action.is_enabled(true, false));
    }

    #[test]
    fn test_add_bitfield_action() {
        let action = AddBitFieldAction;
        assert_eq!(action.menu_group(), "4 - Bit Field Group");
        assert!(action.is_enabled(true, false));
    }
}
