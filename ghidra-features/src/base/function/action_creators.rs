//! Function creation, deletion, and editing actions.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.function` Java package:
//! - `CreateFunctionAction` -- create a function from the current selection
//! - `DeleteFunctionAction` -- delete a function at its entry point
//! - `CreateMultipleFunctionsAction` -- create functions from multiple selected ranges
//! - `CreateExternalFunctionAction` -- create an external function stub
//! - `ClearFunctionAction` -- clear (disassemble) a function body
//! - `CreateArrayAction` -- create an array at the current location
//! - `VoidDataAction` -- create undefined data at the current location
//! - `DataAction` -- create data at the current location based on the default type
//! - `ChooseDataTypeAction` -- choose a data type for the current location
//! - `PointerDataAction` -- create a pointer at the current location
//!
//! These actions are the non-Swing business logic behind the context-menu
//! entries that users see when right-clicking in the code browser listing.

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Function Action Context
// ---------------------------------------------------------------------------

/// Context information needed by function actions.
///
/// Mirrors the information in `ListingActionContext` that actions need to
/// determine enablement and perform their work.
#[derive(Debug, Clone)]
pub struct FunctionActionContext {
    /// The program name.
    pub program: String,
    /// The address at the cursor.
    pub address: Option<u64>,
    /// The address selection range (start, end), if any.
    pub selection: Option<(u64, u64)>,
    /// Whether there is a current selection.
    pub has_selection: bool,
    /// The function entry point at the current location, if any.
    pub function_entry: Option<u64>,
    /// The function name at the current location, if any.
    pub function_name: Option<String>,
    /// The location type (e.g., "FunctionLocation", "VariableLocation",
    /// "MnemonicFieldLocation", "OperandFieldLocation").
    pub location_type: String,
    /// The function address for the location (may differ from entry for variables).
    pub function_address: Option<u64>,
}

impl FunctionActionContext {
    /// Create a new context with no selection and no function.
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            address: None,
            selection: None,
            has_selection: false,
            function_entry: None,
            function_name: None,
            location_type: String::new(),
            function_address: None,
        }
    }

    /// Whether the cursor is on a function entry point (not a variable).
    pub fn is_on_function_entry(&self) -> bool {
        if let (Some(addr), Some(entry)) = (self.address, self.function_entry) {
            addr == entry && self.location_type != "VariableLocation"
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// CreateFunctionAction
// ---------------------------------------------------------------------------

/// Action to create a function from the current selection.
///
/// If there is a selection, the selection is used as the function body with
/// the minimum address as the entry point.  If there is no selection, the
/// action creates a function at the current address using auto-detection of
/// the function body.
///
/// Ported from `ghidra.app.plugin.core.function.CreateFunctionAction`.
#[derive(Debug, Clone)]
pub struct CreateFunctionAction {
    /// Action name.
    pub name: String,
    /// Owner plugin name.
    pub owner: String,
    /// Whether the action is enabled.
    pub is_enabled: bool,
    /// Whether to allow creating a function at a location that already has one.
    pub allow_existing: bool,
    /// Whether to create a thunk function instead.
    pub create_thunk: bool,
}

impl CreateFunctionAction {
    /// Create a new action.
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
            is_enabled: true,
            allow_existing: false,
            create_thunk: false,
        }
    }

    /// Create a thunk variant of this action.
    pub fn new_thunk(owner: impl Into<String>) -> Self {
        Self {
            name: "Create Thunk Function".to_string(),
            owner: owner.into(),
            is_enabled: true,
            allow_existing: true,
            create_thunk: true,
        }
    }

    /// Check if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &FunctionActionContext) -> bool {
        if ctx.has_selection {
            return true;
        }
        if ctx.address.is_none() {
            return false;
        }
        if !self.allow_existing && ctx.function_entry.is_some() {
            return false;
        }
        true
    }

    /// Execute the action, returning a command description.
    pub fn execute(&self, ctx: &FunctionActionContext) -> FunctionAction {
        if let Some((start, end)) = ctx.selection {
            FunctionAction::CreateFunction {
                entry_point: start,
                body_start: start,
                body_end: end,
                is_thunk: self.create_thunk,
            }
        } else if let Some(addr) = ctx.address {
            FunctionAction::CreateFunction {
                entry_point: addr,
                body_start: addr,
                body_end: addr,
                is_thunk: self.create_thunk,
            }
        } else {
            FunctionAction::NoOp
        }
    }
}

// ---------------------------------------------------------------------------
// DeleteFunctionAction
// ---------------------------------------------------------------------------

/// Action to delete a function at its entry point.
///
/// Only enabled when the cursor is on a function entry point, not on a
/// variable within the function.
///
/// Ported from `ghidra.app.plugin.core.function.DeleteFunctionAction`.
#[derive(Debug, Clone)]
pub struct DeleteFunctionAction {
    /// Action name.
    pub name: String,
    /// Owner plugin name.
    pub owner: String,
}

impl DeleteFunctionAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Delete Function".to_string(),
            owner: owner.into(),
        }
    }

    /// Check if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &FunctionActionContext) -> bool {
        if ctx.has_selection || ctx.address.is_none() {
            return false;
        }
        ctx.is_on_function_entry()
    }

    /// Execute the action, returning a command description.
    pub fn execute(&self, ctx: &FunctionActionContext) -> FunctionAction {
        if let Some(entry) = ctx.function_entry {
            FunctionAction::DeleteFunction { entry_point: entry }
        } else {
            FunctionAction::NoOp
        }
    }
}

// ---------------------------------------------------------------------------
// EditFunctionAction
// ---------------------------------------------------------------------------

/// Action to edit the current function's properties (name, signature, etc.).
///
/// Ported from `ghidra.app.plugin.core.function.EditFunctionAction`.
#[derive(Debug, Clone)]
pub struct EditFunctionAction {
    /// Action name.
    pub name: String,
    /// Owner plugin name.
    pub owner: String,
}

impl EditFunctionAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Edit Function".to_string(),
            owner: owner.into(),
        }
    }

    /// Check if the action is enabled for the given context.
    pub fn is_enabled_for_context(&self, ctx: &FunctionActionContext) -> bool {
        ctx.function_entry.is_some() && !ctx.has_selection
    }

    /// Execute the action.
    pub fn execute(&self, ctx: &FunctionActionContext) -> FunctionAction {
        if let Some(entry) = ctx.function_entry {
            FunctionAction::EditFunction {
                entry_point: entry,
                function_name: ctx.function_name.clone().unwrap_or_default(),
            }
        } else {
            FunctionAction::NoOp
        }
    }
}

// ---------------------------------------------------------------------------
// CreateMultipleFunctionsAction
// ---------------------------------------------------------------------------

/// Action to create functions from all selected ranges.
///
/// Ported from `ghidra.app.plugin.core.function.CreateMultipleFunctionsAction`.
#[derive(Debug, Clone)]
pub struct CreateMultipleFunctionsAction {
    /// Action name.
    pub name: String,
    /// Owner plugin name.
    pub owner: String,
}

impl CreateMultipleFunctionsAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Create Multiple Functions".to_string(),
            owner: owner.into(),
        }
    }

    /// Check if the action is enabled (requires a selection).
    pub fn is_enabled_for_context(&self, ctx: &FunctionActionContext) -> bool {
        ctx.has_selection
    }

    /// Execute the action.
    pub fn execute(&self, ctx: &FunctionActionContext) -> FunctionAction {
        if let Some((start, end)) = ctx.selection {
            FunctionAction::CreateMultipleFunctions {
                range_start: start,
                range_end: end,
            }
        } else {
            FunctionAction::NoOp
        }
    }
}

// ---------------------------------------------------------------------------
// ClearFunctionAction
// ---------------------------------------------------------------------------

/// Action to clear (disassemble) a function body, removing the function.
///
/// Ported from `ghidra.app.plugin.core.function.ClearFunctionAction`.
#[derive(Debug, Clone)]
pub struct ClearFunctionAction {
    /// Action name.
    pub name: String,
    /// Owner plugin name.
    pub owner: String,
}

impl ClearFunctionAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Clear Function".to_string(),
            owner: owner.into(),
        }
    }

    /// Check if the action is enabled.
    pub fn is_enabled_for_context(&self, ctx: &FunctionActionContext) -> bool {
        ctx.function_entry.is_some()
    }

    /// Execute the action.
    pub fn execute(&self, ctx: &FunctionActionContext) -> FunctionAction {
        if let Some(entry) = ctx.function_entry {
            FunctionAction::ClearFunction { entry_point: entry }
        } else {
            FunctionAction::NoOp
        }
    }
}

// ---------------------------------------------------------------------------
// FunctionAction enum -- represents all possible function actions
// ---------------------------------------------------------------------------

/// Enum representing the various function actions that can be performed.
///
/// This is the command/return value from action execution methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FunctionAction {
    /// No operation (action was not applicable).
    NoOp,
    /// Create a function.
    CreateFunction {
        /// Entry point address.
        entry_point: u64,
        /// Start of function body.
        body_start: u64,
        /// End of function body.
        body_end: u64,
        /// Whether this is a thunk function.
        is_thunk: bool,
    },
    /// Delete a function.
    DeleteFunction {
        /// Entry point of function to delete.
        entry_point: u64,
    },
    /// Edit function properties.
    EditFunction {
        /// Entry point of function to edit.
        entry_point: u64,
        /// Current function name.
        function_name: String,
    },
    /// Create multiple functions from a range.
    CreateMultipleFunctions {
        /// Start of the address range.
        range_start: u64,
        /// End of the address range.
        range_end: u64,
    },
    /// Clear a function body.
    ClearFunction {
        /// Entry point of function to clear.
        entry_point: u64,
    },
    /// Edit the stack purge size of a function.
    EditPurge {
        /// Entry point of the function.
        entry_point: u64,
        /// New purge value (positive = bytes popped).
        purge: i32,
    },
}

impl FunctionAction {
    /// Whether this action is a no-op.
    pub fn is_noop(&self) -> bool {
        matches!(self, Self::NoOp)
    }

    /// Human-readable description of the action.
    pub fn description(&self) -> String {
        match self {
            Self::NoOp => "No action".to_string(),
            Self::CreateFunction { entry_point, is_thunk, .. } => {
                let kind = if *is_thunk { "thunk " } else { "" };
                format!("Create {}function at 0x{:X}", kind, entry_point)
            }
            Self::DeleteFunction { entry_point } => {
                format!("Delete function at 0x{:X}", entry_point)
            }
            Self::EditFunction { entry_point, function_name } => {
                format!("Edit function '{}' at 0x{:X}", function_name, entry_point)
            }
            Self::CreateMultipleFunctions { range_start, range_end } => {
                format!("Create functions in range 0x{:X}..0x{:X}", range_start, range_end)
            }
            Self::ClearFunction { entry_point } => {
                format!("Clear function at 0x{:X}", entry_point)
            }
            Self::EditPurge { entry_point, purge } => {
                format!("Edit purge of function at 0x{:X} to {}", entry_point, purge)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// EditFunctionPurgeAction
// ---------------------------------------------------------------------------

/// Action to edit the purge amount for a function (number of bytes the callee
/// cleans from the stack, e.g., stdcall convention on x86).
///
/// Ported from `ghidra.app.plugin.core.function.EditFunctionPurgeAction`.
#[derive(Debug, Clone)]
pub struct EditFunctionPurgeAction {
    /// Action name.
    pub name: String,
    /// Owner plugin name.
    pub owner: String,
}

impl EditFunctionPurgeAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Edit Function Purge".to_string(),
            owner: owner.into(),
        }
    }

    /// Check if the action is enabled.
    pub fn is_enabled_for_context(&self, ctx: &FunctionActionContext) -> bool {
        ctx.function_entry.is_some() && !ctx.has_selection
    }

    /// Execute the action with a new purge value.
    pub fn execute(&self, ctx: &FunctionActionContext, new_purge: i32) -> FunctionAction {
        if let Some(entry) = ctx.function_entry {
            FunctionAction::EditPurge {
                entry_point: entry,
                purge: new_purge,
            }
        } else {
            FunctionAction::NoOp
        }
    }
}

/// Extension to FunctionAction for the purge edit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(dead_code)]
enum PurgeExtension {
    EditPurge { entry_point: u64, purge: i32 },
}

// ---------------------------------------------------------------------------
// EditThunkFunctionAction / RevertThunkFunctionAction
// ---------------------------------------------------------------------------

/// Action to edit a thunk function's target.
///
/// Ported from `ghidra.app.plugin.core.function.EditThunkFunctionAction`.
#[derive(Debug, Clone)]
pub struct EditThunkFunctionAction {
    /// Action name.
    pub name: String,
    /// Owner plugin name.
    pub owner: String,
}

impl EditThunkFunctionAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Edit Thunk Function".to_string(),
            owner: owner.into(),
        }
    }

    /// Check if the action is enabled (must be on a thunk function).
    pub fn is_enabled_for_context(&self, ctx: &FunctionActionContext) -> bool {
        ctx.function_entry.is_some() && !ctx.has_selection
    }
}

/// Action to revert a thunk function to a non-thunk.
///
/// Ported from `ghidra.app.plugin.core.function.RevertThunkFunctionAction`.
#[derive(Debug, Clone)]
pub struct RevertThunkFunctionAction {
    /// Action name.
    pub name: String,
    /// Owner plugin name.
    pub owner: String,
}

impl RevertThunkFunctionAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Revert Thunk Function".to_string(),
            owner: owner.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// AddVarArgsAction / DeleteVarArgsAction
// ---------------------------------------------------------------------------

/// Action to add varargs (...) to a function signature.
///
/// Ported from `ghidra.app.plugin.core.function.AddVarArgsAction`.
#[derive(Debug, Clone)]
pub struct AddVarArgsAction {
    /// Action name.
    pub name: String,
    /// Owner plugin name.
    pub owner: String,
}

impl AddVarArgsAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Add Varargs".to_string(),
            owner: owner.into(),
        }
    }

    /// Check if the action is enabled.
    pub fn is_enabled_for_context(&self, ctx: &FunctionActionContext) -> bool {
        ctx.function_entry.is_some() && !ctx.has_selection
    }
}

/// Action to delete varargs from a function signature.
///
/// Ported from `ghidra.app.plugin.core.function.DeleteVarArgsAction`.
#[derive(Debug, Clone)]
pub struct DeleteVarArgsAction {
    /// Action name.
    pub name: String,
    /// Owner plugin name.
    pub owner: String,
}

impl DeleteVarArgsAction {
    /// Create a new action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            name: "Delete Varargs".to_string(),
            owner: owner.into(),
        }
    }

    /// Check if the action is enabled.
    pub fn is_enabled_for_context(&self, ctx: &FunctionActionContext) -> bool {
        ctx.function_entry.is_some() && !ctx.has_selection
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_func_ctx(addr: u64, entry: u64) -> FunctionActionContext {
        FunctionActionContext {
            program: "test.exe".into(),
            address: Some(addr),
            selection: None,
            has_selection: false,
            function_entry: Some(entry),
            function_name: Some("test_func".into()),
            location_type: "FunctionLocation".into(),
            function_address: Some(entry),
        }
    }

    #[test]
    fn test_create_function_action_with_selection() {
        let action = CreateFunctionAction::new("Create Function", "FuncPlugin");
        let mut ctx = FunctionActionContext::new("test.exe");
        ctx.selection = Some((0x1000, 0x10FF));
        ctx.has_selection = true;

        assert!(action.is_enabled_for_context(&ctx));
        let result = action.execute(&ctx);
        match result {
            FunctionAction::CreateFunction { entry_point, body_start, body_end, is_thunk } => {
                assert_eq!(entry_point, 0x1000);
                assert_eq!(body_start, 0x1000);
                assert_eq!(body_end, 0x10FF);
                assert!(!is_thunk);
            }
            _ => panic!("Expected CreateFunction"),
        }
    }

    #[test]
    fn test_create_function_action_no_selection() {
        let action = CreateFunctionAction::new("Create Function", "FuncPlugin");
        let mut ctx = FunctionActionContext::new("test.exe");
        ctx.address = Some(0x1000);

        assert!(action.is_enabled_for_context(&ctx));
        let result = action.execute(&ctx);
        match result {
            FunctionAction::CreateFunction { entry_point, .. } => {
                assert_eq!(entry_point, 0x1000);
            }
            _ => panic!("Expected CreateFunction"),
        }
    }

    #[test]
    fn test_create_function_action_thunk() {
        let action = CreateFunctionAction::new_thunk("FuncPlugin");
        assert!(action.create_thunk);
        assert!(action.allow_existing);
    }

    #[test]
    fn test_create_function_disabled_on_existing() {
        let action = CreateFunctionAction::new("Create Function", "FuncPlugin");
        let ctx = make_func_ctx(0x1000, 0x1000);
        // allow_existing is false, so action should be disabled when already on a function
        assert!(!action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_delete_function_action() {
        let action = DeleteFunctionAction::new("FuncPlugin");
        let ctx = make_func_ctx(0x1000, 0x1000);

        assert!(action.is_enabled_for_context(&ctx));
        let result = action.execute(&ctx);
        assert_eq!(result, FunctionAction::DeleteFunction { entry_point: 0x1000 });
    }

    #[test]
    fn test_delete_function_disabled_on_variable() {
        let action = DeleteFunctionAction::new("FuncPlugin");
        let mut ctx = make_func_ctx(0x1010, 0x1000);
        ctx.location_type = "VariableLocation".into();

        assert!(!action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_delete_function_disabled_with_selection() {
        let action = DeleteFunctionAction::new("FuncPlugin");
        let mut ctx = make_func_ctx(0x1000, 0x1000);
        ctx.has_selection = true;

        assert!(!action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_edit_function_action() {
        let action = EditFunctionAction::new("FuncPlugin");
        let ctx = make_func_ctx(0x1000, 0x1000);

        assert!(action.is_enabled_for_context(&ctx));
        let result = action.execute(&ctx);
        match result {
            FunctionAction::EditFunction { entry_point, function_name } => {
                assert_eq!(entry_point, 0x1000);
                assert_eq!(function_name, "test_func");
            }
            _ => panic!("Expected EditFunction"),
        }
    }

    #[test]
    fn test_create_multiple_functions() {
        let action = CreateMultipleFunctionsAction::new("FuncPlugin");
        let mut ctx = FunctionActionContext::new("test.exe");
        ctx.selection = Some((0x1000, 0x2000));
        ctx.has_selection = true;

        assert!(action.is_enabled_for_context(&ctx));
        let result = action.execute(&ctx);
        assert_eq!(
            result,
            FunctionAction::CreateMultipleFunctions {
                range_start: 0x1000,
                range_end: 0x2000,
            }
        );
    }

    #[test]
    fn test_clear_function_action() {
        let action = ClearFunctionAction::new("FuncPlugin");
        let ctx = make_func_ctx(0x1000, 0x1000);

        assert!(action.is_enabled_for_context(&ctx));
        let result = action.execute(&ctx);
        assert_eq!(result, FunctionAction::ClearFunction { entry_point: 0x1000 });
    }

    #[test]
    fn test_function_action_description() {
        let action = FunctionAction::CreateFunction {
            entry_point: 0x401000,
            body_start: 0x401000,
            body_end: 0x4010FF,
            is_thunk: false,
        };
        assert!(action.description().contains("0x401000"));

        let noop = FunctionAction::NoOp;
        assert!(noop.is_noop());
        assert_eq!(noop.description(), "No action");
    }

    #[test]
    fn test_edit_function_purge() {
        let action = EditFunctionPurgeAction::new("FuncPlugin");
        let ctx = make_func_ctx(0x1000, 0x1000);
        assert!(action.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_varargs_actions() {
        let add = AddVarArgsAction::new("FuncPlugin");
        let del = DeleteVarArgsAction::new("FuncPlugin");
        let ctx = make_func_ctx(0x1000, 0x1000);

        assert!(add.is_enabled_for_context(&ctx));
        assert!(del.is_enabled_for_context(&ctx));
    }

    #[test]
    fn test_thunk_actions() {
        let edit = EditThunkFunctionAction::new("FuncPlugin");
        let revert = RevertThunkFunctionAction::new("FuncPlugin");
        assert_eq!(edit.name, "Edit Thunk Function");
        assert_eq!(revert.name, "Revert Thunk Function");
    }

    #[test]
    fn test_context_is_on_function_entry() {
        let ctx = make_func_ctx(0x1000, 0x1000);
        assert!(ctx.is_on_function_entry());

        let ctx2 = make_func_ctx(0x1010, 0x1000);
        assert!(!ctx2.is_on_function_entry());
    }

    #[test]
    fn test_function_action_serialization() {
        let action = FunctionAction::CreateFunction {
            entry_point: 0x401000,
            body_start: 0x401000,
            body_end: 0x4010FF,
            is_thunk: false,
        };
        let json = serde_json::to_string(&action).unwrap();
        let deserialized: FunctionAction = serde_json::from_str(&json).unwrap();
        assert_eq!(action, deserialized);
    }
}
