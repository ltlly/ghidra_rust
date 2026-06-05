//! Function plugin -- ported from `FunctionPlugin.java`.
//!
//! The [`FunctionPlugin`] is the central controller for function
//! management.  It creates and registers all function-related actions,
//! manages the favourite data-type list, and provides helper methods
//! for resolving functions at a given context location.

use ghidra_core::addr::Address;
use ghidra_core::symbol::{Symbol, SymbolType};
use serde::{Deserialize, Serialize};

use super::actions::*;
use super::variable::*;
use super::variable_comment::VariableCommentAction;
use super::thunk::*;
use super::stack::*;
use super::stack_depth::EditFunctionPurgeAction;

// ---------------------------------------------------------------------------
// FunctionPlugin constants (menu groups, subgroups)
// ---------------------------------------------------------------------------

/// Menu subgroup name for function-related items.
pub const FUNCTION_MENU_SUBGROUP: &str = "Function";

/// Menu subgroup for thunk function items.
pub const THUNK_FUNCTION_MENU_SUBGROUP: &str = "FunctionThunk";

/// Menu path: function pull-right menu.
pub const FUNCTION_MENU_PULLRIGHT: &str = "Function";

/// Menu path: variable pull-right menu.
pub const VARIABLE_MENU_PULLRIGHT: &str = "Variable";

/// Menu path: set data type pull-right menu.
pub const SET_DATA_TYPE_PULLRIGHT: &str = "Set Data Type";

/// Menu path: set return type.
pub const SET_RETURN_TYPE_MENU_PATH: &str = "Set Return Type";

/// Menu path: set parameter type.
pub const SET_PARAMETER_TYPE_MENU_PATH: &str = "Set Parameter Type";

/// Subgroup at the beginning of the function menu.
pub const FUNCTION_SUBGROUP_BEGINNING: &str = "FunctionBegin";

/// Subgroup in the middle of the function menu.
pub const FUNCTION_SUBGROUP_MIDDLE: &str = "FunctionMiddle";

/// Menu subgroup for stack operations.
pub const STACK_MENU_SUBGROUP: &str = "Stack";

/// Menu subgroup for variable operations.
pub const VARIABLE_MENU_SUBGROUP: &str = "Variable";

/// Menu subgroup for data-type operations.
pub const SET_DATA_TYPE_MENU_SUBGROUP: &str = "DataType";

/// Subgroup for set return type actions.
pub const SET_RETURN_TYPE_SUBGROUP: &str = "SetReturnType";

/// Subgroup for set parameter type actions.
pub const SET_PARAMETER_TYPE_SUBGROUP: &str = "SetParamType";

/// Subgroup for comment actions.
pub const COMMENT_SUBGROUP: &str = "Comment";

// ---------------------------------------------------------------------------
// FunctionPlugin
// ---------------------------------------------------------------------------

/// The function plugin -- manages all function-related actions.
///
/// In Ghidra Java this extends `Plugin` and implements `DataService`.
/// Here we model the non-GUI parts: action registry, action enabling
/// checks, and helper methods for resolving functions from context.
///
/// # Example
///
/// ```
/// use ghidra_features::base::function::FunctionPlugin;
///
/// let plugin = FunctionPlugin::new();
/// assert_eq!(plugin.action_count(), 0); // actions registered on init
/// assert_eq!(plugin.favorites_count(), 0);
/// ```
#[derive(Debug)]
pub struct FunctionPlugin {
    /// The plugin display name.
    name: String,

    // -- Function actions --
    create_function_action: Option<CreateFunctionAction>,
    create_external_function_action: Option<CreateExternalFunctionAction>,
    create_multiple_functions_action: Option<CreateMultipleFunctionsAction>,
    recreate_function_action: Option<CreateFunctionAction>,
    thunk_function_action: Option<CreateFunctionAction>,
    delete_function_action: Option<DeleteFunctionAction>,
    edit_function_action: Option<EditFunctionAction>,
    edit_function_name_action: Option<EditNameAction>,
    edit_variable_name_action: Option<EditNameAction>,
    edit_operand_name_action: Option<EditOperandNameAction>,

    // -- Thunk actions --
    edit_thunk_function_action: Option<EditThunkFunctionAction>,
    revert_thunk_function_action: Option<RevertThunkFunctionAction>,

    // -- Variable actions --
    variable_delete_action: Option<VariableDeleteAction>,
    variable_comment_action: Option<VariableCommentAction>,

    // -- Stack actions --
    analyze_stack_refs_action: Option<AnalyzeStackRefsAction>,
    edit_function_purge_action: Option<EditFunctionPurgeAction>,

    // -- Favourite data types --
    favorites: Vec<String>,
}

impl FunctionPlugin {
    /// Creates a new function plugin with default settings.
    pub fn new() -> Self {
        Self {
            name: "FunctionPlugin".to_string(),
            create_function_action: None,
            create_external_function_action: None,
            create_multiple_functions_action: None,
            recreate_function_action: None,
            thunk_function_action: None,
            delete_function_action: None,
            edit_function_action: None,
            edit_function_name_action: None,
            edit_variable_name_action: None,
            edit_operand_name_action: None,
            edit_thunk_function_action: None,
            revert_thunk_function_action: None,
            variable_delete_action: None,
            variable_comment_action: None,
            analyze_stack_refs_action: None,
            edit_function_purge_action: None,
            favorites: Vec::new(),
        }
    }

    /// Creates and registers all default actions (equivalent to
    /// `FunctionPlugin.createActions()` in Java).
    pub fn create_actions(&mut self) {
        // Function creation
        self.create_function_action =
            Some(CreateFunctionAction::new("Create Function", false, false));
        self.create_external_function_action =
            Some(CreateExternalFunctionAction::new("Create External Function"));
        self.create_multiple_functions_action =
            Some(CreateMultipleFunctionsAction::new());
        self.recreate_function_action =
            Some(CreateFunctionAction::new("Re-create Function", true, false));
        self.thunk_function_action =
            Some(CreateFunctionAction::new("Create Thunk Function", false, true));

        // Function editing
        self.delete_function_action = Some(DeleteFunctionAction::new());
        self.edit_function_action = Some(EditFunctionAction::new());
        self.edit_function_name_action = Some(EditNameAction::new_for_function());
        self.edit_variable_name_action = Some(EditNameAction::new_for_variable());
        self.edit_operand_name_action = Some(EditOperandNameAction::new());

        // Thunk
        self.edit_thunk_function_action = Some(EditThunkFunctionAction::new());
        self.revert_thunk_function_action = Some(RevertThunkFunctionAction::new());

        // Variable
        self.variable_delete_action = Some(VariableDeleteAction::new());
        self.variable_comment_action = Some(VariableCommentAction::new());

        // Stack
        self.analyze_stack_refs_action = Some(AnalyzeStackRefsAction::new());
        self.edit_function_purge_action = Some(EditFunctionPurgeAction::new());
    }

    /// Returns the number of registered actions.
    pub fn action_count(&self) -> usize {
        let mut count = 0;
        if self.create_function_action.is_some() { count += 1; }
        if self.create_external_function_action.is_some() { count += 1; }
        if self.create_multiple_functions_action.is_some() { count += 1; }
        if self.recreate_function_action.is_some() { count += 1; }
        if self.thunk_function_action.is_some() { count += 1; }
        if self.delete_function_action.is_some() { count += 1; }
        if self.edit_function_action.is_some() { count += 1; }
        if self.edit_function_name_action.is_some() { count += 1; }
        if self.edit_variable_name_action.is_some() { count += 1; }
        if self.edit_operand_name_action.is_some() { count += 1; }
        if self.edit_thunk_function_action.is_some() { count += 1; }
        if self.revert_thunk_function_action.is_some() { count += 1; }
        if self.variable_delete_action.is_some() { count += 1; }
        if self.variable_comment_action.is_some() { count += 1; }
        if self.analyze_stack_refs_action.is_some() { count += 1; }
        if self.edit_function_purge_action.is_some() { count += 1; }
        count
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    // -----------------------------------------------------------------------
    // Context helpers
    // -----------------------------------------------------------------------

    /// Resolves a function from a listing context at the given address.
    /// Returns the function symbol if one exists at `addr`.
    pub fn get_function_at(symbols: &[Symbol], addr: Address) -> Option<&Symbol> {
        symbols.iter().find(|s| {
            s.kind() == SymbolType::Function && s.address().offset == addr.offset
        })
    }

    /// Returns the function containing the given address (any address
    /// within the function body).  This is a simplified version -- the
    /// full Ghidra impl uses `FunctionManager.getFunctionContaining()`.
    pub fn get_function_containing(
        symbols: &[Symbol],
        addr: Address,
    ) -> Option<&Symbol> {
        // Simplified: return the function at or before `addr`.
        symbols
            .iter()
            .filter(|s| s.kind() == SymbolType::Function)
            .min_by_key(|s| {
                let diff = addr.offset.wrapping_sub(s.address().offset);
                if addr.offset >= s.address().offset {
                    diff
                } else {
                    u64::MAX
                }
            })
            .filter(|s| addr.offset >= s.address().offset)
    }

    // -----------------------------------------------------------------------
    // Favourite data types
    // -----------------------------------------------------------------------

    /// Returns the favourite data type names.
    pub fn favorites(&self) -> &[String] {
        &self.favorites
    }

    /// Adds a favourite data type name.
    pub fn add_favorite(&mut self, name: String) {
        if !self.favorites.contains(&name) {
            self.favorites.push(name);
        }
    }

    /// Removes a favourite data type name.
    pub fn remove_favorite(&mut self, name: &str) -> bool {
        let before = self.favorites.len();
        self.favorites.retain(|n| n != name);
        self.favorites.len() < before
    }

    /// Returns the number of favourite data types.
    pub fn favorites_count(&self) -> usize {
        self.favorites.len()
    }

    /// Disposes the plugin (clears all actions and favourites).
    pub fn dispose(&mut self) {
        self.create_function_action = None;
        self.create_external_function_action = None;
        self.create_multiple_functions_action = None;
        self.recreate_function_action = None;
        self.thunk_function_action = None;
        self.delete_function_action = None;
        self.edit_function_action = None;
        self.edit_function_name_action = None;
        self.edit_variable_name_action = None;
        self.edit_operand_name_action = None;
        self.edit_thunk_function_action = None;
        self.revert_thunk_function_action = None;
        self.variable_delete_action = None;
        self.variable_comment_action = None;
        self.analyze_stack_refs_action = None;
        self.edit_function_purge_action = None;
        self.favorites.clear();
    }
}

impl Default for FunctionPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = FunctionPlugin::new();
        assert_eq!(plugin.action_count(), 0);
        assert_eq!(plugin.favorites_count(), 0);
    }

    #[test]
    fn test_create_actions() {
        let mut plugin = FunctionPlugin::new();
        plugin.create_actions();
        assert_eq!(plugin.action_count(), 16);
    }

    #[test]
    fn test_favorites() {
        let mut plugin = FunctionPlugin::new();
        plugin.add_favorite("int".to_string());
        plugin.add_favorite("char*".to_string());
        assert_eq!(plugin.favorites_count(), 2);
        // No duplicates
        plugin.add_favorite("int".to_string());
        assert_eq!(plugin.favorites_count(), 2);
        assert!(plugin.remove_favorite("int"));
        assert_eq!(plugin.favorites_count(), 1);
        assert!(!plugin.remove_favorite("nonexistent"));
    }

    #[test]
    fn test_get_function_at() {
        let symbols = vec![
            Symbol::function("main", Address::new(0x401000)),
            Symbol::label("data", Address::new(0x402000)),
        ];
        let func = FunctionPlugin::get_function_at(&symbols, Address::new(0x401000));
        assert!(func.is_some());
        assert_eq!(func.unwrap().name(), "main");
        assert!(FunctionPlugin::get_function_at(&symbols, Address::new(0x403000)).is_none());
    }

    #[test]
    fn test_get_function_containing() {
        let symbols = vec![
            Symbol::function("main", Address::new(0x401000)),
            Symbol::function("helper", Address::new(0x401100)),
        ];
        let func = FunctionPlugin::get_function_containing(&symbols, Address::new(0x401050));
        assert!(func.is_some());
        assert_eq!(func.unwrap().name(), "main");
    }

    #[test]
    fn test_constants() {
        assert_eq!(FUNCTION_MENU_SUBGROUP, "Function");
        assert_eq!(THUNK_FUNCTION_MENU_SUBGROUP, "FunctionThunk");
        assert_eq!(FUNCTION_MENU_PULLRIGHT, "Function");
        assert_eq!(STACK_MENU_SUBGROUP, "Stack");
    }

    #[test]
    fn test_dispose() {
        let mut plugin = FunctionPlugin::new();
        plugin.create_actions();
        plugin.add_favorite("int".to_string());
        plugin.dispose();
        assert_eq!(plugin.action_count(), 0);
        assert_eq!(plugin.favorites_count(), 0);
    }

    #[test]
    fn test_plugin_name() {
        let plugin = FunctionPlugin::new();
        assert_eq!(plugin.name(), "FunctionPlugin");
    }

    #[test]
    fn test_plugin_default_trait() {
        let plugin = FunctionPlugin::default();
        assert_eq!(plugin.action_count(), 0);
        assert_eq!(plugin.name(), "FunctionPlugin");
    }

    #[test]
    fn test_favorites_ordering_preserved() {
        let mut plugin = FunctionPlugin::new();
        plugin.add_favorite("char".to_string());
        plugin.add_favorite("int".to_string());
        plugin.add_favorite("float".to_string());
        let favs = plugin.favorites();
        assert_eq!(favs[0], "char");
        assert_eq!(favs[1], "int");
        assert_eq!(favs[2], "float");
    }

    #[test]
    fn test_get_function_at_no_symbols() {
        let symbols: Vec<Symbol> = vec![];
        assert!(FunctionPlugin::get_function_at(&symbols, Address::new(0x1000)).is_none());
    }

    #[test]
    fn test_get_function_at_wrong_kind() {
        let symbols = vec![
            Symbol::label("data", Address::new(0x1000)),
        ];
        assert!(FunctionPlugin::get_function_at(&symbols, Address::new(0x1000)).is_none());
    }

    #[test]
    fn test_get_function_containing_no_functions() {
        let symbols = vec![
            Symbol::label("data", Address::new(0x1000)),
        ];
        assert!(FunctionPlugin::get_function_containing(&symbols, Address::new(0x1000)).is_none());
    }

    #[test]
    fn test_get_function_containing_before_first() {
        let symbols = vec![
            Symbol::function("main", Address::new(0x401000)),
        ];
        assert!(FunctionPlugin::get_function_containing(&symbols, Address::new(0x100000)).is_none());
    }

    #[test]
    fn test_all_menu_constants() {
        assert!(!FUNCTION_MENU_SUBGROUP.is_empty());
        assert!(!THUNK_FUNCTION_MENU_SUBGROUP.is_empty());
        assert!(!FUNCTION_MENU_PULLRIGHT.is_empty());
        assert!(!VARIABLE_MENU_PULLRIGHT.is_empty());
        assert!(!SET_DATA_TYPE_PULLRIGHT.is_empty());
        assert!(!SET_RETURN_TYPE_MENU_PATH.is_empty());
        assert!(!SET_PARAMETER_TYPE_MENU_PATH.is_empty());
        assert!(!FUNCTION_SUBGROUP_BEGINNING.is_empty());
        assert!(!FUNCTION_SUBGROUP_MIDDLE.is_empty());
        assert!(!STACK_MENU_SUBGROUP.is_empty());
        assert!(!VARIABLE_MENU_SUBGROUP.is_empty());
        assert!(!SET_DATA_TYPE_MENU_SUBGROUP.is_empty());
        assert!(!SET_RETURN_TYPE_SUBGROUP.is_empty());
        assert!(!SET_PARAMETER_TYPE_SUBGROUP.is_empty());
        assert!(!COMMENT_SUBGROUP.is_empty());
    }

    #[test]
    fn test_debug_trait() {
        let plugin = FunctionPlugin::new();
        let debug = format!("{:?}", plugin);
        assert!(debug.contains("FunctionPlugin"));
    }
}
