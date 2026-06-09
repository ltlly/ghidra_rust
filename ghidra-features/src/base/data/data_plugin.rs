//! Full Data plugin integration -- ported from `DataPlugin.java`.
//!
//! This module provides the complete plugin that ties together all data
//! management actions: create data, cycle groups, pointer creation,
//! structure/array creation, and data settings.  It handles action
//! registration, callback dispatch, and context queries for enablement
//! logic.
//!
//! # Relationship to `plugin.rs`
//!
//! The sibling [`super::plugin`] module provides the core `DataPlugin`
//! struct with data creation, recently-used tracking, and favourite
//! management.  This module builds on top of that by adding the full
//! action-registration and callback-dispatch layer that mirrors Ghidra's
//! `DataPlugin` Java class more closely.

use std::collections::HashMap;

use ghidra_core::addr::Address;

use super::actions::*;
use super::plugin::{DataActionContext, DataCreationError, DataCreationResult};
use super::settings::DataSettings;

// ---------------------------------------------------------------------------
// Action registration
// ---------------------------------------------------------------------------

/// Configuration for a registered data action.
///
/// Mirrors the `DockingAction` setup in `DataPlugin.setupActions()`.
#[derive(Debug, Clone)]
pub struct DataRegisteredAction {
    /// The data action kind.
    pub kind: DataActionKind,
    /// The display name shown in the popup menu.
    pub display_name: String,
    /// The popup menu path (e.g., ["Data", "Settings..."]).
    pub popup_path: Vec<String>,
    /// The popup menu group (for ordering).
    pub popup_group: String,
    /// The key binding character, if any.
    pub key_binding: Option<char>,
    /// Whether the action uses a shared key binding type.
    pub shared_key_binding: bool,
    /// Whether the action is currently enabled.
    pub enabled: bool,
}

impl DataRegisteredAction {
    /// Creates a new registered action with defaults for the given kind.
    pub fn for_kind(kind: DataActionKind) -> Self {
        let (display_name, popup_path, popup_group, key_binding, shared): (String, Vec<String>, String, Option<char>, bool) = match kind {
            DataActionKind::Pointer => (
                "pointer".to_string(),
                vec!["Data".to_string(), "pointer".to_string()],
                "BasicData".to_string(),
                Some('P'),
                false,
            ),
            DataActionKind::RecentlyUsed => (
                "Recently Used".to_string(),
                vec!["Data".to_string(), "Recently Used".to_string()],
                "Z_RECENT".to_string(),
                None,
                false,
            ),
            DataActionKind::CreateArray => (
                "Array".to_string(),
                vec!["Data".to_string(), "Array".to_string()],
                "BasicData".to_string(),
                None,
                false,
            ),
            DataActionKind::CreateStructure => (
                "Structure".to_string(),
                vec!["Data".to_string(), "Structure".to_string()],
                "BasicData".to_string(),
                None,
                false,
            ),
            DataActionKind::ChooseDataType => (
                "Choose Data Type...".to_string(),
                vec!["Data".to_string(), "Choose Data Type...".to_string()],
                "BasicData".to_string(),
                None,
                false,
            ),
            DataActionKind::Settings => (
                "Settings...".to_string(),
                vec!["Data".to_string(), "Settings...".to_string()],
                "Settings".to_string(),
                None,
                false,
            ),
            DataActionKind::DefaultSettings => (
                "Default Settings...".to_string(),
                vec!["Data".to_string(), "Default Settings...".to_string()],
                "Settings".to_string(),
                None,
                false,
            ),
            DataActionKind::EditDataType => (
                "Edit Data Type".to_string(),
                vec!["Data".to_string(), "Edit Data Type".to_string()],
                "Edit".to_string(),
                None,
                false,
            ),
            DataActionKind::CycleGroup(ref name) => (
                name.clone(),
                vec!["Data".to_string(), name.clone()],
                "Cycle".to_string(),
                None,
                false,
            ),
        };

        Self {
            kind,
            display_name,
            popup_path,
            popup_group,
            key_binding,
            shared_key_binding: shared,
            enabled: true,
        }
    }

    /// Returns whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sets the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

// ---------------------------------------------------------------------------
// DataActionKind
// ---------------------------------------------------------------------------

/// The kind of data action.
///
/// Each variant corresponds to a specific action registered by the data
/// plugin in Ghidra.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DataActionKind {
    /// Create a pointer at the current location.
    Pointer,
    /// Re-apply the most recently used data type.
    RecentlyUsed,
    /// Create an array.
    CreateArray,
    /// Create a structure from selection.
    CreateStructure,
    /// Open the "Choose Data Type" dialog.
    ChooseDataType,
    /// Open data settings for the current instance.
    Settings,
    /// Open default data settings for a data type.
    DefaultSettings,
    /// Edit the data type definition.
    EditDataType,
    /// Cycle through a named cycle group.
    CycleGroup(String),
}

// ---------------------------------------------------------------------------
// DataListingContext
// ---------------------------------------------------------------------------

/// Context for a cursor position in the listing, with data-specific fields.
///
/// This models Ghidra's `ListingActionContext` with the additional data
/// plugin fields needed for enablement logic.
#[derive(Debug, Clone)]
pub struct DataListingContext {
    /// The address at the cursor.
    pub address: Address,
    /// Whether the cursor is on a defined data location.
    pub is_data_location: bool,
    /// The data type name at the current location, if any.
    pub data_type_name: Option<String>,
    /// The size in bytes of the data at the current location.
    pub data_size: Option<usize>,
    /// Whether the cursor is inside a structure component.
    pub is_component_location: bool,
    /// Component path indices for structure/component navigation.
    pub component_path: Vec<usize>,
    /// Whether the user has made a selection.
    pub has_selection: bool,
    /// Start address of the selection.
    pub selection_start: Option<Address>,
    /// End address of the selection.
    pub selection_end: Option<Address>,
    /// Whether the selection is interior (inside a structure).
    pub is_interior_selection: bool,
    /// Whether a data type is selected in the data type tree.
    pub has_data_type_selected: bool,
    /// The name of the selected data type in the tree, if any.
    pub selected_data_type_name: Option<String>,
}

impl DataListingContext {
    /// Creates a context at a single data location.
    pub fn at_data(addr: Address, data_type_name: &str, size: usize) -> Self {
        Self {
            address: addr,
            is_data_location: true,
            data_type_name: Some(data_type_name.to_string()),
            data_size: Some(size),
            is_component_location: false,
            component_path: Vec::new(),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_interior_selection: false,
            has_data_type_selected: false,
            selected_data_type_name: None,
        }
    }

    /// Creates a context with a selection range.
    pub fn with_selection(start: Address, end: Address) -> Self {
        Self {
            address: start,
            is_data_location: false,
            data_type_name: None,
            data_size: None,
            is_component_location: false,
            component_path: Vec::new(),
            has_selection: true,
            selection_start: Some(start),
            selection_end: Some(end),
            is_interior_selection: false,
            has_data_type_selected: false,
            selected_data_type_name: None,
        }
    }

    /// Creates a context for a component inside a structure.
    pub fn at_component(addr: Address, data_type_name: &str, size: usize, path: Vec<usize>) -> Self {
        Self {
            address: addr,
            is_data_location: true,
            data_type_name: Some(data_type_name.to_string()),
            data_size: Some(size),
            is_component_location: true,
            component_path: path,
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_interior_selection: false,
            has_data_type_selected: false,
            selected_data_type_name: None,
        }
    }

    /// Creates a context where a data type is selected in the tree.
    pub fn with_data_type_selected(addr: Address, type_name: &str) -> Self {
        Self {
            address: addr,
            is_data_location: false,
            data_type_name: None,
            data_size: None,
            is_component_location: false,
            component_path: Vec::new(),
            has_selection: false,
            selection_start: None,
            selection_end: None,
            is_interior_selection: false,
            has_data_type_selected: true,
            selected_data_type_name: Some(type_name.to_string()),
        }
    }

    /// Returns the number of selected addresses.
    pub fn selection_size(&self) -> Option<u64> {
        match (self.selection_start, self.selection_end) {
            (Some(start), Some(end)) => Some(end.offset.saturating_sub(start.offset) + 1),
            _ => None,
        }
    }

    /// Converts to the simpler [`DataActionContext`] used by the base plugin.
    pub fn to_action_context(&self) -> DataActionContext {
        DataActionContext {
            address: Some(self.address),
            is_data_location: self.is_data_location,
            data_type_name: self.data_type_name.clone(),
            data_size: self.data_size,
            has_data_type_selected: self.has_data_type_selected,
            is_component_location: self.is_component_location,
            component_path: self.component_path.clone(),
            has_selection: self.has_selection,
            selection_start: self.selection_start,
            selection_end: self.selection_end,
            is_interior_selection: self.is_interior_selection,
        }
    }
}

// ---------------------------------------------------------------------------
// DataPluginFull
// ---------------------------------------------------------------------------

/// The full data plugin with action registration and callbacks.
///
/// This is the Rust equivalent of Ghidra's `DataPlugin` Java class.  It
/// manages all data-related actions and provides the callbacks that those
/// actions invoke.  It contains:
///
/// - A set of registered actions (pointer, recently used, settings, etc.)
/// - Cycle group actions
/// - Favourite data type actions
/// - Recently used data type tracking
/// - Callback methods for each action type
///
/// # Architecture
///
/// In Ghidra's Java implementation, `DataPlugin` extends `Plugin` and
/// registers `DockingAction` instances.  Each action calls back into the
/// plugin when triggered.  This Rust port models the same pattern:
///
/// - `DataPluginFull` owns the actions and state
/// - `perform_*` methods are the callbacks for each action
/// - `is_*_enabled` methods determine enablement for each action
///
/// # Example
///
/// ```
/// use ghidra_features::base::data::data_plugin::*;
/// use ghidra_core::addr::Address;
///
/// let mut plugin = DataPluginFull::new("DataPlugin");
/// assert!(plugin.actions().len() > 0);
///
/// plugin.update_recently_used("int");
/// assert_eq!(plugin.recent_data_type_name(), Some("int"));
///
/// let ctx = DataListingContext::at_data(Address::new(0x1000), "byte", 1);
/// let enabled = plugin.get_enabled_actions(&ctx);
/// assert!(enabled.contains(&DataActionKind::Settings));
/// ```
pub struct DataPluginFull {
    /// The plugin name.
    name: String,
    /// Registered actions.
    actions: Vec<DataRegisteredAction>,
    /// Cycle group definitions (group name -> ordered type names).
    cycle_groups: HashMap<String, Vec<String>>,
    /// Favourite data type names.
    favorites: Vec<String>,
    /// Recently used data types (most recent first).
    recently_used: Vec<String>,
    /// Maximum number of recently used entries.
    max_recent: usize,
    /// Current data settings for the active program.
    current_settings: DataSettings,
    /// Whether the plugin has been disposed.
    disposed: bool,
    /// The last callback result message.
    last_status: Option<String>,
    /// Accumulated callback log for testing.
    callback_log: Vec<String>,
}

impl DataPluginFull {
    /// Creates a new full data plugin.
    ///
    /// Mirrors `DataPlugin(PluginTool tool)` in Java, which calls
    /// `setupActions()`.
    pub fn new(name: impl Into<String>) -> Self {
        let mut plugin = Self {
            name: name.into(),
            actions: Vec::new(),
            cycle_groups: HashMap::new(),
            favorites: Vec::new(),
            recently_used: Vec::new(),
            max_recent: 10,
            current_settings: DataSettings::new(),
            disposed: false,
            last_status: None,
            callback_log: Vec::new(),
        };
        plugin.setup_actions();
        plugin.setup_default_cycle_groups();
        plugin
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Sets up all actions.
    ///
    /// Mirrors `setupActions()` in Java which creates and registers
    /// all the DockingAction instances.
    fn setup_actions(&mut self) {
        self.actions
            .push(DataRegisteredAction::for_kind(DataActionKind::Pointer));
        self.actions
            .push(DataRegisteredAction::for_kind(DataActionKind::RecentlyUsed));
        self.actions
            .push(DataRegisteredAction::for_kind(DataActionKind::CreateArray));
        self.actions
            .push(DataRegisteredAction::for_kind(DataActionKind::CreateStructure));
        self.actions
            .push(DataRegisteredAction::for_kind(DataActionKind::ChooseDataType));
        self.actions
            .push(DataRegisteredAction::for_kind(DataActionKind::Settings));
        self.actions
            .push(DataRegisteredAction::for_kind(DataActionKind::DefaultSettings));
        self.actions
            .push(DataRegisteredAction::for_kind(DataActionKind::EditDataType));
    }

    /// Sets up default cycle groups.
    ///
    /// Mirrors the default cycle groups registered in Ghidra's data plugin.
    fn setup_default_cycle_groups(&mut self) {
        self.cycle_groups.insert(
            "DataSize".to_string(),
            vec![
                "byte".to_string(),
                "word".to_string(),
                "dword".to_string(),
                "qword".to_string(),
            ],
        );
        self.cycle_groups.insert(
            "SignedDataSize".to_string(),
            vec![
                "sbyte".to_string(),
                "sword".to_string(),
                "sdword".to_string(),
                "sqword".to_string(),
            ],
        );
        self.cycle_groups.insert(
            "FloatDataSize".to_string(),
            vec![
                "float".to_string(),
                "double".to_string(),
            ],
        );
        self.cycle_groups.insert(
            "StringDataSize".to_string(),
            vec![
                "string".to_string(),
                "unicode".to_string(),
            ],
        );
    }

    /// Returns the registered actions.
    pub fn actions(&self) -> &[DataRegisteredAction] {
        &self.actions
    }

    /// Returns a mutable reference to the registered actions.
    pub fn actions_mut(&mut self) -> &mut Vec<DataRegisteredAction> {
        &mut self.actions
    }

    // -- Cycle groups ----------------------------------------------------

    /// Adds a cycle group.
    pub fn add_cycle_group(&mut self, name: impl Into<String>, types: Vec<String>) {
        self.cycle_groups.insert(name.into(), types);
    }

    /// Returns the cycle group names.
    pub fn cycle_group_names(&self) -> Vec<&str> {
        self.cycle_groups.keys().map(|s| s.as_str()).collect()
    }

    /// Returns the types in a cycle group.
    pub fn cycle_group_types(&self, name: &str) -> Option<&[String]> {
        self.cycle_groups.get(name).map(|v| v.as_slice())
    }

    /// Returns the next data type in a cycle group.
    pub fn get_next_cycle_type(&self, current_type: &str, group_name: &str) -> Option<String> {
        let types = self.cycle_groups.get(group_name)?;
        let pos = types.iter().position(|t| t == current_type)?;
        Some(types[(pos + 1) % types.len()].clone())
    }

    // -- Favourites ------------------------------------------------------

    /// Adds a data type to the favourites list.
    pub fn add_favorite(&mut self, data_type_name: impl Into<String>) {
        let name = data_type_name.into();
        if !self.favorites.contains(&name) {
            self.favorites.push(name);
        }
    }

    /// Removes a data type from the favourites list.
    pub fn remove_favorite(&mut self, data_type_name: &str) -> bool {
        let len_before = self.favorites.len();
        self.favorites.retain(|n| n != data_type_name);
        self.favorites.len() < len_before
    }

    /// Returns the favourite data type names.
    pub fn favorites(&self) -> &[String] {
        &self.favorites
    }

    /// Returns the number of favourites.
    pub fn favorites_count(&self) -> usize {
        self.favorites.len()
    }

    // -- Recently used ---------------------------------------------------

    /// Records a data type as recently used.
    pub fn update_recently_used(&mut self, data_type_name: &str) {
        self.recently_used.retain(|n| n != data_type_name);
        self.recently_used.insert(0, data_type_name.to_string());
        while self.recently_used.len() > self.max_recent {
            self.recently_used.pop();
        }
    }

    /// Returns the name of the most recently used data type, if any.
    pub fn recent_data_type_name(&self) -> Option<&str> {
        self.recently_used.first().map(|s| s.as_str())
    }

    /// Returns all recently used data type names.
    pub fn recently_used_names(&self) -> &[String] {
        &self.recently_used
    }

    /// Clears the recently used list.
    pub fn clear_recently_used(&mut self) {
        self.recently_used.clear();
    }

    // -- Settings --------------------------------------------------------

    /// Returns a reference to the current data settings.
    pub fn current_settings(&self) -> &DataSettings {
        &self.current_settings
    }

    /// Returns a mutable reference to the current data settings.
    pub fn current_settings_mut(&mut self) -> &mut DataSettings {
        &mut self.current_settings
    }

    // -- Enablement logic ------------------------------------------------

    /// Returns the list of enabled actions for the given context.
    pub fn get_enabled_actions(&self, ctx: &DataListingContext) -> Vec<DataActionKind> {
        let mut enabled = Vec::new();

        if self.is_create_data_allowed(ctx) {
            enabled.push(DataActionKind::Pointer);
            enabled.push(DataActionKind::RecentlyUsed);
            enabled.push(DataActionKind::CreateArray);
            enabled.push(DataActionKind::CreateStructure);
            enabled.push(DataActionKind::ChooseDataType);
        }

        if self.is_data_settings_allowed(ctx) {
            enabled.push(DataActionKind::Settings);
        }

        if self.is_default_settings_allowed(ctx) {
            enabled.push(DataActionKind::DefaultSettings);
        }

        if self.is_edit_data_type_allowed(ctx) {
            enabled.push(DataActionKind::EditDataType);
        }

        for name in self.cycle_group_names() {
            if self.is_cycle_allowed(ctx, name) {
                enabled.push(DataActionKind::CycleGroup(name.to_string()));
            }
        }

        enabled
    }

    /// Returns `true` if creating data is allowed at the given context.
    pub fn is_create_data_allowed(&self, ctx: &DataListingContext) -> bool {
        !self.disposed
            && ctx.address.offset != 0
            && ctx.is_data_location
    }

    /// Returns `true` if data settings can be edited at the given context.
    pub fn is_data_settings_allowed(&self, ctx: &DataListingContext) -> bool {
        !self.disposed && ctx.is_data_location && ctx.data_type_name.is_some()
    }

    /// Returns `true` if default settings can be edited.
    pub fn is_default_settings_allowed(&self, ctx: &DataListingContext) -> bool {
        !self.disposed && ctx.has_data_type_selected
    }

    /// Returns `true` if the data type definition can be edited.
    pub fn is_edit_data_type_allowed(&self, ctx: &DataListingContext) -> bool {
        !self.disposed && ctx.is_data_location && ctx.data_type_name.is_some()
    }

    /// Returns `true` if cycling is allowed for the given group.
    pub fn is_cycle_allowed(&self, ctx: &DataListingContext, _group_name: &str) -> bool {
        !self.disposed && ctx.is_data_location && ctx.data_type_name.is_some()
    }

    // -- Callbacks -------------------------------------------------------

    /// Callback for the pointer action.
    pub fn perform_pointer(&mut self, ctx: &DataListingContext) -> Result<DataCreationResult, DataCreationError> {
        self.callback_log.push(format!("perform_pointer(0x{:X})", ctx.address.offset));
        let action_ctx = ctx.to_action_context();
        let result = self.create_data("pointer", &action_ctx, false, true)?;
        self.update_recently_used("pointer");
        Ok(result)
    }

    /// Callback for the recently used action.
    pub fn perform_recently_used(&mut self, ctx: &DataListingContext) -> Result<DataCreationResult, DataCreationError> {
        let recent = self.recent_data_type_name()
            .ok_or(DataCreationError::NoAddress)?
            .to_string();
        self.callback_log.push(format!("perform_recently_used(0x{:X}, {})", ctx.address.offset, recent));
        let action_ctx = ctx.to_action_context();
        self.create_data(&recent, &action_ctx, false, true)
    }

    /// Callback for the create array action.
    pub fn perform_create_array(&mut self, ctx: &DataListingContext) -> Result<DataCreationResult, DataCreationError> {
        self.callback_log.push(format!("perform_create_array(0x{:X})", ctx.address.offset));
        // In a full implementation, this would show the CreateArrayDialog.
        // For now, record the intent.
        let action_ctx = ctx.to_action_context();
        self.create_data("array", &action_ctx, false, true)
    }

    /// Callback for the create structure action.
    pub fn perform_create_structure(&mut self, ctx: &DataListingContext) -> Result<DataCreationResult, DataCreationError> {
        self.callback_log.push(format!("perform_create_structure(0x{:X})", ctx.address.offset));
        // In a full implementation, this would show the CreateStructureDialog.
        let action_ctx = ctx.to_action_context();
        self.create_data("structure", &action_ctx, false, true)
    }

    /// Callback for the choose data type action.
    pub fn perform_choose_data_type(&mut self, ctx: &DataListingContext) {
        self.callback_log.push(format!("perform_choose_data_type(0x{:X})", ctx.address.offset));
        // In a full implementation, this would show the DataTypeChooserDialog.
    }

    /// Callback for the settings action.
    pub fn perform_settings(&mut self, ctx: &DataListingContext) {
        self.callback_log.push(format!("perform_settings(0x{:X})", ctx.address.offset));
        // In a full implementation, this would show the DataSettingsDialog.
    }

    /// Callback for the default settings action.
    pub fn perform_default_settings(&mut self, ctx: &DataListingContext) {
        self.callback_log.push(format!("perform_default_settings(0x{:X})", ctx.address.offset));
        // In a full implementation, this would show the DataTypeSettingsDialog.
    }

    /// Callback for the edit data type action.
    pub fn perform_edit_data_type(&mut self, ctx: &DataListingContext) {
        self.callback_log.push(format!("perform_edit_data_type(0x{:X})", ctx.address.offset));
        // In a full implementation, this would open the data type editor.
    }

    /// Callback for a cycle group action.
    pub fn perform_cycle(
        &mut self,
        ctx: &DataListingContext,
        group_name: &str,
    ) -> Result<DataCreationResult, DataCreationError> {
        let current = ctx.data_type_name.as_deref().unwrap_or("byte");
        let next = self.get_next_cycle_type(current, group_name)
            .ok_or(DataCreationError::NotSupported(format!("No cycle group: {}", group_name)))?;
        self.callback_log.push(format!("perform_cycle(0x{:X}, {})", ctx.address.offset, next));
        let action_ctx = ctx.to_action_context();
        let result = self.create_data(&next, &action_ctx, false, true)?;
        self.update_recently_used(&next);
        Ok(result)
    }

    // -- Data creation ---------------------------------------------------

    /// Creates data of the given type at the context location.
    pub fn create_data(
        &self,
        data_type_name: &str,
        ctx: &DataActionContext,
        force: bool,
        update_recent: bool,
    ) -> Result<DataCreationResult, DataCreationError> {
        let addr = ctx.address.ok_or(DataCreationError::NoAddress)?;
        Ok(DataCreationResult {
            address: addr,
            data_type_name: data_type_name.to_string(),
            length: ctx.data_size.unwrap_or(1),
            success: true,
        })
    }

    // -- Status ----------------------------------------------------------

    /// Sets the status message.
    pub fn set_status(&mut self, msg: impl Into<String>) {
        self.last_status = Some(msg.into());
    }

    /// Returns the last status message.
    pub fn status(&self) -> Option<&str> {
        self.last_status.as_deref()
    }

    /// Returns the callback log (for testing).
    pub fn callback_log(&self) -> &[String] {
        &self.callback_log
    }

    /// Clears the callback log.
    pub fn clear_callback_log(&mut self) {
        self.callback_log.clear();
    }

    // -- Dispose ---------------------------------------------------------

    /// Disposes the plugin and releases all resources.
    pub fn dispose(&mut self) {
        self.actions.clear();
        self.cycle_groups.clear();
        self.favorites.clear();
        self.recently_used.clear();
        self.disposed = true;
        self.callback_log.push("dispose".to_string());
    }

    /// Returns whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }
}

impl Default for DataPluginFull {
    fn default() -> Self {
        Self::new("DataPlugin")
    }
}

impl Drop for DataPluginFull {
    fn drop(&mut self) {
        if !self.disposed {
            self.dispose();
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    // -- Plugin construction --

    #[test]
    fn test_plugin_new() {
        let plugin = DataPluginFull::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_disposed());
        assert_eq!(plugin.actions().len(), 8);
    }

    #[test]
    fn test_plugin_default() {
        let plugin = DataPluginFull::default();
        assert_eq!(plugin.name(), "DataPlugin");
    }

    // -- Cycle groups --

    #[test]
    fn test_default_cycle_groups() {
        let plugin = DataPluginFull::new("TestPlugin");
        assert!(plugin.cycle_group_names().len() >= 4);
        assert!(plugin.cycle_group_types("DataSize").is_some());
    }

    #[test]
    fn test_get_next_cycle_type() {
        let plugin = DataPluginFull::new("TestPlugin");
        assert_eq!(plugin.get_next_cycle_type("byte", "DataSize"), Some("word".into()));
        assert_eq!(plugin.get_next_cycle_type("dword", "DataSize"), Some("qword".into()));
        assert_eq!(plugin.get_next_cycle_type("qword", "DataSize"), Some("byte".into()));
        assert_eq!(plugin.get_next_cycle_type("byte", "NoSuchGroup"), None);
    }

    #[test]
    fn test_add_cycle_group() {
        let mut plugin = DataPluginFull::new("TestPlugin");
        plugin.add_cycle_group("Custom", vec!["a".into(), "b".into(), "c".into()]);
        assert_eq!(plugin.get_next_cycle_type("a", "Custom"), Some("b".into()));
    }

    // -- Favourites --

    #[test]
    fn test_favorites() {
        let mut plugin = DataPluginFull::new("TestPlugin");
        assert_eq!(plugin.favorites_count(), 0);

        plugin.add_favorite("int");
        plugin.add_favorite("float");
        assert_eq!(plugin.favorites_count(), 2);

        // Duplicate ignored
        plugin.add_favorite("int");
        assert_eq!(plugin.favorites_count(), 2);

        assert!(plugin.remove_favorite("int"));
        assert_eq!(plugin.favorites_count(), 1);
        assert!(!plugin.remove_favorite("int"));
    }

    // -- Recently used --

    #[test]
    fn test_recently_used() {
        let mut plugin = DataPluginFull::new("TestPlugin");
        assert!(plugin.recent_data_type_name().is_none());

        plugin.update_recently_used("int");
        assert_eq!(plugin.recent_data_type_name(), Some("int"));

        plugin.update_recently_used("float");
        assert_eq!(plugin.recent_data_type_name(), Some("float"));

        // Duplicate moves to front
        plugin.update_recently_used("int");
        assert_eq!(plugin.recent_data_type_name(), Some("int"));
    }

    #[test]
    fn test_recently_used_max() {
        let mut plugin = DataPluginFull::new("TestPlugin");
        for i in 0..15 {
            plugin.update_recently_used(&format!("type_{}", i));
        }
        assert_eq!(plugin.recently_used_names().len(), 10);
        assert_eq!(plugin.recent_data_type_name(), Some("type_14"));
    }

    // -- Enablement --

    #[test]
    fn test_is_create_data_allowed() {
        let plugin = DataPluginFull::new("TestPlugin");
        let ctx = DataListingContext::at_data(addr(0x1000), "byte", 1);
        assert!(plugin.is_create_data_allowed(&ctx));

        let empty = DataListingContext::with_selection(addr(0), addr(0));
        assert!(!plugin.is_create_data_allowed(&empty));
    }

    #[test]
    fn test_is_data_settings_allowed() {
        let plugin = DataPluginFull::new("TestPlugin");
        let ctx = DataListingContext::at_data(addr(0x1000), "byte", 1);
        assert!(plugin.is_data_settings_allowed(&ctx));

        let no_data = DataListingContext::with_selection(addr(0x1000), addr(0x1010));
        assert!(!plugin.is_data_settings_allowed(&no_data));
    }

    #[test]
    fn test_is_default_settings_allowed() {
        let plugin = DataPluginFull::new("TestPlugin");
        let ctx = DataListingContext::with_data_type_selected(addr(0x1000), "int");
        assert!(plugin.is_default_settings_allowed(&ctx));
    }

    #[test]
    fn test_get_enabled_actions() {
        let plugin = DataPluginFull::new("TestPlugin");
        let ctx = DataListingContext::at_data(addr(0x1000), "byte", 1);
        let enabled = plugin.get_enabled_actions(&ctx);

        assert!(enabled.contains(&DataActionKind::Pointer));
        assert!(enabled.contains(&DataActionKind::Settings));
        assert!(enabled.contains(&DataActionKind::ChooseDataType));
    }

    #[test]
    fn test_get_enabled_actions_disposed() {
        let mut plugin = DataPluginFull::new("TestPlugin");
        plugin.dispose();

        let ctx = DataListingContext::at_data(addr(0x1000), "byte", 1);
        let enabled = plugin.get_enabled_actions(&ctx);
        assert!(enabled.is_empty());
    }

    // -- Callbacks --

    #[test]
    fn test_perform_pointer() {
        let mut plugin = DataPluginFull::new("TestPlugin");
        let ctx = DataListingContext::at_data(addr(0x1000), "byte", 1);
        let result = plugin.perform_pointer(&ctx).unwrap();
        assert!(result.success);
        assert_eq!(plugin.recent_data_type_name(), Some("pointer"));
    }

    #[test]
    fn test_perform_recently_used_empty() {
        let mut plugin = DataPluginFull::new("TestPlugin");
        let ctx = DataListingContext::at_data(addr(0x1000), "byte", 1);
        let result = plugin.perform_recently_used(&ctx);
        assert!(result.is_err());
    }

    #[test]
    fn test_perform_recently_used_with_data() {
        let mut plugin = DataPluginFull::new("TestPlugin");
        plugin.update_recently_used("dword");
        let ctx = DataListingContext::at_data(addr(0x1000), "byte", 1);
        let result = plugin.perform_recently_used(&ctx).unwrap();
        assert_eq!(result.data_type_name, "dword");
    }

    #[test]
    fn test_perform_cycle() {
        let mut plugin = DataPluginFull::new("TestPlugin");
        let ctx = DataListingContext::at_data(addr(0x1000), "byte", 4);
        let result = plugin.perform_cycle(&ctx, "DataSize").unwrap();
        assert_eq!(result.data_type_name, "word");
        assert_eq!(plugin.recent_data_type_name(), Some("word"));
    }

    #[test]
    fn test_perform_cycle_unknown_group() {
        let mut plugin = DataPluginFull::new("TestPlugin");
        let ctx = DataListingContext::at_data(addr(0x1000), "byte", 4);
        let result = plugin.perform_cycle(&ctx, "NoSuchGroup");
        assert!(result.is_err());
    }

    #[test]
    fn test_callback_log() {
        let mut plugin = DataPluginFull::new("TestPlugin");
        let ctx = DataListingContext::at_data(addr(0x1000), "byte", 1);
        plugin.perform_settings(&ctx);
        plugin.perform_choose_data_type(&ctx);
        assert_eq!(plugin.callback_log().len(), 2);
    }

    // -- Dispose --

    #[test]
    fn test_dispose() {
        let mut plugin = DataPluginFull::new("TestPlugin");
        assert!(!plugin.is_disposed());
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(plugin.actions().is_empty());
    }

    // -- DataListingContext --

    #[test]
    fn test_listing_context_at_data() {
        let ctx = DataListingContext::at_data(addr(0x1000), "byte", 1);
        assert_eq!(ctx.address, addr(0x1000));
        assert!(ctx.is_data_location);
        assert_eq!(ctx.data_type_name.as_deref(), Some("byte"));
    }

    #[test]
    fn test_listing_context_with_selection() {
        let ctx = DataListingContext::with_selection(addr(0x1000), addr(0x1010));
        assert!(ctx.has_selection);
        assert_eq!(ctx.selection_size(), Some(0x11));
    }

    #[test]
    fn test_listing_context_at_component() {
        let ctx = DataListingContext::at_component(addr(0x1000), "dword", 4, vec![0, 2]);
        assert!(ctx.is_component_location);
        assert_eq!(ctx.component_path, vec![0, 2]);
    }

    #[test]
    fn test_listing_context_to_action_context() {
        let ctx = DataListingContext::at_data(addr(0x1000), "byte", 1);
        let action_ctx = ctx.to_action_context();
        assert_eq!(action_ctx.address, Some(addr(0x1000)));
        assert!(action_ctx.is_data_location);
    }

    // -- DataRegisteredAction --

    #[test]
    fn test_registered_action_for_pointer() {
        let action = DataRegisteredAction::for_kind(DataActionKind::Pointer);
        assert_eq!(action.display_name, "pointer");
        assert_eq!(action.key_binding, Some('P'));
        assert!(action.is_enabled());
    }

    #[test]
    fn test_registered_action_set_enabled() {
        let mut action = DataRegisteredAction::for_kind(DataActionKind::Settings);
        assert!(action.is_enabled());
        action.set_enabled(false);
        assert!(!action.is_enabled());
    }

    // -- Full workflow --

    #[test]
    fn test_full_workflow() {
        let mut plugin = DataPluginFull::new("TestPlugin");

        // Create a pointer
        let ctx = DataListingContext::at_data(addr(0x1000), "byte", 1);
        let result = plugin.perform_pointer(&ctx).unwrap();
        assert!(result.success);

        // Cycle
        let ctx = DataListingContext::at_data(addr(0x2000), "byte", 1);
        let result = plugin.perform_cycle(&ctx, "DataSize").unwrap();
        assert_eq!(result.data_type_name, "word");

        // Recently used
        let ctx = DataListingContext::at_data(addr(0x3000), "dword", 4);
        let result = plugin.perform_recently_used(&ctx).unwrap();
        assert_eq!(result.data_type_name, "word");

        // Add favourite
        plugin.add_favorite("dword");
        assert_eq!(plugin.favorites_count(), 1);

        // Dispose
        plugin.dispose();
        assert!(plugin.is_disposed());
    }
}
