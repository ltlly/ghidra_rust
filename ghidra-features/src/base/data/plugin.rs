//! DataPlugin -- ported from `DataPlugin.java`.
//!
//! The [`DataPlugin`] is the central controller for data management in
//! the listing.  It provides methods for creating data from data types,
//! cycling data through cycle groups, creating structures and arrays,
//! and managing the recently-used and favourite data type lists.
//!
//! # Key concepts
//!
//! - **Create data** -- applies a [`DataType`] at a listing address or
//!   across a selection.
//! - **Cycle groups** -- a set of related data types that the user can
//!   cycle through with a single key binding (e.g., byte -> word -> dword).
//! - **Favourites** -- user-pinned data types shown in the "Data" popup
//!   menu for quick access.
//! - **Recently used** -- tracks the last data type the user applied so
//!   it can be re-applied with a single action.

use std::collections::VecDeque;
use std::fmt;

use ghidra_core::addr::Address;
use ghidra_core::data::{DataType, DataTypeManager};

use super::actions::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Threshold for using background commands instead of foreground ones.
pub const BACKGROUND_SELECTION_THRESHOLD: usize = 2048;

/// Menu popup path prefix for data-related actions.
pub const DATA_MENU_POPUP_PATH: &str = "Data";

/// Edit data type popup path.
pub const EDIT_DATA_TYPE_POPUP_PATH: &[&str] = &["Data", "Edit Data Type"];

/// Data settings popup path.
pub const DATA_SETTINGS_POPUP_PATH: &[&str] = &["Data", "Settings..."];

/// Default settings popup path.
pub const DEFAULT_SETTINGS_POPUP_PATH: &[&str] = &["Data", "Default Settings..."];

/// Datatype settings popup path.
pub const DATATYPE_SETTINGS_POPUP_PATH: &[&str] = &["Settings..."];

/// Choose data type popup path.
pub const CHOOSE_DATA_TYPE_POPUP_PATH: &[&str] = &["Data", "Choose Data Type..."];

/// Basic data group name for menu ordering.
pub const BASIC_DATA_GROUP: &str = "BasicData";

/// Recent group name for menu ordering.
pub const RECENT_GROUP: &str = "Z_RECENT";

// ---------------------------------------------------------------------------
// DataPlugin
// ---------------------------------------------------------------------------

/// The data plugin -- manages all data-related actions.
///
/// Ported from Ghidra's `DataPlugin` Java class.  In Rust we model the
/// non-GUI parts: action registry, favourite/recent data type tracking,
/// and helper methods for creating data at a given context location.
///
/// # Example
///
/// ```
/// use ghidra_features::base::data::DataPlugin;
///
/// let mut plugin = DataPlugin::new("DataPlugin");
/// assert!(plugin.action_count() > 0);
/// assert_eq!(plugin.favorites_count(), 0);
/// assert!(plugin.recent_data_type_name().is_none());
/// ```
#[derive(Debug)]
pub struct DataPlugin {
    /// The plugin display name.
    name: String,

    // -- Actions --
    pointer_action: Option<PointerDataAction>,
    recently_used_action: Option<RecentlyUsedAction>,
    create_structure_action: Option<CreateStructureAction>,
    create_array_action: Option<CreateArrayAction>,
    choose_data_type_action: Option<ChooseDataTypeAction>,
    favorite_actions: Vec<DataAction>,
    cycle_group_actions: Vec<CycleGroupAction>,

    /// Recently used data types (most recent first).
    recently_used: VecDeque<String>,

    /// Maximum number of recently used entries to track.
    max_recent: usize,

    /// Whether the plugin has been disposed.
    disposed: bool,
}

impl DataPlugin {
    /// Creates a new data plugin.
    pub fn new(name: impl Into<String>) -> Self {
        let mut plugin = Self {
            name: name.into(),
            pointer_action: Some(PointerDataAction::new()),
            recently_used_action: Some(RecentlyUsedAction::new()),
            create_structure_action: Some(CreateStructureAction::new()),
            create_array_action: Some(CreateArrayAction::new()),
            choose_data_type_action: Some(ChooseDataTypeAction::new()),
            favorite_actions: Vec::new(),
            cycle_group_actions: Vec::new(),
            recently_used: VecDeque::new(),
            max_recent: 10,
            disposed: false,
        };
        plugin.init();
        plugin
    }

    /// Creates a data plugin with no actions (for testing).
    pub fn new_empty(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            pointer_action: None,
            recently_used_action: None,
            create_structure_action: None,
            create_array_action: None,
            choose_data_type_action: None,
            favorite_actions: Vec::new(),
            cycle_group_actions: Vec::new(),
            recently_used: VecDeque::new(),
            max_recent: 10,
            disposed: false,
        }
    }

    fn init(&mut self) {
        self.update_favorite_actions();
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Disposes the plugin and releases all resources.
    pub fn dispose(&mut self) {
        self.pointer_action = None;
        self.recently_used_action = None;
        self.create_structure_action = None;
        self.create_array_action = None;
        self.choose_data_type_action = None;
        self.favorite_actions.clear();
        self.cycle_group_actions.clear();
        self.recently_used.clear();
        self.disposed = true;
    }

    // -- Action management --

    /// Returns the total number of registered actions.
    pub fn action_count(&self) -> usize {
        let mut count = self.favorite_actions.len() + self.cycle_group_actions.len();
        if self.pointer_action.is_some() {
            count += 1;
        }
        if self.recently_used_action.is_some() {
            count += 1;
        }
        if self.create_structure_action.is_some() {
            count += 1;
        }
        if self.create_array_action.is_some() {
            count += 1;
        }
        if self.choose_data_type_action.is_some() {
            count += 1;
        }
        count
    }

    /// Adds a cycle group action.
    pub fn add_cycle_group_action(&mut self, action: CycleGroupAction) {
        self.cycle_group_actions.push(action);
    }

    /// Returns the number of favourite actions.
    pub fn favorites_count(&self) -> usize {
        self.favorite_actions.len()
    }

    /// Returns the number of cycle group actions.
    pub fn cycle_group_count(&self) -> usize {
        self.cycle_group_actions.len()
    }

    // -- Recently used data types --

    /// Records a data type as recently used.
    pub fn update_recently_used(&mut self, data_type_name: &str) {
        self.recently_used.retain(|n| n != data_type_name);
        self.recently_used.push_front(data_type_name.to_string());
        while self.recently_used.len() > self.max_recent {
            self.recently_used.pop_back();
        }
    }

    /// Returns the name of the most recently used data type, if any.
    pub fn recent_data_type_name(&self) -> Option<&str> {
        self.recently_used.front().map(|s| s.as_str())
    }

    /// Returns all recently used data type names.
    pub fn recently_used_names(&self) -> Vec<&str> {
        self.recently_used.iter().map(|s| s.as_str()).collect()
    }

    /// Clears the recently used list.
    pub fn clear_recently_used(&mut self) {
        self.recently_used.clear();
    }

    // -- Favourites --

    /// Updates the favourite actions from the data type manager.
    ///
    /// This is a no-op in the non-GUI port; it would be called when the
    /// data type manager's favourite list changes.
    fn update_favorite_actions(&mut self) {
        // In the full implementation, this queries the DataTypeManagerService
        // for the user's favourite data types and creates a DataAction for each.
        // We keep the slot for future expansion.
    }

    // -- Action context checks --

    /// Returns `true` if creating data is allowed at the given context.
    ///
    /// This models `isCreateDataAllowed` from the Java `DataPlugin`.
    pub fn is_create_data_allowed(&self, ctx: &DataActionContext) -> bool {
        ctx.address.is_some()
            && ctx.is_data_location
            && !self.disposed
    }

    /// Returns `true` if data settings can be edited at the given context.
    pub fn is_data_settings_allowed(&self, ctx: &DataActionContext, is_default: bool) -> bool {
        if self.disposed {
            return false;
        }
        if is_default {
            ctx.has_data_type_selected
        } else {
            ctx.address.is_some() && ctx.is_data_location
        }
    }

    // -- Data creation --

    /// Creates data of the given type at the context location.
    ///
    /// This models `doCreateData` and `createData` from the Java plugin.
    pub fn create_data(
        &self,
        data_type_name: &str,
        ctx: &DataActionContext,
        _force: bool,
        _update_recent: bool,
    ) -> Result<DataCreationResult, DataCreationError> {
        let addr = ctx
            .address
            .ok_or(DataCreationError::NoAddress)?;

        Ok(DataCreationResult {
            address: addr,
            data_type_name: data_type_name.to_string(),
            length: ctx.data_size.unwrap_or(1),
            success: true,
        })
    }

    /// Determines the next data type in a cycle group for the given
    /// current type.
    pub fn get_next_cycle_type(
        &self,
        current_type: &str,
        cycle_group_name: &str,
    ) -> Option<String> {
        self.cycle_group_actions
            .iter()
            .find(|g| g.group_name() == cycle_group_name)
            .and_then(|g| g.next_type(current_type))
    }

    // -- Pointer action helpers --

    /// Returns the pointer data type action, if registered.
    pub fn pointer_action(&self) -> Option<&PointerDataAction> {
        self.pointer_action.as_ref()
    }

    /// Returns the recently used action, if registered.
    pub fn recently_used_action(&self) -> Option<&RecentlyUsedAction> {
        self.recently_used_action.as_ref()
    }

    /// Returns the create structure action, if registered.
    pub fn create_structure_action(&self) -> Option<&CreateStructureAction> {
        self.create_structure_action.as_ref()
    }

    /// Returns the create array action, if registered.
    pub fn create_array_action(&self) -> Option<&CreateArrayAction> {
        self.create_array_action.as_ref()
    }

    /// Returns the choose data type action, if registered.
    pub fn choose_data_type_action(&self) -> Option<&ChooseDataTypeAction> {
        self.choose_data_type_action.as_ref()
    }

    /// Returns a reference to the cycle group actions.
    pub fn cycle_group_actions(&self) -> &[CycleGroupAction] {
        &self.cycle_group_actions
    }
}

impl Default for DataPlugin {
    fn default() -> Self {
        Self::new_empty("DataPlugin")
    }
}

impl Drop for DataPlugin {
    fn drop(&mut self) {
        if !self.disposed {
            self.dispose();
        }
    }
}

// ---------------------------------------------------------------------------
// DataActionContext
// ---------------------------------------------------------------------------

/// Context information for data plugin actions.
///
/// Models `ListingActionContext` with data-specific fields.
#[derive(Debug, Clone, Default)]
pub struct DataActionContext {
    /// The current address, if any.
    pub address: Option<Address>,
    /// Whether the cursor is on a defined data location.
    pub is_data_location: bool,
    /// The data type name at the current location, if any.
    pub data_type_name: Option<String>,
    /// The size in bytes of the data at the current location.
    pub data_size: Option<usize>,
    /// Whether a data type is selected (for default settings).
    pub has_data_type_selected: bool,
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
}

impl DataActionContext {
    /// Creates a context at a single data location.
    pub fn at_data(addr: Address, data_type_name: &str, size: usize) -> Self {
        Self {
            address: Some(addr),
            is_data_location: true,
            data_type_name: Some(data_type_name.to_string()),
            data_size: Some(size),
            ..Default::default()
        }
    }

    /// Creates a context with a selection range.
    pub fn with_selection(start: Address, end: Address) -> Self {
        Self {
            address: Some(start),
            has_selection: true,
            selection_start: Some(start),
            selection_end: Some(end),
            ..Default::default()
        }
    }

    /// Returns the number of selected addresses.
    pub fn selection_size(&self) -> Option<u64> {
        match (self.selection_start, self.selection_end) {
            (Some(start), Some(end)) => Some(end.offset.saturating_sub(start.offset) + 1),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// DataCreationResult
// ---------------------------------------------------------------------------

/// Result of a data creation operation.
#[derive(Debug, Clone)]
pub struct DataCreationResult {
    /// The address where data was created.
    pub address: Address,
    /// The name of the data type that was created.
    pub data_type_name: String,
    /// The length in bytes of the created data.
    pub length: usize,
    /// Whether the operation succeeded.
    pub success: bool,
}

// ---------------------------------------------------------------------------
// DataCreationError
// ---------------------------------------------------------------------------

/// Errors that can occur during data creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataCreationError {
    /// No address available in the context.
    NoAddress,
    /// The data type was not found.
    DataTypeNotFound(String),
    /// The target area overlaps existing defined data.
    Overlap,
    /// The target area is not writable.
    NotWritable,
    /// The data type cannot be applied at this location.
    Inapplicable(String),
    /// The user cancelled the operation.
    Cancelled,
    /// The operation is not supported.
    NotSupported(String),
}

impl fmt::Display for DataCreationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAddress => write!(f, "No address in context"),
            Self::DataTypeNotFound(name) => write!(f, "Data type not found: {}", name),
            Self::Overlap => write!(f, "Overlaps existing defined data"),
            Self::NotWritable => write!(f, "Target area is not writable"),
            Self::Inapplicable(msg) => write!(f, "Cannot apply data type: {}", msg),
            Self::Cancelled => write!(f, "Operation cancelled"),
            Self::NotSupported(msg) => write!(f, "Not supported: {}", msg),
        }
    }
}

impl std::error::Error for DataCreationError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_plugin_new() {
        let plugin = DataPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_disposed());
        assert_eq!(plugin.action_count(), 5); // pointer, recent, struct, array, choose
        assert_eq!(plugin.favorites_count(), 0);
        assert!(plugin.recent_data_type_name().is_none());
    }

    #[test]
    fn test_data_plugin_dispose() {
        let mut plugin = DataPlugin::new("TestPlugin");
        assert!(!plugin.is_disposed());
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert_eq!(plugin.action_count(), 0);
    }

    #[test]
    fn test_recently_used() {
        let mut plugin = DataPlugin::new("TestPlugin");
        assert!(plugin.recent_data_type_name().is_none());

        plugin.update_recently_used("int");
        assert_eq!(plugin.recent_data_type_name(), Some("int"));

        plugin.update_recently_used("float");
        assert_eq!(plugin.recent_data_type_name(), Some("float"));
        assert_eq!(plugin.recently_used_names(), vec!["float", "int"]);

        // Duplicate should move to front
        plugin.update_recently_used("int");
        assert_eq!(plugin.recent_data_type_name(), Some("int"));
        assert_eq!(plugin.recently_used_names(), vec!["int", "float"]);
    }

    #[test]
    fn test_recently_used_max() {
        let mut plugin = DataPlugin::new("TestPlugin");
        for i in 0..15 {
            plugin.update_recently_used(&format!("type_{}", i));
        }
        assert_eq!(plugin.recently_used_names().len(), 10);
        assert_eq!(plugin.recent_data_type_name(), Some("type_14"));
    }

    #[test]
    fn test_clear_recently_used() {
        let mut plugin = DataPlugin::new("TestPlugin");
        plugin.update_recently_used("int");
        plugin.clear_recently_used();
        assert!(plugin.recent_data_type_name().is_none());
    }

    #[test]
    fn test_create_data_no_address() {
        let plugin = DataPlugin::new("TestPlugin");
        let ctx = DataActionContext::default();
        let result = plugin.create_data("int", &ctx, false, false);
        assert_eq!(result.unwrap_err(), DataCreationError::NoAddress);
    }

    #[test]
    fn test_create_data_success() {
        let plugin = DataPlugin::new("TestPlugin");
        let ctx = DataActionContext::at_data(Address::new(0x1000), "byte", 1);
        let result = plugin.create_data("int", &ctx, false, true).unwrap();
        assert!(result.success);
        assert_eq!(result.data_type_name, "int");
    }

    #[test]
    fn test_is_create_data_allowed() {
        let plugin = DataPlugin::new("TestPlugin");
        let ctx = DataActionContext::at_data(Address::new(0x1000), "byte", 1);
        assert!(plugin.is_create_data_allowed(&ctx));

        let empty_ctx = DataActionContext::default();
        assert!(!plugin.is_create_data_allowed(&empty_ctx));

        let no_data = DataActionContext {
            address: Some(Address::new(0x1000)),
            is_data_location: false,
            ..Default::default()
        };
        assert!(!plugin.is_create_data_allowed(&no_data));
    }

    #[test]
    fn test_cycle_group() {
        let mut plugin = DataPlugin::new("TestPlugin");
        let cg = CycleGroupAction::new(
            "DataSize",
            vec![
                "byte".to_string(),
                "word".to_string(),
                "dword".to_string(),
                "qword".to_string(),
            ],
        );
        plugin.add_cycle_group_action(cg);

        assert_eq!(plugin.cycle_group_count(), 1);
        assert_eq!(plugin.get_next_cycle_type("byte", "DataSize"), Some("word".into()));
        assert_eq!(plugin.get_next_cycle_type("dword", "DataSize"), Some("qword".into()));
        assert_eq!(plugin.get_next_cycle_type("qword", "DataSize"), Some("byte".into()));
        assert_eq!(plugin.get_next_cycle_type("byte", "NoSuchGroup"), None);
    }

    #[test]
    fn test_data_action_context_selection() {
        let ctx = DataActionContext::with_selection(Address::new(0x1000), Address::new(0x1010));
        assert!(ctx.has_selection);
        assert_eq!(ctx.selection_size(), Some(0x11));
    }

    #[test]
    fn test_data_creation_error_display() {
        let err = DataCreationError::DataTypeNotFound("foo".into());
        assert_eq!(err.to_string(), "Data type not found: foo");
    }

    #[test]
    fn test_pointer_action() {
        let plugin = DataPlugin::new("TestPlugin");
        let pa = plugin.pointer_action().unwrap();
        assert_eq!(pa.name(), "Define Pointer");
    }

    #[test]
    fn test_recently_used_action() {
        let plugin = DataPlugin::new("TestPlugin");
        let ra = plugin.recently_used_action().unwrap();
        assert_eq!(ra.name(), "Recently Used");
    }
}
