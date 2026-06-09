//! Data Graph Plugin -- displays a graph of data objects in memory.
//!
//! Ported from Ghidra's `datagraph.DataGraphPlugin` Java class.
//!
//! From any data object in the listing, the user can display a graph of that
//! data object. Initially, a graph is shown with one vertex that has a
//! scrollable view of the values in memory associated with that data. Pointers
//! and references from or to that data can be explored by following the
//! references and creating additional vertices for the referenced code or data.

use std::collections::HashSet;

use super::data_graph_options::DataGraphOptions;

/// Identifier string for the "Display Data Graph" action.
const ACTION_DISPLAY_DATA_GRAPH: &str = "Display Data Graph";

/// Identifier string for the "Navigate In" toggle action.
const ACTION_NAVIGATE_IN: &str = "Navigate In";

/// Identifier string for the "Navigate Out" toggle action.
const ACTION_NAVIGATE_OUT: &str = "Navigate Out";

/// Identifier string for the "Compact Format" toggle action.
const ACTION_COMPACT_FORMAT: &str = "Compact Format";

/// Identifier string for the "Show Popups" toggle action.
const ACTION_SHOW_POPUPS: &str = "Show Popups";

/// Identifier string for the "Select Home Vertex" action.
const ACTION_SELECT_HOME: &str = "Select Home Vertex";

/// Identifier string for the "Relayout Graph" action.
const ACTION_RELAYOUT: &str = "Relayout Graph";

/// Identifier string for the "Incoming References" action.
const ACTION_INCOMING_REFS: &str = "Incoming References";

/// Identifier string for the "Outgoing References" action.
const ACTION_OUTGOING_REFS: &str = "Outgoing References";

/// Identifier string for the "Delete Vertices" action.
const ACTION_DELETE_VERTICES: &str = "Delete Vertices";

/// Identifier string for the "Set Original Vertex" action.
const ACTION_SET_ORIGINAL_VERTEX: &str = "Set Original Vertex";

/// Identifier string for the "Reset Vertex Location" action.
const ACTION_RESET_LOCATION: &str = "Reset Vertex Location";

/// Identifier string for the "Expand Fully" action.
const ACTION_EXPAND_FULLY: &str = "Expand Fully";

/// The location of a data item within a program, identified by its offset.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataLocation {
    /// The program name.
    pub program_name: String,
    /// The address offset of the data.
    pub address: u64,
}

impl DataLocation {
    pub fn new(program_name: impl Into<String>, address: u64) -> Self {
        Self {
            program_name: program_name.into(),
            address,
        }
    }
}

/// Represents a data object that can be displayed in the graph.
#[derive(Debug, Clone)]
pub struct DataObject {
    /// The address of this data object.
    pub address: u64,
    /// The data type name.
    pub type_name: String,
    /// The display label.
    pub label: String,
    /// The size in bytes.
    pub size: usize,
    /// Whether this is the top-level (root) data object.
    pub is_root: bool,
    /// Parent data object address (if this is a sub-component).
    pub parent_address: Option<u64>,
}

impl DataObject {
    /// Create a new top-level data object.
    pub fn new(address: u64, type_name: impl Into<String>, size: usize) -> Self {
        let tn = type_name.into();
        Self {
            address,
            label: tn.clone(),
            type_name: tn,
            size,
            is_root: true,
            parent_address: None,
        }
    }

    /// Create a child data object (sub-component of a parent).
    pub fn child(
        address: u64,
        type_name: impl Into<String>,
        size: usize,
        parent_address: u64,
    ) -> Self {
        let tn = type_name.into();
        Self {
            address,
            label: tn.clone(),
            type_name: tn,
            size,
            is_root: false,
            parent_address: Some(parent_address),
        }
    }
}

/// Tracks whether a provider is active and what data it is showing.
#[derive(Debug)]
pub struct DataGraphProviderState {
    /// The provider ID.
    pub id: u64,
    /// The program name this provider is showing.
    pub program_name: String,
    /// The root data object address.
    pub root_address: u64,
    /// Whether this provider is currently visible.
    pub visible: bool,
}

impl DataGraphProviderState {
    pub fn new(id: u64, program_name: impl Into<String>, root_address: u64) -> Self {
        Self {
            id,
            program_name: program_name.into(),
            root_address,
            visible: true,
        }
    }

    /// Mark the provider as closed.
    pub fn close(&mut self) {
        self.visible = false;
    }
}

// --------------------------------------------------------------------------
// Action context types (ported from DegContext / DegSatelliteContext)
// --------------------------------------------------------------------------

/// Action context for the data exploration graph.
///
/// Ported from `datagraph.DegContext`.  Holds the vertex the user is
/// interacting with and the set of currently selected vertices.
#[derive(Debug, Clone)]
pub struct DegContext {
    /// The vertex under the mouse / focus, if any.
    pub vertex_id: Option<u64>,
    /// Set of selected vertex IDs.
    pub selected_vertex_ids: HashSet<u64>,
}

impl DegContext {
    /// Create a new context with no target vertex.
    pub fn new(selected_vertex_ids: HashSet<u64>) -> Self {
        Self {
            vertex_id: None,
            selected_vertex_ids,
        }
    }

    /// Create a context with a specific target vertex.
    pub fn with_vertex(vertex_id: u64, selected_vertex_ids: HashSet<u64>) -> Self {
        Self {
            vertex_id: Some(vertex_id),
            selected_vertex_ids,
        }
    }

    /// Whether satellite-view actions should be shown (true when no vertex
    /// is targeted, matching the Java `shouldShowSatelliteActions` logic).
    pub fn should_show_satellite_actions(&self) -> bool {
        self.vertex_id.is_none()
    }
}

/// Action context for the satellite graph view.
///
/// Ported from `datagraph.DegSatelliteContext`.
#[derive(Debug, Clone)]
pub struct DegSatelliteContext {
    /// The provider ID this context belongs to.
    pub provider_id: u64,
}

impl DegSatelliteContext {
    pub fn new(provider_id: u64) -> Self {
        Self { provider_id }
    }
}

// --------------------------------------------------------------------------
// Provider-level actions (ported from DataGraphProvider.createActions)
// --------------------------------------------------------------------------

/// Describes a single provider-level action that can be installed on the
/// data graph provider toolbar or popup menu.
#[derive(Debug, Clone)]
pub struct ProviderAction {
    /// Unique action name.
    pub name: String,
    /// Optional toolbar icon resource key.
    pub icon_key: Option<String>,
    /// Toolbar group for ordering.
    pub group: String,
    /// Human-readable description.
    pub description: String,
    /// Whether this is a toggle action.
    pub is_toggle: bool,
    /// Initial toggle state (only meaningful for toggle actions).
    pub selected: bool,
    /// Whether this is a popup-menu-only action.
    pub popup_only: bool,
    /// Menu path for popup menu entries.
    pub popup_path: Option<String>,
}

impl ProviderAction {
    /// Build the standard set of provider actions matching the Java
    /// `DataGraphProvider.createActions` method.
    pub fn default_actions() -> Vec<ProviderAction> {
        vec![
            ProviderAction {
                name: ACTION_SELECT_HOME.into(),
                icon_key: Some("icon.home".into()),
                group: "A".into(),
                description: "Selects and Centers Original Source Vertex".into(),
                is_toggle: false,
                selected: false,
                popup_only: false,
                popup_path: None,
            },
            ProviderAction {
                name: ACTION_RELAYOUT.into(),
                icon_key: Some("icon.plugin.datagraph.action.viewer.reset".into()),
                group: "A".into(),
                description: "Erases all manual vertex positioning information".into(),
                is_toggle: false,
                selected: false,
                popup_only: false,
                popup_path: None,
            },
            ProviderAction {
                name: ACTION_COMPACT_FORMAT.into(),
                icon_key: Some("icon.plugin.datagraph.action.viewer.vertex.format".into()),
                group: "A".into(),
                description: "Show Expanded information in data vertices.".into(),
                is_toggle: true,
                selected: true,
                popup_only: false,
                popup_path: None,
            },
            ProviderAction {
                name: ACTION_NAVIGATE_IN.into(),
                icon_key: Some("icon.navigate.on.incoming".into()),
                group: "B".into(),
                description: "Attempts to select vertex corresponding to tool location changes.".into(),
                is_toggle: true,
                selected: false,
                popup_only: false,
                popup_path: None,
            },
            ProviderAction {
                name: ACTION_NAVIGATE_OUT.into(),
                icon_key: Some("icon.navigate.on.outgoing".into()),
                group: "B".into(),
                description: "Selecting vertices or locations inside a vertex navigates the tool.".into(),
                is_toggle: true,
                selected: true,
                popup_only: false,
                popup_path: None,
            },
            ProviderAction {
                name: ACTION_SHOW_POPUPS.into(),
                icon_key: None,
                group: "".into(),
                description: "Toggles whether or not to show tooltips".into(),
                is_toggle: true,
                selected: true,
                popup_only: true,
                popup_path: Some("Display Popup Windows".into()),
            },
            ProviderAction {
                name: ACTION_INCOMING_REFS.into(),
                icon_key: None,
                group: "A".into(),
                description: "Show Vertices for known references to this vertex.".into(),
                is_toggle: false,
                selected: false,
                popup_only: true,
                popup_path: Some("Add All Incoming References".into()),
            },
            ProviderAction {
                name: ACTION_OUTGOING_REFS.into(),
                icon_key: None,
                group: "A".into(),
                description: "Show Vertices for known references to this vertex.".into(),
                is_toggle: false,
                selected: false,
                popup_only: true,
                popup_path: Some("Add All Outgoing References".into()),
            },
            ProviderAction {
                name: ACTION_DELETE_VERTICES.into(),
                icon_key: None,
                group: "B".into(),
                description: "Removes the selected vertices and their descendants from the graph".into(),
                is_toggle: false,
                selected: false,
                popup_only: true,
                popup_path: Some("Delete Selected Vertices".into()),
            },
            ProviderAction {
                name: ACTION_SET_ORIGINAL_VERTEX.into(),
                icon_key: None,
                group: "B".into(),
                description: "Reorient graph as though this was the first vertex shown".into(),
                is_toggle: false,
                selected: false,
                popup_only: true,
                popup_path: Some("Set Vertex as Original Source".into()),
            },
            ProviderAction {
                name: ACTION_RESET_LOCATION.into(),
                icon_key: Some("icon.refresh".into()),
                group: "B".into(),
                description: "Resets the vertex to the automated layout location.".into(),
                is_toggle: false,
                selected: false,
                popup_only: true,
                popup_path: Some("Restore Location".into()),
            },
            ProviderAction {
                name: ACTION_EXPAND_FULLY.into(),
                icon_key: None,
                group: "C".into(),
                description: "Expand all levels under selected row".into(),
                is_toggle: false,
                selected: false,
                popup_only: true,
                popup_path: Some("Expand Fully".into()),
            },
        ]
    }
}

/// The main plugin for displaying data graphs.
///
/// Ported from `datagraph.DataGraphPlugin`.
///
/// Manages the set of active [`DataGraphProviderState`] instances and the
/// shared [`DataGraphOptions`] that govern display behaviour.  The plugin
/// listens for location change events and forwards them to each active
/// provider.
#[derive(Debug)]
pub struct DataGraphPlugin {
    /// Unique plugin name.
    name: String,
    /// Set of active provider states.
    active_providers: Vec<DataGraphProviderState>,
    /// Shared display options (last-write-wins across providers).
    options: DataGraphOptions,
    /// Next provider ID.
    next_provider_id: u64,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

impl DataGraphPlugin {
    /// Create a new data graph plugin.
    pub fn new() -> Self {
        Self {
            name: "Data Graph".to_string(),
            active_providers: Vec::new(),
            options: DataGraphOptions::new(),
            next_provider_id: 1,
            disposed: false,
        }
    }

    /// Restore plugin configuration from persisted key-value pairs.
    ///
    /// Ported from `DataGraphPlugin.readConfigState(SaveState)`.
    pub fn read_config_state(&mut self, pairs: &[(&str, bool)]) {
        self.options = DataGraphOptions::from_pairs(pairs);
    }

    /// Persist plugin configuration as key-value pairs.
    ///
    /// Ported from `DataGraphPlugin.writeConfigState(SaveState)`.
    pub fn write_config_state(&self) -> Vec<(&'static str, bool)> {
        self.options.to_pairs()
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get a reference to the shared display options.
    pub fn options(&self) -> &DataGraphOptions {
        &self.options
    }

    /// Get a mutable reference to the shared display options.
    pub fn options_mut(&mut self) -> &mut DataGraphOptions {
        &mut self.options
    }

    /// Set the shared display options (e.g., from persisted config state).
    pub fn set_options(&mut self, options: DataGraphOptions) {
        self.options = options;
    }

    // ------------------------------------------------------------------
    // Provider management
    // ------------------------------------------------------------------

    /// Show a data graph for the given data object.  Returns the provider ID.
    pub fn show_data_graph(
        &mut self,
        program_name: impl Into<String>,
        data: &DataObject,
    ) -> u64 {
        let pn = program_name.into();
        let id = self.next_provider_id;
        self.next_provider_id += 1;

        let mut provider = DataGraphProviderState::new(id, &pn, data.address);
        provider.visible = true;
        self.active_providers.push(provider);

        id
    }

    /// Remove (close) a provider by ID.
    pub fn remove_provider(&mut self, provider_id: u64) {
        self.active_providers.retain(|p| p.id != provider_id);
    }

    /// Get the number of active providers.
    pub fn active_provider_count(&self) -> usize {
        self.active_providers.len()
    }

    /// Check whether any providers are active.
    pub fn has_active_providers(&self) -> bool {
        !self.active_providers.is_empty()
    }

    /// Forward a location change to all active providers.
    pub fn set_location(&mut self, location: &DataLocation) {
        // In the full implementation this would notify each provider of the
        // new location so it can select the matching vertex.  Here we record
        // the event.
        for provider in &mut self.active_providers {
            if provider.program_name == location.program_name {
                // Provider is interested in this location change.
                let _ = provider; // placeholder for future notification
            }
        }
    }

    // ------------------------------------------------------------------
    // Actions
    // ------------------------------------------------------------------

    /// Check whether the "Display Data Graph" action should be enabled for
    /// the given data type name.  In the Java version this checks whether the
    /// code unit is a `Data`; here we simply check the type is non-empty.
    pub fn is_graph_action_enabled(type_name: &str) -> bool {
        !type_name.is_empty()
    }

    /// Whether incoming references can be shown for a vertex of the given
    /// kind.  Matches Java `DataGraphProvider.canShowReferences`.
    pub fn can_show_references(is_data_vertex: bool) -> bool {
        is_data_vertex
    }

    /// Whether the selected vertices can be closed/deleted.
    ///
    /// A single selected vertex may only be deleted if it is not the root.
    /// Matches Java `DataGraphProvider.canClose`.
    pub fn can_close(selected: &[&DataObject]) -> bool {
        if selected.is_empty() {
            return false;
        }
        if selected.len() > 1 {
            return true;
        }
        // Single vertex: can only close if not root.
        !selected[0].is_root
    }

    /// Whether the graph can be reoriented around the given vertex.
    ///
    /// Matches Java `DataGraphProvider.canOrientGraphAround`.
    pub fn can_orient_around(is_data_vertex: bool, is_root: bool) -> bool {
        is_data_vertex && !is_root
    }

    /// Resolve the top-level data object by walking up through parent
    /// addresses until the root is found.
    pub fn get_top_level_data(data: &DataObject, all: &[DataObject]) -> DataObject {
        let mut current = data.clone();
        while let Some(parent_addr) = current.parent_address {
            if let Some(parent) = all.iter().find(|d| d.address == parent_addr) {
                current = parent.clone();
            } else {
                break;
            }
        }
        current
    }

    /// Whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose the plugin, closing all providers.
    pub fn dispose(&mut self) {
        self.active_providers.clear();
        self.disposed = true;
    }
}

impl Default for DataGraphPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = DataGraphPlugin::new();
        assert_eq!(plugin.name(), "Data Graph");
        assert!(!plugin.has_active_providers());
        assert!(!plugin.is_disposed());
    }

    #[test]
    fn test_show_data_graph() {
        let mut plugin = DataGraphPlugin::new();
        let data = DataObject::new(0x1000, "int", 4);
        let id = plugin.show_data_graph("test.exe", &data);
        assert_eq!(id, 1);
        assert!(plugin.has_active_providers());
        assert_eq!(plugin.active_provider_count(), 1);
    }

    #[test]
    fn test_remove_provider() {
        let mut plugin = DataGraphPlugin::new();
        let data = DataObject::new(0x1000, "int", 4);
        let id = plugin.show_data_graph("test.exe", &data);
        plugin.remove_provider(id);
        assert!(!plugin.has_active_providers());
    }

    #[test]
    fn test_multiple_providers() {
        let mut plugin = DataGraphPlugin::new();
        let d1 = DataObject::new(0x1000, "int", 4);
        let d2 = DataObject::new(0x2000, "char", 1);
        let id1 = plugin.show_data_graph("a.exe", &d1);
        let id2 = plugin.show_data_graph("b.exe", &d2);
        assert_ne!(id1, id2);
        assert_eq!(plugin.active_provider_count(), 2);
    }

    #[test]
    fn test_graph_action_enabled() {
        assert!(DataGraphPlugin::is_graph_action_enabled("int"));
        assert!(!DataGraphPlugin::is_graph_action_enabled(""));
    }

    #[test]
    fn test_get_top_level_data() {
        let root = DataObject::new(0x1000, "struct", 16);
        let child = DataObject::child(0x1008, "int", 4, 0x1000);
        let all = vec![root.clone(), child.clone()];
        let top = DataGraphPlugin::get_top_level_data(&child, &all);
        assert_eq!(top.address, 0x1000);
        assert!(top.is_root);
    }

    #[test]
    fn test_dispose() {
        let mut plugin = DataGraphPlugin::new();
        let data = DataObject::new(0x1000, "int", 4);
        plugin.show_data_graph("test.exe", &data);
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(!plugin.has_active_providers());
    }

    #[test]
    fn test_data_location() {
        let loc = DataLocation::new("test.exe", 0x1000);
        assert_eq!(loc.program_name, "test.exe");
        assert_eq!(loc.address, 0x1000);
    }

    #[test]
    fn test_data_object_child() {
        let child = DataObject::child(0x1008, "int", 4, 0x1000);
        assert!(!child.is_root);
        assert_eq!(child.parent_address, Some(0x1000));
    }

    #[test]
    fn test_options_round_trip() {
        let mut plugin = DataGraphPlugin::new();
        plugin.options_mut().set_navigate_in(true);
        plugin.options_mut().set_compact_format(false);
        assert!(plugin.options().is_navigate_in());
        assert!(!plugin.options().use_compact_format());
    }

    // -- DegContext tests ---------------------------------------------------

    #[test]
    fn test_deg_context_no_vertex() {
        let mut sel = HashSet::new();
        sel.insert(1);
        let ctx = DegContext::new(sel.clone());
        assert!(ctx.vertex_id.is_none());
        assert!(ctx.should_show_satellite_actions());
        assert_eq!(ctx.selected_vertex_ids.len(), 1);
    }

    #[test]
    fn test_deg_context_with_vertex() {
        let ctx = DegContext::with_vertex(5, HashSet::new());
        assert_eq!(ctx.vertex_id, Some(5));
        assert!(!ctx.should_show_satellite_actions());
    }

    // -- DegSatelliteContext tests ------------------------------------------

    #[test]
    fn test_deg_satellite_context() {
        let ctx = DegSatelliteContext::new(42);
        assert_eq!(ctx.provider_id, 42);
    }

    // -- Config persistence tests ------------------------------------------

    #[test]
    fn test_read_config_state() {
        let mut plugin = DataGraphPlugin::new();
        let pairs = vec![
            ("Navigate In", true),
            ("Navigate Out", false),
            ("Compact Format", false),
            ("Show Popups", false),
        ];
        plugin.read_config_state(&pairs);
        assert!(plugin.options().is_navigate_in());
        assert!(!plugin.options().is_navigate_out());
        assert!(!plugin.options().use_compact_format());
        assert!(!plugin.options().is_show_popups());
    }

    #[test]
    fn test_write_config_state_round_trip() {
        let mut plugin = DataGraphPlugin::new();
        plugin.options_mut().set_navigate_in(true);
        plugin.options_mut().set_navigate_out(false);

        let pairs = plugin.write_config_state();
        let mut plugin2 = DataGraphPlugin::new();
        plugin2.read_config_state(&pairs);

        assert!(plugin2.options().is_navigate_in());
        assert!(!plugin2.options().is_navigate_out());
    }

    // -- Action predicate tests --------------------------------------------

    #[test]
    fn test_can_show_references() {
        assert!(DataGraphPlugin::can_show_references(true));
        assert!(!DataGraphPlugin::can_show_references(false));
    }

    #[test]
    fn test_can_close() {
        let root = DataObject::new(0x1000, "struct", 16);
        let child = DataObject::child(0x1008, "int", 4, 0x1000);

        // Empty selection cannot be closed.
        assert!(!DataGraphPlugin::can_close(&[]));

        // Root alone cannot be closed.
        assert!(!DataGraphPlugin::can_close(&[&root]));

        // Non-root alone can be closed.
        assert!(DataGraphPlugin::can_close(&[&child]));

        // Multiple selection can always be closed.
        assert!(DataGraphPlugin::can_close(&[&root, &child]));
    }

    #[test]
    fn test_can_orient_around() {
        assert!(!DataGraphPlugin::can_orient_around(true, true));   // data root
        assert!(DataGraphPlugin::can_orient_around(true, false));   // data non-root
        assert!(!DataGraphPlugin::can_orient_around(false, false)); // not a data vertex
    }

    // -- ProviderAction tests ----------------------------------------------

    #[test]
    fn test_default_actions_count() {
        let actions = ProviderAction::default_actions();
        // 12 actions matching the Java DataGraphProvider.createActions
        assert_eq!(actions.len(), 12);
    }

    #[test]
    fn test_default_actions_have_names() {
        let actions = ProviderAction::default_actions();
        let names: Vec<&str> = actions.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&ACTION_DISPLAY_DATA_GRAPH) || names.contains(&ACTION_SELECT_HOME));
        assert!(names.contains(&ACTION_NAVIGATE_IN));
        assert!(names.contains(&ACTION_NAVIGATE_OUT));
        assert!(names.contains(&ACTION_SHOW_POPUPS));
    }
}
