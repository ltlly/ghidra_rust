// ===========================================================================
// Program Tree View Management -- ported from Ghidra's
// `ghidra.app.plugin.core.programtree` package.
//
// Includes:
// - ProgramTreePanel              -- panel containing the program tree
// - ViewPanel                     -- panel for program view management
// - ViewManagerComponentProvider  -- component provider for views
// - ViewProviderService           -- service for managing view providers
// - ProgramListener               -- listener for program changes
// - TreeListener                  -- listener for tree events
// - ViewChangeListener            -- listener for view changes
// ===========================================================================

use ghidra_core::Address;

// ---------------------------------------------------------------------------
// ProgramTreePanel
// ---------------------------------------------------------------------------

/// Panel that displays and manages the program tree.
///
/// Ported from `ghidra.app.plugin.core.programtree.ProgramTreePanel`.
#[derive(Debug, Clone)]
pub struct ProgramTreePanel {
    /// The name of this panel.
    pub name: String,
    /// Whether the panel is visible.
    pub visible: bool,
    /// The current tree name.
    pub tree_name: String,
    /// The nodes in this tree.
    pub nodes: Vec<TreePanelNode>,
    /// The currently selected node index.
    pub selected_index: Option<usize>,
}

/// A node in the program tree panel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreePanelNode {
    /// The node name.
    pub name: String,
    /// The address range associated with this node.
    pub address_range: Option<(Address, Address)>,
    /// The depth in the tree (0 = root).
    pub depth: usize,
    /// Whether this node is a leaf (no children).
    pub is_leaf: bool,
}

impl ProgramTreePanel {
    /// Create a new panel.
    pub fn new(name: impl Into<String>, tree_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            visible: true,
            tree_name: tree_name.into(),
            nodes: Vec::new(),
            selected_index: None,
        }
    }

    /// Add a node to the panel.
    pub fn add_node(&mut self, node: TreePanelNode) {
        self.nodes.push(node);
    }

    /// Select a node by index.
    pub fn select(&mut self, index: usize) {
        if index < self.nodes.len() {
            self.selected_index = Some(index);
        }
    }

    /// Get the selected node.
    pub fn selected_node(&self) -> Option<&TreePanelNode> {
        self.selected_index.and_then(|i| self.nodes.get(i))
    }

    /// Get the node count.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

// ---------------------------------------------------------------------------
// ViewPanel
// ---------------------------------------------------------------------------

/// A panel that provides a view of a program region.
///
/// Ported from `ghidra.app.plugin.core.programtree.ViewPanel`.
#[derive(Debug, Clone)]
pub struct ViewPanel {
    /// The panel identifier.
    pub id: String,
    /// The view type.
    pub view_type: ViewType,
    /// The currently visible address range.
    pub visible_range: Option<(Address, Address)>,
    /// Whether the panel is active/focused.
    pub active: bool,
    /// The panel title.
    pub title: String,
}

/// The type of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewType {
    /// Listing (code) view.
    Listing,
    /// Decompiler view.
    Decompiler,
    /// Hex dump view.
    HexDump,
    /// Function graph view.
    FunctionGraph,
    /// Undefined.
    Undefined,
}

impl ViewPanel {
    /// Create a new view panel.
    pub fn new(id: impl Into<String>, view_type: ViewType) -> Self {
        Self {
            id: id.into(),
            view_type,
            visible_range: None,
            active: false,
            title: String::new(),
        }
    }

    /// Set the visible address range.
    pub fn set_visible_range(&mut self, start: Address, end: Address) {
        self.visible_range = Some((start, end));
    }

    /// Activate this panel.
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Deactivate this panel.
    pub fn deactivate(&mut self) {
        self.active = false;
    }
}

// ---------------------------------------------------------------------------
// ViewManagerComponentProvider
// ---------------------------------------------------------------------------

/// Component provider that manages multiple view panels.
///
/// Ported from
/// `ghidra.app.plugin.core.programtree.ViewManagerComponentProvider`.
#[derive(Debug, Clone)]
pub struct ViewManagerComponentProvider {
    /// The provider name.
    pub name: String,
    /// The managed view panels.
    pub panels: Vec<ViewPanel>,
    /// The active panel index.
    pub active_panel_index: Option<usize>,
    /// Whether the provider is visible.
    pub visible: bool,
}

impl ViewManagerComponentProvider {
    /// Create a new provider.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            panels: Vec::new(),
            active_panel_index: None,
            visible: true,
        }
    }

    /// Add a view panel.
    pub fn add_panel(&mut self, panel: ViewPanel) -> usize {
        let index = self.panels.len();
        self.panels.push(panel);
        index
    }

    /// Set the active panel.
    pub fn set_active_panel(&mut self, index: usize) {
        if index < self.panels.len() {
            // Deactivate all others.
            for (i, panel) in self.panels.iter_mut().enumerate() {
                if i == index {
                    panel.activate();
                } else {
                    panel.deactivate();
                }
            }
            self.active_panel_index = Some(index);
        }
    }

    /// Get the active panel.
    pub fn active_panel(&self) -> Option<&ViewPanel> {
        self.active_panel_index.and_then(|i| self.panels.get(i))
    }

    /// Get the number of panels.
    pub fn panel_count(&self) -> usize {
        self.panels.len()
    }
}

// ---------------------------------------------------------------------------
// ViewProviderService
// ---------------------------------------------------------------------------

/// Service for managing view providers.
///
/// Ported from `ghidra.app.plugin.core.programtree.ViewProviderService`.
#[derive(Debug, Clone)]
pub struct ViewProviderService {
    /// Registered view providers.
    pub providers: Vec<String>,
    /// The active provider name.
    pub active_provider: Option<String>,
}

impl ViewProviderService {
    /// Create a new service.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            active_provider: None,
        }
    }

    /// Register a provider.
    pub fn register(&mut self, name: impl Into<String>) {
        let name = name.into();
        if !self.providers.contains(&name) {
            self.providers.push(name);
        }
    }

    /// Set the active provider.
    pub fn set_active(&mut self, name: &str) {
        if self.providers.iter().any(|p| p == name) {
            self.active_provider = Some(name.to_string());
        }
    }

    /// Get the number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }
}

impl Default for ViewProviderService {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Listeners
// ---------------------------------------------------------------------------

/// Trait for listening to program changes.
pub trait ProgramListener: Send + Sync {
    /// Called when a program's memory layout changes.
    fn on_memory_changed(&mut self, _program_name: &str) {}
    /// Called when the listing changes.
    fn on_listing_changed(&mut self, _program_name: &str) {}
    /// Called when a program is closed.
    fn on_program_closed(&mut self, _program_name: &str) {}
}

/// Trait for listening to tree events.
pub trait TreeListener: Send + Sync {
    /// Called when a node is selected.
    fn on_node_selected(&mut self, _node_name: &str) {}
    /// Called when a node is expanded.
    fn on_node_expanded(&mut self, _node_name: &str) {}
    /// Called when a node is collapsed.
    fn on_node_collapsed(&mut self, _node_name: &str) {}
}

/// Trait for listening to view changes.
pub trait ViewChangeListener: Send + Sync {
    /// Called when the active view changes.
    fn on_view_changed(&mut self, _view_id: &str) {}
    /// Called when a view's visible range changes.
    fn on_range_changed(&mut self, _view_id: &str, _start: Address, _end: Address) {}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_tree_panel() {
        let mut panel = ProgramTreePanel::new("Main", "Default Tree");
        panel.add_node(TreePanelNode {
            name: "code".into(),
            address_range: Some((Address::new(0x400000), Address::new(0x401000))),
            depth: 0,
            is_leaf: false,
        });
        panel.select(0);
        assert_eq!(panel.node_count(), 1);
        assert_eq!(panel.selected_node().unwrap().name, "code");
    }

    #[test]
    fn test_view_panel() {
        let mut panel = ViewPanel::new("listing1", ViewType::Listing);
        assert!(!panel.active);
        panel.activate();
        assert!(panel.active);
        panel.set_visible_range(Address::new(0x400000), Address::new(0x401000));
        assert!(panel.visible_range.is_some());
    }

    #[test]
    fn test_view_manager() {
        let mut mgr = ViewManagerComponentProvider::new("ViewManager");
        mgr.add_panel(ViewPanel::new("p1", ViewType::Listing));
        mgr.add_panel(ViewPanel::new("p2", ViewType::Decompiler));
        assert_eq!(mgr.panel_count(), 2);

        mgr.set_active_panel(1);
        assert_eq!(mgr.active_panel().unwrap().id, "p2");
        assert!(mgr.active_panel().unwrap().active);
    }

    #[test]
    fn test_view_provider_service() {
        let mut svc = ViewProviderService::new();
        svc.register("Listing");
        svc.register("Decompiler");
        assert_eq!(svc.provider_count(), 2);

        svc.set_active("Listing");
        assert_eq!(svc.active_provider.as_deref(), Some("Listing"));

        // Registering same name twice should not duplicate.
        svc.register("Listing");
        assert_eq!(svc.provider_count(), 2);
    }

    #[test]
    fn test_view_type_variants() {
        assert_ne!(ViewType::Listing, ViewType::HexDump);
        assert_eq!(ViewType::FunctionGraph.display_name(), "Function Graph");
    }
}

impl ViewType {
    /// Display name for the view type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Listing => "Listing",
            Self::Decompiler => "Decompiler",
            Self::HexDump => "Hex Dump",
            Self::FunctionGraph => "Function Graph",
            Self::Undefined => "Undefined",
        }
    }
}
