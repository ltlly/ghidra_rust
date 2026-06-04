//! Component provider abstractions for the docking framework.
//!
//! A [`DockingComponent`] is the trait that every dockable view must implement.
//! [`ComponentProvider`] enumerates all known provider types, and
//! [`WindowPosition`] describes where a window can be placed.

use std::collections::HashMap;

use super::action::DockingAction;

// ---------------------------------------------------------------------------
// ComponentProvider — the well-known provider kinds
// ---------------------------------------------------------------------------

/// Identifies a specific type of dockable window / view.
///
/// These map roughly to the `ComponentProvider` implementations in Ghidra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum ComponentProvider {
    /// The main code listing view.
    ListingView,
    /// The decompiler output view.
    DecompilerView,
    /// The symbol tree browser.
    SymbolTree,
    /// The data-type manager browser.
    DataTypeManager,
    /// Raw byte / hex view.
    BytesView,
    /// Call graph / function graph view.
    FunctionGraph,
    /// Interactive console / script REPL.
    Console,
    /// Program tree / segment tree browser.
    ProgramTree,
    /// Bookmarks / notes browser.
    Bookmarks,
    /// Search results view.
    SearchResults,
    /// Cross-reference table.
    References,
    /// Function call tree.
    FunctionCallTree,
    /// Data / type relationship graph.
    DataGraph,
    /// Version-tracking / diff view.
    VersionTracking,
    /// PDB symbol viewer.
    PdbViewer,
    /// Memory map / layout view.
    MemoryMap,
    /// CPU register state view.
    RegisterView,
    /// Stack frame viewer.
    StackView,
}

impl ComponentProvider {
    /// Human-readable name for the provider kind.
    pub fn display_name(&self) -> &'static str {
        match self {
            ComponentProvider::ListingView => "Listing",
            ComponentProvider::DecompilerView => "Decompiler",
            ComponentProvider::SymbolTree => "Symbol Tree",
            ComponentProvider::DataTypeManager => "Data Type Manager",
            ComponentProvider::BytesView => "Bytes",
            ComponentProvider::FunctionGraph => "Function Graph",
            ComponentProvider::Console => "Console",
            ComponentProvider::ProgramTree => "Program Tree",
            ComponentProvider::Bookmarks => "Bookmarks",
            ComponentProvider::SearchResults => "Search Results",
            ComponentProvider::References => "References",
            ComponentProvider::FunctionCallTree => "Function Call Tree",
            ComponentProvider::DataGraph => "Data Graph",
            ComponentProvider::VersionTracking => "Version Tracking",
            ComponentProvider::PdbViewer => "PDB Viewer",
            ComponentProvider::MemoryMap => "Memory Map",
            ComponentProvider::RegisterView => "Registers",
            ComponentProvider::StackView => "Stack",
        }
    }

    /// A short icon name / identifier for the provider.
    pub fn icon_name(&self) -> &'static str {
        match self {
            ComponentProvider::ListingView => "listing",
            ComponentProvider::DecompilerView => "decompiler",
            ComponentProvider::SymbolTree => "symbol_tree",
            ComponentProvider::DataTypeManager => "data_types",
            ComponentProvider::BytesView => "bytes",
            ComponentProvider::FunctionGraph => "function_graph",
            ComponentProvider::Console => "console",
            ComponentProvider::ProgramTree => "program_tree",
            ComponentProvider::Bookmarks => "bookmarks",
            ComponentProvider::SearchResults => "search",
            ComponentProvider::References => "references",
            ComponentProvider::FunctionCallTree => "call_tree",
            ComponentProvider::DataGraph => "data_graph",
            ComponentProvider::VersionTracking => "version_tracking",
            ComponentProvider::PdbViewer => "pdb",
            ComponentProvider::MemoryMap => "memory_map",
            ComponentProvider::RegisterView => "registers",
            ComponentProvider::StackView => "stack",
        }
    }
}

// ---------------------------------------------------------------------------
// WindowPosition
// ---------------------------------------------------------------------------

/// Where a dockable window is located.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum WindowPosition {
    /// Dock to the top edge.
    Top,
    /// Dock to the bottom edge.
    Bottom,
    /// Dock to the left edge.
    Left,
    /// Dock to the right edge.
    Right,
    /// Center area (usually tabbed).
    Center,
    /// Floating / custom position with explicit coordinates and size.
    Custom {
        x: f32,
        y: f32,
        width: f32,
        height: f32,
    },
}

impl Default for WindowPosition {
    fn default() -> Self {
        WindowPosition::Center
    }
}

impl WindowPosition {
    /// Returns `true` when the position is a dock edge (not center or
    /// custom).
    pub fn is_dock_edge(&self) -> bool {
        matches!(
            self,
            WindowPosition::Top
                | WindowPosition::Bottom
                | WindowPosition::Left
                | WindowPosition::Right
        )
    }

    /// Returns `true` when the position is floating (custom).
    pub fn is_floating(&self) -> bool {
        matches!(self, WindowPosition::Custom { .. })
    }

    /// Returns the side name as a string (for layout persistence).
    pub fn side_name(&self) -> &'static str {
        match self {
            WindowPosition::Top => "top",
            WindowPosition::Bottom => "bottom",
            WindowPosition::Left => "left",
            WindowPosition::Right => "right",
            WindowPosition::Center => "center",
            WindowPosition::Custom { .. } => "custom",
        }
    }
}

// ---------------------------------------------------------------------------
// DockingComponent trait
// ---------------------------------------------------------------------------

/// Every dockable view / window must implement this trait.
///
/// The trait provides the metadata the docking framework needs to manage
/// window visibility, title bars, associated actions, and the parent
/// provider type.
pub trait DockingComponent {
    /// Title shown in the window chrome / tab.
    fn get_title(&self) -> &str;

    /// Optional icon name for the window.
    fn get_icon(&self) -> Option<&str> {
        None
    }

    /// Actions this component contributes to the tool.
    fn get_actions(&self) -> Vec<DockingAction> {
        Vec::new()
    }

    /// Whether the component is currently visible.
    fn is_visible(&self) -> bool;

    /// Show or hide the component.
    fn set_visible(&mut self, visible: bool);

    /// The provider kind this component belongs to.
    fn get_component_provider(&self) -> ComponentProvider;

    /// The default sub-component name (instance identifier).
    fn get_default_component(&self) -> &str;

    /// A unique instance key composed of provider and default-component
    /// name.  Used to look up window placements in the layout.
    fn instance_key(&self) -> (ComponentProvider, String) {
        (
            self.get_component_provider(),
            self.get_default_component().to_owned(),
        )
    }
}

// ---------------------------------------------------------------------------
// ComponentProviderInfo — rich metadata for a component provider
// ---------------------------------------------------------------------------

/// Extended metadata for a component provider.
///
/// In Ghidra, `ComponentProvider` (the class, not the enum) carries rich
/// metadata about a dockable window: the tool it belongs to, its owner,
/// how it handles focus, its menu groups, etc.  This trait provides the
/// same metadata for Rust-side providers.
pub trait ComponentProviderInfo {
    /// The unique component identity (provider + default component).
    fn component_id(&self) -> (ComponentProvider, String);

    /// The title displayed in the window chrome.
    fn window_title(&self) -> &str;

    /// The name of the tool this provider belongs to (e.g. "CodeBrowser").
    fn tool_name(&self) -> &str {
        ""
    }

    /// An optional owner (e.g. the plugin that created this provider).
    fn owner(&self) -> &str {
        ""
    }

    /// Sub-title (for providers with multiple instances, e.g. listing
    /// views showing different programs).
    fn sub_title(&self) -> &str {
        ""
    }

    /// The menu group used when this provider's items appear in the
    /// Window menu (e.g. "Views").
    fn window_menu_group(&self) -> &str {
        "Views"
    }

    /// Priority for the Window menu ordering (lower = earlier).
    fn window_menu_priority(&self) -> u32 {
        100
    }

    /// Whether this provider supports temporary (transient) windows.
    fn supports_temporary_window(&self) -> bool {
        true
    }

    /// Whether this provider handles its own focus management.
    fn manages_own_focus(&self) -> bool {
        false
    }

    /// The preferred default position when first docked.
    fn default_position(&self) -> WindowPosition {
        WindowPosition::Center
    }

    /// The preferred default size (width, height) when first shown.
    fn default_size(&self) -> (f32, f32) {
        (400.0, 300.0)
    }

    /// Whether this provider has a custom context menu.
    fn has_context_menu(&self) -> bool {
        false
    }

    /// Whether this provider should be shown by default in new tools.
    fn is_default_provider(&self) -> bool {
        false
    }

    /// Help location identifier for the help system.
    fn help_location(&self) -> Option<&str> {
        None
    }
}

// ---------------------------------------------------------------------------
// Basic component implementations for testing / factory purposes
// ---------------------------------------------------------------------------

/// A minimal docking component for use in tests or simple windows.
#[derive(Debug, Clone)]
pub struct SimpleComponent {
    provider: ComponentProvider,
    title: String,
    default_name: String,
    icon: Option<String>,
    visible: bool,
    actions: Vec<DockingAction>,
    /// The tool this component belongs to.
    tool_name: String,
    /// Owner plugin or creator.
    owner: String,
    /// Sub-title for multi-instance windows.
    sub_title: String,
    /// Window menu group.
    window_menu_group: String,
    /// Window menu priority.
    window_menu_priority: u32,
    /// Default docking position.
    default_position: WindowPosition,
    /// Default window size.
    default_size: (f32, f32),
    /// Whether this provider is a default (shown on new tool creation).
    is_default: bool,
}

impl SimpleComponent {
    pub fn new(
        provider: ComponentProvider,
        title: impl Into<String>,
        default_name: impl Into<String>,
    ) -> Self {
        Self {
            provider,
            title: title.into(),
            default_name: default_name.into(),
            icon: None,
            visible: true,
            actions: Vec::new(),
            tool_name: String::new(),
            owner: String::new(),
            sub_title: String::new(),
            window_menu_group: "Views".to_owned(),
            window_menu_priority: 100,
            default_position: WindowPosition::Center,
            default_size: (400.0, 300.0),
            is_default: false,
        }
    }

    pub fn with_icon(mut self, icon: impl Into<String>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    pub fn with_actions(mut self, actions: Vec<DockingAction>) -> Self {
        self.actions = actions;
        self
    }

    pub fn with_visibility(mut self, visible: bool) -> Self {
        self.visible = visible;
        self
    }

    /// Set the tool this component belongs to.
    pub fn with_tool_name(mut self, name: impl Into<String>) -> Self {
        self.tool_name = name.into();
        self
    }

    /// Set the owner (plugin name) of this component.
    pub fn with_owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = owner.into();
        self
    }

    /// Set the sub-title (for multi-instance providers).
    pub fn with_sub_title(mut self, sub_title: impl Into<String>) -> Self {
        self.sub_title = sub_title.into();
        self
    }

    /// Set the window menu group.
    pub fn with_window_menu_group(mut self, group: impl Into<String>) -> Self {
        self.window_menu_group = group.into();
        self
    }

    /// Set the window menu priority (lower = earlier in menu).
    pub fn with_window_menu_priority(mut self, priority: u32) -> Self {
        self.window_menu_priority = priority;
        self
    }

    /// Set the default docking position.
    pub fn with_default_position(mut self, position: WindowPosition) -> Self {
        self.default_position = position;
        self
    }

    /// Set the default window size.
    pub fn with_default_size(mut self, width: f32, height: f32) -> Self {
        self.default_size = (width, height);
        self
    }

    /// Mark this as a default provider (shown when a new tool is created).
    pub fn as_default_provider(mut self) -> Self {
        self.is_default = true;
        self
    }

    /// Get the tool name.
    pub fn tool_name(&self) -> &str {
        &self.tool_name
    }

    /// Get the owner.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Get the sub-title.
    pub fn sub_title(&self) -> &str {
        &self.sub_title
    }

    /// Get the window menu group.
    pub fn window_menu_group(&self) -> &str {
        &self.window_menu_group
    }

    /// Get the window menu priority.
    pub fn window_menu_priority(&self) -> u32 {
        self.window_menu_priority
    }

    /// Get the default position.
    pub fn default_position(&self) -> &WindowPosition {
        &self.default_position
    }

    /// Get the default size.
    pub fn default_size(&self) -> (f32, f32) {
        self.default_size
    }

    /// Whether this is a default provider.
    pub fn is_default_provider_flag(&self) -> bool {
        self.is_default
    }
}

impl DockingComponent for SimpleComponent {
    fn get_title(&self) -> &str {
        &self.title
    }

    fn get_icon(&self) -> Option<&str> {
        self.icon.as_deref()
    }

    fn get_actions(&self) -> Vec<DockingAction> {
        self.actions.clone()
    }

    fn is_visible(&self) -> bool {
        self.visible
    }

    fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    fn get_component_provider(&self) -> ComponentProvider {
        self.provider
    }

    fn get_default_component(&self) -> &str {
        &self.default_name
    }
}

impl ComponentProviderInfo for SimpleComponent {
    fn component_id(&self) -> (ComponentProvider, String) {
        (self.provider, self.default_name.clone())
    }

    fn window_title(&self) -> &str {
        &self.title
    }

    fn tool_name(&self) -> &str {
        &self.tool_name
    }

    fn owner(&self) -> &str {
        &self.owner
    }

    fn sub_title(&self) -> &str {
        &self.sub_title
    }

    fn window_menu_group(&self) -> &str {
        &self.window_menu_group
    }

    fn window_menu_priority(&self) -> u32 {
        self.window_menu_priority
    }

    fn default_position(&self) -> WindowPosition {
        self.default_position.clone()
    }

    fn default_size(&self) -> (f32, f32) {
        self.default_size
    }

    fn is_default_provider(&self) -> bool {
        self.is_default
    }
}

/// Collection of dockable components, keyed by their instance key.
pub type ComponentMap = HashMap<(ComponentProvider, String), Box<dyn DockingComponent>>;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_component_provider_display() {
        assert_eq!(ComponentProvider::ListingView.display_name(), "Listing");
        assert_eq!(ComponentProvider::Console.display_name(), "Console");
        assert_eq!(ComponentProvider::PdbViewer.icon_name(), "pdb");
    }

    #[test]
    fn test_window_position_default() {
        let pos = WindowPosition::default();
        assert_eq!(pos, WindowPosition::Center);
    }

    #[test]
    fn test_window_position_is_dock_edge() {
        assert!(WindowPosition::Top.is_dock_edge());
        assert!(WindowPosition::Left.is_dock_edge());
        assert!(!WindowPosition::Center.is_dock_edge());
        assert!(!WindowPosition::Custom {
            x: 0.0,
            y: 0.0,
            width: 100.0,
            height: 100.0
        }
        .is_dock_edge());
    }

    #[test]
    fn test_simple_component() {
        let comp = SimpleComponent::new(ComponentProvider::Console, "Python Console", "python")
            .with_icon("console")
            .with_visibility(false);

        assert_eq!(comp.get_title(), "Python Console");
        assert_eq!(comp.get_icon(), Some("console"));
        assert!(!comp.is_visible());
        assert_eq!(comp.get_component_provider(), ComponentProvider::Console);
        assert_eq!(comp.get_default_component(), "python");
        assert_eq!(
            comp.instance_key(),
            (ComponentProvider::Console, "python".to_owned())
        );
    }

    #[test]
    fn test_simple_component_visibility() {
        let mut comp = SimpleComponent::new(ComponentProvider::ListingView, "Listing", "listing");
        assert!(comp.is_visible());
        comp.set_visible(false);
        assert!(!comp.is_visible());
    }

    #[test]
    fn test_simple_component_provider_info() {
        let comp = SimpleComponent::new(ComponentProvider::DecompilerView, "Decompile", "decompile")
            .with_tool_name("CodeBrowser")
            .with_owner("DecompilerPlugin")
            .with_sub_title("test.exe")
            .with_window_menu_group("Analysis")
            .with_window_menu_priority(10)
            .with_default_position(WindowPosition::Right)
            .with_default_size(600.0, 500.0)
            .as_default_provider();

        assert_eq!(comp.tool_name(), "CodeBrowser");
        assert_eq!(comp.owner(), "DecompilerPlugin");
        assert_eq!(comp.sub_title(), "test.exe");
        assert_eq!(comp.window_menu_group(), "Analysis");
        assert_eq!(comp.window_menu_priority(), 10);
        assert_eq!(comp.default_position(), &WindowPosition::Right);
        assert_eq!(comp.default_size(), (600.0, 500.0));
        assert!(comp.is_default_provider_flag());
    }

    #[test]
    fn test_component_provider_info_trait() {
        let comp = SimpleComponent::new(ComponentProvider::Console, "Console", "console")
            .with_tool_name("TestTool")
            .with_owner("ConsolePlugin");

        let info: &dyn ComponentProviderInfo = &comp;
        assert_eq!(info.window_title(), "Console");
        assert_eq!(info.tool_name(), "TestTool");
        assert_eq!(info.owner(), "ConsolePlugin");
        assert_eq!(info.window_menu_group(), "Views"); // default
        assert_eq!(info.window_menu_priority(), 100); // default
        assert!(info.supports_temporary_window());
        assert!(!info.manages_own_focus());
        assert!(!info.is_default_provider());
        assert!(!info.has_context_menu());
    }
}
