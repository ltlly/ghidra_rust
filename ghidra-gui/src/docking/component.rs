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
}
