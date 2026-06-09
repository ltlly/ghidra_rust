//! Function Graph Provider -- the viewer provider for the function graph.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.functiongraph.FunctionGraphProvider`.
//!
//! The [`FunctionGraphProvider`] is the top-level component for a single
//! function graph view.  It owns the [`FunctionGraphModel`], manages the
//! [`FunctionGraphView`] for rendering, and coordinates user actions
//! (selection, navigation, grouping, layout changes).
//!
//! # Lifecycle
//!
//! 1. Created by [`FunctionGraphPlugin`] when the user opens a function graph.
//! 2. The model is populated from an [`FGData`] (computed by the decompiler).
//! 3. The view is initialized with the graph data.
//! 4. User interactions (click, drag, zoom, keyboard shortcuts) are routed
//!    through the provider to the model and view.
//! 5. When closed, the provider saves its state and is removed from the plugin.

use super::function_graph_model::FunctionGraphModel;
use super::function_graph_view::FunctionGraphView;
use super::function_graph_options::FunctionGraphPluginOptions;
use super::mvc::{FGData, FunctionGraphOptions};
use super::LayoutAlgorithm;

use ghidra_core::addr::Address;
use ghidra_core::program::listing::Function;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// FunctionGraphProvider
// ---------------------------------------------------------------------------

/// The viewer provider for a single function graph.
///
/// Owns the [`FunctionGraphModel`] and [`FunctionGraphView`] for one
/// function, managing the complete lifecycle from creation through
/// user interaction to close.
#[derive(Debug)]
pub struct FunctionGraphProvider {
    /// Unique ID for this provider instance.
    id: u64,
    /// The function displayed by this provider.
    function: Function,
    /// The data model for the graph.
    model: FunctionGraphModel,
    /// The view component for rendering.
    view: FunctionGraphView,
    /// Whether this provider is the primary (connected) view.
    connected: bool,
    /// Whether the provider has been disposed.
    disposed: bool,
    /// Error message if the graph could not be computed.
    error_message: Option<String>,
    /// Provider options (snapshot of plugin options at creation time).
    options: FunctionGraphOptions,
}

/// Global counter for provider IDs.
static PROVIDER_ID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl FunctionGraphProvider {
    /// Create a new function graph provider.
    ///
    /// If `fg_data` contains a graph, the provider is immediately usable.
    /// Otherwise the provider will show an error message.
    pub fn new(function: Function, fg_data: FGData, options: FunctionGraphOptions) -> Self {
        let id = PROVIDER_ID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let error_message = fg_data.error_message.clone();
        let model = FunctionGraphModel::from_fg_data(fg_data);
        let view = FunctionGraphView::new(model.vertex_count());

        Self {
            id,
            function,
            model,
            view,
            connected: false,
            disposed: false,
            error_message,
            options,
        }
    }

    /// The unique ID of this provider.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// The function displayed by this provider.
    pub fn function(&self) -> &Function {
        &self.function
    }

    /// Whether the provider has a valid graph (no error).
    pub fn has_graph(&self) -> bool {
        self.error_message.is_none() && self.model.vertex_count() > 0
    }

    /// The error message, if any.
    pub fn error_message(&self) -> Option<&str> {
        self.error_message.as_deref()
    }

    /// Whether the given address is within the displayed function.
    pub fn contains_address(&self, addr: Address) -> bool {
        self.model.contains_address(addr)
    }

    // -----------------------------------------------------------------------
    // Model access
    // -----------------------------------------------------------------------

    /// A reference to the graph model.
    pub fn model(&self) -> &FunctionGraphModel {
        &self.model
    }

    /// A mutable reference to the graph model.
    pub fn model_mut(&mut self) -> &mut FunctionGraphModel {
        &mut self.model
    }

    /// A reference to the view.
    pub fn view(&self) -> &FunctionGraphView {
        &self.view
    }

    /// A mutable reference to the view.
    pub fn view_mut(&mut self) -> &mut FunctionGraphView {
        &mut self.view
    }

    // -----------------------------------------------------------------------
    // Navigation
    // -----------------------------------------------------------------------

    /// Navigate to the vertex at the given address.
    ///
    /// If the address corresponds to a vertex, it is selected and
    /// the view is scrolled to center on it.
    pub fn go_to_address(&mut self, addr: Address) {
        if let Some(idx) = self.model.go_to_address(addr) {
            self.view.center_on_vertex(&self.model, idx);
        }
    }

    // -----------------------------------------------------------------------
    // Layout
    // -----------------------------------------------------------------------

    /// Set the layout algorithm and re-apply.
    pub fn set_layout_algorithm(&mut self, algorithm: LayoutAlgorithm) {
        self.model.set_layout_algorithm(algorithm);
        self.view.update_after_layout(&self.model);
    }

    /// Refresh the current layout (re-apply without changing algorithm).
    pub fn refresh_layout(&mut self) {
        self.model.apply_layout();
        self.view.update_after_layout(&self.model);
    }

    // -----------------------------------------------------------------------
    // Selection actions
    // -----------------------------------------------------------------------

    /// Group the currently selected vertices.
    pub fn group_selected(&mut self) {
        if let Some(_rep) = self.model.group_selected() {
            self.view.update_after_group(&self.model);
        }
    }

    /// Ungroup the currently selected group vertex.
    pub fn ungroup_selected(&mut self) {
        if self.model.ungroup_selected() {
            self.view.update_after_group(&self.model);
        }
    }

    // -----------------------------------------------------------------------
    // Options
    // -----------------------------------------------------------------------

    /// Get the current graph options.
    pub fn options(&self) -> &FunctionGraphOptions {
        &self.options
    }

    /// Update the graph options.
    pub fn set_options(&mut self, options: FunctionGraphOptions) {
        self.options = options;
    }

    // -----------------------------------------------------------------------
    // Connected / Disposed state
    // -----------------------------------------------------------------------

    /// Whether this is the connected (primary) provider.
    pub fn is_connected(&self) -> bool {
        self.connected
    }

    /// Set the connected state.
    pub fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
    }

    /// Whether the provider has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Dispose of the provider.
    pub fn dispose(&mut self) {
        self.disposed = true;
    }

    // -----------------------------------------------------------------------
    // Zoom / Scroll
    // -----------------------------------------------------------------------

    /// Zoom in one step.
    pub fn zoom_in(&mut self) {
        self.model.zoom_in();
        self.view.set_zoom(self.model.zoom());
    }

    /// Zoom out one step.
    pub fn zoom_out(&mut self) {
        self.model.zoom_out();
        self.view.set_zoom(self.model.zoom());
    }

    /// Reset zoom to 100%.
    pub fn zoom_reset(&mut self) {
        self.model.zoom_reset();
        self.view.set_zoom(1.0);
    }

    /// Get the current zoom factor.
    pub fn zoom(&self) -> f32 {
        self.model.zoom()
    }

    // -----------------------------------------------------------------------
    // State save / restore
    // -----------------------------------------------------------------------

    /// Save the current provider state for persistence.
    pub fn save_state(&self) -> ProviderState {
        ProviderState {
            function_entry: self.function.entry_point.offset,
            vertex_info: self.model.save_vertex_info(),
            zoom: self.model.zoom(),
            scroll_offset: self.model.scroll_offset(),
            layout_algorithm: self.model.layout().algorithm,
            layout_direction: self.model.layout().direction,
        }
    }
}

// ---------------------------------------------------------------------------
// ProviderState
// ---------------------------------------------------------------------------

/// Serializable state of a function graph provider, for save/restore
/// across sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderState {
    /// The entry address of the function.
    pub function_entry: u64,
    /// Saved vertex positions and types.
    pub vertex_info: Vec<super::mvc::VertexInfo>,
    /// The zoom factor.
    pub zoom: f32,
    /// The scroll offset (graph coordinates).
    pub scroll_offset: (f32, f32),
    /// The layout algorithm in use.
    pub layout_algorithm: super::LayoutAlgorithm,
    /// The layout direction.
    pub layout_direction: super::LayoutDirection,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::addr::{Address, AddressRange};
    use super::super::{CfgEdgeType, FGEdge, FGVertex, FunctionGraph};

    fn dummy_function() -> Function {
        Function::new(
            "test_fn",
            Address::new(0x1000),
            AddressRange::new(Address::new(0x1000), Address::new(0x1100)),
        )
    }

    fn make_fg_data() -> FGData {
        let graph = FunctionGraph::from_parts(
            dummy_function(),
            vec![
                FGVertex::new(Address::new(0x1000), "A".into(), vec![]),
                FGVertex::new(Address::new(0x1010), "B".into(), vec![]),
            ],
            vec![FGEdge::new(0, 1, CfgEdgeType::Fallthrough)],
        );
        FGData::new(dummy_function(), graph)
    }

    #[test]
    fn provider_creation() {
        let provider =
            FunctionGraphProvider::new(dummy_function(), make_fg_data(), FunctionGraphOptions::default());
        assert!(provider.has_graph());
        assert!(!provider.is_disposed());
        assert!(!provider.is_connected());
        assert!(provider.error_message().is_none());
    }

    #[test]
    fn provider_error() {
        let fg_data = FGData::error(dummy_function(), "too large");
        let provider =
            FunctionGraphProvider::new(dummy_function(), fg_data, FunctionGraphOptions::default());
        assert!(!provider.has_graph());
        assert_eq!(provider.error_message(), Some("too large"));
    }

    #[test]
    fn provider_contains_address() {
        let provider =
            FunctionGraphProvider::new(dummy_function(), make_fg_data(), FunctionGraphOptions::default());
        assert!(provider.contains_address(Address::new(0x1050)));
        assert!(!provider.contains_address(Address::new(0x2000)));
    }

    #[test]
    fn provider_zoom() {
        let mut provider =
            FunctionGraphProvider::new(dummy_function(), make_fg_data(), FunctionGraphOptions::default());
        assert_eq!(provider.zoom(), 1.0);
        provider.zoom_in();
        assert!(provider.zoom() > 1.0);
        provider.zoom_reset();
        assert_eq!(provider.zoom(), 1.0);
    }

    #[test]
    fn provider_dispose() {
        let mut provider =
            FunctionGraphProvider::new(dummy_function(), make_fg_data(), FunctionGraphOptions::default());
        provider.dispose();
        assert!(provider.is_disposed());
    }

    #[test]
    fn provider_save_state() {
        let provider =
            FunctionGraphProvider::new(dummy_function(), make_fg_data(), FunctionGraphOptions::default());
        let state = provider.save_state();
        assert_eq!(state.function_entry, 0x1000);
        assert_eq!(state.zoom, 1.0);
        assert_eq!(state.layout_algorithm, LayoutAlgorithm::Hierarchical);
    }

    #[test]
    fn provider_navigation() {
        let mut provider =
            FunctionGraphProvider::new(dummy_function(), make_fg_data(), FunctionGraphOptions::default());
        provider.go_to_address(Address::new(0x1010));
        assert!(provider.model().selected_vertices().contains(&1));
    }
}
