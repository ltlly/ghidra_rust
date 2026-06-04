//! The abstract and concrete code browser plugin implementations.
//!
//! Ports `ghidra.app.plugin.core.codebrowser.AbstractCodeBrowserPlugin` and
//! `ghidra.app.plugin.core.codebrowser.CodeBrowserPlugin`.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::color_model::{
    LayeredColorModel, ListingBackgroundColorModel, MarkerServiceBackgroundColorModel,
    SimpleBackgroundColorModel,
};
use super::hover::{HoverServiceRegistry, ListingHoverService};
use super::plugin_interface::CodeBrowserPluginInterface;
use super::provider::CodeViewerProvider;

/// Configuration constants for the code browser plugin.
pub mod options {
    /// Options category for browser display settings.
    pub const CATEGORY_BROWSER_DISPLAY: &str = "Listing Display";
    /// Options category for browser field settings.
    pub const CATEGORY_BROWSER_FIELDS: &str = "Listing Fields";

    /// Cursor color option name (focused).
    pub const CURSOR_COLOR_FOCUSED: &str = "Cursor.Cursor Color - Focused";
    /// Cursor color option name (unfocused).
    pub const CURSOR_COLOR_UNFOCUSED: &str = "Cursor.Cursor Color - Unfocused";
    /// Mouse wheel horizontal scrolling option.
    pub const MOUSE_WHEEL_HORIZONTAL_SCROLLING: &str = "Mouse Wheel Shift Scroll";
    /// Selection color option.
    pub const SELECTION_COLOR: &str = "Selection Color";
    /// Highlight color option.
    pub const HIGHLIGHT_COLOR: &str = "Highlight Color";
    /// Highlight cursor line option.
    pub const HIGHLIGHT_CURSOR_LINE: &str = "Highlight Cursor Line";
    /// Cursor line background color option.
    pub const HIGHLIGHT_CURSOR_LINE_COLOR: &str = "Highlight Cursor Line Color";
}

// ---------------------------------------------------------------------------
// AbstractCodeBrowserPlugin
// ---------------------------------------------------------------------------

/// The abstract base class for code browser plugins.
///
/// Manages the connected (primary) and disconnected (cloned) providers,
/// the view address set, options initialization, and service lifecycle.
///
/// Ported from Ghidra's `AbstractCodeBrowserPlugin`.
#[derive(Debug)]
pub struct AbstractCodeBrowserPlugin {
    /// The name of this plugin.
    name: String,
    /// The primary (connected) code viewer provider.
    connected_provider: CodeViewerProvider,
    /// Disconnected (cloned) providers.
    disconnected_providers: Vec<CodeViewerProvider>,
    /// The current program name.
    current_program: Option<String>,
    /// The current view address set (stored as sorted non-overlapping ranges).
    current_view: Vec<(u64, u64)>,
    /// Hover service registry.
    hover_registry: HoverServiceRegistry,
    /// Background color model.
    color_model: Option<Arc<RwLock<dyn ListingBackgroundColorModel>>>,
    /// Whether the plugin is disposed.
    disposed: bool,
    /// Plugin options (key-value store).
    options: HashMap<String, PluginOption>,
}

/// A plugin option value.
#[derive(Debug, Clone)]
pub enum PluginOption {
    /// Boolean option.
    Bool(bool),
    /// Integer option.
    Int(i32),
    /// String option.
    String(String),
    /// Color option (stored as ARGB u32).
    Color(u32),
}

impl AbstractCodeBrowserPlugin {
    /// Create a new abstract code browser plugin.
    pub fn new(name: impl Into<String>) -> Self {
        let name_str = name.into();
        let connected_provider = CodeViewerProvider::new(&name_str, true);

        Self {
            name: name_str,
            connected_provider,
            disconnected_providers: Vec::new(),
            current_program: None,
            current_view: Vec::new(),
            hover_registry: HoverServiceRegistry::new(),
            color_model: None,
            disposed: false,
            options: HashMap::new(),
        }
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // ---------------------------------------------------------------
    // Provider access
    // ---------------------------------------------------------------

    /// Get a reference to the connected (primary) provider.
    pub fn connected_provider(&self) -> &CodeViewerProvider {
        &self.connected_provider
    }

    /// Get a mutable reference to the connected (primary) provider.
    pub fn connected_provider_mut(&mut self) -> &mut CodeViewerProvider {
        &mut self.connected_provider
    }

    /// Get all disconnected (cloned) providers.
    pub fn disconnected_providers(&self) -> &[CodeViewerProvider] {
        &self.disconnected_providers
    }

    /// Create a new disconnected (cloned) provider.
    pub fn create_disconnected_provider(&mut self) -> &CodeViewerProvider {
        let provider = CodeViewerProvider::new(&self.name, false);
        self.disconnected_providers.push(provider);
        self.disconnected_providers.last().unwrap()
    }

    /// Remove a disconnected provider by ID.
    pub fn remove_disconnected_provider(&mut self, id: u64) -> Option<CodeViewerProvider> {
        if let Some(pos) = self.disconnected_providers.iter().position(|p| p.id() == id) {
            Some(self.disconnected_providers.remove(pos))
        } else {
            None
        }
    }

    // ---------------------------------------------------------------
    // Program / View management
    // ---------------------------------------------------------------

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Set the current program.
    pub fn set_current_program(&mut self, program: Option<String>) {
        self.current_program = program.clone();
        self.connected_provider.set_program(program);
    }

    /// Get the current view (sorted non-overlapping address ranges).
    pub fn current_view(&self) -> &[(u64, u64)] {
        &self.current_view
    }

    /// Set the current view.
    pub fn set_view(&mut self, ranges: Vec<(u64, u64)>) {
        self.current_view = ranges;
    }

    // ---------------------------------------------------------------
    // Hover services
    // ---------------------------------------------------------------

    /// Register a hover service with this plugin.
    pub fn add_hover_service(&mut self, service: Box<dyn ListingHoverService>) {
        self.hover_registry.register(service);
    }

    /// Get the hover service registry.
    pub fn hover_registry(&self) -> &HoverServiceRegistry {
        &self.hover_registry
    }

    // ---------------------------------------------------------------
    // Options
    // ---------------------------------------------------------------

    /// Get a boolean option value.
    pub fn get_bool_option(&self, name: &str, default: bool) -> bool {
        match self.options.get(name) {
            Some(PluginOption::Bool(v)) => *v,
            _ => default,
        }
    }

    /// Set a boolean option.
    pub fn set_bool_option(&mut self, name: impl Into<String>, value: bool) {
        self.options.insert(name.into(), PluginOption::Bool(value));
    }

    /// Get an integer option value.
    pub fn get_int_option(&self, name: &str, default: i32) -> i32 {
        match self.options.get(name) {
            Some(PluginOption::Int(v)) => *v,
            _ => default,
        }
    }

    /// Set an integer option.
    pub fn set_int_option(&mut self, name: impl Into<String>, value: i32) {
        self.options.insert(name.into(), PluginOption::Int(value));
    }

    /// Get a string option value.
    pub fn get_string_option<'a>(&'a self, name: &str, default: &'a str) -> String {
        match self.options.get(name) {
            Some(PluginOption::String(v)) => v.clone(),
            _ => default.to_string(),
        }
    }

    /// Set a string option.
    pub fn set_string_option(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.options
            .insert(name.into(), PluginOption::String(value.into()));
    }

    // ---------------------------------------------------------------
    // Color model
    // ---------------------------------------------------------------

    /// Set the background color model.
    pub fn set_color_model(&mut self, model: Arc<RwLock<dyn ListingBackgroundColorModel>>) {
        self.color_model = Some(model);
    }

    /// Get the background color model, if set.
    pub fn color_model(&self) -> Option<&Arc<RwLock<dyn ListingBackgroundColorModel>>> {
        self.color_model.as_ref()
    }

    /// Create and install a layered color model from the primary model
    /// and a new marker service model.
    pub fn update_background_color_model(&mut self) {
        let marker_colors = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let marker_model = MarkerServiceBackgroundColorModel::new(marker_colors);

        if let Some(primary) = self.color_model.take() {
            let layered = LayeredColorModel::from_models(primary, Arc::new(RwLock::new(marker_model)));
            self.color_model = Some(Arc::new(RwLock::new(layered)));
        } else {
            self.color_model = Some(Arc::new(RwLock::new(marker_model)));
        }
    }

    // ---------------------------------------------------------------
    // Data state persistence
    // ---------------------------------------------------------------

    /// Save the plugin's data state.
    pub fn save_data_state(&self) -> HashMap<String, String> {
        let mut state = self.connected_provider.save_data_state();
        state.insert(
            "Num Disconnected".to_string(),
            self.disconnected_providers.len().to_string(),
        );
        state
    }

    /// Restore the plugin's data state.
    pub fn read_data_state(&mut self, state: &HashMap<String, String>) {
        self.connected_provider.read_data_state(state);
    }

    // ---------------------------------------------------------------
    // Lifecycle
    // ---------------------------------------------------------------

    /// Dispose of this plugin.
    pub fn dispose(&mut self) {
        self.disposed = true;
        self.connected_provider.dispose();
        for mut p in self.disconnected_providers.drain(..) {
            p.dispose();
        }
        self.hover_registry = HoverServiceRegistry::new();
    }
}

// ---------------------------------------------------------------------------
// CodeBrowserPlugin (concrete)
// ---------------------------------------------------------------------------

/// The concrete code browser plugin.
///
/// This is the main plugin that Ghidra instantiates for the code listing
/// view. It extends `AbstractCodeBrowserPlugin` with concrete service
/// registration, event handling, and transient state management.
///
/// Ported from Ghidra's `CodeBrowserPlugin`.
#[derive(Debug)]
pub struct CodeBrowserPlugin {
    /// The abstract base.
    inner: AbstractCodeBrowserPlugin,
    /// Plugin status.
    status: PluginStatus,
    /// Plugin category.
    category: String,
    /// Services provided by this plugin.
    services_provided: Vec<String>,
    /// Services required by this plugin.
    services_required: Vec<String>,
}

/// Plugin status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStatus {
    /// Plugin is in development.
    Stable,
    /// Plugin is released.
    Released,
    /// Plugin is experimental.
    Experimental,
}

impl CodeBrowserPlugin {
    /// Plugin short description.
    pub const DESCRIPTION: &'static str =
        "This plugin provides the main program listing display window. \
         It also includes the header component which allows the various \
         program fields to be arranged as desired.";

    /// Plugin category.
    pub const CATEGORY: &'static str = "Code Viewer";

    /// Create a new code browser plugin.
    pub fn new() -> Self {
        Self {
            inner: AbstractCodeBrowserPlugin::new("CodeBrowserPlugin"),
            status: PluginStatus::Released,
            category: Self::CATEGORY.to_string(),
            services_provided: vec![
                "CodeViewerService".to_string(),
                "CodeFormatService".to_string(),
                "FieldMouseHandlerService".to_string(),
            ],
            services_required: vec![
                "ProgramManager".to_string(),
                "GoToService".to_string(),
                "ClipboardService".to_string(),
            ],
        }
    }

    /// Get the plugin status.
    pub fn status(&self) -> PluginStatus {
        self.status
    }

    /// Get the plugin category.
    pub fn category(&self) -> &str {
        &self.category
    }

    /// Get the services provided.
    pub fn services_provided(&self) -> &[String] {
        &self.services_provided
    }

    /// Get the services required.
    pub fn services_required(&self) -> &[String] {
        &self.services_required
    }

    /// Get a reference to the abstract plugin.
    pub fn inner(&self) -> &AbstractCodeBrowserPlugin {
        &self.inner
    }

    /// Get a mutable reference to the abstract plugin.
    pub fn inner_mut(&mut self) -> &mut AbstractCodeBrowserPlugin {
        &mut self.inner
    }

    /// Get the connected provider.
    pub fn connected_provider(&self) -> &CodeViewerProvider {
        self.inner.connected_provider()
    }

    /// Get a mutable reference to the connected provider.
    pub fn connected_provider_mut(&mut self) -> &mut CodeViewerProvider {
        self.inner.connected_provider_mut()
    }

    /// Broadcast a location change event.
    pub fn broadcast_location_changed(&self, address: &str) {
        let _ = address; // In a full implementation, fire a PluginEvent.
    }

    /// Broadcast a selection change event.
    pub fn broadcast_selection_changed(&self, start: Option<&str>, end: Option<&str>) {
        let _ = (start, end);
    }

    /// Broadcast a highlight change event.
    pub fn broadcast_highlight_changed(&self, start: Option<&str>, end: Option<&str>) {
        let _ = (start, end);
    }
}

impl Default for CodeBrowserPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeBrowserPluginInterface for CodeBrowserPlugin {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn is_disposed(&self) -> bool {
        self.inner.is_disposed()
    }

    fn provider_closed(&self, _provider_id: u64) {
        // In a full implementation, remove the provider from the disconnected list.
    }

    fn broadcast_location_changed(&self, _provider_id: u64, address: &str) {
        self.broadcast_location_changed(address);
    }

    fn broadcast_selection_changed(
        &self,
        _provider_id: u64,
        selection_start: Option<&str>,
        selection_end: Option<&str>,
    ) {
        self.broadcast_selection_changed(selection_start, selection_end);
    }

    fn broadcast_highlight_changed(
        &self,
        _provider_id: u64,
        highlight_start: Option<&str>,
        highlight_end: Option<&str>,
    ) {
        self.broadcast_highlight_changed(highlight_start, highlight_end);
    }

    fn create_new_disconnected_provider(&self) -> Option<CodeViewerProvider> {
        // In a real implementation this would clone the format manager etc.
        // For now, return None since we'd need &mut self.
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abstract_plugin_creation() {
        let plugin = AbstractCodeBrowserPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_disposed());
        assert!(plugin.connected_provider().is_connected());
        assert!(plugin.disconnected_providers().is_empty());
    }

    #[test]
    fn test_abstract_plugin_program() {
        let mut plugin = AbstractCodeBrowserPlugin::new("TestPlugin");
        assert!(plugin.current_program().is_none());
        plugin.set_current_program(Some("test.exe".into()));
        assert_eq!(plugin.current_program(), Some("test.exe"));
        assert_eq!(plugin.connected_provider().program(), Some("test.exe"));
    }

    #[test]
    fn test_abstract_plugin_disconnected_provider() {
        let mut plugin = AbstractCodeBrowserPlugin::new("TestPlugin");
        let _ = plugin.create_disconnected_provider();
        assert_eq!(plugin.disconnected_providers().len(), 1);
        assert!(!plugin.disconnected_providers()[0].is_connected());
    }

    #[test]
    fn test_abstract_plugin_options() {
        let mut plugin = AbstractCodeBrowserPlugin::new("TestPlugin");
        assert!(!plugin.get_bool_option("show_header", false));
        plugin.set_bool_option("show_header", true);
        assert!(plugin.get_bool_option("show_header", false));

        assert_eq!(plugin.get_int_option("font_size", 12), 12);
        plugin.set_int_option("font_size", 14);
        assert_eq!(plugin.get_int_option("font_size", 12), 14);
    }

    #[test]
    fn test_abstract_plugin_color_model() {
        use super::super::color_model::RgbaColor;

        let mut plugin = AbstractCodeBrowserPlugin::new("TestPlugin");
        assert!(plugin.color_model().is_none());

        let model = Arc::new(RwLock::new(SimpleBackgroundColorModel::new(
            RgbaColor::new(255, 255, 255),
        )));
        plugin.set_color_model(model);
        assert!(plugin.color_model().is_some());
    }

    #[test]
    fn test_abstract_plugin_view() {
        let mut plugin = AbstractCodeBrowserPlugin::new("TestPlugin");
        assert!(plugin.current_view().is_empty());
        plugin.set_view(vec![(0x1000, 0x10FF), (0x2000, 0x20FF)]);
        assert_eq!(plugin.current_view().len(), 2);
    }

    #[test]
    fn test_abstract_plugin_dispose() {
        let mut plugin = AbstractCodeBrowserPlugin::new("TestPlugin");
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(plugin.connected_provider().is_disposed());
    }

    #[test]
    fn test_abstract_plugin_save_restore_state() {
        let mut plugin = AbstractCodeBrowserPlugin::new("TestPlugin");
        plugin.connected_provider_mut().go_to("0xDEAD");
        plugin.connected_provider_mut().set_cursor_offset(5);

        let state = plugin.save_data_state();
        let mut plugin2 = AbstractCodeBrowserPlugin::new("TestPlugin");
        plugin2.read_data_state(&state);
        assert_eq!(plugin2.connected_provider().current_address(), Some("0xDEAD"));
    }

    #[test]
    fn test_code_browser_plugin_creation() {
        let plugin = CodeBrowserPlugin::new();
        assert_eq!(plugin.name(), "CodeBrowserPlugin");
        assert_eq!(plugin.status(), PluginStatus::Released);
        assert_eq!(plugin.category(), "Code Viewer");
        assert!(!plugin.services_provided().is_empty());
        assert!(!plugin.services_required().is_empty());
    }

    #[test]
    fn test_code_browser_plugin_services() {
        let plugin = CodeBrowserPlugin::new();
        assert!(plugin.services_provided().contains(&"CodeViewerService".to_string()));
        assert!(plugin.services_provided().contains(&"CodeFormatService".to_string()));
        assert!(plugin.services_required().contains(&"ProgramManager".to_string()));
    }

    #[test]
    fn test_code_browser_plugin_interface() {
        let plugin = CodeBrowserPlugin::new();
        assert_eq!(plugin.name(), "CodeBrowserPlugin");
        assert!(!plugin.is_disposed());
    }

    #[test]
    fn test_code_browser_plugin_default() {
        let plugin = CodeBrowserPlugin::default();
        assert_eq!(plugin.name(), "CodeBrowserPlugin");
    }

    #[test]
    fn test_code_browser_plugin_description() {
        assert!(!CodeBrowserPlugin::DESCRIPTION.is_empty());
        assert!(CodeBrowserPlugin::DESCRIPTION.contains("listing"));
    }

    #[test]
    fn test_code_browser_plugin_inner_access() {
        let mut plugin = CodeBrowserPlugin::new();
        plugin.inner_mut().set_current_program(Some("prog.exe".into()));
        assert_eq!(plugin.inner().current_program(), Some("prog.exe"));
    }
}
