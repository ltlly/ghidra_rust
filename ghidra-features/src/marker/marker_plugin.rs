//! Marker Manager Plugin.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.marker.MarkerManagerPlugin`.
//!
//! This plugin extends the code browser to include left and right marker
//! components. The left margin shows marks related to the address being shown
//! at that location. The right margin shows marks at a position that is
//! relative to addresses within the overall program (Overview).
//!
//! The plugin provides a service that other plugins can use to display markers.
//! Two types of markers are supported: point markers and area markers.
//! Area markers indicate a range value such as selection. Point markers
//! represent individual addresses such as bookmarks.

use super::marker_provider::{MarkerMarginProvider, MarkerOverviewProvider};
use super::{MarkerManager, MarkerSet, RgbColor};
use std::collections::HashMap;

// ============================================================================
// Plugin status and metadata
// ============================================================================

/// The release status of a plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginStatus {
    /// Stable, released plugin.
    Released,
    /// Plugin under active development.
    Development,
    /// Plugin is unstable or experimental.
    Unstable,
    /// Plugin has been replaced or deprecated.
    Replaced,
}

/// Metadata about a plugin, mirroring Ghidra's `@PluginInfo` annotation.
#[derive(Debug, Clone)]
pub struct PluginInfo {
    /// Current status of the plugin.
    pub status: PluginStatus,
    /// The package this plugin belongs to (e.g., "Core").
    pub package_name: String,
    /// Category for UI grouping.
    pub category: String,
    /// Short description shown in tooltips.
    pub short_description: String,
    /// Full description of the plugin's purpose.
    pub description: String,
    /// Services that must be provided by other plugins.
    pub services_required: Vec<String>,
    /// Services that this plugin provides.
    pub services_provided: Vec<String>,
    /// Events consumed by the plugin.
    pub events_consumed: Vec<String>,
}

impl PluginInfo {
    /// Create plugin info for the Marker Manager Plugin.
    pub fn marker_manager() -> Self {
        Self {
            status: PluginStatus::Released,
            package_name: "Core".to_string(),
            category: "Common".to_string(),
            short_description: "Provides the marker display".to_string(),
            description: "This plugin extends the code browser to include left and right marker \
                components. The left margin shows marks related to the address being shown at \
                that location. The right margin shows marks at a position that is relative to \
                an address within the overall program (Overview). This plugin also provides \
                a service that other plugins can use to display markers. Two types of markers are \
                supported: point markers and area markers. Area markers are used to indicate a \
                range value such as selection. Point markers are used to represent individual \
                addresses such as bookmarks."
                .to_string(),
            services_required: vec!["GoToService".to_string()],
            services_provided: vec![
                "MarkerService".to_string(),
                "ListingMarginProviderService".to_string(),
                "ListingOverviewProviderService".to_string(),
            ],
            events_consumed: vec![],
        }
    }
}

// ============================================================================
// ToolOptions -- browser navigation marker options
// ============================================================================

/// Options category for navigation markers in the browser.
pub const CATEGORY_BROWSER_NAVIGATION_MARKERS: &str = "NavigationMarkers";

/// Options for configuring marker display behavior.
///
/// Ported from Ghidra's options management in `MarkerManagerPlugin`.
#[derive(Debug, Clone)]
pub struct MarkerOptions {
    /// Whether individual marker types are enabled (by name).
    enabled_markers: HashMap<String, bool>,
}

impl MarkerOptions {
    /// Create a new set of marker options.
    pub fn new() -> Self {
        Self {
            enabled_markers: HashMap::new(),
        }
    }

    /// Register a marker type with a default enabled state.
    pub fn register_marker(&mut self, name: &str, default_enabled: bool) {
        self.enabled_markers
            .entry(name.to_string())
            .or_insert(default_enabled);
    }

    /// Check if a marker type is enabled.
    pub fn is_marker_enabled(&self, name: &str) -> bool {
        self.enabled_markers.get(name).copied().unwrap_or(true)
    }

    /// Set whether a marker type is enabled.
    pub fn set_marker_enabled(&mut self, name: &str, enabled: bool) {
        self.enabled_markers.insert(name.to_string(), enabled);
    }

    /// Get all registered marker names and their enabled state.
    pub fn all_markers(&self) -> &HashMap<String, bool> {
        &self.enabled_markers
    }

    /// Remove a marker type registration.
    pub fn unregister_marker(&mut self, name: &str) {
        self.enabled_markers.remove(name);
    }
}

impl Default for MarkerOptions {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// MarkerManagerPlugin -- the main plugin
// ============================================================================

/// The Marker Manager Plugin.
///
/// Ported from `ghidra.app.plugin.core.marker.MarkerManagerPlugin`.
///
/// Manages marker and navigation panels. Implements
/// `ListingMarginProviderService` and `ListingOverviewProviderService` to
/// provide marker display in both the margin and overview bar.
#[derive(Debug)]
pub struct MarkerManagerPlugin {
    /// The plugin's unique identifier.
    id: u64,
    /// The plugin name.
    name: String,
    /// The marker manager that handles all marker set operations.
    pub marker_manager: MarkerManager,
    /// Registered margin providers.
    margin_providers: Vec<MarkerMarginProvider>,
    /// Registered overview providers.
    overview_providers: Vec<MarkerOverviewProvider>,
    /// Options for controlling marker visibility.
    pub options: MarkerOptions,
    /// Whether the plugin has been disposed.
    disposed: bool,
}

impl MarkerManagerPlugin {
    /// Create a new MarkerManagerPlugin.
    ///
    /// Corresponds to the Java constructor `MarkerManagerPlugin(PluginTool tool)`.
    pub fn new(id: u64, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            marker_manager: MarkerManager::new(),
            margin_providers: Vec::new(),
            overview_providers: Vec::new(),
            options: MarkerOptions::new(),
            disposed: false,
        }
    }

    /// Get the plugin's unique ID.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Get the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Dispose the plugin, releasing all resources.
    ///
    /// Mirrors Java's `dispose()` method.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.margin_providers.clear();
        self.overview_providers.clear();
        self.marker_manager.clear();
    }

    /// Whether the plugin has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // -- ListingMarginProviderService implementation --

    /// Create a new margin provider for displaying markers in the listing margin.
    ///
    /// Mirrors Java's `createMarginProvider()`.
    pub fn create_margin_provider(&mut self) -> MarkerMarginProvider {
        let provider = MarkerMarginProvider::new(self.margin_providers.len());
        self.margin_providers.push(provider.clone());
        provider
    }

    /// Check if a margin provider is owned by this plugin.
    ///
    /// Mirrors Java's `isOwner(ListingMarginProvider provider)`.
    pub fn is_margin_provider_owner(&self, provider: &MarkerMarginProvider) -> bool {
        self.margin_providers.iter().any(|p| p.id() == provider.id())
    }

    /// Remove a margin provider.
    pub fn remove_margin_provider(&mut self, provider_id: usize) {
        self.margin_providers.retain(|p| p.id() != provider_id);
    }

    /// Get all registered margin providers.
    pub fn margin_providers(&self) -> &[MarkerMarginProvider] {
        &self.margin_providers
    }

    // -- ListingOverviewProviderService implementation --

    /// Create a new overview provider for displaying markers in the overview bar.
    ///
    /// Mirrors Java's `createOverviewProvider()`.
    pub fn create_overview_provider(&mut self) -> MarkerOverviewProvider {
        let provider = MarkerOverviewProvider::new(
            self.overview_providers.len(),
            &self.name,
        );
        self.overview_providers.push(provider.clone());
        provider
    }

    /// Check if an overview provider is owned by this plugin.
    ///
    /// Mirrors Java's `isOwner(ListingOverviewProvider provider)`.
    pub fn is_overview_provider_owner(&self, provider: &MarkerOverviewProvider) -> bool {
        self.overview_providers.iter().any(|p| p.id() == provider.id())
    }

    /// Remove an overview provider.
    pub fn remove_overview_provider(&mut self, provider_id: usize) {
        self.overview_providers.retain(|p| p.id() != provider_id);
    }

    /// Get all registered overview providers.
    pub fn overview_providers(&self) -> &[MarkerOverviewProvider] {
        &self.overview_providers
    }

    // -- MarkerService convenience methods --

    /// Create an area marker set and register it with the manager.
    ///
    /// Mirrors `MarkerService.createAreaMarker()`.
    pub fn create_area_marker(
        &mut self,
        name: &str,
        description: &str,
        priority: i32,
        show_markers: bool,
        show_navigation: bool,
        color_background: bool,
        color: RgbColor,
        is_preferred: bool,
    ) -> String {
        let set = super::AreaMarkerSetImpl::new(name, description, priority, color)
            .with_show_markers(show_markers)
            .with_show_navigation(show_navigation)
            .with_color_background(color_background)
            .with_preferred(is_preferred);
        let set_name = set.name().to_string();
        self.marker_manager.add_marker_set(Box::new(set));
        self.options.register_marker(&set_name, true);
        set_name
    }

    /// Create a point marker set and register it with the manager.
    ///
    /// Mirrors `MarkerService.createPointMarker()`.
    pub fn create_point_marker(
        &mut self,
        name: &str,
        description: &str,
        priority: i32,
        show_markers: bool,
        show_navigation: bool,
        color_background: bool,
        color: RgbColor,
        is_preferred: bool,
    ) -> String {
        let set = super::PointMarkerSetImpl::new(name, description, priority, color)
            .with_show_markers(show_markers)
            .with_show_navigation(show_navigation)
            .with_color_background(color_background)
            .with_preferred(is_preferred);
        let set_name = set.name().to_string();
        self.marker_manager.add_marker_set(Box::new(set));
        self.options.register_marker(&set_name, true);
        set_name
    }

    /// Remove a marker set by name.
    ///
    /// Mirrors `MarkerService.removeMarker()`.
    pub fn remove_marker(&mut self, name: &str) {
        self.marker_manager.remove_marker_sets(name);
        self.options.unregister_marker(name);
    }

    /// Set a marker set as the active one for a named group.
    ///
    /// Mirrors `MarkerService.setMarkerForGroup()`.
    pub fn set_marker_for_group(&mut self, group_name: &str, set_name: &str) {
        self.marker_manager
            .set_marker_for_group(group_name, set_name);
    }

    /// Remove a marker from a group.
    ///
    /// Mirrors `MarkerService.removeMarkerForGroup()`.
    pub fn remove_marker_for_group(&mut self, group_name: &str) {
        self.marker_manager.remove_marker_for_group(group_name);
    }

    /// Check if a marker set is the active marker for its group.
    ///
    /// Mirrors `MarkerService.isActiveMarkerForGroup()`.
    pub fn is_active_marker_for_group(&self, group_name: &str, set_name: &str) -> bool {
        self.marker_manager
            .get_marker_for_group(group_name)
            .map(|s| s == set_name)
            .unwrap_or(false)
    }

    /// Get the background color at the given address, blending all active
    /// background-coloring marker sets.
    ///
    /// Mirrors `MarkerService.getBackgroundColor()`.
    pub fn get_background_color(&self, address: u64) -> Option<RgbColor> {
        self.marker_manager.get_background_color(address)
    }

    /// Get the marker set with the given name.
    pub fn get_marker_set(&self, name: &str) -> Vec<&dyn MarkerSet> {
        self.marker_manager.get_marker_sets(name)
    }

    /// Get tooltip lines for markers at the given address.
    pub fn get_tooltip_lines(&self, address: u64) -> Vec<String> {
        self.marker_manager.get_tooltip_lines(address)
    }

    /// Repaint all margin providers.
    ///
    /// Mirrors the update cycle that notifies margin and overview providers.
    pub fn repaint_providers(&self) {
        // In the Java version this is handled by SwingUpdateManager;
        // here it is a no-op placeholder for the rendering subsystem.
    }

    /// Refresh the action list for overview providers.
    ///
    /// Mirrors `refreshActionList(Program)`.
    pub fn refresh_action_list(&self) {
        // In the Java version this rebuilds docking actions from marker sets;
        // here it is a no-op placeholder for the UI action system.
    }

    /// Update marker sets and repaint.
    ///
    /// Mirrors `updateMarkerSets(Program, boolean, boolean, boolean)`.
    pub fn update_marker_sets(
        &mut self,
        update_markers: bool,
        update_navigation: bool,
        update_now: bool,
    ) {
        // Clear dirty flag to acknowledge changes
        if update_now {
            self.marker_manager.clear_dirty();
        }
        // In the full implementation this would trigger provider repaints
    }
}

impl Default for MarkerManagerPlugin {
    fn default() -> Self {
        Self::new(0, "MarkerManagerPlugin")
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_info() {
        let info = PluginInfo::marker_manager();
        assert_eq!(info.status, PluginStatus::Released);
        assert_eq!(info.package_name, "Core");
        assert_eq!(info.category, "Common");
        assert!(info.services_provided.contains(&"MarkerService".to_string()));
        assert!(info.services_provided.contains(&"ListingMarginProviderService".to_string()));
        assert!(info.services_provided.contains(&"ListingOverviewProviderService".to_string()));
        assert!(info.services_required.contains(&"GoToService".to_string()));
    }

    #[test]
    fn test_plugin_creation() {
        let plugin = MarkerManagerPlugin::new(42, "TestPlugin");
        assert_eq!(plugin.id(), 42);
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_disposed());
    }

    #[test]
    fn test_plugin_default() {
        let plugin = MarkerManagerPlugin::default();
        assert_eq!(plugin.id(), 0);
        assert_eq!(plugin.name(), "MarkerManagerPlugin");
    }

    #[test]
    fn test_plugin_dispose() {
        let mut plugin = MarkerManagerPlugin::new(1, "Test");
        let _mp = plugin.create_margin_provider();
        let _op = plugin.create_overview_provider();

        assert!(!plugin.is_disposed());
        plugin.dispose();
        assert!(plugin.is_disposed());
        assert!(plugin.margin_providers().is_empty());
        assert!(plugin.overview_providers().is_empty());

        // Double dispose is safe
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_create_margin_provider() {
        let mut plugin = MarkerManagerPlugin::new(1, "Test");
        let provider = plugin.create_margin_provider();
        assert!(plugin.is_margin_provider_owner(&provider));
        assert_eq!(plugin.margin_providers().len(), 1);

        let provider2 = plugin.create_margin_provider();
        assert_eq!(plugin.margin_providers().len(), 2);
        assert!(plugin.is_margin_provider_owner(&provider2));
    }

    #[test]
    fn test_remove_margin_provider() {
        let mut plugin = MarkerManagerPlugin::new(1, "Test");
        let provider = plugin.create_margin_provider();
        let provider_id = provider.id();
        assert_eq!(plugin.margin_providers().len(), 1);

        plugin.remove_margin_provider(provider_id);
        assert_eq!(plugin.margin_providers().len(), 0);
    }

    #[test]
    fn test_create_overview_provider() {
        let mut plugin = MarkerManagerPlugin::new(1, "Test");
        let provider = plugin.create_overview_provider();
        assert!(plugin.is_overview_provider_owner(&provider));
        assert_eq!(plugin.overview_providers().len(), 1);

        let provider2 = plugin.create_overview_provider();
        assert_eq!(plugin.overview_providers().len(), 2);
    }

    #[test]
    fn test_remove_overview_provider() {
        let mut plugin = MarkerManagerPlugin::new(1, "Test");
        let provider = plugin.create_overview_provider();
        let provider_id = provider.id();
        assert_eq!(plugin.overview_providers().len(), 1);

        plugin.remove_overview_provider(provider_id);
        assert_eq!(plugin.overview_providers().len(), 0);
    }

    #[test]
    fn test_create_area_marker() {
        let mut plugin = MarkerManagerPlugin::new(1, "Test");
        let name = plugin.create_area_marker(
            "Errors",
            "Error markers",
            10,
            true,
            true,
            false,
            RgbColor::RED,
            true,
        );
        assert_eq!(name, "Errors");

        let sets = plugin.get_marker_set("Errors");
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].name(), "Errors");
        assert_eq!(sets[0].priority(), 10);
        assert!(sets[0].show_markers());
        assert!(sets[0].show_navigation());
        assert!(!sets[0].color_background());
        assert!(sets[0].is_preferred());
    }

    #[test]
    fn test_create_point_marker() {
        let mut plugin = MarkerManagerPlugin::new(1, "Test");
        let name = plugin.create_point_marker(
            "Bookmarks",
            "User bookmarks",
            5,
            true,
            false,
            false,
            RgbColor::GREEN,
            true,
        );
        assert_eq!(name, "Bookmarks");

        let sets = plugin.get_marker_set("Bookmarks");
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].name(), "Bookmarks");
        assert!(!sets[0].show_navigation());
    }

    #[test]
    fn test_remove_marker() {
        let mut plugin = MarkerManagerPlugin::new(1, "Test");
        plugin.create_area_marker("Errors", "", 10, true, true, false, RgbColor::RED, true);
        assert_eq!(plugin.marker_manager.marker_set_count(), 1);

        plugin.remove_marker("Errors");
        assert_eq!(plugin.marker_manager.marker_set_count(), 0);
        assert!(plugin.get_marker_set("Errors").is_empty());
    }

    #[test]
    fn test_marker_groups() {
        let mut plugin = MarkerManagerPlugin::new(1, "Test");
        plugin.set_marker_for_group("Errors", "AnalysisErrors");
        assert!(plugin.is_active_marker_for_group("Errors", "AnalysisErrors"));
        assert!(!plugin.is_active_marker_for_group("Errors", "OtherErrors"));

        plugin.remove_marker_for_group("Errors");
        assert!(!plugin.is_active_marker_for_group("Errors", "AnalysisErrors"));
    }

    #[test]
    fn test_background_color() {
        let mut plugin = MarkerManagerPlugin::new(1, "Test");
        plugin.create_area_marker(
            "Warnings",
            "Warnings",
            5,
            true,
            true,
            true,
            RgbColor::YELLOW,
            true,
        );

        // No markers added to the set yet, so no background color
        let color = plugin.get_background_color(0x1000);
        assert!(color.is_none());
    }

    #[test]
    fn test_tooltip_lines() {
        let mut plugin = MarkerManagerPlugin::new(1, "Test");
        plugin.create_area_marker("Search", "Found", 5, true, true, false, RgbColor::CYAN, true);
        let lines = plugin.get_tooltip_lines(0x1000);
        // Empty because no addresses have been added to the marker set
        assert!(lines.is_empty());
    }

    #[test]
    fn test_options() {
        let mut opts = MarkerOptions::new();
        assert!(opts.is_marker_enabled("anything")); // default true

        opts.register_marker("Errors", true);
        opts.register_marker("Warnings", false);
        assert!(opts.is_marker_enabled("Errors"));
        assert!(!opts.is_marker_enabled("Warnings"));

        opts.set_marker_enabled("Errors", false);
        assert!(!opts.is_marker_enabled("Errors"));

        opts.unregister_marker("Errors");
        assert!(opts.is_marker_enabled("Errors")); // falls back to default true
    }

    #[test]
    fn test_plugin_with_options() {
        let mut plugin = MarkerManagerPlugin::new(1, "Test");
        plugin.create_area_marker("Errors", "", 10, true, true, false, RgbColor::RED, true);

        assert!(plugin.options.is_marker_enabled("Errors"));
        plugin.options.set_marker_enabled("Errors", false);
        assert!(!plugin.options.is_marker_enabled("Errors"));
    }

    #[test]
    fn test_margin_provider_not_owner() {
        let mut plugin = MarkerManagerPlugin::new(1, "Test");
        let provider = plugin.create_margin_provider();
        plugin.remove_margin_provider(provider.id());
        assert!(!plugin.is_margin_provider_owner(&provider));
    }

    #[test]
    fn test_overview_provider_not_owner() {
        let mut plugin = MarkerManagerPlugin::new(1, "Test");
        let provider = plugin.create_overview_provider();
        plugin.remove_overview_provider(provider.id());
        assert!(!plugin.is_overview_provider_owner(&provider));
    }

    #[test]
    fn test_multiple_marker_sets() {
        let mut plugin = MarkerManagerPlugin::new(1, "Test");
        plugin.create_area_marker("Errors", "errors", 10, true, true, false, RgbColor::RED, true);
        plugin.create_area_marker("Warnings", "warnings", 5, true, true, false, RgbColor::YELLOW, true);
        plugin.create_point_marker("Bookmarks", "bookmarks", 3, true, true, false, RgbColor::GREEN, true);

        assert_eq!(plugin.marker_manager.marker_set_count(), 3);
        assert_eq!(plugin.get_marker_set("Errors").len(), 1);
        assert_eq!(plugin.get_marker_set("Warnings").len(), 1);
        assert_eq!(plugin.get_marker_set("Bookmarks").len(), 1);
    }
}
