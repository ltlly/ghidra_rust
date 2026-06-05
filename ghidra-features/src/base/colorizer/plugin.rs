//! Colorizer plugin -- manages colorizing actions and navigation.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.colorizer`:
//!
//! - [`ColorizingPlugin`] -- plugin managing set/clear/navigate color actions
//! - [`NextColorRangeAction`] -- navigate to the next color range
//! - [`PreviousColorRangeAction`] -- navigate to the previous color range

use super::{Color, ColorizingService, ColorizingServiceImpl};

/// Plugin providing color actions for the listing view.
///
/// Ported from `ghidra.app.plugin.core.colorizer.ColorizingPlugin`.
///
/// Manages set/clear/navigate color actions and maintains a marker set
/// showing where colors have been applied.
#[derive(Debug)]
pub struct ColorizingPlugin {
    /// The colorizing service backing store.
    service: ColorizingServiceImpl,
    /// Plugin name.
    name: String,
    /// Whether the plugin is active.
    active: bool,
    /// Marker set ranges (min, max) for colored addresses.
    marker_ranges: Vec<(u64, u64)>,
    /// Recently used colors for toolbar.
    toolbar_colors: Vec<Color>,
}

impl ColorizingPlugin {
    /// Create a new colorizing plugin.
    pub fn new() -> Self {
        Self {
            service: ColorizingServiceImpl::new(),
            name: "ColorizingPlugin".to_string(),
            active: false,
            marker_ranges: Vec::new(),
            toolbar_colors: Vec::new(),
        }
    }

    /// Plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Activate the plugin.
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Deactivate the plugin.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Whether the plugin is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get a reference to the colorizing service.
    pub fn service(&self) -> &ColorizingServiceImpl {
        &self.service
    }

    /// Get a mutable reference to the colorizing service.
    pub fn service_mut(&mut self) -> &mut ColorizingServiceImpl {
        &mut self.service
    }

    /// Set a background color over an address range.
    pub fn set_color(&mut self, min_addr: u64, max_addr: u64, color: Color) {
        self.service.set_background_color(min_addr, max_addr, color);
        self.update_markers();
        self.update_toolbar_color(color);
    }

    /// Clear background color over an address range.
    pub fn clear_color(&mut self, min_addr: u64, max_addr: u64) {
        self.service.clear_background_color(min_addr, max_addr);
        self.update_markers();
    }

    /// Clear all background colors.
    pub fn clear_all_colors(&mut self) {
        self.service.clear_all_background_colors();
        self.marker_ranges.clear();
    }

    /// Get all colored address ranges.
    pub fn get_all_color_ranges(&self) -> Vec<(u64, u64)> {
        self.service.all_colored_addresses()
    }

    /// Get the next color range after the given address.
    ///
    /// Returns the start address of the next range, or None if there are
    /// no color ranges after the given address.
    pub fn next_color_range(&self, current_addr: u64) -> Option<u64> {
        self.service
            .all_colored_addresses()
            .iter()
            .find(|(start, _)| *start > current_addr)
            .map(|(start, _)| *start)
    }

    /// Get the previous color range before the given address.
    ///
    /// Returns the start address of the previous range, or None if there are
    /// no color ranges before the given address.
    pub fn previous_color_range(&self, current_addr: u64) -> Option<u64> {
        self.service
            .all_colored_addresses()
            .iter()
            .rev()
            .find(|(start, _)| *start < current_addr)
            .map(|(start, _)| *start)
    }

    /// Get the most recently used color.
    pub fn most_recent_color(&self) -> Option<Color> {
        self.service.most_recent_color()
    }

    /// Get the marker ranges.
    pub fn marker_ranges(&self) -> &[(u64, u64)] {
        &self.marker_ranges
    }

    fn update_markers(&mut self) {
        self.marker_ranges = self.service.all_colored_addresses();
    }

    fn update_toolbar_color(&mut self, color: Color) {
        self.toolbar_colors.retain(|&c| c != color);
        self.toolbar_colors.insert(0, color);
        if self.toolbar_colors.len() > 16 {
            self.toolbar_colors.truncate(16);
        }
    }
}

impl Default for ColorizingPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Action to navigate to the next color range in the listing.
///
/// Ported from `ghidra.app.plugin.core.colorizer.NextColorRangeAction`.
#[derive(Debug, Clone)]
pub struct NextColorRangeAction {
    /// The action name.
    name: String,
    /// Menu group.
    group: String,
    /// Whether the action is enabled.
    enabled: bool,
}

impl NextColorRangeAction {
    /// Create a new next-color-range action.
    pub fn new() -> Self {
        Self {
            name: "Next Color Range".to_string(),
            group: "Navigation".to_string(),
            enabled: true,
        }
    }

    /// Action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Menu group.
    pub fn group(&self) -> &str {
        &self.group
    }

    /// Whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set whether the action is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Execute the action: find the next color range.
    ///
    /// Returns the address to navigate to, or None if no next range exists.
    pub fn execute(&self, plugin: &ColorizingPlugin, current_addr: u64) -> Option<u64> {
        plugin.next_color_range(current_addr)
    }
}

impl Default for NextColorRangeAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Action to navigate to the previous color range in the listing.
///
/// Ported from `ghidra.app.plugin.core.colorizer.PreviousColorRangeAction`.
#[derive(Debug, Clone)]
pub struct PreviousColorRangeAction {
    /// The action name.
    name: String,
    /// Menu group.
    group: String,
    /// Whether the action is enabled.
    enabled: bool,
}

impl PreviousColorRangeAction {
    /// Create a new previous-color-range action.
    pub fn new() -> Self {
        Self {
            name: "Previous Color Range".to_string(),
            group: "Navigation".to_string(),
            enabled: true,
        }
    }

    /// Action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Menu group.
    pub fn group(&self) -> &str {
        &self.group
    }

    /// Whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set whether the action is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Execute the action: find the previous color range.
    ///
    /// Returns the address to navigate to, or None if no previous range exists.
    pub fn execute(&self, plugin: &ColorizingPlugin, current_addr: u64) -> Option<u64> {
        plugin.previous_color_range(current_addr)
    }
}

impl Default for PreviousColorRangeAction {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_colorizing_plugin_lifecycle() {
        let mut plugin = ColorizingPlugin::new();
        assert_eq!(plugin.name(), "ColorizingPlugin");
        assert!(!plugin.is_active());

        plugin.activate();
        assert!(plugin.is_active());

        plugin.deactivate();
        assert!(!plugin.is_active());
    }

    #[test]
    fn test_colorizing_plugin_set_and_clear() {
        let mut plugin = ColorizingPlugin::new();
        plugin.set_color(0x1000, 0x1010, 0xFF0000);
        assert_eq!(plugin.service().get_background_color(0x1005), Some(0xFF0000));
        assert!(!plugin.marker_ranges().is_empty());

        plugin.clear_color(0x1005, 0x1010);
        assert_eq!(plugin.service().get_background_color(0x1005), None);
        assert_eq!(plugin.service().get_background_color(0x1004), Some(0xFF0000));
    }

    #[test]
    fn test_colorizing_plugin_clear_all() {
        let mut plugin = ColorizingPlugin::new();
        plugin.set_color(0x1000, 0x2000, 0xFF0000);
        plugin.set_color(0x3000, 0x4000, 0x00FF00);
        assert!(!plugin.get_all_color_ranges().is_empty());

        plugin.clear_all_colors();
        assert!(plugin.get_all_color_ranges().is_empty());
    }

    #[test]
    fn test_colorizing_plugin_navigation() {
        let mut plugin = ColorizingPlugin::new();
        plugin.set_color(0x1000, 0x1010, 0xFF0000);
        plugin.set_color(0x3000, 0x3010, 0x00FF00);
        plugin.set_color(0x5000, 0x5010, 0x0000FF);

        // Next range after 0x1000
        assert_eq!(plugin.next_color_range(0x1000), Some(0x3000));
        assert_eq!(plugin.next_color_range(0x3000), Some(0x5000));
        assert_eq!(plugin.next_color_range(0x5000), None);

        // Previous range before 0x5000
        assert_eq!(plugin.previous_color_range(0x5000), Some(0x3000));
        assert_eq!(plugin.previous_color_range(0x3000), Some(0x1000));
        assert_eq!(plugin.previous_color_range(0x1000), None);
    }

    #[test]
    fn test_colorizing_plugin_recent_color() {
        let mut plugin = ColorizingPlugin::new();
        plugin.set_color(0x1000, 0x1000, 0xFF0000);
        plugin.set_color(0x2000, 0x2000, 0x00FF00);
        assert_eq!(plugin.most_recent_color(), Some(0x00FF00));
    }

    #[test]
    fn test_colorizing_plugin_toolbar_colors() {
        let mut plugin = ColorizingPlugin::new();
        plugin.set_color(0x1000, 0x1000, 0xFF0000);
        plugin.set_color(0x2000, 0x2000, 0x00FF00);
        plugin.set_color(0x3000, 0x3000, 0xFF0000); // same red again
        // Should be deduped: [red, green]
        assert_eq!(plugin.service().recent_colors().len(), 2);
    }

    #[test]
    fn test_next_color_range_action() {
        let action = NextColorRangeAction::new();
        assert_eq!(action.name(), "Next Color Range");
        assert_eq!(action.group(), "Navigation");
        assert!(action.is_enabled());

        let mut plugin = ColorizingPlugin::new();
        plugin.set_color(0x1000, 0x1010, 0xFF0000);
        plugin.set_color(0x5000, 0x5010, 0x00FF00);

        assert_eq!(action.execute(&plugin, 0x1000), Some(0x5000));
        assert_eq!(action.execute(&plugin, 0x5000), None);
    }

    #[test]
    fn test_previous_color_range_action() {
        let action = PreviousColorRangeAction::new();
        assert_eq!(action.name(), "Previous Color Range");

        let mut plugin = ColorizingPlugin::new();
        plugin.set_color(0x1000, 0x1010, 0xFF0000);
        plugin.set_color(0x5000, 0x5010, 0x00FF00);

        assert_eq!(action.execute(&plugin, 0x5000), Some(0x1000));
        assert_eq!(action.execute(&plugin, 0x1000), None);
    }

    #[test]
    fn test_next_color_range_action_disabled() {
        let mut action = NextColorRangeAction::new();
        action.set_enabled(false);
        assert!(!action.is_enabled());
    }

    #[test]
    fn test_previous_color_range_action_disabled() {
        let mut action = PreviousColorRangeAction::new();
        action.set_enabled(false);
        assert!(!action.is_enabled());
    }

    #[test]
    fn test_colorizing_plugin_empty_navigation() {
        let plugin = ColorizingPlugin::new();
        assert_eq!(plugin.next_color_range(0), None);
        assert_eq!(plugin.previous_color_range(0), None);
    }
}
