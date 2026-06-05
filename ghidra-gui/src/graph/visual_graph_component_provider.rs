//! Base component provider for displaying VisualGraphs.
//!
//! Ports `ghidra.graph.VisualGraphComponentProvider`.

use std::collections::HashSet;

/// Satellite display position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SatellitePosition {
    /// Top-left corner.
    TopLeft,
    /// Top-right corner.
    TopRight,
    /// Bottom-left corner.
    BottomLeft,
    /// Bottom-right corner.
    BottomRight,
}

impl Default for SatellitePosition {
    fn default() -> Self {
        SatellitePosition::BottomRight
    }
}

/// Featurette (sub-feature) for a visual graph provider.
pub trait VisualGraphFeaturette: Send + Sync {
    /// Called when the provider is opened.
    fn provider_opened(&self, _provider_id: &str) {}
    /// Called when the provider is closed.
    fn provider_closed(&self, _provider_id: &str) {}
}

/// A base component provider for displaying VisualGraphs.
///
/// This provides common infrastructure including satellite view support,
/// sub-feature management, and configuration state.
pub struct VisualGraphComponentProvider {
    /// Provider name.
    pub name: String,
    /// Owner (typically plugin class name).
    pub owner: String,
    /// Whether the satellite is visible.
    pub satellite_visible: bool,
    /// Satellite position.
    pub satellite_position: SatellitePosition,
    /// Whether to display popups on hover.
    pub display_popups: bool,
    /// Whether the provider is currently visible.
    pub visible: bool,
    /// Registered featurette IDs.
    featurette_ids: HashSet<String>,
}

impl VisualGraphComponentProvider {
    /// Create a new provider.
    pub fn new(name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            owner: owner.into(),
            satellite_visible: true,
            satellite_position: SatellitePosition::default(),
            display_popups: true,
            visible: false,
            featurette_ids: HashSet::new(),
        }
    }

    /// Called when the component becomes visible.
    pub fn component_shown(&mut self) {
        self.visible = true;
    }

    /// Called when the component is hidden.
    pub fn component_hidden(&mut self) {
        self.visible = false;
    }

    /// Toggle satellite visibility.
    pub fn toggle_satellite(&mut self) {
        self.satellite_visible = !self.satellite_visible;
    }

    /// Set satellite position.
    pub fn set_satellite_position(&mut self, pos: SatellitePosition) {
        self.satellite_position = pos;
    }

    /// Register a sub-feature.
    pub fn add_featurette(&mut self, id: impl Into<String>) {
        self.featurette_ids.insert(id.into());
    }

    /// Check if a featurette is registered.
    pub fn has_featurette(&self, id: &str) -> bool {
        self.featurette_ids.contains(id)
    }

    /// Save configuration state.
    pub fn save_config_state(&self) -> ProviderConfigState {
        ProviderConfigState {
            satellite_visible: self.satellite_visible,
            satellite_position: self.satellite_position,
            display_popups: self.display_popups,
        }
    }

    /// Restore configuration state.
    pub fn restore_config_state(&mut self, state: &ProviderConfigState) {
        self.satellite_visible = state.satellite_visible;
        self.satellite_position = state.satellite_position;
        self.display_popups = state.display_popups;
    }
}

/// Saved configuration state for a VisualGraphComponentProvider.
#[derive(Debug, Clone)]
pub struct ProviderConfigState {
    /// Whether the satellite is visible.
    pub satellite_visible: bool,
    /// Satellite position.
    pub satellite_position: SatellitePosition,
    /// Whether popups are displayed.
    pub display_popups: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = VisualGraphComponentProvider::new("Graph View", "TestPlugin");
        assert_eq!(provider.name, "Graph View");
        assert!(!provider.visible);
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = VisualGraphComponentProvider::new("Graph", "Owner");
        provider.component_shown();
        assert!(provider.visible);
        provider.component_hidden();
        assert!(!provider.visible);
    }

    #[test]
    fn test_provider_satellite() {
        let mut provider = VisualGraphComponentProvider::new("Graph", "Owner");
        assert!(provider.satellite_visible);
        provider.toggle_satellite();
        assert!(!provider.satellite_visible);
        provider.set_satellite_position(SatellitePosition::TopLeft);
        assert_eq!(provider.satellite_position, SatellitePosition::TopLeft);
    }

    #[test]
    fn test_provider_featurettes() {
        let mut provider = VisualGraphComponentProvider::new("Graph", "Owner");
        provider.add_featurette("satellite");
        assert!(provider.has_featurette("satellite"));
        assert!(!provider.has_featurette("other"));
    }

    #[test]
    fn test_provider_config_state() {
        let mut provider = VisualGraphComponentProvider::new("Graph", "Owner");
        provider.satellite_visible = false;
        provider.display_popups = false;
        let state = provider.save_config_state();

        let mut provider2 = VisualGraphComponentProvider::new("Graph", "Owner");
        provider2.restore_config_state(&state);
        assert!(!provider2.satellite_visible);
        assert!(!provider2.display_popups);
    }
}
