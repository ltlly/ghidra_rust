//! Plugin-like featurettes for visual graph providers.
//!
//! Ports `ghidra.graph.featurette.VisualGraphFeaturette`
//! and `ghidra.graph.featurette.VgSatelliteFeaturette`.

/// Position of the satellite viewer relative to the main viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SatellitePosition {
    /// Upper-left corner.
    UpperLeft,
    /// Upper-right corner.
    UpperRight,
    /// Lower-left corner.
    LowerLeft,
    /// Lower-right corner.
    LowerRight,
}

impl Default for SatellitePosition {
    fn default() -> Self {
        Self::LowerRight
    }
}

/// A sub-feature that can be attached to a visual graph component provider.
///
/// Ports `ghidra.graph.featurette.VisualGraphFeaturette`.
pub trait VisualGraphFeaturette {
    /// Human-readable name of this featurette.
    fn name(&self) -> &str;

    /// Called when the provider is shown.
    fn provider_opened(&self) {}

    /// Called when the provider is hidden/closed.
    fn provider_closed(&self) {}

    /// Remove / dispose of this featurette.
    fn remove(&self) {}
}

/// Satellite viewer featurette.
///
/// Ports `ghidra.graph.featurette.VgSatelliteFeaturette`.
#[derive(Debug)]
pub struct VgSatelliteFeaturette {
    visible: bool,
    position: SatellitePosition,
}

impl VgSatelliteFeaturette {
    /// Create a new satellite featurette.
    pub fn new() -> Self {
        Self {
            visible: true,
            position: SatellitePosition::default(),
        }
    }

    /// Get the satellite position.
    pub fn position(&self) -> SatellitePosition {
        self.position
    }

    /// Set the satellite position.
    pub fn set_position(&mut self, pos: SatellitePosition) {
        self.position = pos;
    }

    /// Whether the satellite is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set satellite visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }
}

impl Default for VgSatelliteFeaturette {
    fn default() -> Self {
        Self::new()
    }
}

impl VisualGraphFeaturette for VgSatelliteFeaturette {
    fn name(&self) -> &str {
        "Satellite"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_satellite_defaults() {
        let sat = VgSatelliteFeaturette::new();
        assert!(sat.is_visible());
        assert_eq!(sat.position(), SatellitePosition::LowerRight);
    }

    #[test]
    fn test_satellite_position_change() {
        let mut sat = VgSatelliteFeaturette::new();
        sat.set_position(SatellitePosition::UpperLeft);
        assert_eq!(sat.position(), SatellitePosition::UpperLeft);
    }

    #[test]
    fn test_satellite_visibility() {
        let mut sat = VgSatelliteFeaturette::new();
        sat.set_visible(false);
        assert!(!sat.is_visible());
    }

    #[test]
    fn test_satellite_featurette_name() {
        let sat = VgSatelliteFeaturette::new();
        assert_eq!(sat.name(), "Satellite");
    }
}
