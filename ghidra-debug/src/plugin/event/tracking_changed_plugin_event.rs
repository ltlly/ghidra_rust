//! Tracking changed event.

/// Tracking changed event.
#[derive(Debug, Clone)]
pub struct TrackingChangedPluginEvent {
    /// tracking_enabled
    pub tracking_enabled: bool,
}

impl TrackingChangedPluginEvent {
    /// Create a new TrackingChangedPluginEvent.
    pub fn new(tracking_enabled: bool) -> Self {
        Self { tracking_enabled }
    }

    /// tracking_enabled
    pub fn tracking_enabled(&self) -> &bool {
        &self.tracking_enabled
    }
}

impl Default for TrackingChangedPluginEvent {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = TrackingChangedPluginEvent::new(true);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = TrackingChangedPluginEvent::default();
    }
}
