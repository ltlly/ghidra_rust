//! Inactive coordinates event.

/// Inactive coordinates event.
#[derive(Debug, Clone)]
pub struct TraceInactiveCoordinatesPluginEvent {
    /// coordinates_json
    pub coordinates_json: String,
}

impl TraceInactiveCoordinatesPluginEvent {
    /// Create a new TraceInactiveCoordinatesPluginEvent.
    pub fn new(coordinates_json: String) -> Self {
        Self { coordinates_json }
    }

    /// coordinates_json
    pub fn coordinates_json(&self) -> &String {
        &self.coordinates_json
    }
}

impl Default for TraceInactiveCoordinatesPluginEvent {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = TraceInactiveCoordinatesPluginEvent::new("test".to_string());
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = TraceInactiveCoordinatesPluginEvent::default();
    }
}
