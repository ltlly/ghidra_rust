//! TraceEmulationIntegration ported from TraceEmulationIntegration.java.
//!
//! Integrates p-code emulation with trace recording.

use std::collections::HashMap;

/// Integrates pcode emulation with the trace database.
#[derive(Debug)]
pub struct TraceEmulationIntegration {
    /// The snap at which emulation starts.
    start_snap: i64,
    /// Callbacks configuration.
    callbacks: HashMap<String, String>,
}

impl TraceEmulationIntegration {
    /// Create a new integration at the given snap.
    pub fn new(start_snap: i64) -> Self {
        Self {
            start_snap,
            callbacks: HashMap::new(),
        }
    }

    /// Get the start snap.
    pub fn start_snap(&self) -> i64 {
        self.start_snap
    }

    /// Set a callback configuration.
    pub fn set_callback(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.callbacks.insert(key.into(), value.into());
    }

    /// Get a callback configuration.
    pub fn get_callback(&self, key: &str) -> Option<&str> {
        self.callbacks.get(key).map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_integration_creation() {
        let integration = TraceEmulationIntegration::new(100);
        assert_eq!(integration.start_snap(), 100);
    }

    #[test]
    fn test_callbacks() {
        let mut integration = TraceEmulationIntegration::new(0);
        integration.set_callback("on_write", "record");
        assert_eq!(integration.get_callback("on_write"), Some("record"));
        assert_eq!(integration.get_callback("missing"), None);
    }
}
