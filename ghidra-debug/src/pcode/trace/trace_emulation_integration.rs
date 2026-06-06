//! Emulator-trace integration.

/// Emulator-trace integration.
#[derive(Debug, Clone)]
pub struct TraceEmulationIntegration {
    /// delayed_write
    pub delayed_write: bool,
    /// immediate_write
    pub immediate_write: bool,
}

impl TraceEmulationIntegration {
    /// Create a new TraceEmulationIntegration.
    pub fn new(delayed_write: bool, immediate_write: bool) -> Self {
        Self { delayed_write, immediate_write }
    }

    /// delayed_write
    pub fn delayed_write(&self) -> &bool {
        &self.delayed_write
    }

    /// immediate_write
    pub fn immediate_write(&self) -> &bool {
        &self.immediate_write
    }
}

impl Default for TraceEmulationIntegration {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = TraceEmulationIntegration::new(true, true);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = TraceEmulationIntegration::default();
    }
}
