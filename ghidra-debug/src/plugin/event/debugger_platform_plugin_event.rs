//! Platform change event.

/// Platform change event.
#[derive(Debug, Clone)]
pub struct DebuggerPlatformPluginEvent {
    /// platform_name
    pub platform_name: String,
    /// architecture_id
    pub architecture_id: Option<String>,
}

impl DebuggerPlatformPluginEvent {
    /// Create a new DebuggerPlatformPluginEvent.
    pub fn new(platform_name: String, architecture_id: Option<String>) -> Self {
        Self { platform_name, architecture_id }
    }

    /// platform_name
    pub fn platform_name(&self) -> &String {
        &self.platform_name
    }

    /// architecture_id
    pub fn architecture_id(&self) -> Option<&str> {
        self.architecture_id.as_deref()
    }
}

impl Default for DebuggerPlatformPluginEvent {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = DebuggerPlatformPluginEvent::new("test".to_string(), None);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerPlatformPluginEvent::default();
    }
}
