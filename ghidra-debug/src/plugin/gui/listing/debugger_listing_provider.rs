//! Listing provider.

/// Listing provider.
#[derive(Debug, Clone)]
pub struct DebuggerListingProvider {
    /// provider_id
    pub provider_id: String,
    /// visible
    pub visible: bool,
}

impl DebuggerListingProvider {
    /// Create a new DebuggerListingProvider.
    pub fn new(provider_id: String, visible: bool) -> Self {
        Self { provider_id, visible }
    }

    /// provider_id
    pub fn provider_id(&self) -> &String {
        &self.provider_id
    }

    /// visible
    pub fn visible(&self) -> &bool {
        &self.visible
    }
}

impl Default for DebuggerListingProvider {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = DebuggerListingProvider::new("test".to_string(), true);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerListingProvider::default();
    }
}
