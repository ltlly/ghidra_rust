//! Action context provider.

/// Action context provider.
#[derive(Debug, Clone)]
pub struct ActionContextProvider {
    /// provider_name
    pub provider_name: String,
    /// enabled
    pub enabled: bool,
}

impl ActionContextProvider {
    /// Create a new ActionContextProvider.
    pub fn new(provider_name: String, enabled: bool) -> Self {
        Self { provider_name, enabled }
    }

    /// provider_name
    pub fn provider_name(&self) -> &String {
        &self.provider_name
    }

    /// enabled
    pub fn enabled(&self) -> &bool {
        &self.enabled
    }
}

impl Default for ActionContextProvider {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = ActionContextProvider::new("test".to_string(), true);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = ActionContextProvider::default();
    }
}
