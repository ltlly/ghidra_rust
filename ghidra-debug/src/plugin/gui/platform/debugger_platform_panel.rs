//! Platform panel.

/// Platform panel.
#[derive(Debug, Clone)]
pub struct DebuggerPlatformPanel {
    /// available_platforms
    pub available_platforms: Vec<String>,
    /// selected_platform
    pub selected_platform: Option<String>,
}

impl DebuggerPlatformPanel {
    /// Create a new DebuggerPlatformPanel.
    pub fn new(available_platforms: Vec<String>, selected_platform: Option<String>) -> Self {
        Self { available_platforms, selected_platform }
    }

    /// available_platforms
    pub fn available_platforms(&self) -> &Vec<String> {
        &self.available_platforms
    }

    /// selected_platform
    pub fn selected_platform(&self) -> Option<&str> {
        self.selected_platform.as_deref()
    }
}

impl Default for DebuggerPlatformPanel {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = DebuggerPlatformPanel::new(vec![], None);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerPlatformPanel::default();
    }
}
