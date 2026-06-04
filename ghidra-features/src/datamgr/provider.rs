//! DataTypesProvider -- ported from `DataTypesProvider.java`.
//!
//! The provider that manages the data types tree view display and
//! coordinates user interactions with the tree.

/// Configuration for the data types tree display.
#[derive(Debug, Clone)]
pub struct DataTypesConfig {
    /// Show built-in types.
    pub show_built_in: bool,
    /// Show program types.
    pub show_program: bool,
    /// Show archive types.
    pub show_archive: bool,
    /// Filter text (substring match on type name).
    pub filter_text: Option<String>,
    /// Show only recently used types.
    pub show_recent_only: bool,
    /// The maximum number of recently used types to show.
    pub max_recent: usize,
}

impl Default for DataTypesConfig {
    fn default() -> Self {
        Self {
            show_built_in: true,
            show_program: true,
            show_archive: true,
            filter_text: None,
            show_recent_only: false,
            max_recent: 20,
        }
    }
}

/// The data types provider.
///
/// Ported from `DataTypesProvider.java`.  Manages the tree view that
/// shows data types organized by category and archive.
///
/// # Example
///
/// ```
/// use ghidra_features::datamgr::provider::*;
///
/// let mut provider = DataTypesProvider::new("DataTypeTree");
/// provider.set_visible(true);
/// assert!(provider.is_visible());
/// ```
#[derive(Debug)]
pub struct DataTypesProvider {
    /// The provider name.
    name: String,
    /// The display configuration.
    config: DataTypesConfig,
    /// Whether the provider is visible.
    visible: bool,
    /// The active program name.
    program_name: Option<String>,
    /// The number of types displayed.
    displayed_count: usize,
}

impl DataTypesProvider {
    /// Creates a new data types provider.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            config: DataTypesConfig::default(),
            visible: false,
            program_name: None,
            displayed_count: 0,
        }
    }

    /// Returns the provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the configuration.
    pub fn config(&self) -> &DataTypesConfig {
        &self.config
    }

    /// Returns a mutable reference to the configuration.
    pub fn config_mut(&mut self) -> &mut DataTypesConfig {
        &mut self.config
    }

    /// Returns whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Sets the visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Sets the program name.
    pub fn set_program_name(&mut self, name: Option<String>) {
        self.program_name = name;
    }

    /// Returns the program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Sets the displayed type count.
    pub fn set_displayed_count(&mut self, count: usize) {
        self.displayed_count = count;
    }

    /// Returns the displayed type count.
    pub fn displayed_count(&self) -> usize {
        self.displayed_count
    }

    /// Applies a filter to the display.
    pub fn apply_filter(&mut self, filter_text: Option<String>) {
        self.config.filter_text = filter_text;
    }

    /// Clears the filter.
    pub fn clear_filter(&mut self) {
        self.config.filter_text = None;
    }

    /// Disposes the provider.
    pub fn dispose(&mut self) {
        self.visible = false;
        self.program_name = None;
        self.displayed_count = 0;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = DataTypesProvider::new("TestDT");
        assert_eq!(provider.name(), "TestDT");
        assert!(!provider.is_visible());
        assert_eq!(provider.displayed_count(), 0);
    }

    #[test]
    fn test_provider_config() {
        let provider = DataTypesProvider::new("Test");
        let config = provider.config();
        assert!(config.show_built_in);
        assert!(config.show_program);
        assert!(config.show_archive);
        assert!(!config.show_recent_only);
    }

    #[test]
    fn test_provider_filter() {
        let mut provider = DataTypesProvider::new("Test");
        provider.apply_filter(Some("int".to_string()));
        assert!(provider.config().filter_text.is_some());
        provider.clear_filter();
        assert!(provider.config().filter_text.is_none());
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = DataTypesProvider::new("Test");
        provider.set_visible(true);
        assert!(provider.is_visible());
        provider.dispose();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_config_default() {
        let config = DataTypesConfig::default();
        assert_eq!(config.max_recent, 20);
    }
}
