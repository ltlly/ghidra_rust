//! UI providers for the Sample Table Plugin extension.
//!
//! Ported from `SampleTableProvider.java` and `SampleSearchTableProvider.java`
//! in the SampleTablePlugin extension.
//!
//! Providers manage the component lifecycle (visibility, disposal) and
//! bridge the plugin model to the UI layer. In the Java originals these
//! extend `ComponentProviderAdapter` and manage Swing components. In Rust
//! we capture the essential state and lifecycle without a GUI framework.

// ---------------------------------------------------------------------------
// SampleTableProvider
// ---------------------------------------------------------------------------

/// Provider for the algorithm-based function statistics table.
///
/// Ported from `SampleTableProvider.java`. In the Java original this
/// extends `ComponentProviderAdapter` and builds a Swing panel with a
/// `GFilterTable`, checkbox controls for algorithm selection, a
/// file-chooser panel, and options management.
///
/// In Rust we model the lifecycle and state: visibility, algorithm
/// checkbox state, file path, and the reset-data option.
#[derive(Debug)]
pub struct SampleTableProvider {
    /// Provider name.
    name: String,
    /// Whether the provider is visible.
    visible: bool,
    /// Names of discovered algorithms.
    discovered_algorithms: Vec<String>,
    /// Whether each algorithm is selected (parallel to `discovered_algorithms`).
    selected: Vec<bool>,
    /// Path for saving table data.
    save_path: Option<String>,
    /// Whether to reset table data before reload.
    reset_table_data: bool,
}

impl SampleTableProvider {
    /// Create a new provider with the given name.
    ///
    /// By default, the three built-in algorithms are discovered and all
    /// selected.
    pub fn new(name: impl Into<String>) -> Self {
        let discovered_algorithms = vec![
            "Size".to_string(),
            "Basic Block Count".to_string(),
            "References To".to_string(),
        ];
        let selected = vec![true; discovered_algorithms.len()];
        Self {
            name: name.into(),
            visible: true,
            discovered_algorithms,
            selected,
            save_path: None,
            reset_table_data: true,
        }
    }

    /// Provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the provider is currently visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Dispose the provider (hide and release resources).
    pub fn dispose(&mut self) {
        self.visible = false;
    }

    /// Get the names of discovered algorithms.
    pub fn discovered_algorithms(&self) -> &[String] {
        &self.discovered_algorithms
    }

    /// Get the selected state of each algorithm.
    pub fn selected_algorithms(&self) -> &[bool] {
        &self.selected
    }

    /// Toggle algorithm selection by index.
    pub fn toggle_algorithm(&mut self, index: usize) {
        if let Some(sel) = self.selected.get_mut(index) {
            *sel = !*sel;
        }
    }

    /// Get the list of selected algorithm names.
    pub fn get_selected_algorithm_names(&self) -> Vec<&str> {
        self.discovered_algorithms
            .iter()
            .zip(self.selected.iter())
            .filter(|(_, &sel)| sel)
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Set the save path for table data export.
    pub fn set_save_path(&mut self, path: Option<String>) {
        self.save_path = path;
    }

    /// Get the save path.
    pub fn save_path(&self) -> Option<&str> {
        self.save_path.as_deref()
    }

    /// Whether to reset existing table data.
    pub fn reset_table_data(&self) -> bool {
        self.reset_table_data
    }

    /// Set the reset-table-data option.
    pub fn set_reset_table_data(&mut self, value: bool) {
        self.reset_table_data = value;
    }
}

// ---------------------------------------------------------------------------
// SampleSearchTableProvider
// ---------------------------------------------------------------------------

/// Provider for the search-results table.
///
/// Ported from `SampleSearchTableProvider.java`. Manages the visibility
/// lifecycle of the search table component.
#[derive(Debug)]
pub struct SampleSearchTableProvider {
    /// Provider name.
    name: String,
    /// Whether the provider is visible.
    visible: bool,
}

impl SampleSearchTableProvider {
    /// Create a new provider with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            visible: true,
        }
    }

    /// Provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the provider is currently visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Dispose the provider (hide and release resources).
    pub fn dispose(&mut self) {
        self.visible = false;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_new() {
        let p = SampleTableProvider::new("P");
        assert_eq!(p.name(), "P");
        assert!(p.is_visible());
        assert_eq!(p.discovered_algorithms().len(), 3);
    }

    #[test]
    fn test_provider_dispose() {
        let mut p = SampleTableProvider::new("P");
        p.dispose();
        assert!(!p.is_visible());
    }

    #[test]
    fn test_provider_algorithms_default_selected() {
        let p = SampleTableProvider::new("P");
        assert!(p.selected_algorithms().iter().all(|&s| s));
        let names = p.get_selected_algorithm_names();
        assert_eq!(names, vec!["Size", "Basic Block Count", "References To"]);
    }

    #[test]
    fn test_provider_toggle_algorithm() {
        let mut p = SampleTableProvider::new("P");
        p.toggle_algorithm(1); // deselect "Basic Block Count"
        assert!(!p.selected_algorithms()[1]);
        let names = p.get_selected_algorithm_names();
        assert_eq!(names, vec!["Size", "References To"]);
    }

    #[test]
    fn test_provider_toggle_algorithm_out_of_bounds() {
        let mut p = SampleTableProvider::new("P");
        p.toggle_algorithm(100); // should be a no-op
        assert!(p.selected_algorithms().iter().all(|&s| s));
    }

    #[test]
    fn test_provider_save_path() {
        let mut p = SampleTableProvider::new("P");
        assert!(p.save_path().is_none());
        p.set_save_path(Some("/tmp/results.csv".to_string()));
        assert_eq!(p.save_path(), Some("/tmp/results.csv"));
        p.set_save_path(None);
        assert!(p.save_path().is_none());
    }

    #[test]
    fn test_provider_reset_table_data() {
        let mut p = SampleTableProvider::new("P");
        assert!(p.reset_table_data());
        p.set_reset_table_data(false);
        assert!(!p.reset_table_data());
    }

    #[test]
    fn test_search_provider_new() {
        let p = SampleSearchTableProvider::new("SP");
        assert_eq!(p.name(), "SP");
        assert!(p.is_visible());
    }

    #[test]
    fn test_search_provider_dispose() {
        let mut p = SampleSearchTableProvider::new("SP");
        p.dispose();
        assert!(!p.is_visible());
    }
}
