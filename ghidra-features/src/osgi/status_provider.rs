//! Bundle status component provider.
//!
//! Ported from `ghidra.app.plugin.core.osgi.BundleStatusComponentProvider`.
//!
//! Provides the UI component for displaying bundle status information
//! in a table format within the Ghidra tool window.

use super::status_table::{BundleStatusColumns, BundleStatusTableModel, BundleStatusEntry};
use super::{BundleStatus, GhidraBundle};

/// Configuration for the bundle status provider.
#[derive(Debug, Clone)]
pub struct BundleStatusProviderConfig {
    /// Window title.
    pub title: String,
    /// Whether to show the file column.
    pub show_file_column: bool,
    /// Whether to auto-refresh.
    pub auto_refresh: bool,
    /// Refresh interval in milliseconds.
    pub refresh_interval_ms: u64,
}

impl Default for BundleStatusProviderConfig {
    fn default() -> Self {
        Self {
            title: "Bundle Status".to_string(),
            show_file_column: true,
            auto_refresh: false,
            refresh_interval_ms: 5000,
        }
    }
}

/// Provider for displaying bundle status in a component.
///
/// Ported from `ghidra.app.plugin.core.osgi.BundleStatusComponentProvider`.
#[derive(Debug)]
pub struct BundleStatusComponentProvider {
    /// The table model holding bundle data.
    model: BundleStatusTableModel,
    /// Provider configuration.
    config: BundleStatusProviderConfig,
    /// Whether the provider is visible.
    visible: bool,
}

impl BundleStatusComponentProvider {
    /// Create a new provider with default configuration.
    pub fn new() -> Self {
        Self {
            model: BundleStatusTableModel::new(),
            config: BundleStatusProviderConfig::default(),
            visible: false,
        }
    }

    /// Create a provider with custom configuration.
    pub fn with_config(config: BundleStatusProviderConfig) -> Self {
        Self {
            model: BundleStatusTableModel::new(),
            config,
            visible: false,
        }
    }

    /// Update the displayed bundles.
    pub fn update_bundles(&mut self, bundles: &[GhidraBundle]) {
        self.model = BundleStatusTableModel::from_bundles(bundles);
    }

    /// Get the table model.
    pub fn model(&self) -> &BundleStatusTableModel {
        &self.model
    }

    /// Get the provider title.
    pub fn title(&self) -> &str {
        &self.config.title
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Sort the table by a column.
    pub fn sort_by(&mut self, column: usize, ascending: bool) {
        self.model.sort_by(column, ascending);
    }

    /// Get the number of active bundles.
    pub fn active_bundle_count(&self) -> usize {
        self.model.filter_by_status(BundleStatus::Active).len()
    }

    /// Get the number of errored bundles.
    pub fn error_bundle_count(&self) -> usize {
        self.model.filter_by_status(BundleStatus::Error).len()
    }
}

impl Default for BundleStatusComponentProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_bundle(name: &str, status: BundleStatus) -> GhidraBundle {
        GhidraBundle {
            symbolic_name: format!("ghidra.{}", name),
            display_name: name.to_string(),
            version: "1.0.0".to_string(),
            status,
            source_path: PathBuf::from(format!("/tmp/{}.jar", name)),
            description: String::new(),
            dependencies: Vec::new(),
            exports: Vec::new(),
            activator: None,
        }
    }

    #[test]
    fn test_provider_new() {
        let provider = BundleStatusComponentProvider::new();
        assert!(!provider.is_visible());
        assert_eq!(provider.title(), "Bundle Status");
        assert_eq!(provider.model().row_count(), 0);
    }

    #[test]
    fn test_provider_update_bundles() {
        let mut provider = BundleStatusComponentProvider::new();
        let bundles = vec![
            make_bundle("a", BundleStatus::Active),
            make_bundle("b", BundleStatus::Error),
        ];
        provider.update_bundles(&bundles);
        assert_eq!(provider.model().row_count(), 2);
    }

    #[test]
    fn test_provider_active_count() {
        let mut provider = BundleStatusComponentProvider::new();
        let bundles = vec![
            make_bundle("a", BundleStatus::Active),
            make_bundle("b", BundleStatus::Active),
            make_bundle("c", BundleStatus::Installed),
        ];
        provider.update_bundles(&bundles);
        assert_eq!(provider.active_bundle_count(), 2);
    }

    #[test]
    fn test_provider_error_count() {
        let mut provider = BundleStatusComponentProvider::new();
        let bundles = vec![
            make_bundle("a", BundleStatus::Active),
            make_bundle("b", BundleStatus::Error),
        ];
        provider.update_bundles(&bundles);
        assert_eq!(provider.error_bundle_count(), 1);
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = BundleStatusComponentProvider::new();
        assert!(!provider.is_visible());
        provider.set_visible(true);
        assert!(provider.is_visible());
    }

    #[test]
    fn test_provider_config() {
        let config = BundleStatusProviderConfig {
            title: "Custom Title".to_string(),
            show_file_column: false,
            auto_refresh: true,
            refresh_interval_ms: 1000,
        };
        let provider = BundleStatusComponentProvider::with_config(config);
        assert_eq!(provider.title(), "Custom Title");
    }
}
