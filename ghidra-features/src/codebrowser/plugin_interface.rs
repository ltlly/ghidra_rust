//! The `CodeBrowserPluginInterface` trait.
//!
//! Ports `ghidra.app.plugin.core.codebrowser.CodeBrowserPluginInterface`,
//! which defines the contract between the code viewer provider and the
//! plugin that manages it.

use super::provider::CodeViewerProvider;

/// Trait that the code browser plugin must implement.
///
/// This decouples the `CodeViewerProvider` from the concrete plugin class,
/// allowing the provider to call back into the plugin for event broadcasting,
/// service resolution, and lifecycle management.
///
/// Ported from Ghidra's `CodeBrowserPluginInterface`.
pub trait CodeBrowserPluginInterface: Send + Sync {
    /// Get the name of this plugin.
    fn name(&self) -> &str;

    /// Whether this plugin has been disposed.
    fn is_disposed(&self) -> bool;

    /// Notification that a provider has been closed.
    fn provider_closed(&self, provider_id: u64);

    /// Broadcast that the location has changed in the given provider.
    fn broadcast_location_changed(&self, provider_id: u64, address: &str);

    /// Broadcast that the selection has changed in the given provider.
    fn broadcast_selection_changed(
        &self,
        provider_id: u64,
        selection_start: Option<&str>,
        selection_end: Option<&str>,
    );

    /// Broadcast that the highlight has changed in the given provider.
    fn broadcast_highlight_changed(
        &self,
        provider_id: u64,
        highlight_start: Option<&str>,
        highlight_end: Option<&str>,
    );

    /// Create a new disconnected (secondary) provider.
    ///
    /// This is used when the user clones the listing view.
    fn create_new_disconnected_provider(&self) -> Option<CodeViewerProvider>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// A test implementation of `CodeBrowserPluginInterface`.
    struct MockPlugin {
        name: String,
        disposed: Arc<AtomicBool>,
        broadcast_count: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl MockPlugin {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                disposed: Arc::new(AtomicBool::new(false)),
                broadcast_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            }
        }
    }

    impl CodeBrowserPluginInterface for MockPlugin {
        fn name(&self) -> &str {
            &self.name
        }

        fn is_disposed(&self) -> bool {
            self.disposed.load(Ordering::SeqCst)
        }

        fn provider_closed(&self, _provider_id: u64) {
            // no-op for test
        }

        fn broadcast_location_changed(&self, _provider_id: u64, _address: &str) {
            self.broadcast_count.fetch_add(1, Ordering::SeqCst);
        }

        fn broadcast_selection_changed(
            &self,
            _provider_id: u64,
            _selection_start: Option<&str>,
            _selection_end: Option<&str>,
        ) {
            self.broadcast_count.fetch_add(1, Ordering::SeqCst);
        }

        fn broadcast_highlight_changed(
            &self,
            _provider_id: u64,
            _highlight_start: Option<&str>,
            _highlight_end: Option<&str>,
        ) {
            self.broadcast_count.fetch_add(1, Ordering::SeqCst);
        }

        fn create_new_disconnected_provider(&self) -> Option<CodeViewerProvider> {
            None
        }
    }

    #[test]
    fn test_mock_plugin_basic() {
        let plugin = MockPlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_disposed());
    }

    #[test]
    fn test_mock_plugin_broadcast() {
        let plugin = MockPlugin::new("TestPlugin");
        plugin.broadcast_location_changed(1, "0x1000");
        plugin.broadcast_selection_changed(1, Some("0x1000"), Some("0x1010"));
        assert_eq!(plugin.broadcast_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_mock_plugin_dispose() {
        let plugin = MockPlugin::new("TestPlugin");
        plugin.disposed.store(true, Ordering::SeqCst);
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_create_disconnected_provider_none() {
        let plugin = MockPlugin::new("TestPlugin");
        assert!(plugin.create_new_disconnected_provider().is_none());
    }
}
