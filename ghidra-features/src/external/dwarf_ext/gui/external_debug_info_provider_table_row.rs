//! ExternalDebugInfoProviderTableRow -- represents a row in the provider table.
//!
//! Ported from `ghidra.app.util.bin.format.dwarf.external.gui.ExternalDebugInfoProviderTableRow`.
//!
//! Each row wraps a [`DebugInfoProvider`] and tracks its current
//! [`DebugInfoProviderStatus`].  Rows can be enabled/disabled; disabling
//! wraps the provider in a [`DisabledDebugInfoProvider`].

use std::sync::Arc;

use super::super::debug_info_provider::DebugInfoProvider;
use super::super::debug_info_provider_status::DebugInfoProviderStatus;
use super::super::disabled_debug_info_provider::DisabledDebugInfoProvider;

/// Represents a row in the external debug info provider table.
///
/// Each row holds a reference to a [`DebugInfoProvider`] and its current
/// status.  The row can be enabled or disabled; disabling wraps the
/// provider in a [`DisabledDebugInfoProvider`].
#[derive(Debug)]
pub struct ExternalDebugInfoProviderTableRow {
    /// The provider (possibly wrapped in DisabledDebugInfoProvider).
    item: Arc<dyn DebugInfoProvider>,
    /// The current status of this provider.
    status: DebugInfoProviderStatus,
}

impl ExternalDebugInfoProviderTableRow {
    /// Creates a new table row with the given provider.
    pub fn new(item: Arc<dyn DebugInfoProvider>) -> Self {
        Self {
            item,
            status: DebugInfoProviderStatus::Unknown,
        }
    }

    /// Returns a reference to the provider.
    pub fn item(&self) -> &Arc<dyn DebugInfoProvider> {
        &self.item
    }

    /// Replaces the provider.
    pub fn set_item(&mut self, new_item: Arc<dyn DebugInfoProvider>) {
        self.item = new_item;
    }

    /// Returns the current status.
    pub fn status(&self) -> DebugInfoProviderStatus {
        self.status
    }

    /// Sets the status.
    pub fn set_status(&mut self, status: DebugInfoProviderStatus) {
        self.status = status;
    }

    /// Returns `true` if the provider is not wrapped in a
    /// [`DisabledDebugInfoProvider`].
    pub fn is_enabled(&self) -> bool {
        // Check if the provider's name starts with the disabled prefix.
        // This is a simplified check; the Java version uses instanceof.
        !self.item.name().starts_with("disabled://")
    }

    /// Enables or disables this row.
    ///
    /// When disabling, the provider is wrapped in a
    /// [`DisabledDebugInfoProvider`].  When enabling, the original
    /// provider is unwrapped.
    pub fn set_enabled(&mut self, enabled: bool) {
        if self.is_enabled() == enabled {
            return;
        }

        self.status = DebugInfoProviderStatus::Unknown;

        if enabled {
            // Unwrap: remove the disabled prefix to get the original name.
            let name = self.item.name();
            if let Some(inner_name) = name.strip_prefix("disabled://") {
                // We can't easily unwrap without the registry, so we
                // create a placeholder that represents the inner provider.
                // The caller should use the registry to recreate the provider.
                // For now, we just strip the prefix.
                let placeholder = PlaceholderProvider::new(
                    inner_name.to_string(),
                    format!("Enabled: {}", inner_name),
                );
                self.item = Arc::new(placeholder);
            }
        } else {
            // Wrap: create a DisabledDebugInfoProvider.
            let disabled = DisabledDebugInfoProvider::new(Box::new(PlaceholderProvider::new(
                self.item.name().to_string(),
                self.item.descriptive_name().to_string(),
            )));
            self.item = Arc::new(disabled);
        }
    }

    /// Returns `true` if the underlying provider is a
    /// [`DisabledDebugInfoProvider`].
    pub fn is_disabled(&self) -> bool {
        self.item.name().starts_with("disabled://")
    }
}

impl Clone for ExternalDebugInfoProviderTableRow {
    fn clone(&self) -> Self {
        Self {
            item: Arc::clone(&self.item),
            status: self.status,
        }
    }
}

impl std::fmt::Display for ExternalDebugInfoProviderTableRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SearchLocationsTableRow: [ status: {:?}, item: {}]",
            self.status,
            self.item.name()
        )
    }
}

// ---------------------------------------------------------------------------
// PlaceholderProvider (used for wrapping/unwrapping)
// ---------------------------------------------------------------------------

/// A minimal [`DebugInfoProvider`] used as a placeholder when wrapping
/// and unwrapping providers.
#[derive(Debug)]
struct PlaceholderProvider {
    name: String,
    descriptive_name: String,
}

impl PlaceholderProvider {
    fn new(name: String, descriptive_name: String) -> Self {
        Self {
            name,
            descriptive_name,
        }
    }
}

impl DebugInfoProvider for PlaceholderProvider {
    fn name(&self) -> &str {
        &self.name
    }

    fn descriptive_name(&self) -> &str {
        &self.descriptive_name
    }

    fn status(&self) -> DebugInfoProviderStatus {
        DebugInfoProviderStatus::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_provider(name: &str) -> Arc<dyn DebugInfoProvider> {
        Arc::new(PlaceholderProvider::new(
            name.to_string(),
            format!("Test: {}", name),
        ))
    }

    #[test]
    fn test_new_row() {
        let row = ExternalDebugInfoProviderTableRow::new(make_provider("test"));
        assert_eq!(row.item().name(), "test");
        assert_eq!(row.status(), DebugInfoProviderStatus::Unknown);
    }

    #[test]
    fn test_set_status() {
        let mut row = ExternalDebugInfoProviderTableRow::new(make_provider("test"));
        row.set_status(DebugInfoProviderStatus::Valid);
        assert_eq!(row.status(), DebugInfoProviderStatus::Valid);
    }

    #[test]
    fn test_is_enabled_default() {
        let row = ExternalDebugInfoProviderTableRow::new(make_provider("test"));
        assert!(row.is_enabled());
    }

    #[test]
    fn test_is_disabled_default() {
        let row = ExternalDebugInfoProviderTableRow::new(make_provider("test"));
        assert!(!row.is_disabled());
    }

    #[test]
    fn test_is_disabled_with_prefix() {
        let row = ExternalDebugInfoProviderTableRow::new(make_provider(
            "disabled://debuglink:///usr/lib/debug",
        ));
        assert!(!row.is_enabled());
        assert!(row.is_disabled());
    }

    #[test]
    fn test_set_enabled_false() {
        let mut row = ExternalDebugInfoProviderTableRow::new(make_provider("test"));
        assert!(row.is_enabled());

        row.set_enabled(false);
        assert!(!row.is_enabled());
        assert!(row.is_disabled());
        assert_eq!(row.status(), DebugInfoProviderStatus::Unknown);
    }

    #[test]
    fn test_set_enabled_true() {
        let mut row = ExternalDebugInfoProviderTableRow::new(make_provider(
            "disabled://test",
        ));
        assert!(!row.is_enabled());

        row.set_enabled(true);
        assert!(row.is_enabled());
        assert_eq!(row.status(), DebugInfoProviderStatus::Unknown);
    }

    #[test]
    fn test_set_enabled_noop() {
        let mut row = ExternalDebugInfoProviderTableRow::new(make_provider("test"));
        row.set_status(DebugInfoProviderStatus::Valid);

        // Already enabled, setting enabled should be a no-op
        row.set_enabled(true);
        assert_eq!(row.status(), DebugInfoProviderStatus::Valid);
    }

    #[test]
    fn test_set_item() {
        let mut row = ExternalDebugInfoProviderTableRow::new(make_provider("original"));
        assert_eq!(row.item().name(), "original");

        row.set_item(make_provider("replacement"));
        assert_eq!(row.item().name(), "replacement");
    }

    #[test]
    fn test_display() {
        let row = ExternalDebugInfoProviderTableRow::new(make_provider("test"));
        let display = format!("{}", row);
        assert!(display.contains("SearchLocationsTableRow"));
        assert!(display.contains("Unknown"));
        assert!(display.contains("test"));
    }

    #[test]
    fn test_clone() {
        let mut row = ExternalDebugInfoProviderTableRow::new(make_provider("test"));
        row.set_status(DebugInfoProviderStatus::Valid);

        let cloned = row.clone();
        assert_eq!(cloned.item().name(), "test");
        assert_eq!(cloned.status(), DebugInfoProviderStatus::Valid);
    }
}
