//! Colorizing service -- ported from `ColorizingService.java`.
//!
//! Defines the service trait and default provider for programmatic
//! color management in the listing, along with a no-op null
//! implementation for testing.
//!
//! Ported from:
//! - `ghidra.app.plugin.core.colorizer.ColorizingService`
//! - `ghidra.app.plugin.core.colorizer.ColorizingServiceProvider`

use super::{ColorEntry, ColorizerMode};
use ghidra_core::Address;

// ---------------------------------------------------------------------------
// ColorizingService trait
// ---------------------------------------------------------------------------

/// Service interface for programmatic color management.
///
/// Ported from `ghidra.app.plugin.core.colorizer.ColorizingService`.
///
/// Plugins and other components consume this trait to set, query, and
/// remove per-address background colors in the listing view.
pub trait ColorizingService: Send + Sync {
    /// Set the color for an address.
    fn set_color(&mut self, address: Address, color: ColorEntry);

    /// Remove the color for an address.
    fn remove_color(&mut self, address: Address);

    /// Get the color for an address.
    fn get_color(&self, address: Address) -> Option<&ColorEntry>;

    /// Get the current colorizer mode.
    fn mode(&self) -> ColorizerMode;

    /// Set the colorizer mode.
    fn set_mode(&mut self, mode: ColorizerMode);

    /// Clear all colors.
    fn clear_all(&mut self);

    /// Get the total number of colored addresses.
    fn colored_count(&self) -> usize;
}

// ---------------------------------------------------------------------------
// ColorizingServiceProvider
// ---------------------------------------------------------------------------

/// Default implementation of [`ColorizingService`].
///
/// Ported from `ghidra.app.plugin.core.colorizer.ColorizingServiceProvider`.
///
/// Delegates to the in-memory [`super::ColorizerModel`] for all state.
#[derive(Debug, Default)]
pub struct ColorizingServiceProvider {
    model: super::ColorizerModel,
}

impl ColorizingServiceProvider {
    /// Create a new service provider.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a reference to the underlying model.
    pub fn model(&self) -> &super::ColorizerModel {
        &self.model
    }

    /// Get a mutable reference to the underlying model.
    pub fn model_mut(&mut self) -> &mut super::ColorizerModel {
        &mut self.model
    }
}

impl ColorizingService for ColorizingServiceProvider {
    fn set_color(&mut self, address: Address, color: ColorEntry) {
        self.model.set_color(address, color);
    }

    fn remove_color(&mut self, address: Address) {
        self.model.remove_color(address);
    }

    fn get_color(&self, address: Address) -> Option<&ColorEntry> {
        self.model.get_color(address)
    }

    fn set_mode(&mut self, mode: ColorizerMode) {
        self.model.set_mode(mode);
    }

    fn mode(&self) -> ColorizerMode {
        self.model.mode()
    }

    fn clear_all(&mut self) {
        self.model.clear();
    }

    fn colored_count(&self) -> usize {
        self.model.count()
    }
}

// ---------------------------------------------------------------------------
// NullColorizingService -- no-op for testing
// ---------------------------------------------------------------------------

/// A no-op implementation of [`ColorizingService`] for testing.
#[derive(Debug, Default)]
pub struct NullColorizingService;

impl ColorizingService for NullColorizingService {
    fn set_color(&mut self, _address: Address, _color: ColorEntry) {}
    fn remove_color(&mut self, _address: Address) {}
    fn get_color(&self, _address: Address) -> Option<&ColorEntry> {
        None
    }
    fn mode(&self) -> ColorizerMode {
        ColorizerMode::None
    }
    fn set_mode(&mut self, _mode: ColorizerMode) {}
    fn clear_all(&mut self) {}
    fn colored_count(&self) -> usize {
        0
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_provider_set_and_get() {
        let mut provider = ColorizingServiceProvider::new();
        assert_eq!(provider.mode(), ColorizerMode::None);

        provider.set_mode(ColorizerMode::ByFunction);
        assert_eq!(provider.mode(), ColorizerMode::ByFunction);

        provider.set_color(Address::new(0x1000), ColorEntry::new(255, 0, 0));
        let color = provider.get_color(Address::new(0x1000));
        assert!(color.is_some());
        assert_eq!(color.unwrap().r, 255);
    }

    #[test]
    fn test_service_provider_remove() {
        let mut provider = ColorizingServiceProvider::new();
        provider.set_color(Address::new(0x1000), ColorEntry::red());
        provider.remove_color(Address::new(0x1000));
        assert!(provider.get_color(Address::new(0x1000)).is_none());
    }

    #[test]
    fn test_service_provider_remove_nonexistent() {
        let mut provider = ColorizingServiceProvider::new();
        // Should not panic
        provider.remove_color(Address::new(0x9999));
    }

    #[test]
    fn test_service_provider_clear_all() {
        let mut provider = ColorizingServiceProvider::new();
        provider.set_color(Address::new(0x1000), ColorEntry::red());
        provider.set_color(Address::new(0x2000), ColorEntry::blue());
        assert_eq!(provider.colored_count(), 2);

        provider.clear_all();
        assert_eq!(provider.colored_count(), 0);
    }

    #[test]
    fn test_service_provider_model_access() {
        let mut provider = ColorizingServiceProvider::new();
        provider.set_color(Address::new(0x1000), ColorEntry::green());
        assert_eq!(provider.model().count(), 1);
    }

    #[test]
    fn test_null_service() {
        let mut svc = NullColorizingService;
        assert_eq!(svc.mode(), ColorizerMode::None);
        assert_eq!(svc.colored_count(), 0);
        assert!(svc.get_color(Address::new(0x1000)).is_none());
        svc.set_color(Address::new(0x1000), ColorEntry::red()); // no-op
        svc.remove_color(Address::new(0x1000)); // no-op
        svc.clear_all(); // no-op
        assert_eq!(svc.colored_count(), 0);
    }
}
