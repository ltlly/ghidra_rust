//! Colorizing plugin, service, and command actions.
//!
//! Ported from `ghidra.app.plugin.core.colorizer.ColorizingPlugin`,
//! `ColorizingService`, `ColorizingServiceProvider`,
//! `SetColorCommand`, `ClearColorCommand`,
//! `NextColorRangeAction`, `PreviousColorRangeAction`.

use super::{ColorEntry, ColorizerModel, ColorizerMode};
use ghidra_core::Address;

// ---------------------------------------------------------------------------
// ColorizingService trait
// ---------------------------------------------------------------------------

/// Service interface for programmatic color management.
///
/// Ported from `ghidra.app.plugin.core.colorizer.ColorizingService`.
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
}

// ---------------------------------------------------------------------------
// ColorizingServiceProvider
// ---------------------------------------------------------------------------

/// Default implementation of the colorizing service.
///
/// Ported from `ghidra.app.plugin.core.colorizer.ColorizingServiceProvider`.
#[derive(Debug, Default)]
pub struct ColorizingServiceProvider {
    model: ColorizerModel,
}

impl ColorizingServiceProvider {
    /// Create a new service provider.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get a reference to the underlying model.
    pub fn model(&self) -> &ColorizerModel {
        &self.model
    }

    /// Get a mutable reference to the underlying model.
    pub fn model_mut(&mut self) -> &mut ColorizerModel {
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
}

// ---------------------------------------------------------------------------
// ColorizingPlugin
// ---------------------------------------------------------------------------

/// Plugin providing color range management in the listing.
///
/// Ported from `ghidra.app.plugin.core.colorizer.ColorizingPlugin`.
#[derive(Debug)]
pub struct ColorizingPlugin {
    service: ColorizingServiceProvider,
}

impl ColorizingPlugin {
    /// Create a new colorizing plugin.
    pub fn new() -> Self {
        Self {
            service: ColorizingServiceProvider::new(),
        }
    }

    /// Get the colorizing service.
    pub fn service(&self) -> &dyn ColorizingService {
        &self.service
    }

    /// Get a mutable reference to the colorizing service.
    pub fn service_mut(&mut self) -> &mut dyn ColorizingService {
        &mut self.service
    }

    /// Set a color on an address (convenience method).
    pub fn set_color(&mut self, address: Address, r: u8, g: u8, b: u8) {
        self.service.set_color(address, ColorEntry::new(r, g, b));
    }

    /// Remove a color from an address (convenience method).
    pub fn remove_color(&mut self, address: Address) {
        self.service.remove_color(address);
    }

    /// Get all colored addresses sorted.
    pub fn colored_addresses(&self) -> Vec<Address> {
        self.service.model().colored_addresses()
    }
}

impl Default for ColorizingPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SetColorCommand / ClearColorCommand
// ---------------------------------------------------------------------------

/// Command to set a color on an address.
///
/// Ported from `ghidra.app.plugin.core.colorizer.SetColorCommand`.
#[derive(Debug, Clone)]
pub struct SetColorCommand {
    /// The address.
    pub address: Address,
    /// The color to set.
    pub color: ColorEntry,
    /// Command name.
    name: String,
}

impl SetColorCommand {
    /// Create a new set-color command.
    pub fn new(address: Address, color: ColorEntry) -> Self {
        Self {
            address,
            color,
            name: "Set Color".to_string(),
        }
    }

    /// Get the command name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Apply the command to a service.
    pub fn apply(&self, service: &mut dyn ColorizingService) {
        service.set_color(self.address, self.color.clone());
    }
}

/// Command to clear a color on an address.
///
/// Ported from `ghidra.app.plugin.core.colorizer.ClearColorCommand`.
#[derive(Debug, Clone)]
pub struct ClearColorCommand {
    /// The address.
    pub address: Address,
    /// Command name.
    name: String,
}

impl ClearColorCommand {
    /// Create a new clear-color command.
    pub fn new(address: Address) -> Self {
        Self {
            address,
            name: "Clear Color".to_string(),
        }
    }

    /// Get the command name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Apply the command to a service.
    pub fn apply(&self, service: &mut dyn ColorizingService) {
        service.remove_color(self.address);
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_colorizing_service_provider() {
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
    fn test_colorizing_plugin() {
        let mut plugin = ColorizingPlugin::new();
        plugin.set_color(Address::new(0x1000), 255, 0, 0);
        plugin.set_color(Address::new(0x2000), 0, 255, 0);

        let addrs = plugin.colored_addresses();
        assert_eq!(addrs.len(), 2);

        plugin.remove_color(Address::new(0x1000));
        let addrs = plugin.colored_addresses();
        assert_eq!(addrs.len(), 1);
    }

    #[test]
    fn test_set_color_command() {
        let mut provider = ColorizingServiceProvider::new();
        let cmd = SetColorCommand::new(Address::new(0x1000), ColorEntry::new(0, 0, 255));
        assert_eq!(cmd.name(), "Set Color");
        cmd.apply(&mut provider);

        let color = provider.get_color(Address::new(0x1000));
        assert!(color.is_some());
        assert_eq!(color.unwrap().b, 255);
    }

    #[test]
    fn test_clear_color_command() {
        let mut provider = ColorizingServiceProvider::new();
        provider.set_color(Address::new(0x1000), ColorEntry::new(255, 0, 0));

        let cmd = ClearColorCommand::new(Address::new(0x1000));
        assert_eq!(cmd.name(), "Clear Color");
        cmd.apply(&mut provider);

        assert!(provider.get_color(Address::new(0x1000)).is_none());
    }

    #[test]
    fn test_service_remove_nonexistent() {
        let mut provider = ColorizingServiceProvider::new();
        // Should not panic
        provider.remove_color(Address::new(0x9999));
    }

    #[test]
    fn test_plugin_mode() {
        let mut plugin = ColorizingPlugin::new();
        assert_eq!(plugin.service().mode(), ColorizerMode::None);

        plugin.service_mut().set_mode(ColorizerMode::ByEntropy);
        assert_eq!(plugin.service().mode(), ColorizerMode::ByEntropy);
    }
}
