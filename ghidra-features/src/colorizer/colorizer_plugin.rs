//! Colorizing plugin -- ported from `ColorizingPlugin.java`.
//!
//! Provides the plugin-level orchestration for color range management
//! in the listing, including command actions and navigation.
//!
//! Ported from:
//! - `ghidra.app.plugin.core.colorizer.ColorizingPlugin`
//! - `ghidra.app.plugin.core.colorizer.SetColorCommand`
//! - `ghidra.app.plugin.core.colorizer.ClearColorCommand`
//! - `ghidra.app.plugin.core.colorizer.NextColorRangeAction`
//! - `ghidra.app.plugin.core.colorizer.PreviousColorRangeAction`

use super::{ColorEntry, ColorRange, ColorizerMode};
use super::colorizer_service::{ColorizingService, ColorizingServiceProvider};
use ghidra_core::Address;

// ---------------------------------------------------------------------------
// ColorizingPlugin
// ---------------------------------------------------------------------------

/// Plugin providing color range management in the listing.
///
/// Ported from `ghidra.app.plugin.core.colorizer.ColorizingPlugin`.
///
/// Owns a [`ColorizingServiceProvider`] and exposes convenience
/// methods for programmatic and command-driven color operations.
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

    /// Get the current colorizer mode.
    pub fn mode(&self) -> ColorizerMode {
        self.service.mode()
    }

    /// Set the colorizer mode.
    pub fn set_mode(&mut self, mode: ColorizerMode) {
        self.service.set_mode(mode);
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

/// Command to clear all colors.
///
/// Ported from the clear-all action in `ColorizingPlugin`.
#[derive(Debug, Clone)]
pub struct ClearAllColorsCommand {
    name: String,
}

impl ClearAllColorsCommand {
    /// Create a new clear-all command.
    pub fn new() -> Self {
        Self {
            name: "Clear All Colors".to_string(),
        }
    }

    /// Get the command name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Apply the command to a service.
    pub fn apply(&self, service: &mut dyn ColorizingService) {
        service.clear_all();
    }
}

impl Default for ClearAllColorsCommand {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Navigation actions
// ---------------------------------------------------------------------------

/// Action to navigate to the next color range.
///
/// Ported from `ghidra.app.plugin.core.colorizer.NextColorRangeAction`.
#[derive(Debug)]
pub struct NextColorRangeAction;

impl NextColorRangeAction {
    /// The action name.
    pub const NAME: &'static str = "Next Color Range";

    /// Execute the action: find the next color range from the given address.
    pub fn execute(model: &super::ColorizerModel, from: Address) -> Option<ColorRange> {
        super::ColorizingService::find_next_color_range(model, from)
    }
}

/// Action to navigate to the previous color range.
///
/// Ported from `ghidra.app.plugin.core.colorizer.PreviousColorRangeAction`.
#[derive(Debug)]
pub struct PreviousColorRangeAction;

impl PreviousColorRangeAction {
    /// The action name.
    pub const NAME: &'static str = "Previous Color Range";

    /// Execute the action: find the previous color range from the given address.
    pub fn execute(model: &super::ColorizerModel, from: Address) -> Option<ColorRange> {
        super::ColorizingService::find_previous_color_range(model, from)
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_plugin_mode() {
        let mut plugin = ColorizingPlugin::new();
        assert_eq!(plugin.mode(), ColorizerMode::None);

        plugin.set_mode(ColorizerMode::ByEntropy);
        assert_eq!(plugin.mode(), ColorizerMode::ByEntropy);
    }

    #[test]
    fn test_plugin_default() {
        let plugin = ColorizingPlugin::default();
        assert_eq!(plugin.mode(), ColorizerMode::None);
        assert!(plugin.colored_addresses().is_empty());
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
    fn test_clear_all_colors_command() {
        let mut provider = ColorizingServiceProvider::new();
        provider.set_color(Address::new(0x1000), ColorEntry::red());
        provider.set_color(Address::new(0x2000), ColorEntry::blue());
        assert_eq!(provider.colored_count(), 2);

        let cmd = ClearAllColorsCommand::new();
        assert_eq!(cmd.name(), "Clear All Colors");
        cmd.apply(&mut provider);
        assert_eq!(provider.colored_count(), 0);
    }

    #[test]
    fn test_next_color_range_action() {
        let mut model = super::super::ColorizerModel::new();
        model.set_color(Address::new(0x1000), ColorEntry::red());
        model.set_color(Address::new(0x1001), ColorEntry::red());
        model.set_color(Address::new(0x2000), ColorEntry::blue());

        let next = NextColorRangeAction::execute(&model, Address::new(0x1000)).unwrap();
        assert_eq!(next.start.offset, 0x1000);
    }

    #[test]
    fn test_previous_color_range_action() {
        let mut model = super::super::ColorizerModel::new();
        model.set_color(Address::new(0x1000), ColorEntry::red());
        model.set_color(Address::new(0x2000), ColorEntry::blue());

        let prev = PreviousColorRangeAction::execute(&model, Address::new(0x2000)).unwrap();
        assert_eq!(prev.start.offset, 0x2000);
    }
}
