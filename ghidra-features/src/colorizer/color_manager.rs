//! Color management for the listing colorizer.
//!
//! Ported from `ghidra.app.plugin.core.colorizer` Java package.
//!
//! Provides color management for address-based highlighting in the
//! code browser listing, supporting multiple color layers and
//! configurable color schemes.

use std::collections::HashMap;

/// An RGBA color value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RgbaColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl RgbaColor {
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    pub const fn with_alpha(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// White color.
    pub const WHITE: Self = Self::new(255, 255, 255);
    /// Black color.
    pub const BLACK: Self = Self::new(0, 0, 0);
    /// Red color.
    pub const RED: Self = Self::new(255, 0, 0);
    /// Green color.
    pub const GREEN: Self = Self::new(0, 255, 0);
    /// Blue color.
    pub const BLUE: Self = Self::new(0, 0, 255);
    /// Yellow color.
    pub const YELLOW: Self = Self::new(255, 255, 0);
    /// Cyan color.
    pub const CYAN: Self = Self::new(0, 255, 255);
    /// Magenta color.
    pub const MAGENTA: Self = Self::new(255, 0, 255);
    /// Orange color.
    pub const ORANGE: Self = Self::new(255, 165, 0);

    /// Create from a 32-bit packed RGBA value.
    pub const fn from_u32(rgba: u32) -> Self {
        Self {
            r: ((rgba >> 24) & 0xFF) as u8,
            g: ((rgba >> 16) & 0xFF) as u8,
            b: ((rgba >> 8) & 0xFF) as u8,
            a: (rgba & 0xFF) as u8,
        }
    }

    /// Pack into a 32-bit RGBA value.
    pub const fn to_u32(self) -> u32 {
        ((self.r as u32) << 24)
            | ((self.g as u32) << 16)
            | ((self.b as u32) << 8)
            | (self.a as u32)
    }
}

/// A color layer in the listing.
///
/// Each layer has a priority and can assign colors to addresses.
/// Higher-priority layers override lower-priority ones.
#[derive(Debug)]
pub struct ColorLayer {
    /// Layer name.
    pub name: String,
    /// Layer priority (higher = more visible).
    pub priority: i32,
    /// Whether this layer is visible.
    pub visible: bool,
    /// Color assignments: address -> color.
    colors: HashMap<u64, RgbaColor>,
}

impl ColorLayer {
    /// Create a new color layer.
    pub fn new(name: impl Into<String>, priority: i32) -> Self {
        Self {
            name: name.into(),
            priority,
            visible: true,
            colors: HashMap::new(),
        }
    }

    /// Set the color for an address.
    pub fn set_color(&mut self, address: u64, color: RgbaColor) {
        self.colors.insert(address, color);
    }

    /// Get the color for an address.
    pub fn get_color(&self, address: u64) -> Option<RgbaColor> {
        self.colors.get(&address).copied()
    }

    /// Remove the color for an address.
    pub fn clear_color(&mut self, address: u64) {
        self.colors.remove(&address);
    }

    /// Clear all colors.
    pub fn clear_all(&mut self) {
        self.colors.clear();
    }

    /// Number of color assignments.
    pub fn len(&self) -> usize {
        self.colors.len()
    }

    /// Whether this layer has no colors.
    pub fn is_empty(&self) -> bool {
        self.colors.is_empty()
    }

    /// Get all colored addresses.
    pub fn colored_addresses(&self) -> Vec<u64> {
        self.colors.keys().copied().collect()
    }
}

/// Color manager for the listing.
///
/// Ported from the color management logic in `ghidra.app.plugin.core.colorizer`.
///
/// Manages multiple color layers and resolves the final color for each
/// address by priority.
#[derive(Debug)]
pub struct ListingColorManager {
    /// Color layers, ordered by priority.
    layers: Vec<ColorLayer>,
    /// Default background color.
    default_color: RgbaColor,
}

impl ListingColorManager {
    /// Create a new color manager.
    pub fn new() -> Self {
        Self {
            layers: Vec::new(),
            default_color: RgbaColor::WHITE,
        }
    }

    /// Set the default background color.
    pub fn set_default_color(&mut self, color: RgbaColor) {
        self.default_color = color;
    }

    /// Add a color layer.
    pub fn add_layer(&mut self, layer: ColorLayer) {
        self.layers.push(layer);
        // Sort by priority (highest first)
        self.layers.sort_by(|a, b| b.priority.cmp(&a.priority));
    }

    /// Get a layer by name.
    pub fn layer(&self, name: &str) -> Option<&ColorLayer> {
        self.layers.iter().find(|l| l.name == name)
    }

    /// Get a mutable layer by name.
    pub fn layer_mut(&mut self, name: &str) -> Option<&mut ColorLayer> {
        self.layers.iter_mut().find(|l| l.name == name)
    }

    /// Remove a layer by name.
    pub fn remove_layer(&mut self, name: &str) -> Option<ColorLayer> {
        if let Some(pos) = self.layers.iter().position(|l| l.name == name) {
            Some(self.layers.remove(pos))
        } else {
            None
        }
    }

    /// Get the resolved color for an address.
    ///
    /// Returns the color from the highest-priority visible layer,
    /// or the default color if no layer has a color for this address.
    pub fn get_color(&self, address: u64) -> RgbaColor {
        for layer in &self.layers {
            if layer.visible {
                if let Some(color) = layer.get_color(address) {
                    return color;
                }
            }
        }
        self.default_color
    }

    /// Number of layers.
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// Clear all layers.
    pub fn clear(&mut self) {
        self.layers.clear();
    }
}

impl Default for ListingColorManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rgba_color() {
        let c = RgbaColor::new(255, 0, 0);
        assert_eq!(c.r, 255);
        assert_eq!(c.a, 255);

        let c2 = RgbaColor::with_alpha(0, 0, 0, 128);
        assert_eq!(c2.a, 128);
    }

    #[test]
    fn test_rgba_color_packed() {
        let c = RgbaColor::new(0xAA, 0xBB, 0xCC);
        let packed = c.to_u32();
        let unpacked = RgbaColor::from_u32(packed);
        assert_eq!(c, unpacked);
    }

    #[test]
    fn test_color_layer() {
        let mut layer = ColorLayer::new("test", 10);
        assert!(layer.is_empty());

        layer.set_color(0x1000, RgbaColor::RED);
        assert_eq!(layer.len(), 1);
        assert_eq!(layer.get_color(0x1000), Some(RgbaColor::RED));
        assert_eq!(layer.get_color(0x2000), None);

        layer.clear_color(0x1000);
        assert!(layer.is_empty());
    }

    #[test]
    fn test_listing_color_manager() {
        let mut mgr = ListingColorManager::new();

        let mut layer1 = ColorLayer::new("low", 1);
        layer1.set_color(0x1000, RgbaColor::BLUE);

        let mut layer2 = ColorLayer::new("high", 10);
        layer2.set_color(0x1000, RgbaColor::RED);

        mgr.add_layer(layer1);
        mgr.add_layer(layer2);

        // High priority layer should win
        assert_eq!(mgr.get_color(0x1000), RgbaColor::RED);

        // Address with no color in any layer -> default
        assert_eq!(mgr.get_color(0x2000), RgbaColor::WHITE);
    }

    #[test]
    fn test_listing_color_manager_visible() {
        let mut mgr = ListingColorManager::new();

        let mut layer = ColorLayer::new("test", 10);
        layer.set_color(0x1000, RgbaColor::RED);
        layer.visible = false;
        mgr.add_layer(layer);

        // Layer is hidden, so should return default
        assert_eq!(mgr.get_color(0x1000), RgbaColor::WHITE);
    }

    #[test]
    fn test_listing_color_manager_remove_layer() {
        let mut mgr = ListingColorManager::new();
        mgr.add_layer(ColorLayer::new("a", 1));
        mgr.add_layer(ColorLayer::new("b", 2));
        assert_eq!(mgr.layer_count(), 2);

        mgr.remove_layer("a");
        assert_eq!(mgr.layer_count(), 1);
    }
}
