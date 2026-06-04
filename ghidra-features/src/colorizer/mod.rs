//! Colorizer Plugin -- colorize code units in the listing.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.colorizer` Java package.
//!
//! Provides model-level logic for applying color schemes to addresses
//! in the listing view, including heat-map coloring based on analysis
//! properties.

use ghidra_core::Address;
use std::collections::HashMap;

/// The colorizer mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorizerMode {
    /// No colorization.
    #[default]
    None,
    /// Color by function.
    ByFunction,
    /// Color by instruction type.
    ByInstructionType,
    /// Color by register usage.
    ByRegister,
    /// Color by entropy/byte values.
    ByEntropy,
}

/// A color entry for an address.
#[derive(Debug, Clone)]
pub struct ColorEntry {
    /// The color as RGB.
    pub r: u8,
    pub g: u8,
    pub b: u8,
    /// Whether this is foreground (text) or background color.
    pub is_foreground: bool,
}

impl ColorEntry {
    /// Create a new color entry.
    pub fn new(r: u8, g: u8, b: u8) -> Self {
        Self {
            r,
            g,
            b,
            is_foreground: false,
        }
    }
}

/// Manages color assignments for the listing.
#[derive(Debug, Default)]
pub struct ColorizerModel {
    mode: ColorizerMode,
    colors: HashMap<u64, ColorEntry>,
}

impl ColorizerModel {
    /// Create a new colorizer model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the colorizer mode.
    pub fn set_mode(&mut self, mode: ColorizerMode) {
        self.mode = mode;
    }

    /// Get the current mode.
    pub fn mode(&self) -> ColorizerMode {
        self.mode
    }

    /// Set the color for an address.
    pub fn set_color(&mut self, address: Address, color: ColorEntry) {
        self.colors.insert(address.offset, color);
    }

    /// Get the color for an address.
    pub fn get_color(&self, address: Address) -> Option<&ColorEntry> {
        self.colors.get(&address.offset)
    }

    /// Clear all colors.
    pub fn clear(&mut self) {
        self.colors.clear();
    }

    /// Return the number of colored addresses.
    pub fn count(&self) -> usize {
        self.colors.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_colorizer_mode() {
        let mut model = ColorizerModel::new();
        assert_eq!(model.mode(), ColorizerMode::None);
        model.set_mode(ColorizerMode::ByFunction);
        assert_eq!(model.mode(), ColorizerMode::ByFunction);
    }

    #[test]
    fn test_set_and_get_color() {
        let mut model = ColorizerModel::new();
        model.set_color(Address::new(0x1000), ColorEntry::new(255, 0, 0));
        let color = model.get_color(Address::new(0x1000)).unwrap();
        assert_eq!(color.r, 255);
    }
}
