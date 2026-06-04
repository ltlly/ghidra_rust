//! Listing GUI integration types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.listing`
//! package in the Debugger module. Provides types for integrating
//! the trace listing view with the debugger.

use serde::{Deserialize, Serialize};

/// A blended background color model for the listing.
///
/// Ported from Ghidra's `MultiBlendedListingBackgroundColorModel`.
/// Manages blending multiple color sources for the code listing display.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlendedListingColorModel {
    /// Base background colors by address (as offset).
    pub base_colors: Vec<(u64, u32)>,
    /// Overlay colors (debugger-specific highlights).
    pub overlay_colors: Vec<(u64, u32)>,
    /// The blend factor (0.0 = all base, 1.0 = all overlay).
    pub blend_factor: f32,
}

impl BlendedListingColorModel {
    /// Create a new blended color model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a base color for an address.
    pub fn set_base_color(&mut self, address: u64, color: u32) {
        self.base_colors.push((address, color));
        self.base_colors.sort_by_key(|&(a, _)| a);
    }

    /// Set an overlay color for an address.
    pub fn set_overlay_color(&mut self, address: u64, color: u32) {
        self.overlay_colors.push((address, color));
        self.overlay_colors.sort_by_key(|&(a, _)| a);
    }

    /// Get the blended color at an address.
    pub fn color_at(&self, address: u64) -> u32 {
        let base = self
            .base_colors
            .iter()
            .find(|&&(a, _)| a == address)
            .map(|&(_, c)| c)
            .unwrap_or(0xff_ffffff);

        let overlay = self
            .overlay_colors
            .iter()
            .find(|&&(a, _)| a == address)
            .map(|&(_, c)| c);

        match overlay {
            Some(ov) => Self::blend_colors(base, ov, self.blend_factor),
            None => base,
        }
    }

    /// Blend two ARGB colors.
    fn blend_colors(base: u32, overlay: u32, factor: f32) -> u32 {
        let f = factor.clamp(0.0, 1.0);
        let inv_f = 1.0 - f;

        let r = ((base >> 16 & 0xff) as f32 * inv_f + (overlay >> 16 & 0xff) as f32 * f) as u32;
        let g = ((base >> 8 & 0xff) as f32 * inv_f + (overlay >> 8 & 0xff) as f32 * f) as u32;
        let b = ((base & 0xff) as f32 * inv_f + (overlay & 0xff) as f32 * f) as u32;

        0xff000000 | (r.min(255) << 16) | (g.min(255) << 8) | b.min(255)
    }

    /// Clear all colors.
    pub fn clear(&mut self) {
        self.base_colors.clear();
        self.overlay_colors.clear();
    }
}

/// Debugger-specific program location for the listing view.
///
/// Ported from Ghidra's `DebuggerProgramLocationActionContext`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerListingLocation {
    /// The address offset.
    pub address: u64,
    /// The address space name.
    pub space_name: String,
    /// The current snap.
    pub snap: i64,
    /// The thread key (for register-space addresses).
    pub thread_key: Option<i64>,
    /// The frame level.
    pub frame: i32,
}

impl DebuggerListingLocation {
    /// Create a new listing location.
    pub fn new(address: u64, snap: i64) -> Self {
        Self {
            address,
            space_name: String::from("ram"),
            snap,
            thread_key: None,
            frame: 0,
        }
    }

    /// Create a register-space location.
    pub fn register(address: u64, snap: i64, thread_key: i64) -> Self {
        Self {
            address,
            space_name: String::from("register"),
            snap,
            thread_key: Some(thread_key),
            frame: 0,
        }
    }

    /// Whether this location is in register space.
    pub fn is_register_space(&self) -> bool {
        self.space_name == "register"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blended_color_model() {
        let mut model = BlendedListingColorModel::new();
        model.set_base_color(0x400000, 0xff_ff0000);
        model.set_overlay_color(0x400000, 0xff_00ff00);
        model.blend_factor = 0.5;

        let color = model.color_at(0x400000);
        // Should be a blend of red and green
        let r = (color >> 16) & 0xff;
        let g = (color >> 8) & 0xff;
        assert!(r > 0);
        assert!(g > 0);
    }

    #[test]
    fn test_blended_color_model_no_overlay() {
        let mut model = BlendedListingColorModel::new();
        model.set_base_color(0x400000, 0xff_ff0000);
        assert_eq!(model.color_at(0x400000), 0xff_ff0000);
        assert_eq!(model.color_at(0x500000), 0xff_ffffff); // Default white
    }

    #[test]
    fn test_blend_colors() {
        let blended = BlendedListingColorModel::blend_colors(0xff_ff0000, 0xff_00ff00, 0.5);
        let r = (blended >> 16) & 0xff;
        let g = (blended >> 8) & 0xff;
        // Should be approximately 128 for both
        assert!((120..=136).contains(&r));
        assert!((120..=136).contains(&g));
    }

    #[test]
    fn test_listing_location() {
        let loc = DebuggerListingLocation::new(0x400000, 10);
        assert_eq!(loc.address, 0x400000);
        assert_eq!(loc.snap, 10);
        assert!(!loc.is_register_space());
    }

    #[test]
    fn test_listing_location_register() {
        let loc = DebuggerListingLocation::register(0x20, 10, 1);
        assert!(loc.is_register_space());
        assert_eq!(loc.thread_key, Some(1));
    }
}
