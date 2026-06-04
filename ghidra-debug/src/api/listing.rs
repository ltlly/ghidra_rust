//! Debugger listing integration types.
//!
//! Ported from Ghidra's `ghidra.debug.api.listing` package.

use serde::{Deserialize, Serialize};

/// The source of data displayed in the listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ListingDataSource {
    /// Data from the trace (dynamic).
    Trace,
    /// Data from the mapped program (static).
    Program,
    /// Blended data from both trace and program.
    Blended,
}

/// A color model for the listing background that blends trace and program data.
///
/// Ported from Ghidra's `MultiBlendedListingBackgroundColorModel`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlendedListingColorModel {
    /// The blend factor (0.0 = all program, 1.0 = all trace).
    pub blend_factor: f32,
    /// Color for known memory regions.
    pub known_color: [u8; 4],
    /// Color for unknown memory regions.
    pub unknown_color: [u8; 4],
    /// Color for written (modified) memory.
    pub written_color: [u8; 4],
    /// Color for read-only memory.
    pub readonly_color: [u8; 4],
}

impl Default for BlendedListingColorModel {
    fn default() -> Self {
        Self {
            blend_factor: 0.5,
            known_color: [0xf0, 0xf0, 0xf0, 0xff],
            unknown_color: [0xff, 0xe0, 0xe0, 0xff],
            written_color: [0xe0, 0xff, 0xe0, 0xff],
            readonly_color: [0xe0, 0xe0, 0xff, 0xff],
        }
    }
}

impl BlendedListingColorModel {
    /// Create a new color model with default colors.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the blend factor.
    pub fn with_blend_factor(mut self, factor: f32) -> Self {
        self.blend_factor = factor.clamp(0.0, 1.0);
        self
    }

    /// Get the color for a given address based on its data source.
    pub fn color_for(&self, source: ListingDataSource) -> [u8; 4] {
        match source {
            ListingDataSource::Trace => self.written_color,
            ListingDataSource::Program => self.known_color,
            ListingDataSource::Blended => {
                // Simple linear blend of known and written colors
                let f = self.blend_factor;
                [
                    (self.known_color[0] as f32 * (1.0 - f) + self.written_color[0] as f32 * f) as u8,
                    (self.known_color[1] as f32 * (1.0 - f) + self.written_color[1] as f32 * f) as u8,
                    (self.known_color[2] as f32 * (1.0 - f) + self.written_color[2] as f32 * f) as u8,
                    0xff,
                ]
            }
        }
    }
}

/// Debugger-specific listing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebuggerListingConfig {
    /// Whether to show trace data in the listing.
    pub show_trace_data: bool,
    /// Whether to highlight unknown (uninitialized) memory.
    pub highlight_unknown: bool,
    /// The color model.
    pub color_model: BlendedListingColorModel,
    /// Whether to follow the program counter.
    pub follow_pc: bool,
}

impl Default for DebuggerListingConfig {
    fn default() -> Self {
        Self {
            show_trace_data: true,
            highlight_unknown: true,
            color_model: BlendedListingColorModel::default(),
            follow_pc: true,
        }
    }
}

impl DebuggerListingConfig {
    /// Create with defaults.
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blended_color_model() {
        let model = BlendedListingColorModel::new()
            .with_blend_factor(0.3);
        assert!((model.blend_factor - 0.3).abs() < f32::EPSILON);
    }

    #[test]
    fn test_color_for_source() {
        let model = BlendedListingColorModel::new();
        let trace_color = model.color_for(ListingDataSource::Trace);
        assert_eq!(trace_color, model.written_color);

        let prog_color = model.color_for(ListingDataSource::Program);
        assert_eq!(prog_color, model.known_color);

        let blended = model.color_for(ListingDataSource::Blended);
        assert_eq!(blended[3], 0xff); // alpha always 0xff
    }

    #[test]
    fn test_blend_clamp() {
        let model = BlendedListingColorModel::new().with_blend_factor(2.0);
        assert!((model.blend_factor - 1.0).abs() < f32::EPSILON);

        let model = BlendedListingColorModel::new().with_blend_factor(-1.0);
        assert!((model.blend_factor).abs() < f32::EPSILON);
    }

    #[test]
    fn test_listing_config() {
        let config = DebuggerListingConfig::new();
        assert!(config.show_trace_data);
        assert!(config.follow_pc);
    }

    #[test]
    fn test_listing_config_serde() {
        let config = DebuggerListingConfig::new();
        let json = serde_json::to_string(&config).unwrap();
        let back: DebuggerListingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.show_trace_data, config.show_trace_data);
    }
}
