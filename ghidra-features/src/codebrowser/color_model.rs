//! Background color models for the listing display.
//!
//! Ports `ghidra.app.plugin.core.codebrowser.LayeredColorModel` and
//! `ghidra.app.plugin.core.codebrowser.MarkerServiceBackgroundColorModel`.
//!
//! The listing uses a composable color model system where different sources
//! (marker service, cursor line highlight, selection, etc.) can each contribute
//! background colors. The [`LayeredColorModel`] blends two models together.

use std::fmt;
use std::sync::{Arc, RwLock};

/// RGBA color representation.
///
/// Defined locally to avoid a cyclic dependency with `ghidra-gui`.
/// Matches the layout of `ghidra_gui::gui_util::web_colors::RgbaColor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RgbaColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl RgbaColor {
    /// Create a new opaque color.
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// Create a color with alpha.
    pub const fn with_alpha(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Blend two colors with the given weight (0.0 = all secondary, 1.0 = all primary).
    pub fn blend(primary: RgbaColor, secondary: RgbaColor, weight: f64) -> RgbaColor {
        let w = weight.clamp(0.0, 1.0);
        RgbaColor {
            r: (primary.r as f64 * w + secondary.r as f64 * (1.0 - w)) as u8,
            g: (primary.g as f64 * w + secondary.g as f64 * (1.0 - w)) as u8,
            b: (primary.b as f64 * w + secondary.b as f64 * (1.0 - w)) as u8,
            a: (primary.a as f64 * w + secondary.a as f64 * (1.0 - w)) as u8,
        }
    }
}

// ---------------------------------------------------------------------------
// ListingBackgroundColorModel trait
// ---------------------------------------------------------------------------

/// Trait for models that provide background colors for listing rows.
///
/// In Ghidra this was a Java interface `ListingBackgroundColorModel` that
/// `ListingPanel` queried for each visible line.
pub trait ListingBackgroundColorModel: Send + Sync + fmt::Debug {
    /// Get the background color for the row at the given index.
    fn get_background_color(&self, index: u64) -> RgbaColor;

    /// Get the default background color used when no special color applies.
    fn get_default_background_color(&self) -> RgbaColor;

    /// Set the default background color.
    fn set_default_background_color(&mut self, color: RgbaColor);

    /// Notification that the underlying listing data has changed.
    ///
    /// Implementors should update any cached program or index map references.
    fn model_data_changed(&mut self) {
        // Default: no-op.
    }
}

// ---------------------------------------------------------------------------
// SimpleBackgroundColorModel
// ---------------------------------------------------------------------------

/// A trivial color model that returns a fixed default color for all rows.
///
/// Useful as a baseline or primary model in a [`LayeredColorModel`].
#[derive(Debug, Clone)]
pub struct SimpleBackgroundColorModel {
    default_color: RgbaColor,
}

impl SimpleBackgroundColorModel {
    /// Create a new simple color model with the given default.
    pub fn new(default_color: RgbaColor) -> Self {
        Self { default_color }
    }
}

impl ListingBackgroundColorModel for SimpleBackgroundColorModel {
    fn get_background_color(&self, _index: u64) -> RgbaColor {
        self.default_color
    }

    fn get_default_background_color(&self) -> RgbaColor {
        self.default_color
    }

    fn set_default_background_color(&mut self, color: RgbaColor) {
        self.default_color = color;
    }
}

// ---------------------------------------------------------------------------
// MarkerServiceBackgroundColorModel
// ---------------------------------------------------------------------------

/// Background color model driven by a marker service.
///
/// Queries the marker service for each address and returns the marker's
/// background color if present, otherwise the default.
///
/// Ported from Ghidra's `MarkerServiceBackgroundColorModel`.
#[derive(Debug)]
pub struct MarkerServiceBackgroundColorModel {
    /// Per-address background colors provided by the marker service.
    ///
    /// In a full implementation this would be backed by the actual
    /// `MarkerService`; here we use a simple map.
    address_colors: Arc<RwLock<std::collections::HashMap<u64, RgbaColor>>>,
    default_color: RgbaColor,
}

impl MarkerServiceBackgroundColorModel {
    /// Theme key for the marker service default background.
    pub const THEME_KEY: &'static str = "color.bg.markerservice";

    /// Create a new marker service color model.
    ///
    /// The `address_colors` map provides per-address override colors;
    /// addresses not in the map will use the default.
    pub fn new(
        address_colors: Arc<RwLock<std::collections::HashMap<u64, RgbaColor>>>,
    ) -> Self {
        Self {
            address_colors,
            default_color: RgbaColor::new(0xFF, 0xFF, 0xFF),
        }
    }

    /// Set a marker color for a specific address.
    pub fn set_marker_color(&self, address: u64, color: RgbaColor) {
        if let Ok(mut map) = self.address_colors.write() {
            map.insert(address, color);
        }
    }

    /// Remove a marker color for a specific address.
    pub fn remove_marker_color(&self, address: u64) {
        if let Ok(mut map) = self.address_colors.write() {
            map.remove(&address);
        }
    }

    /// Clear all marker colors.
    pub fn clear_marker_colors(&self) {
        if let Ok(mut map) = self.address_colors.write() {
            map.clear();
        }
    }
}

impl ListingBackgroundColorModel for MarkerServiceBackgroundColorModel {
    fn get_background_color(&self, index: u64) -> RgbaColor {
        if let Ok(map) = self.address_colors.read() {
            if let Some(&color) = map.get(&index) {
                return color;
            }
        }
        self.default_color
    }

    fn get_default_background_color(&self) -> RgbaColor {
        self.default_color
    }

    fn set_default_background_color(&mut self, color: RgbaColor) {
        self.default_color = color;
    }

    fn model_data_changed(&mut self) {
        // In a full implementation, update program / index map references.
    }
}

// ---------------------------------------------------------------------------
// LayeredColorModel
// ---------------------------------------------------------------------------

/// A composite color model that blends two [`ListingBackgroundColorModel`]s.
///
/// - If only the primary has a non-default color, the primary's color is used.
/// - If only the secondary has a non-default color, the secondary's color is used.
/// - If both have non-default colors, the result is a blend (67% primary, 33% secondary).
/// - If neither has a non-default color, the primary's default is used.
///
/// Ported from Ghidra's `LayeredColorModel`.
pub struct LayeredColorModel {
    primary: Box<dyn ListingBackgroundColorModel>,
    secondary: Box<dyn ListingBackgroundColorModel>,
}

impl LayeredColorModel {
    /// Blend ratio for the primary model (matching Ghidra's 0.67).
    const PRIMARY_WEIGHT: f64 = 0.67;

    /// Create a new layered color model.
    pub fn new(
        primary: Box<dyn ListingBackgroundColorModel>,
        secondary: Box<dyn ListingBackgroundColorModel>,
    ) -> Self {
        Self { primary, secondary }
    }

    /// Create from two `Arc`-wrapped models.
    pub fn from_models(
        primary: Arc<RwLock<dyn ListingBackgroundColorModel>>,
        secondary: Arc<RwLock<dyn ListingBackgroundColorModel>>,
    ) -> Self {
        // Wrap Arc<RwLock<..>> into delegating boxes.
        let p = ArcModel(primary);
        let s = ArcModel(secondary);
        Self {
            primary: Box::new(p),
            secondary: Box::new(s),
        }
    }
}

impl ListingBackgroundColorModel for LayeredColorModel {
    fn get_background_color(&self, index: u64) -> RgbaColor {
        let primary_color = self.primary.get_background_color(index);
        let secondary_color = self.secondary.get_background_color(index);

        let primary_default = self.primary.get_default_background_color();
        let secondary_default = self.secondary.get_default_background_color();

        // If primary is at default, use secondary.
        if primary_color == primary_default {
            return secondary_color;
        }
        // If secondary is at default, use primary.
        if secondary_color == secondary_default {
            return primary_color;
        }
        // Both are non-default: blend.
        RgbaColor::blend(primary_color, secondary_color, Self::PRIMARY_WEIGHT)
    }

    fn get_default_background_color(&self) -> RgbaColor {
        self.primary.get_default_background_color()
    }

    fn set_default_background_color(&mut self, color: RgbaColor) {
        self.primary.set_default_background_color(color);
        self.secondary.set_default_background_color(color);
    }

    fn model_data_changed(&mut self) {
        self.primary.model_data_changed();
        self.secondary.model_data_changed();
    }
}

impl fmt::Debug for LayeredColorModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LayeredColorModel").finish()
    }
}

// ---------------------------------------------------------------------------
// ArcModel — wrapper so LayeredColorModel can own Arc<RwLock<..>> models
// ---------------------------------------------------------------------------

/// Internal wrapper that delegates `ListingBackgroundColorModel` through an
/// `Arc<RwLock<..>>`.
struct ArcModel(Arc<RwLock<dyn ListingBackgroundColorModel>>);

impl fmt::Debug for ArcModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArcModel").finish()
    }
}

impl ListingBackgroundColorModel for ArcModel {
    fn get_background_color(&self, index: u64) -> RgbaColor {
        self.0.read().map(|m| m.get_background_color(index)).unwrap_or(RgbaColor::new(0xFF, 0xFF, 0xFF))
    }

    fn get_default_background_color(&self) -> RgbaColor {
        self.0.read().map(|m| m.get_default_background_color()).unwrap_or(RgbaColor::new(0xFF, 0xFF, 0xFF))
    }

    fn set_default_background_color(&mut self, color: RgbaColor) {
        if let Ok(mut m) = self.0.write() {
            m.set_default_background_color(color);
        }
    }

    fn model_data_changed(&mut self) {
        if let Ok(mut m) = self.0.write() {
            m.model_data_changed();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_color_model() {
        let red = RgbaColor::new(255, 0, 0);
        let model = SimpleBackgroundColorModel::new(red);
        assert_eq!(model.get_background_color(0), red);
        assert_eq!(model.get_background_color(999), red);
        assert_eq!(model.get_default_background_color(), red);
    }

    #[test]
    fn test_marker_service_model_default() {
        let colors = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let model = MarkerServiceBackgroundColorModel::new(colors);
        let default = model.get_default_background_color();
        // An address with no marker should return the default.
        assert_eq!(model.get_background_color(0x1000), default);
    }

    #[test]
    fn test_marker_service_model_with_markers() {
        let colors = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let model = MarkerServiceBackgroundColorModel::new(Arc::clone(&colors));

        let red = RgbaColor::new(255, 0, 0);
        model.set_marker_color(0x1000, red);

        assert_eq!(model.get_background_color(0x1000), red);
        // Address with no marker returns default.
        assert_eq!(model.get_background_color(0x2000), model.get_default_background_color());
    }

    #[test]
    fn test_marker_service_model_remove_and_clear() {
        let colors = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let model = MarkerServiceBackgroundColorModel::new(Arc::clone(&colors));

        model.set_marker_color(0x1000, RgbaColor::new(255, 0, 0));
        model.set_marker_color(0x2000, RgbaColor::new(0, 255, 0));
        model.remove_marker_color(0x1000);
        assert_eq!(
            model.get_background_color(0x1000),
            model.get_default_background_color()
        );

        model.clear_marker_colors();
        assert_eq!(
            model.get_background_color(0x2000),
            model.get_default_background_color()
        );
    }

    #[test]
    fn test_layered_color_model_neither_active() {
        let white = RgbaColor::new(255, 255, 255);
        let primary = SimpleBackgroundColorModel::new(white);
        let secondary = SimpleBackgroundColorModel::new(white);
        let layered = LayeredColorModel::new(Box::new(primary), Box::new(secondary));

        // When neither model has a non-default color, the primary's default is used.
        assert_eq!(layered.get_background_color(0), white);
    }

    #[test]
    fn test_layered_color_model_primary_only() {
        let white = RgbaColor::new(255, 255, 255);
        let blue = RgbaColor::new(0, 0, 255);

        let colors = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let primary = MarkerServiceBackgroundColorModel::new(Arc::clone(&colors));
        primary.set_marker_color(0x1000, blue);

        let secondary = SimpleBackgroundColorModel::new(white);
        let layered = LayeredColorModel::new(Box::new(primary), Box::new(secondary));

        // Only primary has a non-default color at 0x1000.
        assert_eq!(layered.get_background_color(0x1000), blue);
    }

    #[test]
    fn test_layered_color_model_both_active() {
        let red = RgbaColor::new(255, 0, 0);
        let blue = RgbaColor::new(0, 0, 255);

        let colors_p = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let primary = MarkerServiceBackgroundColorModel::new(Arc::clone(&colors_p));
        primary.set_marker_color(0x1000, red);

        let colors_s = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let secondary = MarkerServiceBackgroundColorModel::new(Arc::clone(&colors_s));
        secondary.set_marker_color(0x1000, blue);

        let layered = LayeredColorModel::new(Box::new(primary), Box::new(secondary));

        // Both active: blended at 67% primary.
        let result = layered.get_background_color(0x1000);
        let expected = RgbaColor::blend(red, blue, 0.67);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_layered_set_default_propagates() {
        let white = RgbaColor::new(255, 255, 255);
        let gray = RgbaColor::new(128, 128, 128);

        let primary = SimpleBackgroundColorModel::new(white);
        let secondary = SimpleBackgroundColorModel::new(white);
        let mut layered = LayeredColorModel::new(Box::new(primary), Box::new(secondary));

        layered.set_default_background_color(gray);
        assert_eq!(layered.get_default_background_color(), gray);
        // Both models should now have gray as default.
        assert_eq!(layered.get_background_color(0), gray);
    }
}
