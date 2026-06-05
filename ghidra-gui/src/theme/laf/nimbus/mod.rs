//! Nimbus Look-and-Feel support.
//!
//! Ports Ghidra's `generic.theme.laf.nimbus` package. Provides the
//! [`SelectedTreePainter`] which renders selected-tree-row backgrounds
//! in the Nimbus L&F, together with [`NimbusLafManager`] which manages
//! the Nimbus-specific UIDefaults and color registrations.
//!
//! In the Rust/egui port these types model theme properties and paint
//! configuration rather than driving Swing directly.

use std::collections::HashMap;

// ============================================================================
// PaintContext (modelled after Swing Nimbus PaintContext)
// ============================================================================

/// Cache mode for a Nimbus region painter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheMode {
    /// No caching -- always repaint.
    NoCaching,
    /// Fixed-size 9-way image cache.
    FixedNine,
    /// Fixed-size center cache.
    FixedCenter,
}

/// Insets used by the Nimbus paint context.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PaintInsets {
    pub top: f32,
    pub left: f32,
    pub bottom: f32,
    pub right: f32,
}

impl PaintInsets {
    pub const fn new(top: f32, left: f32, bottom: f32, right: f32) -> Self {
        Self { top, left, bottom, right }
    }
}

/// Paint context for a Nimbus region painter.
#[derive(Debug, Clone)]
pub struct PaintContext {
    /// Insets around the painted region.
    pub insets: PaintInsets,
    /// Canvas size for the painting operations.
    pub canvas_size: (f32, f32),
    /// Whether painting is done in a horizontal orientation.
    pub horizontal: bool,
    /// The caching strategy.
    pub cache_mode: CacheMode,
    /// Horizontal decoding scale factor.
    pub decode_scale_x: f32,
    /// Vertical decoding scale factor.
    pub decode_scale_y: f32,
}

impl Default for PaintContext {
    fn default() -> Self {
        Self {
            insets: PaintInsets::new(5.0, 5.0, 5.0, 5.0),
            canvas_size: (100.0, 30.0),
            horizontal: false,
            cache_mode: CacheMode::NoCaching,
            decode_scale_x: 1.0,
            decode_scale_y: 1.0,
        }
    }
}

impl PaintContext {
    /// Decode an X value using the canvas width and scale factor.
    pub fn decode_x(&self, encoded: f32) -> f32 {
        (encoded / 3.0) * self.canvas_size.0 * self.decode_scale_x
    }

    /// Decode a Y value using the canvas height and scale factor.
    pub fn decode_y(&self, encoded: f32) -> f32 {
        (encoded / 3.0) * self.canvas_size.1 * self.decode_scale_y
    }
}

// ============================================================================
// SelectedTreePainter
// ============================================================================

/// Nimbus selected-tree-row painter.
///
/// Fills the background of a selected tree row using the theme color
/// `"color.bg.tree.selected"`.  In the Java source this extends
/// `javax.swing.plaf.nimbus.AbstractRegionPainter`; here we model the
/// state as data and provide a `paint()` method that returns draw
/// instructions for an egui-based renderer.
///
/// # Ported from
/// `generic.theme.laf.nimbus.SelectedTreePainter`
#[derive(Debug, Clone)]
pub struct SelectedTreePainter {
    /// The paint context (insets, canvas size, cache mode).
    pub paint_context: PaintContext,
    /// The theme color key used for the selection fill.
    pub color_key: String,
    /// The resolved color (lazily loaded from the theme system).
    resolved_color: Option<[u8; 4]>,
    /// The rectangle to fill: (x, y, width, height).
    pub rect: (f32, f32, f32, f32),
}

impl Default for SelectedTreePainter {
    fn default() -> Self {
        Self::new()
    }
}

impl SelectedTreePainter {
    /// Create a new SelectedTreePainter with default settings.
    pub fn new() -> Self {
        Self {
            paint_context: PaintContext {
                insets: PaintInsets::new(5.0, 5.0, 5.0, 5.0),
                canvas_size: (100.0, 30.0),
                ..Default::default()
            },
            color_key: "color.bg.tree.selected".to_string(),
            resolved_color: None,
            rect: (0.0, 0.0, 0.0, 0.0),
        }
    }

    /// Resolve the selection color from a color map.
    ///
    /// Mimics the Java implementation's `lazyLoadColor()` -- the color is
    /// resolved the first time `paint` is called (after the theme system
    /// has bootstrapped).
    pub fn resolve_color(&mut self, color_map: &HashMap<String, [u8; 4]>) {
        if self.resolved_color.is_none() {
            self.resolved_color = color_map.get(&self.color_key).copied();
        }
    }

    /// Return the resolved selection color, if any.
    pub fn selection_color(&self) -> Option<[u8; 4]> {
        self.resolved_color
    }

    /// Compute the paint rectangle from the canvas size.
    ///
    /// The rectangle covers the full canvas (0,0) to (width, height)
    /// decoded from the 3-unit coordinate system.
    pub fn update_shape(&mut self) {
        let w = self.paint_context.decode_x(3.0);
        let h = self.paint_context.decode_y(3.0);
        self.rect = (0.0, 0.0, w, h);
    }

    /// Generate a fill instruction.
    ///
    /// Returns `Some((rect, color))` if the painter is ready (color
    /// resolved and canvas non-zero), or `None` otherwise.
    pub fn paint(&mut self, color_map: &HashMap<String, [u8; 4]>) -> Option<((f32, f32, f32, f32), [u8; 4])> {
        self.resolve_color(color_map);
        self.update_shape();
        let color = self.resolved_color?;
        if self.rect.2 > 0.0 && self.rect.3 > 0.0 {
            Some((self.rect, color))
        } else {
            None
        }
    }
}

// ============================================================================
// NimbusLafManager
// ============================================================================

/// Manager for the Nimbus Look-and-Feel.
///
/// Registers Nimbus-specific UIDefaults mappings, color assignments, and
/// component font overrides.  In Ghidra this is
/// `NimbusLookAndFeelManager`; here we model the data and provide
/// lookups.
///
/// # Ported from
/// `generic.theme.laf.concrete_managers` (Nimbus section)
#[derive(Debug, Clone, Default)]
pub struct NimbusLafManager {
    /// UIDefaults key/value pairs specific to Nimbus.
    pub ui_defaults: HashMap<String, String>,
    /// Color assignments for Nimbus theme IDs.
    pub color_defaults: HashMap<String, String>,
    /// Font overrides for specific component types.
    pub font_overrides: HashMap<String, String>,
}

impl NimbusLafManager {
    /// Create a new Nimbus L&F manager with Ghidra's default mappings.
    pub fn new() -> Self {
        let mut manager = Self::default();
        manager.register_defaults();
        manager
    }

    /// Register Ghidra's default Nimbus UIDefaults and colors.
    fn register_defaults(&mut self) {
        // Tree
        self.ui_defaults.insert(
            "Tree.selectionBackground".into(),
            "color.bg.tree.selected".into(),
        );
        self.ui_defaults.insert(
            "Tree.selectionForeground".into(),
            "color.fg.tree.selected".into(),
        );
        self.ui_defaults.insert(
            "Tree.background".into(),
            "color.bg.tree".into(),
        );

        // Table
        self.ui_defaults.insert(
            "Table.selectionBackground".into(),
            "color.bg.table.selected".into(),
        );
        self.ui_defaults.insert(
            "Table.selectionForeground".into(),
            "color.fg.table.selected".into(),
        );

        // List
        self.ui_defaults.insert(
            "List.selectionBackground".into(),
            "color.bg.list.selected".into(),
        );

        // Menu / MenuItem
        self.ui_defaults.insert(
            "MenuItem.selectionBackground".into(),
            "color.bg.menu.selected".into(),
        );

        // Scrollbar
        self.ui_defaults.insert(
            "ScrollBar.thumb".into(),
            "color.bg.scrollbar".into(),
        );
    }

    /// Look up a UIDefaults value by key.
    pub fn get_ui_default(&self, key: &str) -> Option<&str> {
        self.ui_defaults.get(key).map(|s| s.as_str())
    }

    /// Look up a color default by theme ID.
    pub fn get_color_default(&self, theme_id: &str) -> Option<&str> {
        self.color_defaults.get(theme_id).map(|s| s.as_str())
    }

    /// Insert a UIDefaults key/value pair.
    pub fn set_ui_default(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.ui_defaults.insert(key.into(), value.into());
    }

    /// Insert a color default.
    pub fn set_color_default(&mut self, theme_id: impl Into<String>, value: impl Into<String>) {
        self.color_defaults.insert(theme_id.into(), value.into());
    }

    /// Insert a font override.
    pub fn set_font_override(&mut self, component: impl Into<String>, font: impl Into<String>) {
        self.font_overrides.insert(component.into(), font.into());
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_color_map() -> HashMap<String, [u8; 4]> {
        let mut m = HashMap::new();
        m.insert("color.bg.tree.selected".to_string(), [0x33, 0x99, 0xff, 0xff]);
        m
    }

    #[test]
    fn selected_tree_painter_new() {
        let painter = SelectedTreePainter::new();
        assert_eq!(painter.color_key, "color.bg.tree.selected");
        assert!(painter.resolved_color.is_none());
    }

    #[test]
    fn selected_tree_painter_resolve_color() {
        let mut painter = SelectedTreePainter::new();
        let colors = sample_color_map();
        painter.resolve_color(&colors);
        assert_eq!(painter.selection_color(), Some([0x33, 0x99, 0xff, 0xff]));
    }

    #[test]
    fn selected_tree_painter_resolve_missing_key() {
        let mut painter = SelectedTreePainter::new();
        let colors = HashMap::new();
        painter.resolve_color(&colors);
        assert!(painter.selection_color().is_none());
    }

    #[test]
    fn selected_tree_painter_lazy_resolve() {
        let mut painter = SelectedTreePainter::new();
        // First call resolves the color.
        let colors = sample_color_map();
        painter.resolve_color(&colors);
        assert!(painter.selection_color().is_some());
        // Second call with empty map should not clobber the cached color.
        painter.resolve_color(&HashMap::new());
        assert!(painter.selection_color().is_some());
    }

    #[test]
    fn selected_tree_painter_update_shape() {
        let mut painter = SelectedTreePainter::new();
        painter.update_shape();
        assert!(painter.rect.2 > 0.0);
        assert!(painter.rect.3 > 0.0);
    }

    #[test]
    fn selected_tree_painter_paint() {
        let mut painter = SelectedTreePainter::new();
        let colors = sample_color_map();
        let result = painter.paint(&colors);
        assert!(result.is_some());
        let (rect, color) = result.unwrap();
        assert_eq!(color, [0x33, 0x99, 0xff, 0xff]);
        assert!(rect.2 > 0.0);
    }

    #[test]
    fn selected_tree_painter_paint_no_color() {
        let mut painter = SelectedTreePainter::new();
        let result = painter.paint(&HashMap::new());
        assert!(result.is_none());
    }

    #[test]
    fn paint_context_decode() {
        let ctx = PaintContext::default();
        let x = ctx.decode_x(3.0);
        let y = ctx.decode_y(3.0);
        assert_eq!(x, 100.0);
        assert_eq!(y, 30.0);
    }

    #[test]
    fn paint_context_decode_zero() {
        let ctx = PaintContext::default();
        assert_eq!(ctx.decode_x(0.0), 0.0);
        assert_eq!(ctx.decode_y(0.0), 0.0);
    }

    #[test]
    fn paint_context_custom_canvas() {
        let ctx = PaintContext {
            canvas_size: (200.0, 60.0),
            ..Default::default()
        };
        assert_eq!(ctx.decode_x(3.0), 200.0);
        assert_eq!(ctx.decode_y(3.0), 60.0);
    }

    #[test]
    fn nimbus_laf_manager_defaults() {
        let manager = NimbusLafManager::new();
        assert!(manager.get_ui_default("Tree.selectionBackground").is_some());
        assert!(manager.get_ui_default("Table.selectionBackground").is_some());
        assert!(manager.get_ui_default("Nonexistent").is_none());
    }

    #[test]
    fn nimbus_laf_manager_set_and_get() {
        let mut manager = NimbusLafManager::new();
        manager.set_ui_default("Custom.key", "Custom.value");
        assert_eq!(manager.get_ui_default("Custom.key"), Some("Custom.value"));

        manager.set_color_default("my.theme.id", "#ff0000");
        assert_eq!(manager.get_color_default("my.theme.id"), Some("#ff0000"));

        manager.set_font_override("JTree", "Monospaced-12");
    }

    #[test]
    fn paint_context_default() {
        let ctx = PaintContext::default();
        assert_eq!(ctx.cache_mode, CacheMode::NoCaching);
        assert_eq!(ctx.decode_scale_x, 1.0);
        assert_eq!(ctx.decode_scale_y, 1.0);
        assert!(!ctx.horizontal);
    }

    #[test]
    fn paint_insets() {
        let insets = PaintInsets::new(1.0, 2.0, 3.0, 4.0);
        assert_eq!(insets.top, 1.0);
        assert_eq!(insets.left, 2.0);
        assert_eq!(insets.bottom, 3.0);
        assert_eq!(insets.right, 4.0);
    }

    #[test]
    fn selected_tree_painter_clone() {
        let painter = SelectedTreePainter::new();
        let cloned = painter.clone();
        assert_eq!(cloned.color_key, painter.color_key);
    }

    #[test]
    fn nimbus_laf_manager_clone() {
        let manager = NimbusLafManager::new();
        let cloned = manager.clone();
        assert_eq!(
            cloned.get_ui_default("Tree.selectionBackground"),
            manager.get_ui_default("Tree.selectionBackground")
        );
    }
}
