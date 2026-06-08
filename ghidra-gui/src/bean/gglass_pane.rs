//! Glass pane overlay for the Ghidra GUI.
//!
//! Ports `ghidra.util.bean.GGlassPane` from Ghidra's Java source.
//!
//! The glass pane is a transparent overlay drawn on top of the main application
//! window. It is used for rendering transient visual effects such as
//! drag-and-drop feedback, progress indicators, and annotation overlays.

use std::collections::HashMap;

/// Identifier for a glass pane painter.
pub type PainterId = u64;

/// A glass pane overlay that paints on top of the application.
///
/// Ports `ghidra.util.bean.GGlassPane`. This is the primary overlay surface
/// used by the docking framework for visual feedback. Multiple painters can
/// be registered and are composited in order.
#[derive(Debug)]
pub struct GGlassPane {
    /// Registered painters, keyed by id.
    painters: HashMap<PainterId, GlassPanePainterEntry>,
    /// Next painter id.
    next_id: PainterId,
    /// Whether the glass pane is visible.
    visible: bool,
    /// Whether mouse events should pass through to underlying components.
    pass_through: bool,
    /// Pending paint requests (dirty regions).
    dirty_regions: Vec<DirtyRegion>,
}

/// An entry for a registered glass pane painter.
#[derive(Debug, Clone)]
struct GlassPanePainterEntry {
    /// The painter id.
    id: PainterId,
    /// Description of the painter (for debugging).
    description: String,
    /// Layer order (higher = drawn later, on top).
    z_order: i32,
    /// Whether this painter is currently active.
    active: bool,
}

/// A dirty region that needs repainting.
#[derive(Debug, Clone, Copy)]
pub struct DirtyRegion {
    /// X coordinate of the dirty region.
    pub x: f64,
    /// Y coordinate of the dirty region.
    pub y: f64,
    /// Width of the dirty region.
    pub width: f64,
    /// Height of the dirty region.
    pub height: f64,
}

impl GGlassPane {
    /// Create a new glass pane.
    pub fn new() -> Self {
        Self {
            painters: HashMap::new(),
            next_id: 1,
            visible: false,
            pass_through: true,
            dirty_regions: Vec::new(),
        }
    }

    /// Register a painter with the given description and z-order.
    ///
    /// Returns a unique id that can be used to remove or modify the painter.
    pub fn add_painter(&mut self, description: impl Into<String>, z_order: i32) -> PainterId {
        let id = self.next_id;
        self.next_id += 1;
        self.painters.insert(
            id,
            GlassPanePainterEntry {
                id,
                description: description.into(),
                z_order,
                active: true,
            },
        );
        id
    }

    /// Remove a painter by id.
    pub fn remove_painter(&mut self, id: PainterId) -> bool {
        self.painters.remove(&id).is_some()
    }

    /// Set whether a painter is active.
    pub fn set_painter_active(&mut self, id: PainterId, active: bool) {
        if let Some(painter) = self.painters.get_mut(&id) {
            painter.active = active;
        }
    }

    /// Get the number of registered painters.
    pub fn painter_count(&self) -> usize {
        self.painters.len()
    }

    /// Whether the glass pane is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set the glass pane visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
        if visible {
            self.mark_dirty_full();
        }
    }

    /// Whether mouse events pass through to underlying components.
    pub fn is_pass_through(&self) -> bool {
        self.pass_through
    }

    /// Set whether mouse events pass through.
    pub fn set_pass_through(&mut self, pass_through: bool) {
        self.pass_through = pass_through;
    }

    /// Mark a region as dirty (needing repaint).
    pub fn mark_dirty(&mut self, region: DirtyRegion) {
        self.dirty_regions.push(region);
    }

    /// Mark the entire pane as dirty.
    pub fn mark_dirty_full(&mut self) {
        self.dirty_regions.push(DirtyRegion {
            x: 0.0,
            y: 0.0,
            width: f64::MAX,
            height: f64::MAX,
        });
    }

    /// Drain the dirty regions (consuming them).
    pub fn drain_dirty_regions(&mut self) -> Vec<DirtyRegion> {
        std::mem::take(&mut self.dirty_regions)
    }

    /// Whether there are pending dirty regions.
    pub fn is_dirty(&self) -> bool {
        !self.dirty_regions.is_empty()
    }

    /// Get the active painters sorted by z-order.
    pub fn active_painters(&self) -> Vec<PainterId> {
        let mut entries: Vec<_> = self
            .painters
            .values()
            .filter(|p| p.active)
            .collect();
        entries.sort_by_key(|p| p.z_order);
        entries.iter().map(|p| p.id).collect()
    }

    /// Get the description of a painter.
    pub fn painter_description(&self, id: PainterId) -> Option<&str> {
        self.painters.get(&id).map(|p| p.description.as_str())
    }
}

impl Default for GGlassPane {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glass_pane_new() {
        let gp = GGlassPane::new();
        assert!(!gp.is_visible());
        assert!(gp.is_pass_through());
        assert_eq!(gp.painter_count(), 0);
    }

    #[test]
    fn glass_pane_add_remove_painter() {
        let mut gp = GGlassPane::new();
        let id1 = gp.add_painter("drag feedback", 10);
        let _id2 = gp.add_painter("progress overlay", 20);
        assert_eq!(gp.painter_count(), 2);

        assert!(gp.remove_painter(id1));
        assert_eq!(gp.painter_count(), 1);
        assert!(!gp.remove_painter(id1)); // already removed
    }

    #[test]
    fn glass_pane_painter_active() {
        let mut gp = GGlassPane::new();
        let id = gp.add_painter("test", 5);
        gp.set_painter_active(id, false);
        assert!(gp.active_painters().is_empty());

        gp.set_painter_active(id, true);
        assert_eq!(gp.active_painters().len(), 1);
    }

    #[test]
    fn glass_pane_active_painters_sorted() {
        let mut gp = GGlassPane::new();
        let id1 = gp.add_painter("low", 1);
        let id2 = gp.add_painter("high", 10);
        let id3 = gp.add_painter("mid", 5);

        let active = gp.active_painters();
        assert_eq!(active, vec![id1, id3, id2]);
    }

    #[test]
    fn glass_pane_visibility() {
        let mut gp = GGlassPane::new();
        gp.set_visible(true);
        assert!(gp.is_visible());
        assert!(gp.is_dirty()); // marking dirty when made visible
    }

    #[test]
    fn glass_pane_dirty_regions() {
        let mut gp = GGlassPane::new();
        assert!(!gp.is_dirty());

        gp.mark_dirty(DirtyRegion {
            x: 10.0,
            y: 20.0,
            width: 100.0,
            height: 50.0,
        });
        assert!(gp.is_dirty());

        let regions = gp.drain_dirty_regions();
        assert_eq!(regions.len(), 1);
        assert!(!gp.is_dirty());
    }

    #[test]
    fn glass_pane_mark_dirty_full() {
        let mut gp = GGlassPane::new();
        gp.mark_dirty_full();
        assert!(gp.is_dirty());
        let regions = gp.drain_dirty_regions();
        assert_eq!(regions.len(), 1);
    }

    #[test]
    fn glass_pane_pass_through() {
        let mut gp = GGlassPane::new();
        assert!(gp.is_pass_through());
        gp.set_pass_through(false);
        assert!(!gp.is_pass_through());
    }

    #[test]
    fn glass_pane_painter_description() {
        let mut gp = GGlassPane::new();
        let id = gp.add_painter("drag feedback", 10);
        assert_eq!(gp.painter_description(id), Some("drag feedback"));
        assert_eq!(gp.painter_description(999), None);
    }
}
