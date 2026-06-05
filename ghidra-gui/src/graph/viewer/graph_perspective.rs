//! Graph perspective save/restore.
//!
//! Ports Ghidra's `ghidra.graph.viewer.GraphPerspectiveInfo` and
//! `ghidra.graph.viewer.ViewRestoreOption`.
//!
//! A perspective captures the view state of a graph viewer: center position,
//! zoom level, which vertices are selected, and which are filtered.  This
//! allows the user to return to a previously saved view configuration.

use std::collections::HashSet;

use super::Point2D;

// ============================================================================
// ViewRestoreOption
// ============================================================================

/// How the graph view should be restored.
///
/// Port of `ghidra.graph.viewer.ViewRestoreOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ViewRestoreOption {
    /// Restore the full perspective (zoom, center, selection).
    Full,
    /// Restore only the zoom level.
    ZoomOnly,
    /// Restore only the center position.
    CenterOnly,
    /// Do not restore; use the default layout.
    None,
}

impl Default for ViewRestoreOption {
    fn default() -> Self {
        Self::Full
    }
}

// ============================================================================
// GraphPerspectiveInfo
// ============================================================================

/// Captures the view state of a graph viewer at a point in time.
///
/// Port of `ghidra.graph.viewer.GraphPerspectiveInfo`.
///
/// The perspective stores enough information to restore the viewer to
/// approximately the same visual configuration when the user navigates
/// back to a function.
#[derive(Debug, Clone)]
pub struct GraphPerspectiveInfo {
    /// Center of the viewport in layout coordinates.
    pub center: Point2D,
    /// Zoom scale factor (1.0 = 100%).
    pub scale: f64,
    /// IDs of the currently selected vertices.
    pub selected_vertices: HashSet<String>,
    /// IDs of the currently filtered (hidden) vertices.
    pub filtered_vertices: HashSet<String>,
    /// Which restore mode to use.
    pub restore_option: ViewRestoreOption,
}

impl GraphPerspectiveInfo {
    /// Create a new perspective at the given center and scale.
    pub fn new(center: Point2D, scale: f64) -> Self {
        Self {
            center,
            scale,
            selected_vertices: HashSet::new(),
            filtered_vertices: HashSet::new(),
            restore_option: ViewRestoreOption::Full,
        }
    }

    /// Create an empty perspective (default view).
    pub fn empty() -> Self {
        Self {
            center: Point2D::ZERO,
            scale: 1.0,
            selected_vertices: HashSet::new(),
            filtered_vertices: HashSet::new(),
            restore_option: ViewRestoreOption::None,
        }
    }

    /// Whether this perspective has any state to restore.
    pub fn has_state(&self) -> bool {
        !self.selected_vertices.is_empty()
            || !self.filtered_vertices.is_empty()
            || self.center != Point2D::ZERO
            || (self.scale - 1.0).abs() > f64::EPSILON
    }

    /// Add a vertex to the selected set.
    pub fn select_vertex(&mut self, vertex_id: impl Into<String>) {
        self.selected_vertices.insert(vertex_id.into());
    }

    /// Remove a vertex from the selected set.
    pub fn deselect_vertex(&mut self, vertex_id: &str) {
        self.selected_vertices.remove(vertex_id);
    }

    /// Add a vertex to the filtered (hidden) set.
    pub fn filter_vertex(&mut self, vertex_id: impl Into<String>) {
        self.filtered_vertices.insert(vertex_id.into());
    }

    /// Remove a vertex from the filtered set.
    pub fn unfilter_vertex(&mut self, vertex_id: &str) {
        self.filtered_vertices.remove(vertex_id);
    }

    /// Whether a vertex is selected in this perspective.
    pub fn is_vertex_selected(&self, vertex_id: &str) -> bool {
        self.selected_vertices.contains(vertex_id)
    }

    /// Whether a vertex is filtered (hidden) in this perspective.
    pub fn is_vertex_filtered(&self, vertex_id: &str) -> bool {
        self.filtered_vertices.contains(vertex_id)
    }

    /// Merge another perspective into this one.
    ///
    /// The scale and center are taken from `other`; selected and
    /// filtered vertices are unioned.
    pub fn merge(&mut self, other: &GraphPerspectiveInfo) {
        self.center = other.center;
        self.scale = other.scale;
        self.selected_vertices
            .extend(other.selected_vertices.iter().cloned());
        self.filtered_vertices
            .extend(other.filtered_vertices.iter().cloned());
    }
}

impl Default for GraphPerspectiveInfo {
    fn default() -> Self {
        Self::empty()
    }
}

// ============================================================================
// RelayoutOption
// ============================================================================

/// How the graph should be re-laid-out.
///
/// Port of `ghidra.graph.job.RelayoutOption`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelayoutOption {
    /// Perform a full layout from scratch.
    Full,
    /// Preserve existing vertex positions where possible.
    PreservePositions,
    /// Only reposition vertices that overlap.
    FixOverlaps,
}

impl Default for RelayoutOption {
    fn default() -> Self {
        Self::Full
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perspective_new() {
        let p = GraphPerspectiveInfo::new(Point2D::new(100.0, 200.0), 1.5);
        assert!((p.center.x - 100.0).abs() < f64::EPSILON);
        assert!((p.scale - 1.5).abs() < f64::EPSILON);
        assert!(p.selected_vertices.is_empty());
    }

    #[test]
    fn perspective_empty_has_no_state() {
        let p = GraphPerspectiveInfo::empty();
        assert!(!p.has_state());
    }

    #[test]
    fn perspective_has_state_with_selection() {
        let mut p = GraphPerspectiveInfo::empty();
        p.select_vertex("v1");
        assert!(p.has_state());
    }

    #[test]
    fn perspective_has_state_with_non_default_center() {
        let p = GraphPerspectiveInfo::new(Point2D::new(50.0, 50.0), 1.0);
        assert!(p.has_state());
    }

    #[test]
    fn perspective_select_deselect() {
        let mut p = GraphPerspectiveInfo::empty();
        p.select_vertex("v1");
        p.select_vertex("v2");
        assert!(p.is_vertex_selected("v1"));
        assert!(p.is_vertex_selected("v2"));
        p.deselect_vertex("v1");
        assert!(!p.is_vertex_selected("v1"));
        assert!(p.is_vertex_selected("v2"));
    }

    #[test]
    fn perspective_filter_unfilter() {
        let mut p = GraphPerspectiveInfo::empty();
        p.filter_vertex("v1");
        assert!(p.is_vertex_filtered("v1"));
        p.unfilter_vertex("v1");
        assert!(!p.is_vertex_filtered("v1"));
    }

    #[test]
    fn perspective_merge() {
        let mut p1 = GraphPerspectiveInfo::new(Point2D::new(10.0, 10.0), 1.0);
        p1.select_vertex("v1");

        let mut p2 = GraphPerspectiveInfo::new(Point2D::new(50.0, 50.0), 2.0);
        p2.select_vertex("v2");
        p2.filter_vertex("v3");

        p1.merge(&p2);

        assert!((p1.center.x - 50.0).abs() < f64::EPSILON);
        assert!((p1.scale - 2.0).abs() < f64::EPSILON);
        assert!(p1.is_vertex_selected("v1"));
        assert!(p1.is_vertex_selected("v2"));
        assert!(p1.is_vertex_filtered("v3"));
    }

    #[test]
    fn view_restore_option_default() {
        let opt = ViewRestoreOption::default();
        assert_eq!(opt, ViewRestoreOption::Full);
    }

    #[test]
    fn relayout_option_default() {
        assert_eq!(RelayoutOption::default(), RelayoutOption::Full);
    }
}
