//! Graph viewer utility functions.
//!
//! Port of Ghidra's `ghidra.graph.viewer.GraphViewerUtils`.

use super::job::Rect2D;

/// Utility functions for graph viewers.
///
/// Port of `ghidra.graph.viewer.GraphViewerUtils`.
pub struct GraphViewerUtils;

impl GraphViewerUtils {
    /// Calculate the bounding box that contains all given points.
    pub fn bounding_box(points: &[(f64, f64)]) -> Option<Rect2D> {
        if points.is_empty() {
            return None;
        }
        let mut min_x = f64::MAX;
        let mut min_y = f64::MAX;
        let mut max_x = f64::MIN;
        let mut max_y = f64::MIN;
        for &(x, y) in points {
            min_x = min_x.min(x);
            min_y = min_y.min(y);
            max_x = max_x.max(x);
            max_y = max_y.max(y);
        }
        Some(Rect2D::new(min_x, min_y, max_x - min_x, max_y - min_y))
    }

    /// Scale a rectangle by the given factor.
    pub fn scale_rect(rect: &Rect2D, scale: f64) -> Rect2D {
        Rect2D::new(
            rect.x * scale,
            rect.y * scale,
            rect.width * scale,
            rect.height * scale,
        )
    }

    /// Translate a rectangle by the given offset.
    pub fn translate_rect(rect: &Rect2D, dx: f64, dy: f64) -> Rect2D {
        Rect2D::new(rect.x + dx, rect.y + dy, rect.width, rect.height)
    }

    /// Clamp a value between min and max.
    pub fn clamp(value: f64, min: f64, max: f64) -> f64 {
        value.max(min).min(max)
    }

    /// Calculate the distance between two points.
    pub fn distance(x1: f64, y1: f64, x2: f64, y2: f64) -> f64 {
        ((x2 - x1).powi(2) + (y2 - y1).powi(2)).sqrt()
    }

    /// Determine if a point is inside a padded rectangle.
    pub fn is_in_padded_rect(px: f64, py: f64, rect: &Rect2D, padding: f64) -> bool {
        px >= rect.x - padding
            && px <= rect.right() + padding
            && py >= rect.y - padding
            && py <= rect.bottom() + padding
    }
}

/// A perspective transform for graph view operations.
///
/// Port of `ghidra.graph.viewer.GraphPerspectiveInfo`.
#[derive(Debug, Clone)]
pub struct GraphPerspectiveInfo {
    /// The scale factor.
    pub scale: f64,
    /// The translation offset x.
    pub translate_x: f64,
    /// The translation offset y.
    pub translate_y: f64,
}

impl GraphPerspectiveInfo {
    /// Create a default identity perspective.
    pub fn identity() -> Self {
        Self { scale: 1.0, translate_x: 0.0, translate_y: 0.0 }
    }

    /// Apply the transform to a point.
    pub fn transform(&self, x: f64, y: f64) -> (f64, f64) {
        (x * self.scale + self.translate_x, y * self.scale + self.translate_y)
    }

    /// Inverse-transform a point.
    pub fn inverse_transform(&self, x: f64, y: f64) -> (f64, f64) {
        if self.scale == 0.0 {
            return (0.0, 0.0);
        }
        (
            (x - self.translate_x) / self.scale,
            (y - self.translate_y) / self.scale,
        )
    }
}

impl Default for GraphPerspectiveInfo {
    fn default() -> Self {
        Self::identity()
    }
}

/// Listener trait for satellite graph changes.
///
/// Port of `ghidra.graph.viewer.GraphSatelliteListener`.
pub trait GraphSatelliteListener: std::fmt::Debug {
    /// Called when the satellite viewport changes.
    fn viewport_changed(&self, x: f64, y: f64, width: f64, height: f64);

    /// Called when the satellite is shown/hidden.
    fn visibility_changed(&self, visible: bool);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounding_box() {
        let points = vec![(1.0, 2.0), (3.0, 4.0), (5.0, 6.0)];
        let bb = GraphViewerUtils::bounding_box(&points).unwrap();
        assert!((bb.x - 1.0).abs() < f64::EPSILON);
        assert!((bb.y - 2.0).abs() < f64::EPSILON);
        assert!((bb.width - 4.0).abs() < f64::EPSILON);
        assert!((bb.height - 4.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_bounding_box_empty() {
        assert!(GraphViewerUtils::bounding_box(&[]).is_none());
    }

    #[test]
    fn test_distance() {
        let d = GraphViewerUtils::distance(0.0, 0.0, 3.0, 4.0);
        assert!((d - 5.0).abs() < 1e-10);
    }

    #[test]
    fn test_perspective_identity() {
        let p = GraphPerspectiveInfo::identity();
        let (x, y) = p.transform(10.0, 20.0);
        assert!((x - 10.0).abs() < f64::EPSILON);
        assert!((y - 20.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_perspective_transform() {
        let p = GraphPerspectiveInfo { scale: 2.0, translate_x: 5.0, translate_y: 10.0 };
        let (x, y) = p.transform(3.0, 4.0);
        assert!((x - 11.0).abs() < f64::EPSILON);
        assert!((y - 18.0).abs() < f64::EPSILON);

        let (ox, oy) = p.inverse_transform(11.0, 18.0);
        assert!((ox - 3.0).abs() < 1e-10);
        assert!((oy - 4.0).abs() < 1e-10);
    }

    #[test]
    fn test_is_in_padded_rect() {
        let rect = Rect2D::new(10.0, 10.0, 20.0, 20.0);
        assert!(GraphViewerUtils::is_in_padded_rect(15.0, 15.0, &rect, 0.0));
        assert!(!GraphViewerUtils::is_in_padded_rect(5.0, 15.0, &rect, 0.0));
        assert!(GraphViewerUtils::is_in_padded_rect(5.0, 15.0, &rect, 10.0));
    }
}
