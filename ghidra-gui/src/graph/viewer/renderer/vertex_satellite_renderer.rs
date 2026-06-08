//! Satellite renderer for vertices (miniature overview).
//!
//! Ports `ghidra.graph.viewer.renderer.VisualVertexSatelliteRenderer`.

use crate::graph::viewer::Rect2D;

/// Renders vertices in the satellite (overview/minimap) view.
///
/// In the satellite view, vertices are rendered as simple shapes
/// without labels, at a very small scale.
#[derive(Debug, Clone)]
pub struct VisualVertexSatelliteRenderer {
    /// The color used for rendering satellite vertices.
    pub vertex_color: String,
    /// The scale factor for satellite rendering.
    pub scale: f64,
    /// Minimum vertex size in pixels (even when zoomed out).
    pub min_vertex_size: f64,
}

impl VisualVertexSatelliteRenderer {
    /// Create a new satellite renderer.
    pub fn new() -> Self {
        Self {
            vertex_color: "#6699CC".to_string(),
            scale: 0.1,
            min_vertex_size: 2.0,
        }
    }

    /// Compute the satellite bounds for a vertex.
    pub fn compute_satellite_bounds(&self, full_bounds: Rect2D) -> Rect2D {
        let w = (full_bounds.width * self.scale).max(self.min_vertex_size);
        let h = (full_bounds.height * self.scale).max(self.min_vertex_size);
        Rect2D::new(
            full_bounds.x * self.scale,
            full_bounds.y * self.scale,
            w,
            h,
        )
    }
}

impl Default for VisualVertexSatelliteRenderer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_satellite_bounds() {
        let renderer = VisualVertexSatelliteRenderer::new();
        let full = Rect2D::new(100.0, 200.0, 500.0, 300.0);
        let sat = renderer.compute_satellite_bounds(full);
        assert_eq!(sat.x, 10.0);
        assert_eq!(sat.y, 20.0);
        assert_eq!(sat.width, 50.0);
        assert_eq!(sat.height, 30.0);
    }

    #[test]
    fn test_min_size() {
        let renderer = VisualVertexSatelliteRenderer::new();
        let tiny = Rect2D::new(0.0, 0.0, 5.0, 5.0);
        let sat = renderer.compute_satellite_bounds(tiny);
        assert!(sat.width >= renderer.min_vertex_size);
        assert!(sat.height >= renderer.min_vertex_size);
    }
}
