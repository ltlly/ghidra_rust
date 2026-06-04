//! Shape utilities for graph rendering.
//!
//! Ports `ghidra.graph.viewer.shape` package.

use crate::graph::viewer::Point2D;

/// A 2D shape path for rendering complex vertex shapes.
#[derive(Debug, Clone)]
pub enum ShapePath {
    /// A sequence of line segments.
    Lines { points: Vec<Point2D> },
    /// A rectangle.
    Rect { x: f64, y: f64, width: f64, height: f64, radius: f64 },
    /// An ellipse.
    Ellipse { cx: f64, cy: f64, rx: f64, ry: f64 },
    /// A polygon (closed line path).
    Polygon { points: Vec<Point2D> },
    /// A compound path.
    Compound { paths: Vec<ShapePath> },
}

impl ShapePath {
    /// Test if a point is inside this shape.
    pub fn contains(&self, point: Point2D) -> bool {
        match self {
            ShapePath::Rect { x, y, width, height, .. } => {
                point.x >= *x
                    && point.x <= x + width
                    && point.y >= *y
                    && point.y <= y + height
            }
            ShapePath::Ellipse { cx, cy, rx, ry } => {
                if *rx == 0.0 || *ry == 0.0 {
                    return false;
                }
                let dx = (point.x - cx) / rx;
                let dy = (point.y - cy) / ry;
                dx * dx + dy * dy <= 1.0
            }
            ShapePath::Polygon { points } => point_in_polygon(&point, points),
            ShapePath::Lines { .. } => false,
            ShapePath::Compound { paths } => paths.iter().any(|p| p.contains(point)),
        }
    }

    /// Get the bounding box of this shape.
    pub fn bounding_box(&self) -> (f64, f64, f64, f64) {
        match self {
            ShapePath::Rect { x, y, width, height, .. } => (*x, *y, *x + width, *y + height),
            ShapePath::Ellipse { cx, cy, rx, ry } => (cx - rx, cy - ry, cx + rx, cy + ry),
            ShapePath::Polygon { points } | ShapePath::Lines { points } => {
                let mut min_x = f64::MAX;
                let mut min_y = f64::MAX;
                let mut max_x = f64::MIN;
                let mut max_y = f64::MIN;
                for p in points {
                    min_x = min_x.min(p.x);
                    min_y = min_y.min(p.y);
                    max_x = max_x.max(p.x);
                    max_y = max_y.max(p.y);
                }
                (min_x, min_y, max_x, max_y)
            }
            ShapePath::Compound { paths } => {
                let mut min_x = f64::MAX;
                let mut min_y = f64::MAX;
                let mut max_x = f64::MIN;
                let mut max_y = f64::MIN;
                for p in paths {
                    let (lx, ly, hx, hy) = p.bounding_box();
                    min_x = min_x.min(lx);
                    min_y = min_y.min(ly);
                    max_x = max_x.max(hx);
                    max_y = max_y.max(hy);
                }
                (min_x, min_y, max_x, max_y)
            }
        }
    }
}

/// Ray-casting algorithm for point-in-polygon testing.
fn point_in_polygon(point: &Point2D, polygon: &[Point2D]) -> bool {
    if polygon.len() < 3 {
        return false;
    }
    let mut inside = false;
    let n = polygon.len();
    let mut j = n - 1;
    for i in 0..n {
        let xi = polygon[i].x;
        let yi = polygon[i].y;
        let xj = polygon[j].x;
        let yj = polygon[j].y;

        if ((yi > point.y) != (yj > point.y))
            && (point.x < (xj - xi) * (point.y - yi) / (yj - yi) + xi)
        {
            inside = !inside;
        }
        j = i;
    }
    inside
}

/// Creates standard vertex shape paths for use in rendering.
pub struct ShapeFactory;

impl ShapeFactory {
    /// Create a rounded rectangle path.
    pub fn rounded_rect(x: f64, y: f64, width: f64, height: f64, radius: f64) -> ShapePath {
        ShapePath::Rect { x, y, width, height, radius }
    }

    /// Create a diamond path centered at (cx, cy).
    pub fn diamond(cx: f64, cy: f64, half_width: f64, half_height: f64) -> ShapePath {
        ShapePath::Polygon {
            points: vec![
                Point2D::new(cx, cy - half_height),
                Point2D::new(cx + half_width, cy),
                Point2D::new(cx, cy + half_height),
                Point2D::new(cx - half_width, cy),
            ],
        }
    }

    /// Create a hexagon path centered at (cx, cy).
    pub fn hexagon(cx: f64, cy: f64, radius: f64) -> ShapePath {
        let points: Vec<Point2D> = (0..6)
            .map(|i| {
                let angle = std::f64::consts::PI / 3.0 * i as f64 - std::f64::consts::PI / 6.0;
                Point2D::new(cx + radius * angle.cos(), cy + radius * angle.sin())
            })
            .collect();
        ShapePath::Polygon { points }
    }

    /// Create an ellipse path.
    pub fn ellipse(cx: f64, cy: f64, rx: f64, ry: f64) -> ShapePath {
        ShapePath::Ellipse { cx, cy, rx, ry }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rect_contains() {
        let shape = ShapePath::Rect { x: 0.0, y: 0.0, width: 100.0, height: 50.0, radius: 0.0 };
        assert!(shape.contains(Point2D::new(50.0, 25.0)));
        assert!(!shape.contains(Point2D::new(150.0, 25.0)));
    }

    #[test]
    fn ellipse_contains() {
        let shape = ShapePath::Ellipse { cx: 50.0, cy: 50.0, rx: 50.0, ry: 25.0 };
        assert!(shape.contains(Point2D::new(50.0, 50.0)));
        assert!(!shape.contains(Point2D::new(200.0, 50.0)));
    }

    #[test]
    fn polygon_contains() {
        let shape = ShapePath::Polygon {
            points: vec![
                Point2D::new(0.0, 0.0),
                Point2D::new(100.0, 0.0),
                Point2D::new(100.0, 100.0),
                Point2D::new(0.0, 100.0),
            ],
        };
        assert!(shape.contains(Point2D::new(50.0, 50.0)));
        assert!(!shape.contains(Point2D::new(150.0, 50.0)));
    }

    #[test]
    fn diamond_factory() {
        let shape = ShapeFactory::diamond(50.0, 50.0, 30.0, 20.0);
        assert!(shape.contains(Point2D::new(50.0, 50.0)));
        assert!(shape.contains(Point2D::new(50.0, 35.0)));
        assert!(!shape.contains(Point2D::new(50.0, 20.0)));
    }

    #[test]
    fn hexagon_factory() {
        let shape = ShapeFactory::hexagon(50.0, 50.0, 30.0);
        assert!(shape.contains(Point2D::new(50.0, 50.0)));
    }

    #[test]
    fn bounding_box() {
        let shape = ShapePath::Ellipse { cx: 10.0, cy: 20.0, rx: 5.0, ry: 3.0 };
        let (min_x, min_y, max_x, max_y) = shape.bounding_box();
        assert!((min_x - 5.0).abs() < 0.01);
        assert!((min_y - 17.0).abs() < 0.01);
        assert!((max_x - 15.0).abs() < 0.01);
        assert!((max_y - 23.0).abs() < 0.01);
    }

    #[test]
    fn compound_contains() {
        let shape = ShapePath::Compound {
            paths: vec![
                ShapePath::Rect { x: 0.0, y: 0.0, width: 50.0, height: 50.0, radius: 0.0 },
                ShapePath::Rect { x: 60.0, y: 0.0, width: 50.0, height: 50.0, radius: 0.0 },
            ],
        };
        assert!(shape.contains(Point2D::new(25.0, 25.0)));
        assert!(shape.contains(Point2D::new(85.0, 25.0)));
        assert!(!shape.contains(Point2D::new(55.0, 25.0)));
    }
}
