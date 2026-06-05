//! GUI Utilities Plugin
//!
//! Ported from `ghidra.app.plugin.gui`.
//!
//! Contains the Window Location Plugin, a developer diagnostic tool
//! that visualizes all open windows and their screen geometry.

use std::collections::HashMap;

/// Window Location Plugin.
///
/// A developer diagnostic plugin that shows all known window positions
/// and screen geometry. Useful for debugging multi-monitor layouts
/// and window management issues.
///
/// In the Java version, this renders an interactive Swing panel. In Rust,
/// we provide the data model and geometry computation.
#[derive(Debug, Clone)]
pub struct WindowLocationPlugin {
    /// Plugin name.
    pub name: String,
    /// Currently tracked windows.
    pub windows: Vec<WindowInfo>,
    /// Screen geometry information.
    pub screens: Vec<ScreenInfo>,
}

impl WindowLocationPlugin {
    /// Plugin name constant.
    pub const NAME: &'static str = "Window Locations";

    /// Create a new window location plugin.
    pub fn new() -> Self {
        Self {
            name: Self::NAME.to_string(),
            windows: Vec::new(),
            screens: Vec::new(),
        }
    }

    /// Add a window to the tracking list.
    pub fn add_window(&mut self, info: WindowInfo) {
        self.windows.push(info);
    }

    /// Clear all tracked windows.
    pub fn clear_windows(&mut self) {
        self.windows.clear();
    }

    /// Get all tracked windows.
    pub fn windows(&self) -> &[WindowInfo] {
        &self.windows
    }

    /// Get all tracked screens.
    pub fn screens(&self) -> &[ScreenInfo] {
        &self.screens
    }

    /// Compute the bounding rectangle that encompasses all windows and screens.
    pub fn compute_virtual_bounds(&self) -> Rectangle {
        let mut bounds = Rectangle {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        };

        for w in &self.windows {
            bounds = bounds.union(&w.bounds);
        }

        for s in &self.screens {
            bounds = bounds.union(&s.bounds);
        }

        bounds
    }
}

impl Default for WindowLocationPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a tracked window.
#[derive(Debug, Clone)]
pub struct WindowInfo {
    /// Window title.
    pub title: String,
    /// Window bounds (x, y, width, height).
    pub bounds: Rectangle,
    /// Z-order (higher = on top).
    pub z_order: u32,
    /// Whether the window is currently selected in the viewer.
    pub is_selected: bool,
    /// The initial bounds (for reset functionality).
    pub initial_bounds: Rectangle,
}

impl WindowInfo {
    /// Create a new window info.
    pub fn new(title: &str, bounds: Rectangle, z_order: u32) -> Self {
        Self {
            title: title.to_string(),
            bounds,
            z_order,
            is_selected: false,
            initial_bounds: bounds,
        }
    }

    /// Reset the window to its initial bounds.
    pub fn reset_location(&mut self) {
        self.bounds = self.initial_bounds;
    }

    /// Move the window by the given delta.
    pub fn move_by(&mut self, dx: i32, dy: i32) {
        self.bounds.x += dx;
        self.bounds.y += dy;
    }

    /// Check if a point is contained within this window's bounds.
    pub fn contains(&self, x: i32, y: i32) -> bool {
        self.bounds.contains(x, y)
    }

    /// Set the selection state.
    pub fn set_selected(&mut self, selected: bool) {
        self.is_selected = selected;
    }
}

/// Screen/monitor information.
#[derive(Debug, Clone)]
pub struct ScreenInfo {
    /// Screen index (0-based).
    pub index: usize,
    /// Screen bounds.
    pub bounds: Rectangle,
    /// Whether this is the primary screen.
    pub is_primary: bool,
}

impl ScreenInfo {
    /// Create a new screen info.
    pub fn new(index: usize, bounds: Rectangle, is_primary: bool) -> Self {
        Self {
            index,
            bounds,
            is_primary,
        }
    }
}

/// A 2D rectangle with integer coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rectangle {
    /// X coordinate of the top-left corner.
    pub x: i32,
    /// Y coordinate of the top-left corner.
    pub y: i32,
    /// Width of the rectangle.
    pub width: i32,
    /// Height of the rectangle.
    pub height: i32,
}

impl Rectangle {
    /// Create a new rectangle.
    pub fn new(x: i32, y: i32, width: i32, height: i32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }

    /// Create a rectangle from origin and size tuples.
    pub fn from_xywh(x: i32, y: i32, w: i32, h: i32) -> Self {
        Self::new(x, y, w, h)
    }

    /// The right edge (x + width).
    pub fn right(&self) -> i32 {
        self.x + self.width
    }

    /// The bottom edge (y + height).
    pub fn bottom(&self) -> i32 {
        self.y + self.height
    }

    /// Whether this rectangle contains a point.
    pub fn contains(&self, x: i32, y: i32) -> bool {
        x >= self.x && x < self.right() && y >= self.y && y < self.bottom()
    }

    /// Compute the union of two rectangles (bounding box).
    pub fn union(&self, other: &Rectangle) -> Rectangle {
        if self.width == 0 && self.height == 0 {
            return *other;
        }
        if other.width == 0 && other.height == 0 {
            return *self;
        }

        let x = self.x.min(other.x);
        let y = self.y.min(other.y);
        let right = self.right().max(other.right());
        let bottom = self.bottom().max(other.bottom());

        Rectangle {
            x,
            y,
            width: right - x,
            height: bottom - y,
        }
    }

    /// Compute the intersection of two rectangles.
    pub fn intersection(&self, other: &Rectangle) -> Option<Rectangle> {
        let x = self.x.max(other.x);
        let y = self.y.max(other.y);
        let right = self.right().min(other.right());
        let bottom = self.bottom().min(other.bottom());

        if right > x && bottom > y {
            Some(Rectangle {
                x,
                y,
                width: right - x,
                height: bottom - y,
            })
        } else {
            None
        }
    }

    /// The area of this rectangle.
    pub fn area(&self) -> i64 {
        self.width as i64 * self.height as i64
    }
}

impl Default for Rectangle {
    fn default() -> Self {
        Self {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        }
    }
}

/// Compute a scale transform to fit all windows and screens into a display area.
pub fn compute_display_transform(
    virtual_bounds: &Rectangle,
    display_width: i32,
    display_height: i32,
) -> (f64, f64, f64) {
    let full_width = virtual_bounds.width as f64;
    let full_height = virtual_bounds.height as f64;

    if full_width == 0.0 || full_height == 0.0 {
        return (1.0, 0.0, 0.0);
    }

    let dw = display_width as f64 / full_width;
    let dh = display_height as f64 / full_height;
    let scale = dw.min(dh);

    let tx = -(virtual_bounds.x as f64) * scale;
    let ty = -(virtual_bounds.y as f64) * scale;

    (scale, tx, ty)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = WindowLocationPlugin::new();
        assert_eq!(plugin.name, "Window Locations");
        assert!(plugin.windows().is_empty());
    }

    #[test]
    fn test_add_window() {
        let mut plugin = WindowLocationPlugin::new();
        plugin.add_window(WindowInfo::new(
            "Test Window",
            Rectangle::new(100, 100, 800, 600),
            0,
        ));
        assert_eq!(plugin.windows().len(), 1);
        assert_eq!(plugin.windows()[0].title, "Test Window");
    }

    #[test]
    fn test_clear_windows() {
        let mut plugin = WindowLocationPlugin::new();
        plugin.add_window(WindowInfo::new("W1", Rectangle::new(0, 0, 100, 100), 0));
        plugin.add_window(WindowInfo::new("W2", Rectangle::new(200, 200, 100, 100), 1));
        assert_eq!(plugin.windows().len(), 2);
        plugin.clear_windows();
        assert!(plugin.windows().is_empty());
    }

    #[test]
    fn test_window_info() {
        let mut w = WindowInfo::new("Test", Rectangle::new(10, 20, 300, 400), 0);
        assert!(!w.is_selected);
        assert!(w.contains(50, 50));
        assert!(!w.contains(5, 5));

        w.move_by(100, 100);
        assert_eq!(w.bounds.x, 110);
        assert_eq!(w.bounds.y, 120);

        w.reset_location();
        assert_eq!(w.bounds.x, 10);
        assert_eq!(w.bounds.y, 20);
    }

    #[test]
    fn test_rectangle_basics() {
        let r = Rectangle::new(10, 20, 100, 200);
        assert_eq!(r.right(), 110);
        assert_eq!(r.bottom(), 220);
        assert!(r.contains(50, 100));
        assert!(!r.contains(5, 5));
        assert_eq!(r.area(), 20000);
    }

    #[test]
    fn test_rectangle_union() {
        let r1 = Rectangle::new(0, 0, 100, 100);
        let r2 = Rectangle::new(50, 50, 100, 100);
        let u = r1.union(&r2);
        assert_eq!(u.x, 0);
        assert_eq!(u.y, 0);
        assert_eq!(u.width, 150);
        assert_eq!(u.height, 150);
    }

    #[test]
    fn test_rectangle_intersection() {
        let r1 = Rectangle::new(0, 0, 100, 100);
        let r2 = Rectangle::new(50, 50, 100, 100);
        let i = r1.intersection(&r2).unwrap();
        assert_eq!(i.x, 50);
        assert_eq!(i.y, 50);
        assert_eq!(i.width, 50);
        assert_eq!(i.height, 50);

        let r3 = Rectangle::new(200, 200, 100, 100);
        assert!(r1.intersection(&r3).is_none());
    }

    #[test]
    fn test_virtual_bounds() {
        let mut plugin = WindowLocationPlugin::new();
        plugin.add_window(WindowInfo::new(
            "W1",
            Rectangle::new(100, 100, 800, 600),
            0,
        ));
        plugin.add_window(WindowInfo::new(
            "W2",
            Rectangle::new(1000, 500, 400, 300),
            1,
        ));
        let bounds = plugin.compute_virtual_bounds();
        assert_eq!(bounds.x, 100);
        assert_eq!(bounds.y, 100);
        assert_eq!(bounds.width, 1300); // 100 to 1400
        assert_eq!(bounds.height, 700); // 100 to 800
    }

    #[test]
    fn test_display_transform() {
        let bounds = Rectangle::new(0, 0, 1000, 500);
        let (scale, tx, ty) = compute_display_transform(&bounds, 500, 250);
        assert!((scale - 0.5).abs() < 1e-10);
        assert!((tx).abs() < 1e-10);
        assert!((ty).abs() < 1e-10);
    }

    #[test]
    fn test_display_transform_offset() {
        let bounds = Rectangle::new(100, 200, 800, 400);
        let (scale, tx, ty) = compute_display_transform(&bounds, 400, 200);
        assert!((scale - 0.5).abs() < 1e-10);
        assert!((tx - (-50.0)).abs() < 1e-10);
        assert!((ty - (-100.0)).abs() < 1e-10);
    }

    #[test]
    fn test_empty_bounds_transform() {
        let bounds = Rectangle::default();
        let (scale, _, _) = compute_display_transform(&bounds, 100, 100);
        assert_eq!(scale, 1.0);
    }

    #[test]
    fn test_screen_info() {
        let screen = ScreenInfo::new(0, Rectangle::new(0, 0, 1920, 1080), true);
        assert!(screen.is_primary);
        assert_eq!(screen.bounds.width, 1920);
    }
}
