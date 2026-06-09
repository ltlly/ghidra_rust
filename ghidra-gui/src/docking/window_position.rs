//! Window position management for the docking framework.
//!
//! Port of Ghidra's `docking.WindowPosition` and related position types.
//! Provides a richer API for window positioning than the basic enum in
//! [`super::component::WindowPosition`], including coordinate management,
//! screen-aware placement, and serialization support.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// WindowPosition — rich positioning information
// ---------------------------------------------------------------------------

/// Comprehensive window position information.
///
/// This extends the basic [`super::component::WindowPosition`] enum with
/// concrete coordinate and size data, multi-monitor awareness, and
/// serialization support.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WindowPositionInfo {
    /// The x coordinate of the window's top-left corner.
    pub x: f32,
    /// The y coordinate of the window's top-left corner.
    pub y: f32,
    /// The width of the window.
    pub width: f32,
    /// The height of the window.
    pub height: f32,
    /// Whether the window is maximized.
    pub maximized: bool,
    /// Whether the window is minimized.
    pub minimized: bool,
    /// The dock edge this window is attached to, if any.
    pub dock_edge: DockEdge,
    /// The monitor index for multi-monitor setups.
    pub monitor: u32,
    /// Whether the position has been explicitly set by the user.
    pub user_defined: bool,
}

impl WindowPositionInfo {
    /// Create a new window position.
    pub fn new(x: f32, y: f32, width: f32, height: f32) -> Self {
        Self {
            x,
            y,
            width,
            height,
            maximized: false,
            minimized: false,
            dock_edge: DockEdge::None,
            monitor: 0,
            user_defined: false,
        }
    }

    /// Create a position at the center of the screen.
    pub fn centered(screen_width: f32, screen_height: f32) -> Self {
        let w = 800.0_f32.min(screen_width * 0.8);
        let h = 600.0_f32.min(screen_height * 0.8);
        Self::new(
            (screen_width - w) / 2.0,
            (screen_height - h) / 2.0,
            w,
            h,
        )
    }

    /// Create a default position.
    pub fn default_position() -> Self {
        Self::new(100.0, 100.0, 800.0, 600.0)
    }

    /// Set the dock edge.
    pub fn with_dock_edge(mut self, edge: DockEdge) -> Self {
        self.dock_edge = edge;
        self
    }

    /// Set the monitor index.
    pub fn with_monitor(mut self, monitor: u32) -> Self {
        self.monitor = monitor;
        self
    }

    /// Mark as user-defined.
    pub fn with_user_defined(mut self) -> Self {
        self.user_defined = true;
        self
    }

    /// Mark as maximized.
    pub fn with_maximized(mut self, maximized: bool) -> Self {
        self.maximized = maximized;
        self
    }

    /// The right edge (x + width).
    pub fn right(&self) -> f32 {
        self.x + self.width
    }

    /// The bottom edge (y + height).
    pub fn bottom(&self) -> f32 {
        self.y + self.height
    }

    /// The center point (x + width/2, y + height/2).
    pub fn center(&self) -> (f32, f32) {
        (self.x + self.width / 2.0, self.y + self.height / 2.0)
    }

    /// Whether this position overlaps with another.
    pub fn overlaps(&self, other: &WindowPositionInfo) -> bool {
        self.x < other.right()
            && self.right() > other.x
            && self.y < other.bottom()
            && self.bottom() > other.y
    }

    /// Whether this position is fully contained within a screen.
    pub fn is_on_screen(&self, screen_width: f32, screen_height: f32) -> bool {
        self.x >= 0.0
            && self.y >= 0.0
            && self.right() <= screen_width
            && self.bottom() <= screen_height
    }

    /// Clamp this position to fit within the given screen bounds.
    pub fn clamp_to_screen(&mut self, screen_width: f32, screen_height: f32) {
        if self.width > screen_width {
            self.width = screen_width;
        }
        if self.height > screen_height {
            self.height = screen_height;
        }
        if self.x < 0.0 {
            self.x = 0.0;
        }
        if self.y < 0.0 {
            self.y = 0.0;
        }
        if self.right() > screen_width {
            self.x = screen_width - self.width;
        }
        if self.bottom() > screen_height {
            self.y = screen_height - self.height;
        }
    }

    /// The area (width * height).
    pub fn area(&self) -> f32 {
        self.width * self.height
    }

    /// Move the window by the given delta.
    pub fn translate(&mut self, dx: f32, dy: f32) {
        self.x += dx;
        self.y += dy;
    }

    /// Resize the window.
    pub fn resize(&mut self, width: f32, height: f32) {
        self.width = width.max(50.0);
        self.height = height.max(50.0);
    }
}

impl Default for WindowPositionInfo {
    fn default() -> Self {
        Self::default_position()
    }
}

impl fmt::Display for WindowPositionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "({}, {} {}x{})",
            self.x, self.y, self.width, self.height
        )
    }
}

// ---------------------------------------------------------------------------
// DockEdge — which edge a window is docked to
// ---------------------------------------------------------------------------

/// Which edge of the main window a component is docked to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DockEdge {
    /// Not docked (floating or center).
    None,
    /// Docked to the top edge.
    Top,
    /// Docked to the bottom edge.
    Bottom,
    /// Docked to the left edge.
    Left,
    /// Docked to the right edge.
    Right,
}

impl DockEdge {
    /// Whether this is a horizontal edge (top/bottom).
    pub fn is_horizontal(&self) -> bool {
        matches!(self, DockEdge::Top | DockEdge::Bottom)
    }

    /// Whether this is a vertical edge (left/right).
    pub fn is_vertical(&self) -> bool {
        matches!(self, DockEdge::Left | DockEdge::Right)
    }

    /// Whether this edge is set (not None).
    pub fn is_docked(&self) -> bool {
        !matches!(self, DockEdge::None)
    }

    /// The opposite edge.
    pub fn opposite(&self) -> DockEdge {
        match self {
            DockEdge::None => DockEdge::None,
            DockEdge::Top => DockEdge::Bottom,
            DockEdge::Bottom => DockEdge::Top,
            DockEdge::Left => DockEdge::Right,
            DockEdge::Right => DockEdge::Left,
        }
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            DockEdge::None => "None",
            DockEdge::Top => "Top",
            DockEdge::Bottom => "Bottom",
            DockEdge::Left => "Left",
            DockEdge::Right => "Right",
        }
    }
}

impl Default for DockEdge {
    fn default() -> Self {
        DockEdge::None
    }
}

impl fmt::Display for DockEdge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_position_info_new() {
        let pos = WindowPositionInfo::new(10.0, 20.0, 300.0, 200.0);
        assert_eq!(pos.x, 10.0);
        assert_eq!(pos.y, 20.0);
        assert_eq!(pos.width, 300.0);
        assert_eq!(pos.height, 200.0);
        assert!(!pos.maximized);
        assert!(!pos.minimized);
        assert_eq!(pos.dock_edge, DockEdge::None);
        assert_eq!(pos.monitor, 0);
        assert!(!pos.user_defined);
    }

    #[test]
    fn test_position_info_centered() {
        let pos = WindowPositionInfo::centered(1920.0, 1080.0);
        assert!(pos.x > 0.0);
        assert!(pos.y > 0.0);
        assert!(pos.width <= 1920.0 * 0.8);
        assert!(pos.height <= 1080.0 * 0.8);
    }

    #[test]
    fn test_position_info_edges() {
        let pos = WindowPositionInfo::new(100.0, 200.0, 300.0, 400.0);
        assert_eq!(pos.right(), 400.0);
        assert_eq!(pos.bottom(), 600.0);
        assert_eq!(pos.center(), (250.0, 400.0));
    }

    #[test]
    fn test_position_info_overlaps() {
        let a = WindowPositionInfo::new(0.0, 0.0, 100.0, 100.0);
        let b = WindowPositionInfo::new(50.0, 50.0, 100.0, 100.0);
        let c = WindowPositionInfo::new(200.0, 200.0, 100.0, 100.0);
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_position_info_on_screen() {
        let pos = WindowPositionInfo::new(0.0, 0.0, 800.0, 600.0);
        assert!(pos.is_on_screen(1920.0, 1080.0));
        assert!(!pos.is_on_screen(400.0, 300.0));
    }

    #[test]
    fn test_position_info_clamp() {
        let mut pos = WindowPositionInfo::new(-50.0, -50.0, 800.0, 600.0);
        pos.clamp_to_screen(1920.0, 1080.0);
        assert!(pos.x >= 0.0);
        assert!(pos.y >= 0.0);
        assert!(pos.right() <= 1920.0);
        assert!(pos.bottom() <= 1080.0);
    }

    #[test]
    fn test_position_info_area() {
        let pos = WindowPositionInfo::new(0.0, 0.0, 100.0, 200.0);
        assert_eq!(pos.area(), 20000.0);
    }

    #[test]
    fn test_position_info_translate() {
        let mut pos = WindowPositionInfo::new(100.0, 200.0, 300.0, 400.0);
        pos.translate(10.0, 20.0);
        assert_eq!(pos.x, 110.0);
        assert_eq!(pos.y, 220.0);
    }

    #[test]
    fn test_position_info_resize() {
        let mut pos = WindowPositionInfo::new(0.0, 0.0, 300.0, 400.0);
        pos.resize(500.0, 600.0);
        assert_eq!(pos.width, 500.0);
        assert_eq!(pos.height, 600.0);
        // Minimum size enforced.
        pos.resize(10.0, 10.0);
        assert_eq!(pos.width, 50.0);
        assert_eq!(pos.height, 50.0);
    }

    #[test]
    fn test_position_info_builder() {
        let pos = WindowPositionInfo::new(0.0, 0.0, 800.0, 600.0)
            .with_dock_edge(DockEdge::Left)
            .with_monitor(1)
            .with_user_defined()
            .with_maximized(true);
        assert_eq!(pos.dock_edge, DockEdge::Left);
        assert_eq!(pos.monitor, 1);
        assert!(pos.user_defined);
        assert!(pos.maximized);
    }

    #[test]
    fn test_position_info_display() {
        let pos = WindowPositionInfo::new(10.0, 20.0, 300.0, 400.0);
        let s = format!("{}", pos);
        assert!(s.contains("10"));
        assert!(s.contains("300"));
    }

    #[test]
    fn test_position_info_default() {
        let pos = WindowPositionInfo::default();
        assert_eq!(pos.width, 800.0);
        assert_eq!(pos.height, 600.0);
    }

    #[test]
    fn test_dock_edge_basic() {
        assert!(DockEdge::Top.is_horizontal());
        assert!(DockEdge::Bottom.is_horizontal());
        assert!(!DockEdge::Left.is_horizontal());
        assert!(DockEdge::Left.is_vertical());
        assert!(DockEdge::Right.is_vertical());
        assert!(!DockEdge::None.is_vertical());
        assert!(DockEdge::Top.is_docked());
        assert!(!DockEdge::None.is_docked());
    }

    #[test]
    fn test_dock_edge_opposite() {
        assert_eq!(DockEdge::Top.opposite(), DockEdge::Bottom);
        assert_eq!(DockEdge::Bottom.opposite(), DockEdge::Top);
        assert_eq!(DockEdge::Left.opposite(), DockEdge::Right);
        assert_eq!(DockEdge::Right.opposite(), DockEdge::Left);
        assert_eq!(DockEdge::None.opposite(), DockEdge::None);
    }

    #[test]
    fn test_dock_edge_name() {
        assert_eq!(DockEdge::Top.name(), "Top");
        assert_eq!(DockEdge::None.name(), "None");
    }

    #[test]
    fn test_dock_edge_display() {
        assert_eq!(format!("{}", DockEdge::Left), "Left");
    }

    #[test]
    fn test_dock_edge_default() {
        assert_eq!(DockEdge::default(), DockEdge::None);
    }
}
