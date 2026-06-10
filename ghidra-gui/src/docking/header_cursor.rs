//! Cursor management for dockable headers.
//!
//! Port of Ghidra's `HeaderCursor`.  Provides cursor shape management for
//! the drag-and-drop regions of dockable component headers.  When the user
//! hovers over a header, the cursor changes to indicate available actions
//! (drag to move, resize, close, etc.).

// ---------------------------------------------------------------------------
// HeaderCursorRegion — the region of a header the cursor is over
// ---------------------------------------------------------------------------

/// Identifies a region of a dockable header that has its own cursor shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HeaderCursorRegion {
    /// The title / label area (drag to move).
    Title,
    /// The close button.
    CloseButton,
    /// The maximize / restore button.
    MaximizeButton,
    /// The minimize / iconify button.
    MinimizeButton,
    /// The pin / unpin button.
    PinButton,
    /// The drag handle for reordering tabs.
    DragHandle,
    /// The left edge for resizing.
    ResizeLeft,
    /// The right edge for resizing.
    ResizeRight,
    /// The top edge for resizing.
    ResizeTop,
    /// The bottom edge for resizing.
    ResizeBottom,
    /// The top-left corner for resizing.
    ResizeTopLeft,
    /// The top-right corner for resizing.
    ResizeTopRight,
    /// The bottom-left corner for resizing.
    ResizeBottomLeft,
    /// The bottom-right corner for resizing.
    ResizeBottomRight,
    /// No specific region (default cursor).
    None,
}

// ---------------------------------------------------------------------------
// CursorShape — the cursor shape to display
// ---------------------------------------------------------------------------

/// Cursor shapes used by the docking header.
///
/// Maps to egui cursor icons but is kept as a separate enum so the docking
/// framework does not depend directly on egui types in its API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CursorShape {
    /// Default arrow cursor.
    Default,
    /// Move / drag cursor (crosshair or grab).
    Move,
    /// Pointer / hand cursor (over a clickable element).
    Pointer,
    /// Resize horizontally.
    ResizeHorizontal,
    /// Resize vertically.
    ResizeVertical,
    /// Resize diagonally (top-left to bottom-right).
    ResizeNwSe,
    /// Resize diagonally (top-right to bottom-left).
    ResizeNeSw,
    /// Text selection cursor.
    Text,
    /// Not-allowed cursor (drop not permitted).
    NotAllowed,
}

impl Default for CursorShape {
    fn default() -> Self {
        CursorShape::Default
    }
}

impl CursorShape {
    /// Convert to the corresponding [`egui::CursorIcon`].
    pub fn to_egui(self) -> egui::CursorIcon {
        match self {
            CursorShape::Default => egui::CursorIcon::Default,
            CursorShape::Move => egui::CursorIcon::Grab,
            CursorShape::Pointer => egui::CursorIcon::PointingHand,
            CursorShape::ResizeHorizontal => egui::CursorIcon::ResizeHorizontal,
            CursorShape::ResizeVertical => egui::CursorIcon::ResizeVertical,
            CursorShape::ResizeNwSe => egui::CursorIcon::ResizeNwSe,
            CursorShape::ResizeNeSw => egui::CursorIcon::ResizeNeSw,
            CursorShape::Text => egui::CursorIcon::Text,
            CursorShape::NotAllowed => egui::CursorIcon::NotAllowed,
        }
    }
}

// ---------------------------------------------------------------------------
// HeaderCursor — manages cursor state for a dockable header
// ---------------------------------------------------------------------------

/// Manages the cursor shape based on the current hover position within a
/// dockable header.
///
/// # Usage
///
/// ```ignore
/// let mut cursor = HeaderCursor::new();
/// // On each frame, update the cursor based on the mouse position.
/// if let Some(region) = cursor.hit_test(mouse_pos, header_rect) {
///     cursor.set_region(region);
/// } else {
///     cursor.set_region(HeaderCursorRegion::None);
/// }
/// // Apply the cursor to the egui context.
/// ctx.set_cursor_icon(cursor.current_shape().to_egui());
/// ```
#[derive(Debug, Clone)]
pub struct HeaderCursor {
    /// The currently active region.
    current_region: HeaderCursorRegion,
    /// Whether the cursor is currently pressed (dragging).
    pressed: bool,
    /// The header height used for edge-hit detection.
    header_height: f32,
    /// The size of the resize edge hit zone in pixels.
    resize_edge_size: f32,
    /// The size of the button hit zones in pixels.
    button_size: f32,
}

impl HeaderCursor {
    /// Create a new header cursor with default settings.
    pub fn new() -> Self {
        Self {
            current_region: HeaderCursorRegion::None,
            pressed: false,
            header_height: 24.0,
            resize_edge_size: 6.0,
            button_size: 20.0,
        }
    }

    /// Returns the currently active region.
    pub fn current_region(&self) -> HeaderCursorRegion {
        self.current_region
    }

    /// Set the active region.
    pub fn set_region(&mut self, region: HeaderCursorRegion) {
        self.current_region = region;
    }

    /// Returns the cursor shape for the current region.
    pub fn current_shape(&self) -> CursorShape {
        region_to_cursor(self.current_region, self.pressed)
    }

    /// Returns whether the cursor is in a pressed (dragging) state.
    pub fn is_pressed(&self) -> bool {
        self.pressed
    }

    /// Set the pressed state.
    pub fn set_pressed(&mut self, pressed: bool) {
        self.pressed = pressed;
    }

    /// Set the header height for hit testing.
    pub fn set_header_height(&mut self, height: f32) {
        self.header_height = height;
    }

    /// Set the resize edge hit zone size.
    pub fn set_resize_edge_size(&mut self, size: f32) {
        self.resize_edge_size = size;
    }

    /// Set the button hit zone size.
    pub fn set_button_size(&mut self, size: f32) {
        self.button_size = size;
    }

    /// Hit-test a point against the header rectangle.
    ///
    /// Returns the [`HeaderCursorRegion`] under the point, or
    /// [`HeaderCursorRegion::None`] if the point is outside the header.
    pub fn hit_test(
        &self,
        point: (f32, f32),
        header_rect: (f32, f32, f32, f32),
    ) -> HeaderCursorRegion {
        let (px, py) = point;
        let (hx, hy, hw, hh) = header_rect;

        // Check if the point is within the header bounds.
        if px < hx || px > hx + hw || py < hy || py > hy + hh {
            return HeaderCursorRegion::None;
        }

        // Check resize edges first (they take priority).
        let edge = self.resize_edge_size;
        let on_left = px - hx < edge;
        let on_right = hx + hw - px < edge;
        let on_top = py - hy < edge;
        let on_bottom = hy + hh - py < edge;

        match (on_left, on_right, on_top, on_bottom) {
            (true, _, true, _) => return HeaderCursorRegion::ResizeTopLeft,
            (_, true, true, _) => return HeaderCursorRegion::ResizeTopRight,
            (true, _, _, true) => return HeaderCursorRegion::ResizeBottomLeft,
            (_, true, _, true) => return HeaderCursorRegion::ResizeBottomRight,
            (true, _, _, _) => return HeaderCursorRegion::ResizeLeft,
            (_, true, _, _) => return HeaderCursorRegion::ResizeRight,
            (_, _, true, _) => return HeaderCursorRegion::ResizeTop,
            (_, _, _, true) => return HeaderCursorRegion::ResizeBottom,
            _ => {}
        }

        // Check button zones (right-aligned).
        let btn = self.button_size;
        let buttons_start_x = hx + hw - btn * 3.0; // 3 buttons
        if px >= buttons_start_x {
            let rel_x = px - buttons_start_x;
            let button_index = (rel_x / btn) as u32;
            match button_index {
                0 => return HeaderCursorRegion::PinButton,
                1 => return HeaderCursorRegion::MaximizeButton,
                2 => return HeaderCursorRegion::CloseButton,
                _ => {}
            }
        }

        // Default: the title area.
        HeaderCursorRegion::Title
    }
}

impl Default for HeaderCursor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map a header cursor region to a cursor shape.
fn region_to_cursor(region: HeaderCursorRegion, pressed: bool) -> CursorShape {
    match region {
        HeaderCursorRegion::Title => {
            if pressed {
                CursorShape::Move
            } else {
                CursorShape::Default
            }
        }
        HeaderCursorRegion::CloseButton
        | HeaderCursorRegion::MaximizeButton
        | HeaderCursorRegion::MinimizeButton
        | HeaderCursorRegion::PinButton => CursorShape::Pointer,
        HeaderCursorRegion::DragHandle => CursorShape::Move,
        HeaderCursorRegion::ResizeLeft | HeaderCursorRegion::ResizeRight => {
            CursorShape::ResizeHorizontal
        }
        HeaderCursorRegion::ResizeTop | HeaderCursorRegion::ResizeBottom => {
            CursorShape::ResizeVertical
        }
        HeaderCursorRegion::ResizeTopLeft | HeaderCursorRegion::ResizeBottomRight => {
            CursorShape::ResizeNwSe
        }
        HeaderCursorRegion::ResizeTopRight | HeaderCursorRegion::ResizeBottomLeft => {
            CursorShape::ResizeNeSw
        }
        HeaderCursorRegion::None => CursorShape::Default,
    }
}
