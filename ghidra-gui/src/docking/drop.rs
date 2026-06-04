//! Drag-and-drop support for the docking framework.
//!
//! Port of Ghidra's `DropCode` and related types.  Defines the set of
//! valid drag-and-drop targets when rearranging dockable windows.

use serde::{Deserialize, Serialize};

use super::component::WindowPosition;

// ---------------------------------------------------------------------------
// DropCode
// ---------------------------------------------------------------------------

/// An enum representing available drag-and-drop options for a docking tool.
///
/// Each variant describes a different way a component can be dropped relative
/// to an existing component or window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DropCode {
    /// Invalid / no-drop zone.
    Invalid,
    /// Stack (tab) with the target component.
    Stack,
    /// Drop to the left of the target.
    Left,
    /// Drop to the right of the target.
    Right,
    /// Drop above the target.
    Top,
    /// Drop below the target.
    Bottom,
    /// Drop into the root of the layout tree.
    Root,
    /// Drop into a new separate window.
    Window,
}

impl DropCode {
    /// Whether this drop code represents a valid drop operation.
    pub fn is_valid(&self) -> bool {
        !matches!(self, DropCode::Invalid)
    }

    /// Whether this drop code results in a split (left, right, top, bottom).
    pub fn is_split(&self) -> bool {
        matches!(
            self,
            DropCode::Left | DropCode::Right | DropCode::Top | DropCode::Bottom
        )
    }

    /// Whether this drop code stacks (tabs) the component.
    pub fn is_stack(&self) -> bool {
        matches!(self, DropCode::Stack)
    }

    /// Whether this drop code creates a new window.
    pub fn is_new_window(&self) -> bool {
        matches!(self, DropCode::Window)
    }

    /// Convert this drop code to the corresponding `WindowPosition`.
    pub fn to_window_position(&self) -> WindowPosition {
        match self {
            DropCode::Left => WindowPosition::Left,
            DropCode::Right => WindowPosition::Right,
            DropCode::Top => WindowPosition::Top,
            DropCode::Bottom => WindowPosition::Bottom,
            _ => WindowPosition::default(),
        }
    }

    /// Whether this drop code represents a vertical split (top/bottom).
    pub fn is_vertical(&self) -> bool {
        matches!(self, DropCode::Top | DropCode::Bottom)
    }

    /// Whether this drop code represents a horizontal split (left/right).
    pub fn is_horizontal(&self) -> bool {
        matches!(self, DropCode::Left | DropCode::Right)
    }

    /// Human-readable name.
    pub fn display_name(&self) -> &'static str {
        match self {
            DropCode::Invalid => "Invalid",
            DropCode::Stack => "Stack",
            DropCode::Left => "Left",
            DropCode::Right => "Right",
            DropCode::Top => "Top",
            DropCode::Bottom => "Bottom",
            DropCode::Root => "Root",
            DropCode::Window => "Window",
        }
    }
}

impl Default for DropCode {
    fn default() -> Self {
        DropCode::Invalid
    }
}

impl std::fmt::Display for DropCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// DropRegion — describes a drop region on a component header
// ---------------------------------------------------------------------------

/// Describes the visual region that a drop operation targets.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct DropRegion {
    /// The drop code for this region.
    pub drop_code: DropCode,
    /// The x coordinate of the region center (relative to the component).
    pub center_x: f32,
    /// The y coordinate of the region center (relative to the component).
    pub center_y: f32,
    /// Width of the drop region.
    pub width: f32,
    /// Height of the drop region.
    pub height: f32,
}

impl DropRegion {
    /// Create a new drop region.
    pub fn new(
        drop_code: DropCode,
        center_x: f32,
        center_y: f32,
        width: f32,
        height: f32,
    ) -> Self {
        Self {
            drop_code,
            center_x,
            center_y,
            width,
            height,
        }
    }

    /// Whether a point (x, y) is inside this region.
    pub fn contains(&self, x: f32, y: f32) -> bool {
        let half_w = self.width / 2.0;
        let half_h = self.height / 2.0;
        x >= self.center_x - half_w
            && x <= self.center_x + half_w
            && y >= self.center_y - half_h
            && y <= self.center_y + half_h
    }
}

// ---------------------------------------------------------------------------
// DropTarget — information about a drop target
// ---------------------------------------------------------------------------

/// Describes a valid drop target during a drag operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DropTarget {
    /// The name/ID of the target component.
    pub component_id: String,
    /// The drop code for this target.
    pub drop_code: DropCode,
}

impl DropTarget {
    /// Create a new drop target.
    pub fn new(component_id: impl Into<String>, drop_code: DropCode) -> Self {
        Self {
            component_id: component_id.into(),
            drop_code,
        }
    }

    /// Whether this target represents a valid drop.
    pub fn is_valid(&self) -> bool {
        self.drop_code.is_valid()
    }
}

// ---------------------------------------------------------------------------
// DropState — tracks the current drag-and-drop state
// ---------------------------------------------------------------------------

/// Tracks the state of an in-progress drag-and-drop operation.
#[derive(Debug, Clone, Default)]
pub struct DropState {
    /// Whether a drag operation is currently in progress.
    pub dragging: bool,
    /// The ID of the component being dragged, if any.
    pub drag_source: Option<String>,
    /// The current drop target, if the cursor is over a valid target.
    pub current_target: Option<DropTarget>,
    /// All valid drop targets for the current drag operation.
    pub valid_targets: Vec<DropTarget>,
}

impl DropState {
    /// Create a new drop state (not dragging).
    pub fn new() -> Self {
        Self::default()
    }

    /// Start a drag operation.
    pub fn start_drag(&mut self, source_id: impl Into<String>) {
        self.dragging = true;
        self.drag_source = Some(source_id.into());
        self.current_target = None;
    }

    /// End the drag operation.
    pub fn end_drag(&mut self) -> Option<DropTarget> {
        let result = self.current_target.take();
        self.dragging = false;
        self.drag_source = None;
        self.valid_targets.clear();
        result
    }

    /// Cancel the drag operation (no drop).
    pub fn cancel_drag(&mut self) {
        self.dragging = false;
        self.drag_source = None;
        self.current_target = None;
        self.valid_targets.clear();
    }

    /// Update the current target during dragging.
    pub fn update_target(&mut self, target: Option<DropTarget>) {
        self.current_target = target;
    }

    /// Set the valid targets for the current drag.
    pub fn set_valid_targets(&mut self, targets: Vec<DropTarget>) {
        self.valid_targets = targets;
    }

    /// Whether the drag operation has a valid current target.
    pub fn has_valid_target(&self) -> bool {
        self.current_target.as_ref().map_or(false, |t| t.is_valid())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drop_code_validity() {
        assert!(!DropCode::Invalid.is_valid());
        assert!(DropCode::Stack.is_valid());
        assert!(DropCode::Left.is_valid());
        assert!(DropCode::Right.is_valid());
        assert!(DropCode::Top.is_valid());
        assert!(DropCode::Bottom.is_valid());
        assert!(DropCode::Root.is_valid());
        assert!(DropCode::Window.is_valid());
    }

    #[test]
    fn test_drop_code_is_split() {
        assert!(DropCode::Left.is_split());
        assert!(DropCode::Right.is_split());
        assert!(DropCode::Top.is_split());
        assert!(DropCode::Bottom.is_split());
        assert!(!DropCode::Stack.is_split());
        assert!(!DropCode::Window.is_split());
        assert!(!DropCode::Invalid.is_split());
    }

    #[test]
    fn test_drop_code_directionality() {
        assert!(DropCode::Left.is_horizontal());
        assert!(DropCode::Right.is_horizontal());
        assert!(!DropCode::Top.is_horizontal());

        assert!(DropCode::Top.is_vertical());
        assert!(DropCode::Bottom.is_vertical());
        assert!(!DropCode::Left.is_vertical());
    }

    #[test]
    fn test_drop_code_to_window_position() {
        assert_eq!(DropCode::Left.to_window_position(), WindowPosition::Left);
        assert_eq!(DropCode::Right.to_window_position(), WindowPosition::Right);
        assert_eq!(DropCode::Top.to_window_position(), WindowPosition::Top);
        assert_eq!(
            DropCode::Bottom.to_window_position(),
            WindowPosition::Bottom
        );
        // Stack, Window, Invalid, Root -> default (Center)
        assert_eq!(
            DropCode::Stack.to_window_position(),
            WindowPosition::default()
        );
    }

    #[test]
    fn test_drop_code_display() {
        assert_eq!(DropCode::Invalid.to_string(), "Invalid");
        assert_eq!(DropCode::Stack.to_string(), "Stack");
        assert_eq!(DropCode::Window.to_string(), "Window");
    }

    #[test]
    fn test_drop_region_contains() {
        let region = DropRegion::new(DropCode::Stack, 100.0, 100.0, 40.0, 40.0);
        assert!(region.contains(100.0, 100.0)); // center
        assert!(region.contains(110.0, 110.0)); // inside
        assert!(!region.contains(200.0, 200.0)); // outside
        assert!(!region.contains(79.0, 79.0)); // outside
    }

    #[test]
    fn test_drop_target() {
        let target = DropTarget::new("listing-view", DropCode::Left);
        assert_eq!(target.component_id, "listing-view");
        assert_eq!(target.drop_code, DropCode::Left);
        assert!(target.is_valid());

        let invalid = DropTarget::new("x", DropCode::Invalid);
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_drop_state_lifecycle() {
        let mut state = DropState::new();
        assert!(!state.dragging);
        assert!(state.drag_source.is_none());

        state.start_drag("listing");
        assert!(state.dragging);
        assert_eq!(state.drag_source.as_deref(), Some("listing"));

        state.update_target(Some(DropTarget::new("decompiler", DropCode::Right)));
        assert!(state.has_valid_target());

        let target = state.end_drag();
        assert!(!state.dragging);
        assert!(target.is_some());
        assert_eq!(target.unwrap().component_id, "decompiler");
    }

    #[test]
    fn test_drop_state_cancel() {
        let mut state = DropState::new();
        state.start_drag("listing");
        state.update_target(Some(DropTarget::new("x", DropCode::Left)));
        state.cancel_drag();

        assert!(!state.dragging);
        assert!(state.drag_source.is_none());
        assert!(state.current_target.is_none());
    }

    #[test]
    fn test_drop_state_valid_targets() {
        let mut state = DropState::new();
        state.start_drag("listing");
        state.set_valid_targets(vec![
            DropTarget::new("decompiler", DropCode::Right),
            DropTarget::new("console", DropCode::Bottom),
        ]);
        assert_eq!(state.valid_targets.len(), 2);
    }

    #[test]
    fn test_drop_code_default() {
        assert_eq!(DropCode::default(), DropCode::Invalid);
    }
}
