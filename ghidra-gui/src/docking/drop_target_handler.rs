//! The `DropTargetHandler` trait for the docking framework.
//!
//! Port of Ghidra's `docking.DropTargetHandler` interface.  In Java,
//! `DropTargetHandler` is the callback interface that the docking
//! framework uses to process drag-and-drop operations when rearranging
//! dockable windows.
//!
//! The existing [`super::drop`] module provides the data types
//! (`DropCode`, `DropTarget`, `DropState`, `DropRegion`); this trait
//! defines the handler contract.

use std::fmt;

use super::component::ComponentProvider as ProviderType;
use super::drop::{DropCode, DropTarget};

// ---------------------------------------------------------------------------
// DropTargetHandler trait
// ---------------------------------------------------------------------------

/// The handler interface for docking drag-and-drop operations.
///
/// When the user drags a dockable component, the framework calls into
/// this handler to determine valid drop targets, visual feedback, and
/// the actual drop operation.
pub trait DropTargetHandler: fmt::Debug + Send + Sync {
    /// Called when a drag operation starts.
    ///
    /// `source_provider` is the provider being dragged.
    fn drag_started(&mut self, source_provider: ProviderType, source_name: &str);

    /// Called as the drag cursor moves over the docking area.
    ///
    /// Returns the `DropCode` indicating what kind of drop would occur
    /// at the current position, or `DropCode::Invalid` if no drop is
    /// possible.
    fn drag_over(
        &mut self,
        x: f32,
        y: f32,
        source_provider: ProviderType,
        source_name: &str,
    ) -> DropCode;

    /// Called when the drag cursor enters a potential drop target.
    fn drag_enter(
        &mut self,
        target_provider: ProviderType,
        target_name: &str,
        drop_code: DropCode,
    );

    /// Called when the drag cursor leaves a potential drop target.
    fn drag_leave(
        &mut self,
        target_provider: ProviderType,
        target_name: &str,
    );

    /// Called when the user completes a drop operation.
    ///
    /// Returns `true` if the drop was accepted and the component was
    /// rearranged.
    fn drop(
        &mut self,
        source_provider: ProviderType,
        source_name: &str,
        target_provider: ProviderType,
        target_name: &str,
        drop_code: DropCode,
    ) -> bool;

    /// Called when the drag operation is cancelled (e.g. by pressing
    /// Escape).
    fn drag_cancelled(&mut self);

    /// Get all valid drop targets for the current drag operation.
    fn valid_targets(&self) -> Vec<DropTarget>;

    /// Whether the handler is currently tracking a drag operation.
    fn is_dragging(&self) -> bool;

    /// The provider being dragged, if any.
    fn drag_source(&self) -> Option<(ProviderType, String)> {
        None
    }

    /// Whether a given drop code is valid for the current drag.
    fn is_valid_drop(&self, drop_code: &DropCode) -> bool {
        drop_code.is_valid()
    }

    /// Get the visual drop regions for the given target component.
    ///
    /// These regions are used to render the drop indicators (the arrows
    /// and highlights that show the user where the component will land).
    fn drop_regions(
        &self,
        target_provider: ProviderType,
        target_name: &str,
    ) -> Vec<DropRegionVisual> {
        let _ = (target_provider, target_name);
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// DropRegionVisual — visual description of a drop region
// ---------------------------------------------------------------------------

/// Describes a visual drop region for rendering drop indicators.
///
/// This extends the data-level [`super::drop::DropRegion`] with
/// rendering hints.
#[derive(Debug, Clone)]
pub struct DropRegionVisual {
    /// The drop code for this region.
    pub drop_code: DropCode,
    /// The x coordinate of the region center (relative to the target).
    pub center_x: f32,
    /// The y coordinate of the region center (relative to the target).
    pub center_y: f32,
    /// Width of the drop indicator.
    pub width: f32,
    /// Height of the drop indicator.
    pub height: f32,
    /// Whether this region is the currently highlighted target.
    pub highlighted: bool,
    /// A human-readable label (e.g. "Left", "Tab with").
    pub label: String,
}

impl DropRegionVisual {
    /// Create a new visual drop region.
    pub fn new(
        drop_code: DropCode,
        center_x: f32,
        center_y: f32,
        width: f32,
        height: f32,
    ) -> Self {
        let label = drop_code.display_name().to_owned();
        Self {
            drop_code,
            center_x,
            center_y,
            width,
            height,
            highlighted: false,
            label,
        }
    }

    /// Set the highlighted state.
    pub fn with_highlighted(mut self, highlighted: bool) -> Self {
        self.highlighted = highlighted;
        self
    }

    /// Set the label.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct MockHandler {
        dragging: bool,
        source: Option<(ProviderType, String)>,
    }

    impl MockHandler {
        fn new() -> Self {
            Self { dragging: false, source: None }
        }
    }

    impl DropTargetHandler for MockHandler {
        fn drag_started(&mut self, provider: ProviderType, name: &str) {
            self.dragging = true;
            self.source = Some((provider, name.to_owned()));
        }
        fn drag_over(&mut self, _x: f32, _y: f32, _sp: ProviderType, _sn: &str) -> DropCode {
            if self.dragging { DropCode::Stack } else { DropCode::Invalid }
        }
        fn drag_enter(&mut self, _tp: ProviderType, _tn: &str, _dc: DropCode) {}
        fn drag_leave(&mut self, _tp: ProviderType, _tn: &str) {}
        fn drop(
            &mut self,
            _sp: ProviderType,
            _sn: &str,
            _tp: ProviderType,
            _tn: &str,
            dc: DropCode,
        ) -> bool {
            self.dragging = false;
            self.source = None;
            dc.is_valid()
        }
        fn drag_cancelled(&mut self) {
            self.dragging = false;
            self.source = None;
        }
        fn valid_targets(&self) -> Vec<DropTarget> { Vec::new() }
        fn is_dragging(&self) -> bool { self.dragging }
        fn drag_source(&self) -> Option<(ProviderType, String)> { self.source.clone() }
    }

    #[test]
    fn test_handler_lifecycle() {
        let mut handler = MockHandler::new();
        assert!(!handler.is_dragging());
        assert!(handler.drag_source().is_none());

        handler.drag_started(ProviderType::ListingView, "listing");
        assert!(handler.is_dragging());
        assert_eq!(
            handler.drag_source(),
            Some((ProviderType::ListingView, "listing".to_owned()))
        );

        let code = handler.drag_over(100.0, 200.0, ProviderType::Console, "console");
        assert_eq!(code, DropCode::Stack);

        handler.drag_cancelled();
        assert!(!handler.is_dragging());
    }

    #[test]
    fn test_handler_drop() {
        let mut handler = MockHandler::new();
        handler.drag_started(ProviderType::ListingView, "listing");

        let accepted = handler.drop(
            ProviderType::ListingView, "listing",
            ProviderType::Console, "console",
            DropCode::Right,
        );
        assert!(accepted);
        assert!(!handler.is_dragging());
    }

    #[test]
    fn test_handler_is_valid_drop() {
        let handler = MockHandler::new();
        assert!(handler.is_valid_drop(&DropCode::Left));
        assert!(!handler.is_valid_drop(&DropCode::Invalid));
    }

    #[test]
    fn test_drop_region_visual() {
        let region = DropRegionVisual::new(DropCode::Stack, 100.0, 100.0, 40.0, 40.0);
        assert_eq!(region.drop_code, DropCode::Stack);
        assert!(!region.highlighted);
        assert_eq!(region.label, "Stack");
        assert!(region.contains(100.0, 100.0));
        assert!(!region.contains(200.0, 200.0));

        let region = region.with_highlighted(true).with_label("Tab with");
        assert!(region.highlighted);
        assert_eq!(region.label, "Tab with");
    }

    #[test]
    fn test_handler_as_trait_object() {
        let handler: Box<dyn DropTargetHandler> = Box::new(MockHandler::new());
        assert!(!handler.is_dragging());
    }
}
