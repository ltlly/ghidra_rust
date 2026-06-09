//! The `DockableComponent` trait for the docking framework.
//!
//! Port of Ghidra's `docking.DockableComponent` interface.  In Java,
//! `DockableComponent` is the interface that the actual Swing/AWT
//! component embedded in a docking window implements.  It bridges the
//! docking framework's window management with the UI component.
//!
//! In this Rust/egui port, `DockableComponent` represents the renderable
//! surface of a dockable window.  The framework calls into it to:
//! - Paint the component's content.
//! - Handle input events.
//! - Manage the component's preferred size and minimum size.
//! - Report whether the component can be closed.

use std::fmt;

use super::action_context::DockingActionContext;
use super::component::{ComponentProvider as ProviderType, WindowPosition};

// ---------------------------------------------------------------------------
// DockableComponent trait
// ---------------------------------------------------------------------------

/// The interface that a dockable UI component implements.
///
/// This is the Rust equivalent of Ghidra's `DockableComponent`.  Each
/// dockable view (Listing, Decompiler, Console, etc.) provides a
/// component that the docking framework can place in a window, resize,
/// and manage.
pub trait DockableComponent: fmt::Debug + Send + Sync {
    /// The component's identifier (unique within the tool).
    fn component_id(&self) -> String;

    /// The provider type this component belongs to.
    fn provider_type(&self) -> ProviderType;

    /// The window title for this component.
    fn window_title(&self) -> &str;

    /// Optional icon identifier.
    fn icon(&self) -> Option<&str> {
        None
    }

    /// The preferred size (width, height) for this component.
    fn preferred_size(&self) -> (f32, f32) {
        (400.0, 300.0)
    }

    /// The minimum size (width, height) for this component.
    fn minimum_size(&self) -> (f32, f32) {
        (100.0, 100.0)
    }

    /// The maximum size (width, height) for this component, if bounded.
    fn maximum_size(&self) -> Option<(f32, f32)> {
        None
    }

    /// The preferred docking position for this component.
    fn preferred_position(&self) -> WindowPosition {
        WindowPosition::Center
    }

    /// Whether the component is currently visible.
    fn is_visible(&self) -> bool;

    /// Show the component.
    fn show(&mut self);

    /// Hide the component.
    fn hide(&mut self);

    /// Whether the component has focus.
    fn has_focus(&self) -> bool {
        false
    }

    /// Request focus for this component.
    fn request_focus(&mut self) {}

    /// Called when this component gains focus.
    fn focus_gained(&self) {}

    /// Called when this component loses focus.
    fn focus_lost(&self) {}

    /// Whether the component can be closed by the user.
    fn closeable(&self) -> bool {
        true
    }

    /// Called when the user requests to close this component.
    /// Returns `true` if the close was accepted.
    fn close_requested(&mut self) -> bool {
        self.hide();
        true
    }

    /// Called when the action context changes.
    fn context_changed(&self, _context: &DockingActionContext) {}

    /// Called when the component is being disposed.
    fn dispose(&mut self) {}

    /// Whether the component supports drag-and-drop.
    fn supports_drag(&self) -> bool {
        false
    }

    /// Whether the component accepts drop operations.
    fn accepts_drops(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct MockComponent {
        id: String,
        visible: bool,
    }

    impl MockComponent {
        fn new(id: &str) -> Self {
            Self { id: id.to_owned(), visible: true }
        }
    }

    impl DockableComponent for MockComponent {
        fn component_id(&self) -> String { self.id.clone() }
        fn provider_type(&self) -> ProviderType { ProviderType::Console }
        fn window_title(&self) -> &str { &self.id }
        fn is_visible(&self) -> bool { self.visible }
        fn show(&mut self) { self.visible = true; }
        fn hide(&mut self) { self.visible = false; }
    }

    #[test]
    fn test_dockable_component_basic() {
        let comp = MockComponent::new("console");
        assert_eq!(comp.component_id(), "console");
        assert_eq!(comp.provider_type(), ProviderType::Console);
        assert_eq!(comp.window_title(), "console");
        assert!(comp.is_visible());
    }

    #[test]
    fn test_dockable_component_defaults() {
        let comp = MockComponent::new("test");
        assert!(comp.icon().is_none());
        assert_eq!(comp.preferred_size(), (400.0, 300.0));
        assert_eq!(comp.minimum_size(), (100.0, 100.0));
        assert!(comp.maximum_size().is_none());
        assert_eq!(comp.preferred_position(), WindowPosition::Center);
        assert!(!comp.has_focus());
        assert!(comp.closeable());
        assert!(!comp.supports_drag());
        assert!(!comp.accepts_drops());
    }

    #[test]
    fn test_dockable_component_visibility() {
        let mut comp = MockComponent::new("test");
        assert!(comp.is_visible());
        comp.hide();
        assert!(!comp.is_visible());
        comp.show();
        assert!(comp.is_visible());
    }

    #[test]
    fn test_dockable_component_close() {
        let mut comp = MockComponent::new("test");
        assert!(comp.close_requested());
        assert!(!comp.is_visible());
    }

    #[test]
    fn test_dockable_component_as_trait_object() {
        let comp: Box<dyn DockableComponent> = Box::new(MockComponent::new("boxed"));
        assert_eq!(comp.component_id(), "boxed");
    }
}
