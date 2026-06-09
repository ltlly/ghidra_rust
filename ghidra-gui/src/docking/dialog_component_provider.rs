//! The `DialogComponentProvider` trait for the docking framework.
//!
//! Port of Ghidra's `docking.DialogComponentProvider` abstract class.
//! In Java this extends `ComponentProvider` and adds dialog-specific
//! behaviour: modal/modeless operation, status lines, button panels,
//! and help integration.
//!
//! The existing [`super::dialog::DialogComponentProvider`] struct
//! provides a concrete implementation; this trait defines the abstract
//! contract so alternative dialog implementations can be created.

use std::fmt;

use super::action_context::DockingActionContext;
use super::component::ComponentProvider as ProviderType;
use super::component::WindowPosition;

// ---------------------------------------------------------------------------
// DialogComponentProvider trait
// ---------------------------------------------------------------------------

/// The trait that dialog-style component providers implement.
///
/// Dialogs in Ghidra's docking framework are a specialised kind of
/// component provider.  They can be modal or modeless, have status
/// lines, button panels, and support running background tasks.
pub trait DialogComponentProvider: fmt::Debug + Send + Sync {
    /// The dialog title.
    fn title(&self) -> &str;

    /// Set the dialog title.
    fn set_title(&mut self, title: &str);

    /// The window title (default: same as `title()`).
    fn window_title(&self) -> &str {
        self.title()
    }

    /// Whether the dialog is modal.
    fn is_modal(&self) -> bool;

    /// Set the modal mode.
    fn set_modal(&mut self, modal: bool);

    /// Whether the dialog is currently visible.
    fn is_visible(&self) -> bool;

    /// Show the dialog.
    fn show(&mut self);

    /// Close the dialog.
    fn close(&mut self);

    /// Whether the dialog has been disposed.
    fn is_disposed(&self) -> bool;

    /// Dispose of the dialog, releasing all resources.
    fn dispose(&mut self);

    // -- Status --

    /// Whether this dialog includes a status line.
    fn has_status_line(&self) -> bool {
        true
    }

    /// Get the current status text.
    fn status_text(&self) -> &str {
        ""
    }

    /// Set the status text.
    fn set_status_text(&mut self, text: &str);

    /// Clear the status text.
    fn clear_status_text(&mut self);

    // -- Buttons --

    /// Whether this dialog includes a button panel.
    fn has_button_panel(&self) -> bool {
        true
    }

    /// The number of buttons in the panel.
    fn button_count(&self) -> usize {
        0
    }

    /// Trigger the OK / apply action.
    fn ok_clicked(&mut self);

    /// Trigger the cancel action.
    fn cancel_clicked(&mut self);

    // -- Size / position --

    /// The default dialog size (width, height).
    fn default_size(&self) -> (f32, f32) {
        (500.0, 400.0)
    }

    /// Set the default dialog size.
    fn set_default_size(&mut self, width: f32, height: f32);

    /// The remembered position (x, y) if the user has moved the dialog.
    fn remembered_position(&self) -> Option<(f32, f32)> {
        None
    }

    /// Set the remembered position.
    fn set_remembered_position(&mut self, x: f32, y: f32);

    /// The preferred docking position for this dialog.
    fn default_position(&self) -> WindowPosition {
        WindowPosition::Center
    }

    // -- Task support --

    /// Whether this dialog can run background tasks.
    fn can_run_tasks(&self) -> bool {
        false
    }

    // -- Help --

    /// Invoke the help system for this dialog.
    fn invoke_help(&self) {}

    /// Set a help callback.
    fn set_help_location(&mut self, location: &str);

    // -- Accessibility --

    /// The accessible description for screen readers.
    fn accessible_description(&self) -> Option<&str> {
        None
    }

    /// Set the accessible description.
    fn set_accessible_description(&mut self, description: &str);

    // -- Context --

    /// Get the action context for this dialog.
    fn action_context(&self) -> DockingActionContext {
        DockingActionContext::new()
    }

    // -- Close callback --

    /// Set a callback invoked when the dialog is closed.
    fn set_on_close(&mut self, callback: Option<Box<dyn Fn() + Send + Sync>>);

    // -- Component provider --

    /// The component provider type for this dialog.
    fn provider_type(&self) -> ProviderType;

    /// Instance key for layout persistence.
    fn instance_key(&self) -> (ProviderType, String);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct MockDialog {
        title: String,
        modal: bool,
        visible: bool,
        disposed: bool,
        status: String,
    }

    impl MockDialog {
        fn new(title: &str) -> Self {
            Self {
                title: title.to_owned(),
                modal: true,
                visible: false,
                disposed: false,
                status: String::new(),
            }
        }
    }

    impl DialogComponentProvider for MockDialog {
        fn title(&self) -> &str { &self.title }
        fn set_title(&mut self, title: &str) { self.title = title.to_owned(); }
        fn is_modal(&self) -> bool { self.modal }
        fn set_modal(&mut self, modal: bool) { self.modal = modal; }
        fn is_visible(&self) -> bool { self.visible && !self.disposed }
        fn show(&mut self) { if !self.disposed { self.visible = true; } }
        fn close(&mut self) { self.visible = false; }
        fn is_disposed(&self) -> bool { self.disposed }
        fn dispose(&mut self) { self.visible = false; self.disposed = true; }
        fn status_text(&self) -> &str { &self.status }
        fn set_status_text(&mut self, text: &str) { self.status = text.to_owned(); }
        fn clear_status_text(&mut self) { self.status.clear(); }
        fn ok_clicked(&mut self) { self.close(); }
        fn cancel_clicked(&mut self) { self.close(); }
        fn set_default_size(&mut self, _w: f32, _h: f32) {}
        fn set_remembered_position(&mut self, _x: f32, _y: f32) {}
        fn set_help_location(&mut self, _loc: &str) {}
        fn set_accessible_description(&mut self, _desc: &str) {}
        fn set_on_close(&mut self, _cb: Option<Box<dyn Fn() + Send + Sync>>) {}
        fn provider_type(&self) -> ProviderType { ProviderType::Console }
        fn instance_key(&self) -> (ProviderType, String) {
            (ProviderType::Console, "dialog".to_owned())
        }
    }

    #[test]
    fn test_dialog_trait_lifecycle() {
        let mut dlg = MockDialog::new("Test");
        assert_eq!(dlg.title(), "Test");
        assert!(!dlg.is_visible());
        assert!(!dlg.is_disposed());

        dlg.show();
        assert!(dlg.is_visible());

        dlg.close();
        assert!(!dlg.is_visible());

        dlg.show();
        assert!(dlg.is_visible());
        dlg.dispose();
        assert!(dlg.is_disposed());
        assert!(!dlg.is_visible());
        // Show should not work after dispose.
        dlg.show();
        assert!(!dlg.is_visible());
    }

    #[test]
    fn test_dialog_trait_modal() {
        let mut dlg = MockDialog::new("Test");
        assert!(dlg.is_modal());
        dlg.set_modal(false);
        assert!(!dlg.is_modal());
    }

    #[test]
    fn test_dialog_trait_status() {
        let mut dlg = MockDialog::new("Test");
        assert!(dlg.status_text().is_empty());
        dlg.set_status_text("Loading...");
        assert_eq!(dlg.status_text(), "Loading...");
        dlg.clear_status_text();
        assert!(dlg.status_text().is_empty());
    }

    #[test]
    fn test_dialog_trait_title() {
        let mut dlg = MockDialog::new("Old");
        assert_eq!(dlg.window_title(), "Old");
        dlg.set_title("New");
        assert_eq!(dlg.title(), "New");
        assert_eq!(dlg.window_title(), "New");
    }

    #[test]
    fn test_dialog_trait_defaults() {
        let dlg = MockDialog::new("Test");
        assert!(dlg.has_status_line());
        assert!(dlg.has_button_panel());
        assert_eq!(dlg.button_count(), 0);
        assert_eq!(dlg.default_size(), (500.0, 400.0));
        assert!(!dlg.can_run_tasks());
        assert!(dlg.remembered_position().is_none());
        assert!(dlg.accessible_description().is_none());
    }

    #[test]
    fn test_dialog_trait_as_trait_object() {
        let dlg: Box<dyn DialogComponentProvider> = Box::new(MockDialog::new("Boxed"));
        assert_eq!(dlg.title(), "Boxed");
    }
}
