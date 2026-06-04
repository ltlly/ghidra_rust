//! Dialog component provider for the docking framework.
//!
//! Port of Ghidra's `DialogComponentProvider` and related dialog types.
//! Provides a structured way to build modal and modeless dialogs with
//! status lines, button panels, and work areas.

use std::collections::HashMap;
use std::sync::Arc;

use super::action::{ActionCallback, DockingAction};

// ---------------------------------------------------------------------------
// MessageType — severity levels for status messages
// ---------------------------------------------------------------------------

/// Severity level for dialog status messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageType {
    /// Informational message (default colour).
    Info,
    /// Warning message.
    Warning,
    /// Error message.
    Error,
}

impl Default for MessageType {
    fn default() -> Self {
        MessageType::Info
    }
}

// ---------------------------------------------------------------------------
// ButtonSpec — a named button in the dialog
// ---------------------------------------------------------------------------

/// Describes a button that should appear in the dialog's button panel.
#[derive(Debug, Clone)]
pub struct ButtonSpec {
    /// Display label for the button.
    pub label: String,
    /// Optional tooltip text.
    pub tooltip: Option<String>,
    /// Whether the button is initially enabled.
    pub enabled: bool,
    /// Callback invoked when the button is pressed.
    pub callback: Option<ActionCallback>,
    /// Whether this is the default button (activated by Enter).
    pub is_default: bool,
    /// Whether this is the cancel button (activated by Escape).
    pub is_cancel: bool,
}

impl ButtonSpec {
    /// Create a new button spec.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            tooltip: None,
            enabled: true,
            callback: None,
            is_default: false,
            is_cancel: false,
        }
    }

    /// Set tooltip.
    pub fn with_tooltip(mut self, tooltip: impl Into<String>) -> Self {
        self.tooltip = Some(tooltip.into());
        self
    }

    /// Set whether the button is enabled.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Set the callback.
    pub fn with_callback(mut self, callback: ActionCallback) -> Self {
        self.callback = Some(callback);
        self
    }

    /// Mark this as the default button.
    pub fn as_default(mut self) -> Self {
        self.is_default = true;
        self
    }

    /// Mark this as the cancel button.
    pub fn as_cancel(mut self) -> Self {
        self.is_cancel = true;
        self
    }
}

// ---------------------------------------------------------------------------
// DialogComponentProvider
// ---------------------------------------------------------------------------

/// The core dialog abstraction in Ghidra's docking framework.
///
/// `DialogComponentProvider` manages:
/// - A title and modal/non-modal mode
/// - An optional status line at the bottom
/// - An optional button panel (OK, Cancel, Help, etc.)
/// - A work area where content is placed
/// - Optional progress-task support
///
/// In this Rust port the "work area" is a logical container; actual
/// rendering is delegated to the egui layer.
pub struct DialogComponentProvider {
    /// Dialog title.
    title: String,
    /// Whether the dialog is modal.
    modal: bool,
    /// Whether the dialog includes a status line.
    include_status: bool,
    /// Whether the dialog includes a button panel.
    include_buttons: bool,
    /// Whether the dialog can run background tasks.
    can_run_tasks: bool,
    /// Current status text.
    status_text: String,
    /// Current status severity.
    status_type: MessageType,
    /// Ordered list of buttons in the button panel.
    buttons: Vec<ButtonSpec>,
    /// Dismiss actions keyed by name.
    dismiss_actions: HashMap<String, DockingAction>,
    /// Whether the dialog is currently visible.
    visible: bool,
    /// Whether the dialog has been disposed.
    disposed: bool,
    /// Default dialog size (width, height).
    default_size: (f32, f32),
    /// Accessible description for screen readers.
    accessible_description: Option<String>,
    /// Whether the dialog has been resized by the user.
    resized: bool,
    /// Remembered dialog position (x, y).
    remembered_position: Option<(f32, f32)>,
    /// Remembered dialog size (width, height).
    remembered_size: Option<(f32, f32)>,
    /// Callback when the dialog is closed.
    on_close_callback: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Callback when help is requested.
    on_help_callback: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl DialogComponentProvider {
    /// Create a modal dialog with status and buttons.
    pub fn new(title: impl Into<String>) -> Self {
        Self::with_options(title, true, true, true, false)
    }

    /// Create a dialog with the specified modal mode.
    pub fn with_modal(title: impl Into<String>, modal: bool) -> Self {
        Self::with_options(title, modal, true, true, false)
    }

    /// Full constructor with all options.
    pub fn with_options(
        title: impl Into<String>,
        modal: bool,
        include_status: bool,
        include_buttons: bool,
        can_run_tasks: bool,
    ) -> Self {
        let title = title.into();
        let mut dlg = Self {
            title: title.clone(),
            modal,
            include_status,
            include_buttons,
            can_run_tasks,
            status_text: String::new(),
            status_type: MessageType::Info,
            buttons: Vec::new(),
            dismiss_actions: HashMap::new(),
            visible: false,
            disposed: false,
            default_size: (500.0, 400.0),
            accessible_description: None,
            resized: false,
            remembered_position: None,
            remembered_size: None,
            on_close_callback: None,
            on_help_callback: None,
        };
        if include_buttons {
            dlg.add_default_buttons();
        }
        dlg
    }

    /// Add standard OK / Cancel buttons.
    fn add_default_buttons(&mut self) {
        self.buttons.push(ButtonSpec::new("OK").as_default());
        self.buttons.push(ButtonSpec::new("Cancel").as_cancel());
    }

    // ---------------------------------------------------------------
    // Title / identity
    // ---------------------------------------------------------------

    /// Get the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Set the dialog title.
    pub fn set_title(&mut self, title: impl Into<String>) {
        self.title = title.into();
    }

    // ---------------------------------------------------------------
    // Modal
    // ---------------------------------------------------------------

    /// Whether the dialog is modal.
    pub fn is_modal(&self) -> bool {
        self.modal
    }

    /// Set the modal mode.
    pub fn set_modal(&mut self, modal: bool) {
        self.modal = modal;
    }

    // ---------------------------------------------------------------
    // Visibility
    // ---------------------------------------------------------------

    /// Whether the dialog is currently visible.
    pub fn is_visible(&self) -> bool {
        self.visible && !self.disposed
    }

    /// Show the dialog.
    pub fn show(&mut self) {
        if !self.disposed {
            self.visible = true;
        }
    }

    /// Close the dialog.
    pub fn close(&mut self) {
        self.visible = false;
        if let Some(cb) = &self.on_close_callback {
            cb();
        }
    }

    /// Dispose of the dialog, releasing all resources.
    pub fn dispose(&mut self) {
        self.visible = false;
        self.disposed = true;
        self.buttons.clear();
        self.dismiss_actions.clear();
        self.on_close_callback = None;
        self.on_help_callback = None;
    }

    /// Whether the dialog has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // ---------------------------------------------------------------
    // Status
    // ---------------------------------------------------------------

    /// Whether this dialog includes a status line.
    pub fn has_status(&self) -> bool {
        self.include_status
    }

    /// Get the current status text.
    pub fn status_text(&self) -> &str {
        &self.status_text
    }

    /// Get the current status severity.
    pub fn status_type(&self) -> MessageType {
        self.status_type
    }

    /// Set the status text with the default severity (Info).
    pub fn set_status_text(&mut self, text: impl Into<String>) {
        self.status_text = text.into();
        self.status_type = MessageType::Info;
    }

    /// Set the status text with a specific severity.
    pub fn set_status_text_with_type(
        &mut self,
        text: impl Into<String>,
        msg_type: MessageType,
    ) {
        self.status_text = text.into();
        self.status_type = msg_type;
    }

    /// Clear the status text.
    pub fn clear_status_text(&mut self) {
        self.status_text.clear();
        self.status_type = MessageType::Info;
    }

    // ---------------------------------------------------------------
    // Buttons
    // ---------------------------------------------------------------

    /// Whether this dialog includes a button panel.
    pub fn has_buttons(&self) -> bool {
        self.include_buttons
    }

    /// Add a button to the dialog.
    pub fn add_button(&mut self, button: ButtonSpec) {
        self.buttons.push(button);
    }

    /// Get all button specs.
    pub fn buttons(&self) -> &[ButtonSpec] {
        &self.buttons
    }

    /// Get a mutable reference to all button specs.
    pub fn buttons_mut(&mut self) -> &mut Vec<ButtonSpec> {
        &mut self.buttons
    }

    /// Enable or disable a button by label.
    pub fn set_button_enabled(&mut self, label: &str, enabled: bool) -> bool {
        if let Some(btn) = self.buttons.iter_mut().find(|b| b.label == label) {
            btn.enabled = enabled;
            true
        } else {
            false
        }
    }

    /// Remove all buttons.
    pub fn clear_buttons(&mut self) {
        self.buttons.clear();
    }

    /// Remove a button by label.
    pub fn remove_button(&mut self, label: &str) -> bool {
        if let Some(pos) = self.buttons.iter().position(|b| b.label == label) {
            self.buttons.remove(pos);
            true
        } else {
            false
        }
    }

    /// Find the default button (if any).
    pub fn default_button(&self) -> Option<&ButtonSpec> {
        self.buttons.iter().find(|b| b.is_default)
    }

    /// Find the cancel button (if any).
    pub fn cancel_button(&self) -> Option<&ButtonSpec> {
        self.buttons.iter().find(|b| b.is_cancel)
    }

    /// Trigger the OK (default) button action.
    pub fn ok_clicked(&mut self) {
        // Find and invoke the default button's callback.
        let idx = self.buttons.iter().position(|b| b.is_default);
        if let Some(idx) = idx {
            if let Some(cb) = &self.buttons[idx].callback {
                cb.call();
            }
        }
    }

    /// Trigger the Cancel button action.
    pub fn cancel_clicked(&mut self) {
        let idx = self.buttons.iter().position(|b| b.is_cancel);
        if let Some(idx) = idx {
            if let Some(cb) = &self.buttons[idx].callback {
                cb.call();
            }
        }
        self.close();
    }

    // ---------------------------------------------------------------
    // Dismiss actions
    // ---------------------------------------------------------------

    /// Add a dismiss action (an action that closes the dialog).
    pub fn add_dismiss_action(&mut self, action: DockingAction) {
        self.dismiss_actions.insert(action.name.clone(), action);
    }

    /// Get a dismiss action by name.
    pub fn get_dismiss_action(&self, name: &str) -> Option<&DockingAction> {
        self.dismiss_actions.get(name)
    }

    /// Remove a dismiss action by name.
    pub fn remove_dismiss_action(&mut self, name: &str) -> Option<DockingAction> {
        self.dismiss_actions.remove(name)
    }

    // ---------------------------------------------------------------
    // Size / position
    // ---------------------------------------------------------------

    /// Get the default dialog size.
    pub fn default_size(&self) -> (f32, f32) {
        self.default_size
    }

    /// Set the default dialog size.
    pub fn set_default_size(&mut self, width: f32, height: f32) {
        self.default_size = (width, height);
    }

    /// Whether the dialog has been resized.
    pub fn is_resized(&self) -> bool {
        self.resized
    }

    /// Mark the dialog as having been resized.
    pub fn set_resized(&mut self, resized: bool) {
        self.resized = resized;
    }

    /// Get the remembered position.
    pub fn remembered_position(&self) -> Option<(f32, f32)> {
        self.remembered_position
    }

    /// Set the remembered position.
    pub fn set_remembered_position(&mut self, x: f32, y: f32) {
        self.remembered_position = Some((x, y));
    }

    /// Clear the remembered position.
    pub fn clear_remembered_position(&mut self) {
        self.remembered_position = None;
    }

    /// Get the remembered size.
    pub fn remembered_size(&self) -> Option<(f32, f32)> {
        self.remembered_size
    }

    /// Set the remembered size.
    pub fn set_remembered_size(&mut self, width: f32, height: f32) {
        self.remembered_size = Some((width, height));
    }

    // ---------------------------------------------------------------
    // Callbacks
    // ---------------------------------------------------------------

    /// Set a callback invoked when the dialog is closed.
    pub fn set_on_close(&mut self, callback: Arc<dyn Fn() + Send + Sync>) {
        self.on_close_callback = Some(callback);
    }

    /// Set a callback invoked when help is requested.
    pub fn set_on_help(&mut self, callback: Arc<dyn Fn() + Send + Sync>) {
        self.on_help_callback = Some(callback);
    }

    /// Invoke the help callback if set.
    pub fn invoke_help(&self) {
        if let Some(cb) = &self.on_help_callback {
            cb();
        }
    }

    // ---------------------------------------------------------------
    // Accessibility
    // ---------------------------------------------------------------

    /// Set the accessible description for screen readers.
    pub fn set_accessible_description(&mut self, description: impl Into<String>) {
        self.accessible_description = Some(description.into());
    }

    /// Get the accessible description.
    pub fn accessible_description(&self) -> Option<&str> {
        self.accessible_description.as_deref()
    }

    // ---------------------------------------------------------------
    // Task support
    // ---------------------------------------------------------------

    /// Whether this dialog supports running background tasks.
    pub fn can_run_tasks(&self) -> bool {
        self.can_run_tasks
    }
}

impl fmt::Debug for DialogComponentProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DialogComponentProvider")
            .field("title", &self.title)
            .field("modal", &self.modal)
            .field("visible", &self.visible)
            .field("disposed", &self.disposed)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ReusableDialogComponentProvider
// ---------------------------------------------------------------------------

/// A convenience extension of `DialogComponentProvider` that is designed
/// to be reused across invocations rather than created fresh each time.
///
/// Ghidra's `ReusableDialogComponentProvider` adds helper methods for
/// resetting state between uses.
pub struct ReusableDialogComponentProvider {
    /// The inner dialog provider.
    inner: DialogComponentProvider,
}

impl ReusableDialogComponentProvider {
    /// Create a new reusable dialog.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            inner: DialogComponentProvider::new(title),
        }
    }

    /// Create with modal mode.
    pub fn with_modal(title: impl Into<String>, modal: bool) -> Self {
        Self {
            inner: DialogComponentProvider::with_modal(title, modal),
        }
    }

    /// Get an immutable reference to the inner dialog.
    pub fn dialog(&self) -> &DialogComponentProvider {
        &self.inner
    }

    /// Get a mutable reference to the inner dialog.
    pub fn dialog_mut(&mut self) -> &mut DialogComponentProvider {
        &mut self.inner
    }

    /// Reset the dialog for reuse: clears status, re-enables all buttons.
    pub fn reset(&mut self) {
        self.inner.clear_status_text();
        for btn in &mut self.inner.buttons {
            btn.enabled = true;
        }
    }

    /// Show the dialog (delegates to inner).
    pub fn show(&mut self) {
        self.inner.show();
    }

    /// Close the dialog (delegates to inner).
    pub fn close(&mut self) {
        self.inner.close();
    }
}

impl std::ops::Deref for ReusableDialogComponentProvider {
    type Target = DialogComponentProvider;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl std::ops::DerefMut for ReusableDialogComponentProvider {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

use std::fmt;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dialog_new() {
        let dlg = DialogComponentProvider::new("Test Dialog");
        assert_eq!(dlg.title(), "Test Dialog");
        assert!(dlg.is_modal());
        assert!(!dlg.is_visible());
        assert!(dlg.has_status());
        assert!(dlg.has_buttons());
        assert_eq!(dlg.buttons().len(), 2); // OK + Cancel
        assert!(dlg.default_button().is_some());
        assert!(dlg.cancel_button().is_some());
        assert_eq!(dlg.default_button().unwrap().label, "OK");
        assert_eq!(dlg.cancel_button().unwrap().label, "Cancel");
    }

    #[test]
    fn test_dialog_with_options() {
        let dlg = DialogComponentProvider::with_options(
            "No Status",
            false,
            false,
            false,
            true,
        );
        assert_eq!(dlg.title(), "No Status");
        assert!(!dlg.is_modal());
        assert!(!dlg.has_status());
        assert!(!dlg.has_buttons());
        assert!(dlg.buttons().is_empty());
        assert!(dlg.can_run_tasks());
    }

    #[test]
    fn test_dialog_visibility() {
        let mut dlg = DialogComponentProvider::new("Test");
        assert!(!dlg.is_visible());
        dlg.show();
        assert!(dlg.is_visible());
        dlg.close();
        assert!(!dlg.is_visible());
    }

    #[test]
    fn test_dialog_dispose() {
        let mut dlg = DialogComponentProvider::new("Test");
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
    fn test_dialog_status() {
        let mut dlg = DialogComponentProvider::new("Test");
        assert!(dlg.status_text().is_empty());

        dlg.set_status_text("Loading...");
        assert_eq!(dlg.status_text(), "Loading...");
        assert_eq!(dlg.status_type(), MessageType::Info);

        dlg.set_status_text_with_type("Something wrong", MessageType::Warning);
        assert_eq!(dlg.status_text(), "Something wrong");
        assert_eq!(dlg.status_type(), MessageType::Warning);

        dlg.set_status_text_with_type("Fatal error", MessageType::Error);
        assert_eq!(dlg.status_type(), MessageType::Error);

        dlg.clear_status_text();
        assert!(dlg.status_text().is_empty());
    }

    #[test]
    fn test_dialog_buttons() {
        let mut dlg = DialogComponentProvider::new("Test");

        dlg.add_button(ButtonSpec::new("Apply").with_tooltip("Apply changes"));
        assert_eq!(dlg.buttons().len(), 3);

        assert!(dlg.set_button_enabled("Apply", false));
        assert!(!dlg.buttons()[2].enabled);

        assert!(dlg.remove_button("Apply"));
        assert_eq!(dlg.buttons().len(), 2);

        assert!(!dlg.remove_button("Nonexistent"));
    }

    #[test]
    fn test_dialog_button_builder() {
        let btn = ButtonSpec::new("Help")
            .with_tooltip("Show help")
            .with_enabled(false)
            .as_default();

        assert_eq!(btn.label, "Help");
        assert_eq!(btn.tooltip.as_deref(), Some("Show help"));
        assert!(!btn.enabled);
        assert!(btn.is_default);
        assert!(!btn.is_cancel);
    }

    #[test]
    fn test_dialog_size_and_position() {
        let mut dlg = DialogComponentProvider::new("Test");
        assert_eq!(dlg.default_size(), (500.0, 400.0));
        dlg.set_default_size(800.0, 600.0);
        assert_eq!(dlg.default_size(), (800.0, 600.0));

        assert!(dlg.remembered_position().is_none());
        dlg.set_remembered_position(100.0, 200.0);
        assert_eq!(dlg.remembered_position(), Some((100.0, 200.0)));
        dlg.clear_remembered_position();
        assert!(dlg.remembered_position().is_none());
    }

    #[test]
    fn test_dialog_accessibility() {
        let mut dlg = DialogComponentProvider::new("Test");
        assert!(dlg.accessible_description().is_none());
        dlg.set_accessible_description("A dialog for configuring analysis options");
        assert_eq!(
            dlg.accessible_description(),
            Some("A dialog for configuring analysis options")
        );
    }

    #[test]
    fn test_dialog_set_title() {
        let mut dlg = DialogComponentProvider::new("Old Title");
        assert_eq!(dlg.title(), "Old Title");
        dlg.set_title("New Title");
        assert_eq!(dlg.title(), "New Title");
    }

    #[test]
    fn test_reusable_dialog() {
        let mut dlg = ReusableDialogComponentProvider::new("Reusable");
        dlg.set_status_text("First use");
        dlg.dialog_mut().set_button_enabled("OK", false);
        assert_eq!(dlg.status_text(), "First use");
        assert!(!dlg.dialog().buttons()[0].enabled);

        dlg.reset();
        assert!(dlg.status_text().is_empty());
        assert!(dlg.dialog().buttons()[0].enabled);
    }

    #[test]
    fn test_dismiss_actions() {
        let mut dlg = DialogComponentProvider::new("Test");
        let action = DockingAction::new("close-dialog", "Close");
        dlg.add_dismiss_action(action);

        assert!(dlg.get_dismiss_action("close-dialog").is_some());
        assert!(dlg.get_dismiss_action("nonexistent").is_none());

        let removed = dlg.remove_dismiss_action("close-dialog");
        assert!(removed.is_some());
        assert!(dlg.get_dismiss_action("close-dialog").is_none());
    }

    #[test]
    fn test_dialog_close_callback() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let called = Arc::new(AtomicBool::new(false));
        let called2 = called.clone();

        let mut dlg = DialogComponentProvider::new("Test");
        dlg.set_on_close(Arc::new(move || {
            called2.store(true, Ordering::SeqCst);
        }));

        dlg.show();
        assert!(!called.load(Ordering::SeqCst));
        dlg.close();
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_dialog_resized() {
        let mut dlg = DialogComponentProvider::new("Test");
        assert!(!dlg.is_resized());
        dlg.set_resized(true);
        assert!(dlg.is_resized());
    }

    #[test]
    fn test_message_type_default() {
        assert_eq!(MessageType::default(), MessageType::Info);
    }
}
