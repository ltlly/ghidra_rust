//! Stack Editor Provider -- editor for a function's stack frame.
//!
//! Ported from `ghidra.app.plugin.core.stackeditor.StackEditorProvider`.
//!
//! Provides the component provider for editing a function's stack frame,
//! including variable management, data type assignment, and stack layout.

use super::StackEditorAction;

/// The provider that hosts the stack editor UI for a single function.
///
/// Each open function stack editor gets its own `StackEditorProvider`.
#[derive(Debug)]
pub struct StackEditorProvider {
    /// The function name being edited.
    pub function_name: String,
    /// The program name containing the function.
    pub program_name: String,
    /// The display title for this provider.
    title: String,
    /// Whether this provider is visible.
    visible: bool,
    /// Whether the editor has unsaved changes.
    has_changes: bool,
    /// Pending actions to apply.
    pending_actions: Vec<StackEditorAction>,
}

impl StackEditorProvider {
    /// Create a new stack editor provider for a function.
    pub fn new(function_name: impl Into<String>, program_name: impl Into<String>) -> Self {
        let fn_name = function_name.into();
        let pgm_name = program_name.into();
        let title = format!("Stack Editor - {} ({})", fn_name, pgm_name);
        Self {
            function_name: fn_name,
            program_name: pgm_name,
            title,
            visible: false,
            has_changes: false,
            pending_actions: Vec::new(),
        }
    }

    /// Get the display title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Get the display name (function name).
    pub fn display_name(&self) -> String {
        format!("stack frame: {}", self.function_name)
    }

    /// Show the provider.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the provider.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Whether the editor has unsaved changes.
    pub fn needs_save(&self) -> bool {
        self.has_changes
    }

    /// Mark the editor as having changes.
    pub fn set_changed(&mut self, changed: bool) {
        self.has_changes = changed;
    }

    /// Queue an action to be applied.
    pub fn queue_action(&mut self, action: StackEditorAction) {
        self.pending_actions.push(action);
        self.has_changes = true;
    }

    /// Take all pending actions.
    pub fn take_pending_actions(&mut self) -> Vec<StackEditorAction> {
        std::mem::take(&mut self.pending_actions)
    }

    /// Get the help name for context help.
    pub fn help_name(&self) -> &str {
        "Stack_Editor"
    }

    /// Get the help topic.
    pub fn help_topic(&self) -> &str {
        "StackEditor"
    }

    /// Dispose of the provider.
    pub fn dispose(&mut self) {
        self.visible = false;
        self.pending_actions.clear();
        self.has_changes = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = StackEditorProvider::new("main", "test_program");
        assert_eq!(provider.function_name, "main");
        assert_eq!(provider.program_name, "test_program");
        assert!(!provider.is_visible());
        assert!(!provider.needs_save());
    }

    #[test]
    fn test_provider_title() {
        let provider = StackEditorProvider::new("myFunc", "prog");
        assert!(provider.title().contains("myFunc"));
        assert!(provider.title().contains("prog"));
    }

    #[test]
    fn test_provider_display_name() {
        let provider = StackEditorProvider::new("main", "test");
        assert_eq!(provider.display_name(), "stack frame: main");
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = StackEditorProvider::new("main", "test");
        assert!(!provider.is_visible());
        provider.show();
        assert!(provider.is_visible());
        provider.hide();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_changes() {
        let mut provider = StackEditorProvider::new("main", "test");
        assert!(!provider.needs_save());
        provider.set_changed(true);
        assert!(provider.needs_save());
        provider.set_changed(false);
        assert!(!provider.needs_save());
    }

    #[test]
    fn test_provider_actions() {
        let mut provider = StackEditorProvider::new("main", "test");
        provider.queue_action(StackEditorAction::AddLocal);
        provider.queue_action(StackEditorAction::AddParameter);
        assert!(provider.needs_save());
        assert_eq!(provider.pending_actions.len(), 2);

        let actions = provider.take_pending_actions();
        assert_eq!(actions.len(), 2);
        assert!(provider.pending_actions.is_empty());
    }

    #[test]
    fn test_provider_dispose() {
        let mut provider = StackEditorProvider::new("main", "test");
        provider.show();
        provider.set_changed(true);
        provider.queue_action(StackEditorAction::AddLocal);
        provider.dispose();
        assert!(!provider.is_visible());
        assert!(!provider.needs_save());
        assert!(provider.pending_actions.is_empty());
    }

    #[test]
    fn test_provider_help() {
        let provider = StackEditorProvider::new("main", "test");
        assert_eq!(provider.help_name(), "Stack_Editor");
        assert_eq!(provider.help_topic(), "StackEditor");
    }
}
