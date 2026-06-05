//! Comment Window plugin -- manages the comment window view.
//!
//! Ported from `ghidra.app.plugin.core.commentwindow`:
//!
//! - [`CommentWindowPlugin`] -- plugin managing the comment window
//! - [`CommentWindowProvider`] -- provider for the comment table view

use super::{CommentEntry, CommentTableModel};
use ghidra_core::Address;

/// Plugin providing a table view of all comments in the program.
///
/// Ported from `ghidra.app.plugin.core.commentwindow.CommentWindowPlugin`.
#[derive(Debug)]
pub struct CommentWindowPlugin {
    /// Plugin name.
    name: String,
    /// The comment table model.
    model: CommentTableModel,
    /// Whether the provider is visible.
    visible: bool,
    /// Current program name.
    current_program: Option<String>,
    /// Whether we need to reload on next visibility.
    needs_reload: bool,
}

impl CommentWindowPlugin {
    /// Create a new comment window plugin.
    pub fn new() -> Self {
        Self {
            name: "CommentWindowPlugin".to_string(),
            model: CommentTableModel::new(),
            visible: false,
            current_program: None,
            needs_reload: true,
        }
    }

    /// Plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.current_program = program;
        self.needs_reload = true;
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set the provider visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
        if visible && self.needs_reload {
            self.needs_reload = false;
        }
    }

    /// Add a comment entry.
    pub fn add_comment(&mut self, entry: CommentEntry) {
        self.model.add_entry(entry);
    }

    /// Remove comments at the given address.
    pub fn remove_comments_at(&mut self, address: Address) {
        self.model.remove_entries_at(address);
    }

    /// Get the comment table model.
    pub fn model(&self) -> &CommentTableModel {
        &self.model
    }

    /// Get mutable access to the comment table model.
    pub fn model_mut(&mut self) -> &mut CommentTableModel {
        &mut self.model
    }

    /// Get the total comment count.
    pub fn comment_count(&self) -> usize {
        self.model.total_count()
    }
}

impl Default for CommentWindowPlugin {
    fn default() -> Self {
        Self::new()
    }
}

/// Provider for the comment window table view.
///
/// Ported from `ghidra.app.plugin.core.commentwindow.CommentWindowProvider`.
#[derive(Debug)]
pub struct CommentWindowProvider {
    /// Provider name.
    name: String,
    /// Whether the provider is visible.
    visible: bool,
    /// The table model.
    model: CommentTableModel,
    /// Column widths.
    column_widths: Vec<u32>,
}

impl CommentWindowProvider {
    /// Create a new provider.
    pub fn new(model: CommentTableModel) -> Self {
        Self {
            name: "Comment Window".to_string(),
            visible: false,
            model,
            column_widths: vec![100, 150, 350],
        }
    }

    /// Provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Get the table model.
    pub fn model(&self) -> &CommentTableModel {
        &self.model
    }

    /// Get mutable access to the table model.
    pub fn model_mut(&mut self) -> &mut CommentTableModel {
        &mut self.model
    }

    /// Get column widths.
    pub fn column_widths(&self) -> &[u32] {
        &self.column_widths
    }

    /// Reload the table model with comments from the program.
    pub fn reload(&mut self, entries: Vec<CommentEntry>) {
        // Clear and re-populate
        for entry in entries {
            self.model.add_entry(entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::CommentType;

    #[test]
    fn test_comment_window_plugin_lifecycle() {
        let mut plugin = CommentWindowPlugin::new();
        assert_eq!(plugin.name(), "CommentWindowPlugin");
        assert!(!plugin.is_visible());
        assert!(plugin.current_program().is_none());

        plugin.set_program(Some("test.exe".into()));
        assert_eq!(plugin.current_program(), Some("test.exe"));

        plugin.set_visible(true);
        assert!(plugin.is_visible());
    }

    #[test]
    fn test_comment_window_plugin_comments() {
        let mut plugin = CommentWindowPlugin::new();
        assert_eq!(plugin.comment_count(), 0);

        plugin.add_comment(CommentEntry::new(Address::new(0x1000), CommentType::Eol, "test"));
        plugin.add_comment(CommentEntry::new(Address::new(0x2000), CommentType::Pre, "another"));
        assert_eq!(plugin.comment_count(), 2);

        plugin.remove_comments_at(Address::new(0x1000));
        assert_eq!(plugin.comment_count(), 1);
    }

    #[test]
    fn test_comment_window_plugin_filter() {
        let mut plugin = CommentWindowPlugin::new();
        plugin.add_comment(CommentEntry::new(Address::new(0x1000), CommentType::Eol, "EOL"));
        plugin.add_comment(CommentEntry::new(Address::new(0x2000), CommentType::Pre, "Pre"));
        plugin.add_comment(CommentEntry::new(Address::new(0x3000), CommentType::Eol, "EOL2"));

        plugin.model_mut().set_type_filter(vec![CommentType::Eol]);
        assert_eq!(plugin.model_mut().filtered_count(), 2);
    }

    #[test]
    fn test_comment_window_provider() {
        let model = CommentTableModel::new();
        let mut provider = CommentWindowProvider::new(model);
        assert_eq!(provider.name(), "Comment Window");
        assert!(!provider.is_visible());
        assert_eq!(provider.column_widths().len(), 3);

        provider.set_visible(true);
        assert!(provider.is_visible());
    }

    #[test]
    fn test_comment_window_provider_reload() {
        let model = CommentTableModel::new();
        let mut provider = CommentWindowProvider::new(model);

        let entries = vec![
            CommentEntry::new(Address::new(0x1000), CommentType::Eol, "c1"),
            CommentEntry::new(Address::new(0x2000), CommentType::Pre, "c2"),
        ];
        provider.reload(entries);
        assert_eq!(provider.model().total_count(), 2);
    }
}
