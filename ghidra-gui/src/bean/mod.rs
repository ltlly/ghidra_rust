//! Bean component utilities.
//!
//! Ports Ghidra's `ghidra.util.bean` types for option editor panels and
//! chooser widgets.

/// Select mode for choosers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelectMode {
    /// Select a single item.
    Single,
    /// Select multiple items.
    Multiple,
    /// Select a contiguous range of items.
    Contiguous,
}

impl Default for SelectMode {
    fn default() -> Self {
        Self::Single
    }
}

/// Abstract chooser base types for selection panels.
///
/// Ports Ghidra's `ghidra.util.bean.opteditor.AbstractChooser`.
#[derive(Debug, Clone)]
pub struct AbstractChooser {
    /// The title of the chooser.
    title: String,
    /// Whether the chooser allows multiple selections.
    select_mode: SelectMode,
    /// The currently selected items.
    selected_items: Vec<String>,
}

impl AbstractChooser {
    /// Create a new chooser.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            select_mode: SelectMode::default(),
            selected_items: Vec::new(),
        }
    }

    /// Set the selection mode.
    pub fn set_select_mode(&mut self, mode: SelectMode) {
        self.select_mode = mode;
    }

    /// Get the selection mode.
    pub fn select_mode(&self) -> SelectMode {
        self.select_mode
    }

    /// Get the title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Set the selected items.
    pub fn set_selected(&mut self, items: Vec<String>) {
        self.selected_items = items;
    }

    /// Get the selected items.
    pub fn selected(&self) -> &[String] {
        &self.selected_items
    }

    /// Get the first selected item, if any.
    pub fn first_selected(&self) -> Option<&str> {
        self.selected_items.first().map(|s| s.as_str())
    }

    /// Clear the selection.
    pub fn clear_selection(&mut self) {
        self.selected_items.clear();
    }

    /// Check if anything is selected.
    pub fn has_selection(&self) -> bool {
        !self.selected_items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abstract_chooser_basic() {
        let chooser = AbstractChooser::new("Select Option");
        assert_eq!(chooser.title(), "Select Option");
        assert_eq!(chooser.select_mode(), SelectMode::Single);
        assert!(!chooser.has_selection());
    }

    #[test]
    fn test_abstract_chooser_selection() {
        let mut chooser = AbstractChooser::new("Test");
        chooser.set_select_mode(SelectMode::Multiple);
        chooser.set_selected(vec!["a".into(), "b".into(), "c".into()]);

        assert!(chooser.has_selection());
        assert_eq!(chooser.selected().len(), 3);
        assert_eq!(chooser.first_selected(), Some("a"));

        chooser.clear_selection();
        assert!(!chooser.has_selection());
        assert!(chooser.first_selected().is_none());
    }
}
