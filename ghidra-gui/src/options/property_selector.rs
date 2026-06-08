//! Port of `ghidra.framework.options.PropertySelector`.
//!
//! A combo box-based selector property editor that allows selecting from
//! a list of predefined tag values. In the Java version this extends
//! `JComboBox<String>`; in Rust/egui it stores the list of tags and the
//! currently selected index.

/// A combo box-based selector for option values that use tags.
///
/// Ported from Ghidra's `ghidra.framework.options.PropertySelector`.
/// In the Java version, this extends `JComboBox<String>` and listens for
/// item events. In Rust, this stores the available tags and the currently
/// selected tag index.
#[derive(Debug, Clone)]
pub struct PropertySelector {
    /// The available tag values.
    tags: Vec<String>,
    /// Currently selected tag index.
    selected: usize,
    /// Whether to notify the parent editor of changes.
    notify_editor: bool,
}

impl PropertySelector {
    /// Create a new property selector with the given tags.
    ///
    /// Selects the first tag by default.
    pub fn new(tags: Vec<String>) -> Self {
        Self {
            tags,
            selected: 0,
            notify_editor: true,
        }
    }

    /// Create a new property selector with the given tags and initially
    /// selected tag text.
    ///
    /// If the initial selection is not found in the tags, defaults to index 0.
    pub fn with_selection(tags: Vec<String>, initial: &str) -> Self {
        let selected = tags
            .iter()
            .position(|t| t == initial)
            .unwrap_or(0);
        Self {
            tags,
            selected,
            notify_editor: true,
        }
    }

    /// Get the list of available tags.
    pub fn tags(&self) -> &[String] {
        &self.tags
    }

    /// Get the currently selected tag index.
    pub fn selected_index(&self) -> usize {
        self.selected
    }

    /// Get the currently selected tag text.
    pub fn selected_text(&self) -> Option<&str> {
        self.tags.get(self.selected).map(|s| s.as_str())
    }

    /// Set the selected index.
    pub fn set_selected_index(&mut self, index: usize) {
        if index < self.tags.len() {
            self.selected = index;
        }
    }

    /// Set the selection by tag text.
    ///
    /// Returns `true` if the tag was found and selected.
    pub fn set_selected_text(&mut self, text: &str) -> bool {
        if let Some(pos) = self.tags.iter().position(|t| t == text) {
            self.selected = pos;
            true
        } else {
            false
        }
    }

    /// Update the selection from an external source without triggering
    /// editor notifications.
    pub fn set_selected_silent(&mut self, text: &str) {
        self.notify_editor = false;
        self.set_selected_text(text);
        self.notify_editor = true;
    }

    /// Check whether editor notifications are enabled.
    pub fn notify_editor(&self) -> bool {
        self.notify_editor
    }

    /// Get the number of available tags.
    pub fn len(&self) -> usize {
        self.tags.len()
    }

    /// Check if there are no tags.
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }
}

impl Default for PropertySelector {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

impl std::fmt::Display for PropertySelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.selected_text() {
            Some(text) => write!(f, "PropertySelector: {} [{} tags]", text, self.tags.len()),
            None => write!(f, "PropertySelector: (empty)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_property_selector_new() {
        let tags = vec!["low".to_string(), "medium".to_string(), "high".to_string()];
        let ps = PropertySelector::new(tags);
        assert_eq!(ps.len(), 3);
        assert_eq!(ps.selected_index(), 0);
        assert_eq!(ps.selected_text(), Some("low"));
    }

    #[test]
    fn test_property_selector_with_selection() {
        let tags = vec!["low".to_string(), "medium".to_string(), "high".to_string()];
        let ps = PropertySelector::with_selection(tags, "medium");
        assert_eq!(ps.selected_index(), 1);
        assert_eq!(ps.selected_text(), Some("medium"));
    }

    #[test]
    fn test_property_selector_with_selection_not_found() {
        let tags = vec!["a".to_string(), "b".to_string()];
        let ps = PropertySelector::with_selection(tags, "z");
        assert_eq!(ps.selected_index(), 0);
    }

    #[test]
    fn test_property_selector_default() {
        let ps = PropertySelector::default();
        assert!(ps.is_empty());
        assert_eq!(ps.selected_text(), None);
    }

    #[test]
    fn test_property_selector_set_selected_index() {
        let tags = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let mut ps = PropertySelector::new(tags);
        ps.set_selected_index(2);
        assert_eq!(ps.selected_text(), Some("c"));
    }

    #[test]
    fn test_property_selector_set_selected_index_out_of_bounds() {
        let tags = vec!["a".to_string()];
        let mut ps = PropertySelector::new(tags);
        ps.set_selected_index(5);
        // Should not change
        assert_eq!(ps.selected_index(), 0);
    }

    #[test]
    fn test_property_selector_set_selected_text() {
        let tags = vec!["x".to_string(), "y".to_string()];
        let mut ps = PropertySelector::new(tags);
        assert!(ps.set_selected_text("y"));
        assert_eq!(ps.selected_index(), 1);
        assert!(!ps.set_selected_text("z"));
        assert_eq!(ps.selected_index(), 1);
    }

    #[test]
    fn test_property_selector_set_selected_silent() {
        let tags = vec!["a".to_string(), "b".to_string()];
        let mut ps = PropertySelector::new(tags);
        ps.set_selected_silent("b");
        assert_eq!(ps.selected_text(), Some("b"));
        assert!(ps.notify_editor());
    }

    #[test]
    fn test_property_selector_tags() {
        let tags = vec!["one".to_string(), "two".to_string()];
        let ps = PropertySelector::new(tags.clone());
        assert_eq!(ps.tags(), tags.as_slice());
    }

    #[test]
    fn test_property_selector_display() {
        let tags = vec!["low".to_string(), "high".to_string()];
        let ps = PropertySelector::new(tags);
        let s = format!("{}", ps);
        assert!(s.contains("low"));
        assert!(s.contains("2 tags"));
    }
}
