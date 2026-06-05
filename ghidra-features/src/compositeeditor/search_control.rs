//! Search control panel for the composite editor.
//!
//! Ported from `ghidra.app.plugin.core.compositeeditor.SearchControlPanel`.
//!
//! Provides a type-ahead search widget used in the composite editor
//! for selecting data types from the type archive.

/// The mode of the search control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchMode {
    /// Search by data type name.
    ByName,
    /// Search by data type size.
    BySize,
    /// Search by category.
    ByCategory,
}

/// Search state for the composite editor type search control.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.SearchControlPanel`.
#[derive(Debug, Clone)]
pub struct SearchControlPanel {
    /// The current search text.
    pub search_text: String,
    /// The search mode.
    pub mode: SearchMode,
    /// Whether the search panel is visible.
    pub visible: bool,
    /// Whether to match case.
    pub case_sensitive: bool,
    /// Whether to match whole words only.
    pub whole_word: bool,
    /// Maximum number of results.
    pub max_results: usize,
    /// Current search results.
    results: Vec<SearchResult>,
    /// Currently selected result index.
    selected_index: Option<usize>,
}

/// A single search result in the type search.
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// The data type name.
    pub type_name: String,
    /// The category path.
    pub category_path: String,
    /// The data type size (in bytes, if known).
    pub size: Option<u32>,
}

impl SearchResult {
    /// Full path (category + name).
    pub fn full_path(&self) -> String {
        if self.category_path.is_empty() || self.category_path == "/" {
            self.type_name.clone()
        } else {
            format!("{}/{}", self.category_path, self.type_name)
        }
    }
}

impl SearchControlPanel {
    /// Create a new search control panel.
    pub fn new() -> Self {
        Self {
            search_text: String::new(),
            mode: SearchMode::ByName,
            visible: false,
            case_sensitive: false,
            whole_word: false,
            max_results: 100,
            results: Vec::new(),
            selected_index: None,
        }
    }

    /// Show the search panel.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the search panel.
    pub fn hide(&mut self) {
        self.visible = false;
        self.search_text.clear();
        self.results.clear();
        self.selected_index = None;
    }

    /// Whether the panel is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set the search text and filter results.
    pub fn set_search_text(&mut self, text: impl Into<String>) {
        self.search_text = text.into();
        self.selected_index = None;
    }

    /// Get the current search text.
    pub fn search_text(&self) -> &str {
        &self.search_text
    }

    /// Set the search results (typically populated by external code).
    pub fn set_results(&mut self, results: Vec<SearchResult>) {
        self.results = results;
        if !self.results.is_empty() {
            self.selected_index = Some(0);
        } else {
            self.selected_index = None;
        }
    }

    /// Get the search results.
    pub fn results(&self) -> &[SearchResult] {
        &self.results
    }

    /// Get the currently selected result.
    pub fn selected_result(&self) -> Option<&SearchResult> {
        self.selected_index.and_then(|i| self.results.get(i))
    }

    /// Move selection to the next result.
    pub fn select_next(&mut self) {
        if let Some(idx) = self.selected_index {
            if idx + 1 < self.results.len() {
                self.selected_index = Some(idx + 1);
            }
        }
    }

    /// Move selection to the previous result.
    pub fn select_previous(&mut self) {
        if let Some(idx) = self.selected_index {
            if idx > 0 {
                self.selected_index = Some(idx - 1);
            }
        }
    }

    /// Whether there are results.
    pub fn has_results(&self) -> bool {
        !self.results.is_empty()
    }

    /// Number of results.
    pub fn result_count(&self) -> usize {
        self.results.len()
    }

    /// Clear all results.
    pub fn clear_results(&mut self) {
        self.results.clear();
        self.selected_index = None;
    }
}

impl Default for SearchControlPanel {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_control_panel_creation() {
        let panel = SearchControlPanel::new();
        assert!(!panel.is_visible());
        assert_eq!(panel.search_text(), "");
        assert_eq!(panel.mode, SearchMode::ByName);
    }

    #[test]
    fn test_search_control_panel_show_hide() {
        let mut panel = SearchControlPanel::new();
        panel.show();
        assert!(panel.is_visible());
        panel.hide();
        assert!(!panel.is_visible());
    }

    #[test]
    fn test_search_control_panel_search_text() {
        let mut panel = SearchControlPanel::new();
        panel.set_search_text("int");
        assert_eq!(panel.search_text(), "int");
    }

    #[test]
    fn test_search_control_panel_results() {
        let mut panel = SearchControlPanel::new();
        let results = vec![
            SearchResult {
                type_name: "int".into(),
                category_path: "/".into(),
                size: Some(4),
            },
            SearchResult {
                type_name: "uint".into(),
                category_path: "/".into(),
                size: Some(4),
            },
        ];
        panel.set_results(results);
        assert_eq!(panel.result_count(), 2);
        assert!(panel.has_results());
        assert_eq!(panel.selected_result().unwrap().type_name, "int");
    }

    #[test]
    fn test_search_control_panel_navigate() {
        let mut panel = SearchControlPanel::new();
        panel.set_results(vec![
            SearchResult { type_name: "a".into(), category_path: "/".into(), size: None },
            SearchResult { type_name: "b".into(), category_path: "/".into(), size: None },
            SearchResult { type_name: "c".into(), category_path: "/".into(), size: None },
        ]);

        panel.select_next();
        assert_eq!(panel.selected_result().unwrap().type_name, "b");
        panel.select_next();
        assert_eq!(panel.selected_result().unwrap().type_name, "c");
        panel.select_next(); // at end, stays at c
        assert_eq!(panel.selected_result().unwrap().type_name, "c");

        panel.select_previous();
        assert_eq!(panel.selected_result().unwrap().type_name, "b");
    }

    #[test]
    fn test_search_control_panel_clear() {
        let mut panel = SearchControlPanel::new();
        panel.set_results(vec![
            SearchResult { type_name: "int".into(), category_path: "/".into(), size: None },
        ]);
        panel.clear_results();
        assert!(!panel.has_results());
        assert!(panel.selected_result().is_none());
    }

    #[test]
    fn test_search_control_panel_hide_resets() {
        let mut panel = SearchControlPanel::new();
        panel.show();
        panel.set_search_text("int");
        panel.set_results(vec![
            SearchResult { type_name: "int".into(), category_path: "/".into(), size: None },
        ]);
        panel.hide();
        assert_eq!(panel.search_text(), "");
        assert!(!panel.has_results());
    }

    #[test]
    fn test_search_result_full_path() {
        let r = SearchResult {
            type_name: "int".into(),
            category_path: "/MyCat".into(),
            size: Some(4),
        };
        assert_eq!(r.full_path(), "/MyCat/int");

        let r2 = SearchResult {
            type_name: "int".into(),
            category_path: "/".into(),
            size: Some(4),
        };
        assert_eq!(r2.full_path(), "int");
    }

    #[test]
    fn test_search_modes() {
        assert_ne!(SearchMode::ByName, SearchMode::BySize);
        assert_ne!(SearchMode::BySize, SearchMode::ByCategory);
    }
}
