//! Find dialog.
//!
//! Port of Ghidra's `FindDialog` class. Provides a search dialog with string
//! and regex modes, next/previous/find-all buttons, and search history.
//!
//! In egui immediate-mode style, the dialog is rendered via
//! [`FindDialog::show`].

/// Search mode for the find dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindMode {
    /// Plain string search.
    String,
    /// Regular expression search.
    Regex,
}

impl Default for FindMode {
    fn default() -> Self {
        FindMode::String
    }
}

/// Direction for search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchDirection {
    Forward,
    Backward,
}

/// Result of a single search operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    /// The row index where the match was found, or `None` if no match.
    pub row: Option<usize>,
    /// The column index of the match.
    pub column: Option<usize>,
    /// The start offset within the matched text.
    pub start: Option<usize>,
    /// The end offset within the matched text.
    pub end: Option<usize>,
}

impl SearchResult {
    pub fn found(row: usize, column: usize, start: usize, end: usize) -> Self {
        Self {
            row: Some(row),
            column: Some(column),
            start: Some(start),
            end: Some(end),
        }
    }

    pub fn not_found() -> Self {
        Self {
            row: None,
            column: None,
            start: None,
            end: None,
        }
    }

    pub fn is_found(&self) -> bool {
        self.row.is_some()
    }
}

/// A search provider that the find dialog delegates to.
pub trait FindDialogSearcher {
    /// Search for `text` starting at the given cursor position.
    fn search(
        &self,
        text: &str,
        forward: bool,
        use_regex: bool,
    ) -> SearchResult;

    /// Get the current cursor position (row, column).
    fn cursor_position(&self) -> (usize, usize);
}

/// State for the find dialog.
pub struct FindDialog {
    /// Dialog title.
    title: String,
    /// Whether the dialog is currently open.
    open: bool,
    /// The current search text.
    search_text: String,
    /// Search mode.
    mode: FindMode,
    /// Search history (recent searches).
    history: Vec<String>,
    /// Maximum history size.
    max_history: usize,
    /// Whether the "Find All" feature is enabled.
    find_all_enabled: bool,
    /// Whether the API-level disable for find-all is active.
    find_all_api_disabled: bool,
    /// Last search result.
    last_result: SearchResult,
    /// Whether the dialog was closed by the user.
    closed: bool,
}

impl FindDialog {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            open: false,
            search_text: String::new(),
            mode: FindMode::String,
            history: Vec::new(),
            max_history: 20,
            find_all_enabled: true,
            find_all_api_disabled: false,
            last_result: SearchResult::not_found(),
            closed: false,
        }
    }

    /// Open the dialog.
    pub fn open(&mut self) {
        self.open = true;
        self.closed = false;
    }

    /// Close the dialog.
    pub fn close(&mut self) {
        self.open = false;
        self.closed = true;
    }

    /// Returns `true` if the dialog is currently open.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Get the current search text.
    pub fn search_text(&self) -> &str {
        &self.search_text
    }

    /// Set the search text.
    pub fn set_search_text(&mut self, text: impl Into<String>) {
        self.search_text = text.into();
    }

    /// Get the current search mode.
    pub fn mode(&self) -> FindMode {
        self.mode
    }

    /// Set the search mode.
    pub fn set_mode(&mut self, mode: FindMode) {
        self.mode = mode;
    }

    /// Enable or disable the "Find All" button.
    pub fn set_find_all_enabled(&mut self, enabled: bool) {
        self.find_all_enabled = enabled;
    }

    /// Get the search history.
    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Get the last search result.
    pub fn last_result(&self) -> &SearchResult {
        &self.last_result
    }

    /// Add a search to the history.
    fn add_to_history(&mut self, text: String) {
        if text.is_empty() {
            return;
        }
        // Remove existing entry if present
        self.history.retain(|s| s != &text);
        self.history.insert(0, text);
        if self.history.len() > self.max_history {
            self.history.truncate(self.max_history);
        }
    }

    /// Perform a search with the given searcher.
    pub fn do_search(
        &mut self,
        searcher: &dyn FindDialogSearcher,
        forward: bool,
    ) -> SearchResult {
        if self.search_text.is_empty() {
            return SearchResult::not_found();
        }

        self.add_to_history(self.search_text.clone());
        let use_regex = self.mode == FindMode::Regex;
        let result = searcher.search(&self.search_text, forward, use_regex);
        self.last_result = result.clone();
        result
    }

    /// Perform a "find all" search.
    pub fn do_search_all(
        &mut self,
        searcher: &dyn FindDialogSearcher,
    ) -> SearchResult {
        if !self.find_all_enabled || self.find_all_api_disabled {
            return SearchResult::not_found();
        }
        self.do_search(searcher, true)
    }

    /// Show the find dialog using egui.
    pub fn show(&mut self, ctx: &egui::Context) -> bool {
        if !self.open {
            return false;
        }

        let mut should_search_forward = false;
        let mut should_search_backward = false;
        let mut should_search_all = false;
        let mut should_close = false;

        let title = self.title.clone();
        let find_all_enabled = self.find_all_enabled && !self.find_all_api_disabled;
        let search_text_empty = self.search_text.is_empty();

        egui::Window::new(&title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                // Search text input
                ui.horizontal(|ui| {
                    ui.label("Find:");
                    let response = ui.text_edit_singleline(&mut self.search_text);
                    // Focus the text field when dialog opens
                    if self.open {
                        response.request_focus();
                    }
                });

                // Mode selection
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.mode, FindMode::String, "String");
                    ui.selectable_value(&mut self.mode, FindMode::Regex, "Regular Expression");
                });

                ui.add_space(4.0);
                ui.separator();
                ui.add_space(4.0);

                // Buttons
                ui.horizontal(|ui| {
                    let next_enabled = !search_text_empty;
                    let prev_enabled = !search_text_empty;
                    let all_enabled = !search_text_empty && find_all_enabled;

                    if ui.add_enabled(next_enabled, egui::Button::new("Next")).clicked() {
                        should_search_forward = true;
                    }
                    if ui
                        .add_enabled(prev_enabled, egui::Button::new("Previous"))
                        .clicked()
                    {
                        should_search_backward = true;
                    }
                    if ui
                        .add_enabled(all_enabled, egui::Button::new("Find All"))
                        .clicked()
                    {
                        should_search_all = true;
                    }
                    if ui.button("Close").clicked() {
                        should_close = true;
                    }
                });

                // Show status
                if !self.search_text.is_empty() && self.last_result.is_found() {
                    ui.colored_label(
                        egui::Color32::from_rgb(50, 180, 50),
                        "Match found",
                    );
                } else if !self.search_text.is_empty() {
                    ui.colored_label(
                        egui::Color32::from_rgb(200, 50, 50),
                        "No match found",
                    );
                }
            });

        if should_close {
            self.close();
        }

        should_search_forward || should_search_backward || should_search_all
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct MockSearcher {
        data: Vec<String>,
    }

    impl MockSearcher {
        fn new(data: Vec<String>) -> Self {
            Self { data }
        }
    }

    impl FindDialogSearcher for MockSearcher {
        fn search(&self, text: &str, _forward: bool, _use_regex: bool) -> SearchResult {
            for (i, line) in self.data.iter().enumerate() {
                if let Some(pos) = line.find(text) {
                    return SearchResult::found(i, 0, pos, pos + text.len());
                }
            }
            SearchResult::not_found()
        }

        fn cursor_position(&self) -> (usize, usize) {
            (0, 0)
        }
    }

    #[test]
    fn test_new_dialog() {
        let dialog = FindDialog::new("Find");
        assert!(!dialog.is_open());
        assert!(dialog.search_text().is_empty());
        assert_eq!(dialog.mode(), FindMode::String);
    }

    #[test]
    fn test_open_close() {
        let mut dialog = FindDialog::new("Find");
        dialog.open();
        assert!(dialog.is_open());
        dialog.close();
        assert!(!dialog.is_open());
    }

    #[test]
    fn test_set_search_text() {
        let mut dialog = FindDialog::new("Find");
        dialog.set_search_text("hello");
        assert_eq!(dialog.search_text(), "hello");
    }

    #[test]
    fn test_set_mode() {
        let mut dialog = FindDialog::new("Find");
        dialog.set_mode(FindMode::Regex);
        assert_eq!(dialog.mode(), FindMode::Regex);
    }

    #[test]
    fn test_find_mode_default() {
        assert_eq!(FindMode::default(), FindMode::String);
    }

    #[test]
    fn test_search_found() {
        let mut dialog = FindDialog::new("Find");
        dialog.set_search_text("world");
        let searcher = MockSearcher::new(vec!["hello world".into(), "foo bar".into()]);
        let result = dialog.do_search(&searcher, true);
        assert!(result.is_found());
        assert_eq!(result.row, Some(0));
        assert_eq!(result.start, Some(6));
    }

    #[test]
    fn test_search_not_found() {
        let mut dialog = FindDialog::new("Find");
        dialog.set_search_text("xyz");
        let searcher = MockSearcher::new(vec!["hello world".into()]);
        let result = dialog.do_search(&searcher, true);
        assert!(!result.is_found());
    }

    #[test]
    fn test_search_empty_text() {
        let mut dialog = FindDialog::new("Find");
        let searcher = MockSearcher::new(vec!["hello".into()]);
        let result = dialog.do_search(&searcher, true);
        assert!(!result.is_found());
    }

    #[test]
    fn test_search_history() {
        let mut dialog = FindDialog::new("Find");
        let searcher = MockSearcher::new(vec!["hello world".into()]);

        dialog.set_search_text("hello");
        dialog.do_search(&searcher, true);
        dialog.set_search_text("world");
        dialog.do_search(&searcher, true);

        assert_eq!(dialog.history().len(), 2);
        assert_eq!(dialog.history()[0], "world");
        assert_eq!(dialog.history()[1], "hello");
    }

    #[test]
    fn test_search_history_no_duplicates() {
        let mut dialog = FindDialog::new("Find");
        let searcher = MockSearcher::new(vec!["hello".into()]);

        dialog.set_search_text("hello");
        dialog.do_search(&searcher, true);
        dialog.set_search_text("hello");
        dialog.do_search(&searcher, true);

        assert_eq!(dialog.history().len(), 1);
    }

    #[test]
    fn test_search_history_max_size() {
        let mut dialog = FindDialog::new("Find");
        dialog.max_history = 3;
        let searcher = MockSearcher::new(vec!["a b c d e".into()]);

        for word in &["a", "b", "c", "d", "e"] {
            dialog.set_search_text(*word);
            dialog.do_search(&searcher, true);
        }

        assert_eq!(dialog.history().len(), 3);
    }

    #[test]
    fn test_find_all_disabled() {
        let mut dialog = FindDialog::new("Find");
        dialog.set_search_text("test");
        dialog.set_find_all_enabled(false);
        let searcher = MockSearcher::new(vec!["test".into()]);
        let result = dialog.do_search_all(&searcher);
        assert!(!result.is_found());
    }

    #[test]
    fn test_find_all_api_disabled() {
        let mut dialog = FindDialog::new("Find");
        dialog.set_search_text("test");
        dialog.find_all_api_disabled = true;
        let searcher = MockSearcher::new(vec!["test".into()]);
        let result = dialog.do_search_all(&searcher);
        assert!(!result.is_found());
    }

    #[test]
    fn test_search_result_found() {
        let r = SearchResult::found(1, 2, 3, 5);
        assert!(r.is_found());
        assert_eq!(r.row, Some(1));
        assert_eq!(r.column, Some(2));
        assert_eq!(r.start, Some(3));
        assert_eq!(r.end, Some(5));
    }

    #[test]
    fn test_search_result_not_found() {
        let r = SearchResult::not_found();
        assert!(!r.is_found());
        assert_eq!(r.row, None);
    }
}
