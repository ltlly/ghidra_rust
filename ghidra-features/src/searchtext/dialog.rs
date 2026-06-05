//! Search text dialog -- UI model for the search dialog.
//!
//! Ported from `ghidra.app.plugin.core.searchtext.SearchTextDialog`.

use super::SearchOptions;

/// State of the search text dialog.
///
/// Ported from `ghidra.app.plugin.core.searchtext.SearchTextDialog`.
#[derive(Debug, Clone)]
pub struct SearchTextDialog {
    /// Current search text.
    text: String,
    /// Case-sensitive toggle.
    case_sensitive: bool,
    /// Search direction (true = forward).
    forward: bool,
    /// Search all fields toggle.
    search_all: bool,
    /// Search functions.
    functions: bool,
    /// Search comments.
    comments: bool,
    /// Search labels.
    labels: bool,
    /// Search instruction mnemonics.
    instr_mnemonics: bool,
    /// Search instruction operands.
    instr_operands: bool,
    /// Search data mnemonics.
    data_mnemonics: bool,
    /// Search data operands.
    data_operands: bool,
    /// Whether to use program database search.
    database_search: bool,
    /// Status text.
    status_text: String,
    /// Whether the user has a selection in the listing.
    has_selection: bool,
}

impl SearchTextDialog {
    /// Create a new search dialog with default settings.
    pub fn new() -> Self {
        Self {
            text: String::new(),
            case_sensitive: false,
            forward: true,
            search_all: true,
            functions: true,
            comments: true,
            labels: true,
            instr_mnemonics: true,
            instr_operands: true,
            data_mnemonics: true,
            data_operands: true,
            database_search: true,
            status_text: String::new(),
            has_selection: false,
        }
    }

    /// Set the search text.
    pub fn set_text(&mut self, text: impl Into<String>) {
        self.text = text.into();
    }

    /// Get the search text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Set whether the listing has a selection.
    pub fn set_has_selection(&mut self, has_selection: bool) {
        self.has_selection = has_selection;
    }

    /// Set the status text.
    pub fn set_status_text(&mut self, text: impl Into<String>) {
        self.status_text = text.into();
    }

    /// Get the status text.
    pub fn status_text(&self) -> &str {
        &self.status_text
    }

    /// Set the case sensitivity.
    pub fn set_case_sensitive(&mut self, case_sensitive: bool) {
        self.case_sensitive = case_sensitive;
    }

    /// Set the search direction.
    pub fn set_forward(&mut self, forward: bool) {
        self.forward = forward;
    }

    /// Set whether to search all fields.
    pub fn set_search_all(&mut self, search_all: bool) {
        self.search_all = search_all;
    }

    /// Toggle the database/listing search mode.
    pub fn set_database_search(&mut self, database_search: bool) {
        self.database_search = database_search;
    }

    /// Get the current search options.
    pub fn get_search_options(&self) -> SearchOptions {
        SearchOptions::new(
            &self.text,
            self.database_search,
            self.functions,
            self.comments,
            self.labels,
            self.instr_mnemonics,
            self.instr_operands,
            self.data_mnemonics,
            self.data_operands,
            self.case_sensitive,
            self.forward,
            false, // include_non_loaded_blocks
            self.search_all,
        )
    }
}

impl Default for SearchTextDialog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dialog_defaults() {
        let dialog = SearchTextDialog::new();
        assert_eq!(dialog.text(), "");
        assert!(dialog.status_text().is_empty());
    }

    #[test]
    fn test_dialog_set_text() {
        let mut dialog = SearchTextDialog::new();
        dialog.set_text("hello");
        assert_eq!(dialog.text(), "hello");
    }

    #[test]
    fn test_dialog_get_options() {
        let mut dialog = SearchTextDialog::new();
        dialog.set_text("mov");
        dialog.set_case_sensitive(true);
        dialog.set_forward(false);
        dialog.set_search_all(false);

        let opts = dialog.get_search_options();
        assert_eq!(opts.text(), "mov");
        assert!(opts.is_case_sensitive());
        assert!(!opts.is_forward());
        assert!(!opts.search_all_fields());
    }

    #[test]
    fn test_dialog_status() {
        let mut dialog = SearchTextDialog::new();
        dialog.set_status_text("Searching...");
        assert_eq!(dialog.status_text(), "Searching...");
    }

    #[test]
    fn test_dialog_database_toggle() {
        let mut dialog = SearchTextDialog::new();
        assert!(dialog.get_search_options().is_program_database_search());

        dialog.set_database_search(false);
        assert!(!dialog.get_search_options().is_program_database_search());
    }
}
