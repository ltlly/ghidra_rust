//! Find action for the dual decompiler diff view.
//!
//! Ported from Ghidra's `DecompilerDiffViewFindAction` Java class in
//! `ghidra.features.codecompare.decompile`.
//!
//! Provides a Find dialog that searches within the currently focused
//! decompiler panel of a code comparison view. The action is enabled
//! only when the context is a [`DualDecompilerActionContext`].
//!
//! In the original Java, this class extends `DockingAction` and uses
//! `FindDialog` with a `DecompilerSearcher`. In this Rust port we
//! capture the logical state and search behavior without the Swing layer.
//!
//! # Key types
//!
//! - [`FindDialogState`] -- the state of the find dialog for one side
//! - [`DecompilerDiffFindAction`] -- the find action managing dialogs for both sides

use std::sync::{Arc, Mutex};

use super::super::model::ComparisonSide;
use super::super::graphanalysis::Side;

/// The state of a find dialog for one decompiler panel.
///
/// Tracks the search text, match position, and whether the dialog
/// is currently open.
#[derive(Debug, Clone)]
pub struct FindDialogState {
    /// The current search text.
    pub search_text: String,
    /// The currently highlighted match index (0-based).
    pub current_match: usize,
    /// Total number of matches found.
    pub total_matches: usize,
    /// Whether the dialog is currently open.
    pub is_open: bool,
    /// Whether the search is case-sensitive.
    pub case_sensitive: bool,
    /// Whether to use regular expressions.
    pub use_regex: bool,
}

impl FindDialogState {
    /// Create a new find dialog state with defaults.
    pub fn new() -> Self {
        Self {
            search_text: String::new(),
            current_match: 0,
            total_matches: 0,
            is_open: false,
            case_sensitive: false,
            use_regex: false,
        }
    }

    /// Open the dialog with optional pre-filled text.
    pub fn open(&mut self, initial_text: Option<&str>) {
        self.is_open = true;
        if let Some(text) = initial_text {
            if !text.is_empty() {
                self.search_text = text.to_string();
            }
        }
    }

    /// Close the dialog and clear search results.
    pub fn close(&mut self) {
        self.is_open = false;
        self.current_match = 0;
        self.total_matches = 0;
    }

    /// Set the search text and reset match tracking.
    pub fn set_search_text(&mut self, text: impl Into<String>) {
        self.search_text = text.into();
        self.current_match = 0;
        self.total_matches = 0;
    }

    /// Update match information after a search.
    pub fn set_matches(&mut self, total: usize) {
        self.total_matches = total;
        if total == 0 {
            self.current_match = 0;
        } else if self.current_match >= total {
            self.current_match = total - 1;
        }
    }

    /// Navigate to the next match. Wraps around.
    pub fn next_match(&mut self) -> bool {
        if self.total_matches == 0 {
            return false;
        }
        self.current_match = (self.current_match + 1) % self.total_matches;
        true
    }

    /// Navigate to the previous match. Wraps around.
    pub fn previous_match(&mut self) -> bool {
        if self.total_matches == 0 {
            return false;
        }
        self.current_match = if self.current_match == 0 {
            self.total_matches - 1
        } else {
            self.current_match - 1
        };
        true
    }

    /// Whether there are any matches.
    pub fn has_matches(&self) -> bool {
        self.total_matches > 0
    }

    /// Get a status string for display.
    pub fn status_text(&self) -> String {
        if self.search_text.is_empty() {
            return String::new();
        }
        if self.total_matches == 0 {
            return "No matches found".to_string();
        }
        format!(
            "Match {} of {}",
            self.current_match + 1,
            self.total_matches
        )
    }
}

impl Default for FindDialogState {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of performing a find operation.
#[derive(Debug, Clone)]
pub struct FindResult {
    /// The match index (0-based).
    pub match_index: usize,
    /// The line number where the match was found.
    pub line_number: usize,
    /// The column start of the match.
    pub column_start: usize,
    /// The column end of the match (exclusive).
    pub column_end: usize,
    /// The matched text.
    pub matched_text: String,
}

/// Find action for the dual decompiler diff view.
///
/// Manages find dialogs for both the left and right decompiler panels.
/// When the user invokes Find, the dialog is shown for the currently
/// focused side. The action is only enabled when the context is a
/// dual decompiler context.
///
/// Ported from Ghidra's `DecompilerDiffViewFindAction` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::decompile::find_action::*;
/// use ghidra_features::codecompare::graphanalysis::Side;
///
/// let mut action = DecompilerDiffFindAction::new("MyPlugin");
///
/// // Open find dialog for the left side
/// action.open_find(Side::Left, Some("main"));
/// let state = action.get_state(Side::Left);
/// assert!(state.is_open);
/// assert_eq!(state.search_text, "main");
///
/// // Perform a search
/// action.set_matches(Side::Left, 3);
/// let state = action.get_state(Side::Left);
/// assert_eq!(state.total_matches, 3);
/// ```
pub struct DecompilerDiffFindAction {
    /// The owner (plugin) name.
    owner: String,
    /// Find dialog state for the left side.
    left_state: FindDialogState,
    /// Find dialog state for the right side.
    right_state: FindDialogState,
    /// Whether the action is enabled.
    enabled: bool,
    /// The action name.
    name: String,
    /// Keyboard shortcut description.
    key_binding: Option<String>,
}

impl DecompilerDiffFindAction {
    /// Create a new find action.
    pub fn new(owner: impl Into<String>) -> Self {
        Self {
            owner: owner.into(),
            left_state: FindDialogState::new(),
            right_state: FindDialogState::new(),
            enabled: true,
            name: "Find".to_string(),
            key_binding: Some("Ctrl+F".to_string()),
        }
    }

    /// Get the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the owner name.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Get the keyboard shortcut.
    pub fn key_binding(&self) -> Option<&str> {
        self.key_binding.as_deref()
    }

    /// Check if the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the find dialog state for the given side.
    pub fn get_state(&self, side: Side) -> &FindDialogState {
        match side {
            Side::Left => &self.left_state,
            Side::Right => &self.right_state,
        }
    }

    /// Get a mutable reference to the find dialog state for the given side.
    pub fn get_state_mut(&mut self, side: Side) -> &mut FindDialogState {
        match side {
            Side::Left => &mut self.left_state,
            Side::Right => &mut self.right_state,
        }
    }

    /// Open the find dialog for the given side.
    ///
    /// If `initial_text` is provided, it will be pre-filled in the search field.
    pub fn open_find(&mut self, side: Side, initial_text: Option<&str>) {
        self.get_state_mut(side).open(initial_text);
    }

    /// Close the find dialog for the given side and clear results.
    pub fn close_find(&mut self, side: Side) {
        self.get_state_mut(side).close();
    }

    /// Set the search text for the given side.
    pub fn set_search_text(&mut self, side: Side, text: impl Into<String>) {
        self.get_state_mut(side).set_search_text(text);
    }

    /// Update the match count for the given side after performing a search.
    pub fn set_matches(&mut self, side: Side, total: usize) {
        self.get_state_mut(side).set_matches(total);
    }

    /// Navigate to the next match on the given side.
    ///
    /// Returns true if navigation occurred.
    pub fn next_match(&mut self, side: Side) -> bool {
        self.get_state_mut(side).next_match()
    }

    /// Navigate to the previous match on the given side.
    ///
    /// Returns true if navigation occurred.
    pub fn previous_match(&mut self, side: Side) -> bool {
        self.get_state_mut(side).previous_match()
    }

    /// Perform a find operation on the given text.
    ///
    /// Returns all matches found in the text.
    pub fn find_in_text(
        &self,
        side: Side,
        text: &str,
    ) -> Vec<FindResult> {
        let state = self.get_state(side);
        if state.search_text.is_empty() {
            return Vec::new();
        }

        let search_text = if state.case_sensitive {
            state.search_text.clone()
        } else {
            state.search_text.to_lowercase()
        };

        let mut results = Vec::new();
        for (line_num, line) in text.lines().enumerate() {
            let haystack = if state.case_sensitive {
                line.to_string()
            } else {
                line.to_lowercase()
            };

            let mut start = 0;
            while let Some(pos) = haystack[start..].find(&search_text) {
                let abs_pos = start + pos;
                results.push(FindResult {
                    match_index: results.len(),
                    line_number: line_num,
                    column_start: abs_pos,
                    column_end: abs_pos + search_text.len(),
                    matched_text: line[abs_pos..abs_pos + search_text.len()].to_string(),
                });
                start = abs_pos + 1;
            }
        }

        results
    }

    /// Dispose of this action (close both dialogs).
    pub fn dispose(&mut self) {
        self.left_state.close();
        self.right_state.close();
        self.enabled = false;
    }
}

/// A simple find action listener that tracks find operations.
#[derive(Debug, Default)]
pub struct TrackingFindListener {
    /// Number of find operations performed.
    pub find_count: std::sync::Mutex<usize>,
    /// Number of navigation operations.
    pub nav_count: std::sync::Mutex<usize>,
}

impl TrackingFindListener {
    /// Create a new tracking find listener.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a find operation.
    pub fn record_find(&self) {
        *self.find_count.lock().unwrap() += 1;
    }

    /// Record a navigation operation.
    pub fn record_nav(&self) {
        *self.nav_count.lock().unwrap() += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- FindDialogState tests ---

    #[test]
    fn test_find_dialog_state_new() {
        let state = FindDialogState::new();
        assert!(state.search_text.is_empty());
        assert_eq!(state.current_match, 0);
        assert_eq!(state.total_matches, 0);
        assert!(!state.is_open);
        assert!(!state.case_sensitive);
        assert!(!state.use_regex);
    }

    #[test]
    fn test_find_dialog_state_open() {
        let mut state = FindDialogState::new();
        state.open(Some("test"));
        assert!(state.is_open);
        assert_eq!(state.search_text, "test");
    }

    #[test]
    fn test_find_dialog_state_open_empty() {
        let mut state = FindDialogState::new();
        state.open(None);
        assert!(state.is_open);
        assert!(state.search_text.is_empty());
    }

    #[test]
    fn test_find_dialog_state_close() {
        let mut state = FindDialogState::new();
        state.open(Some("test"));
        state.set_matches(5);
        state.close();
        assert!(!state.is_open);
        assert_eq!(state.current_match, 0);
        assert_eq!(state.total_matches, 0);
    }

    #[test]
    fn test_find_dialog_state_set_search_text() {
        let mut state = FindDialogState::new();
        state.set_search_text("hello");
        assert_eq!(state.search_text, "hello");
        assert_eq!(state.current_match, 0);
    }

    #[test]
    fn test_find_dialog_state_set_matches() {
        let mut state = FindDialogState::new();
        state.set_matches(10);
        assert_eq!(state.total_matches, 10);
    }

    #[test]
    fn test_find_dialog_state_next_match() {
        let mut state = FindDialogState::new();
        state.set_matches(3);
        assert!(state.next_match());
        assert_eq!(state.current_match, 1);
        assert!(state.next_match());
        assert_eq!(state.current_match, 2);
        assert!(state.next_match());
        assert_eq!(state.current_match, 0); // wraps
    }

    #[test]
    fn test_find_dialog_state_previous_match() {
        let mut state = FindDialogState::new();
        state.set_matches(3);
        assert!(state.previous_match());
        assert_eq!(state.current_match, 2); // wraps
        assert!(state.previous_match());
        assert_eq!(state.current_match, 1);
    }

    #[test]
    fn test_find_dialog_state_no_matches() {
        let mut state = FindDialogState::new();
        assert!(!state.next_match());
        assert!(!state.previous_match());
        assert!(!state.has_matches());
    }

    #[test]
    fn test_find_dialog_state_has_matches() {
        let mut state = FindDialogState::new();
        state.set_matches(5);
        assert!(state.has_matches());
    }

    #[test]
    fn test_find_dialog_state_status_text() {
        let mut state = FindDialogState::new();
        assert_eq!(state.status_text(), "");

        state.set_search_text("test");
        assert_eq!(state.status_text(), "No matches found");

        state.set_matches(5);
        state.current_match = 2;
        assert_eq!(state.status_text(), "Match 3 of 5");
    }

    #[test]
    fn test_find_dialog_state_set_matches_clamp() {
        let mut state = FindDialogState::new();
        state.set_matches(3);
        state.current_match = 5;
        state.set_matches(3);
        assert_eq!(state.current_match, 2); // clamped
    }

    // --- DecompilerDiffFindAction tests ---

    #[test]
    fn test_find_action_new() {
        let action = DecompilerDiffFindAction::new("TestPlugin");
        assert_eq!(action.name(), "Find");
        assert_eq!(action.owner(), "TestPlugin");
        assert_eq!(action.key_binding(), Some("Ctrl+F"));
        assert!(action.is_enabled());
    }

    #[test]
    fn test_find_action_open_find() {
        let mut action = DecompilerDiffFindAction::new("Test");
        action.open_find(Side::Left, Some("main"));

        let state = action.get_state(Side::Left);
        assert!(state.is_open);
        assert_eq!(state.search_text, "main");
    }

    #[test]
    fn test_find_action_close_find() {
        let mut action = DecompilerDiffFindAction::new("Test");
        action.open_find(Side::Right, Some("test"));
        action.close_find(Side::Right);

        let state = action.get_state(Side::Right);
        assert!(!state.is_open);
    }

    #[test]
    fn test_find_action_set_search_text() {
        let mut action = DecompilerDiffFindAction::new("Test");
        action.set_search_text(Side::Left, "hello world");
        assert_eq!(action.get_state(Side::Left).search_text, "hello world");
    }

    #[test]
    fn test_find_action_set_matches() {
        let mut action = DecompilerDiffFindAction::new("Test");
        action.set_matches(Side::Left, 10);
        assert_eq!(action.get_state(Side::Left).total_matches, 10);
    }

    #[test]
    fn test_find_action_next_match() {
        let mut action = DecompilerDiffFindAction::new("Test");
        action.set_matches(Side::Left, 5);
        assert!(action.next_match(Side::Left));
        assert_eq!(action.get_state(Side::Left).current_match, 1);
    }

    #[test]
    fn test_find_action_previous_match() {
        let mut action = DecompilerDiffFindAction::new("Test");
        action.set_matches(Side::Right, 5);
        assert!(action.previous_match(Side::Right));
        assert_eq!(action.get_state(Side::Right).current_match, 4);
    }

    #[test]
    fn test_find_action_find_in_text() {
        let action = DecompilerDiffFindAction::new("Test");
        let mut action = action;
        action.set_search_text(Side::Left, "int");

        let text = "int x = 5;\nint y = 10;\nfloat z = 3.14;";
        let results = action.find_in_text(Side::Left, text);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].line_number, 0);
        assert_eq!(results[0].column_start, 0);
        assert_eq!(results[1].line_number, 1);
    }

    #[test]
    fn test_find_action_find_in_text_no_match() {
        let mut action = DecompilerDiffFindAction::new("Test");
        action.set_search_text(Side::Left, "xyz");

        let text = "int x = 5;";
        let results = action.find_in_text(Side::Left, text);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_find_action_find_in_text_empty_search() {
        let action = DecompilerDiffFindAction::new("Test");
        let text = "int x = 5;";
        let results = action.find_in_text(Side::Left, text);
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_find_action_find_in_text_multiple_per_line() {
        let mut action = DecompilerDiffFindAction::new("Test");
        action.set_search_text(Side::Left, "x");

        let text = "x = x + x;";
        let results = action.find_in_text(Side::Left, text);
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn test_find_action_enabled() {
        let mut action = DecompilerDiffFindAction::new("Test");
        assert!(action.is_enabled());

        action.set_enabled(false);
        assert!(!action.is_enabled());
    }

    #[test]
    fn test_find_action_dispose() {
        let mut action = DecompilerDiffFindAction::new("Test");
        action.open_find(Side::Left, Some("test"));
        action.open_find(Side::Right, Some("test"));
        action.dispose();

        assert!(!action.is_enabled());
        assert!(!action.get_state(Side::Left).is_open);
        assert!(!action.get_state(Side::Right).is_open);
    }

    #[test]
    fn test_find_action_default_state() {
        let action = DecompilerDiffFindAction::new("Test");
        assert!(!action.get_state(Side::Left).is_open);
        assert!(!action.get_state(Side::Right).is_open);
        assert!(action.get_state(Side::Left).search_text.is_empty());
    }

    // --- TrackingFindListener tests ---

    #[test]
    fn test_tracking_find_listener() {
        let listener = TrackingFindListener::new();
        assert_eq!(*listener.find_count.lock().unwrap(), 0);
        assert_eq!(*listener.nav_count.lock().unwrap(), 0);

        listener.record_find();
        listener.record_find();
        listener.record_nav();

        assert_eq!(*listener.find_count.lock().unwrap(), 2);
        assert_eq!(*listener.nav_count.lock().unwrap(), 1);
    }
}
