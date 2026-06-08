//! All-history action for searching across all label history entries.
//!
//! Ported from Ghidra's `AllHistoryAction` (`AllHistoryAction.java`).
//!
//! This action is available from the menu bar under "Search > Label History..."
//! and allows the user to search all label history entries across the entire
//! program, with optional regex filtering by label name.

use ghidra_core::addr::Address;

use super::dialogs::LabelHistoryTask;
use super::history::{LabelHistoryAction, LabelHistoryEntry};

// ---------------------------------------------------------------------------
// AllHistoryAction
// ---------------------------------------------------------------------------

/// Action that shows all label history across the program.
///
/// This is the Rust equivalent of Ghidra's `AllHistoryAction`. It appears
/// in the Search menu and allows the user to browse or search all label
/// history entries in the program.
///
/// When triggered, it creates a [`LabelHistoryInputDialog`](super::dialogs::LabelHistoryInputDialog)
/// that lets the user optionally filter by label name pattern.
///
/// # Example
///
/// ```
/// use ghidra_features::base::label::AllHistoryAction;
///
/// let action = AllHistoryAction::new();
/// assert_eq!(action.name(), "Show All History");
/// assert_eq!(action.menu_path(), &["Search", "Label History..."]);
/// assert!(action.is_enabled());
/// ```
#[derive(Debug, Clone)]
pub struct AllHistoryAction {
    /// The action name.
    name: String,
    /// The owner (plugin name).
    owner: String,
    /// The menu bar path.
    menu_path: Vec<String>,
    /// The menu group.
    menu_group: String,
    /// Whether the action is currently enabled.
    enabled: bool,
    /// Key binding character (H).
    key_binding: Option<char>,
    /// The accumulated history results after execution.
    results: Vec<LabelHistoryEntry>,
    /// Whether the action has been executed.
    executed: bool,
    /// Optional search filter pattern.
    filter_pattern: Option<String>,
}

impl AllHistoryAction {
    /// Creates a new AllHistoryAction.
    ///
    /// Mirrors `AllHistoryAction(PluginTool tool, String owner)` in Java.
    pub fn new() -> Self {
        Self {
            name: "Show All History".to_string(),
            owner: String::new(),
            menu_path: vec!["Search".to_string(), "Label History...".to_string()],
            menu_group: "search 1".to_string(),
            enabled: true,
            key_binding: Some('H'),
            results: Vec::new(),
            executed: false,
            filter_pattern: None,
        }
    }

    /// Sets the owner (plugin name).
    pub fn with_owner(mut self, owner: impl Into<String>) -> Self {
        self.owner = owner.into();
        self
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the owner.
    pub fn owner(&self) -> &str {
        &self.owner
    }

    /// Returns the menu bar path.
    pub fn menu_path(&self) -> &[String] {
        &self.menu_path
    }

    /// Returns the menu group.
    pub fn menu_group(&self) -> &str {
        &self.menu_group
    }

    /// Returns the key binding character, if any.
    pub fn key_binding(&self) -> Option<char> {
        self.key_binding
    }

    /// Returns whether the action is enabled.
    ///
    /// Mirrors `isEnabledForContext()`: the action is enabled when the
    /// listing context has a valid address.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sets the enabled state.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Checks whether this action is enabled for a specific address.
    ///
    /// Mirrors `isEnabledForContext(ListingActionContext context)`:
    /// the action is enabled when `context.getAddress() != null`.
    pub fn is_enabled_for_context(&self, address: Option<&Address>) -> bool {
        address.is_some()
    }

    /// Sets the optional filter pattern for searching label history.
    ///
    /// When set, only label history entries whose label matches the
    /// pattern will be included in the results.
    pub fn set_filter_pattern(&mut self, pattern: impl Into<String>) {
        self.filter_pattern = Some(pattern.into());
    }

    /// Returns the current filter pattern, if any.
    pub fn filter_pattern(&self) -> Option<&str> {
        self.filter_pattern.as_deref()
    }

    /// Clears the filter pattern.
    pub fn clear_filter_pattern(&mut self) {
        self.filter_pattern = None;
    }

    /// Executes the action with the given history entries.
    ///
    /// This simulates the Java `actionPerformed()` method which creates
    /// a `LabelHistoryInputDialog` and then runs a `LabelHistoryTask`.
    ///
    /// In this Rust port, we accept pre-collected history entries and
    /// apply the filter pattern if set.
    ///
    /// Returns a [`LabelHistoryTask`] that can be used to retrieve
    /// the filtered results.
    pub fn execute(&mut self, all_history: Vec<LabelHistoryEntry>) -> LabelHistoryTask {
        let mut task = LabelHistoryTask::for_all();

        let filtered = if let Some(ref pattern) = self.filter_pattern {
            filter_history(&all_history, pattern)
        } else {
            all_history
        };

        task.set_results(filtered.clone());
        self.results = filtered;
        self.executed = true;

        task
    }

    /// Returns whether the action has been executed.
    pub fn is_executed(&self) -> bool {
        self.executed
    }

    /// Returns the results from the last execution.
    pub fn results(&self) -> &[LabelHistoryEntry] {
        &self.results
    }

    /// Returns the number of results.
    pub fn result_count(&self) -> usize {
        self.results.len()
    }

    /// Returns whether any results were found.
    pub fn has_results(&self) -> bool {
        !self.results.is_empty()
    }

    /// Resets the action state for re-execution.
    pub fn reset(&mut self) {
        self.results.clear();
        self.executed = false;
    }
}

impl Default for AllHistoryAction {
    fn default() -> Self {
        Self::new()
    }
}

/// Filters label history entries by a pattern.
///
/// Performs a case-insensitive substring match on the label name,
/// matching Ghidra's `UserSearchUtils.createSearchPattern()` behavior
/// for non-regex patterns.
fn filter_history(entries: &[LabelHistoryEntry], pattern: &str) -> Vec<LabelHistoryEntry> {
    let pattern_lower = pattern.to_lowercase();
    entries
        .iter()
        .filter(|e| e.label.to_lowercase().contains(&pattern_lower))
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    fn sample_history() -> Vec<LabelHistoryEntry> {
        vec![
            LabelHistoryEntry::new(
                addr(0x1000),
                LabelHistoryAction::Add,
                "main",
                "user1",
                "2024-01-01",
            ),
            LabelHistoryEntry::new(
                addr(0x1000),
                LabelHistoryAction::Rename,
                "main_old",
                "user1",
                "2024-01-02",
            ),
            LabelHistoryEntry::new(
                addr(0x2000),
                LabelHistoryAction::Add,
                "helper",
                "user2",
                "2024-01-03",
            ),
            LabelHistoryEntry::new(
                addr(0x2000),
                LabelHistoryAction::Remove,
                "helper",
                "user2",
                "2024-01-04",
            ),
            LabelHistoryEntry::new(
                addr(0x3000),
                LabelHistoryAction::Add,
                "init_func",
                "user1",
                "2024-01-05",
            ),
        ]
    }

    #[test]
    fn test_action_new() {
        let action = AllHistoryAction::new();
        assert_eq!(action.name(), "Show All History");
        assert_eq!(action.owner(), "");
        assert!(action.is_enabled());
        assert!(!action.is_executed());
        assert!(action.results().is_empty());
    }

    #[test]
    fn test_action_with_owner() {
        let action = AllHistoryAction::new().with_owner("LabelMgrPlugin");
        assert_eq!(action.owner(), "LabelMgrPlugin");
    }

    #[test]
    fn test_action_menu_path() {
        let action = AllHistoryAction::new();
        assert_eq!(action.menu_path(), &["Search", "Label History..."]);
        assert_eq!(action.menu_group(), "search 1");
    }

    #[test]
    fn test_action_key_binding() {
        let action = AllHistoryAction::new();
        assert_eq!(action.key_binding(), Some('H'));
    }

    #[test]
    fn test_action_enabled_for_context() {
        let action = AllHistoryAction::new();
        assert!(action.is_enabled_for_context(Some(&addr(0x1000))));
        assert!(!action.is_enabled_for_context(None));
    }

    #[test]
    fn test_action_set_enabled() {
        let mut action = AllHistoryAction::new();
        assert!(action.is_enabled());
        action.set_enabled(false);
        assert!(!action.is_enabled());
        action.set_enabled(true);
        assert!(action.is_enabled());
    }

    #[test]
    fn test_execute_without_filter() {
        let mut action = AllHistoryAction::new();
        let task = action.execute(sample_history());

        assert!(action.is_executed());
        assert!(task.is_completed());
        assert_eq!(action.result_count(), 5);
        assert!(action.has_results());
    }

    #[test]
    fn test_execute_with_filter() {
        let mut action = AllHistoryAction::new();
        action.set_filter_pattern("main");
        let task = action.execute(sample_history());

        assert!(action.is_executed());
        assert_eq!(action.result_count(), 2); // main and main_old
        assert!(task.is_completed());
        assert_eq!(task.results().len(), 2);
    }

    #[test]
    fn test_execute_filter_case_insensitive() {
        let mut action = AllHistoryAction::new();
        action.set_filter_pattern("HELPER");
        let task = action.execute(sample_history());

        assert_eq!(action.result_count(), 2);
        assert_eq!(task.results().len(), 2);
    }

    #[test]
    fn test_execute_filter_no_match() {
        let mut action = AllHistoryAction::new();
        action.set_filter_pattern("nonexistent");
        let task = action.execute(sample_history());

        assert!(action.is_executed());
        assert!(!action.has_results());
        assert_eq!(action.result_count(), 0);
        assert_eq!(task.results().len(), 0);
    }

    #[test]
    fn test_clear_filter_pattern() {
        let mut action = AllHistoryAction::new();
        action.set_filter_pattern("test");
        assert!(action.filter_pattern().is_some());
        action.clear_filter_pattern();
        assert!(action.filter_pattern().is_none());
    }

    #[test]
    fn test_reset() {
        let mut action = AllHistoryAction::new();
        action.execute(sample_history());
        assert!(action.is_executed());
        assert_eq!(action.result_count(), 5);

        action.reset();
        assert!(!action.is_executed());
        assert_eq!(action.result_count(), 0);
    }

    #[test]
    fn test_filter_history() {
        let entries = sample_history();
        let filtered = filter_history(&entries, "init");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].label, "init_func");
    }

    #[test]
    fn test_filter_history_partial_match() {
        let entries = sample_history();
        let filtered = filter_history(&entries, "ain");
        // "main" and "main_old" both contain "ain"
        assert_eq!(filtered.len(), 2);
    }

    #[test]
    fn test_filter_history_empty_pattern() {
        let entries = sample_history();
        let filtered = filter_history(&entries, "");
        // Empty pattern matches everything
        assert_eq!(filtered.len(), 5);
    }
}
