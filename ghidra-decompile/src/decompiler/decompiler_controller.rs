//! Decompiler controller -- manages decompiler session state.
//!
//! Ports Ghidra's `ghidra.app.decompiler.component.DecompilerController`,
//! `DecompilerPanel`, `DecompilerProgramListener`, and related types.

use std::collections::HashMap;

use super::clang_node::ClangNodeId;
use super::component::DecompileData;

/// Manages the decompiler session: current function, decompile data,
/// and panel state.
///
/// Port of `ghidra.app.decompiler.component.DecompilerController`.
#[derive(Debug)]
pub struct DecompilerController {
    /// Current function entry address.
    current_address: Option<u64>,
    /// Cached decompile data keyed by function entry address.
    cache: HashMap<u64, DecompileData>,
    /// Maximum cache size.
    max_cache_size: usize,
    /// Whether a decompile is currently in progress.
    decompiling: bool,
    /// The program name (for display purposes).
    program_name: Option<String>,
    /// Registered listeners.
    listeners: Vec<Box<dyn DecompilerControllerListener>>,
}

/// Listener for decompiler controller events.
pub trait DecompilerControllerListener: Send + Sync + std::fmt::Debug {
    /// Called when a function has been decompiled.
    fn on_decompile_complete(&self, address: u64, data: &DecompileData);

    /// Called when the current function changes.
    fn on_function_changed(&self, old_address: Option<u64>, new_address: Option<u64>);

    /// Called when a decompile error occurs.
    fn on_error(&self, address: u64, error: &str);
}

impl DecompilerController {
    /// Create a new decompiler controller.
    pub fn new() -> Self {
        Self {
            current_address: None,
            cache: HashMap::new(),
            max_cache_size: 16,
            decompiling: false,
            program_name: None,
            listeners: Vec::new(),
        }
    }

    /// Set the current program name.
    pub fn set_program(&mut self, name: impl Into<String>) {
        self.program_name = Some(name.into());
    }

    /// Get the current program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Request decompilation of a function.
    pub fn decompile(&mut self, function_entry: u64) {
        let old = self.current_address;
        self.current_address = Some(function_entry);
        self.decompiling = true;

        for listener in &self.listeners {
            listener.on_function_changed(old, Some(function_entry));
        }
    }

    /// Set decompile results for a function.
    pub fn set_results(&mut self, function_entry: u64, data: DecompileData) {
        self.decompiling = false;

        // Evict oldest entry if cache is full.
        if self.cache.len() >= self.max_cache_size {
            if let Some((&oldest_key, _)) = self.cache.iter().next() {
                self.cache.remove(&oldest_key);
            }
        }

        self.cache.insert(function_entry, data);

        if let Some(data) = self.cache.get(&function_entry) {
            for listener in &self.listeners {
                listener.on_decompile_complete(function_entry, data);
            }
        }
    }

    /// Report a decompile error.
    pub fn report_error(&mut self, function_entry: u64, error: &str) {
        self.decompiling = false;
        for listener in &self.listeners {
            listener.on_error(function_entry, error);
        }
    }

    /// Get the current function entry address.
    pub fn current_address(&self) -> Option<u64> {
        self.current_address
    }

    /// Get cached decompile data for a function.
    pub fn get_data(&self, function_entry: u64) -> Option<&DecompileData> {
        self.cache.get(&function_entry)
    }

    /// Whether a decompile is in progress.
    pub fn is_decompiling(&self) -> bool {
        self.decompiling
    }

    /// Clear the cache.
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Set the maximum cache size.
    pub fn set_max_cache_size(&mut self, size: usize) {
        self.max_cache_size = size;
        // Evict entries if over limit.
        while self.cache.len() > self.max_cache_size {
            if let Some((&oldest_key, _)) = self.cache.iter().next() {
                self.cache.remove(&oldest_key);
            }
        }
    }

    /// Register a listener.
    pub fn add_listener(&mut self, listener: Box<dyn DecompilerControllerListener>) {
        self.listeners.push(listener);
    }

    /// Get the number of cached entries.
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

impl Default for DecompilerController {
    fn default() -> Self {
        Self::new()
    }
}

/// Cursor position within the decompiler output.
///
/// Port of `ghidra.app.decompiler.DecompilerCursorPosition`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecompilerCursorPosition {
    /// The line number (0-based).
    pub line: usize,
    /// The column within the line (0-based).
    pub col: usize,
    /// The character offset from the start of the decompiled text.
    pub char_offset: usize,
    /// The node id at the cursor position (if any).
    pub node_id: Option<ClangNodeId>,
    /// The address associated with the cursor position.
    pub address: Option<u64>,
}

impl DecompilerCursorPosition {
    /// Create a new cursor position.
    pub fn new(line: usize, col: usize) -> Self {
        Self {
            line,
            col,
            char_offset: 0,
            node_id: None,
            address: None,
        }
    }

    /// Set the character offset.
    pub fn with_offset(mut self, offset: usize) -> Self {
        self.char_offset = offset;
        self
    }

    /// Set the node id.
    pub fn with_node_id(mut self, node_id: ClangNodeId) -> Self {
        self.node_id = Some(node_id);
        self
    }

    /// Set the address.
    pub fn with_address(mut self, address: u64) -> Self {
        self.address = Some(address);
        self
    }

    /// Whether this position has a node id.
    pub fn has_node(&self) -> bool {
        self.node_id.is_some()
    }

    /// Whether this position has an associated address.
    pub fn has_address(&self) -> bool {
        self.address.is_some()
    }
}

impl Default for DecompilerCursorPosition {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

impl std::fmt::Display for DecompilerCursorPosition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line={},col={}", self.line, self.col)
    }
}

/// Results of a search within decompiler output.
///
/// Port of `ghidra.app.decompiler.DecompilerSearchResults`.
#[derive(Debug, Clone, Default)]
pub struct DecompilerSearchResults {
    /// All match positions.
    pub matches: Vec<DecompilerSearchMatch>,
    /// The query string.
    pub query: String,
    /// Index of the currently selected match.
    pub current_index: Option<usize>,
}

/// A single search match within decompiler output.
#[derive(Debug, Clone)]
pub struct DecompilerSearchMatch {
    /// The line number of the match (0-based).
    pub line: usize,
    /// The column of the match start (0-based).
    pub col: usize,
    /// The length of the match in characters.
    pub length: usize,
    /// The matched text.
    pub text: String,
    /// The character offset from the start of the decompiled text.
    pub char_offset: usize,
}

impl DecompilerSearchResults {
    /// Create empty search results.
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            matches: Vec::new(),
            query: query.into(),
            current_index: None,
        }
    }

    /// Add a match.
    pub fn add_match(&mut self, m: DecompilerSearchMatch) {
        self.matches.push(m);
        if self.current_index.is_none() {
            self.current_index = Some(0);
        }
    }

    /// Get the number of matches.
    pub fn match_count(&self) -> usize {
        self.matches.len()
    }

    /// Get the current match.
    pub fn current_match(&self) -> Option<&DecompilerSearchMatch> {
        self.current_index.and_then(|i| self.matches.get(i))
    }

    /// Advance to the next match.
    pub fn next_match(&mut self) -> Option<&DecompilerSearchMatch> {
        if self.matches.is_empty() {
            return None;
        }
        let idx = self.current_index.map_or(0, |i| (i + 1) % self.matches.len());
        self.current_index = Some(idx);
        self.matches.get(idx)
    }

    /// Go to the previous match.
    pub fn prev_match(&mut self) -> Option<&DecompilerSearchMatch> {
        if self.matches.is_empty() {
            return None;
        }
        let idx = self.current_index.map_or(0, |i| {
            if i == 0 { self.matches.len() - 1 } else { i - 1 }
        });
        self.current_index = Some(idx);
        self.matches.get(idx)
    }

    /// Whether there are any matches.
    pub fn has_matches(&self) -> bool {
        !self.matches.is_empty()
    }
}

/// Searcher for decompiler output.
///
/// Port of `ghidra.app.decompiler.DecompilerSearcher`.
#[derive(Debug, Clone)]
pub struct DecompilerSearcher {
    /// The search query.
    query: String,
    /// Whether to search case-sensitively.
    case_sensitive: bool,
    /// Whether to use regular expressions.
    use_regex: bool,
    /// The text to search within.
    text: String,
}

impl DecompilerSearcher {
    /// Create a new searcher.
    pub fn new(query: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            query: query.into(),
            case_sensitive: true,
            use_regex: false,
            text: text.into(),
        }
    }

    /// Set case sensitivity.
    pub fn case_sensitive(mut self, sensitive: bool) -> Self {
        self.case_sensitive = sensitive;
        self
    }

    /// Set regex mode.
    pub fn use_regex(mut self, use_regex: bool) -> Self {
        self.use_regex = use_regex;
        self
    }

    /// Execute the search and return results.
    pub fn search(&self) -> DecompilerSearchResults {
        let mut results = DecompilerSearchResults::new(&self.query);

        if self.query.is_empty() {
            return results;
        }

        let (haystack, needle) = if self.case_sensitive {
            (self.text.clone(), self.query.clone())
        } else {
            (self.text.to_lowercase(), self.query.to_lowercase())
        };

        let mut char_offset = 0;
        for (line_num, line) in haystack.split('\n').enumerate() {
            let mut col = 0;
            while let Some(pos) = line[col..].find(&needle) {
                let actual_col = col + pos;
                let matched_text = &self.text[char_offset + actual_col..char_offset + actual_col + needle.len()];
                results.add_match(DecompilerSearchMatch {
                    line: line_num,
                    col: actual_col,
                    length: needle.len(),
                    text: matched_text.to_string(),
                    char_offset: char_offset + actual_col,
                });
                col = actual_col + 1;
            }
            char_offset += line.len() + 1; // +1 for newline
        }

        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_controller_new() {
        let ctrl = DecompilerController::new();
        assert!(ctrl.current_address().is_none());
        assert!(!ctrl.is_decompiling());
        assert_eq!(ctrl.cache_size(), 0);
    }

    #[test]
    fn test_controller_decompile() {
        let mut ctrl = DecompilerController::new();
        ctrl.decompile(0x1000);
        assert!(ctrl.is_decompiling());
        assert_eq!(ctrl.current_address(), Some(0x1000));
    }

    #[test]
    fn test_controller_set_results() {
        let mut ctrl = DecompilerController::new();
        ctrl.decompile(0x1000);
        ctrl.set_results(0x1000, DecompileData::new(0x1000));
        assert!(!ctrl.is_decompiling());
        assert_eq!(ctrl.cache_size(), 1);
        assert!(ctrl.get_data(0x1000).is_some());
    }

    #[test]
    fn test_controller_cache_eviction() {
        let mut ctrl = DecompilerController::new();
        ctrl.set_max_cache_size(2);
        ctrl.set_results(0x1000, DecompileData::new(0x1000));
        ctrl.set_results(0x2000, DecompileData::new(0x2000));
        ctrl.set_results(0x3000, DecompileData::new(0x3000));
        assert!(ctrl.cache_size() <= 2);
    }

    #[test]
    fn test_controller_clear_cache() {
        let mut ctrl = DecompilerController::new();
        ctrl.set_results(0x1000, DecompileData::new(0x1000));
        ctrl.clear_cache();
        assert_eq!(ctrl.cache_size(), 0);
    }

    #[test]
    fn test_cursor_position_new() {
        let pos = DecompilerCursorPosition::new(5, 10);
        assert_eq!(pos.line, 5);
        assert_eq!(pos.col, 10);
        assert!(!pos.has_node());
        assert!(!pos.has_address());
    }

    #[test]
    fn test_cursor_position_builder() {
        let pos = DecompilerCursorPosition::new(1, 2)
            .with_offset(100)
            .with_address(0x4000);
        assert_eq!(pos.char_offset, 100);
        assert_eq!(pos.address, Some(0x4000));
        assert!(pos.has_address());
    }

    #[test]
    fn test_cursor_position_display() {
        let pos = DecompilerCursorPosition::new(10, 5);
        assert_eq!(format!("{}", pos), "line=10,col=5");
    }

    #[test]
    fn test_search_results_basics() {
        let mut results = DecompilerSearchResults::new("test");
        assert!(!results.has_matches());
        assert_eq!(results.match_count(), 0);

        results.add_match(DecompilerSearchMatch {
            line: 0, col: 5, length: 4, text: "test".into(), char_offset: 5,
        });
        assert!(results.has_matches());
        assert_eq!(results.match_count(), 1);
        assert_eq!(results.current_match().unwrap().col, 5);
    }

    #[test]
    fn test_search_results_navigation() {
        let mut results = DecompilerSearchResults::new("x");
        results.add_match(DecompilerSearchMatch {
            line: 0, col: 0, length: 1, text: "x".into(), char_offset: 0,
        });
        results.add_match(DecompilerSearchMatch {
            line: 1, col: 3, length: 1, text: "x".into(), char_offset: 10,
        });

        let m = results.next_match().unwrap();
        assert_eq!(m.line, 1);
        let m = results.next_match().unwrap();
        assert_eq!(m.line, 0); // wraps around
        let m = results.prev_match().unwrap();
        assert_eq!(m.line, 1); // wraps back
    }

    #[test]
    fn test_searcher_basic() {
        let searcher = DecompilerSearcher::new("main", "int main() {\n  return 0;\n}");
        let results = searcher.search();
        assert_eq!(results.match_count(), 1);
        assert_eq!(results.current_match().unwrap().line, 0);
        assert_eq!(results.current_match().unwrap().col, 4);
    }

    #[test]
    fn test_searcher_case_insensitive() {
        let searcher = DecompilerSearcher::new("MAIN", "int main() {\n  return 0;\n}")
            .case_sensitive(false);
        let results = searcher.search();
        assert_eq!(results.match_count(), 1);
    }

    #[test]
    fn test_searcher_case_sensitive_no_match() {
        let searcher = DecompilerSearcher::new("MAIN", "int main() {}")
            .case_sensitive(true);
        let results = searcher.search();
        assert_eq!(results.match_count(), 0);
    }

    #[test]
    fn test_searcher_multiple_matches() {
        let searcher = DecompilerSearcher::new("x", "x = x + x;");
        let results = searcher.search();
        assert_eq!(results.match_count(), 3);
    }

    #[test]
    fn test_searcher_empty_query() {
        let searcher = DecompilerSearcher::new("", "int main() {}");
        let results = searcher.search();
        assert_eq!(results.match_count(), 0);
    }
}
