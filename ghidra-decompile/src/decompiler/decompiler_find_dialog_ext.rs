//! Decompiler find dialog extension types.
//!
//! Ports additional types from `ghidra.app.decompiler.component.DecompilerFindDialog`
//! and related classes not yet covered.

use serde::{Deserialize, Serialize};

/// The mode of search in the decompiler find dialog.
///
/// Port of the search mode enumeration from `DecompilerFindDialog`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DecompilerSearchMode {
    /// Search in the decompiled C code text.
    DecompiledCode,
    /// Search in the function names.
    FunctionName,
    /// Search in variable names.
    VariableName,
    /// Search in comments.
    Comment,
    /// Search in data type names.
    TypeName,
}

impl Default for DecompilerSearchMode {
    fn default() -> Self {
        Self::DecompiledCode
    }
}

/// Options for a decompiler find/search operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompilerFindOptions {
    /// The search mode.
    pub mode: DecompilerSearchMode,
    /// The search pattern (plain text or regex).
    pub pattern: String,
    /// Whether the search is case-sensitive.
    pub case_sensitive: bool,
    /// Whether the pattern is a regular expression.
    pub regex: bool,
    /// Whether to search backwards.
    pub backwards: bool,
    /// Whether to wrap around at the end of the function.
    pub wrap_around: bool,
}

impl DecompilerFindOptions {
    /// Create new find options with defaults.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            mode: DecompilerSearchMode::default(),
            pattern: pattern.into(),
            case_sensitive: true,
            regex: false,
            backwards: false,
            wrap_around: true,
        }
    }

    /// Set the search mode.
    pub fn with_mode(mut self, mode: DecompilerSearchMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set case sensitivity.
    pub fn case_sensitive(mut self, cs: bool) -> Self {
        self.case_sensitive = cs;
        self
    }

    /// Set regex mode.
    pub fn regex(mut self, regex: bool) -> Self {
        self.regex = regex;
        self
    }

    /// Set backward search.
    pub fn backwards(mut self, backwards: bool) -> Self {
        self.backwards = backwards;
        self
    }

    /// Check if the pattern matches a text line.
    pub fn matches(&self, text: &str) -> bool {
        let haystack = if self.case_sensitive {
            text.to_string()
        } else {
            text.to_lowercase()
        };
        let needle = if self.case_sensitive {
            self.pattern.clone()
        } else {
            self.pattern.to_lowercase()
        };

        if self.regex {
            if let Ok(re) = regex::RegexBuilder::new(&self.pattern)
                .case_insensitive(!self.case_sensitive)
                .build()
            {
                re.is_match(text)
            } else {
                false
            }
        } else {
            haystack.contains(&needle)
        }
    }
}

/// A single match result from the decompiler find dialog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompilerFindMatch {
    /// Line number (0-based).
    pub line: usize,
    /// Column offset within the line.
    pub column: usize,
    /// Length of the match in characters.
    pub length: usize,
    /// The matched text.
    pub text: String,
    /// The search mode that produced this match.
    pub mode: DecompilerSearchMode,
}

impl DecompilerFindMatch {
    /// Create a new find match.
    pub fn new(line: usize, column: usize, text: impl Into<String>, mode: DecompilerSearchMode) -> Self {
        let text = text.into();
        let length = text.len();
        Self {
            line,
            column,
            length,
            text,
            mode,
        }
    }

    /// End column of the match.
    pub fn end_column(&self) -> usize {
        self.column + self.length
    }
}

/// Results from a decompiler find operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecompilerFindResults {
    /// All matches found.
    pub matches: Vec<DecompilerFindMatch>,
    /// Index of the currently focused match.
    pub current_index: Option<usize>,
    /// Total number of lines searched.
    pub lines_searched: usize,
}

impl DecompilerFindResults {
    /// Create empty find results.
    pub fn new() -> Self {
        Self {
            matches: Vec::new(),
            current_index: None,
            lines_searched: 0,
        }
    }

    /// Number of matches found.
    pub fn match_count(&self) -> usize {
        self.matches.len()
    }

    /// Get the current match.
    pub fn current_match(&self) -> Option<&DecompilerFindMatch> {
        self.current_index.and_then(|i| self.matches.get(i))
    }

    /// Move to the next match.
    pub fn next(&mut self) -> Option<&DecompilerFindMatch> {
        if self.matches.is_empty() {
            return None;
        }
        let idx = self.current_index.map_or(0, |i| (i + 1) % self.matches.len());
        self.current_index = Some(idx);
        self.current_match()
    }

    /// Move to the previous match.
    pub fn previous(&mut self) -> Option<&DecompilerFindMatch> {
        if self.matches.is_empty() {
            return None;
        }
        let idx = self.current_index.map_or(0, |i| {
            if i == 0 {
                self.matches.len() - 1
            } else {
                i - 1
            }
        });
        self.current_index = Some(idx);
        self.current_match()
    }

    /// Add a match.
    pub fn add_match(&mut self, m: DecompilerFindMatch) {
        self.matches.push(m);
        if self.current_index.is_none() {
            self.current_index = Some(0);
        }
    }
}

impl Default for DecompilerFindResults {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_options_new() {
        let opts = DecompilerFindOptions::new("test");
        assert_eq!(opts.pattern, "test");
        assert!(opts.case_sensitive);
        assert!(!opts.regex);
        assert!(opts.wrap_around);
    }

    #[test]
    fn test_find_options_matches() {
        let opts = DecompilerFindOptions::new("main");
        assert!(opts.matches("int main() {}"));
        assert!(!opts.matches("int foo() {}"));
    }

    #[test]
    fn test_find_options_case_insensitive() {
        let opts = DecompilerFindOptions::new("MAIN").case_sensitive(false);
        assert!(opts.matches("int main() {}"));
    }

    #[test]
    fn test_find_options_regex() {
        let opts = DecompilerFindOptions::new(r"\bmain\b").regex(true);
        assert!(opts.matches("int main() {}"));
        assert!(!opts.matches("int domain() {}"));
    }

    #[test]
    fn test_find_match() {
        let m = DecompilerFindMatch::new(5, 10, "main", DecompilerSearchMode::DecompiledCode);
        assert_eq!(m.line, 5);
        assert_eq!(m.column, 10);
        assert_eq!(m.end_column(), 14);
    }

    #[test]
    fn test_find_results() {
        let mut results = DecompilerFindResults::new();
        assert_eq!(results.match_count(), 0);
        assert!(results.current_match().is_none());

        results.add_match(DecompilerFindMatch::new(0, 4, "main", DecompilerSearchMode::DecompiledCode));
        results.add_match(DecompilerFindMatch::new(5, 8, "main", DecompilerSearchMode::DecompiledCode));
        assert_eq!(results.match_count(), 2);
        assert!(results.current_match().is_some());

        results.next();
        assert_eq!(results.current_index, Some(1));

        results.next(); // wraps
        assert_eq!(results.current_index, Some(0));

        results.previous(); // wraps to end
        assert_eq!(results.current_index, Some(1));
    }

    #[test]
    fn test_search_mode_default() {
        assert_eq!(DecompilerSearchMode::default(), DecompilerSearchMode::DecompiledCode);
    }
}
