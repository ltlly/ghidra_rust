//! Query data for GoTo navigation and search operations.
//!
//! Ported from `ghidra.app.services.QueryData`. Encapsulates a query string
//! along with case-sensitivity and wildcard metadata. Supports `*` (any
//! substring) and `?` (any single character) wildcards, mirroring the Java
//! implementation.

use std::fmt;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Wildcard character matching any substring (zero or more characters).
const ANY_STRING_WILDCARD: char = '*';

/// Wildcard character matching exactly one character.
const ANY_CHAR_WILDCARD: char = '?';

// ---------------------------------------------------------------------------
// QueryData
// ---------------------------------------------------------------------------

/// Encapsulates a GoTo / search query string with associated options.
///
/// # Examples
///
/// ```
/// use ghidra_features::services::query_data::QueryData;
///
/// let q = QueryData::new("kernel32.*").with_case_sensitive(false);
/// assert!(q.is_wildcard());
/// assert!(!q.is_case_sensitive());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct QueryData {
    /// The raw query string entered by the user.
    query_string: String,
    /// Whether the search should be case-sensitive.
    case_sensitive: bool,
    /// Whether to include dynamic (auto-generated) labels in results.
    include_dynamic_labels: bool,
}

impl QueryData {
    // -- Constructors -------------------------------------------------------

    /// Create a new query with default options (case-insensitive, dynamic
    /// labels included).
    pub fn new(query: impl Into<String>) -> Self {
        Self {
            query_string: query.into(),
            case_sensitive: false,
            include_dynamic_labels: true,
        }
    }

    /// Create a query with explicit case-sensitivity and dynamic-label
    /// settings.
    pub fn with_options(
        query: impl Into<String>,
        case_sensitive: bool,
        include_dynamic_labels: bool,
    ) -> Self {
        Self {
            query_string: query.into(),
            case_sensitive,
            include_dynamic_labels,
        }
    }

    // -- Builder-style setters ----------------------------------------------

    /// Return a copy of this query with the case-sensitivity flag set.
    pub fn with_case_sensitive(mut self, yes: bool) -> Self {
        self.case_sensitive = yes;
        self
    }

    /// Return a copy of this query with the dynamic-labels flag set.
    pub fn with_include_dynamic_labels(mut self, yes: bool) -> Self {
        self.include_dynamic_labels = yes;
        self
    }

    // -- Accessors ----------------------------------------------------------

    /// The raw query string.
    pub fn query_string(&self) -> &str {
        &self.query_string
    }

    /// Whether the query is case-sensitive.
    pub fn is_case_sensitive(&self) -> bool {
        self.case_sensitive
    }

    /// Whether dynamic labels should be included in results.
    pub fn is_include_dynamic_labels(&self) -> bool {
        self.include_dynamic_labels
    }

    /// Returns `true` if the query contains any wildcard characters.
    pub fn is_wildcard(&self) -> bool {
        Self::has_wildcards(&self.query_string)
    }

    // -- Static helpers ------------------------------------------------------

    /// Returns `true` if the given string contains wildcard characters.
    pub fn has_wildcards(query: &str) -> bool {
        query.contains(ANY_STRING_WILDCARD) || query.contains(ANY_CHAR_WILDCARD)
    }

    /// Convert a simple wildcard pattern (using `*` and `?`) into a
    /// case-insensitive regular-expression string.  Returns `None` if the
    /// pattern is not valid regex after conversion.
    pub fn to_regex_pattern(&self) -> String {
        let mut regex = String::with_capacity(self.query_string.len() * 2);
        regex.push('^');
        for ch in self.query_string.chars() {
            match ch {
                ANY_STRING_WILDCARD => regex.push_str(".*"),
                ANY_CHAR_WILDCARD => regex.push('.'),
                // Escape regex-special characters
                '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\'
                | '^' | '$' => {
                    regex.push('\\');
                    regex.push(ch);
                }
                _ => regex.push(ch),
            }
        }
        regex.push('$');
        regex
    }

    /// Perform a simple wildcard match of the query against a candidate
    /// string, respecting case-sensitivity settings.
    pub fn matches(&self, candidate: &str) -> bool {
        let (q, c) = if self.case_sensitive {
            (self.query_string.clone(), candidate.to_string())
        } else {
            (
                self.query_string.to_lowercase(),
                candidate.to_lowercase(),
            )
        };
        wildcard_match(&q, &c)
    }
}

impl fmt::Display for QueryData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "QueryData({:?}, case_sensitive={}, dynamic_labels={})",
            self.query_string, self.case_sensitive, self.include_dynamic_labels
        )
    }
}

// ---------------------------------------------------------------------------
// Wildcard matching (iterative, no regex dependency)
// ---------------------------------------------------------------------------

/// Simple iterative wildcard match supporting `*` and `?`.
///
/// This is a direct port of the classic two-pointer wildcard-matching
/// algorithm and mirrors the Java `String.matches()`-style behaviour used
/// throughout Ghidra.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();

    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_pi, mut star_ti) = (usize::MAX, 0usize);

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star_pi = pi;
            star_ti = ti;
            pi += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }

    // Consume trailing '*' characters in the pattern.
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }

    pi == p.len()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_defaults() {
        let q = QueryData::new("test");
        assert_eq!(q.query_string(), "test");
        assert!(!q.is_case_sensitive());
        assert!(q.is_include_dynamic_labels());
        assert!(!q.is_wildcard());
    }

    #[test]
    fn test_with_options() {
        let q = QueryData::with_options("Foo", true, false);
        assert_eq!(q.query_string(), "Foo");
        assert!(q.is_case_sensitive());
        assert!(!q.is_include_dynamic_labels());
    }

    #[test]
    fn test_builder_chain() {
        let q = QueryData::new("hello")
            .with_case_sensitive(true)
            .with_include_dynamic_labels(false);
        assert!(q.is_case_sensitive());
        assert!(!q.is_include_dynamic_labels());
    }

    #[test]
    fn test_has_wildcards() {
        assert!(QueryData::has_wildcards("foo*"));
        assert!(QueryData::has_wildcards("b?r"));
        assert!(QueryData::has_wildcards("*"));
        assert!(!QueryData::has_wildcards("exact"));
    }

    #[test]
    fn test_is_wildcard() {
        assert!(QueryData::new("*.exe").is_wildcard());
        assert!(!QueryData::new("notepad").is_wildcard());
    }

    #[test]
    fn test_wildcard_match_exact() {
        assert!(wildcard_match("hello", "hello"));
        assert!(!wildcard_match("hello", "world"));
    }

    #[test]
    fn test_wildcard_match_star() {
        assert!(wildcard_match("he*", "hello"));
        assert!(wildcard_match("*lo", "hello"));
        assert!(wildcard_match("h*o", "hello"));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("", ""));
    }

    #[test]
    fn test_wildcard_match_question() {
        assert!(wildcard_match("h?llo", "hello"));
        assert!(wildcard_match("h?llo", "hallo"));
        assert!(!wildcard_match("h?llo", "hllo"));
    }

    #[test]
    fn test_wildcard_match_combined() {
        assert!(wildcard_match("k*32.?l?", "kernel32.dll"));
        assert!(wildcard_match("*.*", "file.txt"));
        assert!(!wildcard_match("*.exe", "file.txt"));
    }

    #[test]
    fn test_matches_case_insensitive() {
        let q = QueryData::new("Hello");
        assert!(q.matches("hello"));
        assert!(q.matches("HELLO"));
        assert!(q.matches("Hello"));
    }

    #[test]
    fn test_matches_case_sensitive() {
        let q = QueryData::new("Hello").with_case_sensitive(true);
        assert!(q.matches("Hello"));
        assert!(!q.matches("hello"));
        assert!(!q.matches("HELLO"));
    }

    #[test]
    fn test_matches_wildcard_case_insensitive() {
        let q = QueryData::new("kernel32.*");
        assert!(q.matches("KERNEL32.DLL"));
        assert!(q.matches("kernel32.dll"));
    }

    #[test]
    fn test_to_regex_pattern() {
        let q = QueryData::new("k*32.?l?");
        assert_eq!(q.to_regex_pattern(), r"^k.*32\..l.$");
    }

    #[test]
    fn test_to_regex_pattern_special_chars() {
        let q = QueryData::new("foo.bar+baz");
        assert_eq!(q.to_regex_pattern(), r"^foo\.bar\+baz$");
    }

    #[test]
    fn test_display() {
        let q = QueryData::new("test");
        let s = format!("{}", q);
        assert!(s.contains("test"));
        assert!(s.contains("case_sensitive=false"));
    }

    #[test]
    fn test_clone_eq() {
        let a = QueryData::new("abc").with_case_sensitive(true);
        let b = a.clone();
        assert_eq!(a, b);
    }
}
