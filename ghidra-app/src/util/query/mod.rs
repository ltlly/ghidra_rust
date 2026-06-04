//! Symbol and address queries (ported from `ghidra.app.util.query`).

use serde::{Deserialize, Serialize};

/// A query for searching symbols.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolQuery {
    /// Symbol name pattern (supports '*' wildcards).
    pub name_pattern: String,
    /// Optional namespace filter.
    pub namespace: Option<String>,
    /// Optional address range filter (start, end).
    pub address_range: Option<(u64, u64)>,
    /// Maximum number of results.
    pub max_results: Option<usize>,
    /// Case-sensitive matching.
    pub case_sensitive: bool,
}

impl SymbolQuery {
    /// Create a query for an exact symbol name.
    pub fn exact(name: impl Into<String>) -> Self {
        Self {
            name_pattern: name.into(),
            namespace: None,
            address_range: None,
            max_results: None,
            case_sensitive: true,
        }
    }

    /// Create a wildcard query.
    pub fn wildcard(pattern: impl Into<String>) -> Self {
        Self {
            name_pattern: pattern.into(),
            namespace: None,
            address_range: None,
            max_results: None,
            case_sensitive: false,
        }
    }

    /// Check if a name matches this query.
    pub fn matches(&self, name: &str, namespace: Option<&str>) -> bool {
        let name_match = if self.name_pattern.contains('*') {
            glob_match(&self.name_pattern, name, self.case_sensitive)
        } else if self.case_sensitive {
            name == self.name_pattern
        } else {
            name.eq_ignore_ascii_case(&self.name_pattern)
        };
        if !name_match {
            return false;
        }
        if let Some(ref ns_filter) = self.namespace {
            match namespace {
                Some(ns) => {
                    let matched = if self.case_sensitive {
                        ns.contains(ns_filter.as_str())
                    } else {
                        ns.to_lowercase().contains(&ns_filter.to_lowercase())
                    };
                    if !matched {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
}

/// Simple glob matching (supports '*' only).
fn glob_match(pattern: &str, text: &str, case_sensitive: bool) -> bool {
    let pattern = if case_sensitive {
        pattern.to_string()
    } else {
        pattern.to_lowercase()
    };
    let text = if case_sensitive {
        text.to_string()
    } else {
        text.to_lowercase()
    };
    glob_match_inner(&pattern, &text)
}

fn glob_match_inner(pattern: &str, text: &str) -> bool {
    if pattern.is_empty() {
        return text.is_empty();
    }
    if pattern == "*" {
        return true;
    }
    if let Some(rest) = pattern.strip_prefix('*') {
        for i in 0..=text.len() {
            if glob_match_inner(rest, &text[i..]) {
                return true;
            }
        }
        return false;
    }
    if text.is_empty() {
        return false;
    }
    if pattern.as_bytes()[0] == text.as_bytes()[0] {
        return glob_match_inner(&pattern[1..], &text[1..]);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_query_exact() {
        let q = SymbolQuery::exact("main");
        assert!(q.matches("main", None));
        assert!(!q.matches("Main", None));
        assert!(!q.matches("main_entry", None));
    }

    #[test]
    fn symbol_query_exact_case_insensitive() {
        let mut q = SymbolQuery::exact("main");
        q.case_sensitive = false;
        assert!(q.matches("Main", None));
        assert!(q.matches("MAIN", None));
    }

    #[test]
    fn symbol_query_wildcard() {
        let q = SymbolQuery::wildcard("init*");
        assert!(q.matches("init", None));
        assert!(q.matches("initialize", None));
        assert!(q.matches("initSubsystem", None));
        assert!(!q.matches("destroy", None));
    }

    #[test]
    fn symbol_query_wildcard_middle() {
        let q = SymbolQuery::wildcard("*::foo");
        assert!(q.matches("std::foo", None));
        assert!(q.matches("abc::foo", None));
        assert!(!q.matches("foo", None));
    }

    #[test]
    fn symbol_query_with_namespace() {
        let mut q = SymbolQuery::exact("foo");
        q.namespace = Some("std".into());
        assert!(q.matches("foo", Some("std")));
        assert!(q.matches("foo", Some("std::string")));
        assert!(!q.matches("foo", Some("boost")));
        assert!(!q.matches("foo", None));
    }

    #[test]
    fn glob_match_basic() {
        assert!(glob_match("*", "anything", true));
        assert!(glob_match("test*", "testing", true));
        assert!(!glob_match("test*", "hello", true));
        assert!(glob_match("*ing", "testing", true));
        assert!(glob_match("t*t", "test", true));
    }
}
