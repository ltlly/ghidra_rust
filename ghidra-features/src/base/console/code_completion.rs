//! Code completion data structure.
//!
//! Port of Ghidra's `ghidra.app.plugin.core.console.CodeCompletion`.
//!
//! Encapsulates a code completion entry with:
//! - A description (what is being completed)
//! - The text to insert
//! - The number of characters to remove before insertion

use std::cmp::Ordering;

/// A single code completion candidate.
///
/// # Example
///
/// If the user types "Runscr" and the completion is "runScript":
/// - `description` = "runScript (Method)"
/// - `insertion` = "runScript"
/// - `chars_to_remove` = 6 (the length of "Runscr")
#[derive(Debug, Clone)]
pub struct CodeCompletion {
    /// Description of what this completion provides.
    description: String,
    /// The text to insert (if accepted), or `None` if invalid.
    insertion: Option<String>,
    /// Number of characters to remove before inserting.
    chars_to_remove: usize,
}

impl CodeCompletion {
    /// Create a new code completion.
    pub fn new(description: impl Into<String>, insertion: Option<impl Into<String>>) -> Self {
        Self {
            description: description.into(),
            insertion: insertion.map(|s| s.into()),
            chars_to_remove: 0,
        }
    }

    /// Create a new code completion with a specific number of characters to remove.
    pub fn with_chars_to_remove(
        description: impl Into<String>,
        insertion: Option<impl Into<String>>,
        chars_to_remove: usize,
    ) -> Self {
        Self {
            description: description.into(),
            insertion: insertion.map(|s| s.into()),
            chars_to_remove,
        }
    }

    /// Returns `true` if this completion would actually insert something.
    pub fn is_valid(&self) -> bool {
        self.insertion.is_some()
    }

    /// Returns the description of this completion.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the text to insert, or `None` if this completion is invalid.
    pub fn insertion(&self) -> Option<&str> {
        self.insertion.as_deref()
    }

    /// Returns the number of characters to remove before insertion.
    pub fn chars_to_remove(&self) -> usize {
        self.chars_to_remove
    }
}

impl PartialEq for CodeCompletion {
    fn eq(&self, other: &Self) -> bool {
        self.description.eq_ignore_ascii_case(&other.description)
    }
}

impl Eq for CodeCompletion {}

impl PartialOrd for CodeCompletion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CodeCompletion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.description
            .to_ascii_lowercase()
            .cmp(&other.description.to_ascii_lowercase())
    }
}

impl std::fmt::Display for CodeCompletion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CodeCompletion: '{}' ({})",
            self.description,
            self.insertion.as_deref().unwrap_or("<null>")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_code_completion_basic() {
        let cc = CodeCompletion::new("runScript (Method)", Some("runScript"));
        assert!(cc.is_valid());
        assert_eq!(cc.description(), "runScript (Method)");
        assert_eq!(cc.insertion(), Some("runScript"));
        assert_eq!(cc.chars_to_remove(), 0);
    }

    #[test]
    fn test_code_completion_with_chars_to_remove() {
        let cc = CodeCompletion::with_chars_to_remove(
            "runScript (Method)",
            Some("runScript"),
            6,
        );
        assert!(cc.is_valid());
        assert_eq!(cc.chars_to_remove(), 6);
    }

    #[test]
    fn test_code_completion_invalid() {
        let cc = CodeCompletion::new("nothing", None::<&str>);
        assert!(!cc.is_valid());
        assert!(cc.insertion().is_none());
    }

    #[test]
    fn test_code_completion_display() {
        let cc = CodeCompletion::new("runScript (Method)", Some("runScript"));
        let display = format!("{}", cc);
        assert_eq!(display, "CodeCompletion: 'runScript (Method)' (runScript)");
    }

    #[test]
    fn test_code_completion_display_null_insertion() {
        let cc = CodeCompletion::new("nothing", None::<&str>);
        let display = format!("{}", cc);
        assert_eq!(display, "CodeCompletion: 'nothing' (<null>)");
    }

    #[test]
    fn test_code_completion_ordering() {
        let mut completions = vec![
            CodeCompletion::new("Zebra", Some("zebra")),
            CodeCompletion::new("apple", Some("apple")),
            CodeCompletion::new("Banana", Some("banana")),
        ];
        completions.sort();

        // Case-insensitive ordering
        assert_eq!(completions[0].description(), "apple");
        assert_eq!(completions[1].description(), "Banana");
        assert_eq!(completions[2].description(), "Zebra");
    }

    #[test]
    fn test_code_completion_equality_case_insensitive() {
        let cc1 = CodeCompletion::new("Hello", Some("hello"));
        let cc2 = CodeCompletion::new("hello", Some("hello"));
        assert_eq!(cc1, cc2);
    }

    #[test]
    fn test_code_completion_clone() {
        let cc = CodeCompletion::new("test", Some("test"));
        let cloned = cc.clone();
        assert_eq!(cc, cloned);
    }

    #[test]
    fn test_is_valid_static_check() {
        // Port of CodeCompletion.isValid() static method
        let valid = CodeCompletion::new("desc", Some("ins"));
        let invalid = CodeCompletion::new("desc", None::<&str>);
        assert!(valid.is_valid());
        assert!(!invalid.is_valid());
    }
}
