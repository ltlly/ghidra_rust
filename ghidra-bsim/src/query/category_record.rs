//! A user-defined category associated with an executable.
//!
//! Ports Ghidra's `ghidra.features.bsim.query.description.CategoryRecord`.

/// A user-defined category associated with an executable.
///
/// Specified by a *type* and then the particular *category* (within the type)
/// that the executable belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CategoryRecord {
    /// The type of category (must not be empty).
    category_type: String,
    /// The type-specific category.
    category: String,
}

impl CategoryRecord {
    /// Create a new category record.
    pub fn new(category_type: String, category: String) -> Self {
        Self {
            category_type,
            category,
        }
    }

    /// Get the category type.
    pub fn category_type(&self) -> &str {
        &self.category_type
    }

    /// Get the category value.
    pub fn category(&self) -> &str {
        &self.category
    }

    /// Validate that the type string contains only allowed characters:
    /// letters, digits, spaces, dots, underscores, colons, slashes, parens.
    pub fn enforce_type_characters(val: &str) -> bool {
        if val.is_empty() {
            return false;
        }
        val.chars().all(|c| {
            c.is_alphanumeric()
                || c == ' '
                || c == '.'
                || c == '_'
                || c == ':'
                || c == '/'
                || c == '('
                || c == ')'
        })
    }
}

impl Default for CategoryRecord {
    fn default() -> Self {
        Self::new(String::new(), String::new())
    }
}

impl PartialOrd for CategoryRecord {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CategoryRecord {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.category_type
            .cmp(&other.category_type)
            .then_with(|| self.category.cmp(&other.category))
    }
}

impl std::fmt::Display for CategoryRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.category_type, self.category)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let c = CategoryRecord::new("OS".to_string(), "Linux".to_string());
        assert_eq!(c.category_type(), "OS");
        assert_eq!(c.category(), "Linux");
    }

    #[test]
    fn test_ordering() {
        let a = CategoryRecord::new("A".to_string(), "x".to_string());
        let b = CategoryRecord::new("B".to_string(), "x".to_string());
        assert!(a < b);
    }

    #[test]
    fn test_ordering_same_type() {
        let a = CategoryRecord::new("T".to_string(), "a".to_string());
        let b = CategoryRecord::new("T".to_string(), "b".to_string());
        assert!(a < b);
    }

    #[test]
    fn test_enforce_type_characters() {
        assert!(CategoryRecord::enforce_type_characters("OS"));
        assert!(CategoryRecord::enforce_type_characters("my_type"));
        assert!(CategoryRecord::enforce_type_characters("a/b"));
        assert!(CategoryRecord::enforce_type_characters("v1.0"));
        assert!(CategoryRecord::enforce_type_characters("func()"));
        assert!(!CategoryRecord::enforce_type_characters(""));
        assert!(!CategoryRecord::enforce_type_characters("bad!"));
        assert!(!CategoryRecord::enforce_type_characters("no@符号"));
    }

    #[test]
    fn test_display() {
        let c = CategoryRecord::new("OS".to_string(), "Linux".to_string());
        assert_eq!(format!("{}", c), "[OS] Linux");
    }

    #[test]
    fn test_equality() {
        let a = CategoryRecord::new("T".to_string(), "C".to_string());
        let b = CategoryRecord::new("T".to_string(), "C".to_string());
        assert_eq!(a, b);
    }
}
