//! Data type selection and navigation utilities (ported from `ghidra.app.util.datatype`).

use serde::{Deserialize, Serialize};

/// Direction for navigating data type trees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NavigationDirection {
    /// Move to parent node.
    Up,
    /// Move to first child.
    Down,
    /// Move to previous sibling.
    Left,
    /// Move to next sibling.
    Right,
}

/// Error when a composite type has no fields.
#[derive(Debug, Clone)]
pub struct EmptyCompositeError {
    /// The type name.
    pub type_name: String,
}

impl std::fmt::Display for EmptyCompositeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "composite type '{}' has no fields", self.type_name)
    }
}

impl std::error::Error for EmptyCompositeError {}

/// URL-like reference to a data type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTypeUrl {
    /// Category path (e.g. "/builtin").
    pub category: String,
    /// Data type name.
    pub name: String,
}

impl DataTypeUrl {
    /// Create a new data type URL.
    pub fn new(category: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            category: category.into(),
            name: name.into(),
        }
    }

    /// Parse from a path-like string (e.g. "/builtin/int").
    pub fn parse(s: &str) -> Option<Self> {
        let (cat, name) = s.rsplit_once('/')?;
        Some(Self {
            category: cat.to_string(),
            name: name.to_string(),
        })
    }

    /// Return the full path string.
    pub fn full_path(&self) -> String {
        if self.category.ends_with('/') {
            format!("{}{}", self.category, self.name)
        } else {
            format!("{}/{}", self.category, self.name)
        }
    }
}

impl std::fmt::Display for DataTypeUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.full_path())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_type_url_parse() {
        let url = DataTypeUrl::parse("/builtin/int").unwrap();
        assert_eq!(url.category, "/builtin");
        assert_eq!(url.name, "int");
        assert_eq!(url.full_path(), "/builtin/int");
    }

    #[test]
    fn data_type_url_display() {
        let url = DataTypeUrl::new("/struct", "Point");
        assert_eq!(url.to_string(), "/struct/Point");
    }

    #[test]
    fn navigation_direction_variants() {
        assert_ne!(NavigationDirection::Up, NavigationDirection::Down);
    }

    #[test]
    fn empty_composite_error() {
        let e = EmptyCompositeError {
            type_name: "Empty".into(),
        };
        assert!(e.to_string().contains("Empty"));
    }
}
