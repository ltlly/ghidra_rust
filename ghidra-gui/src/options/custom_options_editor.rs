//! Port of `ghidra.framework.options.CustomOptionsEditor`.
//!
//! A marker interface for property editors that handle display editing of
//! one or more interrelated options.

/// Marker trait for custom option editors that handle a group of interrelated options.
///
/// Ported from Ghidra's `ghidra.framework.options.CustomOptionsEditor`.
pub trait CustomOptionsEditor: Send + Sync {
    /// Gets the names of the options this editor is editing.
    fn option_names(&self) -> Vec<String>;

    /// Gets the descriptions of the options this editor is editing.
    fn option_descriptions(&self) -> Option<Vec<String>> {
        None
    }

    /// Whether this editor supports the given option name.
    fn supports_option(&self, name: &str) -> bool {
        self.option_names().iter().any(|n| n == name)
    }

    /// Get the number of options being edited.
    fn option_count(&self) -> usize {
        self.option_names().len()
    }
}

/// A simple custom options editor with static option names and descriptions.
///
/// Ported from Ghidra's typical `CustomOptionsEditor` usage pattern.
#[derive(Debug, Clone)]
pub struct SimpleCustomOptionsEditor {
    names: Vec<String>,
    descriptions: Vec<String>,
}

impl SimpleCustomOptionsEditor {
    /// Create a new editor with the given option names.
    pub fn new(names: Vec<String>) -> Self {
        let descriptions = names.iter().map(|_| String::new()).collect();
        Self { names, descriptions }
    }

    /// Set descriptions for the options.
    pub fn with_descriptions(mut self, descriptions: Vec<String>) -> Self {
        self.descriptions = descriptions;
        self
    }

    /// Get the names of the options being edited.
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Get the descriptions of the options being edited.
    pub fn descriptions(&self) -> &[String] {
        &self.descriptions
    }
}

impl CustomOptionsEditor for SimpleCustomOptionsEditor {
    fn option_names(&self) -> Vec<String> {
        self.names.clone()
    }

    fn option_descriptions(&self) -> Option<Vec<String>> {
        Some(self.descriptions.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_custom_options_editor() {
        let editor = SimpleCustomOptionsEditor::new(vec![
            "option1".to_string(),
            "option2".to_string(),
        ]);
        assert_eq!(editor.names().len(), 2);
        assert_eq!(editor.names()[0], "option1");
    }

    #[test]
    fn test_simple_editor_with_descriptions() {
        let editor = SimpleCustomOptionsEditor::new(vec!["opt".to_string()])
            .with_descriptions(vec!["Description".to_string()]);
        assert_eq!(editor.descriptions()[0], "Description");
    }

    #[test]
    fn test_trait_option_count() {
        let editor = SimpleCustomOptionsEditor::new(vec![
            "a".to_string(), "b".to_string(), "c".to_string(),
        ]);
        assert_eq!(editor.option_count(), 3);
        assert!(editor.supports_option("a"));
        assert!(!editor.supports_option("x"));
    }
}
