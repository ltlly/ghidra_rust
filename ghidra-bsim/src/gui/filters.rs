//! BSim search filter types.
//!
//! Ports `ghidra.features.bsim.gui.filters` from Ghidra's Java source.

/// A BSim filter that can be applied to search results.
#[derive(Debug, Clone)]
pub struct BSimFilterType {
    /// Filter name.
    pub name: String,
    /// Filter description.
    pub description: String,
    /// The field this filter operates on.
    pub field: BSimFilterField,
    /// The filter operation.
    pub operation: BSimFilterOperation,
    /// The filter value.
    pub value: String,
}

/// Fields that can be filtered on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BSimFilterField {
    /// Filter by architecture.
    Architecture,
    /// Filter by compiler.
    Compiler,
    /// Filter by executable name.
    ExecutableName,
    /// Filter by MD5 hash.
    Md5,
    /// Filter by date.
    Date,
    /// Filter by function tag.
    FunctionTag,
    /// Filter by whether the binary is executable.
    ExecutableCategory,
    /// Filter by path prefix.
    PathStartsWith,
    /// Filter by whether a function has a named child.
    HasNamedChild,
}

/// Filter operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BSimFilterOperation {
    /// Equal to.
    Equals,
    /// Not equal to.
    NotEquals,
    /// Contains.
    Contains,
    /// Does not contain.
    NotContains,
    /// Starts with.
    StartsWith,
    /// Before (for dates).
    Before,
    /// After (for dates).
    After,
}

impl BSimFilterType {
    /// Create a new filter.
    pub fn new(
        name: impl Into<String>,
        field: BSimFilterField,
        operation: BSimFilterOperation,
        value: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            field,
            operation,
            value: value.into(),
        }
    }

    /// Create an architecture filter.
    pub fn architecture(value: impl Into<String>) -> Self {
        Self::new("Architecture", BSimFilterField::Architecture, BSimFilterOperation::Equals, value)
    }

    /// Create a compiler filter.
    pub fn compiler(value: impl Into<String>) -> Self {
        Self::new("Compiler", BSimFilterField::Compiler, BSimFilterOperation::Equals, value)
    }

    /// Create an executable name filter.
    pub fn executable_name(value: impl Into<String>) -> Self {
        Self::new("ExecutableName", BSimFilterField::ExecutableName, BSimFilterOperation::Contains, value)
    }

    /// Create an MD5 filter.
    pub fn md5(value: impl Into<String>) -> Self {
        Self::new("MD5", BSimFilterField::Md5, BSimFilterOperation::Equals, value)
    }

    /// Create an "is executable" category filter.
    pub fn executable_category() -> Self {
        Self::new("ExecutableCategory", BSimFilterField::ExecutableCategory, BSimFilterOperation::Equals, "true")
    }

    /// Create a "not executable" category filter.
    pub fn not_executable_category() -> Self {
        Self::new("NotExecutableCategory", BSimFilterField::ExecutableCategory, BSimFilterOperation::NotEquals, "true")
    }

    /// Test if a value matches this filter.
    pub fn matches(&self, test_value: &str) -> bool {
        match self.operation {
            BSimFilterOperation::Equals => test_value == self.value,
            BSimFilterOperation::NotEquals => test_value != self.value,
            BSimFilterOperation::Contains => test_value.contains(&self.value),
            BSimFilterOperation::NotContains => !test_value.contains(&self.value),
            BSimFilterOperation::StartsWith => test_value.starts_with(&self.value),
            BSimFilterOperation::Before => test_value < self.value.as_str(),
            BSimFilterOperation::After => test_value > self.value.as_str(),
        }
    }
}

/// A blank/no-op filter that matches everything.
#[derive(Debug, Clone, Default)]
pub struct BlankBSimFilterType;

impl BlankBSimFilterType {
    /// Always returns true.
    pub fn matches(&self) -> bool {
        true
    }
}

/// A negated version of a filter.
#[derive(Debug, Clone)]
pub struct NotFilter {
    /// The inner filter to negate.
    pub inner: BSimFilterType,
}

impl NotFilter {
    /// Create a new negated filter.
    pub fn new(inner: BSimFilterType) -> Self {
        Self { inner }
    }

    /// Test if a value does NOT match the inner filter.
    pub fn matches(&self, test_value: &str) -> bool {
        !self.inner.matches(test_value)
    }
}

/// Multi-choice filter value editor.
#[derive(Debug, Clone)]
pub struct MultiChoiceBSimValueEditor {
    /// Available choices.
    pub choices: Vec<String>,
    /// Selected choices.
    pub selected: Vec<String>,
}

impl MultiChoiceBSimValueEditor {
    /// Create a new multi-choice editor.
    pub fn new(choices: Vec<String>) -> Self {
        Self {
            choices,
            selected: Vec::new(),
        }
    }

    /// Toggle a selection.
    pub fn toggle(&mut self, value: &str) {
        if let Some(pos) = self.selected.iter().position(|s| s == value) {
            self.selected.remove(pos);
        } else if self.choices.contains(&value.to_string()) {
            self.selected.push(value.to_string());
        }
    }

    /// Whether a value is selected.
    pub fn is_selected(&self, value: &str) -> bool {
        self.selected.iter().any(|s| s == value)
    }

    /// Get the number of selections.
    pub fn selection_count(&self) -> usize {
        self.selected.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_architecture() {
        let filter = BSimFilterType::architecture("x86");
        assert!(filter.matches("x86"));
        assert!(!filter.matches("ARM"));
    }

    #[test]
    fn test_filter_compiler() {
        let filter = BSimFilterType::compiler("gcc");
        assert!(filter.matches("gcc"));
        assert!(!filter.matches("msvc"));
    }

    #[test]
    fn test_filter_contains() {
        let filter = BSimFilterType::executable_name("test");
        assert!(filter.matches("test.exe"));
        assert!(filter.matches("my_test_program"));
        assert!(!filter.matches("hello.exe"));
    }

    #[test]
    fn test_filter_starts_with() {
        let filter = BSimFilterType::new("Path", BSimFilterField::PathStartsWith, BSimFilterOperation::StartsWith, "/usr");
        assert!(filter.matches("/usr/bin/test"));
        assert!(!filter.matches("/home/test"));
    }

    #[test]
    fn test_filter_not_equals() {
        let filter = BSimFilterType::new("NotArch", BSimFilterField::Architecture, BSimFilterOperation::NotEquals, "ARM");
        assert!(filter.matches("x86"));
        assert!(!filter.matches("ARM"));
    }

    #[test]
    fn test_blank_filter() {
        let filter = BlankBSimFilterType::default();
        assert!(filter.matches());
    }

    #[test]
    fn test_not_filter() {
        let inner = BSimFilterType::architecture("x86");
        let not = NotFilter::new(inner);
        assert!(!not.matches("x86"));
        assert!(not.matches("ARM"));
    }

    #[test]
    fn test_multi_choice_editor() {
        let mut editor = MultiChoiceBSimValueEditor::new(
            vec!["x86".into(), "ARM".into(), "MIPS".into()],
        );
        assert_eq!(editor.selection_count(), 0);

        editor.toggle("x86");
        assert!(editor.is_selected("x86"));
        assert_eq!(editor.selection_count(), 1);

        editor.toggle("ARM");
        assert!(editor.is_selected("ARM"));
        assert_eq!(editor.selection_count(), 2);

        editor.toggle("x86");
        assert!(!editor.is_selected("x86"));
        assert_eq!(editor.selection_count(), 1);

        // Toggling a non-existent choice should do nothing.
        editor.toggle("RISC-V");
        assert!(!editor.is_selected("RISC-V"));
        assert_eq!(editor.selection_count(), 1);
    }
}
