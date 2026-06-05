//! BSim search filter types.
//!
//! Ports `ghidra.features.bsim.gui.filters` from Ghidra's Java source.
//!
//! # Filter Categories
//!
//! - **Architecture/Compiler** filters: match by processor or compiler
//! - **Executable** filters: match by name, path, MD5, or category
//! - **Date** filters: match by date range
//! - **Function** filters: match by tag or child name
//! - **Value editors**: UI components for editing filter values

pub mod architecture_filters;
pub mod date_filters;
pub mod executable_filters;
pub mod value_editors;

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

// ============================================================================
// Additional filter types ported from Ghidra's Java BSim filter classes
// ============================================================================

/// A "not architecture" filter that excludes results matching a specific architecture.
///
/// Ports `ghidra.features.bsim.gui.filters.NotArchitectureBSimFilterType`.
pub type NotArchitectureBSimFilterType = NotFilter;

impl NotArchitectureBSimFilterType {
    /// Create a "not architecture" filter.
    pub fn not_architecture(value: impl Into<String>) -> Self {
        Self::new(BSimFilterType::architecture(value))
    }
}

/// A "not compiler" filter.
///
/// Ports `ghidra.features.bsim.gui.filters.NotCompilerBSimFilterType`.
pub type NotCompilerBSimFilterType = NotFilter;

impl NotCompilerBSimFilterType {
    /// Create a "not compiler" filter.
    pub fn not_compiler(value: impl Into<String>) -> Self {
        Self::new(BSimFilterType::compiler(value))
    }
}

/// A "not executable name" filter.
///
/// Ports `ghidra.features.bsim.gui.filters.NotExecutableNameBSimFilterType`.
pub type NotExecutableNameBSimFilterType = NotFilter;

impl NotExecutableNameBSimFilterType {
    /// Create a "not executable name" filter.
    pub fn not_executable_name(value: impl Into<String>) -> Self {
        Self::new(BSimFilterType::executable_name(value))
    }
}

/// A "not MD5" filter.
///
/// Ports `ghidra.features.bsim.gui.filters.NotMd5BSimFilterType`.
pub type NotMd5BSimFilterType = NotFilter;

impl NotMd5BSimFilterType {
    /// Create a "not MD5" filter.
    pub fn not_md5(value: impl Into<String>) -> Self {
        Self::new(BSimFilterType::md5(value))
    }
}

/// A "not executable category" filter.
///
/// Ports `ghidra.features.bsim.gui.filters.NotExecutableCategoryBSimFilterType`.
pub type NotExecutableCategoryBSimFilterType = NotFilter;

impl NotExecutableCategoryBSimFilterType {
    /// Create a "not executable category" filter (excludes executables, keeps libraries).
    pub fn not_executable_category() -> Self {
        Self::new(BSimFilterType::executable_category())
    }
}

/// A date filter that accepts results earlier than a given date.
///
/// Ports `ghidra.features.bsim.gui.filters.DateEarlierBSimFilterType`.
#[derive(Debug, Clone)]
pub struct DateEarlierBSimFilterType {
    /// The cutoff date (ISO 8601 string).
    pub cutoff_date: String,
}

impl DateEarlierBSimFilterType {
    /// Create a new "date earlier" filter.
    pub fn new(cutoff_date: impl Into<String>) -> Self {
        Self {
            cutoff_date: cutoff_date.into(),
        }
    }

    /// Test if a date string is before the cutoff.
    pub fn matches(&self, test_date: &str) -> bool {
        test_date < self.cutoff_date.as_str()
    }
}

/// A date filter that accepts results later than a given date.
///
/// Ports `ghidra.features.bsim.gui.filters.DateLaterBSimFilterType`.
#[derive(Debug, Clone)]
pub struct DateLaterBSimFilterType {
    /// The cutoff date (ISO 8601 string).
    pub cutoff_date: String,
}

impl DateLaterBSimFilterType {
    /// Create a new "date later" filter.
    pub fn new(cutoff_date: impl Into<String>) -> Self {
        Self {
            cutoff_date: cutoff_date.into(),
        }
    }

    /// Test if a date string is after the cutoff.
    pub fn matches(&self, test_date: &str) -> bool {
        test_date > self.cutoff_date.as_str()
    }
}

/// A date range filter (composite of earlier + later).
///
/// Ports `ghidra.features.bsim.gui.filters.DateBSimFilterType`.
#[derive(Debug, Clone)]
pub struct DateBSimFilterType {
    /// Start of the date range.
    pub start_date: Option<String>,
    /// End of the date range.
    pub end_date: Option<String>,
}

impl DateBSimFilterType {
    /// Create a date range filter.
    pub fn new(start_date: Option<String>, end_date: Option<String>) -> Self {
        Self { start_date, end_date }
    }

    /// Create a filter accepting dates before the given date.
    pub fn before(date: impl Into<String>) -> Self {
        Self {
            start_date: None,
            end_date: Some(date.into()),
        }
    }

    /// Create a filter accepting dates after the given date.
    pub fn after(date: impl Into<String>) -> Self {
        Self {
            start_date: Some(date.into()),
            end_date: None,
        }
    }

    /// Create a filter accepting dates within a range.
    pub fn between(start: impl Into<String>, end: impl Into<String>) -> Self {
        Self {
            start_date: Some(start.into()),
            end_date: Some(end.into()),
        }
    }

    /// Test if a date falls within the range.
    pub fn matches(&self, test_date: &str) -> bool {
        let after_start = self
            .start_date
            .as_ref()
            .map_or(true, |s| test_date >= s.as_str());
        let before_end = self
            .end_date
            .as_ref()
            .map_or(true, |e| test_date <= e.as_str());
        after_start && before_end
    }
}

/// A boolean value editor for yes/no filter choices.
///
/// Ports `ghidra.features.bsim.gui.filters.BooleanBSimValueEditor`.
#[derive(Debug, Clone)]
pub struct BooleanBSimValueEditor {
    /// The current value.
    pub value: bool,
    /// Display label for "true".
    pub true_label: String,
    /// Display label for "false".
    pub false_label: String,
}

impl BooleanBSimValueEditor {
    /// Create a new boolean editor.
    pub fn new(true_label: impl Into<String>, false_label: impl Into<String>) -> Self {
        Self {
            value: false,
            true_label: true_label.into(),
            false_label: false_label.into(),
        }
    }

    /// Create with default labels.
    pub fn yes_no() -> Self {
        Self::new("Yes", "No")
    }

    /// Toggle the value.
    pub fn toggle(&mut self) {
        self.value = !self.value;
    }

    /// Get the display string for the current value.
    pub fn display_value(&self) -> &str {
        if self.value {
            &self.true_label
        } else {
            &self.false_label
        }
    }
}

impl Default for BooleanBSimValueEditor {
    fn default() -> Self {
        Self::yes_no()
    }
}

/// A string value editor for free-text filter input.
///
/// Ports `ghidra.features.bsim.gui.filters.StringBSimValueEditor`.
#[derive(Debug, Clone)]
pub struct StringBSimValueEditor {
    /// The current text value.
    pub text: String,
    /// Placeholder text when empty.
    pub placeholder: String,
    /// Whether the match should be case-insensitive.
    pub case_insensitive: bool,
}

impl StringBSimValueEditor {
    /// Create a new string editor.
    pub fn new(placeholder: impl Into<String>) -> Self {
        Self {
            text: String::new(),
            placeholder: placeholder.into(),
            case_insensitive: true,
        }
    }

    /// Set the text value.
    pub fn set_text(&mut self, text: impl Into<String>) {
        self.text = text.into();
    }

    /// Test if a value matches the current text.
    pub fn matches(&self, test_value: &str) -> bool {
        if self.text.is_empty() {
            return true; // Empty filter matches everything.
        }
        if self.case_insensitive {
            test_value
                .to_lowercase()
                .contains(&self.text.to_lowercase())
        } else {
            test_value.contains(&self.text)
        }
    }
}

impl Default for StringBSimValueEditor {
    fn default() -> Self {
        Self::new("Enter value...")
    }
}

/// A set of filters applied together (AND logic).
///
/// Ports `ghidra.features.bsim.gui.search.dialog.BSimFilterSet`.
#[derive(Debug, Clone, Default)]
pub struct BSimFilterSet {
    /// The filters in this set.
    filters: Vec<BSimFilterType>,
}

impl BSimFilterSet {
    /// Create an empty filter set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a filter to the set.
    pub fn add(&mut self, filter: BSimFilterType) {
        self.filters.push(filter);
    }

    /// Remove all filters.
    pub fn clear(&mut self) {
        self.filters.clear();
    }

    /// Number of active filters.
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// Whether the filter set is empty.
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    /// Test a value against the field mapped by the filter index.
    /// Each filter is checked against its respective value.
    pub fn matches_all(&self, values: &[(&BSimFilterField, &str)]) -> bool {
        for filter in &self.filters {
            if let Some((_, val)) = values.iter().find(|(f, _)| **f == filter.field) {
                if !filter.matches(val) {
                    return false;
                }
            }
        }
        true
    }

    /// Get the filter names.
    pub fn filter_names(&self) -> Vec<&str> {
        self.filters.iter().map(|f| f.name.as_str()).collect()
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

    #[test]
    fn test_not_architecture_filter() {
        let not_arch = NotArchitectureBSimFilterType::not_architecture("ARM");
        assert!(!not_arch.matches("ARM"));
        assert!(not_arch.matches("x86"));
    }

    #[test]
    fn test_not_compiler_filter() {
        let not_comp = NotCompilerBSimFilterType::not_compiler("msvc");
        assert!(!not_comp.matches("msvc"));
        assert!(not_comp.matches("gcc"));
    }

    #[test]
    fn test_not_executable_name_filter() {
        let not_name = NotExecutableNameBSimFilterType::not_executable_name("malware");
        assert!(!not_name.matches("malware.exe"));
        assert!(not_name.matches("clean.exe"));
    }

    #[test]
    fn test_not_md5_filter() {
        let not_md5 = NotMd5BSimFilterType::not_md5("abc123");
        assert!(!not_md5.matches("abc123"));
        assert!(not_md5.matches("def456"));
    }

    #[test]
    fn test_not_executable_category_filter() {
        let not_exe = NotExecutableCategoryBSimFilterType::not_executable_category();
        // NotFilter on an Equals("true") filter
        assert!(!not_exe.matches("true"));
        assert!(not_exe.matches("false"));
    }

    #[test]
    fn test_date_earlier_filter() {
        let filter = DateEarlierBSimFilterType::new("2024-06-01");
        assert!(filter.matches("2024-01-15"));
        assert!(!filter.matches("2024-12-25"));
        assert!(!filter.matches("2024-06-01")); // equal is not earlier
    }

    #[test]
    fn test_date_later_filter() {
        let filter = DateLaterBSimFilterType::new("2024-06-01");
        assert!(!filter.matches("2024-01-15"));
        assert!(filter.matches("2024-12-25"));
        assert!(!filter.matches("2024-06-01")); // equal is not later
    }

    #[test]
    fn test_date_range_filter() {
        let filter = DateBSimFilterType::between("2024-01-01", "2024-12-31");
        assert!(filter.matches("2024-06-15"));
        assert!(!filter.matches("2023-12-31"));
        assert!(!filter.matches("2025-01-01"));
        assert!(filter.matches("2024-01-01")); // inclusive
        assert!(filter.matches("2024-12-31")); // inclusive
    }

    #[test]
    fn test_date_before() {
        let filter = DateBSimFilterType::before("2024-06-01");
        assert!(filter.matches("2024-01-01"));
        assert!(filter.matches("2024-06-01")); // inclusive
        assert!(!filter.matches("2024-07-01"));
    }

    #[test]
    fn test_date_after() {
        let filter = DateBSimFilterType::after("2024-06-01");
        assert!(!filter.matches("2024-01-01"));
        assert!(filter.matches("2024-06-01")); // inclusive
        assert!(filter.matches("2024-07-01"));
    }

    #[test]
    fn test_boolean_editor_default() {
        let mut editor = BooleanBSimValueEditor::default();
        assert!(!editor.value);
        assert_eq!(editor.display_value(), "No");
        editor.toggle();
        assert!(editor.value);
        assert_eq!(editor.display_value(), "Yes");
    }

    #[test]
    fn test_boolean_editor_custom_labels() {
        let editor = BooleanBSimValueEditor::new("Executable", "Library");
        assert_eq!(editor.display_value(), "Library");
    }

    #[test]
    fn test_string_editor_empty_matches_all() {
        let editor = StringBSimValueEditor::default();
        assert!(editor.matches("anything"));
        assert!(editor.matches(""));
    }

    #[test]
    fn test_string_editor_case_insensitive() {
        let mut editor = StringBSimValueEditor::default();
        editor.set_text("Hello");
        assert!(editor.matches("hello world"));
        assert!(editor.matches("HELLO"));
        assert!(!editor.matches("world"));
    }

    #[test]
    fn test_string_editor_case_sensitive() {
        let mut editor = StringBSimValueEditor::default();
        editor.case_insensitive = false;
        editor.set_text("Hello");
        assert!(editor.matches("Hello world"));
        assert!(!editor.matches("hello world"));
    }

    #[test]
    fn test_filter_set_basic() {
        let mut set = BSimFilterSet::new();
        assert!(set.is_empty());
        set.add(BSimFilterType::architecture("x86"));
        set.add(BSimFilterType::compiler("gcc"));
        assert_eq!(set.len(), 2);
        assert_eq!(set.filter_names(), vec!["Architecture", "Compiler"]);
    }

    #[test]
    fn test_filter_set_matches_all() {
        let mut set = BSimFilterSet::new();
        set.add(BSimFilterType::architecture("x86"));
        set.add(BSimFilterType::compiler("gcc"));

        let values: Vec<(&BSimFilterField, &str)> = vec![
            (&BSimFilterField::Architecture, "x86"),
            (&BSimFilterField::Compiler, "gcc"),
        ];
        assert!(set.matches_all(&values));

        let bad_values: Vec<(&BSimFilterField, &str)> = vec![
            (&BSimFilterField::Architecture, "x86"),
            (&BSimFilterField::Compiler, "msvc"),
        ];
        assert!(!set.matches_all(&bad_values));
    }

    #[test]
    fn test_filter_set_clear() {
        let mut set = BSimFilterSet::new();
        set.add(BSimFilterType::architecture("x86"));
        assert_eq!(set.len(), 1);
        set.clear();
        assert!(set.is_empty());
    }
}
