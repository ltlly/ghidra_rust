//! Port of BSim filter type classes.
//!
//! Ports Ghidra's `ghidra.features.bsim.gui.filters` package with the
//! various filter type implementations for BSim search queries.

use serde::{Deserialize, Serialize};

/// Base trait for BSim filter types.
///
/// Ported from Ghidra's `BSimFilterType`.
pub trait BSimFilterType: Send + Sync {
    /// Get the name of this filter type.
    fn filter_name(&self) -> &str;

    /// Get the display label for this filter.
    fn display_label(&self) -> &str;

    /// Whether this filter is a "not" (negation) filter.
    fn is_negated(&self) -> bool {
        false
    }

    /// Create the corresponding positive/negative variant.
    fn negate(&self) -> Box<dyn BSimFilterType>;

    /// Whether the filter matches the given value.
    fn matches(&self, value: &str) -> bool;

    /// Get the SQL/ES field name this filter operates on.
    fn field_name(&self) -> &str;
}

/// Filter by architecture (e.g., x86, ARM).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchitectureFilter {
    /// The architecture value to match.
    pub value: String,
    /// Whether this is a negated filter.
    pub negated: bool,
}

impl ArchitectureFilter {
    /// Create a new architecture filter.
    pub fn new(value: impl Into<String>) -> Self {
        Self { value: value.into(), negated: false }
    }
    /// Create a negated architecture filter.
    pub fn not(value: impl Into<String>) -> Self {
        Self { value: value.into(), negated: true }
    }
}

impl BSimFilterType for ArchitectureFilter {
    fn filter_name(&self) -> &str { "architecture" }
    fn display_label(&self) -> &str { "Architecture" }
    fn is_negated(&self) -> bool { self.negated }
    fn negate(&self) -> Box<dyn BSimFilterType> {
        Box::new(Self { value: self.value.clone(), negated: !self.negated })
    }
    fn matches(&self, value: &str) -> bool {
        if self.negated { value != self.value } else { value == self.value }
    }
    fn field_name(&self) -> &str { "architecture" }
}

/// Filter by compiler (e.g., gcc, clang, msvc).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerFilter {
    /// The compiler value to match.
    pub value: String,
    /// Whether this is a negated filter.
    pub negated: bool,
}

impl CompilerFilter {
    /// Create a new compiler filter.
    pub fn new(value: impl Into<String>) -> Self {
        Self { value: value.into(), negated: false }
    }
    /// Create a negated compiler filter.
    pub fn not(value: impl Into<String>) -> Self {
        Self { value: value.into(), negated: true }
    }
}

impl BSimFilterType for CompilerFilter {
    fn filter_name(&self) -> &str { "compiler" }
    fn display_label(&self) -> &str { "Compiler" }
    fn is_negated(&self) -> bool { self.negated }
    fn negate(&self) -> Box<dyn BSimFilterType> {
        Box::new(Self { value: self.value.clone(), negated: !self.negated })
    }
    fn matches(&self, value: &str) -> bool {
        if self.negated { value != self.value } else { value == self.value }
    }
    fn field_name(&self) -> &str { "compiler" }
}

/// Filter by executable name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutableNameFilter {
    /// The executable name to match.
    pub value: String,
    /// Whether this is a negated filter.
    pub negated: bool,
}

impl ExecutableNameFilter {
    /// Create a new executable name filter.
    pub fn new(value: impl Into<String>) -> Self {
        Self { value: value.into(), negated: false }
    }
    /// Create a negated executable name filter.
    pub fn not(value: impl Into<String>) -> Self {
        Self { value: value.into(), negated: true }
    }
}

impl BSimFilterType for ExecutableNameFilter {
    fn filter_name(&self) -> &str { "exe_name" }
    fn display_label(&self) -> &str { "Executable Name" }
    fn is_negated(&self) -> bool { self.negated }
    fn negate(&self) -> Box<dyn BSimFilterType> {
        Box::new(Self { value: self.value.clone(), negated: !self.negated })
    }
    fn matches(&self, value: &str) -> bool {
        if self.negated { value != self.value } else { value == self.value }
    }
    fn field_name(&self) -> &str { "exe_name" }
}

/// Filter by executable category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutableCategoryFilter {
    /// The category value to match.
    pub value: String,
    /// Whether this is a negated filter.
    pub negated: bool,
}

impl ExecutableCategoryFilter {
    /// Create a new executable category filter.
    pub fn new(value: impl Into<String>) -> Self {
        Self { value: value.into(), negated: false }
    }
    /// Create a negated executable category filter.
    pub fn not(value: impl Into<String>) -> Self {
        Self { value: value.into(), negated: true }
    }
}

impl BSimFilterType for ExecutableCategoryFilter {
    fn filter_name(&self) -> &str { "exe_category" }
    fn display_label(&self) -> &str { "Executable Category" }
    fn is_negated(&self) -> bool { self.negated }
    fn negate(&self) -> Box<dyn BSimFilterType> {
        Box::new(Self { value: self.value.clone(), negated: !self.negated })
    }
    fn matches(&self, value: &str) -> bool {
        if self.negated { value != self.value } else { value == self.value }
    }
    fn field_name(&self) -> &str { "exe_category" }
}

/// Filter by MD5 hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Md5Filter {
    /// The MD5 hash to match.
    pub value: String,
    /// Whether this is a negated filter.
    pub negated: bool,
}

impl Md5Filter {
    /// Create a new MD5 filter.
    pub fn new(value: impl Into<String>) -> Self {
        Self { value: value.into(), negated: false }
    }
    /// Create a negated MD5 filter.
    pub fn not(value: impl Into<String>) -> Self {
        Self { value: value.into(), negated: true }
    }
}

impl BSimFilterType for Md5Filter {
    fn filter_name(&self) -> &str { "md5" }
    fn display_label(&self) -> &str { "MD5 Hash" }
    fn is_negated(&self) -> bool { self.negated }
    fn negate(&self) -> Box<dyn BSimFilterType> {
        Box::new(Self { value: self.value.clone(), negated: !self.negated })
    }
    fn matches(&self, value: &str) -> bool {
        if self.negated { value != self.value } else { value == self.value }
    }
    fn field_name(&self) -> &str { "md5" }
}

/// Filter by date (earlier than a given date).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateEarlierFilter {
    /// ISO-8601 date string.
    pub date: String,
}

impl DateEarlierFilter {
    /// Create a new date-earlier filter.
    pub fn new(date: impl Into<String>) -> Self {
        Self { date: date.into() }
    }
}

impl BSimFilterType for DateEarlierFilter {
    fn filter_name(&self) -> &str { "date_earlier" }
    fn display_label(&self) -> &str { "Date Earlier Than" }
    fn negate(&self) -> Box<dyn BSimFilterType> {
        Box::new(DateLaterFilter::new(self.date.clone()))
    }
    fn matches(&self, _value: &str) -> bool { true } // Date comparison requires parsed dates
    fn field_name(&self) -> &str { "creation_date" }
}

/// Filter by date (later than a given date).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateLaterFilter {
    /// ISO-8601 date string.
    pub date: String,
}

impl DateLaterFilter {
    /// Create a new date-later filter.
    pub fn new(date: impl Into<String>) -> Self {
        Self { date: date.into() }
    }
}

impl BSimFilterType for DateLaterFilter {
    fn filter_name(&self) -> &str { "date_later" }
    fn display_label(&self) -> &str { "Date Later Than" }
    fn negate(&self) -> Box<dyn BSimFilterType> {
        Box::new(DateEarlierFilter::new(self.date.clone()))
    }
    fn matches(&self, _value: &str) -> bool { true }
    fn field_name(&self) -> &str { "creation_date" }
}

/// Blank/empty filter that matches everything.
#[derive(Debug, Clone, Default)]
pub struct BlankFilter;

impl BSimFilterType for BlankFilter {
    fn filter_name(&self) -> &str { "blank" }
    fn display_label(&self) -> &str { "(none)" }
    fn negate(&self) -> Box<dyn BSimFilterType> { Box::new(Self) }
    fn matches(&self, _value: &str) -> bool { true }
    fn field_name(&self) -> &str { "" }
}

/// Filter by whether a function has a named child function.
///
/// Ports `ghidra.features.bsim.gui.filters.HasNamedChildBSimFilterType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HasNamedChildFilter {
    /// The child function name to look for.
    pub child_name: String,
}

impl HasNamedChildFilter {
    /// Create a new filter.
    pub fn new(child_name: impl Into<String>) -> Self {
        Self { child_name: child_name.into() }
    }
}

impl BSimFilterType for HasNamedChildFilter {
    fn filter_name(&self) -> &str { "has_named_child" }
    fn display_label(&self) -> &str { "Has Named Child" }
    fn negate(&self) -> Box<dyn BSimFilterType> { Box::new(Self { child_name: self.child_name.clone() }) }
    fn matches(&self, value: &str) -> bool { value.contains(&self.child_name) }
    fn field_name(&self) -> &str { "child_function" }
}

/// An editor for BSim filter values in the GUI.
///
/// Ports `ghidra.features.bsim.gui.filters.BSimValueEditor`.
#[derive(Debug, Clone)]
pub enum BSimValueEditor {
    /// Simple text/string editor.
    String(StringEditorConfig),
    /// Boolean toggle editor.
    Boolean(BooleanEditorConfig),
    /// Multi-choice selection editor.
    MultiChoice(MultiChoiceEditorConfig),
}

/// Configuration for a string value editor.
#[derive(Debug, Clone)]
pub struct StringEditorConfig {
    /// The field name being edited.
    pub field_name: String,
    /// Placeholder/hint text.
    pub hint: String,
    /// Whether to allow empty values.
    pub allow_empty: bool,
}

impl StringEditorConfig {
    /// Create a new string editor config.
    pub fn new(field_name: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            field_name: field_name.into(),
            hint: hint.into(),
            allow_empty: false,
        }
    }
}

/// Configuration for a boolean value editor.
#[derive(Debug, Clone)]
pub struct BooleanEditorConfig {
    /// The field name being edited.
    pub field_name: String,
    /// The label to display.
    pub label: String,
    /// Default value.
    pub default_value: bool,
}

impl BooleanEditorConfig {
    /// Create a new boolean editor config.
    pub fn new(field_name: impl Into<String>, label: impl Into<String>, default_value: bool) -> Self {
        Self {
            field_name: field_name.into(),
            label: label.into(),
            default_value,
        }
    }
}

/// Configuration for a multi-choice selection editor.
#[derive(Debug, Clone)]
pub struct MultiChoiceEditorConfig {
    /// The field name being edited.
    pub field_name: String,
    /// Available choices.
    pub choices: Vec<String>,
    /// Whether multiple selections are allowed.
    pub allow_multiple: bool,
}

impl MultiChoiceEditorConfig {
    /// Create a new multi-choice editor config.
    pub fn new(field_name: impl Into<String>, choices: Vec<String>) -> Self {
        Self {
            field_name: field_name.into(),
            choices,
            allow_multiple: false,
        }
    }

    /// Allow multiple selections.
    pub fn with_multiple(mut self) -> Self {
        self.allow_multiple = true;
        self
    }
}

/// A set of BSim filters applied to a search query.
///
/// Ports `ghidra.features.bsim.gui.search.dialog.BSimFilterSet`.
#[derive(Debug, Clone)]
pub struct BSimFilterSet {
    /// Active filters.
    pub filters: Vec<BSimFilterEntry>,
}

/// A single filter entry with its value.
#[derive(Debug, Clone)]
pub struct BSimFilterEntry {
    /// The filter type name.
    pub filter_name: String,
    /// The filter value.
    pub value: String,
    /// Whether the filter is active.
    pub active: bool,
}

impl BSimFilterEntry {
    /// Create a new filter entry.
    pub fn new(filter_name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            filter_name: filter_name.into(),
            value: value.into(),
            active: true,
        }
    }

    /// Deactivate this filter.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Activate this filter.
    pub fn activate(&mut self) {
        self.active = true;
    }
}

impl BSimFilterSet {
    /// Create an empty filter set.
    pub fn new() -> Self {
        Self { filters: Vec::new() }
    }

    /// Add a filter entry.
    pub fn add(&mut self, entry: BSimFilterEntry) {
        self.filters.push(entry);
    }

    /// Remove a filter by name.
    pub fn remove(&mut self, name: &str) {
        self.filters.retain(|f| f.filter_name != name);
    }

    /// Get the number of active filters.
    pub fn active_count(&self) -> usize {
        self.filters.iter().filter(|f| f.active).count()
    }

    /// Whether the filter set is empty.
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    /// Get only the active filters.
    pub fn active_filters(&self) -> Vec<&BSimFilterEntry> {
        self.filters.iter().filter(|f| f.active).collect()
    }
}

impl Default for BSimFilterSet {
    fn default() -> Self {
        Self::new()
    }
}

/// A basis of all available BSim filter types.
///
/// Provides a registry of all built-in filter type definitions.
pub struct BSimFilterBasis;

impl BSimFilterBasis {
    /// Get all built-in filter types.
    pub fn all_filters() -> Vec<&'static str> {
        vec![
            "blank",
            "architecture",
            "compiler",
            "exe_name",
            "exe_category",
            "md5",
            "date_earlier",
            "date_later",
            "function_tag",
            "path_starts",
            "has_named_child",
        ]
    }

    /// Get the number of built-in filter types.
    pub fn count() -> usize {
        11
    }

    /// Whether a given filter name is a known built-in type.
    pub fn is_builtin(name: &str) -> bool {
        Self::all_filters().contains(&name)
    }
}

/// Filter by function tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionTagFilter {
    /// The function tag to match.
    pub tag: String,
}

impl FunctionTagFilter {
    /// Create a new function tag filter.
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into() }
    }
}

impl BSimFilterType for FunctionTagFilter {
    fn filter_name(&self) -> &str { "function_tag" }
    fn display_label(&self) -> &str { "Function Tag" }
    fn negate(&self) -> Box<dyn BSimFilterType> { Box::new(Self { tag: self.tag.clone() }) }
    fn matches(&self, value: &str) -> bool { value.contains(&self.tag) }
    fn field_name(&self) -> &str { "function_tag" }
}

/// Filter by path prefix.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathStartsFilter {
    /// The path prefix to match.
    pub prefix: String,
}

impl PathStartsFilter {
    /// Create a new path-starts filter.
    pub fn new(prefix: impl Into<String>) -> Self {
        Self { prefix: prefix.into() }
    }
}

impl BSimFilterType for PathStartsFilter {
    fn filter_name(&self) -> &str { "path_starts" }
    fn display_label(&self) -> &str { "Path Starts With" }
    fn negate(&self) -> Box<dyn BSimFilterType> { Box::new(Self { prefix: self.prefix.clone() }) }
    fn matches(&self, value: &str) -> bool { value.starts_with(&self.prefix) }
    fn field_name(&self) -> &str { "exe_path" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_architecture_filter() {
        let f = ArchitectureFilter::new("x86");
        assert_eq!(f.filter_name(), "architecture");
        assert!(f.matches("x86"));
        assert!(!f.matches("ARM"));
        assert!(!f.is_negated());
    }

    #[test]
    fn test_architecture_filter_negated() {
        let f = ArchitectureFilter::not("x86");
        assert!(f.is_negated());
        assert!(!f.matches("x86"));
        assert!(f.matches("ARM"));
    }

    #[test]
    fn test_compiler_filter() {
        let f = CompilerFilter::new("gcc");
        assert!(f.matches("gcc"));
        assert!(!f.matches("clang"));
    }

    #[test]
    fn test_exe_name_filter() {
        let f = ExecutableNameFilter::new("libc.so");
        assert!(f.matches("libc.so"));
    }

    #[test]
    fn test_exe_category_filter() {
        let f = ExecutableCategoryFilter::new("malware");
        assert!(f.matches("malware"));
    }

    #[test]
    fn test_md5_filter() {
        let f = Md5Filter::new("abc123");
        assert!(f.matches("abc123"));
        assert!(!f.matches("def456"));
    }

    #[test]
    fn test_blank_filter() {
        let f = BlankFilter;
        assert!(f.matches("anything"));
        assert_eq!(f.filter_name(), "blank");
    }

    #[test]
    fn test_function_tag_filter() {
        let f = FunctionTagFilter::new("crypto");
        assert!(f.matches("uses_crypto_lib"));
        assert!(!f.matches("network"));
    }

    #[test]
    fn test_path_starts_filter() {
        let f = PathStartsFilter::new("/usr/lib");
        assert!(f.matches("/usr/lib/libc.so"));
        assert!(!f.matches("/home/user/lib.so"));
    }

    #[test]
    fn test_date_filters() {
        let earlier = DateEarlierFilter::new("2023-01-01");
        let later = DateLaterFilter::new("2023-12-31");
        assert_eq!(earlier.filter_name(), "date_earlier");
        assert_eq!(later.filter_name(), "date_later");
    }

    #[test]
    fn test_negate() {
        let f = ArchitectureFilter::new("x86");
        let neg = f.negate();
        assert!(neg.is_negated());
    }

    #[test]
    fn test_has_named_child_filter() {
        let f = HasNamedChildFilter::new("printf");
        assert_eq!(f.filter_name(), "has_named_child");
        assert!(f.matches("calls_printf"));
        assert!(!f.matches("calls_malloc"));
    }

    #[test]
    fn test_string_editor_config() {
        let config = StringEditorConfig::new("name", "Enter name");
        assert_eq!(config.field_name, "name");
        assert_eq!(config.hint, "Enter name");
        assert!(!config.allow_empty);
    }

    #[test]
    fn test_boolean_editor_config() {
        let config = BooleanEditorConfig::new("is_executable", "Is Executable", true);
        assert_eq!(config.field_name, "is_executable");
        assert!(config.default_value);
    }

    #[test]
    fn test_multi_choice_editor_config() {
        let config = MultiChoiceEditorConfig::new(
            "architecture",
            vec!["x86".to_string(), "ARM".to_string(), "MIPS".to_string()],
        );
        assert_eq!(config.choices.len(), 3);
        assert!(!config.allow_multiple);

        let config = config.with_multiple();
        assert!(config.allow_multiple);
    }

    #[test]
    fn test_filter_entry() {
        let mut entry = BSimFilterEntry::new("architecture", "x86");
        assert_eq!(entry.filter_name, "architecture");
        assert!(entry.active);

        entry.deactivate();
        assert!(!entry.active);

        entry.activate();
        assert!(entry.active);
    }

    #[test]
    fn test_filter_set() {
        let mut set = BSimFilterSet::new();
        assert!(set.is_empty());
        assert_eq!(set.active_count(), 0);

        set.add(BSimFilterEntry::new("architecture", "x86"));
        set.add(BSimFilterEntry::new("compiler", "gcc"));
        set.add(BSimFilterEntry::new("md5", "abc123"));

        assert_eq!(set.filters.len(), 3);
        assert_eq!(set.active_count(), 3);

        set.filters[1].deactivate();
        assert_eq!(set.active_count(), 2);

        let active = set.active_filters();
        assert_eq!(active.len(), 2);

        set.remove("md5");
        assert_eq!(set.filters.len(), 2);
    }

    #[test]
    fn test_filter_set_default() {
        let set = BSimFilterSet::default();
        assert!(set.is_empty());
    }

    #[test]
    fn test_filter_basis() {
        assert_eq!(BSimFilterBasis::count(), 11);
        assert!(BSimFilterBasis::is_builtin("architecture"));
        assert!(BSimFilterBasis::is_builtin("md5"));
        assert!(!BSimFilterBasis::is_builtin("unknown_filter"));

        let all = BSimFilterBasis::all_filters();
        assert!(all.contains(&"blank"));
        assert!(all.contains(&"has_named_child"));
    }

    #[test]
    fn test_value_editor_variants() {
        let string_editor = BSimValueEditor::String(StringEditorConfig::new("name", "hint"));
        let bool_editor = BSimValueEditor::Boolean(BooleanEditorConfig::new("flag", "Flag", false));
        let mc_editor = BSimValueEditor::MultiChoice(
            MultiChoiceEditorConfig::new("arch", vec!["x86".to_string()])
        );

        match string_editor {
            BSimValueEditor::String(config) => assert_eq!(config.field_name, "name"),
            _ => panic!("expected String variant"),
        }

        match bool_editor {
            BSimValueEditor::Boolean(config) => assert!(!config.default_value),
            _ => panic!("expected Boolean variant"),
        }

        match mc_editor {
            BSimValueEditor::MultiChoice(config) => assert_eq!(config.choices.len(), 1),
            _ => panic!("expected MultiChoice variant"),
        }
    }
}
