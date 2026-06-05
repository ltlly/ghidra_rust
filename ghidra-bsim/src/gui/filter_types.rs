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
    pub fn new(value: impl Into<String>) -> Self {
        Self { value: value.into(), negated: false }
    }
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
    pub value: String,
    pub negated: bool,
}

impl CompilerFilter {
    pub fn new(value: impl Into<String>) -> Self {
        Self { value: value.into(), negated: false }
    }
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
    pub value: String,
    pub negated: bool,
}

impl ExecutableNameFilter {
    pub fn new(value: impl Into<String>) -> Self {
        Self { value: value.into(), negated: false }
    }
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
    pub value: String,
    pub negated: bool,
}

impl ExecutableCategoryFilter {
    pub fn new(value: impl Into<String>) -> Self {
        Self { value: value.into(), negated: false }
    }
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
    pub value: String,
    pub negated: bool,
}

impl Md5Filter {
    pub fn new(value: impl Into<String>) -> Self {
        Self { value: value.into(), negated: false }
    }
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
    pub date: String,
}

impl DateLaterFilter {
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

/// Filter by function tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionTagFilter {
    pub tag: String,
}

impl FunctionTagFilter {
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
    pub prefix: String,
}

impl PathStartsFilter {
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
}
