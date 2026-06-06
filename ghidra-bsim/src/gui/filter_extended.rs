//! Extended BSim filter types ported from Ghidra's Java BSim feature.
//!
//! Ports the remaining filter type classes from `ghidra.features.bsim.gui.filters`:
//! - `BSimFilterType` -- base filter type trait and registry
//! - `ArchitectureBSimFilterType` -- filter by processor architecture
//! - `BlankBSimFilterType` -- placeholder filter
//! - `NotArchitectureBSimFilterType` -- negated architecture filter
//! - `NotCompilerBSimFilterType` -- negated compiler filter
//! - `NotExecutableNameBSimFilterType` -- negated executable name filter
//! - `NotExecutableCategoryBSimFilterType` -- negated category filter
//! - `NotMd5BSimFilterType` -- negated MD5 filter
//! - `DateBSimFilterType` -- date-based filters
//! - `DateLaterBSimFilterType` -- filter by date later than
//! - `ExecutableCategoryBSimFilterType` -- filter by executable category
//! - `FunctionTagBSimFilterType` -- filter by function tags

use std::collections::HashMap;
use std::fmt;

// ============================================================================
// BSimFilterType -- base trait
// ============================================================================

/// Base trait for BSim filter types.
///
/// Each filter type represents a different filter criteria that can be applied
/// to a BSim search query.
/// Ported from `ghidra.features.bsim.gui.filters.BSimFilterType`.
pub trait BSimFilterType: fmt::Display {
    /// The XML serialization tag name.
    fn xml_value(&self) -> &str;

    /// The hint text shown in the GUI input field.
    fn hint(&self) -> &str;

    /// The display label.
    fn label(&self) -> &str;

    /// Whether this is a callgraph-based child filter.
    fn is_child_filter(&self) -> bool {
        false
    }

    /// Whether this is a blank (unused) filter.
    fn is_blank(&self) -> bool {
        false
    }

    /// Whether IDs must be resolved relative to the local column database.
    fn is_local(&self) -> bool {
        true
    }

    /// Whether multiple entries of this filter type are allowed.
    fn is_multiple_entry_allowed(&self) -> bool {
        true
    }

    /// Whether multiple entries should be OR'd (true) or AND'd (false).
    fn or_multiple_entries(&self) -> bool {
        true
    }

    /// Evaluate this filter against an executable record's property.
    fn evaluate(&self, property_value: &str, filter_value: &str) -> bool;

    /// Whether the given string is a valid value for this filter.
    fn is_valid_value(&self, value: &str) -> bool {
        !value.is_empty()
    }

    /// Normalize a value for comparison.
    fn normalize_value(&self, value: &str) -> String {
        value.trim().to_string()
    }

    /// Build a combined SQL clause from sub-clauses.
    fn build_sql_combined_clause(&self, sub_clauses: &[String]) -> String {
        let appender = if self.or_multiple_entries() {
            " OR "
        } else {
            " AND "
        };
        let mut clause = String::from("(");
        for (i, sub) in sub_clauses.iter().enumerate() {
            if i > 0 {
                clause.push_str(appender);
            }
            clause.push_str(sub);
        }
        clause.push(')');
        clause
    }

    /// Build a combined Elasticsearch clause from sub-clauses.
    fn build_elastic_combined_clause(&self, sub_clauses: &[String]) -> String {
        let appender = if self.or_multiple_entries() {
            " || "
        } else {
            " && "
        };
        let mut clause = String::from("(");
        for (i, sub) in sub_clauses.iter().enumerate() {
            if i > 0 {
                clause.push_str(appender);
            }
            clause.push_str(sub);
        }
        clause.push(')');
        clause
    }
}

// ============================================================================
// BlankBSimFilterType
// ============================================================================

/// A blank (placeholder) filter type.
///
/// Used as a default/unselected state in the GUI.
/// Ported from `ghidra.features.bsim.gui.filters.BlankBSimFilterType`.
#[derive(Debug, Clone)]
pub struct BlankBSimFilterType;

impl fmt::Display for BlankBSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blank")
    }
}

impl BSimFilterType for BlankBSimFilterType {
    fn xml_value(&self) -> &str {
        "blank"
    }
    fn hint(&self) -> &str {
        ""
    }
    fn label(&self) -> &str {
        "Blank"
    }
    fn is_blank(&self) -> bool {
        true
    }
    fn evaluate(&self, _property_value: &str, _filter_value: &str) -> bool {
        true
    }
}

// ============================================================================
// ArchitectureBSimFilterType
// ============================================================================

/// Filter functions based on a Ghidra computer architecture specification.
///
/// Format: `processor:language:endian:version` (e.g., `x86:LE:64:default`).
/// Ported from `ghidra.features.bsim.gui.filters.ArchitectureBSimFilterType`.
#[derive(Debug, Clone)]
pub struct ArchitectureBSimFilterType;

impl fmt::Display for ArchitectureBSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Architecture equals")
    }
}

impl BSimFilterType for ArchitectureBSimFilterType {
    fn xml_value(&self) -> &str {
        "archequals"
    }
    fn hint(&self) -> &str {
        "x86:LE:64:default"
    }
    fn label(&self) -> &str {
        "Architecture equals"
    }
    fn evaluate(&self, property_value: &str, filter_value: &str) -> bool {
        property_value == filter_value
    }
}

// ============================================================================
// NotArchitectureBSimFilterType
// ============================================================================

/// Negated architecture filter -- excludes functions with a specific architecture.
///
/// Ported from `ghidra.features.bsim.gui.filters.NotArchitectureBSimFilterType`.
#[derive(Debug, Clone)]
pub struct NotArchitectureBSimFilterType;

impl fmt::Display for NotArchitectureBSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Architecture not equals")
    }
}

impl BSimFilterType for NotArchitectureBSimFilterType {
    fn xml_value(&self) -> &str {
        "notarchequals"
    }
    fn hint(&self) -> &str {
        "x86:LE:64:default"
    }
    fn label(&self) -> &str {
        "Architecture not equals"
    }
    fn evaluate(&self, property_value: &str, filter_value: &str) -> bool {
        property_value != filter_value
    }
}

// ============================================================================
// CompilerBSimFilterType
// ============================================================================

/// Filter functions based on the compiler that produced the executable.
///
/// Ported from `ghidra.features.bsim.gui.filters.CompilerBSimFilterType`.
#[derive(Debug, Clone)]
pub struct CompilerBSimFilterType;

impl fmt::Display for CompilerBSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Compiler equals")
    }
}

impl BSimFilterType for CompilerBSimFilterType {
    fn xml_value(&self) -> &str {
        "compilequals"
    }
    fn hint(&self) -> &str {
        "gcc"
    }
    fn label(&self) -> &str {
        "Compiler equals"
    }
    fn evaluate(&self, property_value: &str, filter_value: &str) -> bool {
        property_value.eq_ignore_ascii_case(filter_value)
    }
}

// ============================================================================
// NotCompilerBSimFilterType
// ============================================================================

/// Negated compiler filter.
///
/// Ported from `ghidra.features.bsim.gui.filters.NotCompilerBSimFilterType`.
#[derive(Debug, Clone)]
pub struct NotCompilerBSimFilterType;

impl fmt::Display for NotCompilerBSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Compiler not equals")
    }
}

impl BSimFilterType for NotCompilerBSimFilterType {
    fn xml_value(&self) -> &str {
        "notcompilequals"
    }
    fn hint(&self) -> &str {
        "gcc"
    }
    fn label(&self) -> &str {
        "Compiler not equals"
    }
    fn evaluate(&self, property_value: &str, filter_value: &str) -> bool {
        !property_value.eq_ignore_ascii_case(filter_value)
    }
}

// ============================================================================
// ExecutableNameBSimFilterType
// ============================================================================

/// Filter by executable name.
///
/// Ported from `ghidra.features.bsim.gui.filters.ExecutableNameBSimFilterType`.
#[derive(Debug, Clone)]
pub struct ExecutableNameBSimFilterType;

impl fmt::Display for ExecutableNameBSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Executable name equals")
    }
}

impl BSimFilterType for ExecutableNameBSimFilterType {
    fn xml_value(&self) -> &str {
        "exenamequals"
    }
    fn hint(&self) -> &str {
        "libc.so"
    }
    fn label(&self) -> &str {
        "Executable name equals"
    }
    fn evaluate(&self, property_value: &str, filter_value: &str) -> bool {
        property_value == filter_value
    }
}

// ============================================================================
// NotExecutableNameBSimFilterType
// ============================================================================

/// Negated executable name filter.
///
/// Ported from `ghidra.features.bsim.gui.filters.NotExecutableNameBSimFilterType`.
#[derive(Debug, Clone)]
pub struct NotExecutableNameBSimFilterType;

impl fmt::Display for NotExecutableNameBSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Executable name not equals")
    }
}

impl BSimFilterType for NotExecutableNameBSimFilterType {
    fn xml_value(&self) -> &str {
        "notexenamequals"
    }
    fn hint(&self) -> &str {
        "libc.so"
    }
    fn label(&self) -> &str {
        "Executable name not equals"
    }
    fn evaluate(&self, property_value: &str, filter_value: &str) -> bool {
        property_value != filter_value
    }
}

// ============================================================================
// Md5BSimFilterType
// ============================================================================

/// Filter by MD5 hash of the executable.
///
/// Ported from `ghidra.features.bsim.gui.filters.Md5BSimFilterType`.
#[derive(Debug, Clone)]
pub struct Md5BSimFilterType;

impl fmt::Display for Md5BSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MD5 equals")
    }
}

impl BSimFilterType for Md5BSimFilterType {
    fn xml_value(&self) -> &str {
        "md5equals"
    }
    fn hint(&self) -> &str {
        "d41d8cd98f00b204e9800998ecf8427e"
    }
    fn label(&self) -> &str {
        "MD5 equals"
    }
    fn evaluate(&self, property_value: &str, filter_value: &str) -> bool {
        property_value.eq_ignore_ascii_case(filter_value)
    }
}

// ============================================================================
// NotMd5BSimFilterType
// ============================================================================

/// Negated MD5 filter.
///
/// Ported from `ghidra.features.bsim.gui.filters.NotMd5BSimFilterType`.
#[derive(Debug, Clone)]
pub struct NotMd5BSimFilterType;

impl fmt::Display for NotMd5BSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MD5 not equals")
    }
}

impl BSimFilterType for NotMd5BSimFilterType {
    fn xml_value(&self) -> &str {
        "notmd5equals"
    }
    fn hint(&self) -> &str {
        "d41d8cd98f00b204e9800998ecf8427e"
    }
    fn label(&self) -> &str {
        "MD5 not equals"
    }
    fn evaluate(&self, property_value: &str, filter_value: &str) -> bool {
        !property_value.eq_ignore_ascii_case(filter_value)
    }
}

// ============================================================================
// PathStartsBSimFilterType
// ============================================================================

/// Filter by path prefix of the executable.
///
/// Ported from `ghidra.features.bsim.gui.filters.PathStartsBSimFilterType`.
#[derive(Debug, Clone)]
pub struct PathStartsBSimFilterType;

impl fmt::Display for PathStartsBSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Path starts with")
    }
}

impl BSimFilterType for PathStartsBSimFilterType {
    fn xml_value(&self) -> &str {
        "pathstarts"
    }
    fn hint(&self) -> &str {
        "/usr/lib/"
    }
    fn label(&self) -> &str {
        "Path starts with"
    }
    fn evaluate(&self, property_value: &str, filter_value: &str) -> bool {
        property_value.starts_with(filter_value)
    }
}

// ============================================================================
// HasNamedChildBSimFilterType
// ============================================================================

/// Filter by whether the function has a named child (callgraph-based).
///
/// Ported from `ghidra.features.bsim.gui.filters.HasNamedChildBSimFilterType`.
#[derive(Debug, Clone)]
pub struct HasNamedChildBSimFilterType {
    /// The function name to search for in children.
    pub function_name: String,
}

impl HasNamedChildBSimFilterType {
    /// Create a new has-named-child filter.
    pub fn new(function_name: impl Into<String>) -> Self {
        Self {
            function_name: function_name.into(),
        }
    }
}

impl fmt::Display for HasNamedChildBSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Has named child")
    }
}

impl BSimFilterType for HasNamedChildBSimFilterType {
    fn xml_value(&self) -> &str {
        "hasnamedchild"
    }
    fn hint(&self) -> &str {
        "function_name"
    }
    fn label(&self) -> &str {
        "Has named child"
    }
    fn is_child_filter(&self) -> bool {
        true
    }
    fn evaluate(&self, _property_value: &str, _filter_value: &str) -> bool {
        // Requires callgraph analysis -- placeholder
        true
    }
}

// ============================================================================
// DateBSimFilterType -- base for date filters
// ============================================================================

/// A date-based filter type.
///
/// Base for date-earlier and date-later filters.
/// Ported from `ghidra.features.bsim.gui.filters.DateBSimFilterType`.
#[derive(Debug, Clone)]
pub struct DateBSimFilterType {
    /// The column name (e.g., "Ingest Date").
    pub column_name: String,
    /// Whether this is a "later than" filter (true) or "earlier than" (false).
    pub is_later: bool,
}

impl DateBSimFilterType {
    /// Create a new date filter.
    pub fn new(column_name: impl Into<String>, is_later: bool) -> Self {
        Self {
            column_name: column_name.into(),
            is_later,
        }
    }
}

impl fmt::Display for DateBSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_later {
            write!(f, "{} later than", self.column_name)
        } else {
            write!(f, "{} earlier than", self.column_name)
        }
    }
}

impl BSimFilterType for DateBSimFilterType {
    fn xml_value(&self) -> &str {
        if self.is_later {
            "datelater"
        } else {
            "dateearlier"
        }
    }
    fn hint(&self) -> &str {
        "2024-01-01"
    }
    fn label(&self) -> &str {
        if self.is_later {
            "Date later than"
        } else {
            "Date earlier than"
        }
    }
    fn is_local(&self) -> bool {
        false
    }
    fn is_multiple_entry_allowed(&self) -> bool {
        false
    }
    fn evaluate(&self, _property_value: &str, _filter_value: &str) -> bool {
        // Date comparison requires parsing -- placeholder returns true
        true
    }
}

// ============================================================================
// DateEarlierBSimFilterType
// ============================================================================

/// Filter by date earlier than a given date.
///
/// Ported from `ghidra.features.bsim.gui.filters.DateEarlierBSimFilterType`.
#[derive(Debug, Clone)]
pub struct DateEarlierBSimFilterType {
    inner: DateBSimFilterType,
}

impl DateEarlierBSimFilterType {
    /// Create a new earlier-than-date filter.
    pub fn new(column_name: impl Into<String>) -> Self {
        Self {
            inner: DateBSimFilterType::new(column_name, false),
        }
    }
}

impl fmt::Display for DateEarlierBSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl BSimFilterType for DateEarlierBSimFilterType {
    fn xml_value(&self) -> &str {
        self.inner.xml_value()
    }
    fn hint(&self) -> &str {
        self.inner.hint()
    }
    fn label(&self) -> &str {
        self.inner.label()
    }
    fn is_local(&self) -> bool {
        false
    }
    fn is_multiple_entry_allowed(&self) -> bool {
        false
    }
    fn evaluate(&self, property_value: &str, filter_value: &str) -> bool {
        property_value < filter_value
    }
}

// ============================================================================
// DateLaterBSimFilterType
// ============================================================================

/// Filter by date later than a given date.
///
/// Ported from `ghidra.features.bsim.gui.filters.DateLaterBSimFilterType`.
#[derive(Debug, Clone)]
pub struct DateLaterBSimFilterType {
    inner: DateBSimFilterType,
}

impl DateLaterBSimFilterType {
    /// Create a new later-than-date filter.
    pub fn new(column_name: impl Into<String>) -> Self {
        Self {
            inner: DateBSimFilterType::new(column_name, true),
        }
    }
}

impl fmt::Display for DateLaterBSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

impl BSimFilterType for DateLaterBSimFilterType {
    fn xml_value(&self) -> &str {
        self.inner.xml_value()
    }
    fn hint(&self) -> &str {
        self.inner.hint()
    }
    fn label(&self) -> &str {
        self.inner.label()
    }
    fn is_local(&self) -> bool {
        false
    }
    fn is_multiple_entry_allowed(&self) -> bool {
        false
    }
    fn evaluate(&self, property_value: &str, filter_value: &str) -> bool {
        property_value > filter_value
    }
}

// ============================================================================
// ExecutableCategoryBSimFilterType
// ============================================================================

/// Filter by executable category (e.g., "malware", "firmware").
///
/// Ported from `ghidra.features.bsim.gui.filters.ExecutableCategoryBSimFilterType`.
#[derive(Debug, Clone)]
pub struct ExecutableCategoryBSimFilterType {
    /// The category name.
    pub category: String,
}

impl ExecutableCategoryBSimFilterType {
    /// Create a new executable category filter.
    pub fn new(category: impl Into<String>) -> Self {
        Self {
            category: category.into(),
        }
    }
}

impl fmt::Display for ExecutableCategoryBSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Category equals '{}'", self.category)
    }
}

impl BSimFilterType for ExecutableCategoryBSimFilterType {
    fn xml_value(&self) -> &str {
        "execat"
    }
    fn hint(&self) -> &str {
        "malware"
    }
    fn label(&self) -> &str {
        "Executable category equals"
    }
    fn evaluate(&self, property_value: &str, filter_value: &str) -> bool {
        property_value == filter_value
    }
}

// ============================================================================
// NotExecutableCategoryBSimFilterType
// ============================================================================

/// Negated executable category filter.
///
/// Ported from `ghidra.features.bsim.gui.filters.NotExecutableCategoryBSimFilterType`.
#[derive(Debug, Clone)]
pub struct NotExecutableCategoryBSimFilterType {
    /// The category name to exclude.
    pub category: String,
}

impl NotExecutableCategoryBSimFilterType {
    /// Create a new negated category filter.
    pub fn new(category: impl Into<String>) -> Self {
        Self {
            category: category.into(),
        }
    }
}

impl fmt::Display for NotExecutableCategoryBSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Category not equals '{}'", self.category)
    }
}

impl BSimFilterType for NotExecutableCategoryBSimFilterType {
    fn xml_value(&self) -> &str {
        "notexecat"
    }
    fn hint(&self) -> &str {
        "malware"
    }
    fn label(&self) -> &str {
        "Executable category not equals"
    }
    fn evaluate(&self, property_value: &str, filter_value: &str) -> bool {
        property_value != filter_value
    }
}

// ============================================================================
// FunctionTagBSimFilterType
// ============================================================================

/// Filter by function tag bitmask.
///
/// Ported from `ghidra.features.bsim.gui.filters.FunctionTagBSimFilterType`.
#[derive(Debug, Clone)]
pub struct FunctionTagBSimFilterType {
    /// Tag name.
    pub tag_name: String,
    /// Bitmask for this tag.
    pub flag: u32,
}

impl FunctionTagBSimFilterType {
    /// Bits reserved for built-in tags.
    pub const RESERVED_BITS: u32 = 3;
    /// Mask for KNOWN_LIBRARY tag.
    pub const KNOWN_LIBRARY_MASK: u32 = 1;
    /// Mask for HAS_UNIMPLEMENTED tag.
    pub const HAS_UNIMPLEMENTED_MASK: u32 = 2;
    /// Mask for HAS_BADDATA tag.
    pub const HAS_BADDATA_MASK: u32 = 4;

    /// Create a new function tag filter.
    pub fn new(tag_name: impl Into<String>, flag: u32) -> Self {
        Self {
            tag_name: tag_name.into(),
            flag,
        }
    }
}

impl fmt::Display for FunctionTagBSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag: {}", self.tag_name)
    }
}

impl BSimFilterType for FunctionTagBSimFilterType {
    fn xml_value(&self) -> &str {
        "functag"
    }
    fn hint(&self) -> &str {
        "TAG_NAME"
    }
    fn label(&self) -> &str {
        "Function tag"
    }
    fn evaluate(&self, property_value: &str, _filter_value: &str) -> bool {
        // Property value is a bitmask string
        if let Ok(mask) = property_value.parse::<u32>() {
            (mask & self.flag) != 0
        } else {
            false
        }
    }
}

// ============================================================================
// FilterRegistry -- central registry of all built-in filter types
// ============================================================================

/// A registry of all available BSim filter types.
///
/// Ported from the static `buildFilterBasis` method in `BSimFilterType`.
pub struct FilterRegistry {
    filters: Vec<Box<dyn BSimFilterType>>,
}

impl FilterRegistry {
    /// Create a new filter registry with all built-in filter types.
    pub fn new() -> Self {
        let mut filters: Vec<Box<dyn BSimFilterType>> = Vec::new();
        filters.push(Box::new(BlankBSimFilterType));
        filters.push(Box::new(ExecutableNameBSimFilterType));
        filters.push(Box::new(NotExecutableNameBSimFilterType));
        filters.push(Box::new(Md5BSimFilterType));
        filters.push(Box::new(NotMd5BSimFilterType));
        filters.push(Box::new(ArchitectureBSimFilterType));
        filters.push(Box::new(NotArchitectureBSimFilterType));
        filters.push(Box::new(CompilerBSimFilterType));
        filters.push(Box::new(NotCompilerBSimFilterType));
        filters.push(Box::new(PathStartsBSimFilterType));
        filters.push(Box::new(HasNamedChildBSimFilterType::new("")));
        filters.push(Box::new(DateEarlierBSimFilterType::new("Ingest Date")));
        filters.push(Box::new(DateLaterBSimFilterType::new("Ingest Date")));
        Self { filters }
    }

    /// Get all registered filter types.
    pub fn all_filters(&self) -> &[Box<dyn BSimFilterType>] {
        &self.filters
    }

    /// Find a filter by its XML value tag.
    pub fn find_by_xml_value(&self, xml_val: &str) -> Option<&dyn BSimFilterType> {
        self.filters
            .iter()
            .find(|f| f.xml_value() == xml_val)
            .map(|f| f.as_ref())
    }

    /// Get the number of registered filters.
    pub fn len(&self) -> usize {
        self.filters.len()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }
}

impl Default for FilterRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blank_filter() {
        let filter = BlankBSimFilterType;
        assert!(filter.is_blank());
        assert!(filter.evaluate("anything", "anything"));
        assert_eq!(filter.xml_value(), "blank");
    }

    #[test]
    fn test_architecture_filter() {
        let filter = ArchitectureBSimFilterType;
        assert!(filter.evaluate("x86:LE:64:default", "x86:LE:64:default"));
        assert!(!filter.evaluate("x86:LE:64:default", "ARM:LE:32:v8"));
        assert_eq!(filter.xml_value(), "archequals");
    }

    #[test]
    fn test_not_architecture_filter() {
        let filter = NotArchitectureBSimFilterType;
        assert!(!filter.evaluate("x86:LE:64:default", "x86:LE:64:default"));
        assert!(filter.evaluate("x86:LE:64:default", "ARM:LE:32:v8"));
    }

    #[test]
    fn test_compiler_filter() {
        let filter = CompilerBSimFilterType;
        assert!(filter.evaluate("GCC", "gcc"));
        assert!(filter.evaluate("gcc", "GCC"));
        assert!(!filter.evaluate("gcc", "clang"));
    }

    #[test]
    fn test_not_compiler_filter() {
        let filter = NotCompilerBSimFilterType;
        assert!(!filter.evaluate("GCC", "gcc"));
        assert!(filter.evaluate("gcc", "clang"));
    }

    #[test]
    fn test_executable_name_filter() {
        let filter = ExecutableNameBSimFilterType;
        assert!(filter.evaluate("libc.so", "libc.so"));
        assert!(!filter.evaluate("libc.so", "libm.so"));
    }

    #[test]
    fn test_md5_filter() {
        let filter = Md5BSimFilterType;
        assert!(filter.evaluate(
            "d41d8cd98f00b204e9800998ecf8427e",
            "d41d8cd98f00b204e9800998ecf8427e"
        ));
        assert!(filter.evaluate(
            "D41D8CD98F00B204E9800998ECF8427E",
            "d41d8cd98f00b204e9800998ecf8427e"
        ));
    }

    #[test]
    fn test_path_starts_filter() {
        let filter = PathStartsBSimFilterType;
        assert!(filter.evaluate("/usr/lib/libc.so", "/usr/lib/"));
        assert!(!filter.evaluate("/opt/lib/libc.so", "/usr/lib/"));
    }

    #[test]
    fn test_date_filters() {
        let earlier = DateEarlierBSimFilterType::new("Ingest Date");
        assert!(earlier.evaluate("2023-01-01", "2024-01-01"));
        assert!(!earlier.evaluate("2024-06-01", "2024-01-01"));
        assert!(!earlier.is_multiple_entry_allowed());

        let later = DateLaterBSimFilterType::new("Ingest Date");
        assert!(later.evaluate("2024-06-01", "2024-01-01"));
        assert!(!later.evaluate("2023-01-01", "2024-01-01"));
    }

    #[test]
    fn test_executable_category_filter() {
        let filter = ExecutableCategoryBSimFilterType::new("malware");
        assert!(filter.evaluate("malware", "malware"));
        assert!(!filter.evaluate("firmware", "malware"));
        assert_eq!(filter.category, "malware");
    }

    #[test]
    fn test_not_executable_category_filter() {
        let filter = NotExecutableCategoryBSimFilterType::new("malware");
        assert!(!filter.evaluate("malware", "malware"));
        assert!(filter.evaluate("firmware", "malware"));
    }

    #[test]
    fn test_function_tag_filter() {
        let filter = FunctionTagBSimFilterType::new("KNOWN_LIBRARY", FunctionTagBSimFilterType::KNOWN_LIBRARY_MASK);
        assert!(filter.evaluate("7", "")); // 7 & 1 = 1
        assert!(filter.evaluate("5", "")); // 5 & 1 = 1
        assert!(!filter.evaluate("4", "")); // 4 & 1 = 0
        assert!(!filter.evaluate("2", "")); // 2 & 1 = 0
    }

    #[test]
    fn test_filter_registry() {
        let registry = FilterRegistry::new();
        assert!(registry.len() > 10);
        assert!(!registry.is_empty());

        let arch = registry.find_by_xml_value("archequals");
        assert!(arch.is_some());
        assert_eq!(arch.unwrap().label(), "Architecture equals");

        let blank = registry.find_by_xml_value("blank");
        assert!(blank.is_some());
        assert!(blank.unwrap().is_blank());

        assert!(registry.find_by_xml_value("nonexistent").is_none());
    }

    #[test]
    fn test_combined_clause_building() {
        let filter = ArchitectureBSimFilterType;
        let clauses = vec![
            "arch = 'x86'".to_string(),
            "arch = 'ARM'".to_string(),
        ];
        let combined = filter.build_sql_combined_clause(&clauses);
        assert_eq!(combined, "(arch = 'x86' OR arch = 'ARM')");
    }

    #[test]
    fn test_combined_elastic_clause() {
        let filter = ArchitectureBSimFilterType;
        let clauses = vec![
            "arch == 'x86'".to_string(),
            "arch == 'ARM'".to_string(),
        ];
        let combined = filter.build_elastic_combined_clause(&clauses);
        assert_eq!(combined, "(arch == 'x86' || arch == 'ARM')");
    }

    #[test]
    fn test_normalize_value() {
        let filter = ExecutableNameBSimFilterType;
        assert_eq!(filter.normalize_value("  hello  "), "hello");
    }

    #[test]
    fn test_date_filter_display() {
        let earlier = DateEarlierBSimFilterType::new("Ingest Date");
        let display = format!("{}", earlier);
        assert!(display.contains("earlier"));

        let later = DateLaterBSimFilterType::new("Build Date");
        let display = format!("{}", later);
        assert!(display.contains("later"));
    }

    #[test]
    fn test_has_named_child_filter() {
        let filter = HasNamedChildBSimFilterType::new("malloc");
        assert!(filter.is_child_filter());
        assert_eq!(filter.function_name, "malloc");
    }
}
