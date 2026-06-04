//! Concrete BSim filter types -- port of Ghidra's `ghidra.features.bsim.gui.filters` package.
//!
//! Each filter type represents a different criteria for filtering BSim search results.
//! Filters can be combined into a `BSimFilterSet` and applied to queries.

use serde::{Deserialize, Serialize};

// ============================================================================
// BSimFilterType (abstract base)
// ============================================================================

/// The type of filter operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FilterOperation {
    /// Equals.
    Equals,
    /// Not equals.
    NotEquals,
    /// Contains.
    Contains,
    /// Not contains.
    NotContains,
    /// Starts with.
    StartsWith,
    /// Greater than (date).
    GreaterThan,
    /// Less than (date).
    LessThan,
    /// Has named child.
    HasNamedChild,
    /// Is blank (no filter).
    Blank,
}

impl Default for FilterOperation {
    fn default() -> Self {
        Self::Blank
    }
}

impl std::fmt::Display for FilterOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Equals => write!(f, "equals"),
            Self::NotEquals => write!(f, "not equals"),
            Self::Contains => write!(f, "contains"),
            Self::NotContains => write!(f, "not contains"),
            Self::StartsWith => write!(f, "starts with"),
            Self::GreaterThan => write!(f, "greater than"),
            Self::LessThan => write!(f, "less than"),
            Self::HasNamedChild => write!(f, "has named child"),
            Self::Blank => write!(f, "blank"),
        }
    }
}

/// Concrete BSim filter types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BSimFilterVariant {
    /// Blank / unused filter.
    Blank,
    /// Filter by executable name.
    ExecutableName(FilterOperation),
    /// Filter by MD5 hash.
    Md5(FilterOperation),
    /// Filter by architecture.
    Architecture(FilterOperation),
    /// Filter by compiler.
    Compiler(FilterOperation),
    /// Filter by executable category.
    ExecutableCategory(FilterOperation),
    /// Filter by date (earlier than or later than).
    Date(DateFilter),
    /// Filter by path prefix.
    PathStartsWith,
    /// Filter by function tag.
    FunctionTag(FunctionTagFilter),
    /// Filter by whether the function has a named child (callgraph).
    HasNamedChild,
}

/// Date-specific filter configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DateFilter {
    /// The date column name.
    pub column_name: String,
    /// Whether this is an "earlier than" filter (true) or "later than" (false).
    pub is_earlier: bool,
}

/// Function tag filter configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionTagFilter {
    /// The tag name.
    pub tag_name: String,
    /// Bitmask flag for the tag.
    pub flag: u32,
}

impl FunctionTagFilter {
    /// Known library function tag mask.
    pub const KNOWN_LIBRARY_MASK: u32 = 0x01;
    /// Has unimplemented function tag mask.
    pub const HAS_UNIMPLEMENTED_MASK: u32 = 0x02;
    /// Has bad data function tag mask.
    pub const HAS_BADDATA_MASK: u32 = 0x04;
    /// Number of reserved bits (first 3 are system-defined).
    pub const RESERVED_BITS: u32 = 3;
}

// ============================================================================
// BSimFilterType (concrete type with metadata)
// ============================================================================

/// A complete BSim filter with type, label, hint, and serialization metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BSimFilterType {
    /// The variant (which filter type this is).
    pub variant: BSimFilterVariant,
    /// Human-readable label for GUI menus.
    pub label: String,
    /// XML serialization tag name.
    pub xml_value: String,
    /// Hint text shown in the GUI input field.
    pub hint: String,
}

impl BSimFilterType {
    /// Create a new filter type.
    pub fn new(
        variant: BSimFilterVariant,
        label: impl Into<String>,
        xml_value: impl Into<String>,
        hint: impl Into<String>,
    ) -> Self {
        Self {
            variant,
            label: label.into(),
            xml_value: xml_value.into(),
            hint: hint.into(),
        }
    }

    /// Returns whether this is a child (callgraph) filter.
    pub fn is_child_filter(&self) -> bool {
        matches!(self.variant, BSimFilterVariant::HasNamedChild)
    }

    /// Returns whether this is a blank (unused) filter.
    pub fn is_blank(&self) -> bool {
        matches!(self.variant, BSimFilterVariant::Blank)
    }

    /// Returns whether multiple filters of this type are allowed.
    pub fn is_multiple_entry_allowed(&self) -> bool {
        true
    }

    /// Returns whether multiple filters of this type should be OR'd (vs AND'd).
    pub fn or_multiple_entries(&self) -> bool {
        true
    }

    /// Normalize a value for this filter (default: trim whitespace).
    pub fn normalize_value(&self, value: &str) -> String {
        value.trim().to_string()
    }
}

impl std::fmt::Display for BSimFilterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label)
    }
}

impl PartialOrd for BSimFilterType {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BSimFilterType {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.label.cmp(&other.label)
    }
}

// ============================================================================
// Filter factories
// ============================================================================

/// The standard blank filter.
pub fn blank_filter() -> BSimFilterType {
    BSimFilterType::new(BSimFilterVariant::Blank, "Blank", "blank", "")
}

/// Filter by executable name.
pub fn executable_name_filter(op: FilterOperation) -> BSimFilterType {
    let label = match op {
        FilterOperation::Equals => "Executable Name equals",
        FilterOperation::NotEquals => "Executable Name not equals",
        FilterOperation::Contains => "Executable Name contains",
        FilterOperation::NotContains => "Executable Name not contains",
        FilterOperation::StartsWith => "Executable Name starts with",
        _ => "Executable Name",
    };
    BSimFilterType::new(
        BSimFilterVariant::ExecutableName(op),
        label,
        "exename",
        "program.exe",
    )
}

/// Filter by MD5 hash.
pub fn md5_filter(op: FilterOperation) -> BSimFilterType {
    let label = match op {
        FilterOperation::Equals => "MD5 equals",
        FilterOperation::NotEquals => "MD5 not equals",
        _ => "MD5",
    };
    BSimFilterType::new(
        BSimFilterVariant::Md5(op),
        label,
        "md5",
        "d41d8cd98f00b204e9800998ecf8427e",
    )
}

/// Filter by architecture.
pub fn architecture_filter(op: FilterOperation) -> BSimFilterType {
    let label = match op {
        FilterOperation::Equals => "Architecture equals",
        FilterOperation::NotEquals => "Architecture not equals",
        _ => "Architecture",
    };
    BSimFilterType::new(
        BSimFilterVariant::Architecture(op),
        label,
        "archequals",
        "x86:LE:64:default",
    )
}

/// Filter by compiler.
pub fn compiler_filter(op: FilterOperation) -> BSimFilterType {
    let label = match op {
        FilterOperation::Equals => "Compiler equals",
        FilterOperation::NotEquals => "Compiler not equals",
        _ => "Compiler",
    };
    BSimFilterType::new(
        BSimFilterVariant::Compiler(op),
        label,
        "compequals",
        "gcc",
    )
}

/// Filter by executable category.
pub fn executable_category_filter(category: impl Into<String>) -> BSimFilterType {
    let cat = category.into();
    BSimFilterType::new(
        BSimFilterVariant::ExecutableCategory(FilterOperation::Equals),
        format!("Executable Category equals '{}'", cat),
        "execcat",
        &cat,
    )
}

/// Filter by date (earlier than).
pub fn date_earlier_filter(column_name: impl Into<String>) -> BSimFilterType {
    let col = column_name.into();
    BSimFilterType::new(
        BSimFilterVariant::Date(DateFilter {
            column_name: col.clone(),
            is_earlier: true,
        }),
        format!("{} earlier than", col),
        "date_earlier",
        "2024-01-01",
    )
}

/// Filter by date (later than).
pub fn date_later_filter(column_name: impl Into<String>) -> BSimFilterType {
    let col = column_name.into();
    BSimFilterType::new(
        BSimFilterVariant::Date(DateFilter {
            column_name: col.clone(),
            is_earlier: false,
        }),
        format!("{} later than", col),
        "date_later",
        "2024-01-01",
    )
}

/// Filter by path prefix.
pub fn path_starts_with_filter() -> BSimFilterType {
    BSimFilterType::new(
        BSimFilterVariant::PathStartsWith,
        "Path starts with",
        "pathstarts",
        "/usr/lib",
    )
}

/// Filter by function tag.
pub fn function_tag_filter(tag_name: impl Into<String>, flag: u32) -> BSimFilterType {
    let name = tag_name.into();
    BSimFilterType::new(
        BSimFilterVariant::FunctionTag(FunctionTagFilter {
            tag_name: name.clone(),
            flag,
        }),
        format!("Function has tag '{}'", name),
        "functag",
        &name,
    )
}

/// Filter by whether function has a named child in the callgraph.
pub fn has_named_child_filter() -> BSimFilterType {
    BSimFilterType::new(
        BSimFilterVariant::HasNamedChild,
        "Has named child",
        "haschild",
        "child_function",
    )
}

/// Get the base set of BSim filter types.
///
/// This corresponds to Ghidra's `buildFilterBasis()`.
pub fn get_base_filters() -> Vec<BSimFilterType> {
    vec![
        blank_filter(),
        executable_name_filter(FilterOperation::Equals),
        executable_name_filter(FilterOperation::NotEquals),
        md5_filter(FilterOperation::Equals),
        md5_filter(FilterOperation::NotEquals),
        architecture_filter(FilterOperation::Equals),
        architecture_filter(FilterOperation::NotEquals),
        compiler_filter(FilterOperation::Equals),
        compiler_filter(FilterOperation::NotEquals),
        path_starts_with_filter(),
        has_named_child_filter(),
    ]
}

/// Generate a possibly restricted/extended set of BSim filters based on
/// database information.
///
/// This corresponds to Ghidra's `generateBsimFilters()`.
pub fn generate_bsim_filters(
    include_child_filter: bool,
    executable_categories: &[String],
    date_column: Option<&str>,
    function_tags: &[String],
) -> Vec<BSimFilterType> {
    let mut filters: Vec<BSimFilterType> = Vec::new();

    for f in get_base_filters() {
        if f.is_child_filter() && !include_child_filter {
            continue;
        }
        filters.push(f);
    }

    // Add date filters
    let col = date_column.unwrap_or("Ingest Date");
    filters.push(date_earlier_filter(col));
    filters.push(date_later_filter(col));

    // Add executable category filters
    for cat in executable_categories {
        filters.push(executable_category_filter(cat));
    }

    // Add built-in function tag filters
    filters.push(function_tag_filter(
        "KNOWN_LIBRARY",
        FunctionTagFilter::KNOWN_LIBRARY_MASK,
    ));
    filters.push(function_tag_filter(
        "HAS_UNIMPLEMENTED",
        FunctionTagFilter::HAS_UNIMPLEMENTED_MASK,
    ));
    filters.push(function_tag_filter(
        "HAS_BADDATA",
        FunctionTagFilter::HAS_BADDATA_MASK,
    ));

    // Add user-defined function tag filters
    let mut flag: u32 = 1 << FunctionTagFilter::RESERVED_BITS;
    for tag in function_tags {
        filters.push(function_tag_filter(tag, flag));
        flag <<= 1;
    }

    filters
}

// ============================================================================
// BSimFilterSet
// ============================================================================

/// A set of active BSim filters with their values.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BSimFilterSet {
    /// Active filter entries (filter type + user-provided value).
    pub entries: Vec<FilterEntry>,
}

/// A single filter entry in a filter set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterEntry {
    /// The filter type.
    pub filter_type: BSimFilterType,
    /// The user-provided value for this filter.
    pub value: String,
}

impl BSimFilterSet {
    /// Create an empty filter set.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Add a filter entry.
    pub fn add(&mut self, filter_type: BSimFilterType, value: impl Into<String>) {
        let normalized = filter_type.normalize_value(&value.into());
        self.entries.push(FilterEntry {
            filter_type,
            value: normalized,
        });
    }

    /// Remove a filter entry at the given index.
    pub fn remove(&mut self, index: usize) -> Option<FilterEntry> {
        if index < self.entries.len() {
            Some(self.entries.remove(index))
        } else {
            None
        }
    }

    /// Number of active filters.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the filter set is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether any non-blank filters are active.
    pub fn has_active_filters(&self) -> bool {
        self.entries.iter().any(|e| !e.filter_type.is_blank())
    }

    /// Clear all filters.
    pub fn clear(&mut self) {
        self.entries.clear();
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
        let f = blank_filter();
        assert!(f.is_blank());
        assert!(!f.is_child_filter());
        assert_eq!(f.xml_value, "blank");
    }

    #[test]
    fn test_executable_name_filter() {
        let f = executable_name_filter(FilterOperation::Equals);
        assert!(!f.is_blank());
        assert_eq!(f.xml_value, "exename");
        assert!(f.label.contains("Executable Name"));
    }

    #[test]
    fn test_architecture_filter() {
        let f = architecture_filter(FilterOperation::Equals);
        assert_eq!(f.xml_value, "archequals");
        assert!(f.hint.contains("x86"));
    }

    #[test]
    fn test_md5_filter() {
        let f = md5_filter(FilterOperation::NotEquals);
        assert!(f.label.contains("not equals"));
        assert_eq!(f.xml_value, "md5");
    }

    #[test]
    fn test_date_earlier_filter() {
        let f = date_earlier_filter("Ingest Date");
        assert!(f.label.contains("earlier"));
        match &f.variant {
            BSimFilterVariant::Date(d) => {
                assert!(d.is_earlier);
                assert_eq!(d.column_name, "Ingest Date");
            }
            _ => panic!("expected Date variant"),
        }
    }

    #[test]
    fn test_date_later_filter() {
        let f = date_later_filter("Custom Date");
        assert!(f.label.contains("later"));
        match &f.variant {
            BSimFilterVariant::Date(d) => {
                assert!(!d.is_earlier);
                assert_eq!(d.column_name, "Custom Date");
            }
            _ => panic!("expected Date variant"),
        }
    }

    #[test]
    fn test_function_tag_filter() {
        let f = function_tag_filter("KNOWN_LIBRARY", FunctionTagFilter::KNOWN_LIBRARY_MASK);
        assert_eq!(f.xml_value, "functag");
        match &f.variant {
            BSimFilterVariant::FunctionTag(tag) => {
                assert_eq!(tag.tag_name, "KNOWN_LIBRARY");
                assert_eq!(tag.flag, FunctionTagFilter::KNOWN_LIBRARY_MASK);
            }
            _ => panic!("expected FunctionTag variant"),
        }
    }

    #[test]
    fn test_has_named_child_filter() {
        let f = has_named_child_filter();
        assert!(f.is_child_filter());
        assert!(!f.is_blank());
    }

    #[test]
    fn test_path_starts_with_filter() {
        let f = path_starts_with_filter();
        assert_eq!(f.xml_value, "pathstarts");
    }

    #[test]
    fn test_executable_category_filter() {
        let f = executable_category_filter("server");
        assert!(f.label.contains("server"));
        assert_eq!(f.xml_value, "execcat");
    }

    #[test]
    fn test_base_filters() {
        let filters = get_base_filters();
        assert_eq!(filters.len(), 11);
        assert!(filters[0].is_blank());
    }

    #[test]
    fn test_generate_bsim_filters() {
        let filters = generate_bsim_filters(
            true,
            &["server".to_string(), "client".to_string()],
            None,
            &[],
        );
        // 11 base + 2 date + 2 execcat + 3 built-in tags = 18
        assert!(filters.len() >= 18);

        // Check that HasNamedChild is included when include_child_filter is true
        assert!(filters.iter().any(|f| f.is_child_filter()));
    }

    #[test]
    fn test_generate_bsim_filters_no_children() {
        let filters = generate_bsim_filters(false, &[], None, &[]);
        assert!(!filters.iter().any(|f| f.is_child_filter()));
    }

    #[test]
    fn test_filter_set() {
        let mut set = BSimFilterSet::new();
        assert!(set.is_empty());
        assert!(!set.has_active_filters());

        set.add(architecture_filter(FilterOperation::Equals), "x86:LE:64:default");
        assert_eq!(set.len(), 1);
        assert!(set.has_active_filters());
        assert_eq!(set.entries[0].value, "x86:LE:64:default");

        set.add(blank_filter(), "");
        assert_eq!(set.len(), 2);
        assert!(set.has_active_filters()); // still has the arch filter

        set.remove(0);
        assert_eq!(set.len(), 1);
        assert!(!set.has_active_filters()); // only blank left
    }

    #[test]
    fn test_filter_set_normalize() {
        let mut set = BSimFilterSet::new();
        set.add(architecture_filter(FilterOperation::Equals), "  x86:LE:64:default  ");
        assert_eq!(set.entries[0].value, "x86:LE:64:default");
    }

    #[test]
    fn test_filter_operation_display() {
        assert_eq!(FilterOperation::Equals.to_string(), "equals");
        assert_eq!(FilterOperation::NotEquals.to_string(), "not equals");
        assert_eq!(FilterOperation::GreaterThan.to_string(), "greater than");
    }

    #[test]
    fn test_filter_ordering() {
        let f1 = architecture_filter(FilterOperation::Equals);
        let f2 = executable_name_filter(FilterOperation::Equals);
        let mut filters = vec![f1, f2];
        filters.sort();
        // Architecture comes before Executable Name alphabetically
        assert!(filters[0].label < filters[1].label);
    }

    #[test]
    fn test_function_tag_constants() {
        assert_eq!(FunctionTagFilter::KNOWN_LIBRARY_MASK, 0x01);
        assert_eq!(FunctionTagFilter::HAS_UNIMPLEMENTED_MASK, 0x02);
        assert_eq!(FunctionTagFilter::HAS_BADDATA_MASK, 0x04);
        assert_eq!(FunctionTagFilter::RESERVED_BITS, 3);
    }

    #[test]
    fn test_generate_with_user_tags() {
        let tags = vec!["CUSTOM_TAG_1".to_string(), "CUSTOM_TAG_2".to_string()];
        let filters = generate_bsim_filters(false, &[], None, &tags);
        // Should include the user tags
        assert!(filters.iter().any(|f| f.label.contains("CUSTOM_TAG_1")));
        assert!(filters.iter().any(|f| f.label.contains("CUSTOM_TAG_2")));
    }
}
