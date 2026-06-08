//! Field matcher for data-type component lookups.
//!
//! Ported from `ghidra.app.services.FieldMatcher`. Allows clients to match on
//! multiple field attributes (name, offset) within a parent data type. Used
//! throughout Ghidra's data-type analysis and structure-editor pipelines.

use std::collections::BTreeSet;
use std::fmt;

// ---------------------------------------------------------------------------
// Placeholder types
// ---------------------------------------------------------------------------

/// Minimal representation of a Ghidra data type.
///
/// In the full Ghidra codebase this would be `ghidra.program.model.data.DataType`.
/// This placeholder keeps the module self-contained while preserving the
/// semantics of the Java original.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DataType {
    /// The data-type name (e.g. `"int"`, `"my_struct"`).
    pub name: String,
    /// The data-type category path.
    pub category_path: String,
}

impl DataType {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            category_path: String::new(),
        }
    }

    pub fn with_category(mut self, path: impl Into<String>) -> Self {
        self.category_path = path.into();
        self
    }
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.category_path.is_empty() {
            write!(f, "{}", self.name)
        } else {
            write!(f, "{}/{}", self.category_path, self.name)
        }
    }
}

/// Minimal representation of a data-type component (field) inside a composite
/// (struct / union).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataTypeComponent {
    /// Field name (may be auto-generated).
    pub field_name: Option<String>,
    /// Default (auto-generated) field name.
    pub default_field_name: String,
    /// Byte offset of this component within the parent composite.
    pub offset: usize,
}

impl DataTypeComponent {
    pub fn new(field_name: Option<String>, default_field_name: impl Into<String>, offset: usize) -> Self {
        Self {
            field_name,
            default_field_name: default_field_name.into(),
            offset,
        }
    }
}

// ---------------------------------------------------------------------------
// SortedRangeList -- lightweight replacement for Java's SortedRangeList
// ---------------------------------------------------------------------------

/// A sorted, non-overlapping set of integer ranges, collapsed to individual
/// values for simplicity.
///
/// This is a simplified port of `ghidra.util.datastruct.SortedRangeList`,
/// storing individual offsets rather than full `(min, max)` ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SortedRangeList {
    values: BTreeSet<usize>,
}

impl SortedRangeList {
    /// Create an empty range list.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a single value.
    pub fn add(&mut self, value: usize) {
        self.values.insert(value);
    }

    /// Add an inclusive range `[min, max]`.
    pub fn add_range(&mut self, min: usize, max: usize) {
        for v in min..=max {
            self.values.insert(v);
        }
    }

    /// Remove a value.
    pub fn remove(&mut self, value: usize) {
        self.values.remove(&value);
    }

    /// Remove an inclusive range `[min, max]`.
    pub fn remove_range(&mut self, min: usize, max: usize) {
        for v in min..=max {
            self.values.remove(&v);
        }
    }

    /// Returns `true` if the list contains the given value.
    pub fn contains(&self, value: usize) -> bool {
        self.values.contains(&value)
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Number of distinct values.
    pub fn num_values(&self) -> usize {
        self.values.len()
    }

    /// Minimum value, or `None` if empty.
    pub fn min(&self) -> Option<usize> {
        self.values.iter().next().copied()
    }

    /// Maximum value, or `None` if empty.
    pub fn max(&self) -> Option<usize> {
        self.values.iter().next_back().copied()
    }

    /// Clear all values.
    pub fn clear(&mut self) {
        self.values.clear();
    }
}

impl fmt::Display for SortedRangeList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{{}}}", self.values.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(", "))
    }
}

// ---------------------------------------------------------------------------
// FieldMatcher
// ---------------------------------------------------------------------------

/// Matches data-type fields by name and/or offset.
///
/// Use the [`FieldMatcher::new`] constructor to create an "empty" (ignored)
/// matcher that matches any field. Use the named constructors to create
/// matchers that restrict to a specific field name or offset.
///
/// # Examples
///
/// ```
/// use ghidra_features::base::services::field_matcher::{FieldMatcher, DataType};
///
/// let dt = DataType::new("my_struct");
/// let matcher = FieldMatcher::new(dt);
/// assert!(matcher.is_ignored());
/// assert!(matcher.matches(None, 0));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldMatcher {
    /// The data type whose fields we are matching against.
    data_type: DataType,
    /// Optional field name constraint.
    field_name: Option<String>,
    /// Set of acceptable offsets (empty means "any offset").
    field_offsets: SortedRangeList,
}

impl FieldMatcher {
    // -- Constructors -------------------------------------------------------

    /// Create an "empty" (ignored) matcher that matches any field of the
    /// given data type.
    pub fn new(data_type: DataType) -> Self {
        Self {
            data_type,
            field_name: None,
            field_offsets: SortedRangeList::new(),
        }
    }

    /// Create a matcher that requires a specific field name.
    pub fn by_name(data_type: DataType, field_name: impl Into<String>) -> Self {
        Self {
            data_type,
            field_name: Some(field_name.into()),
            field_offsets: SortedRangeList::new(),
        }
    }

    /// Create a matcher that requires a specific offset.
    pub fn by_offset(data_type: DataType, offset: usize) -> Self {
        let mut offsets = SortedRangeList::new();
        offsets.add(offset);
        Self {
            data_type,
            field_name: None,
            field_offsets: offsets,
        }
    }

    /// Create a matcher that requires a specific offset range.
    pub fn by_offset_range(data_type: DataType, min: usize, max: usize) -> Self {
        let mut offsets = SortedRangeList::new();
        offsets.add_range(min, max);
        Self {
            data_type,
            field_name: None,
            field_offsets: offsets,
        }
    }

    // -- Queries ------------------------------------------------------------

    /// Returns `true` if no field name or offset constraint is set.
    ///
    /// An ignored matcher matches any field.
    pub fn is_ignored(&self) -> bool {
        self.field_name.is_none() && self.field_offsets.is_empty()
    }

    /// The data type this matcher is associated with.
    pub fn data_type(&self) -> &DataType {
        &self.data_type
    }

    /// The field name constraint, if any.
    pub fn field_name_constraint(&self) -> Option<&str> {
        self.field_name.as_deref()
    }

    /// The set of acceptable offsets.
    pub fn field_offsets(&self) -> &SortedRangeList {
        &self.field_offsets
    }

    /// Test whether the given field name and offset satisfy this matcher.
    ///
    /// Returns `true` if:
    /// - the matcher is ignored, OR
    /// - the field name matches, OR
    /// - the offset is in the acceptable set.
    pub fn matches(&self, field_name: Option<&str>, offset: usize) -> bool {
        if self.is_ignored() {
            return true;
        }

        if let Some(ref required_name) = self.field_name {
            if field_name == Some(required_name.as_str()) {
                return true;
            }
        }

        if self.field_offsets.contains(offset) {
            return true;
        }

        false
    }

    /// Produce a human-readable display string for this matcher.
    ///
    /// Examples: `"my_struct"`, `"my_struct.field_name"`,
    /// `"my_struct at {0, 4}"`.
    pub fn display_text(&self) -> String {
        if let Some(ref name) = self.field_name {
            return format!("{}.{}", self.data_type.name, name);
        }
        if !self.field_offsets.is_empty() {
            if let Some(composite_name) = self.try_resolve_field_name() {
                return composite_name;
            }
            return format!("{} at {}", self.data_type.name, self.field_offsets);
        }
        self.data_type.name.clone()
    }

    /// Attempt to resolve a field name from the data type and offset.
    ///
    /// Returns the resolved field name, or `None` if resolution fails.
    pub fn get_resolved_field_name(&self) -> Option<String> {
        if let Some(ref name) = self.field_name {
            return Some(name.clone());
        }
        self.try_resolve_field_name()
    }

    // -- Internal helpers ---------------------------------------------------

    // Try to resolve a field name from the offset and composite components.
    //
    // This is a simplified port of
    // `FieldMatcher.generateCompositeFieldNameByOffset()`. In the full Ghidra
    // codebase this queries the actual `Structure` / `Composite` data type.
    // Here we accept an optional component list to simulate that lookup.
    fn try_resolve_field_name(&self) -> Option<String> {
        // Without access to the real data-type hierarchy we cannot resolve
        // the name. Callers that have a component list should use
        // [`resolve_field_name_from_components`].
        None
    }
}

/// Attempt to resolve a field name from a set of data-type components and an
/// offset constraint in the matcher.
///
/// This is the Rust equivalent of the Java private method
/// `generateCompositeFieldNameByOffset()`.
pub fn resolve_field_name_from_components(
    matcher: &FieldMatcher,
    components: &[DataTypeComponent],
) -> Option<String> {
    if matcher.field_offsets.num_values() != 1 {
        return None;
    }

    let offset = matcher.field_offsets.min()?;

    for comp in components {
        if comp.offset == offset {
            return Some(
                comp.field_name
                    .clone()
                    .unwrap_or_else(|| comp.default_field_name.clone()),
            );
        }
    }

    None
}

impl fmt::Display for FieldMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_text())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_dt(name: &str) -> DataType {
        DataType::new(name)
    }

    // -- DataType tests -----------------------------------------------------

    #[test]
    fn test_datatype_display_no_category() {
        let dt = DataType::new("int");
        assert_eq!(format!("{}", dt), "int");
    }

    #[test]
    fn test_datatype_display_with_category() {
        let dt = DataType::new("my_struct").with_category("/my/path");
        assert_eq!(format!("{}", dt), "/my/path/my_struct");
    }

    // -- SortedRangeList tests ----------------------------------------------

    #[test]
    fn test_range_list_empty() {
        let rl = SortedRangeList::new();
        assert!(rl.is_empty());
        assert_eq!(rl.num_values(), 0);
        assert!(!rl.contains(0));
    }

    #[test]
    fn test_range_list_add_single() {
        let mut rl = SortedRangeList::new();
        rl.add(5);
        assert!(!rl.is_empty());
        assert!(rl.contains(5));
        assert!(!rl.contains(4));
        assert_eq!(rl.num_values(), 1);
    }

    #[test]
    fn test_range_list_add_range() {
        let mut rl = SortedRangeList::new();
        rl.add_range(2, 5);
        assert_eq!(rl.num_values(), 4);
        for v in 2..=5 {
            assert!(rl.contains(v));
        }
        assert!(!rl.contains(1));
        assert!(!rl.contains(6));
    }

    #[test]
    fn test_range_list_min_max() {
        let mut rl = SortedRangeList::new();
        rl.add_range(10, 20);
        assert_eq!(rl.min(), Some(10));
        assert_eq!(rl.max(), Some(20));
    }

    #[test]
    fn test_range_list_remove() {
        let mut rl = SortedRangeList::new();
        rl.add_range(0, 4);
        rl.remove(2);
        assert_eq!(rl.num_values(), 4);
        assert!(!rl.contains(2));
    }

    #[test]
    fn test_range_list_remove_range() {
        let mut rl = SortedRangeList::new();
        rl.add_range(0, 9);
        rl.remove_range(3, 6);
        assert_eq!(rl.num_values(), 6);
        for v in 3..=6 {
            assert!(!rl.contains(v));
        }
    }

    #[test]
    fn test_range_list_dedup() {
        let mut rl = SortedRangeList::new();
        rl.add(5);
        rl.add(5);
        assert_eq!(rl.num_values(), 1);
    }

    #[test]
    fn test_range_list_display() {
        let mut rl = SortedRangeList::new();
        rl.add(3);
        let s = format!("{}", rl);
        assert!(s.contains("3"));
    }

    // -- FieldMatcher tests -------------------------------------------------

    #[test]
    fn test_matcher_ignored() {
        let m = FieldMatcher::new(sample_dt("T"));
        assert!(m.is_ignored());
        assert!(m.matches(None, 0));
        assert!(m.matches(Some("anything"), 99));
    }

    #[test]
    fn test_matcher_by_name() {
        let m = FieldMatcher::by_name(sample_dt("T"), "foo");
        assert!(!m.is_ignored());
        assert!(m.matches(Some("foo"), 0));
        assert!(!m.matches(Some("bar"), 0));
        assert!(!m.matches(None, 0));
    }

    #[test]
    fn test_matcher_by_offset() {
        let m = FieldMatcher::by_offset(sample_dt("T"), 4);
        assert!(!m.is_ignored());
        assert!(m.matches(None, 4));
        assert!(m.matches(Some("anything"), 4));
        assert!(!m.matches(None, 0));
    }

    #[test]
    fn test_matcher_by_offset_range() {
        let m = FieldMatcher::by_offset_range(sample_dt("T"), 0, 7);
        assert!(m.matches(None, 0));
        assert!(m.matches(None, 7));
        assert!(!m.matches(None, 8));
    }

    #[test]
    fn test_matcher_name_or_offset() {
        // A matcher with both name and offset should match either.
        let mut m = FieldMatcher::by_name(sample_dt("T"), "x");
        // Also add an offset.
        let mut offsets = SortedRangeList::new();
        offsets.add(8);
        m.field_offsets = offsets;
        assert!(m.matches(Some("x"), 0));
        assert!(m.matches(None, 8));
        assert!(!m.matches(Some("y"), 99));
    }

    #[test]
    fn test_matcher_display_text_name() {
        let m = FieldMatcher::by_name(sample_dt("my_struct"), "field_a");
        assert_eq!(m.display_text(), "my_struct.field_a");
    }

    #[test]
    fn test_matcher_display_text_offset() {
        let m = FieldMatcher::by_offset(sample_dt("my_struct"), 4);
        assert_eq!(m.display_text(), "my_struct at {4}");
    }

    #[test]
    fn test_matcher_display_text_ignored() {
        let m = FieldMatcher::new(sample_dt("my_struct"));
        assert_eq!(m.display_text(), "my_struct");
    }

    #[test]
    fn test_matcher_resolved_field_name_from_name() {
        let m = FieldMatcher::by_name(sample_dt("T"), "bar");
        assert_eq!(m.get_resolved_field_name(), Some("bar".into()));
    }

    #[test]
    fn test_matcher_resolved_field_name_ignored() {
        let m = FieldMatcher::new(sample_dt("T"));
        assert_eq!(m.get_resolved_field_name(), None);
    }

    #[test]
    fn test_resolve_field_name_from_components() {
        let m = FieldMatcher::by_offset(sample_dt("T"), 4);
        let components = vec![
            DataTypeComponent::new(Some("alpha".into()), "field_0", 0),
            DataTypeComponent::new(Some("beta".into()), "field_4", 4),
        ];
        let name = resolve_field_name_from_components(&m, &components);
        assert_eq!(name, Some("beta".into()));
    }

    #[test]
    fn test_resolve_field_name_default() {
        let m = FieldMatcher::by_offset(sample_dt("T"), 0);
        let components = vec![DataTypeComponent::new(None, "field_0", 0)];
        let name = resolve_field_name_from_components(&m, &components);
        assert_eq!(name, Some("field_0".into()));
    }

    #[test]
    fn test_resolve_field_name_no_match() {
        let m = FieldMatcher::by_offset(sample_dt("T"), 99);
        let components = vec![DataTypeComponent::new(Some("a".into()), "f0", 0)];
        assert_eq!(resolve_field_name_from_components(&m, &components), None);
    }

    #[test]
    fn test_resolve_field_name_multiple_offsets() {
        // If multiple offsets are set, resolution returns None.
        let m = FieldMatcher::by_offset_range(sample_dt("T"), 0, 4);
        let components = vec![];
        assert_eq!(resolve_field_name_from_components(&m, &components), None);
    }

    #[test]
    fn test_matcher_display_trait() {
        let m = FieldMatcher::new(sample_dt("T"));
        let s = format!("{}", m);
        assert_eq!(s, "T");
    }

    #[test]
    fn test_matcher_clone_eq() {
        let a = FieldMatcher::by_name(sample_dt("T"), "x");
        let b = a.clone();
        assert_eq!(a, b);
    }
}
