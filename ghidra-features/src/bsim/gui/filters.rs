//! BSim filter types for querying the BSim database.
//!
//! Ports `ghidra.features.bsim.gui.filters` package.

use std::fmt;

/// A BSim filter type that can match or exclude records.
///
/// Ports `ghidra.features.bsim.gui.filters.BSimFilterType`.
#[derive(Debug, Clone)]
pub struct BSimFilterType {
    /// Display name of the filter.
    pub name: String,
    /// The field to filter on.
    pub field: FilterField,
    /// The operator to apply.
    pub operator: FilterOperator,
    /// The value to compare against.
    pub value: FilterValue,
    /// Whether this filter is negated (NOT).
    pub negated: bool,
}

/// Fields that can be filtered on in BSim queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterField {
    /// Filter on architecture string.
    Architecture,
    /// Filter on compiler name.
    Compiler,
    /// Filter on executable name.
    ExecutableName,
    /// Filter on executable category.
    ExecutableCategory,
    /// Filter on function tag.
    FunctionTag,
    /// Filter on MD5 hash.
    Md5,
    /// Filter on date.
    Date,
    /// Filter on file path.
    Path,
}

/// Comparison operators for BSim filters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterOperator {
    /// Exact match.
    Equals,
    /// String contains.
    Contains,
    /// String starts with.
    StartsWith,
    /// Less than (for dates).
    LessThan,
    /// Greater than (for dates).
    GreaterThan,
    /// In a set of values.
    In,
}

/// A filter value (string, date, or multi-choice).
#[derive(Debug, Clone)]
pub enum FilterValue {
    /// String value.
    String(String),
    /// Date value (ISO 8601 string).
    Date(String),
    /// Multiple choice (set of values).
    MultiChoice(Vec<String>),
    /// Boolean flag.
    Boolean(bool),
}

impl BSimFilterType {
    /// Create a new filter.
    pub fn new(
        name: impl Into<String>,
        field: FilterField,
        operator: FilterOperator,
        value: FilterValue,
    ) -> Self {
        Self {
            name: name.into(),
            field,
            operator,
            value,
            negated: false,
        }
    }

    /// Negate this filter.
    pub fn negated(mut self) -> Self {
        self.negated = true;
        self
    }

    /// Generate the SQL WHERE clause for this filter.
    pub fn to_sql_clause(&self) -> String {
        let field_name = match self.field {
            FilterField::Architecture => "architecture",
            FilterField::Compiler => "compiler",
            FilterField::ExecutableName => "exe_name",
            FilterField::ExecutableCategory => "exe_category",
            FilterField::FunctionTag => "function_tag",
            FilterField::Md5 => "md5",
            FilterField::Date => "date_added",
            FilterField::Path => "path",
        };

        let prefix = if self.negated { "NOT " } else { "" };

        match &self.operator {
            FilterOperator::Equals => {
                format!("{}{} = '{}'", prefix, field_name, self.value_str())
            }
            FilterOperator::Contains => {
                format!("{}{} LIKE '%{}%'", prefix, field_name, self.value_str())
            }
            FilterOperator::StartsWith => {
                format!("{}{} LIKE '{}%'", prefix, field_name, self.value_str())
            }
            FilterOperator::LessThan => {
                format!("{}{} < '{}'", prefix, field_name, self.value_str())
            }
            FilterOperator::GreaterThan => {
                format!("{}{} > '{}'", prefix, field_name, self.value_str())
            }
            FilterOperator::In => {
                if let FilterValue::MultiChoice(values) = &self.value {
                    let vals: Vec<String> =
                        values.iter().map(|v| format!("'{}'", v)).collect();
                    format!(
                        "{}{} IN ({})",
                        prefix,
                        field_name,
                        vals.join(", ")
                    )
                } else {
                    format!("{}{} = '{}'", prefix, field_name, self.value_str())
                }
            }
        }
    }

    fn value_str(&self) -> &str {
        match &self.value {
            FilterValue::String(s) => s,
            FilterValue::Date(s) => s,
            FilterValue::Boolean(b) => {
                if *b {
                    "true"
                } else {
                    "false"
                }
            }
            FilterValue::MultiChoice(v) => v.first().map(|s| s.as_str()).unwrap_or(""),
        }
    }
}

impl fmt::Display for BSimFilterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let neg = if self.negated { "NOT " } else { "" };
        write!(
            f,
            "{}{:?} {:?} {:?}",
            neg, self.field, self.operator, self.value
        )
    }
}

/// A filter set: a collection of filters applied together.
#[derive(Debug, Clone, Default)]
pub struct BSimFilterSet {
    filters: Vec<BSimFilterType>,
}

impl BSimFilterSet {
    /// Create an empty filter set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a filter.
    pub fn add(&mut self, filter: BSimFilterType) {
        self.filters.push(filter);
    }

    /// Get all filters.
    pub fn filters(&self) -> &[BSimFilterType] {
        &self.filters
    }

    /// Whether the filter set is empty.
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty()
    }

    /// Generate a combined SQL WHERE clause.
    pub fn to_sql_where(&self) -> Option<String> {
        if self.filters.is_empty() {
            return None;
        }
        let clauses: Vec<String> = self.filters.iter().map(|f| f.to_sql_clause()).collect();
        Some(clauses.join(" AND "))
    }
}

/// Pre-built filter constructors for common BSim filter types.
pub mod presets {
    use super::*;

    /// Filter by architecture (exact match).
    pub fn architecture(arch: &str) -> BSimFilterType {
        BSimFilterType::new(
            "Architecture",
            FilterField::Architecture,
            FilterOperator::Equals,
            FilterValue::String(arch.to_string()),
        )
    }

    /// Filter by architecture (negated).
    pub fn not_architecture(arch: &str) -> BSimFilterType {
        BSimFilterType::new(
            "Not Architecture",
            FilterField::Architecture,
            FilterOperator::Equals,
            FilterValue::String(arch.to_string()),
        )
        .negated()
    }

    /// Filter by compiler name (exact match).
    pub fn compiler(comp: &str) -> BSimFilterType {
        BSimFilterType::new(
            "Compiler",
            FilterField::Compiler,
            FilterOperator::Equals,
            FilterValue::String(comp.to_string()),
        )
    }

    /// Filter by compiler (negated).
    pub fn not_compiler(comp: &str) -> BSimFilterType {
        BSimFilterType::new(
            "Not Compiler",
            FilterField::Compiler,
            FilterOperator::Equals,
            FilterValue::String(comp.to_string()),
        )
        .negated()
    }

    /// Filter by executable name (exact match).
    pub fn executable_name(name: &str) -> BSimFilterType {
        BSimFilterType::new(
            "Executable Name",
            FilterField::ExecutableName,
            FilterOperator::Equals,
            FilterValue::String(name.to_string()),
        )
    }

    /// Filter by executable name (negated).
    pub fn not_executable_name(name: &str) -> BSimFilterType {
        BSimFilterType::new(
            "Not Executable Name",
            FilterField::ExecutableName,
            FilterOperator::Equals,
            FilterValue::String(name.to_string()),
        )
        .negated()
    }

    /// Filter by executable category.
    pub fn executable_category(category: &str) -> BSimFilterType {
        BSimFilterType::new(
            "Executable Category",
            FilterField::ExecutableCategory,
            FilterOperator::Equals,
            FilterValue::String(category.to_string()),
        )
    }

    /// Filter by MD5 hash (exact match).
    pub fn md5(hash: &str) -> BSimFilterType {
        BSimFilterType::new(
            "MD5",
            FilterField::Md5,
            FilterOperator::Equals,
            FilterValue::String(hash.to_string()),
        )
    }

    /// Filter by MD5 hash (negated).
    pub fn not_md5(hash: &str) -> BSimFilterType {
        BSimFilterType::new(
            "Not MD5",
            FilterField::Md5,
            FilterOperator::Equals,
            FilterValue::String(hash.to_string()),
        )
        .negated()
    }

    /// Filter by date earlier than.
    pub fn date_earlier(date: &str) -> BSimFilterType {
        BSimFilterType::new(
            "Date Earlier",
            FilterField::Date,
            FilterOperator::LessThan,
            FilterValue::Date(date.to_string()),
        )
    }

    /// Filter by date later than.
    pub fn date_later(date: &str) -> BSimFilterType {
        BSimFilterType::new(
            "Date Later",
            FilterField::Date,
            FilterOperator::GreaterThan,
            FilterValue::Date(date.to_string()),
        )
    }

    /// Filter by function tag.
    pub fn function_tag(tag: &str) -> BSimFilterType {
        BSimFilterType::new(
            "Function Tag",
            FilterField::FunctionTag,
            FilterOperator::Equals,
            FilterValue::String(tag.to_string()),
        )
    }

    /// Filter by path prefix.
    pub fn path_starts_with(prefix: &str) -> BSimFilterType {
        BSimFilterType::new(
            "Path Starts With",
            FilterField::Path,
            FilterOperator::StartsWith,
            FilterValue::String(prefix.to_string()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::presets;

    #[test]
    fn filter_architecture_sql() {
        let f = presets::architecture("x86:LE:64:default");
        assert_eq!(
            f.to_sql_clause(),
            "architecture = 'x86:LE:64:default'"
        );
    }

    #[test]
    fn filter_not_compiler_sql() {
        let f = presets::not_compiler("gcc");
        assert_eq!(f.to_sql_clause(), "NOT compiler = 'gcc'");
    }

    #[test]
    fn filter_contains_sql() {
        let f = BSimFilterType::new(
            "Name",
            FilterField::ExecutableName,
            FilterOperator::Contains,
            FilterValue::String("libc".to_string()),
        );
        assert_eq!(f.to_sql_clause(), "exe_name LIKE '%libc%'");
    }

    #[test]
    fn filter_starts_with_sql() {
        let f = presets::path_starts_with("/usr/lib");
        assert_eq!(f.to_sql_clause(), "path LIKE '/usr/lib%'");
    }

    #[test]
    fn filter_multi_choice_in() {
        let f = BSimFilterType::new(
            "Categories",
            FilterField::ExecutableCategory,
            FilterOperator::In,
            FilterValue::MultiChoice(vec![
                "crypto".to_string(),
                "network".to_string(),
            ]),
        );
        assert_eq!(
            f.to_sql_clause(),
            "exe_category IN ('crypto', 'network')"
        );
    }

    #[test]
    fn filter_date_earlier() {
        let f = presets::date_earlier("2024-01-01");
        assert_eq!(f.to_sql_clause(), "date_added < '2024-01-01'");
    }

    #[test]
    fn filter_date_later() {
        let f = presets::date_later("2024-06-01");
        assert_eq!(f.to_sql_clause(), "date_added > '2024-06-01'");
    }

    #[test]
    fn filter_md5() {
        let f = presets::md5("abc123");
        assert_eq!(f.to_sql_clause(), "md5 = 'abc123'");
    }

    #[test]
    fn filter_function_tag() {
        let f = presets::function_tag("crypto");
        assert_eq!(f.to_sql_clause(), "function_tag = 'crypto'");
    }

    #[test]
    fn filter_set_to_sql_where() {
        let mut fs = BSimFilterSet::new();
        assert!(fs.to_sql_where().is_none());

        fs.add(presets::architecture("x86:LE:64:default"));
        fs.add(presets::compiler("gcc"));
        let where_clause = fs.to_sql_where().unwrap();
        assert!(where_clause.contains("architecture = 'x86:LE:64:default'"));
        assert!(where_clause.contains("compiler = 'gcc'"));
        assert!(where_clause.contains(" AND "));
    }

    #[test]
    fn filter_display() {
        let f = presets::architecture("x86");
        let s = format!("{}", f);
        assert!(s.contains("Architecture"));
    }

    #[test]
    fn negated_filter_builder() {
        let f = BSimFilterType::new(
            "Test",
            FilterField::Compiler,
            FilterOperator::Equals,
            FilterValue::String("gcc".to_string()),
        )
        .negated();
        assert!(f.negated);
        assert!(f.to_sql_clause().starts_with("NOT"));
    }
}
