//! Specific BSim filter type implementations.
//!
//! Ports the individual BSimFilterType subclasses from
//! `ghidra.features.bsim.gui.filters`.

/// The kind of comparison a filter performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterComparison {
    /// Exact match.
    Equals,
    /// Starts with.
    StartsWith,
    /// Contains.
    Contains,
    /// Less than (for dates/numbers).
    LessThan,
    /// Greater than (for dates/numbers).
    GreaterThan,
    /// Between two values.
    Between,
    /// Boolean (true/false).
    Boolean,
}

/// Architecture-based filter.
#[derive(Debug, Clone)]
pub struct ArchitectureBSimFilterType {
    /// The architecture string to match.
    pub architecture: String,
    /// Whether this is a "not" filter (negation).
    pub negated: bool,
}

impl ArchitectureBSimFilterType {
    /// Create a new architecture filter.
    pub fn new(architecture: impl Into<String>, negated: bool) -> Self {
        Self {
            architecture: architecture.into(),
            negated,
        }
    }

    /// Get the display label.
    pub fn label(&self) -> &str {
        if self.negated { "Not Architecture" } else { "Architecture" }
    }

    /// Get the XML serialization tag.
    pub fn xml_value(&self) -> &str {
        if self.negated { "notarchitecture" } else { "architecture" }
    }
}

/// Date-based filter with comparison mode.
#[derive(Debug, Clone)]
pub struct DateBSimFilterType {
    /// The comparison mode.
    pub comparison: FilterComparison,
    /// The date value (ISO 8601 string).
    pub date_value: String,
}

impl DateBSimFilterType {
    /// Create an "earlier than" filter.
    pub fn earlier_than(date: impl Into<String>) -> Self {
        Self {
            comparison: FilterComparison::LessThan,
            date_value: date.into(),
        }
    }

    /// Create a "later than" filter.
    pub fn later_than(date: impl Into<String>) -> Self {
        Self {
            comparison: FilterComparison::GreaterThan,
            date_value: date.into(),
        }
    }

    /// Get the display label.
    pub fn label(&self) -> &str {
        match self.comparison {
            FilterComparison::LessThan => "Date Earlier Than",
            FilterComparison::GreaterThan => "Date Later Than",
            _ => "Date",
        }
    }

    /// Get the XML serialization tag.
    pub fn xml_value(&self) -> &str {
        match self.comparison {
            FilterComparison::LessThan => "datebefore",
            FilterComparison::GreaterThan => "dateafter",
            _ => "date",
        }
    }
}

/// Compiler-based filter.
#[derive(Debug, Clone)]
pub struct CompilerBSimFilterType {
    /// The compiler name to match.
    pub compiler: String,
    /// Whether this is a "not" filter.
    pub negated: bool,
}

impl CompilerBSimFilterType {
    /// Create a new compiler filter.
    pub fn new(compiler: impl Into<String>, negated: bool) -> Self {
        Self {
            compiler: compiler.into(),
            negated,
        }
    }

    pub fn label(&self) -> &str {
        if self.negated { "Not Compiler" } else { "Compiler" }
    }

    pub fn xml_value(&self) -> &str {
        if self.negated { "notcompiler" } else { "compiler" }
    }
}

/// MD5 hash-based filter.
#[derive(Debug, Clone)]
pub struct Md5BSimFilterType {
    /// The MD5 hash to match.
    pub md5: String,
    /// Whether this is a "not" filter.
    pub negated: bool,
}

impl Md5BSimFilterType {
    pub fn new(md5: impl Into<String>, negated: bool) -> Self {
        Self { md5: md5.into(), negated }
    }

    pub fn label(&self) -> &str {
        if self.negated { "Not MD5" } else { "MD5" }
    }

    pub fn xml_value(&self) -> &str {
        if self.negated { "notmd5" } else { "md5" }
    }
}

/// Executable name filter.
#[derive(Debug, Clone)]
pub struct ExecutableNameBSimFilterType {
    /// The executable name pattern.
    pub name_pattern: String,
    /// Whether this is a "not" filter.
    pub negated: bool,
}

impl ExecutableNameBSimFilterType {
    pub fn new(name: impl Into<String>, negated: bool) -> Self {
        Self { name_pattern: name.into(), negated }
    }

    pub fn label(&self) -> &str {
        if self.negated { "Not Executable Name" } else { "Executable Name" }
    }

    pub fn xml_value(&self) -> &str {
        if self.negated { "notexecutablename" } else { "executablename" }
    }
}

/// Executable category filter.
#[derive(Debug, Clone)]
pub struct ExecutableCategoryBSimFilterType {
    /// The category to match.
    pub category: String,
    /// Whether this is a "not" filter.
    pub negated: bool,
}

impl ExecutableCategoryBSimFilterType {
    pub fn new(category: impl Into<String>, negated: bool) -> Self {
        Self { category: category.into(), negated }
    }

    pub fn label(&self) -> &str {
        if self.negated { "Not Executable Category" } else { "Executable Category" }
    }
}

/// Path prefix filter.
#[derive(Debug, Clone)]
pub struct PathStartsBSimFilterType {
    /// The path prefix.
    pub path_prefix: String,
}

impl PathStartsBSimFilterType {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self { path_prefix: prefix.into() }
    }

    pub fn label(&self) -> &str { "Path Starts With" }
    pub fn xml_value(&self) -> &str { "pathstarts" }
}

/// Function tag filter.
#[derive(Debug, Clone)]
pub struct FunctionTagBSimFilterType {
    /// The tag to match.
    pub tag: String,
}

impl FunctionTagBSimFilterType {
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into() }
    }

    pub fn label(&self) -> &str { "Function Tag" }
    pub fn xml_value(&self) -> &str { "functiontag" }
}

/// Has named child filter (callgraph-based).
#[derive(Debug, Clone)]
pub struct HasNamedChildBSimFilterType {
    /// The child function name pattern.
    pub child_pattern: String,
}

impl HasNamedChildBSimFilterType {
    pub fn new(pattern: impl Into<String>) -> Self {
        Self { child_pattern: pattern.into() }
    }

    pub fn label(&self) -> &str { "Has Named Child" }
    pub fn xml_value(&self) -> &str { "hasnamedchild" }
    pub fn is_child_filter(&self) -> bool { true }
}

/// Blank (placeholder) filter.
#[derive(Debug, Clone, Default)]
pub struct BlankBSimFilterType;

impl BlankBSimFilterType {
    pub fn new() -> Self { Self }
    pub fn is_blank(&self) -> bool { true }
    pub fn label(&self) -> &str { "" }
}

/// All filter type variants.
#[derive(Debug, Clone)]
pub enum BSimFilterTypeVariant {
    Architecture(ArchitectureBSimFilterType),
    Date(DateBSimFilterType),
    Compiler(CompilerBSimFilterType),
    Md5(Md5BSimFilterType),
    ExecutableName(ExecutableNameBSimFilterType),
    ExecutableCategory(ExecutableCategoryBSimFilterType),
    PathStarts(PathStartsBSimFilterType),
    FunctionTag(FunctionTagBSimFilterType),
    HasNamedChild(HasNamedChildBSimFilterType),
    Blank(BlankBSimFilterType),
}

impl BSimFilterTypeVariant {
    /// Get the display label.
    pub fn label(&self) -> &str {
        match self {
            Self::Architecture(f) => f.label(),
            Self::Date(f) => f.label(),
            Self::Compiler(f) => f.label(),
            Self::Md5(f) => f.label(),
            Self::ExecutableName(f) => f.label(),
            Self::ExecutableCategory(f) => f.label(),
            Self::PathStarts(f) => f.label(),
            Self::FunctionTag(f) => f.label(),
            Self::HasNamedChild(f) => f.label(),
            Self::Blank(f) => f.label(),
        }
    }

    /// Check if this is a blank filter.
    pub fn is_blank(&self) -> bool {
        matches!(self, Self::Blank(_))
    }

    /// Check if this is a child (callgraph) filter.
    pub fn is_child_filter(&self) -> bool {
        matches!(self, Self::HasNamedChild(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_architecture_filter() {
        let f = ArchitectureBSimFilterType::new("x86", false);
        assert_eq!(f.label(), "Architecture");
        assert_eq!(f.xml_value(), "architecture");
        let f2 = ArchitectureBSimFilterType::new("ARM", true);
        assert_eq!(f2.label(), "Not Architecture");
    }

    #[test]
    fn test_date_filter() {
        let f = DateBSimFilterType::earlier_than("2023-01-01");
        assert_eq!(f.label(), "Date Earlier Than");
        let f2 = DateBSimFilterType::later_than("2024-01-01");
        assert_eq!(f2.label(), "Date Later Than");
    }

    #[test]
    fn test_compiler_filter() {
        let f = CompilerBSimFilterType::new("GCC", false);
        assert_eq!(f.label(), "Compiler");
    }

    #[test]
    fn test_md5_filter() {
        let f = Md5BSimFilterType::new("abc123", false);
        assert_eq!(f.label(), "MD5");
    }

    #[test]
    fn test_variant_labels() {
        let v = BSimFilterTypeVariant::Blank(BlankBSimFilterType::new());
        assert!(v.is_blank());
        assert!(!v.is_child_filter());

        let v2 = BSimFilterTypeVariant::HasNamedChild(HasNamedChildBSimFilterType::new("func"));
        assert!(v2.is_child_filter());
        assert!(!v2.is_blank());
    }
}
