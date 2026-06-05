//! BSim filter types for searching and filtering function matches.
//!
//! Ports Ghidra's `ghidra.features.bsim.query` filter type classes:
//! - `BSimFilterType` — base trait for all filter types
//! - `ArchitectureBSimFilterType` — filter by architecture
//! - `CompilerBSimFilterType` — filter by compiler
//! - `ExecutableNameBSimFilterType` — filter by executable name
//! - `ExecutableCategoryBSimFilterType` — filter by executable category
//! - `DateEarlierBSimFilterType` / `DateLaterBSimFilterType` — filter by date
//! - `Md5BSimFilterType` — filter by MD5 hash
//! - `FunctionTagBSimFilterType` — filter by function tag
//! - `PathStartsBSimFilterType` — filter by path prefix
//! - `BlankBSimFilterType` — passes all (no filtering)
//! - `HasNamedChildBSimFilterType` — filter by presence of a named child
//!
//! Each filter type can be negated via the `NegatedBSimFilterType` wrapper.

use serde::{Deserialize, Serialize};
use std::fmt;

/// The base trait for all BSim filter types.
///
/// A filter type determines whether a function description matches
/// a given criterion.
pub trait BSimFilterType: fmt::Debug + Send + Sync {
    /// Human-readable name of this filter type.
    fn name(&self) -> &str;

    /// Whether this filter matches the given attributes.
    fn matches(&self, context: &FilterContext<'_>) -> bool;

    /// Wrap this filter in a negating wrapper.
    fn negate(self: Box<Self>) -> Box<dyn BSimFilterType>
    where
        Self: Sized + 'static,
    {
        Box::new(NegatedFilter {
            inner: self,
        })
    }
}

/// Context provided to filter types during matching.
#[derive(Debug, Clone)]
pub struct FilterContext<'a> {
    /// The target architecture (e.g., "x86:LE:64:default").
    pub architecture: &'a str,
    /// The compiler identification.
    pub compiler: Option<&'a str>,
    /// The executable name.
    pub executable_name: &'a str,
    /// The executable category.
    pub executable_category: Option<&'a str>,
    /// The function name.
    pub function_name: &'a str,
    /// The function's MD5 hash (hex string).
    pub md5: Option<&'a str>,
    /// Path prefix (e.g., the library path).
    pub path_prefix: Option<&'a str>,
    /// Tags associated with the function.
    pub function_tags: &'a [&'a str],
    /// Date the executable was seen (ISO 8601).
    pub date: Option<&'a str>,
    /// Named children (for hierarchical queries).
    pub named_children: &'a [&'a str],
}

// =========================================================================
// BlankBSimFilterType — passes everything
// =========================================================================

/// A filter that matches everything (no filtering).
///
/// Ports `BlankBSimFilterType`.
#[derive(Debug, Clone, Copy)]
pub struct BlankFilter;

impl BSimFilterType for BlankFilter {
    fn name(&self) -> &str {
        "blank"
    }

    fn matches(&self, _ctx: &FilterContext<'_>) -> bool {
        true
    }
}

// =========================================================================
// ArchitectureBSimFilterType
// =========================================================================

/// Filter by architecture string.
///
/// Ports `ArchitectureBSimFilterType`.
#[derive(Debug, Clone)]
pub struct ArchitectureFilter {
    /// The architecture string to match (e.g., "x86:LE:64:default").
    pub architecture: String,
}

impl BSimFilterType for ArchitectureFilter {
    fn name(&self) -> &str {
        "architecture"
    }

    fn matches(&self, ctx: &FilterContext<'_>) -> bool {
        ctx.architecture == self.architecture
    }
}

// =========================================================================
// CompilerBSimFilterType
// =========================================================================

/// Filter by compiler.
///
/// Ports `CompilerBSimFilterType`.
#[derive(Debug, Clone)]
pub struct CompilerFilter {
    /// The compiler string to match.
    pub compiler: String,
}

impl BSimFilterType for CompilerFilter {
    fn name(&self) -> &str {
        "compiler"
    }

    fn matches(&self, ctx: &FilterContext<'_>) -> bool {
        ctx.compiler.map_or(false, |c| c == self.compiler)
    }
}

// =========================================================================
// ExecutableNameBSimFilterType
// =========================================================================

/// Filter by executable name.
///
/// Ports `ExecutableNameBSimFilterType`.
#[derive(Debug, Clone)]
pub struct ExecutableNameFilter {
    /// The executable name to match.
    pub exe_name: String,
}

impl BSimFilterType for ExecutableNameFilter {
    fn name(&self) -> &str {
        "executable_name"
    }

    fn matches(&self, ctx: &FilterContext<'_>) -> bool {
        ctx.executable_name == self.exe_name
    }
}

// =========================================================================
// ExecutableCategoryBSimFilterType
// =========================================================================

/// Filter by executable category.
///
/// Ports `ExecutableCategoryBSimFilterType`.
#[derive(Debug, Clone)]
pub struct ExecutableCategoryFilter {
    /// The category to match.
    pub category: String,
}

impl BSimFilterType for ExecutableCategoryFilter {
    fn name(&self) -> &str {
        "executable_category"
    }

    fn matches(&self, ctx: &FilterContext<'_>) -> bool {
        ctx.executable_category.map_or(false, |c| c == self.category)
    }
}

// =========================================================================
// Md5BSimFilterType
// =========================================================================

/// Filter by MD5 hash.
///
/// Ports `Md5BSimFilterType`.
#[derive(Debug, Clone)]
pub struct Md5Filter {
    /// The MD5 hex string to match.
    pub md5: String,
}

impl BSimFilterType for Md5Filter {
    fn name(&self) -> &str {
        "md5"
    }

    fn matches(&self, ctx: &FilterContext<'_>) -> bool {
        ctx.md5.map_or(false, |m| m == self.md5)
    }
}

// =========================================================================
// DateEarlierBSimFilterType
// =========================================================================

/// Filter: matches if the executable date is earlier than the threshold.
///
/// Ports `DateEarlierBSimFilterType`.
#[derive(Debug, Clone)]
pub struct DateEarlierFilter {
    /// ISO 8601 date string threshold.
    pub threshold: String,
}

impl BSimFilterType for DateEarlierFilter {
    fn name(&self) -> &str {
        "date_earlier"
    }

    fn matches(&self, ctx: &FilterContext<'_>) -> bool {
        ctx.date.map_or(false, |d| d < self.threshold.as_str())
    }
}

// =========================================================================
// DateLaterBSimFilterType
// =========================================================================

/// Filter: matches if the executable date is later than the threshold.
///
/// Ports `DateLaterBSimFilterType`.
#[derive(Debug, Clone)]
pub struct DateLaterFilter {
    /// ISO 8601 date string threshold.
    pub threshold: String,
}

impl BSimFilterType for DateLaterFilter {
    fn name(&self) -> &str {
        "date_later"
    }

    fn matches(&self, ctx: &FilterContext<'_>) -> bool {
        ctx.date.map_or(false, |d| d > self.threshold.as_str())
    }
}

// =========================================================================
// FunctionTagBSimFilterType
// =========================================================================

/// Filter by presence of a specific function tag.
///
/// Ports `FunctionTagBSimFilterType`.
#[derive(Debug, Clone)]
pub struct FunctionTagFilter {
    /// The tag to match.
    pub tag: String,
}

impl BSimFilterType for FunctionTagFilter {
    fn name(&self) -> &str {
        "function_tag"
    }

    fn matches(&self, ctx: &FilterContext<'_>) -> bool {
        ctx.function_tags.iter().any(|t| *t == self.tag)
    }
}

// =========================================================================
// PathStartsBSimFilterType
// =========================================================================

/// Filter: matches if the path starts with a given prefix.
///
/// Ports `PathStartsBSimFilterType`.
#[derive(Debug, Clone)]
pub struct PathStartsFilter {
    /// The path prefix to match.
    pub prefix: String,
}

impl BSimFilterType for PathStartsFilter {
    fn name(&self) -> &str {
        "path_starts"
    }

    fn matches(&self, ctx: &FilterContext<'_>) -> bool {
        ctx.path_prefix.map_or(false, |p| p.starts_with(&self.prefix))
    }
}

// =========================================================================
// HasNamedChildBSimFilterType
// =========================================================================

/// Filter: matches if the function has a named child with the given name.
///
/// Ports `HasNamedChildBSimFilterType`.
#[derive(Debug, Clone)]
pub struct HasNamedChildFilter {
    /// The child name to look for.
    pub child_name: String,
}

impl BSimFilterType for HasNamedChildFilter {
    fn name(&self) -> &str {
        "has_named_child"
    }

    fn matches(&self, ctx: &FilterContext<'_>) -> bool {
        ctx.named_children.iter().any(|c| *c == self.child_name)
    }
}

// =========================================================================
// NegatedFilter — wrapper that inverts any filter
// =========================================================================

/// Negates the result of an inner filter.
///
/// Ports the various `Not*BSimFilterType` classes.
#[derive(Debug)]
pub struct NegatedFilter {
    inner: Box<dyn BSimFilterType>,
}

impl BSimFilterType for NegatedFilter {
    fn name(&self) -> &str {
        // Could store a name, but for now use "not_<inner>"
        "negated"
    }

    fn matches(&self, ctx: &FilterContext<'_>) -> bool {
        !self.inner.matches(ctx)
    }
}

/// Convenience: negate an architecture filter.
pub fn not_architecture(architecture: String) -> NegatedFilter {
    NegatedFilter {
        inner: Box::new(ArchitectureFilter { architecture }),
    }
}

/// Convenience: negate a compiler filter.
pub fn not_compiler(compiler: String) -> NegatedFilter {
    NegatedFilter {
        inner: Box::new(CompilerFilter { compiler }),
    }
}

/// Convenience: negate an executable name filter.
pub fn not_executable_name(exe_name: String) -> NegatedFilter {
    NegatedFilter {
        inner: Box::new(ExecutableNameFilter { exe_name }),
    }
}

/// Convenience: negate an executable category filter.
pub fn not_executable_category(category: String) -> NegatedFilter {
    NegatedFilter {
        inner: Box::new(ExecutableCategoryFilter { category }),
    }
}

/// Convenience: negate an MD5 filter.
pub fn not_md5(md5: String) -> NegatedFilter {
    NegatedFilter {
        inner: Box::new(Md5Filter { md5 }),
    }
}

// =========================================================================
// FilterSet — combines multiple filters with AND/OR logic
// =========================================================================

/// A set of filters combined with AND or OR logic.
#[derive(Debug)]
pub enum FilterSet {
    /// All filters must match.
    And(Vec<Box<dyn BSimFilterType>>),
    /// At least one filter must match.
    Or(Vec<Box<dyn BSimFilterType>>),
}

impl BSimFilterType for FilterSet {
    fn name(&self) -> &str {
        match self {
            FilterSet::And(_) => "and",
            FilterSet::Or(_) => "or",
        }
    }

    fn matches(&self, ctx: &FilterContext<'_>) -> bool {
        match self {
            FilterSet::And(filters) => filters.iter().all(|f| f.matches(ctx)),
            FilterSet::Or(filters) => filters.iter().any(|f| f.matches(ctx)),
        }
    }
}

impl FilterSet {
    /// Create a new AND filter set.
    pub fn and(filters: Vec<Box<dyn BSimFilterType>>) -> Self {
        FilterSet::And(filters)
    }

    /// Create a new OR filter set.
    pub fn or(filters: Vec<Box<dyn BSimFilterType>>) -> Self {
        FilterSet::Or(filters)
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context<'a>() -> FilterContext<'a> {
        FilterContext {
            architecture: "x86:LE:64:default",
            compiler: Some("gcc"),
            executable_name: "libc.so.6",
            executable_category: Some("library"),
            function_name: "memcpy",
            md5: Some("abc123"),
            path_prefix: Some("/usr/lib/x86_64-linux-gnu"),
            function_tags: &["important", "libc"],
            date: Some("2024-01-15"),
            named_children: &["child1", "child2"],
        }
    }

    #[test]
    fn blank_filter_matches_everything() {
        let ctx = make_context();
        assert!(BlankFilter.matches(&ctx));
    }

    #[test]
    fn architecture_filter_exact_match() {
        let f = ArchitectureFilter {
            architecture: "x86:LE:64:default".into(),
        };
        assert!(f.matches(&make_context()));
    }

    #[test]
    fn architecture_filter_no_match() {
        let f = ArchitectureFilter {
            architecture: "ARM:LE:32:v8".into(),
        };
        assert!(!f.matches(&make_context()));
    }

    #[test]
    fn compiler_filter_match() {
        let f = CompilerFilter { compiler: "gcc".into() };
        assert!(f.matches(&make_context()));
    }

    #[test]
    fn compiler_filter_no_compiler() {
        let f = CompilerFilter { compiler: "clang".into() };
        assert!(!f.matches(&make_context()));
    }

    #[test]
    fn executable_name_filter() {
        let f = ExecutableNameFilter { exe_name: "libc.so.6".into() };
        assert!(f.matches(&make_context()));
        let f2 = ExecutableNameFilter { exe_name: "libm.so.6".into() };
        assert!(!f2.matches(&make_context()));
    }

    #[test]
    fn executable_category_filter() {
        let f = ExecutableCategoryFilter { category: "library".into() };
        assert!(f.matches(&make_context()));
        let f2 = ExecutableCategoryFilter { category: "kernel".into() };
        assert!(!f2.matches(&make_context()));
    }

    #[test]
    fn md5_filter() {
        let f = Md5Filter { md5: "abc123".into() };
        assert!(f.matches(&make_context()));
        let f2 = Md5Filter { md5: "xyz789".into() };
        assert!(!f2.matches(&make_context()));
    }

    #[test]
    fn date_earlier_filter() {
        let f = DateEarlierFilter { threshold: "2024-06-01".into() };
        assert!(f.matches(&make_context()));
        let f2 = DateEarlierFilter { threshold: "2023-01-01".into() };
        assert!(!f2.matches(&make_context()));
    }

    #[test]
    fn date_later_filter() {
        let f = DateLaterFilter { threshold: "2023-01-01".into() };
        assert!(f.matches(&make_context()));
        let f2 = DateLaterFilter { threshold: "2024-12-31".into() };
        assert!(!f2.matches(&make_context()));
    }

    #[test]
    fn function_tag_filter() {
        let f = FunctionTagFilter { tag: "libc".into() };
        assert!(f.matches(&make_context()));
        let f2 = FunctionTagFilter { tag: "crypto".into() };
        assert!(!f2.matches(&make_context()));
    }

    #[test]
    fn path_starts_filter() {
        let f = PathStartsFilter { prefix: "/usr/lib".into() };
        assert!(f.matches(&make_context()));
        let f2 = PathStartsFilter { prefix: "/home".into() };
        assert!(!f2.matches(&make_context()));
    }

    #[test]
    fn has_named_child_filter() {
        let f = HasNamedChildFilter { child_name: "child1".into() };
        assert!(f.matches(&make_context()));
        let f2 = HasNamedChildFilter { child_name: "missing".into() };
        assert!(!f2.matches(&make_context()));
    }

    #[test]
    fn negated_architecture_filter() {
        let f = not_architecture("ARM:LE:32:v8".into());
        // ARM != x86, so negated should match
        assert!(f.matches(&make_context()));
        let f2 = not_architecture("x86:LE:64:default".into());
        // x86 == x86, so negated should NOT match
        assert!(!f2.matches(&make_context()));
    }

    #[test]
    fn negated_compiler_filter() {
        let f = not_compiler("clang".into());
        assert!(f.matches(&make_context()));
        let f2 = not_compiler("gcc".into());
        assert!(!f2.matches(&make_context()));
    }

    #[test]
    fn negated_md5_filter() {
        let f = not_md5("xyz789".into());
        assert!(f.matches(&make_context()));
        let f2 = not_md5("abc123".into());
        assert!(!f2.matches(&make_context()));
    }

    #[test]
    fn filter_set_and_all_match() {
        let set = FilterSet::and(vec![
            Box::new(ArchitectureFilter { architecture: "x86:LE:64:default".into() }),
            Box::new(CompilerFilter { compiler: "gcc".into() }),
        ]);
        assert!(set.matches(&make_context()));
    }

    #[test]
    fn filter_set_and_partial_match_fails() {
        let set = FilterSet::and(vec![
            Box::new(ArchitectureFilter { architecture: "x86:LE:64:default".into() }),
            Box::new(CompilerFilter { compiler: "clang".into() }),
        ]);
        assert!(!set.matches(&make_context()));
    }

    #[test]
    fn filter_set_or_any_match() {
        let set = FilterSet::or(vec![
            Box::new(ArchitectureFilter { architecture: "ARM:LE:32:v8".into() }),
            Box::new(CompilerFilter { compiler: "gcc".into() }),
        ]);
        assert!(set.matches(&make_context()));
    }

    #[test]
    fn filter_set_or_none_match() {
        let set = FilterSet::or(vec![
            Box::new(ArchitectureFilter { architecture: "ARM:LE:32:v8".into() }),
            Box::new(CompilerFilter { compiler: "clang".into() }),
        ]);
        assert!(!set.matches(&make_context()));
    }

    #[test]
    fn filter_name_methods() {
        assert_eq!(BlankFilter.name(), "blank");
        let f = ArchitectureFilter { architecture: "x86".into() };
        assert_eq!(f.name(), "architecture");
        let f = CompilerFilter { compiler: "gcc".into() };
        assert_eq!(f.name(), "compiler");
        let f = ExecutableNameFilter { exe_name: "test".into() };
        assert_eq!(f.name(), "executable_name");
    }

    #[test]
    fn negated_filter_name() {
        let f = not_architecture("x86".into());
        assert_eq!(f.name(), "negated");
    }
}
