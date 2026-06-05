//! Extended BSim filter types.
//!
//! Ports Ghidra's BSim filter type classes that were not yet ported:
//! `ArchitectureBSimFilterType`, `CompilerBSimFilterType`, `ExecutableNameBSimFilterType`,
//! `ExecutableCategoryBSimFilterType`, `FunctionTagBSimFilterType`, `Md5BSimFilterType`,
//! `DateBSimFilterType`, `DateEarlierBSimFilterType`, `DateLaterBSimFilterType`,
//! `PathStartsBSimFilterType`, `BlankBSimFilterType`, `HasNamedChildBSimFilterType`,
//! `NotArchitectureBSimFilterType`, `NotCompilerBSimFilterType`,
//! `NotExecutableCategoryBSimFilterType`, `NotExecutableNameBSimFilterType`,
//! `NotMd5BSimFilterType`.

use serde::{Deserialize, Serialize};

/// The type of BSim filter (positive or negative match).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FilterMatchKind {
    /// Positive match (include matching).
    Include,
    /// Negative match (exclude matching).
    Exclude,
}

/// Architecture filter for BSim queries.
///
/// Port of Ghidra's `ghidra.features.bsim.gui.filters.ArchitectureBSimFilterType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchitectureFilterType {
    /// The architecture string to match.
    pub architecture: String,
    /// Whether this is a positive or negative filter.
    pub match_kind: FilterMatchKind,
}

impl ArchitectureFilterType {
    /// Create an include filter for architecture.
    pub fn include(architecture: impl Into<String>) -> Self {
        Self {
            architecture: architecture.into(),
            match_kind: FilterMatchKind::Include,
        }
    }

    /// Create an exclude filter for architecture.
    pub fn exclude(architecture: impl Into<String>) -> Self {
        Self {
            architecture: architecture.into(),
            match_kind: FilterMatchKind::Exclude,
        }
    }

    /// The filter name.
    pub fn filter_name(&self) -> &str {
        match self.match_kind {
            FilterMatchKind::Include => "architecture",
            FilterMatchKind::Exclude => "notarchitecture",
        }
    }
}

/// Compiler filter for BSim queries.
///
/// Port of Ghidra's `ghidra.features.bsim.gui.filters.CompilerBSimFilterType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerFilterType {
    /// The compiler string to match.
    pub compiler: String,
    /// Whether this is a positive or negative filter.
    pub match_kind: FilterMatchKind,
}

impl CompilerFilterType {
    /// Create an include filter.
    pub fn include(compiler: impl Into<String>) -> Self {
        Self {
            compiler: compiler.into(),
            match_kind: FilterMatchKind::Include,
        }
    }

    /// Create an exclude filter.
    pub fn exclude(compiler: impl Into<String>) -> Self {
        Self {
            compiler: compiler.into(),
            match_kind: FilterMatchKind::Exclude,
        }
    }
}

/// Executable name filter for BSim queries.
///
/// Port of Ghidra's `ghidra.features.bsim.gui.filters.ExecutableNameBSimFilterType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutableNameFilterType {
    /// The executable name to match.
    pub exe_name: String,
    /// Whether this is a positive or negative filter.
    pub match_kind: FilterMatchKind,
}

impl ExecutableNameFilterType {
    /// Create an include filter.
    pub fn include(exe_name: impl Into<String>) -> Self {
        Self {
            exe_name: exe_name.into(),
            match_kind: FilterMatchKind::Include,
        }
    }

    /// Create an exclude filter.
    pub fn exclude(exe_name: impl Into<String>) -> Self {
        Self {
            exe_name: exe_name.into(),
            match_kind: FilterMatchKind::Exclude,
        }
    }
}

/// Executable category filter.
///
/// Port of Ghidra's `ghidra.features.bsim.gui.filters.ExecutableCategoryBSimFilterType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutableCategoryFilterType {
    /// The category to match.
    pub category: String,
    /// Whether this is a positive or negative filter.
    pub match_kind: FilterMatchKind,
}

impl ExecutableCategoryFilterType {
    /// Create an include filter.
    pub fn include(category: impl Into<String>) -> Self {
        Self {
            category: category.into(),
            match_kind: FilterMatchKind::Include,
        }
    }

    /// Create an exclude filter.
    pub fn exclude(category: impl Into<String>) -> Self {
        Self {
            category: category.into(),
            match_kind: FilterMatchKind::Exclude,
        }
    }
}

/// Function tag filter.
///
/// Port of Ghidra's `ghidra.features.bsim.gui.filters.FunctionTagBSimFilterType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionTagFilterType {
    /// The function tag to match.
    pub tag: String,
}

impl FunctionTagFilterType {
    /// Create a new function tag filter.
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into() }
    }
}

/// MD5 hash filter.
///
/// Port of Ghidra's `ghidra.features.bsim.gui.filters.Md5BSimFilterType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Md5FilterType {
    /// The MD5 hash to match.
    pub md5: String,
    /// Whether this is a positive or negative filter.
    pub match_kind: FilterMatchKind,
}

impl Md5FilterType {
    /// Create an include filter.
    pub fn include(md5: impl Into<String>) -> Self {
        Self {
            md5: md5.into(),
            match_kind: FilterMatchKind::Include,
        }
    }

    /// Create an exclude filter.
    pub fn exclude(md5: impl Into<String>) -> Self {
        Self {
            md5: md5.into(),
            match_kind: FilterMatchKind::Exclude,
        }
    }
}

/// Date filter type (earlier or later).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DateFilterDirection {
    /// Match records earlier than the date.
    Earlier,
    /// Match records later than the date.
    Later,
}

/// Date filter for BSim queries.
///
/// Port of Ghidra's `ghidra.features.bsim.gui.filters.DateBSimFilterType`,
/// `DateEarlierBSimFilterType`, `DateLaterBSimFilterType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DateFilterType {
    /// The date as a Unix timestamp (seconds since epoch).
    pub timestamp: i64,
    /// Whether to match earlier or later.
    pub direction: DateFilterDirection,
}

impl DateFilterType {
    /// Create a filter matching records earlier than the given timestamp.
    pub fn earlier_than(timestamp: i64) -> Self {
        Self {
            timestamp,
            direction: DateFilterDirection::Earlier,
        }
    }

    /// Create a filter matching records later than the given timestamp.
    pub fn later_than(timestamp: i64) -> Self {
        Self {
            timestamp,
            direction: DateFilterDirection::Later,
        }
    }
}

/// Path prefix filter.
///
/// Port of Ghidra's `ghidra.features.bsim.gui.filters.PathStartsBSimFilterType`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathStartsFilterType {
    /// The path prefix to match.
    pub prefix: String,
}

impl PathStartsFilterType {
    /// Create a new path prefix filter.
    pub fn new(prefix: impl Into<String>) -> Self {
        Self { prefix: prefix.into() }
    }

    /// Check if a path matches this filter.
    pub fn matches(&self, path: &str) -> bool {
        path.starts_with(&self.prefix)
    }
}

/// Blank/empty filter (matches nothing).
///
/// Port of Ghidra's `ghidra.features.bsim.gui.filters.BlankBSimFilterType`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct BlankFilterType;

impl BlankFilterType {
    /// Create a new blank filter.
    pub fn new() -> Self {
        Self
    }

    /// Always returns false.
    pub fn matches(&self) -> bool {
        false
    }
}

/// A union of all possible BSim filter types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BSimFilterType {
    /// Filter by architecture.
    Architecture(ArchitectureFilterType),
    /// Filter by compiler.
    Compiler(CompilerFilterType),
    /// Filter by executable name.
    ExecutableName(ExecutableNameFilterType),
    /// Filter by executable category.
    ExecutableCategory(ExecutableCategoryFilterType),
    /// Filter by function tag.
    FunctionTag(FunctionTagFilterType),
    /// Filter by MD5.
    Md5(Md5FilterType),
    /// Filter by date.
    Date(DateFilterType),
    /// Filter by path prefix.
    PathStarts(PathStartsFilterType),
    /// Blank filter (matches nothing).
    Blank(BlankFilterType),
}

impl BSimFilterType {
    /// The name of this filter type.
    pub fn name(&self) -> &str {
        match self {
            Self::Architecture(f) => f.filter_name(),
            Self::Compiler(_) => "compiler",
            Self::ExecutableName(_) => "exename",
            Self::ExecutableCategory(_) => "execat",
            Self::FunctionTag(_) => "functag",
            Self::Md5(_) => "md5",
            Self::Date(f) => match f.direction {
                DateFilterDirection::Earlier => "dateearlier",
                DateFilterDirection::Later => "datelater",
            },
            Self::PathStarts(_) => "pathstarts",
            Self::Blank(_) => "blank",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architecture_filter_include() {
        let f = ArchitectureFilterType::include("x86:LE:64:default");
        assert_eq!(f.filter_name(), "architecture");
        assert_eq!(f.match_kind, FilterMatchKind::Include);
    }

    #[test]
    fn architecture_filter_exclude() {
        let f = ArchitectureFilterType::exclude("ARM");
        assert_eq!(f.filter_name(), "notarchitecture");
        assert_eq!(f.match_kind, FilterMatchKind::Exclude);
    }

    #[test]
    fn compiler_filter_types() {
        let include = CompilerFilterType::include("gcc");
        assert_eq!(include.match_kind, FilterMatchKind::Include);

        let exclude = CompilerFilterType::exclude("msvc");
        assert_eq!(exclude.match_kind, FilterMatchKind::Exclude);
    }

    #[test]
    fn executable_name_filter() {
        let f = ExecutableNameFilterType::include("libc.so");
        assert_eq!(f.exe_name, "libc.so");
    }

    #[test]
    fn executable_category_filter() {
        let f = ExecutableCategoryFilterType::include("library");
        assert_eq!(f.category, "library");
    }

    #[test]
    fn function_tag_filter() {
        let f = FunctionTagFilterType::new("crypto");
        assert_eq!(f.tag, "crypto");
    }

    #[test]
    fn md5_filter() {
        let f = Md5FilterType::include("abc123");
        assert_eq!(f.md5, "abc123");
    }

    #[test]
    fn date_filter_directions() {
        let earlier = DateFilterType::earlier_than(1000);
        assert_eq!(earlier.direction, DateFilterDirection::Earlier);
        assert_eq!(earlier.timestamp, 1000);

        let later = DateFilterType::later_than(2000);
        assert_eq!(later.direction, DateFilterDirection::Later);
    }

    #[test]
    fn path_starts_filter() {
        let f = PathStartsFilterType::new("/usr/lib");
        assert!(f.matches("/usr/lib/libc.so"));
        assert!(!f.matches("/home/user/libc.so"));
    }

    #[test]
    fn blank_filter() {
        let f = BlankFilterType::new();
        assert!(!f.matches());
    }

    #[test]
    fn bsim_filter_type_names() {
        assert_eq!(
            BSimFilterType::Architecture(ArchitectureFilterType::include("x86")).name(),
            "architecture"
        );
        assert_eq!(
            BSimFilterType::Blank(BlankFilterType).name(),
            "blank"
        );
    }
}
