//! Executable-based BSim filter types.
//!
//! Ports `ghidra.features.bsim.gui.filters` executable-related filter classes.

use crate::query::description::BSimExecutableInfo;

/// Filter by executable name.
#[derive(Debug, Clone)]
pub struct ExecutableNameBSimFilterType {
    /// Name to match (substring match).
    pub name_pattern: String,
    /// Whether the match is case-sensitive.
    pub case_sensitive: bool,
}

impl ExecutableNameBSimFilterType {
    /// Create a new name filter.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            name_pattern: pattern.into(),
            case_sensitive: true,
        }
    }

    /// Set case sensitivity.
    pub fn case_sensitive(mut self, cs: bool) -> Self {
        self.case_sensitive = cs;
        self
    }

    /// Check if an executable matches.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        if self.case_sensitive {
            exe.executable_name.contains(&self.name_pattern)
        } else {
            exe.executable_name.to_lowercase().contains(&self.name_pattern.to_lowercase())
        }
    }
}

/// Filter by executable category.
#[derive(Debug, Clone)]
pub struct ExecutableCategoryBSimFilterType {
    /// Category to match.
    pub category: String,
}

impl ExecutableCategoryBSimFilterType {
    /// Create a new category filter.
    pub fn new(category: impl Into<String>) -> Self {
        Self {
            category: category.into(),
        }
    }

    /// Check if an executable matches.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        exe.categories.contains(&self.category)
    }
}

/// Filter by architecture.
#[derive(Debug, Clone)]
pub struct ArchitectureBSimFilterType {
    /// Architecture to match (e.g., "x86", "ARM").
    pub architecture: String,
}

impl ArchitectureBSimFilterType {
    /// Create a new architecture filter.
    pub fn new(architecture: impl Into<String>) -> Self {
        Self {
            architecture: architecture.into(),
        }
    }

    /// Check if an executable matches.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        exe.architecture == self.architecture
    }
}

/// Filter by compiler.
#[derive(Debug, Clone)]
pub struct CompilerBSimFilterType {
    /// Compiler to match (e.g., "gcc", "msvc").
    pub compiler: String,
}

impl CompilerBSimFilterType {
    /// Create a new compiler filter.
    pub fn new(compiler: impl Into<String>) -> Self {
        Self {
            compiler: compiler.into(),
        }
    }

    /// Check if an executable matches.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        exe.compiler == self.compiler
    }
}

/// Filter by MD5 hash.
#[derive(Debug, Clone)]
pub struct Md5BSimFilterType {
    /// MD5 hash to match.
    pub md5: String,
}

impl Md5BSimFilterType {
    /// Create a new MD5 filter.
    pub fn new(md5: impl Into<String>) -> Self {
        Self { md5: md5.into() }
    }

    /// Check if an executable matches.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        exe.md5 == self.md5
    }
}

/// Filter by path prefix.
#[derive(Debug, Clone)]
pub struct PathStartsBSimFilterType {
    /// Path prefix to match.
    pub prefix: String,
}

impl PathStartsBSimFilterType {
    /// Create a new path prefix filter.
    pub fn new(prefix: impl Into<String>) -> Self {
        Self { prefix: prefix.into() }
    }

    /// Check if an executable matches.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        exe.path.starts_with(&self.prefix)
    }
}

/// Negated architecture filter.
#[derive(Debug, Clone)]
pub struct NotArchitectureBSimFilterType {
    /// Architecture to exclude.
    pub architecture: String,
}

impl NotArchitectureBSimFilterType {
    /// Create a new negated architecture filter.
    pub fn new(architecture: impl Into<String>) -> Self {
        Self {
            architecture: architecture.into(),
        }
    }

    /// Check if an executable does NOT match.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        exe.architecture != self.architecture
    }
}

/// Negated compiler filter.
#[derive(Debug, Clone)]
pub struct NotCompilerBSimFilterType {
    /// Compiler to exclude.
    pub compiler: String,
}

impl NotCompilerBSimFilterType {
    /// Create a new negated compiler filter.
    pub fn new(compiler: impl Into<String>) -> Self {
        Self {
            compiler: compiler.into(),
        }
    }

    /// Check if an executable does NOT match.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        exe.compiler != self.compiler
    }
}

/// Negated executable category filter.
#[derive(Debug, Clone)]
pub struct NotExecutableCategoryBSimFilterType {
    /// Category to exclude.
    pub category: String,
}

impl NotExecutableCategoryBSimFilterType {
    /// Create a new negated category filter.
    pub fn new(category: impl Into<String>) -> Self {
        Self {
            category: category.into(),
        }
    }

    /// Check if an executable does NOT match.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        !exe.categories.contains(&self.category)
    }
}

/// Negated executable name filter.
#[derive(Debug, Clone)]
pub struct NotExecutableNameBSimFilterType {
    /// Name pattern to exclude.
    pub name_pattern: String,
}

impl NotExecutableNameBSimFilterType {
    /// Create a new negated name filter.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            name_pattern: pattern.into(),
        }
    }

    /// Check if an executable does NOT match.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        !exe.executable_name.contains(&self.name_pattern)
    }
}

/// Negated MD5 filter.
#[derive(Debug, Clone)]
pub struct NotMd5BSimFilterType {
    /// MD5 to exclude.
    pub md5: String,
}

impl NotMd5BSimFilterType {
    /// Create a new negated MD5 filter.
    pub fn new(md5: impl Into<String>) -> Self {
        Self { md5: md5.into() }
    }

    /// Check if an executable does NOT match.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        exe.md5 != self.md5
    }
}

/// Filter by function tag.
#[derive(Debug, Clone)]
pub struct FunctionTagBSimFilterType {
    /// Tag to match.
    pub tag: String,
}

impl FunctionTagBSimFilterType {
    /// Create a new function tag filter.
    pub fn new(tag: impl Into<String>) -> Self {
        Self { tag: tag.into() }
    }
}

/// Filter by whether executable has named children.
#[derive(Debug, Clone)]
pub struct HasNamedChildBSimFilterType {
    /// Minimum number of named children.
    pub min_count: usize,
}

impl HasNamedChildBSimFilterType {
    /// Create a new has-named-child filter.
    pub fn new(min_count: usize) -> Self {
        Self { min_count }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exe(name: &str) -> BSimExecutableInfo {
        BSimExecutableInfo {
            executable_name: name.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn test_executable_name_filter() {
        let filter = ExecutableNameBSimFilterType::new("test");
        assert!(filter.matches(&make_exe("test_binary")));
        assert!(!filter.matches(&make_exe("other_binary")));
    }

    #[test]
    fn test_executable_name_filter_case_insensitive() {
        let filter = ExecutableNameBSimFilterType::new("TEST").case_sensitive(false);
        assert!(filter.matches(&make_exe("test_binary")));
        assert!(filter.matches(&make_exe("TEST_binary")));
    }

    #[test]
    fn test_architecture_filter() {
        let filter = ArchitectureBSimFilterType::new("x86");
        let mut exe = make_exe("test");
        exe.architecture = "x86".to_string();
        assert!(filter.matches(&exe));
        exe.architecture = "ARM".to_string();
        assert!(!filter.matches(&exe));
    }

    #[test]
    fn test_md5_filter() {
        let filter = Md5BSimFilterType::new("abc123");
        let mut exe = make_exe("test");
        exe.md5 = "abc123".to_string();
        assert!(filter.matches(&exe));
        exe.md5 = "def456".to_string();
        assert!(!filter.matches(&exe));
    }

    #[test]
    fn test_negated_architecture_filter() {
        let filter = NotArchitectureBSimFilterType::new("x86");
        let mut exe = make_exe("test");
        exe.architecture = "x86".to_string();
        assert!(!filter.matches(&exe));
        exe.architecture = "ARM".to_string();
        assert!(filter.matches(&exe));
    }

    #[test]
    fn test_path_starts_filter() {
        let filter = PathStartsBSimFilterType::new("/usr/bin");
        let mut exe = make_exe("test");
        exe.path = "/usr/bin/test".to_string();
        assert!(filter.matches(&exe));
        exe.path = "/home/user/test".to_string();
        assert!(!filter.matches(&exe));
    }
}
