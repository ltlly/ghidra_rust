//! Architecture and compiler BSim filter types.
//!
//! Ports `ghidra.features.bsim.gui.filters` architecture and compiler
//! filter classes from Ghidra's Java source.

use crate::query::description::BSimExecutableInfo;

/// Filter for executables by architecture.
///
/// Port of `ArchitectureBSimFilterType.java`.
#[derive(Debug, Clone)]
pub struct ArchitectureBSimFilterType {
    /// Architecture pattern to match.
    pub pattern: String,
    /// Whether to match case-sensitively.
    pub case_sensitive: bool,
}

impl ArchitectureBSimFilterType {
    /// Create a new architecture filter.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
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
            exe.architecture.contains(&self.pattern)
        } else {
            exe.architecture
                .to_lowercase()
                .contains(&self.pattern.to_lowercase())
        }
    }
}

/// Negated architecture filter.
///
/// Port of `NotArchitectureBSimFilterType.java`.
#[derive(Debug, Clone)]
pub struct NotArchitectureBSimFilterType {
    /// The inner architecture filter (negated).
    pub inner: ArchitectureBSimFilterType,
}

impl NotArchitectureBSimFilterType {
    /// Create a new negated architecture filter.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            inner: ArchitectureBSimFilterType::new(pattern),
        }
    }

    /// Check if an executable does NOT match the architecture.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        !self.inner.matches(exe)
    }
}

/// Filter for executables by compiler.
///
/// Port of `CompilerBSimFilterType.java`.
#[derive(Debug, Clone)]
pub struct CompilerBSimFilterType {
    /// Compiler pattern to match.
    pub pattern: String,
    /// Whether to match case-sensitively.
    pub case_sensitive: bool,
}

impl CompilerBSimFilterType {
    /// Create a new compiler filter.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            case_sensitive: true,
        }
    }

    /// Check if an executable matches.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        if self.case_sensitive {
            exe.compiler.contains(&self.pattern)
        } else {
            exe.compiler
                .to_lowercase()
                .contains(&self.pattern.to_lowercase())
        }
    }
}

/// Negated compiler filter.
///
/// Port of `NotCompilerBSimFilterType.java`.
#[derive(Debug, Clone)]
pub struct NotCompilerBSimFilterType {
    /// The inner compiler filter (negated).
    pub inner: CompilerBSimFilterType,
}

impl NotCompilerBSimFilterType {
    /// Create a new negated compiler filter.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            inner: CompilerBSimFilterType::new(pattern),
        }
    }

    /// Check if an executable does NOT match the compiler.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        !self.inner.matches(exe)
    }
}

/// Filter by executable category.
///
/// Port of `ExecutableCategoryBSimFilterType.java`.
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
        exe.categories.iter().any(|c| c == &self.category)
    }
}

/// Negated executable category filter.
///
/// Port of `NotExecutableCategoryBSimFilterType.java`.
#[derive(Debug, Clone)]
pub struct NotExecutableCategoryBSimFilterType {
    /// The inner category filter (negated).
    pub inner: ExecutableCategoryBSimFilterType,
}

impl NotExecutableCategoryBSimFilterType {
    /// Create a new negated category filter.
    pub fn new(category: impl Into<String>) -> Self {
        Self {
            inner: ExecutableCategoryBSimFilterType::new(category),
        }
    }

    /// Check if an executable does NOT match the category.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        !self.inner.matches(exe)
    }
}

/// Filter by path prefix.
///
/// Port of `PathStartsBSimFilterType.java`.
#[derive(Debug, Clone)]
pub struct PathStartsBSimFilterType {
    /// Path prefix to match.
    pub prefix: String,
}

impl PathStartsBSimFilterType {
    /// Create a new path prefix filter.
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    /// Check if an executable's path starts with the prefix.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        exe.executable_name.starts_with(&self.prefix)
    }
}

/// Filter by MD5 hash.
///
/// Port of `Md5BSimFilterType.java`.
#[derive(Debug, Clone)]
pub struct Md5BSimFilterType {
    /// The MD5 hash to match.
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

/// Negated MD5 filter.
///
/// Port of `NotMd5BSimFilterType.java`.
#[derive(Debug, Clone)]
pub struct NotMd5BSimFilterType {
    /// The inner MD5 filter (negated).
    pub inner: Md5BSimFilterType,
}

impl NotMd5BSimFilterType {
    /// Create a new negated MD5 filter.
    pub fn new(md5: impl Into<String>) -> Self {
        Self {
            inner: Md5BSimFilterType::new(md5),
        }
    }

    /// Check if an executable does NOT match.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        !self.inner.matches(exe)
    }
}

/// Negated executable name filter.
///
/// Port of `NotExecutableNameBSimFilterType.java`.
#[derive(Debug, Clone)]
pub struct NotExecutableNameBSimFilterType {
    /// Name pattern to exclude.
    pub pattern: String,
}

impl NotExecutableNameBSimFilterType {
    /// Create a new negated name filter.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
        }
    }

    /// Check if an executable does NOT match the name.
    pub fn matches(&self, exe: &BSimExecutableInfo) -> bool {
        !exe.executable_name.contains(&self.pattern)
    }
}

/// Filter by function tag.
///
/// Port of `FunctionTagBSimFilterType.java`.
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

    /// Check if a function has this tag.
    pub fn matches_function_tags(&self, tags: &[String]) -> bool {
        tags.iter().any(|t| t == &self.tag)
    }
}

/// Filter checking if a function has a named child.
///
/// Port of `HasNamedChildBSimFilterType.java`.
#[derive(Debug, Clone)]
pub struct HasNamedChildBSimFilterType {
    /// Child name pattern.
    pub child_pattern: String,
}

impl HasNamedChildBSimFilterType {
    /// Create a new named-child filter.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            child_pattern: pattern.into(),
        }
    }

    /// Check if any child name matches.
    pub fn matches_children(&self, children: &[String]) -> bool {
        children.iter().any(|c| c.contains(&self.child_pattern))
    }
}

/// Blank/no-op filter that matches everything.
///
/// Port of `BlankBSimFilterType.java`.
#[derive(Debug, Clone, Default)]
pub struct BlankBSimFilterType;

impl BlankBSimFilterType {
    /// Create a new blank filter.
    pub fn new() -> Self {
        Self
    }

    /// Always returns true.
    pub fn matches(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_exe(name: &str, arch: &str) -> BSimExecutableInfo {
        let mut exe = BSimExecutableInfo::new("id1", name);
        exe.architecture = arch.to_string();
        exe
    }

    #[test]
    fn test_architecture_filter() {
        let f = ArchitectureBSimFilterType::new("x86");
        let exe = make_exe("test.exe", "x86");
        assert!(f.matches(&exe));
        let exe2 = make_exe("test.exe", "ARM");
        assert!(!f.matches(&exe2));
    }

    #[test]
    fn test_not_architecture_filter() {
        let f = NotArchitectureBSimFilterType::new("ARM");
        let exe = make_exe("test.exe", "x86");
        assert!(f.matches(&exe));
        let exe2 = make_exe("test.exe", "ARM");
        assert!(!f.matches(&exe2));
    }

    #[test]
    fn test_compiler_filter() {
        let f = CompilerBSimFilterType::new("gcc");
        let mut exe = make_exe("test.exe", "x86");
        exe.compiler = "gcc 11.2".to_string();
        assert!(f.matches(&exe));
    }

    #[test]
    fn test_category_filter() {
        let f = ExecutableCategoryBSimFilterType::new("malware");
        let mut exe = make_exe("test.exe", "x86");
        exe.categories.push("malware".to_string());
        assert!(f.matches(&exe));
    }

    #[test]
    fn test_path_starts_filter() {
        let f = PathStartsBSimFilterType::new("/usr/lib");
        let mut exe = make_exe("test.exe", "x86");
        exe.executable_name = "/usr/lib/libc.so".to_string();
        assert!(f.matches(&exe));
        exe.executable_name = "/opt/lib/libc.so".to_string();
        assert!(!f.matches(&exe));
    }

    #[test]
    fn test_md5_filter() {
        let f = Md5BSimFilterType::new("abc123");
        let mut exe = make_exe("test.exe", "x86");
        exe.md5 = "abc123".to_string();
        assert!(f.matches(&exe));
    }

    #[test]
    fn test_not_md5_filter() {
        let f = NotMd5BSimFilterType::new("abc123");
        let exe = make_exe("test.exe", "x86");
        assert!(f.matches(&exe));
    }

    #[test]
    fn test_not_executable_name_filter() {
        let f = NotExecutableNameBSimFilterType::new("malware");
        let exe = make_exe("libc.so", "x86");
        assert!(f.matches(&exe));
        let exe2 = make_exe("malware.exe", "x86");
        assert!(!f.matches(&exe2));
    }

    #[test]
    fn test_function_tag_filter() {
        let f = FunctionTagBSimFilterType::new("entry_point");
        let tags = vec!["entry_point".to_string(), "main".to_string()];
        assert!(f.matches_function_tags(&tags));
        let empty: Vec<String> = vec![];
        assert!(!f.matches_function_tags(&empty));
    }

    #[test]
    fn test_has_named_child_filter() {
        let f = HasNamedChildBSimFilterType::new("helper");
        let children = vec!["helper_func".to_string(), "init".to_string()];
        assert!(f.matches_children(&children));
    }

    #[test]
    fn test_blank_filter() {
        let f = BlankBSimFilterType::new();
        assert!(f.matches());
    }
}
