//! Help module locations: directory and JAR-based help collections.
//!
//! Ported from `help.validator.location.*`.

use std::path::{Path, PathBuf};

/// A location where help module content can be found.
///
/// In Ghidra, help modules can reside in directories or JAR files.
/// This trait abstracts over both.
pub trait HelpModuleLocation: std::fmt::Debug {
    /// The name of the help module.
    fn module_name(&self) -> &str;

    /// The root path of this module.
    fn root_path(&self) -> &Path;

    /// Returns `true` if this location is a directory.
    fn is_directory(&self) -> bool;

    /// Returns a human-readable description.
    fn description(&self) -> String;
}

/// A directory-based help module location.
///
/// Ported from `help.validator.location.DirectoryHelpModuleLocation`.
#[derive(Debug, Clone)]
pub struct DirectoryHelpModuleLocation {
    /// The module name (typically the directory name).
    pub name: String,
    /// The directory path.
    pub path: PathBuf,
}

impl DirectoryHelpModuleLocation {
    /// Create a new directory help module location.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        Self { name, path }
    }

    /// Create with an explicit module name.
    pub fn with_name(path: impl Into<PathBuf>, name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
        }
    }
}

impl HelpModuleLocation for DirectoryHelpModuleLocation {
    fn module_name(&self) -> &str {
        &self.name
    }

    fn root_path(&self) -> &Path {
        &self.path
    }

    fn is_directory(&self) -> bool {
        true
    }

    fn description(&self) -> String {
        format!("Directory({})", self.path.display())
    }
}

/// A JAR-based help module location.
///
/// Ported from `help.validator.location.JarHelpModuleLocation`.
#[derive(Debug, Clone)]
pub struct JarHelpModuleLocation {
    /// The module name.
    pub name: String,
    /// Path to the JAR file.
    pub jar_path: PathBuf,
}

impl JarHelpModuleLocation {
    /// Create a new JAR help module location.
    pub fn new(jar_path: impl Into<PathBuf>) -> Self {
        let jar_path = jar_path.into();
        let name = jar_path
            .file_stem()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        Self { name, jar_path }
    }

    /// Try to create from a file, returning `None` if it's not a JAR.
    pub fn from_file(path: &Path) -> Option<Self> {
        if path.is_file()
            && path
                .extension()
                .map_or(false, |e| e == "jar" || e == "zip")
        {
            Some(Self::new(path))
        } else {
            None
        }
    }
}

impl HelpModuleLocation for JarHelpModuleLocation {
    fn module_name(&self) -> &str {
        &self.name
    }

    fn root_path(&self) -> &Path {
        &self.jar_path
    }

    fn is_directory(&self) -> bool {
        false
    }

    fn description(&self) -> String {
        format!("Jar({})", self.jar_path.display())
    }
}

/// A generated directory help module location.
///
/// Ported from `help.validator.location.GeneratedDirectoryHelpModuleLocation`.
#[derive(Debug, Clone)]
pub struct GeneratedDirectoryHelpModuleLocation {
    /// The underlying directory location.
    pub inner: DirectoryHelpModuleLocation,
    /// The build output directory.
    pub build_dir: PathBuf,
}

impl GeneratedDirectoryHelpModuleLocation {
    /// Create a new generated directory help module location.
    pub fn new(
        path: impl Into<PathBuf>,
        build_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            inner: DirectoryHelpModuleLocation::new(path),
            build_dir: build_dir.into(),
        }
    }
}

impl HelpModuleLocation for GeneratedDirectoryHelpModuleLocation {
    fn module_name(&self) -> &str {
        self.inner.module_name()
    }

    fn root_path(&self) -> &Path {
        self.inner.root_path()
    }

    fn is_directory(&self) -> bool {
        true
    }

    fn description(&self) -> String {
        format!(
            "Generated({}, build={})",
            self.inner.path.display(),
            self.build_dir.display()
        )
    }
}

/// A collection of help module locations.
///
/// Ported from `help.validator.location.HelpModuleCollection`.
pub struct HelpModuleCollection {
    /// The name of this collection.
    pub name: String,
    /// The module locations in this collection.
    locations: Vec<Box<dyn HelpModuleLocation>>,
}

impl std::fmt::Debug for HelpModuleCollection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HelpModuleCollection")
            .field("name", &self.name)
            .field("count", &self.locations.len())
            .finish()
    }
}

impl HelpModuleCollection {
    /// Create a new empty collection.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            locations: Vec::new(),
        }
    }

    /// Add a module location.
    pub fn add(&mut self, location: impl HelpModuleLocation + 'static) {
        self.locations.push(Box::new(location));
    }

    /// Returns the number of modules in this collection.
    pub fn len(&self) -> usize {
        self.locations.len()
    }

    /// Returns `true` if the collection is empty.
    pub fn is_empty(&self) -> bool {
        self.locations.is_empty()
    }

    /// Returns all module names.
    pub fn module_names(&self) -> Vec<&str> {
        self.locations.iter().map(|l| l.module_name()).collect()
    }
}

/// Test double for help module location.
///
/// Ported from `help.validator.location.HelpModuleLocationTestDouble`.
#[derive(Debug, Clone)]
pub struct HelpModuleLocationTestDouble {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
}

impl HelpModuleLocationTestDouble {
    /// Create a test double.
    pub fn new(name: impl Into<String>, path: impl Into<PathBuf>, is_dir: bool) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            is_dir,
        }
    }
}

impl HelpModuleLocation for HelpModuleLocationTestDouble {
    fn module_name(&self) -> &str {
        &self.name
    }

    fn root_path(&self) -> &Path {
        &self.path
    }

    fn is_directory(&self) -> bool {
        self.is_dir
    }

    fn description(&self) -> String {
        format!("TestDouble({})", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_directory_location() {
        let loc = DirectoryHelpModuleLocation::new("/help/Core");
        assert_eq!(loc.module_name(), "Core");
        assert!(loc.is_directory());
    }

    #[test]
    fn test_directory_location_with_name() {
        let loc = DirectoryHelpModuleLocation::with_name("/a/b", "CustomName");
        assert_eq!(loc.module_name(), "CustomName");
    }

    #[test]
    fn test_jar_location() {
        let loc = JarHelpModuleLocation::new("/libs/help.jar");
        assert_eq!(loc.module_name(), "help");
        assert!(!loc.is_directory());
    }

    #[test]
    fn test_jar_from_file_nonexistent() {
        // Non-existent files always return None
        let loc = JarHelpModuleLocation::from_file(Path::new("/nonexistent/features.jar"));
        assert!(loc.is_none());

        // Non-jar extension returns None
        let no = JarHelpModuleLocation::from_file(Path::new("/libs/file.txt"));
        assert!(no.is_none());
    }

    #[test]
    fn test_collection() {
        let mut col = HelpModuleCollection::new("Ghidra");
        col.add(DirectoryHelpModuleLocation::new("/help/Core"));
        col.add(JarHelpModuleLocation::new("/help/Features.jar"));
        assert_eq!(col.len(), 2);
        assert!(!col.is_empty());
        let names = col.module_names();
        assert!(names.contains(&"Core"));
        assert!(names.contains(&"Features"));
    }

    #[test]
    fn test_generated_location() {
        let loc = GeneratedDirectoryHelpModuleLocation::new("/help/G", "/build/G");
        assert!(loc.description().contains("Generated"));
        assert!(loc.is_directory());
    }

    #[test]
    fn test_test_double() {
        let td = HelpModuleLocationTestDouble::new("Test", "/test", true);
        assert_eq!(td.module_name(), "Test");
        assert!(td.is_directory());
    }
}
