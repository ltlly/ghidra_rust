//! Resource and classloader abstractions.
//!
//! Port of `generic.jar`: Resource, ResourceFile, ResourceFileFilter,
//! GClassLoader, JarEntryNode, JarEntryRootNode, JarEntryFilter,
//! FileResource, JarResource, and ClassModuleTree.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// A resource that can be read from the filesystem or a jar.
///
/// Port of `generic.jar.Resource`.
#[derive(Debug, Clone)]
pub struct Resource {
    /// Path to the resource.
    pub path: PathBuf,
    /// Whether this resource is a directory.
    pub is_directory: bool,
    /// Whether this resource is a jar file entry.
    pub is_jar_entry: bool,
}

impl Resource {
    /// Create a new file-based resource.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let is_dir = path.is_dir();
        Self {
            path,
            is_directory: is_dir,
            is_jar_entry: false,
        }
    }

    /// Create a resource representing a jar entry.
    pub fn jar_entry(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            is_directory: false,
            is_jar_entry: true,
        }
    }

    /// Get the filename of this resource.
    pub fn name(&self) -> Option<&str> {
        self.path.file_name().and_then(|n| n.to_str())
    }

    /// Get the extension of this resource.
    pub fn extension(&self) -> Option<&str> {
        self.path.extension().and_then(|e| e.to_str())
    }

    /// Read the contents of this resource as bytes.
    pub fn read_bytes(&self) -> std::io::Result<Vec<u8>> {
        std::fs::read(&self.path)
    }

    /// Read the contents of this resource as a UTF-8 string.
    pub fn read_string(&self) -> std::io::Result<String> {
        std::fs::read_to_string(&self.path)
    }
}

/// A file or directory in the application's resource tree.
///
/// Port of `generic.jar.ResourceFile`.
#[derive(Debug, Clone)]
pub struct ResourceFile {
    /// The underlying file path.
    pub file: PathBuf,
    /// Whether this is inside a jar file.
    pub in_jar: bool,
}

impl ResourceFile {
    /// Create from a filesystem path.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            file: path.into(),
            in_jar: false,
        }
    }

    /// Create from a path inside a jar.
    pub fn from_jar(path: impl Into<PathBuf>) -> Self {
        Self {
            file: path.into(),
            in_jar: true,
        }
    }

    /// Get the path.
    pub fn path(&self) -> &Path {
        &self.file
    }

    /// Get the file name.
    pub fn name(&self) -> Option<&str> {
        self.file.file_name().and_then(|n| n.to_str())
    }

    /// Whether this file exists.
    pub fn exists(&self) -> bool {
        self.file.exists()
    }

    /// Whether this is a directory.
    pub fn is_directory(&self) -> bool {
        self.file.is_dir()
    }

    /// Get child files.
    pub fn list_files(&self) -> std::io::Result<Vec<ResourceFile>> {
        if !self.file.is_dir() {
            return Ok(Vec::new());
        }
        let mut result = Vec::new();
        for entry in std::fs::read_dir(&self.file)? {
            let entry = entry?;
            result.push(ResourceFile::new(entry.path()));
        }
        Ok(result)
    }

    /// Get the extension.
    pub fn extension(&self) -> Option<&str> {
        self.file.extension().and_then(|e| e.to_str())
    }

    /// Get an input stream equivalent as bytes.
    pub fn read_bytes(&self) -> std::io::Result<Vec<u8>> {
        std::fs::read(&self.file)
    }
}

impl fmt::Display for ResourceFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.file.display())
    }
}

/// A filter for selecting resource files.
///
/// Port of `generic.jar.ResourceFileFilter`.
pub trait ResourceFileFilter: Send + Sync {
    /// Returns true if the resource file matches the filter.
    fn accepts(&self, file: &ResourceFile) -> bool;
}

/// A file extension-based filter.
pub struct ExtensionFilter {
    /// The extension to match (without the dot).
    pub extension: String,
}

impl ExtensionFilter {
    /// Create a new extension filter.
    pub fn new(extension: impl Into<String>) -> Self {
        Self {
            extension: extension.into(),
        }
    }
}

impl ResourceFileFilter for ExtensionFilter {
    fn accepts(&self, file: &ResourceFile) -> bool {
        file.extension()
            .map(|ext| ext.eq_ignore_ascii_case(&self.extension))
            .unwrap_or(false)
    }
}

/// A node in a jar entry tree.
///
/// Port of `generic.jar.JarEntryNode`.
#[derive(Debug, Clone)]
pub struct JarEntryNode {
    /// Entry name.
    pub name: String,
    /// Full path within the jar.
    pub full_path: String,
    /// Whether this is a directory entry.
    pub is_directory: bool,
    /// Child entries.
    pub children: Vec<JarEntryNode>,
}

impl JarEntryNode {
    /// Create a new jar entry node.
    pub fn new(name: impl Into<String>, full_path: impl Into<String>, is_directory: bool) -> Self {
        Self {
            name: name.into(),
            full_path: full_path.into(),
            is_directory,
            children: Vec::new(),
        }
    }

    /// Add a child entry.
    pub fn add_child(&mut self, child: JarEntryNode) {
        self.children.push(child);
    }

    /// Find a child by name.
    pub fn child(&self, name: &str) -> Option<&JarEntryNode> {
        self.children.iter().find(|c| c.name == name)
    }
}

/// Root node of a jar entry tree.
///
/// Port of `generic.jar.JarEntryRootNode`.
#[derive(Debug, Clone)]
pub struct JarEntryRootNode {
    /// The jar file path.
    pub jar_path: PathBuf,
    /// Root entries.
    pub entries: Vec<JarEntryNode>,
}

impl JarEntryRootNode {
    /// Create a new root node.
    pub fn new(jar_path: impl Into<PathBuf>) -> Self {
        Self {
            jar_path: jar_path.into(),
            entries: Vec::new(),
        }
    }
}

/// A filter for jar entries.
///
/// Port of `generic.jar.JarEntryFilter`.
pub trait JarEntryFilter: Send + Sync {
    /// Returns true if the entry matches.
    fn accepts(&self, name: &str) -> bool;
}

/// A simple classloader that searches application resource paths.
///
/// Port of `generic.jar.GClassLoader`.
#[derive(Debug, Clone)]
pub struct GClassLoader {
    /// Search paths for resources.
    paths: Vec<PathBuf>,
    /// Cached resource map (name -> path).
    resource_cache: HashMap<String, PathBuf>,
}

impl GClassLoader {
    /// Create a new classloader with the given search paths.
    pub fn new(paths: Vec<PathBuf>) -> Self {
        Self {
            paths,
            resource_cache: HashMap::new(),
        }
    }

    /// Get the search paths.
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// Add a search path.
    pub fn add_path(&mut self, path: PathBuf) {
        self.paths.push(path);
    }

    /// Find a resource by name.
    pub fn find_resource(&self, name: &str) -> Option<PathBuf> {
        if let Some(cached) = self.resource_cache.get(name) {
            return Some(cached.clone());
        }
        for path in &self.paths {
            let candidate = path.join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
        None
    }
}

impl Default for GClassLoader {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

/// Tree structure for module class discovery.
///
/// Port of `generic.jar.ClassModuleTree`.
#[derive(Debug, Clone)]
pub struct ClassModuleTree {
    /// Module name.
    pub name: String,
    /// Child modules.
    pub children: Vec<ClassModuleTree>,
    /// Classes in this module.
    pub classes: Vec<String>,
}

impl ClassModuleTree {
    /// Create a new module tree node.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            children: Vec::new(),
            classes: Vec::new(),
        }
    }

    /// Add a child module.
    pub fn add_child(&mut self, child: ClassModuleTree) {
        self.children.push(child);
    }

    /// Add a class to this module.
    pub fn add_class(&mut self, class_name: impl Into<String>) {
        self.classes.push(class_name.into());
    }
}

/// A resource representing a file on disk.
///
/// Port of `generic.jar.FileResource`.
#[derive(Debug, Clone)]
pub struct FileResource {
    /// The file path.
    pub path: PathBuf,
}

impl FileResource {
    /// Create a new file resource.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

/// A resource from within a jar file.
///
/// Port of `generic.jar.JarResource`.
#[derive(Debug, Clone)]
pub struct JarResource {
    /// The jar file path.
    pub jar_path: PathBuf,
    /// Entry name within the jar.
    pub entry_name: String,
}

impl JarResource {
    /// Create a new jar resource.
    pub fn new(jar_path: impl Into<PathBuf>, entry_name: impl Into<String>) -> Self {
        Self {
            jar_path: jar_path.into(),
            entry_name: entry_name.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_basic() {
        let r = Resource::new("/tmp/test.txt");
        assert!(!r.is_jar_entry);
        assert_eq!(r.name(), Some("test.txt"));
        assert_eq!(r.extension(), Some("txt"));
    }

    #[test]
    fn test_resource_file() {
        let rf = ResourceFile::new("/tmp");
        assert!(rf.is_directory());
        assert!(!rf.in_jar);
    }

    #[test]
    fn test_extension_filter() {
        let filter = ExtensionFilter::new("class");
        let rf = ResourceFile::new("/tmp/Foo.class");
        assert!(filter.accepts(&rf));
        let rf2 = ResourceFile::new("/tmp/Foo.txt");
        assert!(!filter.accepts(&rf2));
    }

    #[test]
    fn test_jar_entry_node() {
        let mut root = JarEntryNode::new("root", "/", true);
        let child = JarEntryNode::new("child.txt", "/child.txt", false);
        root.add_child(child);
        assert!(root.child("child.txt").is_some());
        assert!(root.child("missing").is_none());
    }

    #[test]
    fn test_g_class_loader() {
        let loader = GClassLoader::new(vec![PathBuf::from("/tmp")]);
        assert_eq!(loader.paths().len(), 1);
        assert!(loader.find_resource("nonexistent_file_12345").is_none());
    }

    #[test]
    fn test_class_module_tree() {
        let mut tree = ClassModuleTree::new("com.ghidra");
        tree.add_class("com.ghidra.Main");
        tree.add_child(ClassModuleTree::new("com.ghidra.util"));
        assert_eq!(tree.classes.len(), 1);
        assert_eq!(tree.children.len(), 1);
    }
}
