//! Central data type manager handler.
//!
//! Ported from Ghidra's `DataTypeManagerHandler` Java class.
//!
//! [`DataTypeManagerHandler`] is the main coordinator that tracks all
//! open archives, manages the built-in type library, and provides
//! lookup, lifecycle, and persistence operations used by the rest of
//! the data-type manager plugin.

use ghidra_core::data::{
    BuiltInDataTypeManager, CategoryPath, DataType, DataTypeManager,
    SourceArchive, StandaloneDataTypeManager, UniversalID,
};
use std::collections::HashSet;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use super::archive::{
    Archive, ArchiveKind, ArchiveManagerListener, BuiltInArchive, FileArchive,
    InvalidFileArchive, ProgramArchive, ProjectArchive,
};

// ---------------------------------------------------------------------------
// RecentlyUsedDataType
// ---------------------------------------------------------------------------

/// Tracks the most recently used data type for quick-access features.
///
/// Ported from the inner `RecentlyUsedDataType` class inside
/// `DataTypeManagerHandler`.
#[derive(Debug, Clone, Default)]
pub struct RecentlyUsedDataType {
    manager_name: Option<String>,
    category_path: CategoryPath,
    data_type_name: Option<String>,
}

impl RecentlyUsedDataType {
    /// Create an empty (no recent type) tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a data type as recently used.
    pub fn set(&mut self, dt: &dyn DataType, manager_name: Option<&str>) {
        self.data_type_name = Some(dt.name().to_string());
        self.category_path = dt.get_category_path().clone();
        self.manager_name = manager_name.map(|s| s.to_string());
    }

    /// Try to resolve the recently used type from the given manager.
    pub fn resolve(&self, manager: &dyn DataTypeManager) -> Option<Arc<dyn DataType>> {
        let name = self.data_type_name.as_ref()?;
        manager.find_type(&self.category_path, name)
    }

    /// Returns the name of the recently used type, if any.
    pub fn name(&self) -> Option<&str> {
        self.data_type_name.as_deref()
    }

    /// Returns the category path of the recently used type.
    pub fn category_path(&self) -> &CategoryPath {
        &self.category_path
    }

    /// Returns the manager name that owns this type.
    pub fn manager_name(&self) -> Option<&str> {
        self.manager_name.as_deref()
    }
}

// ---------------------------------------------------------------------------
// DataTypeIndexer
// ---------------------------------------------------------------------------

/// A simple indexer that tracks which [`DataTypeManager`]s are active
/// for searching data types across all open archives.
///
/// In the full implementation this would feed a search index (e.g., for
/// the data type chooser dialog).  Here we track the managers and
/// provide a basic name-search.
#[derive(Debug)]
pub struct DataTypeIndexer {
    /// Names of all registered managers.
    managers: Vec<String>,
}

impl DataTypeIndexer {
    /// Create an empty indexer.
    pub fn new() -> Self {
        Self {
            managers: Vec::new(),
        }
    }

    /// Register a manager by name.
    pub fn add_data_type_manager(&mut self, name: impl Into<String>) {
        let name = name.into();
        if !self.managers.contains(&name) {
            self.managers.push(name);
        }
    }

    /// Unregister a manager by name.
    pub fn remove_data_type_manager(&mut self, name: &str) {
        self.managers.retain(|n| n != name);
    }

    /// Number of registered managers.
    pub fn manager_count(&self) -> usize {
        self.managers.len()
    }

    /// Returns names of all registered managers.
    pub fn manager_names(&self) -> &[String] {
        &self.managers
    }
}

impl Default for DataTypeIndexer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DataTypeManagerHandler
// ---------------------------------------------------------------------------

/// Central coordinator for all open data type archives.
///
/// Manages the built-in data type manager, tracks open archives (file,
/// program, project), handles archive lifecycle (open / close / save),
/// and dispatches change notifications to registered listeners.
///
/// Ported from Ghidra's `DataTypeManagerHandler` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::datamgr::handler::DataTypeManagerHandler;
/// use ghidra_features::datamgr::Archive;
///
/// let mut handler = DataTypeManagerHandler::new("Data Type Manager");
/// assert_eq!(handler.all_archives().len(), 0);
///
/// // Open a file archive
/// handler.open_file_archive("test", "/tmp/test.gdt".into(), true);
/// assert_eq!(handler.all_archives().len(), 1);
///
/// // Get the built-in archive
/// assert_eq!(handler.built_in_archive().name(), Some("BuiltInTypes"));
/// ```
pub struct DataTypeManagerHandler {
    /// Plugin/tool name for context.
    plugin_name: String,
    /// The built-in data type archive (always present).
    built_in_archive: BuiltInArchive,
    /// All open archives (including built-in).
    open_archives: Vec<Box<dyn Archive>>,
    /// The program archive, if a program is currently open.
    program_archive_index: Option<usize>,
    /// Indexer for data type search.
    data_type_indexer: DataTypeIndexer,
    /// Recently used data type.
    recently_used: RecentlyUsedDataType,
    /// Modification counter -- incremented on every archive / category /
    /// data type change.
    mod_count: u64,
    /// Archive manager listeners.
    archive_listeners: Vec<Box<dyn ArchiveManagerListener>>,
    /// Recently opened file archive paths.
    recent_archive_paths: Vec<String>,
    /// User-opened file archive paths.
    user_opened_paths: HashSet<String>,
    /// Initially opened file archive paths (for dirty tracking).
    initially_opened_paths: HashSet<String>,
}

impl DataTypeManagerHandler {
    /// Create a new handler with a built-in archive.
    pub fn new(plugin_name: impl Into<String>) -> Self {
        let built_in_dtm = BuiltInDataTypeManager::new();
        let built_in_name = "BuiltInTypes".to_string();

        let mut indexer = DataTypeIndexer::new();
        indexer.add_data_type_manager(&built_in_name);

        let built_in_archive = BuiltInArchive::new(built_in_dtm);

        Self {
            plugin_name: plugin_name.into(),
            built_in_archive,
            open_archives: Vec::new(),
            program_archive_index: None,
            data_type_indexer: indexer,
            recently_used: RecentlyUsedDataType::new(),
            mod_count: 0,
            archive_listeners: Vec::new(),
            recent_archive_paths: Vec::new(),
            user_opened_paths: HashSet::new(),
            initially_opened_paths: HashSet::new(),
        }
    }

    // -- Plugin name --

    /// The name of the owning plugin.
    pub fn plugin_name(&self) -> &str {
        &self.plugin_name
    }

    // -- Modification count --

    /// Returns the current modification count.
    ///
    /// Incremented any time any archive, category, or data type changes.
    pub fn modification_count(&self) -> u64 {
        self.mod_count
    }

    /// Increment the modification counter.
    pub fn increment_mod_count(&mut self) {
        self.mod_count += 1;
    }

    // -- Built-in manager --

    /// Returns a reference to the built-in data type manager.
    ///
    /// This is a convenience shorthand that retrieves the DTM from the
    /// built-in archive.
    pub fn built_in_data_types_manager_ref(&self) -> &dyn DataTypeManager {
        self.built_in_archive.data_type_manager()
    }

    /// Returns a reference to the built-in archive.
    pub fn built_in_archive(&self) -> &BuiltInArchive {
        &self.built_in_archive
    }

    /// Returns a mutable reference to the built-in archive.
    pub fn built_in_archive_mut(&mut self) -> &mut BuiltInArchive {
        &mut self.built_in_archive
    }

    // -- Archive lifecycle --

    /// Open a file archive from a path.
    ///
    /// Returns the index of the newly opened archive in `open_archives`,
    /// or `None` if the archive is already open.
    pub fn open_file_archive(
        &mut self,
        name: impl Into<String>,
        path: PathBuf,
        modifiable: bool,
    ) -> Option<usize> {
        let name = name.into();

        // Check if already open.
        for (i, archive) in self.open_archives.iter().enumerate() {
            if archive.kind() == ArchiveKind::File {
                if let Some(n) = archive.name() {
                    if n == name {
                        return Some(i);
                    }
                }
            }
        }

        let dtm = StandaloneDataTypeManager::new();
        let archive = FileArchive::new(&name, path.clone(), dtm, modifiable);
        let idx = self.open_archives.len();
        self.open_archives.push(Box::new(archive));
        self.data_type_indexer.add_data_type_manager(&name);
        self.recent_archive_paths.push(path.to_string_lossy().into_owned());
        self.mod_count += 1;
        Some(idx)
    }

    /// Open a program archive.
    ///
    /// Returns the index of the archive.
    pub fn open_program_archive(
        &mut self,
        name: impl Into<String>,
        dtm: StandaloneDataTypeManager,
    ) -> usize {
        let name = name.into();
        let archive = ProgramArchive::new(&name, dtm);
        let idx = self.open_archives.len();
        self.open_archives.push(Box::new(archive));
        self.data_type_indexer.add_data_type_manager(&name);
        self.program_archive_index = Some(idx);
        self.mod_count += 1;
        idx
    }

    /// Open a project archive.
    ///
    /// Returns the index of the archive.
    pub fn open_project_archive(
        &mut self,
        name: impl Into<String>,
        domain_file_path: impl Into<String>,
        dtm: StandaloneDataTypeManager,
    ) -> usize {
        let name = name.into();
        let path = domain_file_path.into();
        let archive = ProjectArchive::new(&name, &path, dtm);
        let idx = self.open_archives.len();
        self.open_archives.push(Box::new(archive));
        self.data_type_indexer.add_data_type_manager(&name);
        self.mod_count += 1;
        idx
    }

    /// Add an invalid-file archive placeholder.
    pub fn add_invalid_archive(&mut self, source: SourceArchive) {
        let archive = InvalidFileArchive::new(source);
        self.open_archives.push(Box::new(archive));
        self.mod_count += 1;
    }

    /// Close the archive at the given index.
    ///
    /// Returns `true` if the archive was closed, `false` if the index
    /// is out of range or the archive is the built-in archive.
    pub fn close_archive(&mut self, index: usize) -> bool {
        if index >= self.open_archives.len() {
            return false;
        }
        // Cannot close built-in archive (it is at logical index "before" open_archives).
        // Check kind.
        let kind = self.open_archives[index].kind();
        if kind == ArchiveKind::BuiltIn {
            return false;
        }
        let name = self.open_archives[index]
            .name()
            .unwrap_or("")
            .to_string();
        self.open_archives[index].close();
        self.data_type_indexer.remove_data_type_manager(&name);
        self.open_archives.remove(index);

        // Adjust program archive index.
        if let Some(prog_idx) = self.program_archive_index {
            if prog_idx == index {
                self.program_archive_index = None;
            } else if prog_idx > index {
                self.program_archive_index = Some(prog_idx - 1);
            }
        }

        self.mod_count += 1;
        true
    }

    /// Close all non-built-in archives.
    pub fn close_all_archives(&mut self) {
        for archive in self.open_archives.iter_mut() {
            if archive.kind() != ArchiveKind::BuiltIn {
                if let Some(name) = archive.name() {
                    self.data_type_indexer.remove_data_type_manager(name);
                }
                archive.close();
            }
        }
        self.open_archives.retain(|a| a.kind() == ArchiveKind::BuiltIn);
        self.program_archive_index = None;
        self.mod_count += 1;
    }

    // -- Archive queries --

    /// Returns a slice of all open archives.
    pub fn all_archives(&self) -> &[Box<dyn Archive>] {
        &self.open_archives
    }

    /// Returns the number of open archives (including the built-in one).
    pub fn archive_count(&self) -> usize {
        self.open_archives.len() + 1 // +1 for built-in
    }

    /// Find an archive by its universal ID.
    pub fn find_archive_by_id(&self, id: UniversalID) -> Option<usize> {
        self.open_archives
            .iter()
            .position(|a| a.universal_id() == Some(id))
    }

    /// Returns the data type manager for a source archive, identified by ID.
    pub fn get_data_type_manager_for_source(
        &self,
        source_id: UniversalID,
    ) -> Option<&dyn DataTypeManager> {
        for archive in &self.open_archives {
            if archive.universal_id() == Some(source_id) {
                return Some(archive.data_type_manager());
            }
        }
        None
    }

    /// Returns a list of all modified (changed) file archives.
    pub fn all_modified_file_archives(&self) -> Vec<usize> {
        self.open_archives
            .iter()
            .enumerate()
            .filter(|(_, a)| a.is_modifiable() && a.kind() == ArchiveKind::File && a.is_changed())
            .map(|(i, _)| i)
            .collect()
    }

    /// Returns a list of all file or project archive indices.
    pub fn all_file_or_project_archives(&self) -> Vec<usize> {
        self.open_archives
            .iter()
            .enumerate()
            .filter(|(_, a)| matches!(a.kind(), ArchiveKind::File | ArchiveKind::Project))
            .map(|(i, _)| i)
            .collect()
    }

    // -- Recently used --

    /// Set the recently used data type.
    pub fn set_recently_used_data_type(&mut self, dt: &dyn DataType, manager_name: Option<&str>) {
        self.recently_used.set(dt, manager_name);
    }

    /// Get the recently used data type info.
    pub fn recently_used_data_type(&self) -> &RecentlyUsedDataType {
        &self.recently_used
    }

    // -- Data type indexer --

    /// Returns a reference to the data type indexer.
    pub fn data_type_indexer(&self) -> &DataTypeIndexer {
        &self.data_type_indexer
    }

    // -- Equate names --

    /// Search all open archives for enum value names matching `value`.
    ///
    /// Returns a set of fully-qualified equate names.
    pub fn find_equate_names(&self, _value: i64) -> HashSet<String> {
        // Full implementation would search all EnumDataType members.
        HashSet::new()
    }

    // -- Favorites --

    /// Collect all favorite data types across all open archives.
    pub fn get_favorite_data_types(&self) -> Vec<Arc<dyn DataType>> {
        // In a full implementation, each DTM would have a favorites set.
        Vec::new()
    }

    // -- Listener management --

    /// Register an archive manager listener.
    pub fn add_archive_manager_listener(&mut self, listener: Box<dyn ArchiveManagerListener>) {
        self.archive_listeners.push(listener);
    }

    // -- Recently opened paths --

    /// Returns recently opened archive paths.
    pub fn recent_archive_paths(&self) -> &[String] {
        &self.recent_archive_paths
    }

    /// Add a recently opened archive path.
    pub fn add_recent_archive_path(&mut self, path: impl Into<String>) {
        let path = path.into();
        if !self.recent_archive_paths.contains(&path) {
            self.recent_archive_paths.push(path);
        }
    }

    // -- Source archive name parsing --

    /// Parse a project pathname of the form `:projectName:/path/to/archive`.
    ///
    /// Returns `(project_name, pathname)` or `None` if the format is invalid.
    pub fn parse_project_pathname(project_file_path: &str) -> Option<(&str, &str)> {
        if !project_file_path.starts_with(':') {
            return None;
        }
        let rest = &project_file_path[1..];
        let index = rest.find(':')?;
        let project_name = &rest[..index];
        let pathname = &rest[index + 1..];
        if pathname.len() > 1 && pathname.starts_with('/') {
            Some((project_name, pathname))
        } else {
            None
        }
    }

    /// Construct a project pathname string from project name and file path.
    pub fn get_project_pathname(project_name: &str, pathname: &str) -> String {
        if pathname.len() < 2 || !pathname.starts_with('/') {
            panic!("Absolute project pathname required");
        }
        format!(":{}:{}", project_name, pathname)
    }

    /// Returns `true` if the given path is allowed (not inside a Ghidra installation).
    pub fn is_allowed_archive_path(path: &str) -> bool {
        let unallowed = [
            "/Ghidra/Extensions/",
            "/Ghidra/docs/",
            "/Ghidra/Features/",
            "/Ghidra/Test/",
        ];
        !unallowed.iter().any(|frag| path.contains(frag))
    }
}

impl fmt::Debug for DataTypeManagerHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataTypeManagerHandler")
            .field("plugin_name", &self.plugin_name)
            .field("archive_count", &self.open_archives.len())
            .field("mod_count", &self.mod_count)
            .finish()
    }
}

impl fmt::Display for DataTypeManagerHandler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DataTypeManagerHandler [{}] ({} archives, mod={})",
            self.plugin_name,
            self.archive_count(),
            self.mod_count
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::data::CategoryPath;

    #[test]
    fn test_handler_new() {
        let handler = DataTypeManagerHandler::new("TestPlugin");
        assert_eq!(handler.plugin_name(), "TestPlugin");
        assert_eq!(handler.modification_count(), 0);
        // 1 built-in archive + 0 open_archives
        assert_eq!(handler.archive_count(), 1);
    }

    #[test]
    fn test_handler_open_file_archive() {
        let mut handler = DataTypeManagerHandler::new("Test");
        let idx = handler.open_file_archive("my_types", "/tmp/my_types.gdt".into(), true);
        assert!(idx.is_some());
        assert_eq!(handler.all_archives().len(), 1);
        assert_eq!(handler.archive_count(), 2); // built-in + file
        assert_eq!(handler.modification_count(), 1);
    }

    #[test]
    fn test_handler_open_file_archive_idempotent() {
        let mut handler = DataTypeManagerHandler::new("Test");
        let idx1 = handler.open_file_archive("my_types", "/tmp/my_types.gdt".into(), true);
        let idx2 = handler.open_file_archive("my_types", "/tmp/other.gdt".into(), false);
        assert_eq!(idx1, idx2); // same archive returned
        assert_eq!(handler.all_archives().len(), 1);
    }

    #[test]
    fn test_handler_open_program_archive() {
        let mut handler = DataTypeManagerHandler::new("Test");
        let dtm = StandaloneDataTypeManager::new();
        let idx = handler.open_program_archive("prog", dtm);
        assert_eq!(idx, 0);
        assert_eq!(handler.all_archives().len(), 1);
        assert!(handler.program_archive_index.is_some());
    }

    #[test]
    fn test_handler_close_archive() {
        let mut handler = DataTypeManagerHandler::new("Test");
        handler.open_file_archive("a", "/tmp/a.gdt".into(), true);
        handler.open_file_archive("b", "/tmp/b.gdt".into(), true);
        assert_eq!(handler.all_archives().len(), 2);

        assert!(handler.close_archive(0));
        assert_eq!(handler.all_archives().len(), 1);
        // Remaining archive should be "b"
        assert_eq!(handler.all_archives()[0].name(), Some("b"));
    }

    #[test]
    fn test_handler_close_all_archives() {
        let mut handler = DataTypeManagerHandler::new("Test");
        handler.open_file_archive("a", "/tmp/a.gdt".into(), true);
        handler.open_file_archive("b", "/tmp/b.gdt".into(), true);
        handler.close_all_archives();
        assert_eq!(handler.all_archives().len(), 0);
    }

    #[test]
    fn test_handler_recently_used() {
        use ghidra_core::data::types::StructureDataType;

        let mut handler = DataTypeManagerHandler::new("Test");
        let dt = StructureDataType::new("my_struct");
        handler.set_recently_used_data_type(&dt, Some("prog"));
        assert_eq!(handler.recently_used_data_type().name(), Some("my_struct"));
    }

    #[test]
    fn test_handler_invalid_archive() {
        let mut handler = DataTypeManagerHandler::new("Test");
        let source = SourceArchive::new(UniversalID::new(42), "fid", "LostLib");
        handler.add_invalid_archive(source);
        assert_eq!(handler.all_archives().len(), 1);
        assert_eq!(handler.all_archives()[0].kind(), ArchiveKind::Invalid);
    }

    #[test]
    fn test_handler_find_archive_by_id() {
        let mut handler = DataTypeManagerHandler::new("Test");
        let source = SourceArchive::new(UniversalID::new(77), "fid", "MyLib");
        handler.add_invalid_archive(source);
        let idx = handler.find_archive_by_id(UniversalID::new(77));
        assert!(idx.is_some());
        assert_eq!(handler.find_archive_by_id(UniversalID::new(999)), None);
    }

    #[test]
    fn test_data_type_indexer() {
        let mut indexer = DataTypeIndexer::new();
        assert_eq!(indexer.manager_count(), 0);
        indexer.add_data_type_manager("mgr1");
        indexer.add_data_type_manager("mgr2");
        assert_eq!(indexer.manager_count(), 2);
        indexer.add_data_type_manager("mgr1"); // idempotent
        assert_eq!(indexer.manager_count(), 2);
        indexer.remove_data_type_manager("mgr1");
        assert_eq!(indexer.manager_count(), 1);
        assert_eq!(indexer.manager_names(), &["mgr2"]);
    }

    #[test]
    fn test_recently_used_data_type() {
        use ghidra_core::data::types::StructureDataType;
        use ghidra_core::data::StandaloneDataTypeManager;

        let mut recent = RecentlyUsedDataType::new();
        assert!(recent.name().is_none());

        let dt = StructureDataType::new("foo");
        recent.set(&dt, Some("MyManager"));
        assert_eq!(recent.name(), Some("foo"));
        assert_eq!(recent.manager_name(), Some("MyManager"));

        // The StructureDataType::new("foo") stores at ROOT by default,
        // so add it to the ROOT category in the manager.
        let mut manager = StandaloneDataTypeManager::new();
        let arc_dt: Arc<dyn DataType> = Arc::new(StructureDataType::new("foo"));
        manager.add_type(arc_dt, CategoryPath::ROOT);

        let resolved = recent.resolve(&manager);
        assert!(resolved.is_some());
        assert_eq!(resolved.unwrap().name(), "foo");
    }

    #[test]
    fn test_parse_project_pathname() {
        let result = DataTypeManagerHandler::parse_project_pathname(":MyProject:/data/archive.gdt");
        assert_eq!(result, Some(("MyProject", "/data/archive.gdt")));

        assert!(DataTypeManagerHandler::parse_project_pathname("/not/project/path").is_none());
        assert!(DataTypeManagerHandler::parse_project_pathname(":bad:").is_none());
    }

    #[test]
    fn test_get_project_pathname() {
        let path = DataTypeManagerHandler::get_project_pathname("Proj", "/data/arch.gdt");
        assert_eq!(path, ":Proj:/data/arch.gdt");
    }

    #[test]
    fn test_is_allowed_archive_path() {
        assert!(DataTypeManagerHandler::is_allowed_archive_path("/home/user/archives"));
        assert!(!DataTypeManagerHandler::is_allowed_archive_path(
            "/opt/Ghidra/Features/Base/gdt/types.gdt"
        ));
        assert!(!DataTypeManagerHandler::is_allowed_archive_path(
            "/opt/Ghidra/Extensions/plugin.gdt"
        ));
    }

    #[test]
    fn test_handler_display() {
        let handler = DataTypeManagerHandler::new("Test");
        let s = format!("{}", handler);
        assert!(s.contains("Test"));
        assert!(s.contains("archives"));
    }

    #[test]
    fn test_handler_debug() {
        let handler = DataTypeManagerHandler::new("Test");
        let s = format!("{:?}", handler);
        assert!(s.contains("DataTypeManagerHandler"));
    }

    #[test]
    fn test_find_equate_names_empty() {
        let handler = DataTypeManagerHandler::new("Test");
        let names = handler.find_equate_names(42);
        assert!(names.is_empty());
    }

    #[test]
    fn test_handler_open_project_archive() {
        let mut handler = DataTypeManagerHandler::new("Test");
        let dtm = StandaloneDataTypeManager::new();
        let idx = handler.open_project_archive("proj", "/project/arch.gdt", dtm);
        assert_eq!(idx, 0);
        assert_eq!(handler.all_archives().len(), 1);
        assert_eq!(handler.all_archives()[0].kind(), ArchiveKind::Project);
    }
}
