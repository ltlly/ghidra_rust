//! Project-level filesystem trait.
//!
//! Provides [`ProjectFileSystem`] which is the store-level filesystem abstraction
//! corresponding to `ghidra.framework.store.FileSystem`. This is distinct
//! from the binary-analysis `GFileSystem` trait (also named `FileSystem` in
//! this crate) that lives in the parent module.
//!
//! This module re-exports [`FileSystemStore`] from `crate::filesystem::store`
//! and adds a [`ProjectFileSystem`] trait plus convenience helpers for common
//! store-level filesystem operations such as creating, moving, and deleting
//! files and folders.
//!
//! Also provides [`normalize_path`] for normalizing absolute store paths
//! (handling `.` and `..` segments), corresponding to the Java
//! `FileSystem.normalizePath()` static method.

use std::sync::{Arc, Mutex};

use crate::error::GhidraError;
use crate::filesystem::store::{
    DataFileItem, FileSystemStore, StoreResult, TextDataItem,
};
use crate::generic::task::TaskMonitor;

// ============================================================================
// Result alias
// ============================================================================

/// Result type for project-level filesystem operations.
pub type FsStoreResult<T> = Result<T, GhidraError>;

// ============================================================================
// Path normalization
// ============================================================================

/// Normalize an absolute store path, resolving `.` and `..` segments.
///
/// The path must start with `SEPARATOR` (`'/'`).  Segments of `".."` remove
/// the previous segment.  Segments of `"."` are ignored.  Empty segments
/// (from `"//"`) cause an error.
///
/// Corresponds to `ghidra.framework.store.FileSystem.normalizePath()`.
///
/// # Errors
/// Returns [`GhidraError::InvalidData`] if:
/// - the path does not start with `'/'`
/// - a `".."` would escape above the root
/// - the path contains an empty element (i.e., `"//"`)
pub fn normalize_path(path: &str) -> Result<String, GhidraError> {
    use crate::filesystem::store::SEPARATOR;

    if !path.starts_with(SEPARATOR) {
        return Err(GhidraError::InvalidData(format!(
            "Absolute path required: {}",
            path
        )));
    }

    let split: Vec<&str> = path.split(SEPARATOR).collect();
    let mut elements: Vec<String> = Vec::new();
    elements.push(SEPARATOR.to_string());

    for (i, e) in split.iter().enumerate().skip(1) {
        if e.is_empty() {
            return Err(GhidraError::InvalidData(format!(
                "Invalid path with empty element: {}",
                path
            )));
        }
        if *e == ".." {
            elements.pop();
            if elements.is_empty() {
                return Err(GhidraError::InvalidData(format!(
                    "Invalid path: {}",
                    path
                )));
            }
        } else if *e == "." {
            continue;
        } else {
            if i < split.len() - 1 {
                elements.push(format!("{}{}", e, SEPARATOR));
            } else {
                elements.push(e.to_string());
            }
        }
    }

    if elements.is_empty() {
        return Ok(SEPARATOR.to_string());
    }

    let mut buf = String::new();
    for e in &elements {
        buf.push_str(e);
    }
    if path.ends_with(SEPARATOR) {
        buf.push_str(SEPARATOR);
    }
    Ok(buf)
}

// ============================================================================
// ProjectFileSystem trait
// ============================================================================

/// A convenience alias for the store-level filesystem trait.
///
/// All project-level filesystem implementations should implement
/// [`FileSystemStore`], which this trait extends with additional
/// convenience methods.
///
/// Corresponds to `ghidra.framework.store.FileSystem`.
pub trait ProjectFileSystem: FileSystemStore {
    /// Returns true if this filesystem supports shared access.
    fn is_shared(&self) -> bool {
        false
    }

    /// Returns true if the filesystem is online / accessible.
    ///
    /// Default returns `true`.  Remote filesystems may override to return
    /// `false` when the server is unreachable.
    fn is_online(&self) -> bool {
        true
    }

    /// Returns true if the filesystem is empty (contains no items at all).
    fn is_empty(&self) -> StoreResult<bool> {
        Ok(self.item_count()? == 0)
    }

    /// Create a subfolder at the given parent path, returning the full path.
    fn create_subfolder(
        &self,
        parent_path: &str,
        folder_name: &str,
    ) -> StoreResult<String> {
        self.create_folder(parent_path, folder_name)?;
        let sep = crate::filesystem::store::SEPARATOR;
        let full = if parent_path.ends_with(sep) {
            format!("{}{}", parent_path, folder_name)
        } else {
            format!("{}{}{}", parent_path, sep, folder_name)
        };
        Ok(full)
    }

    /// Recursively delete a folder and all its contents.
    fn delete_folder_recursive(&self, folder_path: &str) -> StoreResult<()> {
        // Delete child items first
        let items = self.get_items(folder_path)?;
        for item_arc in &items {
            let mut item = item_arc.lock().unwrap();
            item.delete(crate::filesystem::store::LATEST_VERSION, "")?;
        }

        // Delete child folders
        let subfolders = self.folder_names(folder_path)?;
        for subfolder in &subfolders {
            let subfolder_path = format!(
                "{}{}{}",
                folder_path,
                if folder_path.ends_with('/') { "" } else { "/" },
                subfolder
            );
            self.delete_folder_recursive(&subfolder_path)?;
        }

        self.delete_folder(folder_path)?;
        Ok(())
    }

    /// Create a data file with byte content.
    fn create_data(
        &self,
        parent_path: &str,
        name: &str,
        data: &[u8],
        content_type: &str,
        monitor: &TaskMonitor,
    ) -> StoreResult<Arc<Mutex<dyn DataFileItem>>> {
        self.create_data_file(parent_path, name, data, "", content_type, monitor)
    }

    /// Create a text data item.
    fn create_text(
        &self,
        parent_path: &str,
        name: &str,
        content_type: &str,
        text_data: &str,
    ) -> StoreResult<Arc<Mutex<dyn TextDataItem>>> {
        self.create_text_data_item(parent_path, name, None, content_type, text_data, "", "")
    }

    /// Check if a specific item exists by path and name.
    fn has_item(&self, folder_path: &str, name: &str) -> StoreResult<bool> {
        self.file_exists(folder_path, name)
    }

    /// Get all item names in a folder, excluding hidden items.
    fn visible_item_names(&self, folder_path: &str) -> StoreResult<Vec<String>> {
        self.item_names(folder_path, false)
    }

    /// Get all item names in a folder, including hidden items.
    fn all_item_names(&self, folder_path: &str) -> StoreResult<Vec<String>> {
        self.item_names(folder_path, true)
    }

    /// Move an item to a new folder with the same name.
    fn move_item_to_folder(
        &self,
        parent_path: &str,
        name: &str,
        new_parent_path: &str,
    ) -> StoreResult<()> {
        self.move_item(parent_path, name, new_parent_path, name)
    }
}

// Blanket implementation: any FileSystemStore automatically gets ProjectFileSystem.
impl<T: FileSystemStore + ?Sized> ProjectFileSystem for T {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem::store::FolderItem;
    use std::collections::HashMap;

    /// A minimal mock filesystem for testing.
    struct MockFs {
        folders: Mutex<HashMap<String, Vec<String>>>,
        items: Mutex<HashMap<String, Vec<String>>>,
    }

    impl MockFs {
        fn new() -> Self {
            Self {
                folders: Mutex::new(HashMap::new()),
                items: Mutex::new(HashMap::new()),
            }
        }
    }

    impl FileSystemStore for MockFs {
        fn user_name(&self) -> &str {
            "test"
        }
        fn item_count(&self) -> StoreResult<i32> {
            Ok(0)
        }
        fn item_names(
            &self,
            _folder_path: &str,
            _include_hidden: bool,
        ) -> StoreResult<Vec<String>> {
            Ok(Vec::new())
        }
        fn folder_names(&self, folder_path: &str) -> StoreResult<Vec<String>> {
            Ok(self
                .folders
                .lock()
                .unwrap()
                .get(folder_path)
                .cloned()
                .unwrap_or_default())
        }
        fn get_items(
            &self,
            _folder_path: &str,
        ) -> StoreResult<Vec<Arc<Mutex<dyn FolderItem>>>> {
            Ok(Vec::new())
        }
        fn get_item(
            &self,
            _folder_path: &str,
            _name: &str,
        ) -> StoreResult<Option<Arc<Mutex<dyn FolderItem>>>> {
            Ok(None)
        }
        fn get_item_by_id(
            &self,
            _file_id: &str,
        ) -> StoreResult<Option<Arc<Mutex<dyn FolderItem>>>> {
            Ok(None)
        }
        fn max_name_length(&self) -> usize {
            200
        }
        fn create_folder(&self, parent_path: &str, folder_name: &str) -> StoreResult<()> {
            let key = parent_path.to_string();
            self.folders
                .lock()
                .unwrap()
                .entry(key)
                .or_default()
                .push(folder_name.to_string());
            Ok(())
        }
        fn delete_folder(&self, _folder_path: &str) -> StoreResult<()> {
            Ok(())
        }
        fn move_folder(
            &self,
            _parent_path: &str,
            _folder_name: &str,
            _new_parent_path: &str,
        ) -> StoreResult<()> {
            Ok(())
        }
        fn rename_folder(
            &self,
            _parent_path: &str,
            _folder_name: &str,
            _new_folder_name: &str,
        ) -> StoreResult<()> {
            Ok(())
        }
        fn move_item(
            &self,
            _parent_path: &str,
            _name: &str,
            _new_parent_path: &str,
            _new_name: &str,
        ) -> StoreResult<()> {
            Ok(())
        }
        fn folder_exists(&self, folder_path: &str) -> StoreResult<bool> {
            Ok(self.folders.lock().unwrap().contains_key(folder_path))
        }
        fn file_exists(&self, _folder_path: &str, _item_name: &str) -> StoreResult<bool> {
            Ok(false)
        }
        fn is_read_only(&self) -> bool {
            false
        }
        fn is_versioned(&self) -> bool {
            false
        }
        fn create_data_file(
            &self,
            _parent_path: &str,
            _name: &str,
            _data: &[u8],
            _comment: &str,
            _content_type: &str,
            _monitor: &TaskMonitor,
        ) -> StoreResult<Arc<Mutex<dyn DataFileItem>>> {
            Err(GhidraError::NotSupported("mock".into()))
        }
        fn create_text_data_item(
            &self,
            _parent_path: &str,
            _name: &str,
            _file_id: Option<&str>,
            _content_type: &str,
            _text_data: &str,
            _comment: &str,
            _user: &str,
        ) -> StoreResult<Arc<Mutex<dyn TextDataItem>>> {
            Err(GhidraError::NotSupported("mock".into()))
        }
        fn is_supported_item_type(&self, _file_type: i32) -> bool {
            true
        }
        fn dispose(&mut self) -> StoreResult<()> {
            Ok(())
        }
        fn migration_in_progress(&self) -> bool {
            false
        }
    }

    #[test]
    fn test_project_filesystem_create_subfolder() {
        let fs = MockFs::new();
        let result = fs.create_subfolder("/", "my_folder");
        assert_eq!(result.unwrap(), "/my_folder");
    }

    #[test]
    fn test_project_filesystem_create_subfolder_trailing_slash() {
        let fs = MockFs::new();
        let result = fs.create_subfolder("/parent/", "child");
        assert_eq!(result.unwrap(), "/parent/child");
    }

    #[test]
    fn test_project_filesystem_is_empty() {
        let fs = MockFs::new();
        assert!(fs.is_empty().unwrap());
    }

    #[test]
    fn test_project_filesystem_is_shared_default() {
        let fs = MockFs::new();
        assert!(!fs.is_shared());
    }

    #[test]
    fn test_project_filesystem_is_online_default() {
        let fs = MockFs::new();
        assert!(fs.is_online());
    }

    #[test]
    fn test_project_filesystem_visible_item_names() {
        let fs = MockFs::new();
        let names = fs.visible_item_names("/").unwrap();
        assert!(names.is_empty());
    }

    // ------------------------------------------------------------------
    // normalize_path tests
    // ------------------------------------------------------------------

    #[test]
    fn test_normalize_path_simple() {
        assert_eq!(normalize_path("/a/b/c").unwrap(), "/a/b/c");
    }

    #[test]
    fn test_normalize_path_dot_dot() {
        assert_eq!(normalize_path("/a/b/../c").unwrap(), "/a/c");
    }

    #[test]
    fn test_normalize_path_dot() {
        assert_eq!(normalize_path("/a/./b").unwrap(), "/a/b");
    }

    #[test]
    fn test_normalize_path_trailing_slash() {
        assert_eq!(normalize_path("/a/b/").unwrap(), "/a/b/");
    }

    #[test]
    fn test_normalize_path_root_only() {
        assert_eq!(normalize_path("/").unwrap(), "/");
    }

    #[test]
    fn test_normalize_path_not_absolute() {
        assert!(normalize_path("a/b").is_err());
    }

    #[test]
    fn test_normalize_path_empty_element() {
        assert!(normalize_path("/a//b").is_err());
    }

    #[test]
    fn test_normalize_path_escape_root() {
        assert!(normalize_path("/../a").is_err());
    }

    #[test]
    fn test_normalize_path_complex() {
        assert_eq!(
            normalize_path("/a/b/c/../../d").unwrap(),
            "/a/d"
        );
    }
}
