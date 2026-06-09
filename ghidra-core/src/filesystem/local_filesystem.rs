//! Local filesystem implementation.
//!
//! Re-exports the local filesystem store types from
//! `crate::filesystem::store::local` and provides a [`LocalFileSystem`]
//! convenience facade that wraps the lower-level store implementations.
//!
//! Corresponds to `ghidra.framework.store.local.LocalFileSystem`.

// Re-export everything from the store local module.
pub use crate::filesystem::store::local::*;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::error::GhidraError;
use crate::filesystem::store::{
    DataFileItem, FolderItem, FileSystemStore, StoreResult, TextDataItem,
    SEPARATOR,
};
use crate::generic::task::TaskMonitor;

// ============================================================================
// LocalFileSystem – convenience wrapper
// ============================================================================

/// A convenience wrapper that operates on a local directory as a project
/// filesystem. Delegates to the underlying [`LocalFileSystemStore`] trait
/// implementation.
///
/// # Example
///
/// ```no_run
/// use ghidra_core::filesystem::local_filesystem::LocalFileSystem;
/// use std::path::PathBuf;
///
/// let fs = LocalFileSystem::open(PathBuf::from("/tmp/ghidra_project"))
///     .expect("failed to open local filesystem");
/// println!("User: {}", fs.user_name());
/// ```
pub struct LocalFileSystem {
    /// The root directory of this local filesystem.
    root_path: PathBuf,
    /// The user name associated with this filesystem.
    user: String,
    /// Tracked folders (path -> subfolder names).
    folders: Mutex<std::collections::HashMap<String, Vec<String>>>,
}

impl LocalFileSystem {
    /// Open or create a local filesystem at the given directory.
    pub fn open(root: PathBuf) -> StoreResult<Self> {
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            root_path: root,
            user: whoami::username(),
            folders: Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// Open a local filesystem with a specific user name.
    pub fn open_with_user(root: PathBuf, user: impl Into<String>) -> StoreResult<Self> {
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            root_path: root,
            user: user.into(),
            folders: Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// The root path of this local filesystem.
    pub fn root_path(&self) -> &Path {
        &self.root_path
    }

    /// Compute the full filesystem path for a logical folder path.
    fn resolve_path(&self, folder_path: &str) -> PathBuf {
        let clean = folder_path.trim_start_matches('/');
        if clean.is_empty() {
            self.root_path.clone()
        } else {
            self.root_path.join(clean)
        }
    }

    /// Compute the full filesystem path for a specific item.
    fn resolve_item_path(&self, folder_path: &str, item_name: &str) -> PathBuf {
        self.resolve_path(folder_path).join(item_name)
    }

    /// Scan the root directory and populate the folder map from disk.
    pub fn scan(&self) -> StoreResult<()> {
        let mut folders = self.folders.lock().unwrap();
        folders.clear();

        if !self.root_path.exists() {
            return Ok(());
        }

        // Add root entry
        folders.entry("".to_string()).or_default();
        folders.entry("/".to_string()).or_default();

        // Walk subdirectories
        self.scan_dir(&self.root_path, "", &mut folders)?;
        Ok(())
    }

    fn scan_dir(
        &self,
        dir: &Path,
        logical_path: &str,
        folders: &mut std::collections::HashMap<String, Vec<String>>,
    ) -> StoreResult<()> {
        let entries = std::fs::read_dir(dir)?;
        for entry in entries {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                // Skip hidden directories
                if name.starts_with('~') || name.starts_with('.') {
                    continue;
                }
                folders
                    .entry(logical_path.to_string())
                    .or_default()
                    .push(name.clone());

                let child_path = if logical_path.is_empty() {
                    name.clone()
                } else {
                    format!("{}{}{}", logical_path, SEPARATOR, name)
                };
                let child_fs_path = dir.join(&name);
                self.scan_dir(&child_fs_path, &child_path, folders)?;
            }
        }
        Ok(())
    }
}

impl FileSystemStore for LocalFileSystem {
    fn user_name(&self) -> &str {
        &self.user
    }

    fn item_count(&self) -> StoreResult<i32> {
        fn count_items(dir: &Path) -> StoreResult<i32> {
            let mut n = 0i32;
            if !dir.exists() {
                return Ok(0);
            }
            for entry in std::fs::read_dir(dir)? {
                let entry = entry?;
                let ft = entry.file_type()?;
                if ft.is_dir() {
                    n += count_items(&entry.path())?;
                } else if ft.is_file() {
                    n += 1;
                }
            }
            Ok(n)
        }
        let count = count_items(&self.root_path)?;
        Ok(count)
    }

    fn item_names(
        &self,
        folder_path: &str,
        _include_hidden: bool,
    ) -> StoreResult<Vec<String>> {
        let dir = self.resolve_path(folder_path);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let ft = entry.file_type()?;
            if ft.is_file() {
                let name = entry.file_name().to_string_lossy().to_string();
                // Skip property files and lock files
                if name.ends_with(".prp") || name.ends_with(".lock") {
                    continue;
                }
                names.push(name);
            }
        }
        Ok(names)
    }

    fn folder_names(&self, folder_path: &str) -> StoreResult<Vec<String>> {
        let dir = self.resolve_path(folder_path);
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let ft = entry.file_type()?;
            if ft.is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.starts_with('~') && !name.starts_with('.') {
                    names.push(name);
                }
            }
        }
        Ok(names)
    }

    fn get_items(
        &self,
        _folder_path: &str,
    ) -> StoreResult<Vec<Arc<Mutex<dyn FolderItem>>>> {
        // Items require property-file parsing; not implemented in this facade.
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
        let dir = self.resolve_item_path(parent_path, folder_name);
        if dir.exists() {
            return Err(GhidraError::InvalidData(format!(
                "Folder already exists: {}",
                dir.display()
            )));
        }
        std::fs::create_dir_all(&dir)?;
        Ok(())
    }

    fn delete_folder(&self, folder_path: &str) -> StoreResult<()> {
        let dir = self.resolve_path(folder_path);
        if !dir.exists() {
            return Err(GhidraError::NotFound(format!(
                "Folder not found: {}",
                dir.display()
            )));
        }
        // Check if empty (excluding hidden files)
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !name.starts_with('~') && !name.starts_with('.') {
                return Err(GhidraError::InvalidData(format!(
                    "Folder not empty: {}",
                    dir.display()
                )));
            }
        }
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }

    fn move_folder(
        &self,
        parent_path: &str,
        folder_name: &str,
        new_parent_path: &str,
    ) -> StoreResult<()> {
        let src = self.resolve_item_path(parent_path, folder_name);
        let dest = self.resolve_item_path(new_parent_path, folder_name);
        if !src.exists() {
            return Err(GhidraError::NotFound(format!(
                "Source folder not found: {}",
                src.display()
            )));
        }
        if dest.exists() {
            return Err(GhidraError::InvalidData(format!(
                "Destination already exists: {}",
                dest.display()
            )));
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(&src, &dest)?;
        Ok(())
    }

    fn rename_folder(
        &self,
        parent_path: &str,
        folder_name: &str,
        new_folder_name: &str,
    ) -> StoreResult<()> {
        let src = self.resolve_item_path(parent_path, folder_name);
        let dest = self.resolve_item_path(parent_path, new_folder_name);
        if !src.exists() {
            return Err(GhidraError::NotFound(format!(
                "Folder not found: {}",
                src.display()
            )));
        }
        if dest.exists() {
            return Err(GhidraError::InvalidData(format!(
                "Destination already exists: {}",
                dest.display()
            )));
        }
        std::fs::rename(&src, &dest)?;
        Ok(())
    }

    fn move_item(
        &self,
        parent_path: &str,
        name: &str,
        new_parent_path: &str,
        new_name: &str,
    ) -> StoreResult<()> {
        let src = self.resolve_item_path(parent_path, name);
        let dest = self.resolve_item_path(new_parent_path, new_name);
        if !src.exists() {
            return Err(GhidraError::NotFound(format!(
                "Source not found: {}",
                src.display()
            )));
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(&src, &dest)?;
        Ok(())
    }

    fn folder_exists(&self, folder_path: &str) -> StoreResult<bool> {
        let dir = self.resolve_path(folder_path);
        Ok(dir.exists() && dir.is_dir())
    }

    fn file_exists(&self, folder_path: &str, item_name: &str) -> StoreResult<bool> {
        let path = self.resolve_item_path(folder_path, item_name);
        Ok(path.exists() && path.is_file())
    }

    fn is_read_only(&self) -> bool {
        false
    }

    fn is_versioned(&self) -> bool {
        false
    }

    fn create_data_file(
        &self,
        parent_path: &str,
        name: &str,
        data: &[u8],
        _comment: &str,
        _content_type: &str,
        _monitor: &TaskMonitor,
    ) -> StoreResult<Arc<Mutex<dyn DataFileItem>>> {
        let path = self.resolve_item_path(parent_path, name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, data)?;
        Err(GhidraError::NotSupported(
            "LocalFileSystem::create_data_file returns stub; use store::local for full implementation".into(),
        ))
    }

    fn create_text_data_item(
        &self,
        parent_path: &str,
        name: &str,
        _file_id: Option<&str>,
        _content_type: &str,
        text_data: &str,
        _comment: &str,
        _user: &str,
    ) -> StoreResult<Arc<Mutex<dyn TextDataItem>>> {
        let path = self.resolve_item_path(parent_path, name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, text_data.as_bytes())?;
        Err(GhidraError::NotSupported(
            "LocalFileSystem::create_text_data_item returns stub; use store::local for full implementation".into(),
        ))
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

impl std::fmt::Debug for LocalFileSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalFileSystem")
            .field("root_path", &self.root_path)
            .field("user", &self.user)
            .finish()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_fs(name: &str) -> (LocalFileSystem, PathBuf) {
        let dir = std::env::temp_dir()
            .join("ghidra_test_local_fs")
            .join(name);
        let _ = std::fs::remove_dir_all(&dir);
        let fs = LocalFileSystem::open(dir.clone()).unwrap();
        (fs, dir)
    }

    fn cleanup(dir: &Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn test_open_and_root() {
        let (fs, dir) = make_test_fs("open_root");
        assert_eq!(fs.root_path(), dir.as_path());
        assert!(!fs.is_read_only());
        assert!(!fs.is_versioned());
        cleanup(&dir);
    }

    #[test]
    fn test_create_and_delete_folder() {
        let (fs, dir) = make_test_fs("create_delete");
        fs.create_folder("/", "my_folder").unwrap();
        assert!(fs.folder_exists("/my_folder").unwrap());
        assert_eq!(fs.folder_names("/").unwrap(), vec!["my_folder"]);

        fs.delete_folder("/my_folder").unwrap();
        assert!(!fs.folder_exists("/my_folder").unwrap());
        cleanup(&dir);
    }

    #[test]
    fn test_create_folder_duplicate() {
        let (fs, dir) = make_test_fs("dup_folder");
        fs.create_folder("/", "dup").unwrap();
        let result = fs.create_folder("/", "dup");
        assert!(result.is_err());
        cleanup(&dir);
    }

    #[test]
    fn test_rename_folder() {
        let (fs, dir) = make_test_fs("rename_folder");
        fs.create_folder("/", "old_name").unwrap();
        fs.rename_folder("/", "old_name", "new_name").unwrap();
        assert!(!fs.folder_exists("/old_name").unwrap());
        assert!(fs.folder_exists("/new_name").unwrap());
        cleanup(&dir);
    }

    #[test]
    fn test_move_folder() {
        let (fs, dir) = make_test_fs("move_folder");
        fs.create_folder("/", "src_dir").unwrap();
        fs.create_folder("/", "dest").unwrap();
        fs.move_folder("/", "src_dir", "/dest").unwrap();
        assert!(!fs.folder_exists("/src_dir").unwrap());
        assert!(fs.folder_exists("/dest/src_dir").unwrap());
        cleanup(&dir);
    }

    #[test]
    fn test_folder_names_empty() {
        let (fs, dir) = make_test_fs("empty_names");
        let names = fs.folder_names("/").unwrap();
        assert!(names.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_item_names_empty() {
        let (fs, dir) = make_test_fs("empty_items");
        let names = fs.item_names("/", false).unwrap();
        assert!(names.is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_user_name() {
        let (fs, dir) = make_test_fs("user_name");
        assert!(!fs.user_name().is_empty());
        cleanup(&dir);
    }

    #[test]
    fn test_open_with_user() {
        let dir = std::env::temp_dir()
            .join("ghidra_test_local_fs")
            .join("custom_user");
        let _ = std::fs::remove_dir_all(&dir);
        let fs = LocalFileSystem::open_with_user(dir.clone(), "custom_user").unwrap();
        assert_eq!(fs.user_name(), "custom_user");
        cleanup(&dir);
    }

    #[test]
    fn test_max_name_length() {
        let (fs, dir) = make_test_fs("max_name");
        assert_eq!(fs.max_name_length(), 200);
        cleanup(&dir);
    }

    #[test]
    fn test_debug_format() {
        let (fs, dir) = make_test_fs("debug_fmt");
        let dbg = format!("{:?}", fs);
        assert!(dbg.contains("LocalFileSystem"));
        assert!(dbg.contains("root_path"));
        cleanup(&dir);
    }

    #[test]
    fn test_file_exists() {
        let (fs, dir) = make_test_fs("file_exists");
        // Write a test file
        let path = dir.join("test_file.txt");
        std::fs::write(&path, b"hello").unwrap();
        assert!(fs.file_exists("/", "test_file.txt").unwrap());
        assert!(!fs.file_exists("/", "nonexistent.txt").unwrap());
        cleanup(&dir);
    }
}
