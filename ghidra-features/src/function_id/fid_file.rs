//! FID file management.
//!
//! Ported from Ghidra's `FidFile` and `FidFileManager` Java classes.
//!
//! Manages FID database files on disk: discovery, loading, and lifecycle.

use std::path::PathBuf;

/// Information about an FID database file on disk.
#[derive(Debug, Clone)]
pub struct FidFile {
    /// Path to the FID database file.
    pub path: PathBuf,
    /// Whether this FID file is enabled for matching.
    pub enabled: bool,
    /// Whether this is a system (built-in) FID file.
    pub is_system: bool,
    /// Human-readable name.
    pub name: String,
    /// Version string.
    pub version: String,
}

impl FidFile {
    /// Create a new FidFile descriptor.
    pub fn new(path: PathBuf, name: String) -> Self {
        Self {
            path,
            enabled: true,
            is_system: false,
            name,
            version: "1.0".to_string(),
        }
    }

    /// Check if the file exists on disk.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Get the file name.
    pub fn file_name(&self) -> Option<&str> {
        self.path.file_name().and_then(|n| n.to_str())
    }
}

/// Manager for discovering and loading FID database files.
#[derive(Debug)]
pub struct FidFileManager {
    /// Known FID files.
    fid_files: Vec<FidFile>,
    /// Search directories.
    search_dirs: Vec<PathBuf>,
}

impl FidFileManager {
    /// Create a new file manager.
    pub fn new() -> Self {
        Self {
            fid_files: Vec::new(),
            search_dirs: Vec::new(),
        }
    }

    /// Add a search directory.
    pub fn add_search_dir(&mut self, dir: PathBuf) {
        self.search_dirs.push(dir);
    }

    /// Register an FID file.
    pub fn add_fid_file(&mut self, fid_file: FidFile) {
        self.fid_files.push(fid_file);
    }

    /// Get all registered FID files.
    pub fn get_fid_files(&self) -> &[FidFile] {
        &self.fid_files
    }

    /// Get only enabled FID files.
    pub fn get_enabled_fid_files(&self) -> Vec<&FidFile> {
        self.fid_files.iter().filter(|f| f.enabled).collect()
    }

    /// Number of registered FID files.
    pub fn file_count(&self) -> usize {
        self.fid_files.len()
    }

    /// Find an FID file by name.
    pub fn find_by_name(&self, name: &str) -> Option<&FidFile> {
        self.fid_files.iter().find(|f| f.name == name)
    }
}

impl Default for FidFileManager {
    fn default() -> Self { Self::new() }
}

/// Listener for FID query close events.
pub trait FidQueryCloseListener {
    /// Called when the FID query is closed.
    fn on_close(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fid_file() {
        let f = FidFile::new(PathBuf::from("/tmp/test.fidb"), "test".into());
        assert_eq!(f.name, "test");
        assert!(f.enabled);
        assert!(!f.is_system);
        assert!(!f.exists());
    }

    #[test]
    fn test_fid_file_manager() {
        let mut mgr = FidFileManager::new();
        assert_eq!(mgr.file_count(), 0);
        mgr.add_fid_file(FidFile::new(PathBuf::from("/tmp/a.fidb"), "a".into()));
        mgr.add_fid_file(FidFile::new(PathBuf::from("/tmp/b.fidb"), "b".into()));
        assert_eq!(mgr.file_count(), 2);
        assert_eq!(mgr.get_enabled_fid_files().len(), 2);
        assert!(mgr.find_by_name("a").is_some());
        assert!(mgr.find_by_name("c").is_none());
    }

    #[test]
    fn test_fid_file_name() {
        let f = FidFile::new(PathBuf::from("/tmp/test.fidb"), "test".into());
        assert_eq!(f.file_name(), Some("test.fidb"));
    }
}
