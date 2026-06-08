//! File System Browser plugin.
//!
//! Ported from `ghidra.plugins.fsbrowser.FileSystemBrowserPlugin`.
//!
//! Provides the top-level plugin that manages filesystem browser windows,
//! handles opening filesystems from disk, and tracks active browser
//! component providers.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use super::{Fsrl, FileSystemRef, GFileSystem, FileSystemService};

// ---------------------------------------------------------------------------
// PluginState -- lifecycle state of the plugin
// ---------------------------------------------------------------------------

/// Lifecycle state of the filesystem browser plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginState {
    /// Plugin has not been initialized yet.
    Uninitialized,
    /// Plugin is active and ready.
    Active,
    /// Plugin has been disposed.
    Disposed,
}

// ---------------------------------------------------------------------------
// BrowserWindowInfo -- tracks an open browser window
// ---------------------------------------------------------------------------

/// Information about an open filesystem browser window.
#[derive(Debug, Clone)]
pub struct BrowserWindowInfo {
    /// Unique window identifier.
    pub window_id: u64,
    /// Title of the browser window.
    pub title: String,
    /// The filesystem reference this window is browsing.
    pub fs_ref: FileSystemRef,
    /// FSRL root URI of the filesystem.
    pub fsrl_root: String,
}

// ---------------------------------------------------------------------------
// FsBrowserPlugin -- the plugin itself
// ---------------------------------------------------------------------------

/// Plugin that provides filesystem browsing capabilities.
///
/// Manages open filesystem browser windows, handles opening new
/// filesystems, and tracks filesystem service integration.
///
/// Ported from `ghidra.plugins.fsbrowser.FileSystemBrowserPlugin`.
#[derive(Debug)]
pub struct FsBrowserPlugin {
    /// Plugin name.
    pub name: String,
    /// Current lifecycle state.
    pub state: PluginState,
    /// Filesystem service for mounting and managing filesystems.
    pub fs_service: FileSystemService,
    /// Currently open browser windows, keyed by window ID.
    pub open_browsers: HashMap<u64, BrowserWindowInfo>,
    /// Last directory the user browsed from.
    pub last_browse_dir: Option<PathBuf>,
    /// Last directory for exporting files.
    pub last_export_dir: Option<PathBuf>,
    /// Next window ID.
    next_window_id: u64,
}

impl FsBrowserPlugin {
    /// Plugin name constant.
    pub const PLUGIN_NAME: &'static str = "FileSystemBrowser";

    /// Create a new plugin instance.
    pub fn new() -> Self {
        Self {
            name: Self::PLUGIN_NAME.to_string(),
            state: PluginState::Uninitialized,
            fs_service: FileSystemService::new(),
            open_browsers: HashMap::new(),
            last_browse_dir: None,
            last_export_dir: None,
            next_window_id: 1,
        }
    }

    /// Initialize the plugin.
    pub fn init(&mut self) {
        self.state = PluginState::Active;
    }

    /// Dispose the plugin, closing all browser windows.
    pub fn dispose(&mut self) {
        self.open_browsers.clear();
        self.state = PluginState::Disposed;
    }

    /// Check if the plugin is active.
    pub fn is_active(&self) -> bool {
        self.state == PluginState::Active
    }

    /// Open a filesystem from a local file path.
    ///
    /// Returns the window ID of the new browser window, or an error
    /// if the file cannot be opened as a filesystem.
    pub fn open_filesystem_from_path(&mut self, path: &Path) -> Result<u64, String> {
        if !path.exists() {
            return Err(format!("File not found: {}", path.display()));
        }

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let fsrl = Fsrl::new(
            format!("file://{}", path.display()),
            &name,
        );

        // Create a simple filesystem representing the opened file
        let root = super::GFile::directory("/", Fsrl::new(format!("{}/", fsrl.uri), "/"));
        let fs = GFileSystem::new(fsrl.clone(), "Raw", root);
        let fs_ref = self.fs_service.mount(fs);

        self.open_filesystem(fs_ref, &name)
    }

    /// Open a filesystem browser window for an already-mounted filesystem.
    pub fn open_filesystem(
        &mut self,
        fs_ref: FileSystemRef,
        title: &str,
    ) -> Result<u64, String> {
        // Extract the fsrl_root URI before moving fs_ref into the info struct.
        let fsrl_root = {
            let fs = fs_ref
                .filesystem
                .read()
                .map_err(|e| format!("Failed to lock filesystem: {e}"))?;
            fs.fsrl_root.uri.clone()
        };

        let window_id = self.next_window_id;
        self.next_window_id += 1;

        let info = BrowserWindowInfo {
            window_id,
            title: title.to_string(),
            fs_ref,
            fsrl_root,
        };

        self.open_browsers.insert(window_id, info);
        Ok(window_id)
    }

    /// Close a browser window by ID.
    pub fn close_browser(&mut self, window_id: u64) -> bool {
        if let Some(info) = self.open_browsers.remove(&window_id) {
            let fsrl_root = info.fsrl_root.clone();
            let remaining = info.fs_ref.release();
            if remaining == 0 {
                let _ = self.fs_service.unmount(&fsrl_root);
            }
            true
        } else {
            false
        }
    }

    /// Get the number of open browser windows.
    pub fn open_browser_count(&self) -> usize {
        self.open_browsers.len()
    }

    /// Set the last browse directory.
    pub fn set_last_browse_dir(&mut self, dir: PathBuf) {
        self.last_browse_dir = Some(dir);
    }

    /// Set the last export directory.
    pub fn set_last_export_dir(&mut self, dir: PathBuf) {
        self.last_export_dir = Some(dir);
    }
}

impl Default for FsBrowserPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsbrowser::{GFile, Fsrl as FsrlType};

    fn make_test_fs() -> GFileSystem {
        let root = GFile::directory("/", FsrlType::new("testfs:/", "/"));
        GFileSystem::new(FsrlType::new("testfs:", "test.zip"), "ZIP", root)
    }

    #[test]
    fn test_plugin_lifecycle() {
        let mut plugin = FsBrowserPlugin::new();
        assert_eq!(plugin.state, PluginState::Uninitialized);
        assert!(!plugin.is_active());

        plugin.init();
        assert_eq!(plugin.state, PluginState::Active);
        assert!(plugin.is_active());

        plugin.dispose();
        assert_eq!(plugin.state, PluginState::Disposed);
        assert!(!plugin.is_active());
        assert_eq!(plugin.open_browser_count(), 0);
    }

    #[test]
    fn test_plugin_open_and_close_browser() {
        let mut plugin = FsBrowserPlugin::new();
        plugin.init();

        let fs = make_test_fs();
        let fs_ref = plugin.fs_service.mount(fs);

        let window_id = plugin.open_filesystem(fs_ref, "test.zip").unwrap();
        assert_eq!(plugin.open_browser_count(), 1);

        assert!(plugin.close_browser(window_id));
        assert_eq!(plugin.open_browser_count(), 0);

        // Closing non-existent window returns false
        assert!(!plugin.close_browser(999));
    }

    #[test]
    fn test_plugin_open_from_path_not_found() {
        let mut plugin = FsBrowserPlugin::new();
        plugin.init();

        let result = plugin.open_filesystem_from_path(Path::new("/nonexistent/file.zip"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("File not found"));
    }

    #[test]
    fn test_plugin_multiple_browsers() {
        let mut plugin = FsBrowserPlugin::new();
        plugin.init();

        let fs1 = make_test_fs();
        let fs2 = {
            let root = GFile::directory("/", FsrlType::new("tarfs:/", "/"));
            GFileSystem::new(FsrlType::new("tarfs:", "data.tar"), "TAR", root)
        };

        let ref1 = plugin.fs_service.mount(fs1);
        let ref2 = plugin.fs_service.mount(fs2);

        let w1 = plugin.open_filesystem(ref1, "test.zip").unwrap();
        let w2 = plugin.open_filesystem(ref2, "data.tar").unwrap();
        assert_ne!(w1, w2);
        assert_eq!(plugin.open_browser_count(), 2);

        plugin.close_browser(w1);
        assert_eq!(plugin.open_browser_count(), 1);

        plugin.dispose();
        assert_eq!(plugin.open_browser_count(), 0);
    }

    #[test]
    fn test_plugin_directory_tracking() {
        let mut plugin = FsBrowserPlugin::new();
        plugin.set_last_browse_dir(PathBuf::from("/tmp/import"));
        plugin.set_last_export_dir(PathBuf::from("/tmp/export"));

        assert_eq!(plugin.last_browse_dir, Some(PathBuf::from("/tmp/import")));
        assert_eq!(plugin.last_export_dir, Some(PathBuf::from("/tmp/export")));
    }
}
