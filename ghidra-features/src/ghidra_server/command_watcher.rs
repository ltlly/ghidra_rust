//! Command queue watcher for the Ghidra Server.
//!
//! Ported from `ghidra.server.CommandWatcher`.
//!
//! Watches the command queue directory for new command files and
//! initiates their processing.  Uses filesystem notifications (inotify
//! on Linux) to detect file creation events and invokes the repository
//! manager's command processing.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Command file extension used by the Ghidra Server.
const CMD_FILE_EXTENSION: &str = ".cmd";

/// Check whether a filename matches the command file pattern.
///
/// Matches Java's `CommandProcessor.CMD_FILE_FILTER`.
pub fn is_command_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|name| name.ends_with(CMD_FILE_EXTENSION))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// CommandWatcher
// ---------------------------------------------------------------------------

/// Watches a command directory for new command files and dispatches them
/// for processing.
///
/// Matches Java's `CommandWatcher`.  This implementation uses polling
/// with `std::fs::read_dir` since `notify` crate would add a dependency;
/// a production implementation would use `inotify` on Linux or `kqueue`
/// on macOS/BSD.
pub struct CommandWatcher {
    /// The directory being watched for command files.
    cmd_dir: PathBuf,
    /// Flag to signal the watcher to stop.
    running: Arc<AtomicBool>,
    /// Handle to the watcher thread.
    handle: Option<thread::JoinHandle<()>>,
}

impl CommandWatcher {
    /// Create a new `CommandWatcher` for the given command directory.
    ///
    /// # Arguments
    ///
    /// * `cmd_dir` -- the directory to watch for `.cmd` files.
    /// * `on_commands_found` -- callback invoked when new command files are detected.
    ///
    /// # Errors
    ///
    /// Returns `io::Error` if the directory cannot be read.
    pub fn new<F>(
        cmd_dir: PathBuf,
        on_commands_found: F,
    ) -> std::io::Result<Self>
    where
        F: Fn() + Send + 'static,
    {
        // Ensure the directory exists.
        if !cmd_dir.exists() {
            std::fs::create_dir_all(&cmd_dir)?;
        }

        let running = Arc::new(AtomicBool::new(true));
        let running_clone = running.clone();
        let dir_clone = cmd_dir.clone();

        let handle = thread::spawn(move || {
            Self::watch_loop(dir_clone, running_clone, on_commands_found);
        });

        Ok(Self {
            cmd_dir,
            running,
            handle: Some(handle),
        })
    }

    /// The watch loop that polls for new command files.
    fn watch_loop(
        cmd_dir: PathBuf,
        running: Arc<AtomicBool>,
        on_commands_found: impl Fn(),
    ) {
        log::info!("Command watcher started");

        // Track the last set of command files we've seen, so we only
        // trigger processing when new files appear.
        let mut last_seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();

        while running.load(Ordering::Relaxed) {
            // Scan for command files.
            let current_files = match std::fs::read_dir(&cmd_dir) {
                Ok(entries) => entries
                    .filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| is_command_file(p))
                    .collect::<std::collections::HashSet<_>>(),
                Err(e) => {
                    log::error!("Failed to read command directory: {e}");
                    thread::sleep(Duration::from_secs(1));
                    continue;
                }
            };

            // Check if there are new files.
            let has_new = current_files.iter().any(|f| !last_seen.contains(f));
            if has_new {
                on_commands_found();
            }

            last_seen = current_files;

            // Poll interval: 500ms (reasonable for command queue).
            thread::sleep(Duration::from_millis(500));
        }

        log::info!("Command watcher terminated.");
    }

    /// Return the command directory path.
    pub fn cmd_dir(&self) -> &Path {
        &self.cmd_dir
    }

    /// Stop the watcher thread.
    pub fn dispose(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for CommandWatcher {
    fn drop(&mut self) {
        self.dispose();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::AtomicU32;

    #[test]
    fn test_is_command_file() {
        assert!(is_command_file(Path::new("/tmp/0001.cmd")));
        assert!(is_command_file(Path::new("repo_12345.cmd")));
        assert!(!is_command_file(Path::new("/tmp/readme.txt")));
        assert!(!is_command_file(Path::new("/tmp/noext")));
    }

    #[test]
    fn test_command_watcher_detects_new_file() {
        let tmp = tempfile::tempdir().unwrap();
        let cmd_dir = tmp.path().join("commands");
        fs::create_dir_all(&cmd_dir).unwrap();

        let counter = Arc::new(AtomicU32::new(0));
        let counter_clone = counter.clone();
        let dir_clone = cmd_dir.clone();

        let mut watcher = CommandWatcher::new(cmd_dir.clone(), move || {
            counter_clone.fetch_add(1, Ordering::Relaxed);
        })
        .unwrap();

        // Give the watcher time to start.
        thread::sleep(Duration::from_millis(100));

        // Create a command file.
        fs::write(dir_clone.join("0001.cmd"), b"test").unwrap();

        // Wait for detection.
        thread::sleep(Duration::from_secs(1));

        assert!(counter.load(Ordering::Relaxed) > 0);
        watcher.dispose();
    }

    #[test]
    fn test_command_watcher_creates_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let cmd_dir = tmp.path().join("new_commands");
        assert!(!cmd_dir.exists());

        let mut watcher = CommandWatcher::new(cmd_dir.clone(), || {}).unwrap();
        assert!(cmd_dir.exists());
        watcher.dispose();
    }
}
