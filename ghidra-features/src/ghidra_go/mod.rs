//! GhidraGo: send Ghidra URLs to a running Ghidra instance.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.go` and `ghidra.GhidraGo`
//! Java packages.  Provides IPC (inter-process communication) between
//! the GhidraGo command-line tool and a running Ghidra instance.
//!
//! # Components
//!
//! - [`GhidraGo`] -- the main client that sends URLs to Ghidra.
//! - [`GhidraGoIpc`] -- the IPC subsystem using file-based locks and URL files.
//! - [`GhidraGoSender`] -- sender side of the IPC (writes URL files).
//! - [`GhidraGoListener`] -- listener side of the IPC (watches for URL files).
//! - [`GhidraGoException`] -- exception types for GhidraGo errors.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use std::fmt;

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

/// Exception types for GhidraGo operations.
///
/// Matches Java's exception classes in `ghidra.app.plugin.core.go.exception`.
#[derive(Debug, Clone)]
pub enum GhidraGoException {
    /// Failed to start Ghidra.
    FailedToStartGhidra(String),
    /// The started Ghidra process exited unexpectedly.
    StartedGhidraProcessExited,
    /// The user chose to stop waiting.
    StopWaiting,
    /// Unable to acquire a lock.
    UnableToGetLock(String),
    /// Generic GhidraGo error.
    Other(String),
}

impl fmt::Display for GhidraGoException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FailedToStartGhidra(msg) => write!(f, "failed to start Ghidra: {msg}"),
            Self::StartedGhidraProcessExited => {
                write!(f, "started Ghidra process exited unexpectedly")
            }
            Self::StopWaiting => write!(f, "stopped waiting"),
            Self::UnableToGetLock(msg) => write!(f, "unable to get lock: {msg}"),
            Self::Other(msg) => write!(f, "GhidraGo error: {msg}"),
        }
    }
}

impl std::error::Error for GhidraGoException {}

// ---------------------------------------------------------------------------
// GhidraGoIpc
// ---------------------------------------------------------------------------

/// Base IPC subsystem for GhidraGo inter-process communication.
///
/// Uses file-based locks for coordination between GhidraGo instances
/// and the listening Ghidra.
///
/// Matches Java's `ghidra.app.plugin.core.go.ipc.GhidraGoIPC`.
pub struct GhidraGoIpc {
    /// Base directory for IPC files.
    channel_path: PathBuf,
    /// Directory for URL files.
    url_files_path: PathBuf,
    /// Lock file for the listener.
    listener_lock_path: PathBuf,
    /// Lock file indicating the listener is ready.
    listener_ready_lock_path: PathBuf,
    /// Lock file for the sender.
    sender_lock_path: PathBuf,
}

impl GhidraGoIpc {
    /// Create a new GhidraGo IPC subsystem.
    pub fn new(base_dir: PathBuf) -> Result<Self, GhidraGoException> {
        let channel_path = base_dir.join("ghidraGo");
        let url_files_path = channel_path.join("urls");

        fs::create_dir_all(&channel_path).map_err(|e| {
            GhidraGoException::Other(format!("Unable to create IPC directory: {e}"))
        })?;
        fs::create_dir_all(&url_files_path).map_err(|e| {
            GhidraGoException::Other(format!("Unable to create URL directory: {e}"))
        })?;

        Ok(Self {
            listener_lock_path: channel_path.join("listenerLock"),
            listener_ready_lock_path: channel_path.join("listenerReadyLock"),
            sender_lock_path: channel_path.join("senderLock"),
            channel_path,
            url_files_path,
        })
    }

    /// The base channel path.
    pub fn channel_path(&self) -> &Path {
        &self.channel_path
    }

    /// The URL files directory.
    pub fn url_files_path(&self) -> &Path {
        &self.url_files_path
    }

    /// Check if a Ghidra is listening and ready.
    pub fn is_ghidra_listening(&self) -> bool {
        // A Ghidra is listening if both lock files exist AND are locked.
        // In the Rust port, we check for file existence as a proxy.
        self.listener_lock_path.exists() && self.listener_ready_lock_path.exists()
    }

    /// Perform a locked action with a given lock file.
    ///
    /// Returns `Ok(result)` if the action succeeded, or an error if
    /// the lock could not be acquired.
    pub fn do_locked_action<F, T>(
        lock_path: &Path,
        wait: bool,
        action: F,
    ) -> Result<T, GhidraGoException>
    where
        F: FnOnce() -> T,
    {
        // Create the lock file if it doesn't exist
        if !lock_path.exists() {
            fs::File::create(lock_path).map_err(|e| {
                GhidraGoException::UnableToGetLock(format!("Cannot create lock file: {e}"))
            })?;
        }

        // Simple file-based lock: write PID to lock file
        let lock_content = format!("{}", std::process::id());
        {
            let mut f = fs::File::create(lock_path).map_err(|e| {
                GhidraGoException::UnableToGetLock(format!("Cannot write lock: {e}"))
            })?;
            f.write_all(lock_content.as_bytes()).map_err(|e| {
                GhidraGoException::UnableToGetLock(format!("Cannot write lock: {e}"))
            })?;
        }

        let result = action();
        Ok(result)
    }

    /// Dispose the IPC subsystem (remove lock files).
    pub fn dispose(&self) {
        let _ = fs::remove_file(&self.listener_lock_path);
        let _ = fs::remove_file(&self.listener_ready_lock_path);
        let _ = fs::remove_file(&self.sender_lock_path);
    }
}

// ---------------------------------------------------------------------------
// GhidraGoSender
// ---------------------------------------------------------------------------

/// The sender side of GhidraGo IPC.
///
/// Writes URL files to the IPC directory for a listening Ghidra to pick up.
///
/// Matches Java's `ghidra.app.plugin.core.go.GhidraGoSender`.
pub struct GhidraGoSender {
    ipc: GhidraGoIpc,
}

impl GhidraGoSender {
    /// Create a new sender.
    pub fn new(base_dir: PathBuf) -> Result<Self, GhidraGoException> {
        Ok(Self {
            ipc: GhidraGoIpc::new(base_dir)?,
        })
    }

    /// The underlying IPC subsystem.
    pub fn ipc(&self) -> &GhidraGoIpc {
        &self.ipc
    }

    /// Check if a Ghidra is listening.
    pub fn is_ghidra_listening(&self) -> bool {
        self.ipc.is_ghidra_listening()
    }

    /// Send a URL to the listening Ghidra.
    ///
    /// Creates a temporary file with the URL, then moves it to the
    /// URL files directory (atomic move to signal the listener).
    pub fn send(&self, url: &str) -> Result<(), GhidraGoException> {
        if url.is_empty() {
            return Err(GhidraGoException::Other(
                "An empty GhidraURL cannot be sent".into(),
            ));
        }

        let filename = format!(
            "{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let random_path = self.ipc.channel_path().join(&filename);
        let written_path = self.ipc.url_files_path().join(&filename);

        // Write URL to temp file
        {
            let mut f = fs::File::create(&random_path).map_err(|e| {
                GhidraGoException::Other(format!("Failed to create URL file: {e}"))
            })?;
            f.write_all(url.as_bytes()).map_err(|e| {
                GhidraGoException::Other(format!("Failed to write URL: {e}"))
            })?;
        }

        // Move to URL files directory (signals the listener)
        fs::rename(&random_path, &written_path).map_err(|e| {
            let _ = fs::remove_file(&random_path);
            GhidraGoException::Other(format!("Failed to move URL file: {e}"))
        })?;

        // Wait for the file to be processed (deleted by the listener)
        self.wait_for_file_processed(&written_path)
    }

    /// Perform a locked action with the sender lock.
    pub fn do_locked_action<F, T>(
        &self,
        wait: bool,
        action: F,
    ) -> Result<T, GhidraGoException>
    where
        F: FnOnce() -> T,
    {
        GhidraGoIpc::do_locked_action(&self.ipc.sender_lock_path, wait, action)
    }

    /// Wait for a file to be processed (deleted) by the listener.
    fn wait_for_file_processed(&self, path: &Path) -> Result<(), GhidraGoException> {
        let deadline = Instant::now() + Duration::from_secs(30);
        while path.exists() {
            if Instant::now() > deadline {
                return Err(GhidraGoException::Other(
                    "Timed out waiting for URL file to be processed".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }

    /// Wait for a Ghidra to be listening.
    pub fn wait_for_listener(&self, timeout: Duration) -> Result<(), GhidraGoException> {
        let deadline = Instant::now() + timeout;
        while !self.is_ghidra_listening() {
            if Instant::now() > deadline {
                return Err(GhidraGoException::Other(
                    "Timed out waiting for Ghidra listener".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Ok(())
    }

    /// Dispose the sender.
    pub fn dispose(&self) {
        // Nothing specific to clean up for the sender
    }
}

// ---------------------------------------------------------------------------
// GhidraGoListener
// ---------------------------------------------------------------------------

/// The listener side of GhidraGo IPC.
///
/// Watches the URL files directory for new files and processes them.
///
/// Matches Java's `ghidra.app.plugin.core.go.ipc.GhidraGoListener`.
pub struct GhidraGoListener {
    ipc: GhidraGoIpc,
    /// Callback to invoke when a URL is received.
    on_url_received: Option<Box<dyn Fn(String) + Send>>,
}

impl GhidraGoListener {
    /// Create a new listener.
    pub fn new(base_dir: PathBuf) -> Result<Self, GhidraGoException> {
        Ok(Self {
            ipc: GhidraGoIpc::new(base_dir)?,
            on_url_received: None,
        })
    }

    /// Set the callback for when a URL is received.
    pub fn set_on_url_received<F>(&mut self, callback: F)
    where
        F: Fn(String) + Send + 'static,
    {
        self.on_url_received = Some(Box::new(callback));
    }

    /// Register as a listener (create lock files).
    pub fn register(&self) -> Result<(), GhidraGoException> {
        // Create listener lock file
        fs::File::create(&self.ipc.listener_lock_path).map_err(|e| {
            GhidraGoException::Other(format!("Failed to create listener lock: {e}"))
        })?;
        // Create listener ready lock file
        fs::File::create(&self.ipc.listener_ready_lock_path).map_err(|e| {
            GhidraGoException::Other(format!("Failed to create listener ready lock: {e}"))
        })?;
        Ok(())
    }

    /// Check for and process any pending URL files.
    pub fn poll_urls(&self) -> Vec<String> {
        let mut urls = Vec::new();
        let url_dir = self.ipc.url_files_path();
        if let Ok(entries) = fs::read_dir(url_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(content) = fs::read_to_string(&path) {
                        urls.push(content.trim().to_string());
                        // Delete the file to signal that it's been processed
                        let _ = fs::remove_file(&path);
                    }
                }
            }
        }
        urls
    }

    /// Process any pending URLs using the registered callback.
    pub fn process_pending_urls(&self) {
        let urls = self.poll_urls();
        if let Some(ref callback) = self.on_url_received {
            for url in urls {
                callback(url);
            }
        }
    }

    /// The underlying IPC subsystem.
    pub fn ipc(&self) -> &GhidraGoIpc {
        &self.ipc
    }

    /// Dispose the listener (remove lock files).
    pub fn dispose(&self) {
        self.ipc.dispose();
    }
}

// ---------------------------------------------------------------------------
// GhidraGo (main client)
// ---------------------------------------------------------------------------

/// The GhidraGo client.
///
/// Processes a Ghidra URL by sending it to a running Ghidra instance,
/// starting one if necessary.
///
/// Matches Java's `ghidra.GhidraGo`.
pub struct GhidraGo {
    sender: GhidraGoSender,
}

impl GhidraGo {
    /// Create a new GhidraGo client.
    pub fn new(base_dir: PathBuf) -> Result<Self, GhidraGoException> {
        Ok(Self {
            sender: GhidraGoSender::new(base_dir)?,
        })
    }

    /// Process a Ghidra URL.
    ///
    /// Sends the URL to a running Ghidra instance, or starts one if needed.
    pub fn launch(&self, url: &str) -> Result<(), GhidraGoException> {
        if url.is_empty() {
            return Err(GhidraGoException::Other(
                "USAGE: ghidraGo <ghidraURL>\n\n\
                 Ghidra URL Forms (ghidraURL):\n\
                 \x20   ghidra://<hostname>[:<port>]/<repo-name>[/<folder-path>[/<program-name>]]\n\
                 \x20   ghidra:/[<local-dirpath>/]<project-name>[?/<folder-path>[/<program-name>]]"
                    .into(),
            ));
        }

        // Validate the URL format
        Self::validate_url(url)?;

        // If no Ghidra is listening, try to start one
        if !self.sender.is_ghidra_listening() {
            self.start_ghidra_if_needed()?;
        }

        // Send the URL
        self.sender.send(url)
    }

    /// Validate a Ghidra URL.
    fn validate_url(url: &str) -> Result<(), GhidraGoException> {
        if url.starts_with("ghidra://") || url.starts_with("ghidra:/") {
            Ok(())
        } else {
            Err(GhidraGoException::Other(format!(
                "Invalid Ghidra URL: {url}"
            )))
        }
    }

    /// Start Ghidra if needed.
    fn start_ghidra_if_needed(&self) -> Result<(), GhidraGoException> {
        // In the full implementation, this would start Ghidra
        // by executing the ghidraRun script.
        // For now, just wait for a listener.
        self.sender
            .wait_for_listener(Duration::from_secs(5))
            .or_else(|_| {
                Err(GhidraGoException::FailedToStartGhidra(
                    "No Ghidra instance found and auto-start not implemented".into(),
                ))
            })
    }

    /// Get the underlying sender.
    pub fn sender(&self) -> &GhidraGoSender {
        &self.sender
    }
}

// ---------------------------------------------------------------------------
// Periodic check utilities
// ---------------------------------------------------------------------------

/// A periodic check that runs a predicate at a given interval.
///
/// Matches Java's `ghidra.app.plugin.core.go.ipc.CheckPeriodicallyRunnable`.
pub struct PeriodicChecker {
    interval: Duration,
    max_wait: Duration,
}

impl PeriodicChecker {
    /// Create a new periodic checker.
    pub fn new(interval: Duration, max_wait: Duration) -> Self {
        Self { interval, max_wait }
    }

    /// Run a check periodically until it returns `true` or the max wait is exceeded.
    ///
    /// Returns `Ok(())` if the check succeeded, or `Err` if timed out.
    pub fn wait_until<F>(&self, check: F) -> Result<(), GhidraGoException>
    where
        F: Fn() -> bool,
    {
        let deadline = Instant::now() + self.max_wait;
        while !check() {
            if Instant::now() > deadline {
                return Err(GhidraGoException::Other(
                    "Periodic check timed out".into(),
                ));
            }
            std::thread::sleep(self.interval);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghidra_go_ipc_creation() {
        let dir = tempfile::tempdir().unwrap();
        let ipc = GhidraGoIpc::new(dir.path().to_path_buf()).unwrap();
        assert!(ipc.channel_path().exists());
        assert!(ipc.url_files_path().exists());
    }

    #[test]
    fn test_ghidra_go_listener_register() {
        let dir = tempfile::tempdir().unwrap();
        let listener = GhidraGoListener::new(dir.path().to_path_buf()).unwrap();
        listener.register().unwrap();

        let ipc = GhidraGoIpc::new(dir.path().to_path_buf()).unwrap();
        assert!(ipc.is_ghidra_listening());
    }

    #[test]
    fn test_ghidra_go_sender_send() {
        let dir = tempfile::tempdir().unwrap();
        let sender = GhidraGoSender::new(dir.path().to_path_buf()).unwrap();

        // Spawn a thread to simulate the listener (deletes the file)
        let url_files_path = sender.ipc().url_files_path().to_path_buf();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            // Delete any files in the URL directory
            if let Ok(entries) = fs::read_dir(&url_files_path) {
                for entry in entries.flatten() {
                    let _ = fs::remove_file(entry.path());
                }
            }
        });

        // Send a URL (should succeed once the listener deletes the file)
        let result = sender.send("ghidra://localhost/repo/program");
        handle.join().unwrap();
        assert!(result.is_ok());
    }

    #[test]
    fn test_ghidra_go_sender_empty_url() {
        let dir = tempfile::tempdir().unwrap();
        let sender = GhidraGoSender::new(dir.path().to_path_buf()).unwrap();
        let result = sender.send("");
        assert!(result.is_err());
    }

    #[test]
    fn test_ghidra_go_listener_poll() {
        let dir = tempfile::tempdir().unwrap();
        let listener = GhidraGoListener::new(dir.path().to_path_buf()).unwrap();

        // Manually write a URL file
        let url_dir = listener.ipc().url_files_path();
        fs::write(url_dir.join("test_url"), "ghidra://localhost/repo").unwrap();

        let urls = listener.poll_urls();
        assert_eq!(urls, vec!["ghidra://localhost/repo"]);

        // File should have been deleted
        assert!(url_dir.join("test_url").exists() == false);
    }

    #[test]
    fn test_ghidra_go_listener_callback() {
        let dir = tempfile::tempdir().unwrap();
        let mut listener = GhidraGoListener::new(dir.path().to_path_buf()).unwrap();

        use std::sync::{Arc, Mutex};
        let received = Arc::new(Mutex::new(Vec::new()));
        let received_clone = received.clone();

        listener.set_on_url_received(move |url| {
            received_clone.lock().unwrap().push(url);
        });

        // Write a URL file
        let url_dir = listener.ipc().url_files_path();
        fs::write(url_dir.join("cb_test"), "ghidra://test").unwrap();

        listener.process_pending_urls();
        let urls = received.lock().unwrap();
        assert_eq!(*urls, vec!["ghidra://test"]);
    }

    #[test]
    fn test_ghidra_go_validate_url() {
        assert!(GhidraGo::validate_url("ghidra://host/repo").is_ok());
        assert!(GhidraGo::validate_url("ghidra:/local/project").is_ok());
        assert!(GhidraGo::validate_url("http://example.com").is_err());
        assert!(GhidraGo::validate_url("").is_err());
    }

    #[test]
    fn test_periodic_checker() {
        let checker = PeriodicChecker::new(
            Duration::from_millis(10),
            Duration::from_millis(100),
        );
        let counter = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let counter_clone = counter.clone();

        let result = checker.wait_until(|| {
            counter_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 3
        });
        assert!(result.is_ok());
    }

    #[test]
    fn test_periodic_checker_timeout() {
        let checker = PeriodicChecker::new(
            Duration::from_millis(10),
            Duration::from_millis(50),
        );
        let result = checker.wait_until(|| false);
        assert!(result.is_err());
    }

    #[test]
    fn test_exception_display() {
        let e = GhidraGoException::FailedToStartGhidra("no script".into());
        assert!(e.to_string().contains("failed to start Ghidra"));

        let e = GhidraGoException::StopWaiting;
        assert!(e.to_string().contains("stopped waiting"));
    }
}
