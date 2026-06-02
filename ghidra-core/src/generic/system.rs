//! System/host information for runtime feature detection.
//!
//! Corresponds to Ghidra's `SystemUtilities` class, providing OS detection,
//! CPU info, and environment properties.

use std::io;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// SystemInfo
// ---------------------------------------------------------------------------

/// System/host information used for runtime feature detection.
#[derive(Debug, Clone)]
pub struct SystemInfo {
    /// Operating system name ("linux", "windows", "macos").
    pub os_name: String,
    /// OS version string.
    pub os_version: String,
    /// CPU architecture ("x86_64", "aarch64", etc.).
    pub arch: String,
    /// Number of logical CPUs.
    pub cpu_count: usize,
    /// Total physical memory in bytes (0 if unavailable).
    pub total_memory: u64,
    /// Whether the platform is big-endian.
    pub is_big_endian: bool,
    /// Page size in bytes.
    pub page_size: usize,
    /// Whether running in headless mode.
    pub headless: bool,
    /// Whether running in testing mode.
    pub testing: bool,
    /// Whether running in development mode.
    pub development: bool,
}

impl Default for SystemInfo {
    fn default() -> Self {
        Self::detect()
    }
}

impl SystemInfo {
    /// Auto-detect system properties at runtime.
    pub fn detect() -> Self {
        Self {
            os_name: std::env::consts::OS.to_string(),
            os_version: detect_os_version(),
            arch: std::env::consts::ARCH.to_string(),
            cpu_count: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            total_memory: detect_total_memory(),
            is_big_endian: !cfg!(target_endian = "little"),
            page_size: Self::detect_page_size(),
            headless: Self::check_headless(),
            testing: Self::check_testing(),
            development: Self::check_development(),
        }
    }

    /// Returns `true` when running on a little-endian host.
    pub fn is_little_endian(&self) -> bool {
        !self.is_big_endian
    }

    /// Returns `true` when running on Linux.
    pub fn is_linux(&self) -> bool {
        self.os_name == "linux"
    }

    /// Returns `true` when running on Windows.
    pub fn is_windows(&self) -> bool {
        self.os_name == "windows"
    }

    /// Returns `true` when running on macOS.
    pub fn is_macos(&self) -> bool {
        self.os_name == "macos"
    }

    /// Returns `true` when the host architecture is 64-bit.
    pub fn is_64bit(&self) -> bool {
        self.arch.contains("64")
    }

    /// Returns `true` when running in headless mode.
    pub fn is_headless(&self) -> bool {
        self.headless
    }

    /// Returns `true` when running in testing mode.
    pub fn is_testing(&self) -> bool {
        self.testing
    }

    /// Returns `true` when running in development mode.
    pub fn is_development(&self) -> bool {
        self.development
    }

    /// Returns `true` when running in release mode.
    pub fn is_release(&self) -> bool {
        !self.development && !self.testing
    }

    /// Returns the default thread pool size for CPU-bound work.
    /// Based on available processors + 1, capped at 11.
    pub fn default_thread_pool_size(&self) -> usize {
        let cpu_count = self.cpu_count.max(1);
        let base = (cpu_count + 1).min(11);
        match std::env::var("cpu_core_override").ok().and_then(|s| s.parse::<usize>().ok()) {
            Some(n) => n.max(1),
            None => {
                let limit = std::env::var("cpu_core_limit")
                    .ok()
                    .and_then(|s| s.parse::<usize>().ok())
                    .unwrap_or(usize::MAX);
                base.min(limit.max(1) + 1)
            }
        }
    }

    /// Get the current user name.
    pub fn user_name() -> String {
        static USER_NAME: OnceLock<String> = OnceLock::new();
        USER_NAME
            .get_or_init(|| {
                let name = whoami::username();
                clean_user_name(&name)
            })
            .clone()
    }

    /// Get the current host name.
    pub fn host_name() -> String {
        whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string())
    }

    fn check_headless() -> bool {
        std::env::var("SYSTEM_UTILITIES_IS_HEADLESS")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(true) // Default to headless for server environments
    }

    fn check_testing() -> bool {
        std::env::var("SYSTEM_UTILITIES_IS_TESTING")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false)
    }

    fn check_development() -> bool {
        // In Rust, development mode is typically indicated by debug_assertions
        cfg!(debug_assertions) ||
        std::env::var("GHIDRA_DEV_MODE")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(false)
    }

    #[cfg(unix)]
    fn detect_page_size() -> usize {
        unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
    }

    #[cfg(windows)]
    fn detect_page_size() -> usize {
        4096
    }

    #[cfg(not(any(unix, windows)))]
    fn detect_page_size() -> usize {
        4096
    }
}

// ---------------------------------------------------------------------------
// Memory information
// ---------------------------------------------------------------------------

/// Detailed memory information for the host system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryInfo {
    /// Total physical memory in bytes (0 if unavailable).
    pub total: u64,
    /// Available/free physical memory in bytes (0 if unavailable).
    pub available: u64,
    /// Used physical memory in bytes.
    pub used: u64,
    /// Total swap memory in bytes (0 if unavailable).
    pub swap_total: u64,
    /// Available swap memory in bytes (0 if unavailable).
    pub swap_free: u64,
    /// Page size in bytes.
    pub page_size: usize,
}

impl MemoryInfo {
    /// Detect memory information for the current system.
    pub fn detect() -> Self {
        Self {
            total: detect_total_memory(),
            available: detect_available_memory(),
            used: 0,
            swap_total: detect_swap_total(),
            swap_free: detect_swap_free(),
            page_size: SystemInfo::detect_page_size(),
        }
    }

    /// Percentage of physical memory used (0.0 to 100.0).
    pub fn usage_percent(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let used = self.used.max(self.total.saturating_sub(self.available));
        ((used as f64 / self.total as f64) * 100.0).clamp(0.0, 100.0)
    }

    /// Returns `true` when swap is enabled and has non-zero capacity.
    pub fn has_swap(&self) -> bool {
        self.swap_total > 0
    }

    /// Percentage of swap used (0.0 to 100.0).
    pub fn swap_usage_percent(&self) -> f64 {
        if self.swap_total == 0 {
            return 0.0;
        }
        let swap_used = self.swap_total.saturating_sub(self.swap_free);
        ((swap_used as f64 / self.swap_total as f64) * 100.0).clamp(0.0, 100.0)
    }
}

impl SystemInfo {
    /// Get detailed memory information for the current system.
    pub fn memory_info(&self) -> MemoryInfo {
        MemoryInfo::detect()
    }

    /// Returns `true` when the system has sufficient memory for Ghidra analysis.
    pub fn has_sufficient_memory(&self, min_required_bytes: u64) -> bool {
        let mem = self.memory_info();
        if mem.total == 0 {
            return true; // Cannot determine, assume sufficient
        }
        mem.available >= min_required_bytes.min(mem.total / 4)
    }

    /// Approximate memory available for new allocations in bytes.
    pub fn available_memory(&self) -> u64 {
        let mem = self.memory_info();
        if mem.available > 0 {
            mem.available
        } else {
            // Fallback: 75% of total
            mem.total * 3 / 4
        }
    }
}

#[cfg(target_os = "linux")]
fn detect_available_memory() -> u64 {
    use std::fs;
    if let Ok(contents) = fs::read_to_string("/proc/meminfo") {
        for line in contents.lines() {
            if line.starts_with("MemAvailable:") {
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = kb_str.parse::<u64>() {
                        return kb * 1024;
                    }
                }
            }
        }
        // Fallback: MemFree + Buffers + Cached
        let mut free = 0u64;
        let mut buffers = 0u64;
        let mut cached = 0u64;
        for line in contents.lines() {
            if line.starts_with("MemFree:") {
                free = line.split_whitespace().nth(1)
                    .and_then(|s| s.parse().ok()).unwrap_or(0) * 1024;
            }
            if line.starts_with("Buffers:") {
                buffers = line.split_whitespace().nth(1)
                    .and_then(|s| s.parse().ok()).unwrap_or(0) * 1024;
            }
            if line.starts_with("Cached:") {
                cached = line.split_whitespace().nth(1)
                    .and_then(|s| s.parse().ok()).unwrap_or(0) * 1024;
            }
        }
        free + buffers + cached
    } else {
        0
    }
}

#[cfg(not(target_os = "linux"))]
fn detect_available_memory() -> u64 { 0 }

#[cfg(target_os = "linux")]
fn detect_swap_total() -> u64 {
    use std::fs;
    if let Ok(contents) = fs::read_to_string("/proc/meminfo") {
        for line in contents.lines() {
            if line.starts_with("SwapTotal:") {
                return line.split_whitespace().nth(1)
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|kb| kb * 1024)
                    .unwrap_or(0);
            }
        }
    }
    0
}

#[cfg(not(target_os = "linux"))]
fn detect_swap_total() -> u64 { 0 }

#[cfg(target_os = "linux")]
fn detect_swap_free() -> u64 {
    use std::fs;
    if let Ok(contents) = fs::read_to_string("/proc/meminfo") {
        for line in contents.lines() {
            if line.starts_with("SwapFree:") {
                return line.split_whitespace().nth(1)
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|kb| kb * 1024)
                    .unwrap_or(0);
            }
        }
    }
    0
}

#[cfg(not(target_os = "linux"))]
fn detect_swap_free() -> u64 { 0 }

// ---------------------------------------------------------------------------
// File utility functions (freestanding, convenience wrappers)
// ---------------------------------------------------------------------------

/// Read the entire contents of a file into a `String`.
///
/// Returns an error if the file does not exist or cannot be read.
pub fn read_file(path: &std::path::Path) -> io::Result<String> {
    std::fs::read_to_string(path)
}

/// Write a string to a file, creating it if necessary.
///
/// Returns an error if the file cannot be written.
pub fn write_file(path: &std::path::Path, contents: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, contents)
}

/// Check whether a file exists at the given path.
pub fn file_exists(path: &std::path::Path) -> bool {
    path.is_file()
}

/// Check whether a directory exists at the given path.
pub fn is_directory(path: &std::path::Path) -> bool {
    path.is_dir()
}

/// List all entries (files and subdirectories) in a directory.
///
/// Returns an empty vector if the path is not a directory or cannot be read.
pub fn list_directory(path: &std::path::Path) -> io::Result<Vec<std::path::PathBuf>> {
    let mut entries = Vec::new();
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            entries.push(entry?.path());
        }
    }
    Ok(entries)
}

/// List only files (excluding subdirectories) in a directory.
pub fn list_files(path: &std::path::Path) -> io::Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                files.push(entry.path());
            }
        }
    }
    Ok(files)
}

/// Recursively list all files in a directory tree.
pub fn list_files_recursive(path: &std::path::Path) -> io::Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let entry_path = entry.path();
            if entry.file_type()?.is_dir() {
                files.extend(list_files_recursive(&entry_path)?);
            } else {
                files.push(entry_path);
            }
        }
    }
    Ok(files)
}

/// Delete a file at the given path. Returns `true` if the file was deleted
/// or did not exist; returns `false` on error.
pub fn delete_file(path: &std::path::Path) -> bool {
    if !path.exists() {
        return true;
    }
    std::fs::remove_file(path).is_ok()
}

/// Create a directory at the given path, including all parent directories.
pub fn create_directory(path: &std::path::Path) -> io::Result<()> {
    std::fs::create_dir_all(path)
}

/// Alias for [`create_directory`] that matches Ghidra's naming convention.
pub fn create_directories(path: &std::path::Path) -> io::Result<()> {
    create_directory(path)
}

/// Read all bytes from a file at the given path.
///
/// Returns the raw bytes or an I/O error.
pub fn read_all_bytes(path: &std::path::Path) -> io::Result<Vec<u8>> {
    std::fs::read(path)
}

/// Write all bytes to a file, creating it if necessary.
///
/// Creates parent directories automatically.
pub fn write_all_bytes(path: &std::path::Path, data: &[u8]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, data)
}

/// Check whether any filesystem entry exists at the given path.
pub fn exists(path: &std::path::Path) -> bool {
    path.exists()
}

/// Return the size of a file in bytes.
///
/// Returns `None` if the path does not exist, is a directory, or the
/// metadata cannot be read.
pub fn get_file_size(path: &std::path::Path) -> Option<u64> {
    path.metadata().ok().filter(|m| m.is_file()).map(|m| m.len())
}

/// Return the last modification time of a file as a [`SystemTime`].
///
/// Returns `None` if the path does not exist or metadata cannot be read.
pub fn get_last_modified(path: &std::path::Path) -> Option<std::time::SystemTime> {
    path.metadata().ok().and_then(|m| m.modified().ok())
}

/// Return the last modification time as a Unix timestamp (seconds since
/// epoch).
pub fn get_last_modified_unix(path: &std::path::Path) -> Option<i64> {
    get_last_modified(path).and_then(|t| {
        t.duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs() as i64)
    })
}

/// Copy a file from `from` to `to`.
///
/// Returns the number of bytes copied, or an I/O error.
pub fn copy_file(from: &std::path::Path, to: &std::path::Path) -> io::Result<u64> {
    if let Some(parent) = to.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::copy(from, to)
}

/// Move or rename a file from `from` to `to`.
///
/// Returns `Ok(())` on success. If the source and destination are on
/// different filesystems, this falls back to copying and deleting.
pub fn move_file(from: &std::path::Path, to: &std::path::Path) -> io::Result<()> {
    if let Some(parent) = to.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }
    match std::fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
            // Fall back to copy + delete
            std::fs::copy(from, to)?;
            std::fs::remove_file(from)?;
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Rename a file (same as [`move_file`] but does not create parent directories).
pub fn rename_file(from: &std::path::Path, to: &std::path::Path) -> io::Result<()> {
    std::fs::rename(from, to)
}

/// Return the file extension as a string (without the leading dot), if any.
pub fn get_file_extension(path: &std::path::Path) -> Option<String> {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_string())
}

/// Return the file name as a string, if any.
pub fn get_file_name(path: &std::path::Path) -> Option<String> {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
}

/// Return the parent directory of a path, if any.
pub fn get_parent(path: &std::path::Path) -> Option<std::path::PathBuf> {
    path.parent().map(|p| p.to_path_buf())
}

/// Return true if the file content at two paths is identical.
pub fn files_are_equal(a: &std::path::Path, b: &std::path::Path) -> io::Result<bool> {
    let meta_a = std::fs::metadata(a)?;
    let meta_b = std::fs::metadata(b)?;
    if meta_a.len() != meta_b.len() {
        return Ok(false);
    }
    let data_a = std::fs::read(a)?;
    let data_b = std::fs::read(b)?;
    Ok(data_a == data_b)
}

/// Check if a path is a symbolic link.
pub fn is_symlink(path: &std::path::Path) -> bool {
    path.is_symlink()
}

/// Resolve a symbolic link to its target path.
pub fn read_symlink(path: &std::path::Path) -> io::Result<std::path::PathBuf> {
    std::fs::read_link(path)
}

/// Return the canonical (absolute, symlink-free) form of a path.
pub fn canonicalize(path: &std::path::Path) -> io::Result<std::path::PathBuf> {
    std::fs::canonicalize(path)
}

// ---------------------------------------------------------------------------
// Process utilities
// ---------------------------------------------------------------------------

/// Result of executing a command.
#[derive(Debug, Clone)]
pub struct CommandResult {
    /// The exit status code.
    pub exit_code: i32,
    /// Standard output captured from the process.
    pub stdout: String,
    /// Standard error captured from the process.
    pub stderr: String,
    /// Whether the process terminated successfully (exit code 0).
    pub success: bool,
}

impl CommandResult {
    fn from_output(output: std::process::Output) -> Self {
        let exit_code = output.status.code().unwrap_or(-1);
        Self {
            exit_code,
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            success: output.status.success(),
        }
    }

    fn from_error(error: std::io::Error) -> Self {
        Self {
            exit_code: -1,
            stdout: String::new(),
            stderr: error.to_string(),
            success: false,
        }
    }
}

/// Execute a command with arguments and capture its output.
///
/// # Arguments
///
/// * `program` - The program or command to execute.
/// * `args` - Arguments to pass to the program.
/// * `working_dir` - Optional working directory for the process.
/// * `timeout_ms` - Optional timeout in milliseconds (0 means no timeout).
///
/// # Returns
///
/// A [`CommandResult`] with exit code, stdout, stderr, and success flag.
pub fn execute_command(
    program: &str,
    args: &[&str],
    working_dir: Option<&std::path::Path>,
    timeout_ms: u64,
) -> CommandResult {
    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.stdin(std::process::Stdio::null());

    if let Some(dir) = working_dir {
        cmd.current_dir(dir);
    }

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return CommandResult::from_error(e),
    };

    if timeout_ms > 0 {
        let _pid = child.id();
        let start = std::time::Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let output = child.wait_with_output().unwrap_or_else(|e| {
                        std::process::Output {
                            status,
                            stdout: Vec::new(),
                            stderr: e.to_string().into_bytes(),
                        }
                    });
                    return CommandResult::from_output(output);
                }
                Ok(None) => {
                    if start.elapsed().as_millis() as u64 > timeout_ms {
                        let _ = child.kill();
                        let _ = child.wait();
                        return CommandResult {
                            exit_code: -1,
                            stdout: String::new(),
                            stderr: format!(
                                "Command '{}' timed out after {} ms",
                                program, timeout_ms
                            ),
                            success: false,
                        };
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => return CommandResult::from_error(e),
            }
        }
    } else {
        match child.wait_with_output() {
            Ok(output) => CommandResult::from_output(output),
            Err(e) => CommandResult::from_error(e),
        }
    }
}
#[cfg(target_os = "linux")]
fn detect_total_memory() -> u64 {
    use std::fs;
    if let Ok(contents) = fs::read_to_string("/proc/meminfo") {
        for line in contents.lines() {
            if line.starts_with("MemTotal:") {
                // Format: "MemTotal:       16384000 kB"
                if let Some(kb_str) = line.split_whitespace().nth(1) {
                    if let Ok(kb) = kb_str.parse::<u64>() {
                        return kb * 1024;
                    }
                }
            }
        }
    }
    0
}

#[cfg(target_os = "macos")]
fn detect_total_memory() -> u64 {
    use std::process::Command;
    if let Ok(output) = Command::new("sysctl").args(["-n", "hw.memsize"]).output() {
        if let Ok(s) = String::from_utf8(output.stdout) {
            return s.trim().parse::<u64>().unwrap_or(0);
        }
    }
    0
}

#[cfg(target_os = "windows")]
fn detect_total_memory() -> u64 {
    // Windows: use kernel32 via windows-sys or default to 0
    0
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn detect_total_memory() -> u64 {
    0
}

/// Detect OS version string.
fn detect_os_version() -> String {
    #[cfg(target_os = "linux")]
    {
        use std::fs;
        if let Ok(contents) = fs::read_to_string("/proc/version") {
            return contents.split_whitespace().take(3).collect::<Vec<_>>().join(" ");
        }
    }
    #[cfg(target_os = "macos")]
    {
        use std::process::Command;
        if let Ok(output) = Command::new("sw_vers").arg("-productVersion").output() {
            if let Ok(s) = String::from_utf8(output.stdout) {
                return s.trim().to_string();
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        // Read from registry or use winver
        use std::process::Command;
        if let Ok(output) = Command::new("ver").output() {
            if let Ok(s) = String::from_utf8(output.stdout) {
                return s.trim().to_string();
            }
        }
    }
    "unknown".to_string()
}

/// Clean a user name by removing spaces and leading domain.
pub fn clean_user_name(name: &str) -> String {
    let mut result = name.replace(' ', "");
    // Remove leading domain name (after last backslash or forward slash)
    if let Some(pos) = result.rfind('\\') {
        result = result[pos + 1..].to_string();
    }
    if let Some(pos) = result.rfind('/') {
        result = result[pos + 1..].to_string();
    }
    result
}

/// Runtime check: returns true if running in headless mode.
pub fn is_headless() -> bool {
    std::env::var("SYSTEM_UTILITIES_IS_HEADLESS")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(true)
}

/// Runtime check: returns true if running in testing mode.
pub fn is_testing() -> bool {
    std::env::var("SYSTEM_UTILITIES_IS_TESTING")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Runtime check: returns true if running in development mode.
pub fn is_development() -> bool {
    cfg!(debug_assertions) ||
    std::env::var("GHIDRA_DEV_MODE")
        .map(|v| v.to_lowercase() == "true")
        .unwrap_or(false)
}

/// Assert a boolean condition. Only active in testing/development mode.
pub fn assert_true(value: bool, message: &str) {
    if is_testing() || is_development() {
        if !value {
            log::error!("Assertion failed: {}", message);
        }
    }
}

// ---------------------------------------------------------------------------
// Environment variable access
// ---------------------------------------------------------------------------

/// Environment variable utilities.
///
/// Provides typed access to environment variables with default values,
/// matching Ghidra's configuration pattern.
pub mod env {
    /// Get an environment variable as a `String`, returning `default_val` if
    /// not set or not valid UTF-8.
    pub fn get_string(key: &str, default_val: &str) -> String {
        std::env::var(key).unwrap_or_else(|_| default_val.to_string())
    }

    /// Get an environment variable, returning `None` if not set.
    pub fn get_string_opt(key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    /// Get an environment variable as a `bool`.
    ///
    /// Returns `true` only when the value is exactly "true" (case-insensitive).
    /// All other values, including absence, return `false`.
    pub fn get_bool(key: &str, default_val: bool) -> bool {
        std::env::var(key)
            .ok()
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(default_val)
    }

    /// Get an environment variable as an `i64`.
    pub fn get_long(key: &str, default_val: i64) -> i64 {
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_val)
    }

    /// Get an environment variable as a `u64`.
    pub fn get_unsigned_long(key: &str, default_val: u64) -> u64 {
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_val)
    }

    /// Get an environment variable as an `f64`.
    pub fn get_double(key: &str, default_val: f64) -> f64 {
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_val)
    }

    /// Get an environment variable as an `i32`.
    pub fn get_int(key: &str, default_val: i32) -> i32 {
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_val)
    }

    /// Get an environment variable as a `usize`.
    pub fn get_size(key: &str, default_val: usize) -> usize {
        std::env::var(key)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_val)
    }

    /// Check whether an environment variable is set (regardless of value).
    pub fn is_set(key: &str) -> bool {
        std::env::var(key).is_ok()
    }

    /// Get a comma-separated or whitespace-separated environment variable as a
    /// vector of strings.
    pub fn get_string_list(key: &str) -> Vec<String> {
        std::env::var(key)
            .ok()
            .map(|v| {
                v.split(|c: char| c == ',' || c.is_whitespace())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Set an environment variable for the current process.
    pub fn set(key: &str, value: &str) {
        std::env::set_var(key, value);
    }

    /// Remove an environment variable.
    pub fn remove(key: &str) {
        std::env::remove_var(key);
    }

    /// Returns all environment variables as key-value pairs.
    pub fn all() -> Vec<(String, String)> {
        std::env::vars().collect()
    }

    /// Get the current working directory.
    pub fn current_dir() -> std::path::PathBuf {
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
    }

    /// Get the temporary directory.
    pub fn temp_dir() -> std::path::PathBuf {
        std::env::temp_dir()
    }

    /// Get the home directory.
    pub fn home_dir() -> Option<std::path::PathBuf> {
        dirs_fallback()
    }

    /// Get the executable path of the current process.
    pub fn current_exe() -> Option<std::path::PathBuf> {
        std::env::current_exe().ok()
    }

    /// Get the arguments passed to the program.
    pub fn args() -> Vec<String> {
        std::env::args().collect()
    }

    /// Find the home directory by checking `HOME` on Unix or `USERPROFILE` on
    /// Windows, falling back to `dirs` crate heuristics.
    fn dirs_fallback() -> Option<std::path::PathBuf> {
        if let Ok(home) = std::env::var("HOME") {
            return Some(std::path::PathBuf::from(home));
        }
        #[cfg(target_os = "windows")]
        {
            if let Ok(profile) = std::env::var("USERPROFILE") {
                return Some(std::path::PathBuf::from(profile));
            }
        }
        // Last resort: home_dir from dirs crate (if available)
        dirs_sys_fallback()
    }

    #[cfg(unix)]
    fn dirs_sys_fallback() -> Option<std::path::PathBuf> {
        // Read /etc/passwd or use $HOME
        None
    }

    #[cfg(not(unix))]
    fn dirs_sys_fallback() -> Option<std::path::PathBuf> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_info_detect() {
        let info = SystemInfo::detect();
        assert!(!info.os_name.is_empty());
        assert!(info.cpu_count > 0);
    }

    #[test]
    fn test_clean_user_name() {
        assert_eq!(clean_user_name("John Doe"), "JohnDoe");
        assert_eq!(clean_user_name(r"DOMAIN\john"), "john");
        assert_eq!(clean_user_name("domain/john"), "john");
    }

    #[test]
    fn test_memory_info_detect() {
        let info = MemoryInfo::detect();
        assert!(info.page_size > 0);
        // total memory may be 0 on unsupported platforms
        let _ = info.usage_percent();
        let _ = info.has_swap();
    }

    #[test]
    fn test_memory_info_sufficient() {
        let sys = SystemInfo::detect();
        // Should not panic; may return true or false
        let _ = sys.has_sufficient_memory(1024 * 1024);
        let _ = sys.available_memory();
    }

    #[test]
    fn test_file_utilities() {
        let tmp = std::env::temp_dir().join("ghidra_sys_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let file_path = tmp.join("test.txt");
        write_file(&file_path, "hello world").unwrap();
        assert!(file_exists(&file_path));
        assert!(!is_directory(&file_path));

        let contents = read_file(&file_path).unwrap();
        assert_eq!(contents, "hello world");

        let entries = list_directory(&tmp).unwrap();
        assert!(!entries.is_empty());

        delete_file(&file_path);
        assert!(!file_exists(&file_path));

        let sub_dir = tmp.join("subdir");
        create_directory(&sub_dir).unwrap();
        assert!(is_directory(&sub_dir));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_execute_command() {
        let result = execute_command("echo", &["hello"], None, 5000);
        assert!(result.success);
        assert!(result.stdout.contains("hello"));
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_execute_command_timeout() {
        let result = execute_command("sleep", &["10"], None, 100);
        assert!(!result.success);
        assert!(result.stderr.contains("timed out") || result.exit_code != 0);
    }

    #[test]
    fn test_list_files_recursive() {
        let tmp = std::env::temp_dir().join("ghidra_sys_recursive_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let sub = tmp.join("sub");
        std::fs::create_dir_all(&sub).unwrap();

        write_file(&tmp.join("a.txt"), "a").unwrap();
        write_file(&sub.join("b.txt"), "b").unwrap();

        let files = list_files_recursive(&tmp).unwrap();
        assert_eq!(files.len(), 2);
        let names: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        assert!(names.contains(&"a.txt".to_string()));
        assert!(names.contains(&"b.txt".to_string()));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_list_files() {
        let tmp = std::env::temp_dir().join("ghidra_sys_list_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        write_file(&tmp.join("file1.txt"), "1").unwrap();
        std::fs::create_dir_all(tmp.join("dir1")).unwrap();

        let files = list_files(&tmp).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].file_name().unwrap().to_string_lossy().contains("file1"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ------------------------------------------------------------------
    // New file utility tests
    // ------------------------------------------------------------------

    #[test]
    fn test_read_all_bytes() {
        let tmp = std::env::temp_dir().join("ghidra_sys_bytes_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let path = tmp.join("data.bin");
        std::fs::write(&path, &[0x01, 0x02, 0x03]).unwrap();
        let bytes = read_all_bytes(&path).unwrap();
        assert_eq!(bytes, vec![0x01, 0x02, 0x03]);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_write_all_bytes() {
        let tmp = std::env::temp_dir().join("ghidra_sys_write_bytes_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let path = tmp.join("sub").join("data.bin");
        write_all_bytes(&path, &[0xAA, 0xBB]).unwrap();
        assert!(path.exists());
        assert_eq!(std::fs::read(&path).unwrap(), vec![0xAA, 0xBB]);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_exists() {
        let tmp = std::env::temp_dir().join("ghidra_sys_exists_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let f = tmp.join("exists.txt");
        assert!(!exists(&f));
        write_file(&f, "hello").unwrap();
        assert!(exists(&f));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_get_file_size() {
        let tmp = std::env::temp_dir().join("ghidra_sys_size_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let f = tmp.join("size.txt");
        write_file(&f, "1234567890").unwrap(); // 10 bytes
        assert_eq!(get_file_size(&f), Some(10));

        let nonexistent = tmp.join("nonexistent");
        assert_eq!(get_file_size(&nonexistent), None);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_get_last_modified() {
        let tmp = std::env::temp_dir().join("ghidra_sys_mtime_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let f = tmp.join("mtime.txt");
        write_file(&f, "test").unwrap();
        let mtime = get_last_modified(&f);
        assert!(mtime.is_some());

        let unix = get_last_modified_unix(&f);
        assert!(unix.is_some());
        assert!(unix.unwrap() > 0);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_copy_file() {
        let tmp = std::env::temp_dir().join("ghidra_sys_copy_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let src = tmp.join("src.txt");
        write_file(&src, "copy me").unwrap();
        let dst = tmp.join("dst.txt");
        let bytes = copy_file(&src, &dst).unwrap();
        assert!(dst.exists());
        assert_eq!(bytes, 7);
        assert_eq!(read_file(&dst).unwrap(), "copy me");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_move_file() {
        let tmp = std::env::temp_dir().join("ghidra_sys_move_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let src = tmp.join("move_src.txt");
        write_file(&src, "move me").unwrap();
        let dst = tmp.join("move_dst.txt");
        move_file(&src, &dst).unwrap();
        assert!(!src.exists());
        assert!(dst.exists());
        assert_eq!(read_file(&dst).unwrap(), "move me");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_files_are_equal() {
        let tmp = std::env::temp_dir().join("ghidra_sys_equal_test");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let a = tmp.join("a.txt");
        let b = tmp.join("b.txt");
        let c = tmp.join("c.txt");
        write_file(&a, "same").unwrap();
        write_file(&b, "same").unwrap();
        write_file(&c, "different!").unwrap();

        assert!(files_are_equal(&a, &b).unwrap());
        assert!(!files_are_equal(&a, &c).unwrap());

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_get_file_extension() {
        assert_eq!(get_file_extension(std::path::Path::new("test.txt")), Some("txt".to_string()));
        assert_eq!(get_file_extension(std::path::Path::new("no_ext")), None);
    }

    #[test]
    fn test_get_file_name() {
        assert_eq!(get_file_name(std::path::Path::new("/foo/bar.txt")), Some("bar.txt".to_string()));
    }

    // ------------------------------------------------------------------
    // Environment variable tests
    // ------------------------------------------------------------------

    #[test]
    fn test_env_get_string_default() {
        let val = env::get_string("GHIDRA_TEST_DOES_NOT_EXIST_XYZ", "default");
        assert_eq!(val, "default");
    }

    #[test]
    fn test_env_get_string_opt_missing() {
        let val = env::get_string_opt("GHIDRA_TEST_DOES_NOT_EXIST_XYZ");
        assert_eq!(val, None);
    }

    #[test]
    fn test_env_get_bool_default() {
        assert!(!env::get_bool("GHIDRA_TEST_DOES_NOT_EXIST_XYZ", false));
        assert!(env::get_bool("GHIDRA_TEST_DOES_NOT_EXIST_XYZ", true));
    }

    #[test]
    fn test_env_get_long_default() {
        assert_eq!(env::get_long("GHIDRA_TEST_DOES_NOT_EXIST_XYZ", 42), 42);
    }

    #[test]
    fn test_env_get_int_default() {
        assert_eq!(env::get_int("GHIDRA_TEST_DOES_NOT_EXIST_XYZ", -1), -1);
    }

    #[test]
    fn test_env_get_size_default() {
        assert_eq!(env::get_size("GHIDRA_TEST_DOES_NOT_EXIST_XYZ", 1024), 1024);
    }

    #[test]
    fn test_env_get_double_default() {
        assert!((env::get_double("GHIDRA_TEST_DOES_NOT_EXIST_XYZ", 3.14) - 3.14).abs() < 0.001);
    }

    #[test]
    fn test_env_is_set() {
        assert!(!env::is_set("GHIDRA_TEST_DOES_NOT_EXIST_XYZ"));
        std::env::set_var("GHIDRA_TEST_TEMP_VAR", "1");
        assert!(env::is_set("GHIDRA_TEST_TEMP_VAR"));
        std::env::remove_var("GHIDRA_TEST_TEMP_VAR");
    }

    #[test]
    fn test_env_set_and_remove() {
        env::set("GHIDRA_TEST_TEMP_SET", "hello");
        assert_eq!(std::env::var("GHIDRA_TEST_TEMP_SET").unwrap(), "hello");
        env::remove("GHIDRA_TEST_TEMP_SET");
        assert!(std::env::var("GHIDRA_TEST_TEMP_SET").is_err());
    }

    #[test]
    fn test_env_get_string_list() {
        std::env::set_var("GHIDRA_TEST_LIST_VAR", "a,b,c");
        let list = env::get_string_list("GHIDRA_TEST_LIST_VAR");
        assert_eq!(list, vec!["a", "b", "c"]);
        std::env::remove_var("GHIDRA_TEST_LIST_VAR");

        let empty = env::get_string_list("GHIDRA_TEST_DOES_NOT_EXIST_XYZ");
        assert!(empty.is_empty());
    }

    #[test]
    fn test_env_current_dir() {
        let dir = env::current_dir();
        assert!(dir.exists());
    }

    #[test]
    fn test_env_temp_dir() {
        let dir = env::temp_dir();
        assert!(dir.exists());
    }

    #[test]
    fn test_env_args() {
        let args = env::args();
        assert!(!args.is_empty());
    }
}
