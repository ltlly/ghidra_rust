//! Archive restoration task and dialog.
//!
//! Ported from `ghidra.app.plugin.core.archive.RestoreTask`,
//! `RestoreDialog`, and `ArchivePlugin`, `ArchiveDialog`,
//! `ArchiveTask`.

use super::ArchiveOptions;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// ArchivePlugin
// ---------------------------------------------------------------------------

/// Plugin providing archive and restore actions.
///
/// Ported from `ghidra.app.plugin.core.archive.ArchivePlugin`.
#[derive(Debug)]
pub struct ArchivePlugin {
    /// The active archive options.
    options: ArchiveOptions,
    /// Whether an archive operation is in progress.
    is_archiving: bool,
    /// Whether a restore operation is in progress.
    is_restoring: bool,
    /// Last archive output path.
    last_archive_path: Option<PathBuf>,
}

impl ArchivePlugin {
    /// Create a new archive plugin.
    pub fn new() -> Self {
        Self {
            options: ArchiveOptions::default(),
            is_archiving: false,
            is_restoring: false,
            last_archive_path: None,
        }
    }

    /// Get the current options.
    pub fn options(&self) -> &ArchiveOptions {
        &self.options
    }

    /// Get mutable options.
    pub fn options_mut(&mut self) -> &mut ArchiveOptions {
        &mut self.options
    }

    /// Whether an archive operation is in progress.
    pub fn is_archiving(&self) -> bool {
        self.is_archiving
    }

    /// Whether a restore operation is in progress.
    pub fn is_restoring(&self) -> bool {
        self.is_restoring
    }

    /// Get the last archive output path.
    pub fn last_archive_path(&self) -> Option<&Path> {
        self.last_archive_path.as_deref()
    }

    /// Start an archive operation.
    pub fn start_archive(&mut self, output: PathBuf) {
        self.is_archiving = true;
        self.last_archive_path = Some(output);
    }

    /// Complete the archive operation.
    pub fn finish_archive(&mut self) {
        self.is_archiving = false;
    }

    /// Start a restore operation.
    pub fn start_restore(&mut self) {
        self.is_restoring = true;
    }

    /// Complete the restore operation.
    pub fn finish_restore(&mut self) {
        self.is_restoring = false;
    }
}

impl Default for ArchivePlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ArchiveDialog
// ---------------------------------------------------------------------------

/// Model for the archive dialog.
///
/// Ported from `ghidra.app.plugin.core.archive.ArchiveDialog`.
#[derive(Debug, Clone)]
pub struct ArchiveDialog {
    /// The output file path.
    output_path: Option<PathBuf>,
    /// The archive options.
    options: ArchiveOptions,
    /// Whether the dialog was confirmed.
    confirmed: bool,
}

impl ArchiveDialog {
    /// Create a new archive dialog.
    pub fn new() -> Self {
        Self {
            output_path: None,
            options: ArchiveOptions::default(),
            confirmed: false,
        }
    }

    /// Set the output path.
    pub fn set_output_path(&mut self, path: impl Into<PathBuf>) {
        self.output_path = Some(path.into());
    }

    /// Get the output path.
    pub fn output_path(&self) -> Option<&Path> {
        self.output_path.as_deref()
    }

    /// Get the options.
    pub fn options(&self) -> &ArchiveOptions {
        &self.options
    }

    /// Get mutable options.
    pub fn options_mut(&mut self) -> &mut ArchiveOptions {
        &mut self.options
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Whether the dialog was confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }
}

impl Default for ArchiveDialog {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ArchiveTask
// ---------------------------------------------------------------------------

/// Background task that performs the archival.
///
/// Ported from `ghidra.app.plugin.core.archive.ArchiveTask`.
#[derive(Debug)]
pub struct ArchiveTask {
    /// The source directory to archive.
    source: PathBuf,
    /// The output archive file.
    output: PathBuf,
    /// The options.
    options: ArchiveOptions,
    /// Number of files processed.
    files_processed: usize,
    /// Total bytes written.
    bytes_written: u64,
    /// Whether the task is complete.
    complete: bool,
    /// Error message if failed.
    error: Option<String>,
}

impl ArchiveTask {
    /// Create a new archive task.
    pub fn new(source: PathBuf, output: PathBuf, options: ArchiveOptions) -> Self {
        Self {
            source,
            output,
            options,
            files_processed: 0,
            bytes_written: 0,
            complete: false,
            error: None,
        }
    }

    /// Get the source path.
    pub fn source(&self) -> &Path {
        &self.source
    }

    /// Get the output path.
    pub fn output(&self) -> &Path {
        &self.output
    }

    /// Execute the archive task (simulated).
    pub fn execute(&mut self) {
        self.complete = true;
        self.files_processed = 0;
        // In a real implementation, this would walk the directory tree
        // and create a ZIP archive.
    }

    /// Whether the task is complete.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Get the number of files processed.
    pub fn files_processed(&self) -> usize {
        self.files_processed
    }

    /// Get total bytes written.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Get the error message.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

// ---------------------------------------------------------------------------
// RestoreTask
// ---------------------------------------------------------------------------

/// Background task that restores from an archive.
///
/// Ported from `ghidra.app.plugin.core.archive.RestoreTask`.
#[derive(Debug)]
pub struct RestoreTask {
    /// The archive file to restore from.
    archive_path: PathBuf,
    /// The destination directory.
    destination: PathBuf,
    /// Number of files restored.
    files_restored: usize,
    /// Total bytes read.
    bytes_read: u64,
    /// Whether the task is complete.
    complete: bool,
    /// Error message if failed.
    error: Option<String>,
}

impl RestoreTask {
    /// Create a new restore task.
    pub fn new(archive_path: PathBuf, destination: PathBuf) -> Self {
        Self {
            archive_path,
            destination,
            files_restored: 0,
            bytes_read: 0,
            complete: false,
            error: None,
        }
    }

    /// Get the archive path.
    pub fn archive_path(&self) -> &Path {
        &self.archive_path
    }

    /// Get the destination path.
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Execute the restore task (simulated).
    pub fn execute(&mut self) {
        self.complete = true;
        self.files_restored = 0;
    }

    /// Whether the task is complete.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Get the number of files restored.
    pub fn files_restored(&self) -> usize {
        self.files_restored
    }

    /// Get total bytes read.
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }

    /// Get the error message.
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

// ---------------------------------------------------------------------------
// RestoreDialog
// ---------------------------------------------------------------------------

/// Model for the restore dialog.
///
/// Ported from `ghidra.app.plugin.core.archive.RestoreDialog`.
#[derive(Debug, Clone)]
pub struct RestoreDialog {
    /// The selected archive file.
    archive_path: Option<PathBuf>,
    /// The destination directory.
    destination: Option<PathBuf>,
    /// Whether to overwrite existing files.
    overwrite: bool,
    /// Whether the dialog was confirmed.
    confirmed: bool,
}

impl RestoreDialog {
    /// Create a new restore dialog.
    pub fn new() -> Self {
        Self {
            archive_path: None,
            destination: None,
            overwrite: false,
            confirmed: false,
        }
    }

    /// Set the archive path.
    pub fn set_archive_path(&mut self, path: impl Into<PathBuf>) {
        self.archive_path = Some(path.into());
    }

    /// Get the archive path.
    pub fn archive_path(&self) -> Option<&Path> {
        self.archive_path.as_deref()
    }

    /// Set the destination directory.
    pub fn set_destination(&mut self, path: impl Into<PathBuf>) {
        self.destination = Some(path.into());
    }

    /// Get the destination directory.
    pub fn destination(&self) -> Option<&Path> {
        self.destination.as_deref()
    }

    /// Set whether to overwrite.
    pub fn set_overwrite(&mut self, overwrite: bool) {
        self.overwrite = overwrite;
    }

    /// Whether to overwrite existing files.
    pub fn is_overwrite(&self) -> bool {
        self.overwrite
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Whether the dialog was confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }
}

impl Default for RestoreDialog {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_archive_plugin_lifecycle() {
        let mut plugin = ArchivePlugin::new();
        assert!(!plugin.is_archiving());
        assert!(!plugin.is_restoring());
        assert!(plugin.last_archive_path().is_none());

        plugin.start_archive(PathBuf::from("/tmp/archive.zip"));
        assert!(plugin.is_archiving());
        assert_eq!(
            plugin.last_archive_path(),
            Some(Path::new("/tmp/archive.zip"))
        );

        plugin.finish_archive();
        assert!(!plugin.is_archiving());
    }

    #[test]
    fn test_archive_plugin_options() {
        let mut plugin = ArchivePlugin::new();
        plugin.options_mut().include_repository = false;
        assert!(!plugin.options().include_repository);
    }

    #[test]
    fn test_archive_dialog() {
        let mut dialog = ArchiveDialog::new();
        assert!(!dialog.is_confirmed());
        assert!(dialog.output_path().is_none());

        dialog.set_output_path("/tmp/out.zip");
        assert_eq!(dialog.output_path(), Some(Path::new("/tmp/out.zip")));

        dialog.confirm();
        assert!(dialog.is_confirmed());
    }

    #[test]
    fn test_archive_task() {
        let mut task = ArchiveTask::new(
            PathBuf::from("/project"),
            PathBuf::from("/tmp/archive.zip"),
            ArchiveOptions::default(),
        );
        assert!(!task.is_complete());

        task.execute();
        assert!(task.is_complete());
        assert!(task.error().is_none());
    }

    #[test]
    fn test_restore_task() {
        let mut task = RestoreTask::new(
            PathBuf::from("/tmp/archive.zip"),
            PathBuf::from("/restored"),
        );
        assert!(!task.is_complete());

        task.execute();
        assert!(task.is_complete());
        assert_eq!(task.archive_path(), Path::new("/tmp/archive.zip"));
        assert_eq!(task.destination(), Path::new("/restored"));
    }

    #[test]
    fn test_restore_dialog() {
        let mut dialog = RestoreDialog::new();
        assert!(!dialog.is_confirmed());
        assert!(!dialog.is_overwrite());

        dialog.set_archive_path("/tmp/archive.zip");
        dialog.set_destination("/restored");
        dialog.set_overwrite(true);

        assert_eq!(dialog.archive_path(), Some(Path::new("/tmp/archive.zip")));
        assert_eq!(dialog.destination(), Some(Path::new("/restored")));
        assert!(dialog.is_overwrite());

        dialog.confirm();
        assert!(dialog.is_confirmed());
    }

    #[test]
    fn test_archive_plugin_restore_lifecycle() {
        let mut plugin = ArchivePlugin::new();
        plugin.start_restore();
        assert!(plugin.is_restoring());
        plugin.finish_restore();
        assert!(!plugin.is_restoring());
    }
}
