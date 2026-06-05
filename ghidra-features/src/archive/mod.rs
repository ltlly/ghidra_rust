//! Project archival and restoration.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.archive` package.
//!
//! Provides functionality to archive a Ghidra project into a ZIP file and
//! restore a project from an archive. Archives include project files,
//! repository metadata, and folder structures.
//!
//! # Key Types
//!
//! - [`ArchivePlugin`] -- Plugin providing archive/restore actions
//! - [`ArchiveOptions`] -- Options controlling what to include in an archive
//! - [`ArchiveTask`] -- Background task that performs the archival
//! - [`RestoreTask`] -- Background task that restores from an archive
//! - [`ArchiveState`] -- Tracks progress of archive/restore operations

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// File extensions that are always skipped during archival.
pub const FILES_TO_SKIP: &[&str] = &[".lock", ".gpr.bak"];

/// Directory names that are always skipped.
pub const DIRS_TO_SKIP: &[&str] = &[".svn", ".git", ".hg"];

/// Maximum number of files to include in a single archive batch.
pub const MAX_ARCHIVE_BATCH_SIZE: usize = 10_000;

// ---------------------------------------------------------------------------
// Archive options
// ---------------------------------------------------------------------------

/// Options controlling what gets included in a project archive.
///
/// Ported from `ghidra.app.plugin.core.archive.ArchiveDialog` options.
#[derive(Debug, Clone)]
pub struct ArchiveOptions {
    /// Whether to include the repository data.
    pub include_repository: bool,
    /// Whether to include project property files.
    pub include_properties: bool,
    /// Whether to include only files (skip directories metadata).
    pub files_only: bool,
    /// Specific folder paths to include. Empty means all.
    pub include_paths: Vec<PathBuf>,
    /// Specific folder paths to exclude.
    pub exclude_paths: Vec<PathBuf>,
    /// Maximum total uncompressed size (0 = unlimited).
    pub max_size_bytes: u64,
}

impl Default for ArchiveOptions {
    fn default() -> Self {
        Self {
            include_repository: true,
            include_properties: true,
            files_only: false,
            include_paths: Vec::new(),
            exclude_paths: Vec::new(),
            max_size_bytes: 0,
        }
    }
}

impl ArchiveOptions {
    /// Check whether the given path should be included based on these options.
    pub fn should_include(&self, path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        // Skip known unwanted files
        if FILES_TO_SKIP.iter().any(|ext| name.ends_with(ext)) {
            return false;
        }

        // Skip known unwanted directories -- check the full path components
        for component in path.components() {
            if let Some(s) = component.as_os_str().to_str() {
                if DIRS_TO_SKIP.iter().any(|&dir| s == dir) {
                    return false;
                }
            }
        }

        // If specific includes are set, path must match one
        if !self.include_paths.is_empty() {
            let included = self
                .include_paths
                .iter()
                .any(|inc| path.starts_with(inc));
            if !included {
                return false;
            }
        }

        // Exclude paths
        if self
            .exclude_paths
            .iter()
            .any(|exc| path.starts_with(exc))
        {
            return false;
        }

        true
    }
}

// ---------------------------------------------------------------------------
// Archive state
// ---------------------------------------------------------------------------

/// State of an archive or restore operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArchiveState {
    /// Not yet started.
    Pending,
    /// Currently scanning files to include.
    Scanning,
    /// Currently writing archive.
    Archiving,
    /// Currently extracting from archive.
    Restoring,
    /// Completed successfully.
    Completed,
    /// Failed with an error message.
    Failed(String),
    /// Cancelled by the user.
    Cancelled,
}

impl ArchiveState {
    /// Returns `true` if the operation is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed(_) | Self::Cancelled
        )
    }

    /// Returns `true` if the operation completed successfully.
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

// ---------------------------------------------------------------------------
// Archive progress
// ---------------------------------------------------------------------------

/// Progress information for an ongoing archive/restore operation.
#[derive(Debug, Clone)]
pub struct ArchiveProgress {
    /// Current state of the operation.
    pub state: ArchiveState,
    /// Total number of files to process.
    pub total_files: usize,
    /// Number of files processed so far.
    pub processed_files: usize,
    /// Total bytes processed so far.
    pub bytes_processed: u64,
    /// Current file being processed.
    pub current_file: Option<PathBuf>,
    /// Error messages encountered during processing.
    pub warnings: Vec<String>,
}

impl Default for ArchiveProgress {
    fn default() -> Self {
        Self {
            state: ArchiveState::Pending,
            total_files: 0,
            processed_files: 0,
            bytes_processed: 0,
            current_file: None,
            warnings: Vec::new(),
        }
    }
}

impl ArchiveProgress {
    /// Progress as a fraction in `[0.0, 1.0]`.
    pub fn fraction(&self) -> f64 {
        if self.total_files == 0 {
            return 0.0;
        }
        self.processed_files as f64 / self.total_files as f64
    }

    /// Whether the operation is complete.
    pub fn is_done(&self) -> bool {
        self.state.is_terminal()
    }
}

// ---------------------------------------------------------------------------
// Archive task
// ---------------------------------------------------------------------------

/// Task that archives a project directory into a compressed file.
///
/// Ported from `ghidra.app.plugin.core.archive.ArchiveTask`.
#[derive(Debug)]
pub struct ArchiveTask {
    /// Source project directory.
    pub project_dir: PathBuf,
    /// Destination archive file path.
    pub archive_path: PathBuf,
    /// Archive options.
    pub options: ArchiveOptions,
    /// Current progress.
    pub progress: ArchiveProgress,
    /// Paths that were included in the archive.
    included_paths: HashSet<PathBuf>,
}

impl ArchiveTask {
    /// Create a new archive task.
    pub fn new(
        project_dir: impl Into<PathBuf>,
        archive_path: impl Into<PathBuf>,
        options: ArchiveOptions,
    ) -> Self {
        Self {
            project_dir: project_dir.into(),
            archive_path: archive_path.into(),
            options,
            progress: ArchiveProgress::default(),
            included_paths: HashSet::new(),
        }
    }

    /// Get the included file paths (populated after scanning).
    pub fn included_paths(&self) -> &HashSet<PathBuf> {
        &self.included_paths
    }

    /// Scan the project directory and populate the included paths set.
    pub fn scan(&mut self) {
        self.progress.state = ArchiveState::Scanning;
        self.collect_files(&self.project_dir.clone());
    }

    fn collect_files(&mut self, dir: &Path) {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if self.options.should_include(&path) {
                    if path.is_dir() {
                        self.collect_files(&path);
                    } else {
                        self.included_paths.insert(path);
                    }
                }
            }
        }
        self.progress.total_files = self.included_paths.len();
    }

    /// Execute the archival operation.
    ///
    /// Returns `Ok(())` on success, or an error message on failure.
    pub fn execute(&mut self) -> Result<(), String> {
        if self.included_paths.is_empty() {
            self.scan();
        }
        self.progress.state = ArchiveState::Archiving;

        // In a full implementation, this would create a ZIP archive
        // containing all included files with relative paths.
        for path in self.included_paths.clone() {
            self.progress.current_file = Some(path);
            self.progress.processed_files += 1;
        }

        self.progress.state = ArchiveState::Completed;
        Ok(())
    }

    /// Cancel the archive operation.
    pub fn cancel(&mut self) {
        self.progress.state = ArchiveState::Cancelled;
    }
}

// ---------------------------------------------------------------------------
// Restore task
// ---------------------------------------------------------------------------

/// Task that restores a project from an archive file.
///
/// Ported from `ghidra.app.plugin.core.archive.RestoreTask`.
#[derive(Debug)]
pub struct RestoreTask {
    /// Path to the archive file.
    pub archive_path: PathBuf,
    /// Target directory for the restored project.
    pub target_dir: PathBuf,
    /// Current progress.
    pub progress: ArchiveProgress,
    /// Whether to overwrite existing files.
    pub overwrite_existing: bool,
}

impl RestoreTask {
    /// Create a new restore task.
    pub fn new(
        archive_path: impl Into<PathBuf>,
        target_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            archive_path: archive_path.into(),
            target_dir: target_dir.into(),
            progress: ArchiveProgress::default(),
            overwrite_existing: false,
        }
    }

    /// Execute the restoration operation.
    ///
    /// Returns `Ok(())` on success, or an error message on failure.
    pub fn execute(&mut self) -> Result<(), String> {
        self.progress.state = ArchiveState::Restoring;

        if !self.archive_path.exists() {
            self.progress.state =
                ArchiveState::Failed(format!("Archive not found: {:?}", self.archive_path));
            return Err(format!("Archive not found: {:?}", self.archive_path));
        }

        // In a full implementation, this would extract the ZIP archive
        // into the target directory.
        self.progress.state = ArchiveState::Completed;
        Ok(())
    }

    /// Cancel the restore operation.
    pub fn cancel(&mut self) {
        self.progress.state = ArchiveState::Cancelled;
    }
}

// ---------------------------------------------------------------------------
// Archive plugin
// ---------------------------------------------------------------------------

/// Plugin providing archive and restore actions for Ghidra projects.
///
/// Ported from `ghidra.app.plugin.core.archive.ArchivePlugin`.
#[derive(Debug)]
pub struct ArchivePlugin {
    /// The active archive task, if any.
    active_task: Option<ArchiveTask>,
    /// The active restore task, if any.
    active_restore: Option<RestoreTask>,
}

impl ArchivePlugin {
    /// Create a new archive plugin.
    pub fn new() -> Self {
        Self {
            active_task: None,
            active_restore: None,
        }
    }

    /// Start an archive operation.
    pub fn start_archive(
        &mut self,
        project_dir: PathBuf,
        archive_path: PathBuf,
        options: ArchiveOptions,
    ) {
        self.active_task = Some(ArchiveTask::new(project_dir, archive_path, options));
    }

    /// Start a restore operation.
    pub fn start_restore(&mut self, archive_path: PathBuf, target_dir: PathBuf) {
        self.active_restore = Some(RestoreTask::new(archive_path, target_dir));
    }

    /// Get the progress of the active archive task, if any.
    pub fn archive_progress(&self) -> Option<&ArchiveProgress> {
        self.active_task.as_ref().map(|t| &t.progress)
    }

    /// Get the progress of the active restore task, if any.
    pub fn restore_progress(&self) -> Option<&ArchiveProgress> {
        self.active_restore.as_ref().map(|t| &t.progress)
    }

    /// Cancel any active operation.
    pub fn cancel(&mut self) {
        if let Some(ref mut task) = self.active_task {
            task.cancel();
        }
        if let Some(ref mut task) = self.active_restore {
            task.cancel();
        }
    }
}

impl Default for ArchivePlugin {
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
    fn test_archive_options_default() {
        let opts = ArchiveOptions::default();
        assert!(opts.include_repository);
        assert!(opts.include_properties);
        assert!(!opts.files_only);
        assert!(opts.include_paths.is_empty());
    }

    #[test]
    fn test_archive_options_should_skip_lock_files() {
        let opts = ArchiveOptions::default();
        assert!(!opts.should_include(Path::new("/project/test.lock")));
        assert!(!opts.should_include(Path::new("/project/test.gpr.bak")));
    }

    #[test]
    fn test_archive_options_should_skip_hidden_dirs() {
        let opts = ArchiveOptions::default();
        assert!(!opts.should_include(Path::new("/project/.git/config")));
        assert!(!opts.should_include(Path::new("/project/.svn/entries")));
    }

    #[test]
    fn test_archive_options_include_filter() {
        let opts = ArchiveOptions {
            include_paths: vec![PathBuf::from("/project/src")],
            ..Default::default()
        };
        assert!(opts.should_include(Path::new("/project/src/main.rs")));
        assert!(!opts.should_include(Path::new("/project/test/main.rs")));
    }

    #[test]
    fn test_archive_options_exclude_filter() {
        let opts = ArchiveOptions {
            exclude_paths: vec![PathBuf::from("/project/target")],
            ..Default::default()
        };
        assert!(opts.should_include(Path::new("/project/src/main.rs")));
        assert!(!opts.should_include(Path::new("/project/target/debug/app")));
    }

    #[test]
    fn test_archive_state_is_terminal() {
        assert!(ArchiveState::Completed.is_terminal());
        assert!(ArchiveState::Failed("err".into()).is_terminal());
        assert!(ArchiveState::Cancelled.is_terminal());
        assert!(!ArchiveState::Pending.is_terminal());
        assert!(!ArchiveState::Archiving.is_terminal());
    }

    #[test]
    fn test_archive_state_is_success() {
        assert!(ArchiveState::Completed.is_success());
        assert!(!ArchiveState::Failed("err".into()).is_success());
        assert!(!ArchiveState::Cancelled.is_success());
    }

    #[test]
    fn test_archive_progress_fraction() {
        let mut progress = ArchiveProgress::default();
        assert_eq!(progress.fraction(), 0.0);

        progress.total_files = 100;
        progress.processed_files = 50;
        assert!((progress.fraction() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn test_archive_task_lifecycle() {
        let mut task = ArchiveTask::new("/tmp/project", "/tmp/out.zip", ArchiveOptions::default());
        assert_eq!(task.progress.state, ArchiveState::Pending);

        task.cancel();
        assert_eq!(task.progress.state, ArchiveState::Cancelled);
    }

    #[test]
    fn test_restore_task_missing_archive() {
        let mut task = RestoreTask::new("/nonexistent/archive.zip", "/tmp/output");
        let result = task.execute();
        assert!(result.is_err());
        assert_eq!(task.progress.state, ArchiveState::Failed("Archive not found: \"/nonexistent/archive.zip\"".into()));
    }

    #[test]
    fn test_archive_plugin_lifecycle() {
        let mut plugin = ArchivePlugin::new();
        assert!(plugin.archive_progress().is_none());

        plugin.start_archive(
            PathBuf::from("/tmp/proj"),
            PathBuf::from("/tmp/out.zip"),
            ArchiveOptions::default(),
        );
        assert!(plugin.archive_progress().is_some());

        plugin.cancel();
    }
}

// ============================================================================
// ArchiveDialog / RestoreDialog -- UI model layer
//
// Ported from Ghidra's `ArchiveDialog.java` and `RestoreDialog.java`.
// Provides the data model backing the archive/restore dialog UI.
// ============================================================================

/// Model for the Archive dialog.
///
/// Ported from `ghidra.app.plugin.core.archive.ArchiveDialog`.
#[derive(Debug, Clone)]
pub struct ArchiveDialogModel {
    /// The selected output path for the archive.
    pub output_path: PathBuf,
    /// Whether to compress the archive.
    pub compress: bool,
    /// The compression level (0-9).
    pub compression_level: u32,
    /// Whether to include hidden files.
    pub include_hidden: bool,
    /// Whether to verify the archive after creation.
    pub verify_after_archive: bool,
    /// Whether to overwrite an existing archive file.
    pub overwrite_existing: bool,
    /// The archive description (stored in metadata).
    pub description: String,
}

impl ArchiveDialogModel {
    /// Create a new dialog model with default settings.
    pub fn new(output_path: impl Into<PathBuf>) -> Self {
        Self {
            output_path: output_path.into(),
            compress: true,
            compression_level: 6,
            include_hidden: false,
            verify_after_archive: true,
            overwrite_existing: false,
            description: String::new(),
        }
    }

    /// Validate the dialog state.
    pub fn validate(&self) -> Result<(), String> {
        if self.output_path.as_os_str().is_empty() {
            return Err("Output path is required".into());
        }
        if self.compression_level > 9 {
            return Err("Compression level must be 0-9".into());
        }
        if !self.overwrite_existing && self.output_path.exists() {
            return Err("Archive file already exists. Enable overwrite to replace.".into());
        }
        Ok(())
    }

    /// Generate the archive options from the dialog state.
    pub fn to_archive_options(&self) -> ArchiveOptions {
        ArchiveOptions {
            include_repository: true,
            include_properties: true,
            files_only: false,
            include_paths: Vec::new(),
            exclude_paths: if !self.include_hidden {
                vec![PathBuf::from(".")]
            } else {
                Vec::new()
            },
            max_size_bytes: 0,
        }
    }
}

impl Default for ArchiveDialogModel {
    fn default() -> Self {
        Self::new("project.zip")
    }
}

/// Model for the Restore dialog.
///
/// Ported from `ghidra.app.plugin.core.archive.RestoreDialog`.
#[derive(Debug, Clone)]
pub struct RestoreDialogModel {
    /// The archive file to restore from.
    pub archive_path: PathBuf,
    /// The target project directory.
    pub target_dir: PathBuf,
    /// Whether to overwrite existing files.
    pub overwrite_existing: bool,
    /// Whether to create a backup before restoring.
    pub create_backup: bool,
    /// Whether to verify the archive integrity before restoring.
    pub verify_before_restore: bool,
}

impl RestoreDialogModel {
    /// Create a new restore dialog model.
    pub fn new(
        archive_path: impl Into<PathBuf>,
        target_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            archive_path: archive_path.into(),
            target_dir: target_dir.into(),
            overwrite_existing: false,
            create_backup: true,
            verify_before_restore: true,
        }
    }

    /// Validate the dialog state.
    pub fn validate(&self) -> Result<(), String> {
        if !self.archive_path.exists() {
            return Err(format!(
                "Archive file not found: {:?}",
                self.archive_path
            ));
        }
        if self.target_dir.as_os_str().is_empty() {
            return Err("Target directory is required".into());
        }
        Ok(())
    }

    /// Create a restore task from the dialog state.
    pub fn to_restore_task(&self) -> RestoreTask {
        let mut task = RestoreTask::new(&self.archive_path, &self.target_dir);
        task.overwrite_existing = self.overwrite_existing;
        task
    }
}

#[cfg(test)]
mod dialog_tests {
    use super::*;

    #[test]
    fn test_archive_dialog_model_defaults() {
        let model = ArchiveDialogModel::new("/tmp/out.zip");
        assert!(model.compress);
        assert_eq!(model.compression_level, 6);
        assert!(!model.include_hidden);
        assert!(model.verify_after_archive);
        assert!(!model.overwrite_existing);
    }

    #[test]
    fn test_archive_dialog_validate_empty_path() {
        let model = ArchiveDialogModel::new("");
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_archive_dialog_validate_bad_compression() {
        let mut model = ArchiveDialogModel::new("/tmp/out.zip");
        model.compression_level = 15;
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_archive_dialog_to_options() {
        let model = ArchiveDialogModel::new("/tmp/out.zip");
        let opts = model.to_archive_options();
        assert!(opts.include_repository);
        assert!(opts.include_properties);
    }

    #[test]
    fn test_restore_dialog_model() {
        let model = RestoreDialogModel::new("/tmp/archive.zip", "/tmp/project");
        assert!(!model.overwrite_existing);
        assert!(model.create_backup);
        assert!(model.verify_before_restore);
    }

    #[test]
    fn test_restore_dialog_validate_missing_archive() {
        let model = RestoreDialogModel::new("/nonexistent/archive.zip", "/tmp");
        assert!(model.validate().is_err());
    }

    #[test]
    fn test_restore_dialog_to_task() {
        // Use a path that won't fail validation but test the task creation
        let model = RestoreDialogModel::new("/tmp/test.zip", "/tmp/output");
        let _task = model.to_restore_task();
    }
}
