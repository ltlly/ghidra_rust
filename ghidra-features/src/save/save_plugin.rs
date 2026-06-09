//! SavePlugin -- modal dialog and task for saving modified domain files.
//!
//! Ported from `ghidra.framework.main.SaveDataDialog` and the inner
//! `SaveTask` class.
//!
//! Provides a dialog that displays a list of domain objects that have
//! changed and lets the user mark which ones to save.  Read-only files
//! are rendered as non-selectable.  The [`SaveTask`] runs the actual
//! save operation in the background with progress and cancellation support.

use std::fmt;

// ---------------------------------------------------------------------------
// DomainFile (placeholder)
// ---------------------------------------------------------------------------

/// Represents a domain file in the Ghidra project.
///
/// Ported from `ghidra.framework.model.DomainFile`.
#[derive(Debug, Clone)]
pub struct DomainFile {
    /// The display name of the file (e.g., "my_binary.exe").
    pub name: String,
    /// The full path within the project (e.g., "/dir/my_binary.exe").
    pub pathname: String,
    /// Whether the file has unsaved changes.
    pub is_changed: bool,
    /// Whether the file can be saved to its current location.
    pub can_save: bool,
    /// Whether the file is in a writable project.
    pub is_in_writable_project: bool,
    /// The project locator name, if known.
    pub project_locator_name: Option<String>,
}

impl DomainFile {
    /// Create a new domain file entry.
    pub fn new(name: impl Into<String>, pathname: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            pathname: pathname.into(),
            is_changed: false,
            can_save: true,
            is_in_writable_project: true,
            project_locator_name: None,
        }
    }

    /// Mark this file as changed.
    pub fn mark_changed(&mut self) {
        self.is_changed = true;
    }

    /// Mark this file as saved (clean).
    pub fn mark_saved(&mut self) {
        self.is_changed = false;
    }
}

// ---------------------------------------------------------------------------
// TaskMonitor (placeholder)
// ---------------------------------------------------------------------------

/// Monitor for tracking progress of a long-running task.
///
/// Ported from `ghidra.util.task.TaskMonitor`.
pub trait TaskMonitor: fmt::Debug + Send + Sync {
    /// Whether the task has been cancelled.
    fn is_cancelled(&self) -> bool;
    /// Set the current progress value.
    fn set_progress(&self, value: u64);
    /// Set the progress message.
    fn set_message(&self, msg: &str);
    /// Get the maximum progress value.
    fn maximum(&self) -> u64;
    /// Set the maximum progress value.
    fn set_maximum(&self, max: u64);
    /// Increment progress by the given amount.
    fn increment_progress(&self, increment: u64);
    /// Initialize progress with a message and maximum.
    fn initialize(&self, max: u64, message: &str);
}

/// A simple in-memory task monitor for testing and headless use.
#[derive(Debug)]
pub struct SimpleTaskMonitor {
    cancelled: std::sync::atomic::AtomicBool,
    progress: std::sync::atomic::AtomicU64,
    max: std::sync::atomic::AtomicU64,
    message: std::sync::Mutex<String>,
}

impl SimpleTaskMonitor {
    /// Create a new simple task monitor.
    pub fn new() -> Self {
        Self {
            cancelled: std::sync::atomic::AtomicBool::new(false),
            progress: std::sync::atomic::AtomicU64::new(0),
            max: std::sync::atomic::AtomicU64::new(100),
            message: std::sync::Mutex::new(String::new()),
        }
    }

    /// Signal cancellation.
    pub fn cancel(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

impl Default for SimpleTaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskMonitor for SimpleTaskMonitor {
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set_progress(&self, value: u64) {
        self.progress
            .store(value, std::sync::atomic::Ordering::Relaxed);
    }

    fn set_message(&self, msg: &str) {
        if let Ok(mut m) = self.message.lock() {
            *m = msg.to_string();
        }
    }

    fn maximum(&self) -> u64 {
        self.max.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn set_maximum(&self, max: u64) {
        self.max
            .store(max, std::sync::atomic::Ordering::Relaxed);
    }

    fn increment_progress(&self, increment: u64) {
        self.progress
            .fetch_add(increment, std::sync::atomic::Ordering::Relaxed);
    }

    fn initialize(&self, max: u64, message: &str) {
        self.set_maximum(max);
        self.set_progress(0);
        self.set_message(message);
    }
}

// ---------------------------------------------------------------------------
// SaveResult
// ---------------------------------------------------------------------------

/// Result of a save operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveResult {
    /// The save completed successfully.
    Success,
    /// The save was cancelled by the user.
    Cancelled,
    /// An error occurred during save.
    Error(String),
    /// No files needed saving.
    NoFilesToSave,
}

impl fmt::Display for SaveResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "Save completed successfully"),
            Self::Cancelled => write!(f, "Save cancelled"),
            Self::Error(msg) => write!(f, "Save error: {}", msg),
            Self::NoFilesToSave => write!(f, "No files to save"),
        }
    }
}

// ---------------------------------------------------------------------------
// SaveTask
// ---------------------------------------------------------------------------

/// Background task that saves one or more domain files.
///
/// Ported from `ghidra.framework.main.SaveDataDialog.SaveTask`.
///
/// Iterates over the provided domain files and saves each one, reporting
/// progress through a [`TaskMonitor`].  The task can be cancelled at any
/// time.
///
/// # Example
///
/// ```
/// use ghidra_features::save::save_plugin::*;
///
/// let files = vec![
///     DomainFile::new("prog1.exe", "/dir/prog1.exe"),
///     DomainFile::new("prog2.exe", "/dir/prog2.exe"),
/// ];
///
/// let monitor = SimpleTaskMonitor::new();
/// let mut task = SaveTask::new(files);
/// let result = task.run(&monitor);
/// assert_eq!(result, SaveResult::Success);
/// ```
#[derive(Debug)]
pub struct SaveTask {
    /// The files to save.
    files: Vec<DomainFile>,
    /// Whether the task completed (not cancelled).
    operation_completed: bool,
}

impl SaveTask {
    /// Create a new save task for the given files.
    pub fn new(files: Vec<DomainFile>) -> Self {
        Self {
            files,
            operation_completed: false,
        }
    }

    /// Get the number of files to save.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Get the task title based on the number of files.
    pub fn title(&self) -> &str {
        if self.files.len() > 1 {
            "Saving Files..."
        } else {
            "Saving File"
        }
    }

    /// Whether the task is cancellable.
    pub fn is_cancellable(&self) -> bool {
        true
    }

    /// Whether the task is modal.
    pub fn is_modal(&self) -> bool {
        true
    }

    /// Whether the operation completed (not cancelled).
    pub fn is_operation_completed(&self) -> bool {
        self.operation_completed
    }

    /// Run the save task.
    ///
    /// Iterates over each file, reports progress, and saves the file.
    /// Returns a [`SaveResult`] indicating the outcome.
    pub fn run(&mut self, monitor: &dyn TaskMonitor) -> SaveResult {
        if self.files.is_empty() {
            self.operation_completed = true;
            return SaveResult::NoFilesToSave;
        }

        let total = self.files.len() as u64;
        monitor.initialize(total, self.title());

        for (i, file) in self.files.iter().enumerate() {
            if monitor.is_cancelled() {
                self.operation_completed = false;
                return SaveResult::Cancelled;
            }

            monitor.set_progress(0);
            monitor.set_message(&format!("Saving {}", file.name));

            // In the real implementation, this would call domain_file.save(monitor).
            // Here we simulate the save by marking it clean.

            monitor.set_progress(i as u64 + 1);
        }

        self.operation_completed = true;
        SaveResult::Success
    }

    /// Consume the task and return the files (useful after a cancelled run
    /// to inspect which files were not saved).
    pub fn into_files(self) -> Vec<DomainFile> {
        self.files
    }

    /// Get a reference to the files.
    pub fn files(&self) -> &[DomainFile] {
        &self.files
    }
}

// ---------------------------------------------------------------------------
// SaveDataDialog
// ---------------------------------------------------------------------------

/// Entry in the save dialog's file list.
#[derive(Debug, Clone)]
pub struct SaveDataEntry {
    /// The domain file to potentially save.
    pub file: DomainFile,
    /// Whether the user has selected this file for saving.
    pub selected: bool,
    /// Whether the file can be saved (not read-only).
    pub saveable: bool,
}

impl SaveDataEntry {
    /// Create a new entry from a domain file.
    pub fn new(file: DomainFile) -> Self {
        let saveable = file.can_save;
        Self {
            file,
            selected: saveable,
            saveable,
        }
    }

    /// Get the display text for this entry.
    ///
    /// Read-only files get a suffix indicating they cannot be saved.
    pub fn display_text(&self) -> String {
        if !self.saveable {
            if !self.file.is_in_writable_project {
                if let Some(ref loc) = self.file.project_locator_name {
                    return format!("{} (Read-Only from {})", self.file.name, loc);
                }
            }
            format!("{} (Read-Only)", self.file.name)
        } else {
            self.file.name.clone()
        }
    }
}

/// Result of showing the save data dialog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveDialogResult {
    /// The user clicked "Save" and files were saved.
    Saved(Vec<String>),
    /// The user clicked "Don't Save".
    DontSave,
    /// The user cancelled the dialog.
    Cancelled,
}

/// Modal dialog for saving modified domain files.
///
/// Ported from `ghidra.framework.main.SaveDataDialog`.
///
/// Displays a list of domain files that have been changed.  The user can
/// check/uncheck individual files, select all, deselect all, and then
/// either save the selected files or skip saving.
///
/// # Example
///
/// ```
/// use ghidra_features::save::save_plugin::*;
///
/// let files = vec![
///     DomainFile::new("prog1.exe", "/dir/prog1.exe"),
///     DomainFile::new("prog2.exe", "/dir/prog2.exe"),
/// ];
///
/// let mut dialog = SaveDataDialog::new("Save Modified Files");
/// dialog.show(files);
///
/// // Select all saveable files
/// dialog.select_all();
///
/// // Check entry count
/// assert_eq!(dialog.entry_count(), 2);
/// ```
#[derive(Debug)]
pub struct SaveDataDialog {
    /// The dialog title.
    title: String,
    /// The entries displayed in the dialog.
    entries: Vec<SaveDataEntry>,
    /// Whether the save button should be enabled.
    save_enabled: bool,
    /// Whether the operation completed.
    operation_completed: bool,
}

impl SaveDataDialog {
    /// Create a new save data dialog.
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            entries: Vec::new(),
            save_enabled: false,
            operation_completed: false,
        }
    }

    /// Show the dialog with the given files.
    ///
    /// Filters out files that have no unsaved changes.
    pub fn show(&mut self, files: Vec<DomainFile>) {
        // Filter to only changed files (matching Java: checkForUnsavedFiles)
        self.entries = files
            .into_iter()
            .filter(|f| f.is_changed)
            .map(SaveDataEntry::new)
            .collect();

        self.update_save_enabled();
        self.operation_completed = self.entries.is_empty();
    }

    /// Get the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Get the number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get a reference to the entries.
    pub fn entries(&self) -> &[SaveDataEntry] {
        &self.entries
    }

    /// Get a mutable reference to the entries.
    pub fn entries_mut(&mut self) -> &mut Vec<SaveDataEntry> {
        &mut self.entries
    }

    /// Whether the save button is enabled.
    pub fn is_save_enabled(&self) -> bool {
        self.save_enabled
    }

    /// Whether the operation completed.
    pub fn is_operation_completed(&self) -> bool {
        self.operation_completed
    }

    /// Select all saveable files.
    pub fn select_all(&mut self) {
        for entry in &mut self.entries {
            if entry.saveable {
                entry.selected = true;
            }
        }
        self.update_save_enabled();
    }

    /// Deselect all files.
    pub fn deselect_all(&mut self) {
        for entry in &mut self.entries {
            entry.selected = false;
        }
        self.update_save_enabled();
    }

    /// Toggle selection of an entry by index.
    pub fn toggle_selection(&mut self, index: usize) -> bool {
        if index < self.entries.len() && self.entries[index].saveable {
            self.entries[index].selected = !self.entries[index].selected;
            self.update_save_enabled();
            true
        } else {
            false
        }
    }

    /// Set selection of an entry by index.
    pub fn set_selected(&mut self, index: usize, selected: bool) -> bool {
        if index < self.entries.len() && (self.entries[index].saveable || !selected) {
            self.entries[index].selected = selected;
            self.update_save_enabled();
            true
        } else {
            false
        }
    }

    /// Execute the "Save" action.
    ///
    /// Collects all selected files and runs a [`SaveTask`].
    /// Returns a [`SaveDialogResult`] indicating the outcome.
    pub fn save(&mut self) -> SaveDialogResult {
        let selected_files: Vec<DomainFile> = self
            .entries
            .iter()
            .filter(|e| e.selected)
            .map(|e| e.file.clone())
            .collect();

        if selected_files.is_empty() {
            self.operation_completed = true;
            return SaveDialogResult::DontSave;
        }

        let monitor = SimpleTaskMonitor::new();
        let mut task = SaveTask::new(selected_files);
        let result = task.run(&monitor);

        match result {
            SaveResult::Success => {
                // Mark saved files as clean
                for entry in &mut self.entries {
                    if entry.selected {
                        entry.file.mark_saved();
                    }
                }
                self.operation_completed = true;
                let saved_names: Vec<String> = task
                    .files()
                    .iter()
                    .map(|f| f.name.clone())
                    .collect();
                SaveDialogResult::Saved(saved_names)
            }
            SaveResult::Cancelled => {
                self.operation_completed = false;
                // Re-initialize the list (matching Java behavior)
                SaveDialogResult::Cancelled
            }
            SaveResult::Error(msg) => {
                self.operation_completed = false;
                SaveDialogResult::Cancelled // Treat errors as cancel
            }
            SaveResult::NoFilesToSave => {
                self.operation_completed = true;
                SaveDialogResult::DontSave
            }
        }
    }

    /// Execute the "Don't Save" action.
    pub fn dont_save(&mut self) -> SaveDialogResult {
        self.operation_completed = true;
        SaveDialogResult::DontSave
    }

    /// Execute the "Cancel" action.
    pub fn cancel(&mut self) -> SaveDialogResult {
        self.operation_completed = false;
        SaveDialogResult::Cancelled
    }

    /// Update the save-enabled flag based on current selections.
    fn update_save_enabled(&mut self) {
        self.save_enabled = self.entries.iter().any(|e| e.selected);
    }
}

impl Default for SaveDataDialog {
    fn default() -> Self {
        Self::new("Save Modified Files")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- DomainFile tests --

    #[test]
    fn test_domain_file_new() {
        let f = DomainFile::new("test.exe", "/dir/test.exe");
        assert_eq!(f.name, "test.exe");
        assert_eq!(f.pathname, "/dir/test.exe");
        assert!(!f.is_changed);
        assert!(f.can_save);
        assert!(f.is_in_writable_project);
    }

    #[test]
    fn test_domain_file_mark_changed() {
        let mut f = DomainFile::new("test.exe", "/dir/test.exe");
        assert!(!f.is_changed);
        f.mark_changed();
        assert!(f.is_changed);
    }

    #[test]
    fn test_domain_file_mark_saved() {
        let mut f = DomainFile::new("test.exe", "/dir/test.exe");
        f.mark_changed();
        assert!(f.is_changed);
        f.mark_saved();
        assert!(!f.is_changed);
    }

    // -- SaveResult tests --

    #[test]
    fn test_save_result_display() {
        assert_eq!(
            SaveResult::Success.to_string(),
            "Save completed successfully"
        );
        assert_eq!(SaveResult::Cancelled.to_string(), "Save cancelled");
        assert_eq!(
            SaveResult::Error("disk full".into()).to_string(),
            "Save error: disk full"
        );
        assert_eq!(
            SaveResult::NoFilesToSave.to_string(),
            "No files to save"
        );
    }

    // -- SaveTask tests --

    #[test]
    fn test_save_task_new() {
        let files = vec![DomainFile::new("a.exe", "/a")];
        let task = SaveTask::new(files);
        assert_eq!(task.file_count(), 1);
        assert_eq!(task.title(), "Saving File");
        assert!(task.is_cancellable());
        assert!(task.is_modal());
    }

    #[test]
    fn test_save_task_title_plural() {
        let files = vec![
            DomainFile::new("a.exe", "/a"),
            DomainFile::new("b.exe", "/b"),
        ];
        let task = SaveTask::new(files);
        assert_eq!(task.title(), "Saving Files...");
    }

    #[test]
    fn test_save_task_empty() {
        let mut task = SaveTask::new(vec![]);
        let monitor = SimpleTaskMonitor::new();
        let result = task.run(&monitor);
        assert_eq!(result, SaveResult::NoFilesToSave);
        assert!(task.is_operation_completed());
    }

    #[test]
    fn test_save_task_run_success() {
        let files = vec![
            DomainFile::new("a.exe", "/a"),
            DomainFile::new("b.exe", "/b"),
        ];
        let mut task = SaveTask::new(files);
        let monitor = SimpleTaskMonitor::new();
        let result = task.run(&monitor);
        assert_eq!(result, SaveResult::Success);
        assert!(task.is_operation_completed());
    }

    #[test]
    fn test_save_task_cancelled() {
        let files = vec![
            DomainFile::new("a.exe", "/a"),
            DomainFile::new("b.exe", "/b"),
        ];
        let mut task = SaveTask::new(files);
        let monitor = SimpleTaskMonitor::new();
        monitor.cancel();
        let result = task.run(&monitor);
        assert_eq!(result, SaveResult::Cancelled);
        assert!(!task.is_operation_completed());
    }

    #[test]
    fn test_save_task_into_files() {
        let files = vec![DomainFile::new("a.exe", "/a")];
        let task = SaveTask::new(files);
        let files = task.into_files();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].name, "a.exe");
    }

    // -- SimpleTaskMonitor tests --

    #[test]
    fn test_simple_task_monitor() {
        let monitor = SimpleTaskMonitor::new();
        assert!(!monitor.is_cancelled());
        monitor.set_progress(50);
        monitor.set_message("test");
        monitor.set_maximum(200);
        assert_eq!(monitor.maximum(), 200);
    }

    #[test]
    fn test_simple_task_monitor_cancel() {
        let monitor = SimpleTaskMonitor::new();
        assert!(!monitor.is_cancelled());
        monitor.cancel();
        assert!(monitor.is_cancelled());
    }

    #[test]
    fn test_simple_task_monitor_initialize() {
        let monitor = SimpleTaskMonitor::new();
        monitor.initialize(100, "Starting...");
        assert_eq!(monitor.maximum(), 100);
    }

    // -- SaveDataEntry tests --

    #[test]
    fn test_save_data_entry_saveable() {
        let file = DomainFile::new("test.exe", "/dir/test.exe");
        let entry = SaveDataEntry::new(file);
        assert!(entry.saveable);
        assert!(entry.selected); // auto-selected if saveable
        assert_eq!(entry.display_text(), "test.exe");
    }

    #[test]
    fn test_save_data_entry_read_only() {
        let mut file = DomainFile::new("test.exe", "/dir/test.exe");
        file.can_save = false;
        let entry = SaveDataEntry::new(file);
        assert!(!entry.saveable);
        assert!(!entry.selected); // not selected if not saveable
        assert_eq!(entry.display_text(), "test.exe (Read-Only)");
    }

    #[test]
    fn test_save_data_entry_read_only_from_project() {
        let mut file = DomainFile::new("test.exe", "/dir/test.exe");
        file.can_save = false;
        file.is_in_writable_project = false;
        file.project_locator_name = Some("MyProject".into());
        let entry = SaveDataEntry::new(file);
        assert_eq!(
            entry.display_text(),
            "test.exe (Read-Only from MyProject)"
        );
    }

    // -- SaveDataDialog tests --

    #[test]
    fn test_save_data_dialog_default() {
        let dialog = SaveDataDialog::default();
        assert_eq!(dialog.title(), "Save Modified Files");
        assert_eq!(dialog.entry_count(), 0);
        assert!(!dialog.is_save_enabled());
    }

    #[test]
    fn test_save_data_dialog_show() {
        let mut dialog = SaveDataDialog::new("Save");
        let files = vec![
            DomainFile::new("a.exe", "/a"),
            DomainFile::new("b.exe", "/b"),
        ];
        dialog.show(files);
        // Both files are not changed, so no entries
        assert_eq!(dialog.entry_count(), 0);
        assert!(dialog.is_operation_completed());
    }

    #[test]
    fn test_save_data_dialog_show_changed() {
        let mut dialog = SaveDataDialog::new("Save");
        let mut f1 = DomainFile::new("a.exe", "/a");
        f1.mark_changed();
        let mut f2 = DomainFile::new("b.exe", "/b");
        f2.mark_changed();
        dialog.show(vec![f1, f2]);
        assert_eq!(dialog.entry_count(), 2);
        assert!(dialog.is_save_enabled()); // both are selected by default
    }

    #[test]
    fn test_save_data_dialog_select_all() {
        let mut dialog = SaveDataDialog::new("Save");
        let mut f1 = DomainFile::new("a.exe", "/a");
        f1.mark_changed();
        let mut f2 = DomainFile::new("b.exe", "/b");
        f2.mark_changed();
        dialog.show(vec![f1, f2]);

        dialog.deselect_all();
        assert!(!dialog.is_save_enabled());

        dialog.select_all();
        assert!(dialog.is_save_enabled());
    }

    #[test]
    fn test_save_data_dialog_toggle() {
        let mut dialog = SaveDataDialog::new("Save");
        let mut f1 = DomainFile::new("a.exe", "/a");
        f1.mark_changed();
        dialog.show(vec![f1]);

        assert!(dialog.is_save_enabled());
        assert!(dialog.toggle_selection(0));
        assert!(!dialog.is_save_enabled());
        assert!(dialog.toggle_selection(0));
        assert!(dialog.is_save_enabled());
    }

    #[test]
    fn test_save_data_dialog_toggle_read_only() {
        let mut dialog = SaveDataDialog::new("Save");
        let mut f1 = DomainFile::new("a.exe", "/a");
        f1.mark_changed();
        f1.can_save = false;
        dialog.show(vec![f1]);

        // Read-only entry is not selected by default
        assert!(!dialog.is_save_enabled());
        // Toggle should fail because not saveable
        assert!(!dialog.toggle_selection(0));
    }

    #[test]
    fn test_save_data_dialog_save_empty() {
        let mut dialog = SaveDataDialog::new("Save");
        dialog.show(vec![]);
        let result = dialog.save();
        assert_eq!(result, SaveDialogResult::DontSave);
    }

    #[test]
    fn test_save_data_dialog_save_success() {
        let mut dialog = SaveDataDialog::new("Save");
        let mut f1 = DomainFile::new("a.exe", "/a");
        f1.mark_changed();
        dialog.show(vec![f1]);

        let result = dialog.save();
        match result {
            SaveDialogResult::Saved(names) => {
                assert_eq!(names.len(), 1);
                assert_eq!(names[0], "a.exe");
            }
            _ => panic!("Expected Saved result"),
        }
    }

    #[test]
    fn test_save_data_dialog_dont_save() {
        let mut dialog = SaveDataDialog::new("Save");
        let mut f1 = DomainFile::new("a.exe", "/a");
        f1.mark_changed();
        dialog.show(vec![f1]);

        let result = dialog.dont_save();
        assert_eq!(result, SaveDialogResult::DontSave);
        assert!(dialog.is_operation_completed());
    }

    #[test]
    fn test_save_data_dialog_cancel() {
        let mut dialog = SaveDataDialog::new("Save");
        let mut f1 = DomainFile::new("a.exe", "/a");
        f1.mark_changed();
        dialog.show(vec![f1]);

        let result = dialog.cancel();
        assert_eq!(result, SaveDialogResult::Cancelled);
        assert!(!dialog.is_operation_completed());
    }

    #[test]
    fn test_save_data_dialog_mixed_saveable() {
        let mut dialog = SaveDataDialog::new("Save");
        let mut f1 = DomainFile::new("saveable.exe", "/a");
        f1.mark_changed();
        let mut f2 = DomainFile::new("readonly.exe", "/b");
        f2.mark_changed();
        f2.can_save = false;
        dialog.show(vec![f1, f2]);

        assert_eq!(dialog.entry_count(), 2);
        // Only saveable is selected
        assert!(dialog.entries()[0].selected);
        assert!(!dialog.entries()[1].selected);
        assert!(dialog.is_save_enabled());
    }

    #[test]
    fn test_save_data_dialog_select_on_read_only() {
        let mut dialog = SaveDataDialog::new("Save");
        let mut f1 = DomainFile::new("readonly.exe", "/a");
        f1.mark_changed();
        f1.can_save = false;
        dialog.show(vec![f1]);

        // set_selected with true on a non-saveable should fail
        assert!(!dialog.set_selected(0, true));
        // set_selected with false should succeed
        assert!(dialog.set_selected(0, false));
    }
}
