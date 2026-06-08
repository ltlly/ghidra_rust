//! GhidraProject -- batch-mode project management.
//!
//! Ported from `ghidra.base.project.GhidraProject` (812 lines Java).
//!
//! Provides a helper class for using Ghidra in "batch" (headless) mode.
//! Supports creating/opening projects, importing programs, running
//! analysis, saving, and closing.
//!
//! # Key Types
//!
//! - [`GhidraProject`] -- The main batch-mode project handle
//! - [`ProjectState`] -- Lifecycle state of the project
//! - [`ProjectInfo`] -- Metadata about a project
//! - [`ProgramRecord`] -- Tracks an opened program and its transaction
//! - [`ImportResult`] -- Result of a program import operation

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// ProjectState -- lifecycle state
// ---------------------------------------------------------------------------

/// Lifecycle state of a Ghidra project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectState {
    /// Project is open and usable.
    Open,
    /// Project has been closed.
    Closed,
    /// Project was closed and deleted (temporary projects).
    Deleted,
}

// ---------------------------------------------------------------------------
// ProjectInfo -- metadata about a project
// ---------------------------------------------------------------------------

/// Metadata about a Ghidra project.
#[derive(Debug, Clone)]
pub struct ProjectInfo {
    /// Name of the project.
    pub name: String,
    /// Parent directory containing the project.
    pub parent_dir: PathBuf,
    /// Whether the project is temporary (deleted on close).
    pub temporary: bool,
    /// Whether the project is shared (remote repository).
    pub shared: bool,
    /// Optional remote repository host.
    pub repository_host: Option<String>,
    /// Optional remote repository port.
    pub repository_port: Option<u16>,
}

impl ProjectInfo {
    /// Create project info for a local project.
    pub fn local(name: impl Into<String>, parent_dir: PathBuf, temporary: bool) -> Self {
        Self {
            name: name.into(),
            parent_dir,
            temporary,
            shared: false,
            repository_host: None,
            repository_port: None,
        }
    }

    /// Create project info for a shared (remote) project.
    pub fn shared(
        name: impl Into<String>,
        parent_dir: PathBuf,
        host: impl Into<String>,
        port: u16,
    ) -> Self {
        Self {
            name: name.into(),
            parent_dir,
            temporary: false,
            shared: true,
            repository_host: Some(host.into()),
            repository_port: Some(port),
        }
    }

    /// Get the full path to the project directory.
    pub fn project_path(&self) -> PathBuf {
        self.parent_dir.join(&self.name)
    }
}

impl fmt::Display for ProjectInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)?;
        if self.shared {
            write!(
                f,
                " [shared: {}:{}]",
                self.repository_host.as_deref().unwrap_or("unknown"),
                self.repository_port.unwrap_or(0)
            )?;
        }
        if self.temporary {
            write!(f, " [temporary]")?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ProgramRecord -- tracks an opened program
// ---------------------------------------------------------------------------

/// Tracks an opened program within a project.
#[derive(Debug, Clone)]
pub struct ProgramRecord {
    /// The program name.
    pub name: String,
    /// The folder path within the project.
    pub folder_path: String,
    /// Transaction ID (negative = no active transaction).
    pub transaction_id: i32,
    /// Whether the program is read-only.
    pub read_only: bool,
    /// Whether the program has been modified.
    pub modified: bool,
}

impl ProgramRecord {
    /// Create a new program record.
    pub fn new(name: impl Into<String>, folder_path: impl Into<String>, read_only: bool) -> Self {
        Self {
            name: name.into(),
            folder_path: folder_path.into(),
            transaction_id: -1,
            read_only,
            modified: false,
        }
    }

    /// Begin a transaction (returns the transaction ID).
    pub fn begin_transaction(&mut self) -> i32 {
        self.transaction_id += 1;
        self.transaction_id
    }

    /// End the current transaction.
    pub fn end_transaction(&mut self, commit: bool) {
        if commit {
            self.modified = true;
        }
        self.transaction_id = -1;
    }

    /// Check if there is an active transaction.
    pub fn has_transaction(&self) -> bool {
        self.transaction_id >= 0
    }
}

// ---------------------------------------------------------------------------
// ImportResult -- result of a program import
// ---------------------------------------------------------------------------

/// Result of importing a program into a project.
#[derive(Debug, Clone)]
pub struct ImportResult {
    /// The imported program name.
    pub program_name: String,
    /// The folder path where it was stored.
    pub folder_path: String,
    /// The path to the source file that was imported.
    pub source_path: PathBuf,
    /// Whether the import succeeded.
    pub success: bool,
    /// Error message if the import failed.
    pub error: Option<String>,
    /// Language/compiler-spec used for the import.
    pub language_id: Option<String>,
    pub compiler_spec_id: Option<String>,
}

impl ImportResult {
    /// Create a successful import result.
    pub fn success(
        name: impl Into<String>,
        folder: impl Into<String>,
        source: PathBuf,
    ) -> Self {
        Self {
            program_name: name.into(),
            folder_path: folder.into(),
            source_path: source,
            success: true,
            error: None,
            language_id: None,
            compiler_spec_id: None,
        }
    }

    /// Create a failed import result.
    pub fn failure(source: PathBuf, error: impl Into<String>) -> Self {
        Self {
            program_name: String::new(),
            folder_path: String::new(),
            source_path: source,
            success: false,
            error: Some(error.into()),
            language_id: None,
            compiler_spec_id: None,
        }
    }

    /// Set the language/compiler-spec used.
    pub fn with_language(
        mut self,
        language_id: impl Into<String>,
        compiler_spec_id: impl Into<String>,
    ) -> Self {
        self.language_id = Some(language_id.into());
        self.compiler_spec_id = Some(compiler_spec_id.into());
        self
    }
}

// ---------------------------------------------------------------------------
// GhidraProject -- the batch-mode project handle
// ---------------------------------------------------------------------------

/// Helper class for using Ghidra in "batch" (headless) mode.
///
/// Provides methods for creating, opening, importing, analyzing,
/// saving, and closing programs within a Ghidra project.
///
/// Ported from `ghidra.base.project.GhidraProject`.
#[derive(Debug)]
pub struct GhidraProject {
    /// Project metadata.
    pub info: ProjectInfo,
    /// Current lifecycle state.
    pub state: ProjectState,
    /// Opened programs.
    pub open_programs: HashMap<String, ProgramRecord>,
    /// Import history.
    pub import_history: Vec<ImportResult>,
    /// Whether to delete the project on close.
    delete_on_close: bool,
}

impl GhidraProject {
    /// Create a new Ghidra project.
    pub fn create(
        parent_dir: impl Into<PathBuf>,
        name: impl Into<String>,
        temporary: bool,
    ) -> Self {
        let info = ProjectInfo::local(name, parent_dir.into(), temporary);
        Self {
            delete_on_close: temporary,
            info,
            state: ProjectState::Open,
            open_programs: HashMap::new(),
            import_history: Vec::new(),
        }
    }

    /// Open an existing project.
    pub fn open(parent_dir: impl Into<PathBuf>, name: impl Into<String>) -> Self {
        let info = ProjectInfo::local(name, parent_dir.into(), false);
        Self {
            delete_on_close: false,
            info,
            state: ProjectState::Open,
            open_programs: HashMap::new(),
            import_history: Vec::new(),
        }
    }

    /// Check if the project is open.
    pub fn is_open(&self) -> bool {
        self.state == ProjectState::Open
    }

    /// Get the project name.
    pub fn name(&self) -> &str {
        &self.info.name
    }

    /// Get the project path.
    pub fn project_path(&self) -> PathBuf {
        self.info.project_path()
    }

    /// Set whether the project should be deleted on close.
    pub fn set_delete_on_close(&mut self, delete: bool) {
        self.delete_on_close = delete;
    }

    /// Import a program into the project.
    pub fn import_program(
        &mut self,
        source_path: &Path,
        folder_path: &str,
    ) -> ImportResult {
        if self.state != ProjectState::Open {
            return ImportResult::failure(source_path.to_path_buf(), "Project is not open");
        }

        if !source_path.exists() {
            return ImportResult::failure(
                source_path.to_path_buf(),
                format!("File not found: {}", source_path.display()),
            );
        }

        let name = source_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let mut record = ProgramRecord::new(&name, folder_path, false);
        record.begin_transaction();

        let result = ImportResult::success(&name, folder_path, source_path.to_path_buf());
        self.open_programs.insert(name.clone(), record);
        self.import_history.push(result.clone());
        result
    }

    /// Open an existing program from the project.
    pub fn open_program(
        &mut self,
        folder_path: &str,
        name: &str,
        read_only: bool,
    ) -> Result<&ProgramRecord, String> {
        if self.state != ProjectState::Open {
            return Err("Project is not open".to_string());
        }

        let key = name.to_string();
        if self.open_programs.contains_key(&key) {
            return Err(format!("Program '{}' is already open", name));
        }

        let mut record = ProgramRecord::new(name, folder_path, read_only);
        record.begin_transaction();
        self.open_programs.insert(key.clone(), record);
        Ok(self.open_programs.get(&key).unwrap())
    }

    /// Close a specific program.
    pub fn close_program(&mut self, name: &str) -> bool {
        if let Some(mut record) = self.open_programs.remove(name) {
            if record.has_transaction() {
                record.end_transaction(false); // discard changes
            }
            true
        } else {
            false
        }
    }

    /// Save a specific program.
    pub fn save_program(&mut self, name: &str, commit: bool) -> bool {
        if let Some(record) = self.open_programs.get_mut(name) {
            if record.has_transaction() {
                record.end_transaction(commit);
                record.begin_transaction(); // start new transaction
            }
            true
        } else {
            false
        }
    }

    /// Save all open programs.
    pub fn save_all(&mut self) {
        for record in self.open_programs.values_mut() {
            if record.has_transaction() {
                record.end_transaction(true);
                record.begin_transaction();
            }
        }
    }

    /// Close the project, releasing all programs.
    pub fn close(&mut self) {
        for (_, mut record) in self.open_programs.drain() {
            if record.has_transaction() {
                record.end_transaction(false);
            }
        }

        self.state = if self.delete_on_close {
            ProjectState::Deleted
        } else {
            ProjectState::Closed
        };
    }

    /// Get the number of open programs.
    pub fn open_program_count(&self) -> usize {
        self.open_programs.len()
    }

    /// Get a list of open program names.
    pub fn open_program_names(&self) -> Vec<&str> {
        self.open_programs.keys().map(|s| s.as_str()).collect()
    }

    /// Get the import history.
    pub fn import_history(&self) -> &[ImportResult] {
        &self.import_history
    }
}

impl Drop for GhidraProject {
    fn drop(&mut self) {
        if self.state == ProjectState::Open {
            self.close();
        }
    }
}

// ---------------------------------------------------------------------------
// Application -- initialization check for batch mode
// ---------------------------------------------------------------------------

/// Represents the Ghidra application initialization state.
///
/// Ported from `ghidra.framework.Application`.
#[derive(Debug)]
pub struct GhidraApplication {
    /// Whether the application has been initialized.
    initialized: bool,
    /// The Ghidra installation directory.
    install_dir: Option<PathBuf>,
    /// Application version string.
    version: String,
}

impl GhidraApplication {
    /// Create a new application instance (not yet initialized).
    pub fn new() -> Self {
        Self {
            initialized: false,
            install_dir: None,
            version: "0.0.0".to_string(),
        }
    }

    /// Initialize the application.
    pub fn initialize(&mut self, install_dir: PathBuf) {
        self.install_dir = Some(install_dir);
        self.initialized = true;
    }

    /// Check if the application is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the installation directory.
    pub fn install_dir(&self) -> Option<&Path> {
        self.install_dir.as_deref()
    }

    /// Set the version string.
    pub fn set_version(&mut self, version: impl Into<String>) {
        self.version = version.into();
    }

    /// Get the version string.
    pub fn version(&self) -> &str {
        &self.version
    }
}

impl Default for GhidraApplication {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_project_create_and_close() {
        let mut project = GhidraProject::create("/tmp/projects", "TestProject", false);
        assert!(project.is_open());
        assert_eq!(project.name(), "TestProject");
        assert_eq!(project.state, ProjectState::Open);

        project.close();
        assert!(!project.is_open());
        assert_eq!(project.state, ProjectState::Closed);
    }

    #[test]
    fn test_project_temporary() {
        let mut project = GhidraProject::create("/tmp/projects", "TempProject", true);
        assert!(project.delete_on_close);

        project.close();
        assert_eq!(project.state, ProjectState::Deleted);
    }

    #[test]
    fn test_project_open() {
        let project = GhidraProject::open("/tmp/projects", "ExistingProject");
        assert!(project.is_open());
        assert!(!project.delete_on_close);
    }

    #[test]
    fn test_project_import_program() {
        // Create a temporary file for testing
        let tmp_dir = std::env::temp_dir();
        let test_file = tmp_dir.join("test_import.bin");
        std::fs::write(&test_file, b"TEST").unwrap();

        let mut project = GhidraProject::create(&tmp_dir, "ImportTest", true);
        let result = project.import_program(&test_file, "/");
        assert!(result.success);
        assert_eq!(result.program_name, "test_import.bin");
        assert_eq!(result.folder_path, "/");
        assert_eq!(project.open_program_count(), 1);

        // Clean up
        project.close();
        let _ = std::fs::remove_file(&test_file);
    }

    #[test]
    fn test_project_import_nonexistent() {
        let mut project = GhidraProject::create("/tmp", "ErrTest", true);
        let result = project.import_program(Path::new("/nonexistent/file.bin"), "/");
        assert!(!result.success);
        assert!(result.error.is_some());
        assert!(result.error.unwrap().contains("File not found"));
    }

    #[test]
    fn test_project_import_closed_project() {
        let mut project = GhidraProject::create("/tmp", "ClosedTest", true);
        project.close();

        let result = import_program_closed(&mut project, "/tmp/test.bin", "/");
        assert!(!result.success);
    }

    fn import_program_closed(project: &mut GhidraProject, path: &str, folder: &str) -> ImportResult {
        project.import_program(Path::new(path), folder)
    }

    #[test]
    fn test_project_open_and_close_program() {
        let mut project = GhidraProject::create("/tmp", "ProgTest", true);

        let record = project.open_program("/", "test.exe", false);
        assert!(record.is_ok());
        assert_eq!(project.open_program_count(), 1);

        // Opening same program again should fail
        let dup = project.open_program("/", "test.exe", false);
        assert!(dup.is_err());

        // Close the program
        assert!(project.close_program("test.exe"));
        assert_eq!(project.open_program_count(), 0);

        // Closing non-existent program returns false
        assert!(!project.close_program("nonexistent.exe"));
    }

    #[test]
    fn test_project_save_program() {
        let mut project = GhidraProject::create("/tmp", "SaveTest", true);
        let _ = project.open_program("/", "test.exe", false);

        assert!(project.save_program("test.exe", true));
        assert!(!project.save_program("nonexistent.exe", true));
    }

    #[test]
    fn test_project_save_all() {
        let mut project = GhidraProject::create("/tmp", "SaveAllTest", true);
        let _ = project.open_program("/", "a.exe", false);
        let _ = project.open_program("/", "b.exe", false);

        project.save_all();
        assert_eq!(project.open_program_count(), 2);
    }

    #[test]
    fn test_project_list_programs() {
        let mut project = GhidraProject::create("/tmp", "ListTest", true);
        let _ = project.open_program("/", "alpha.exe", false);
        let _ = project.open_program("/", "beta.exe", false);

        let names = project.open_program_names();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"alpha.exe"));
        assert!(names.contains(&"beta.exe"));
    }

    #[test]
    fn test_program_record() {
        let mut record = ProgramRecord::new("test.exe", "/", false);
        assert!(!record.has_transaction());
        assert!(!record.modified);

        let txn = record.begin_transaction();
        assert_eq!(txn, 0);
        assert!(record.has_transaction());

        record.end_transaction(true);
        assert!(!record.has_transaction());
        assert!(record.modified);
    }

    #[test]
    fn test_import_result() {
        let success = ImportResult::success("test.exe", "/", PathBuf::from("/tmp/test.exe"))
            .with_language("x86:LE:64:default", "default");
        assert!(success.success);
        assert_eq!(success.language_id, Some("x86:LE:64:default".to_string()));

        let failure = ImportResult::failure(PathBuf::from("/tmp/missing.bin"), "Not found");
        assert!(!failure.success);
        assert!(failure.error.is_some());
    }

    #[test]
    fn test_project_info() {
        let local = ProjectInfo::local("MyProject", PathBuf::from("/tmp/projects"), false);
        assert_eq!(local.name, "MyProject");
        assert!(!local.shared);
        assert_eq!(local.project_path(), PathBuf::from("/tmp/projects/MyProject"));
        assert_eq!(format!("{local}"), "MyProject");

        let shared = ProjectInfo::shared(
            "SharedProject",
            PathBuf::from("/tmp/projects"),
            "ghidra-server.local",
            13100,
        );
        assert!(shared.shared);
        assert_eq!(shared.repository_host, Some("ghidra-server.local".to_string()));
        assert!(format!("{shared}").contains("ghidra-server.local"));

        let temp = ProjectInfo::local("TempProject", PathBuf::from("/tmp"), true);
        assert!(temp.temporary);
        assert!(format!("{temp}").contains("temporary"));
    }

    #[test]
    fn test_ghidra_application() {
        let mut app = GhidraApplication::new();
        assert!(!app.is_initialized());
        assert_eq!(app.version(), "0.0.0");

        app.initialize(PathBuf::from("/opt/ghidra"));
        assert!(app.is_initialized());
        assert_eq!(app.install_dir(), Some(Path::new("/opt/ghidra")));

        app.set_version("11.0");
        assert_eq!(app.version(), "11.0");
    }

    #[test]
    fn test_project_import_history() {
        let tmp_dir = std::env::temp_dir();
        let test_file1 = tmp_dir.join("test1.bin");
        let test_file2 = tmp_dir.join("test2.bin");
        std::fs::write(&test_file1, b"TEST1").unwrap();
        std::fs::write(&test_file2, b"TEST2").unwrap();

        let mut project = GhidraProject::create(&tmp_dir, "HistoryTest", true);
        project.import_program(&test_file1, "/");
        project.import_program(&test_file2, "/subdir");

        let history = project.import_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].program_name, "test1.bin");
        assert_eq!(history[1].folder_path, "/subdir");

        project.close();
        let _ = std::fs::remove_file(&test_file1);
        let _ = std::fs::remove_file(&test_file2);
    }
}
