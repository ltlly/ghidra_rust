//! PyGhidra: Python integration for Ghidra.
//!
//! Ported from Ghidra's `ghidra.pyghidra` Java package.  Provides
//! the core data structures and traits for running Python scripts
//! within a Ghidra analysis session.
//!
//! # Components
//!
//! - [`PyGhidraPlugin`] -- the interactive Python interpreter plugin.
//! - [`PyGhidraProject`] -- a project wrapper for PyGhidra sessions.
//! - [`PyGhidraProjectManager`] -- manages the lifecycle of PyGhidra projects.
//! - [`JavaProperty`] -- property wrapper for bridging Java/Rust getters/setters
//!   to Python's property protocol.
//! - [`PyGhidraScriptProvider`] -- script provider for `.py` scripts.
//! - [`PythonFieldExposer`] -- exposes struct fields to Python.
//! - [`PyGhidraTaskMonitor`] -- task monitor for long-running Python scripts.

pub mod property;
pub mod script_provider;

pub use property::{JavaProperty, JavaPropertyKind, PropertyUtils};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// PyGhidraPlugin
// ---------------------------------------------------------------------------

/// The PyGhidra interactive interpreter plugin.
///
/// Matches Java's `ghidra.pyghidra.PyGhidraPlugin`.  In the Rust port,
/// this is a container for the interpreter state rather than a GUI plugin.
pub struct PyGhidraPlugin {
    /// The title of this plugin.
    title: String,
    /// Current program being analyzed (name or identifier).
    current_program: Arc<Mutex<Option<String>>>,
    /// Current address/location in the program.
    current_location: Arc<Mutex<Option<String>>>,
    /// Current selection in the program.
    current_selection: Arc<Mutex<Option<String>>>,
    /// Current highlight in the program.
    current_highlight: Arc<Mutex<Option<String>>>,
    /// The Python-side initializer (stored as a name for later invocation).
    initializer_set: Arc<Mutex<bool>>,
}

impl PyGhidraPlugin {
    /// The default plugin title.
    pub const TITLE: &'static str = "PyGhidra";

    /// Create a new PyGhidra plugin.
    pub fn new() -> Self {
        Self {
            title: Self::TITLE.to_string(),
            current_program: Arc::new(Mutex::new(None)),
            current_location: Arc::new(Mutex::new(None)),
            current_selection: Arc::new(Mutex::new(None)),
            current_highlight: Arc::new(Mutex::new(None)),
            initializer_set: Arc::new(Mutex::new(false)),
        }
    }

    /// Set the current program.
    pub fn set_current_program(&self, program: Option<String>) {
        if let Ok(mut p) = self.current_program.lock() {
            *p = program;
        }
    }

    /// Get the current program name.
    pub fn current_program(&self) -> Option<String> {
        self.current_program.lock().ok().and_then(|p| p.clone())
    }

    /// Set the current location.
    pub fn set_current_location(&self, location: Option<String>) {
        if let Ok(mut l) = self.current_location.lock() {
            *l = location;
        }
    }

    /// Set the current selection.
    pub fn set_current_selection(&self, selection: Option<String>) {
        if let Ok(mut s) = self.current_selection.lock() {
            *s = selection;
        }
    }

    /// Set the current highlight.
    pub fn set_current_highlight(&self, highlight: Option<String>) {
        if let Ok(mut h) = self.current_highlight.lock() {
            *h = highlight;
        }
    }

    /// Whether the Python-side initializer has been set.
    pub fn has_initializer(&self) -> bool {
        self.initializer_set.lock().map(|v| *v).unwrap_or(false)
    }

    /// Mark the initializer as set.  Panics if already set.
    pub fn set_initializer(&self) {
        let mut init = self.initializer_set.lock().unwrap();
        if *init {
            panic!("PyGhidraPlugin initializer has already been set");
        }
        *init = true;
    }
}

impl Default for PyGhidraPlugin {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PyGhidraProject
// ---------------------------------------------------------------------------

/// A project wrapper for PyGhidra sessions.
///
/// Matches Java's `ghidra.pyghidra.PyGhidraProject`.
pub struct PyGhidraProject {
    /// The project name.
    name: String,
    /// The project directory.
    directory: PathBuf,
    /// Whether the project is currently open.
    is_open: bool,
}

impl PyGhidraProject {
    /// Create a new PyGhidra project.
    pub fn new(name: impl Into<String>, directory: PathBuf) -> Self {
        Self {
            name: name.into(),
            directory,
            is_open: false,
        }
    }

    /// Open the project.
    pub fn open(&mut self) {
        self.is_open = true;
    }

    /// Close the project.
    pub fn close(&mut self) {
        self.is_open = false;
    }

    /// Whether the project is currently open.
    pub fn is_open(&self) -> bool {
        self.is_open
    }

    /// The project name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The project directory.
    pub fn directory(&self) -> &PathBuf {
        &self.directory
    }
}

// ---------------------------------------------------------------------------
// PyGhidraProjectManager
// ---------------------------------------------------------------------------

/// Manages the lifecycle of PyGhidra projects.
///
/// Matches Java's `ghidra.pyghidra.PyGhidraProjectManager`.
pub struct PyGhidraProjectManager {
    projects: HashMap<String, PyGhidraProject>,
}

impl PyGhidraProjectManager {
    /// Create a new project manager.
    pub fn new() -> Self {
        Self {
            projects: HashMap::new(),
        }
    }

    /// Create a new project.
    pub fn create_project(
        &mut self,
        name: impl Into<String>,
        directory: PathBuf,
    ) -> &mut PyGhidraProject {
        let name = name.into();
        let project = PyGhidraProject::new(&name, directory);
        self.projects.insert(name.clone(), project);
        self.projects.get_mut(&name).unwrap()
    }

    /// Open an existing project by name.
    pub fn open_project(&mut self, name: &str) -> Option<&mut PyGhidraProject> {
        if let Some(project) = self.projects.get_mut(name) {
            project.open();
            Some(project)
        } else {
            None
        }
    }

    /// Close a project by name.
    pub fn close_project(&mut self, name: &str) {
        if let Some(project) = self.projects.get_mut(name) {
            project.close();
        }
    }

    /// Close all projects.
    pub fn close_all(&mut self) {
        for project in self.projects.values_mut() {
            project.close();
        }
    }

    /// Get the number of managed projects.
    pub fn project_count(&self) -> usize {
        self.projects.len()
    }

    /// Get a reference to a project by name.
    pub fn get_project(&self, name: &str) -> Option<&PyGhidraProject> {
        self.projects.get(name)
    }
}

impl Default for PyGhidraProjectManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PyGhidraTaskMonitor
// ---------------------------------------------------------------------------

/// A task monitor for long-running Python scripts.
///
/// Matches Java's `ghidra.pyghidra.PyGhidraTaskMonitor`.
#[derive(Debug, Clone)]
pub struct PyGhidraTaskMonitor {
    /// Whether cancellation has been requested.
    cancelled: Arc<Mutex<bool>>,
    /// Current progress message.
    message: Arc<Mutex<String>>,
    /// Current progress value (0-100).
    progress: Arc<Mutex<u32>>,
    /// Maximum progress value.
    maximum: Arc<Mutex<u32>>,
}

impl PyGhidraTaskMonitor {
    /// Create a new task monitor.
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(Mutex::new(false)),
            message: Arc::new(Mutex::new(String::new())),
            progress: Arc::new(Mutex::new(0)),
            maximum: Arc::new(Mutex::new(100)),
        }
    }

    /// Request cancellation.
    pub fn cancel(&self) {
        if let Ok(mut c) = self.cancelled.lock() {
            *c = true;
        }
    }

    /// Check if cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.lock().map(|v| *v).unwrap_or(false)
    }

    /// Set the progress message.
    pub fn set_message(&self, msg: impl Into<String>) {
        if let Ok(mut m) = self.message.lock() {
            *m = msg.into();
        }
    }

    /// Get the current progress message.
    pub fn message(&self) -> String {
        self.message.lock().map(|m| m.clone()).unwrap_or_default()
    }

    /// Set the progress value.
    pub fn set_progress(&self, value: u32) {
        if let Ok(mut p) = self.progress.lock() {
            *p = value;
        }
    }

    /// Get the current progress value.
    pub fn progress(&self) -> u32 {
        self.progress.lock().map(|v| *v).unwrap_or(0)
    }

    /// Set the maximum progress value.
    pub fn set_maximum(&self, value: u32) {
        if let Ok(mut m) = self.maximum.lock() {
            *m = value;
        }
    }

    /// Get the maximum progress value.
    pub fn maximum(&self) -> u32 {
        self.maximum.lock().map(|v| *v).unwrap_or(100)
    }

    /// Check cancellation and return an error if cancelled.
    pub fn check_cancelled(&self) -> Result<(), PyGhidraError> {
        if self.is_cancelled() {
            Err(PyGhidraError::Cancelled)
        } else {
            Ok(())
        }
    }
}

impl Default for PyGhidraTaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PythonFieldExposer
// ---------------------------------------------------------------------------

/// Exposes struct fields to Python via property descriptors.
///
/// Matches Java's `ghidra.pyghidra.PythonFieldExposer`.
pub struct PythonFieldExposer {
    fields: HashMap<String, JavaPropertyKind>,
}

impl PythonFieldExposer {
    /// Create a new field exposer.
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }

    /// Add a field to be exposed.
    pub fn add_field(&mut self, name: impl Into<String>, kind: JavaPropertyKind) {
        self.fields.insert(name.into(), kind);
    }

    /// Get the list of exposed field names.
    pub fn field_names(&self) -> Vec<&str> {
        self.fields.keys().map(|s| s.as_str()).collect()
    }

    /// Get the property kind for a field.
    pub fn field_kind(&self, name: &str) -> Option<&JavaPropertyKind> {
        self.fields.get(name)
    }

    /// The number of exposed fields.
    pub fn field_count(&self) -> usize {
        self.fields.len()
    }
}

impl Default for PythonFieldExposer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PyGhidraError
// ---------------------------------------------------------------------------

/// Errors produced by PyGhidra operations.
#[derive(Debug, Clone)]
pub enum PyGhidraError {
    /// The operation was cancelled.
    Cancelled,
    /// An I/O error occurred.
    Io(String),
    /// A Python-side error occurred.
    PythonError(String),
    /// Generic error.
    Other(String),
}

impl std::fmt::Display for PyGhidraError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cancelled => write!(f, "operation cancelled"),
            Self::Io(msg) => write!(f, "I/O error: {msg}"),
            Self::PythonError(msg) => write!(f, "Python error: {msg}"),
            Self::Other(msg) => write!(f, "error: {msg}"),
        }
    }
}

impl std::error::Error for PyGhidraError {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pyghidra_plugin_lifecycle() {
        let plugin = PyGhidraPlugin::new();
        assert_eq!(plugin.title, PyGhidraPlugin::TITLE);
        assert!(plugin.current_program().is_none());
        assert!(!plugin.has_initializer());

        plugin.set_current_program(Some("test.exe".into()));
        assert_eq!(plugin.current_program(), Some("test.exe".into()));
    }

    #[test]
    #[should_panic(expected = "initializer has already been set")]
    fn test_double_initializer_panics() {
        let plugin = PyGhidraPlugin::new();
        plugin.set_initializer();
        plugin.set_initializer(); // should panic
    }

    #[test]
    fn test_pyghidra_project() {
        let mut project = PyGhidraProject::new("my_project", PathBuf::from("/tmp/proj"));
        assert_eq!(project.name(), "my_project");
        assert!(!project.is_open());

        project.open();
        assert!(project.is_open());

        project.close();
        assert!(!project.is_open());
    }

    #[test]
    fn test_project_manager() {
        let mut mgr = PyGhidraProjectManager::new();
        assert_eq!(mgr.project_count(), 0);

        mgr.create_project("proj1", PathBuf::from("/tmp/p1"));
        assert_eq!(mgr.project_count(), 1);

        assert!(mgr.open_project("proj1").is_some());
        assert!(mgr.get_project("proj1").unwrap().is_open());

        mgr.close_all();
        assert!(!mgr.get_project("proj1").unwrap().is_open());
    }

    #[test]
    fn test_task_monitor() {
        let monitor = PyGhidraTaskMonitor::new();
        assert!(!monitor.is_cancelled());
        assert_eq!(monitor.progress(), 0);

        monitor.set_message("Working...");
        assert_eq!(monitor.message(), "Working...");

        monitor.set_progress(50);
        assert_eq!(monitor.progress(), 50);

        monitor.cancel();
        assert!(monitor.is_cancelled());
        assert!(monitor.check_cancelled().is_err());
    }

    #[test]
    fn test_field_exposer() {
        let mut exposer = PythonFieldExposer::new();
        exposer.add_field("name", JavaPropertyKind::Object);
        exposer.add_field("count", JavaPropertyKind::Integer);
        exposer.add_field("active", JavaPropertyKind::Boolean);

        assert_eq!(exposer.field_count(), 3);
        assert!(exposer.field_names().contains(&"name"));
        assert_eq!(
            exposer.field_kind("count"),
            Some(&JavaPropertyKind::Integer)
        );
    }
}
