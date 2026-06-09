//! ProgramManager -- service interface for managing open programs.
//!
//! Ported from `ghidra.app.services.ProgramManager` (Features/Base).
//!
//! Defines the `ProgramManager` trait and supporting types.  Multiple
//! programs may be open in a tool, but only one is active at any given
//! time.
//!
//! The `ProgramManager` trait mirrors the Java `@ServiceInfo` interface
//! and is implemented by `ProgramManagerPlugin` in the `progmgr` module.
//!
//! # Open modes
//!
//! Programs can be opened in three modes:
//! - [`OpenMode::Hidden`] -- open but not visible (for background use)
//! - [`OpenMode::Current`] -- open and becomes the active program
//! - [`OpenMode::Visible`] -- open and visible, but does not change the
//!   active program
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::program::program_manager::*;
//! use std::sync::Arc;
//!
//! let mut mgr = InMemoryProgramManager::new();
//!
//! let prog = ProgramRef::new("test.exe");
//! mgr.open_program_ref(prog.clone(), OpenMode::Current);
//!
//! assert_eq!(mgr.current_program().map(|p| p.name.clone()), Some("test.exe".into()));
//! assert_eq!(mgr.all_open_programs().len(), 1);
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Core reference types
// ---------------------------------------------------------------------------

/// Lightweight reference to an open program.
///
/// In the full Ghidra implementation this wraps a `ghidra.program.model.listing.Program`.
/// Here we use a name-based handle so the service layer can be tested
/// independently of the core data model.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProgramRef {
    /// The program name.
    pub name: String,
    /// Optional domain file path.
    pub domain_path: Option<String>,
}

impl ProgramRef {
    /// Create a new program reference by name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            domain_path: None,
        }
    }

    /// Create a new program reference with a domain file path.
    pub fn with_path(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            domain_path: Some(path.into()),
        }
    }
}

impl fmt::Display for ProgramRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.domain_path {
            Some(path) => write!(f, "{} ({})", self.name, path),
            None => write!(f, "{}", self.name),
        }
    }
}

/// Reference to a domain file (for opening programs from the file system).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainFileRef {
    /// The full path to the domain file.
    pub path: String,
}

impl DomainFileRef {
    pub fn new(path: impl Into<String>) -> Self {
        Self { path: path.into() }
    }
}

/// A program address (placeholder).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address(pub u64);

// ---------------------------------------------------------------------------
// Open mode
// ---------------------------------------------------------------------------

/// Mode for opening a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// Open in hidden state (for background use with persistent owners).
    Hidden = 0,
    /// Open as the currently active program.
    Current = 1,
    /// Open visible but do not change the active program.
    Visible = 2,
}

// ---------------------------------------------------------------------------
// ProgramManager trait
// ---------------------------------------------------------------------------

/// Service interface for managing open programs.
///
/// Ported from `ghidra.app.services.ProgramManager`.  Multiple programs
/// may be open in a tool, but only one is active at any given time.
pub trait ProgramManager: fmt::Debug + Send + Sync {
    /// Return the program that is currently active.
    ///
    /// Returns `None` if no program is open.
    fn current_program(&self) -> Option<ProgramRef>;

    /// Returns `true` if the specified program is open and visible.
    fn is_visible(&self, program: &ProgramRef) -> bool;

    /// Closes the currently active program.
    ///
    /// Returns `true` if the close was successful.
    fn close_program(&mut self) -> bool;

    /// Open a program from a domain file reference.
    ///
    /// Returns the opened program, or `None` if the open was cancelled
    /// or an error occurred.
    fn open_program(
        &mut self,
        file: &DomainFileRef,
        mode: OpenMode,
    ) -> Option<ProgramRef>;

    /// Register an already-open program with the manager.
    fn open_program_ref(&mut self, program: ProgramRef, mode: OpenMode);

    /// Save the given program.
    fn save_program(&self, program: &ProgramRef) -> bool;

    /// Save all open programs.
    fn save_all(&self) -> Vec<ProgramRef>;

    /// Get all open programs.
    fn all_open_programs(&self) -> Vec<ProgramRef>;

    /// Get all visible programs.
    fn visible_programs(&self) -> Vec<ProgramRef>;

    /// Set the given program as the active program.
    fn set_current_program(&mut self, program: &ProgramRef);

    /// Release a program (remove from the manager).
    fn release_program(&mut self, program: &ProgramRef);

    /// Close a specific program, optionally ignoring unsaved changes.
    ///
    /// Returns `true` if the program was closed.
    fn close_program_by_ref(&mut self, program: &ProgramRef, ignore_changes: bool) -> bool;

    /// Close all programs except the current one.
    ///
    /// Returns `true` if all other programs were closed.
    fn close_other_programs(&mut self, ignore_changes: bool) -> bool;

    /// Close all open programs.
    ///
    /// Returns `true` if all programs were closed.
    fn close_all_programs(&mut self, ignore_changes: bool) -> bool;

    /// Find the first open program that contains the given address.
    fn get_program_at_address(&self, addr: Address) -> Option<ProgramRef>;
}

// ---------------------------------------------------------------------------
// In-memory implementation for testing
// ---------------------------------------------------------------------------

/// Internal state for a managed program.
#[derive(Debug, Clone)]
struct ManagedProgram {
    program: ProgramRef,
    visible: bool,
    dirty: bool,
}

/// In-memory implementation of [`ProgramManager`].
///
/// Stores programs in a `HashMap` and tracks visibility, dirty state,
/// and the currently active program.  Suitable for unit tests and as a
/// reference implementation.
#[derive(Debug)]
pub struct InMemoryProgramManager {
    programs: HashMap<String, ManagedProgram>,
    current: Option<String>,
}

impl InMemoryProgramManager {
    /// Create a new empty manager.
    pub fn new() -> Self {
        Self {
            programs: HashMap::new(),
            current: None,
        }
    }

    /// Mark a program as dirty (having unsaved changes).
    pub fn mark_dirty(&mut self, name: &str) {
        if let Some(mp) = self.programs.get_mut(name) {
            mp.dirty = true;
        }
    }

    /// Mark a program as clean.
    pub fn mark_clean(&mut self, name: &str) {
        if let Some(mp) = self.programs.get_mut(name) {
            mp.dirty = false;
        }
    }

    /// Check if any program has unsaved changes.
    pub fn has_unsaved_programs(&self) -> bool {
        self.programs.values().any(|mp| mp.dirty)
    }

    /// Get the number of open programs.
    pub fn program_count(&self) -> usize {
        self.programs.len()
    }

    /// Check if a program is open.
    pub fn is_open(&self, name: &str) -> bool {
        self.programs.contains_key(name)
    }

    /// Find the next visible program to make current after closing one.
    fn find_next_current(&self) -> Option<String> {
        self.programs
            .iter()
            .filter(|(_, mp)| mp.visible)
            .map(|(name, _)| name.clone())
            .next()
    }
}

impl Default for InMemoryProgramManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ProgramManager for InMemoryProgramManager {
    fn current_program(&self) -> Option<ProgramRef> {
        self.current
            .as_ref()
            .and_then(|name| self.programs.get(name).map(|mp| mp.program.clone()))
    }

    fn is_visible(&self, program: &ProgramRef) -> bool {
        self.programs
            .get(&program.name)
            .map(|mp| mp.visible)
            .unwrap_or(false)
    }

    fn close_program(&mut self) -> bool {
        let current = match &self.current {
            Some(c) => c.clone(),
            None => return false,
        };
        self.close_program_by_ref(&ProgramRef::new(&current), false)
    }

    fn open_program(
        &mut self,
        file: &DomainFileRef,
        mode: OpenMode,
    ) -> Option<ProgramRef> {
        let name = file
            .path
            .rsplit('/')
            .next()
            .unwrap_or(&file.path)
            .to_string();
        let prog = ProgramRef::with_path(&name, &file.path);
        self.open_program_ref(prog.clone(), mode);
        Some(prog)
    }

    fn open_program_ref(&mut self, program: ProgramRef, mode: OpenMode) {
        let visible = mode != OpenMode::Hidden;
        let name = program.name.clone();

        self.programs.entry(name.clone()).or_insert(ManagedProgram {
            program,
            visible,
            dirty: false,
        });

        if mode == OpenMode::Current {
            self.current = Some(name);
        } else if self.current.is_none() {
            self.current = Some(name);
        }
    }

    fn save_program(&self, _program: &ProgramRef) -> bool {
        // In the real implementation, this would persist to disk.
        true
    }

    fn save_all(&self) -> Vec<ProgramRef> {
        self.programs.values().map(|mp| mp.program.clone()).collect()
    }

    fn all_open_programs(&self) -> Vec<ProgramRef> {
        self.programs.values().map(|mp| mp.program.clone()).collect()
    }

    fn visible_programs(&self) -> Vec<ProgramRef> {
        self.programs
            .values()
            .filter(|mp| mp.visible)
            .map(|mp| mp.program.clone())
            .collect()
    }

    fn set_current_program(&mut self, program: &ProgramRef) {
        if self.programs.contains_key(&program.name) {
            self.current = Some(program.name.clone());
        }
    }

    fn release_program(&mut self, program: &ProgramRef) {
        self.programs.remove(&program.name);
        if self.current.as_deref() == Some(program.name.as_str()) {
            self.current = self.find_next_current();
        }
    }

    fn close_program_by_ref(&mut self, program: &ProgramRef, _ignore_changes: bool) -> bool {
        if !self.programs.contains_key(&program.name) {
            return false;
        }
        self.programs.remove(&program.name);
        if self.current.as_deref() == Some(program.name.as_str()) {
            self.current = self.find_next_current();
        }
        true
    }

    fn close_other_programs(&mut self, ignore_changes: bool) -> bool {
        let current_name = self.current.clone();
        let others: Vec<String> = self
            .programs
            .keys()
            .filter(|k| Some(k.as_str()) != current_name.as_deref())
            .cloned()
            .collect();
        for name in others {
            self.close_program_by_ref(&ProgramRef::new(&name), ignore_changes);
        }
        true
    }

    fn close_all_programs(&mut self, ignore_changes: bool) -> bool {
        let names: Vec<String> = self.programs.keys().cloned().collect();
        for name in names {
            self.close_program_by_ref(&ProgramRef::new(&name), ignore_changes);
        }
        true
    }

    fn get_program_at_address(&self, _addr: Address) -> Option<ProgramRef> {
        // In the real implementation, this would query each program's memory
        // map.  Here we return the current program as a placeholder.
        self.current_program()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mgr() -> InMemoryProgramManager {
        InMemoryProgramManager::new()
    }

    #[test]
    fn test_empty_manager() {
        let mgr = make_mgr();
        assert!(mgr.current_program().is_none());
        assert_eq!(mgr.all_open_programs().len(), 0);
        assert_eq!(mgr.program_count(), 0);
    }

    #[test]
    fn test_open_current() {
        let mut mgr = make_mgr();
        mgr.open_program_ref(ProgramRef::new("a.exe"), OpenMode::Current);

        assert_eq!(mgr.current_program().map(|p| p.name), Some("a.exe".into()));
        assert_eq!(mgr.program_count(), 1);
        assert!(mgr.is_open("a.exe"));
    }

    #[test]
    fn test_open_visible() {
        let mut mgr = make_mgr();
        mgr.open_program_ref(ProgramRef::new("a.exe"), OpenMode::Current);
        mgr.open_program_ref(ProgramRef::new("b.exe"), OpenMode::Visible);

        // Current should still be a.exe
        assert_eq!(mgr.current_program().map(|p| p.name), Some("a.exe".into()));
        assert_eq!(mgr.program_count(), 2);
    }

    #[test]
    fn test_open_hidden() {
        let mut mgr = make_mgr();
        mgr.open_program_ref(ProgramRef::new("hidden.exe"), OpenMode::Hidden);

        assert!(!mgr.is_visible(&ProgramRef::new("hidden.exe")));
        // Hidden program becomes current if it's the only one
        assert_eq!(mgr.current_program().map(|p| p.name), Some("hidden.exe".into()));
    }

    #[test]
    fn test_close_program() {
        let mut mgr = make_mgr();
        mgr.open_program_ref(ProgramRef::new("a.exe"), OpenMode::Current);
        assert!(mgr.close_program());
        assert!(mgr.current_program().is_none());
    }

    #[test]
    fn test_close_by_ref() {
        let mut mgr = make_mgr();
        mgr.open_program_ref(ProgramRef::new("a.exe"), OpenMode::Current);
        mgr.open_program_ref(ProgramRef::new("b.exe"), OpenMode::Visible);

        let closed = mgr.close_program_by_ref(&ProgramRef::new("a.exe"), true);
        assert!(closed);
        // b.exe should become current
        assert_eq!(mgr.current_program().map(|p| p.name), Some("b.exe".into()));
    }

    #[test]
    fn test_close_nonexistent() {
        let mut mgr = make_mgr();
        assert!(!mgr.close_program_by_ref(&ProgramRef::new("nope"), true));
    }

    #[test]
    fn test_close_others() {
        let mut mgr = make_mgr();
        mgr.open_program_ref(ProgramRef::new("a.exe"), OpenMode::Current);
        mgr.open_program_ref(ProgramRef::new("b.exe"), OpenMode::Visible);
        mgr.open_program_ref(ProgramRef::new("c.exe"), OpenMode::Visible);

        mgr.close_other_programs(true);
        assert_eq!(mgr.program_count(), 1);
        assert_eq!(mgr.current_program().map(|p| p.name), Some("a.exe".into()));
    }

    #[test]
    fn test_close_all() {
        let mut mgr = make_mgr();
        mgr.open_program_ref(ProgramRef::new("a.exe"), OpenMode::Current);
        mgr.open_program_ref(ProgramRef::new("b.exe"), OpenMode::Visible);

        mgr.close_all_programs(true);
        assert_eq!(mgr.program_count(), 0);
        assert!(mgr.current_program().is_none());
    }

    #[test]
    fn test_set_current() {
        let mut mgr = make_mgr();
        mgr.open_program_ref(ProgramRef::new("a.exe"), OpenMode::Current);
        mgr.open_program_ref(ProgramRef::new("b.exe"), OpenMode::Visible);

        mgr.set_current_program(&ProgramRef::new("b.exe"));
        assert_eq!(mgr.current_program().map(|p| p.name), Some("b.exe".into()));
    }

    #[test]
    fn test_visible_programs() {
        let mut mgr = make_mgr();
        mgr.open_program_ref(ProgramRef::new("a.exe"), OpenMode::Current);
        mgr.open_program_ref(ProgramRef::new("b.exe"), OpenMode::Hidden);

        let visible = mgr.visible_programs();
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].name, "a.exe");
    }

    #[test]
    fn test_release_program() {
        let mut mgr = make_mgr();
        mgr.open_program_ref(ProgramRef::new("a.exe"), OpenMode::Current);
        mgr.open_program_ref(ProgramRef::new("b.exe"), OpenMode::Visible);

        mgr.release_program(&ProgramRef::new("a.exe"));
        assert!(!mgr.is_open("a.exe"));
        assert_eq!(mgr.current_program().map(|p| p.name), Some("b.exe".into()));
    }

    #[test]
    fn test_dirty_tracking() {
        let mut mgr = make_mgr();
        mgr.open_program_ref(ProgramRef::new("a.exe"), OpenMode::Current);

        assert!(!mgr.has_unsaved_programs());
        mgr.mark_dirty("a.exe");
        assert!(mgr.has_unsaved_programs());
        mgr.mark_clean("a.exe");
        assert!(!mgr.has_unsaved_programs());
    }

    #[test]
    fn test_open_from_domain_file() {
        let mut mgr = make_mgr();
        let file = DomainFileRef::new("/path/to/binary.exe");
        let prog = mgr.open_program(&file, OpenMode::Current);

        assert!(prog.is_some());
        let prog = prog.unwrap();
        assert_eq!(prog.name, "binary.exe");
        assert_eq!(prog.domain_path, Some("/path/to/binary.exe".into()));
    }

    #[test]
    fn test_program_ref_display() {
        let prog = ProgramRef::new("test.exe");
        assert_eq!(format!("{}", prog), "test.exe");

        let prog = ProgramRef::with_path("test.exe", "/path/to/test.exe");
        assert_eq!(format!("{}", prog), "test.exe (/path/to/test.exe)");
    }

    #[test]
    fn test_program_ref_equality() {
        let a = ProgramRef::new("test.exe");
        let b = ProgramRef::new("test.exe");
        let c = ProgramRef::new("other.exe");

        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
