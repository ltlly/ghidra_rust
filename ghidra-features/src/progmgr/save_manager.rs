//! ProgramSaveManager -- handles save and save-as operations.
//!
//! Ported from `ghidra.app.plugin.core.progmgr.ProgramSaveManager`.
//!
//! Manages saving programs, including save-as (renaming), checking for
//! unsaved changes, and coordinating save dialogs.

use std::collections::HashMap;

/// Represents the save state of a program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveState {
    /// The program has no unsaved changes.
    Clean,
    /// The program has unsaved changes.
    Dirty,
    /// The program is read-only and cannot be saved.
    ReadOnly,
    /// The program is new (never saved).
    New,
}

/// Manages save operations for programs.
///
/// Tracks which programs have unsaved changes and provides methods
/// for saving individual programs or all changed programs.
#[derive(Debug)]
pub struct ProgramSaveManager {
    /// Map from program name to its save state.
    save_states: HashMap<String, SaveState>,
}

impl ProgramSaveManager {
    /// Create a new ProgramSaveManager.
    pub fn new() -> Self {
        Self {
            save_states: HashMap::new(),
        }
    }

    /// Register a program with the save manager.
    pub fn register_program(&mut self, name: impl Into<String>, state: SaveState) {
        self.save_states.insert(name.into(), state);
    }

    /// Unregister a program.
    pub fn unregister_program(&mut self, name: &str) {
        self.save_states.remove(name);
    }

    /// Mark a program as dirty (having unsaved changes).
    pub fn mark_dirty(&mut self, name: &str) {
        if let Some(state) = self.save_states.get_mut(name) {
            if *state != SaveState::ReadOnly {
                *state = SaveState::Dirty;
            }
        }
    }

    /// Mark a program as clean (no unsaved changes).
    pub fn mark_clean(&mut self, name: &str) {
        if let Some(state) = self.save_states.get_mut(name) {
            if *state != SaveState::ReadOnly {
                *state = SaveState::Clean;
            }
        }
    }

    /// Returns the save state of a program.
    pub fn get_state(&self, name: &str) -> Option<&SaveState> {
        self.save_states.get(name)
    }

    /// Returns `true` if the program has unsaved changes.
    pub fn is_dirty(&self, name: &str) -> bool {
        matches!(
            self.save_states.get(name),
            Some(SaveState::Dirty) | Some(SaveState::New)
        )
    }

    /// Returns `true` if any program has unsaved changes.
    pub fn has_unsaved_programs(&self) -> bool {
        self.save_states
            .values()
            .any(|s| matches!(s, SaveState::Dirty | SaveState::New))
    }

    /// Returns the names of all programs with unsaved changes.
    pub fn dirty_programs(&self) -> Vec<&str> {
        self.save_states
            .iter()
            .filter(|(_, s)| matches!(s, SaveState::Dirty | SaveState::New))
            .map(|(name, _)| name.as_str())
            .collect()
    }

    /// Save a single program (marks it clean).
    ///
    /// Returns `true` if the save succeeded.
    pub fn save_program(&mut self, name: &str) -> bool {
        if let Some(state) = self.save_states.get_mut(name) {
            if *state == SaveState::ReadOnly {
                return false;
            }
            *state = SaveState::Clean;
            true
        } else {
            false
        }
    }

    /// Save all dirty programs.
    ///
    /// Returns the names of successfully saved programs.
    pub fn save_all(&mut self) -> Vec<String> {
        let mut saved = Vec::new();
        for (name, state) in self.save_states.iter_mut() {
            if matches!(state, SaveState::Dirty | SaveState::New) {
                *state = SaveState::Clean;
                saved.push(name.clone());
            }
        }
        saved
    }

    /// Check if a program can be closed (user confirms saving if dirty).
    ///
    /// Returns `true` if the close should proceed.
    pub fn can_close(&self, name: &str) -> bool {
        !self.is_dirty(name) || true // In real impl, would prompt user
    }

    /// Returns the total number of registered programs.
    pub fn program_count(&self) -> usize {
        self.save_states.len()
    }
}

impl Default for ProgramSaveManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_state() {
        let mut mgr = ProgramSaveManager::new();
        mgr.register_program("test.exe", SaveState::Clean);
        assert_eq!(mgr.get_state("test.exe"), Some(&SaveState::Clean));
        assert!(!mgr.is_dirty("test.exe"));
    }

    #[test]
    fn test_mark_dirty() {
        let mut mgr = ProgramSaveManager::new();
        mgr.register_program("test.exe", SaveState::Clean);
        mgr.mark_dirty("test.exe");
        assert!(mgr.is_dirty("test.exe"));
        assert!(mgr.has_unsaved_programs());
    }

    #[test]
    fn test_save_program() {
        let mut mgr = ProgramSaveManager::new();
        mgr.register_program("test.exe", SaveState::Dirty);
        assert!(mgr.save_program("test.exe"));
        assert!(!mgr.is_dirty("test.exe"));
    }

    #[test]
    fn test_save_read_only() {
        let mut mgr = ProgramSaveManager::new();
        mgr.register_program("test.exe", SaveState::ReadOnly);
        assert!(!mgr.save_program("test.exe"));
        assert_eq!(mgr.get_state("test.exe"), Some(&SaveState::ReadOnly));
    }

    #[test]
    fn test_save_all() {
        let mut mgr = ProgramSaveManager::new();
        mgr.register_program("a.exe", SaveState::Clean);
        mgr.register_program("b.exe", SaveState::Dirty);
        mgr.register_program("c.exe", SaveState::New);
        mgr.register_program("d.exe", SaveState::ReadOnly);

        let saved = mgr.save_all();
        assert_eq!(saved.len(), 2);
        assert!(saved.contains(&"b.exe".to_string()));
        assert!(saved.contains(&"c.exe".to_string()));
    }

    #[test]
    fn test_dirty_programs() {
        let mut mgr = ProgramSaveManager::new();
        mgr.register_program("a.exe", SaveState::Dirty);
        mgr.register_program("b.exe", SaveState::Clean);
        mgr.register_program("c.exe", SaveState::New);

        let dirty = mgr.dirty_programs();
        assert_eq!(dirty.len(), 2);
    }

    #[test]
    fn test_unregister() {
        let mut mgr = ProgramSaveManager::new();
        mgr.register_program("test.exe", SaveState::Dirty);
        mgr.unregister_program("test.exe");
        assert!(mgr.get_state("test.exe").is_none());
    }
}
