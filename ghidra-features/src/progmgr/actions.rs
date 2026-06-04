//! Program manager actions -- ported from `ghidra.app.plugin.core.progmgr`.
//!
//! Provides actions for program management: close, save, save-as,
//! undo, redo, and program switching.

use std::fmt;

// ---------------------------------------------------------------------------
// ProgramActionKind
// ---------------------------------------------------------------------------

/// The kind of program management action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramActionKind {
    /// Close the current program.
    Close,
    /// Close all programs.
    CloseAll,
    /// Close all other programs.
    CloseOthers,
    /// Save the current program.
    Save,
    /// Save the current program as a new file.
    SaveAs,
    /// Save all open programs.
    SaveAll,
    /// Undo the last transaction.
    Undo,
    /// Redo the last undone transaction.
    Redo,
    /// Switch to the next program tab.
    NextProgram,
    /// Switch to the previous program tab.
    PreviousProgram,
    /// Show program options.
    ProgramOptions,
}

impl fmt::Display for ProgramActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Close => write!(f, "Close"),
            Self::CloseAll => write!(f, "Close All"),
            Self::CloseOthers => write!(f, "Close Others"),
            Self::Save => write!(f, "Save"),
            Self::SaveAs => write!(f, "Save As"),
            Self::SaveAll => write!(f, "Save All"),
            Self::Undo => write!(f, "Undo"),
            Self::Redo => write!(f, "Redo"),
            Self::NextProgram => write!(f, "Next Program"),
            Self::PreviousProgram => write!(f, "Previous Program"),
            Self::ProgramOptions => write!(f, "Program Options"),
        }
    }
}

// ---------------------------------------------------------------------------
// ProgramAction
// ---------------------------------------------------------------------------

/// A program management action.
///
/// Ported from the various `*Action.java` classes in
/// `ghidra.app.plugin.core.progmgr`.
///
/// # Example
///
/// ```
/// use ghidra_features::progmgr::actions::*;
///
/// let action = ProgramAction::new(ProgramActionKind::Save);
/// assert_eq!(action.name(), "Save");
/// assert!(action.is_enabled());
/// ```
#[derive(Debug, Clone)]
pub struct ProgramAction {
    /// The kind of action.
    kind: ProgramActionKind,
    /// Whether the action is enabled.
    enabled: bool,
    /// The menu group.
    group: String,
    /// The menu sub-group for ordering.
    sub_group: i32,
}

impl ProgramAction {
    /// Creates a new program action.
    pub fn new(kind: ProgramActionKind) -> Self {
        Self {
            kind,
            enabled: true,
            group: "MainMenu".to_string(),
            sub_group: 0,
        }
    }

    /// Returns the action kind.
    pub fn kind(&self) -> ProgramActionKind {
        self.kind
    }

    /// Returns the action name.
    pub fn name(&self) -> &str {
        match self.kind {
            ProgramActionKind::Close => "Close Program",
            ProgramActionKind::CloseAll => "Close All Programs",
            ProgramActionKind::CloseOthers => "Close Other Programs",
            ProgramActionKind::Save => "Save Program",
            ProgramActionKind::SaveAs => "Save Program As...",
            ProgramActionKind::SaveAll => "Save All Programs",
            ProgramActionKind::Undo => "Undo",
            ProgramActionKind::Redo => "Redo",
            ProgramActionKind::NextProgram => "Next Program",
            ProgramActionKind::PreviousProgram => "Previous Program",
            ProgramActionKind::ProgramOptions => "Program Options...",
        }
    }

    /// Returns the key binding (if any).
    pub fn key_binding(&self) -> Option<&str> {
        match self.kind {
            ProgramActionKind::Save => Some("ctrl S"),
            ProgramActionKind::Undo => Some("ctrl Z"),
            ProgramActionKind::Redo => Some("ctrl Y"),
            ProgramActionKind::Close => Some("ctrl W"),
            _ => None,
        }
    }

    /// Returns the menu path.
    pub fn menu_path(&self) -> &str {
        match self.kind {
            ProgramActionKind::Close
            | ProgramActionKind::CloseAll
            | ProgramActionKind::CloseOthers => "File",
            ProgramActionKind::Save
            | ProgramActionKind::SaveAs
            | ProgramActionKind::SaveAll => "File",
            ProgramActionKind::Undo | ProgramActionKind::Redo => "Edit",
            ProgramActionKind::NextProgram | ProgramActionKind::PreviousProgram => "Window",
            ProgramActionKind::ProgramOptions => "Edit",
        }
    }

    /// Returns whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sets whether the action is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns the menu group.
    pub fn group(&self) -> &str {
        &self.group
    }

    /// Sets the menu group.
    pub fn set_group(&mut self, group: impl Into<String>) {
        self.group = group.into();
    }

    /// Returns the sub-group for ordering.
    pub fn sub_group(&self) -> i32 {
        self.sub_group
    }

    /// Sets the sub-group for ordering.
    pub fn set_sub_group(&mut self, sub_group: i32) {
        self.sub_group = sub_group;
    }

    /// Returns `true` if the action is enabled for the given state.
    ///
    /// # Parameters
    ///
    /// * `has_current` - Whether there is a current (active) program.
    /// * `is_dirty` - Whether the current program has unsaved changes.
    /// * `has_undo` - Whether there is an undoable transaction.
    /// * `has_redo` - Whether there is a redoable transaction.
    /// * `program_count` - The number of open programs.
    pub fn is_enabled_for_state(
        &self,
        has_current: bool,
        is_dirty: bool,
        has_undo: bool,
        has_redo: bool,
        program_count: usize,
    ) -> bool {
        if !self.enabled {
            return false;
        }
        match self.kind {
            ProgramActionKind::Close => has_current,
            ProgramActionKind::CloseAll => program_count > 0,
            ProgramActionKind::CloseOthers => program_count > 1,
            ProgramActionKind::Save => has_current && is_dirty,
            ProgramActionKind::SaveAs => has_current,
            ProgramActionKind::SaveAll => program_count > 0,
            ProgramActionKind::Undo => has_current && has_undo,
            ProgramActionKind::Redo => has_current && has_redo,
            ProgramActionKind::NextProgram => program_count > 1,
            ProgramActionKind::PreviousProgram => program_count > 1,
            ProgramActionKind::ProgramOptions => has_current,
        }
    }
}

// ---------------------------------------------------------------------------
// ProgramActionContext
// ---------------------------------------------------------------------------

/// Context for program actions.
#[derive(Debug, Clone, Default)]
pub struct ProgramActionContext {
    /// The name of the current program.
    pub current_program: Option<String>,
    /// Whether the current program has unsaved changes.
    pub is_dirty: bool,
    /// Whether there is an undoable transaction.
    pub has_undo: bool,
    /// Whether there is a redoable transaction.
    pub has_redo: bool,
    /// The total number of open programs.
    pub program_count: usize,
}

impl ProgramActionContext {
    /// Returns whether there is a current program.
    pub fn has_current_program(&self) -> bool {
        self.current_program.is_some()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_kind_display() {
        assert_eq!(ProgramActionKind::Close.to_string(), "Close");
        assert_eq!(ProgramActionKind::SaveAll.to_string(), "Save All");
    }

    #[test]
    fn test_action_creation() {
        let action = ProgramAction::new(ProgramActionKind::Save);
        assert_eq!(action.kind(), ProgramActionKind::Save);
        assert_eq!(action.name(), "Save Program");
        assert!(action.is_enabled());
    }

    #[test]
    fn test_action_key_binding() {
        let save = ProgramAction::new(ProgramActionKind::Save);
        assert_eq!(save.key_binding(), Some("ctrl S"));

        let undo = ProgramAction::new(ProgramActionKind::Undo);
        assert_eq!(undo.key_binding(), Some("ctrl Z"));

        let close = ProgramAction::new(ProgramActionKind::Close);
        assert_eq!(close.key_binding(), Some("ctrl W"));

        let opts = ProgramAction::new(ProgramActionKind::ProgramOptions);
        assert!(opts.key_binding().is_none());
    }

    #[test]
    fn test_action_menu_path() {
        let close = ProgramAction::new(ProgramActionKind::Close);
        assert_eq!(close.menu_path(), "File");

        let undo = ProgramAction::new(ProgramActionKind::Undo);
        assert_eq!(undo.menu_path(), "Edit");
    }

    #[test]
    fn test_save_enabled_when_dirty() {
        let action = ProgramAction::new(ProgramActionKind::Save);
        assert!(!action.is_enabled_for_state(true, false, false, false, 1));
        assert!(action.is_enabled_for_state(true, true, false, false, 1));
        assert!(!action.is_enabled_for_state(false, true, false, false, 0));
    }

    #[test]
    fn test_close_enabled() {
        let action = ProgramAction::new(ProgramActionKind::Close);
        assert!(action.is_enabled_for_state(true, false, false, false, 1));
        assert!(!action.is_enabled_for_state(false, false, false, false, 0));
    }

    #[test]
    fn test_close_others() {
        let action = ProgramAction::new(ProgramActionKind::CloseOthers);
        assert!(!action.is_enabled_for_state(true, false, false, false, 1));
        assert!(action.is_enabled_for_state(true, false, false, false, 2));
    }

    #[test]
    fn test_undo_redo() {
        let undo = ProgramAction::new(ProgramActionKind::Undo);
        let redo = ProgramAction::new(ProgramActionKind::Redo);

        assert!(undo.is_enabled_for_state(true, false, true, false, 1));
        assert!(!undo.is_enabled_for_state(true, false, false, false, 1));
        assert!(redo.is_enabled_for_state(true, false, false, true, 1));
    }

    #[test]
    fn test_next_previous_program() {
        let next = ProgramAction::new(ProgramActionKind::NextProgram);
        assert!(!next.is_enabled_for_state(true, false, false, false, 1));
        assert!(next.is_enabled_for_state(true, false, false, false, 2));
    }

    #[test]
    fn test_action_disabled() {
        let mut action = ProgramAction::new(ProgramActionKind::Save);
        action.set_enabled(false);
        assert!(!action.is_enabled_for_state(true, true, false, false, 1));
    }

    #[test]
    fn test_action_group() {
        let mut action = ProgramAction::new(ProgramActionKind::Save);
        assert_eq!(action.group(), "MainMenu");
        action.set_group("FileGroup");
        assert_eq!(action.group(), "FileGroup");
    }

    #[test]
    fn test_action_context() {
        let mut ctx = ProgramActionContext::default();
        assert!(!ctx.has_current_program());
        ctx.current_program = Some("test.exe".to_string());
        assert!(ctx.has_current_program());
    }

    #[test]
    fn test_all_action_kinds_have_names() {
        let kinds = [
            ProgramActionKind::Close,
            ProgramActionKind::CloseAll,
            ProgramActionKind::CloseOthers,
            ProgramActionKind::Save,
            ProgramActionKind::SaveAs,
            ProgramActionKind::SaveAll,
            ProgramActionKind::Undo,
            ProgramActionKind::Redo,
            ProgramActionKind::NextProgram,
            ProgramActionKind::PreviousProgram,
            ProgramActionKind::ProgramOptions,
        ];
        for kind in &kinds {
            let action = ProgramAction::new(*kind);
            assert!(!action.name().is_empty(), "Empty name for {:?}", kind);
        }
    }
}
