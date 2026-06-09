//! Undo service -- service interface and undo/redo state management.
//!
//! Ported from Ghidra's:
//! - `docking.UndoRedoKeeper` -- generic undo/redo stack with style-edit coalescing
//! - `ghidra.framework.plugintool.util.UndoRedoToolState` -- tool-wide undo/redo state
//! - `ghidra.app.services.UndoService` -- service trait for undo/redo operations
//!
//! Provides the core undo/redo infrastructure used across Ghidra's plugin
//! framework.  The [`UndoRedoKeeper`] manages an undo/redo stack with a
//! maximum depth and coalesces consecutive style edits into a single undo
//! unit.  The [`UndoService`] trait defines the service contract that
//! plugins consume to perform undo/redo on the active domain object.

use std::collections::VecDeque;
use std::fmt;

// ============================================================================
// UndoableEdit trait
// ============================================================================

/// A single undoable/redoable edit operation.
///
/// Ported from `javax.swing.undo.UndoableEdit` (used by `UndoRedoKeeper`).
///
/// Each edit captures enough state to undo and redo itself.  The
/// `presentation_name` is used for display purposes (e.g., in a menu).
pub trait UndoableEdit: fmt::Debug + Send + Sync {
    /// Human-readable name of this edit (e.g., "Insert Text").
    fn presentation_name(&self) -> &str;

    /// Undo this edit.
    fn undo(&mut self) -> Result<(), UndoError>;

    /// Redo this edit.
    fn redo(&mut self) -> Result<(), UndoError>;

    /// Whether this edit can be undone.
    fn can_undo(&self) -> bool {
        true
    }

    /// Whether this edit can be redone.
    fn can_redo(&self) -> bool {
        true
    }

    /// Whether this edit is significant (non-significant edits may be
    /// discarded during coalescing).
    fn is_significant(&self) -> bool {
        true
    }

    /// Whether this edit represents a style-only change (bold, color, etc.).
    ///
    /// Style edits are coalesced by [`UndoRedoKeeper`] so that pressing
    /// undo once reverts all style changes together with the preceding
    /// text edit.
    fn is_style_edit(&self) -> bool {
        false
    }
}

// ============================================================================
// UndoError
// ============================================================================

/// Errors that can occur during undo/redo operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndoError {
    /// Nothing to undo.
    NothingToUndo,
    /// Nothing to redo.
    NothingToRedo,
    /// The edit could not be undone (e.g., already undone).
    CannotUndo(String),
    /// The edit could not be redone (e.g., already redone).
    CannotRedo(String),
    /// A generic error occurred.
    Other(String),
}

impl fmt::Display for UndoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NothingToUndo => write!(f, "Nothing to undo"),
            Self::NothingToRedo => write!(f, "Nothing to redo"),
            Self::CannotUndo(msg) => write!(f, "Cannot undo: {}", msg),
            Self::CannotRedo(msg) => write!(f, "Cannot redo: {}", msg),
            Self::Other(msg) => write!(f, "Undo error: {}", msg),
        }
    }
}

impl std::error::Error for UndoError {}

// ============================================================================
// UndoRedoKeeper
// ============================================================================

/// Manages an undo/redo stack with style-edit coalescing.
///
/// Ported from `docking.UndoRedoKeeper`.
///
/// Style edits (bold, color, etc.) are coalesced so that a single undo
/// operation removes all consecutive style edits along with the preceding
/// text edit.  This provides intuitive behavior in text panes where
/// programmatic style changes should undo as a group.
///
/// # Example
///
/// ```
/// use ghidra_features::undo::undo_service::*;
///
/// let mut keeper = UndoRedoKeeper::new(50);
/// assert!(!keeper.can_undo());
/// assert!(!keeper.can_redo());
/// ```
pub struct UndoRedoKeeper {
    /// Undo stack (most recent at back).
    undo_stack: VecDeque<Box<dyn UndoableEdit>>,
    /// Redo stack (most recent at back).
    redo_stack: VecDeque<Box<dyn UndoableEdit>>,
    /// Maximum depth of each stack.
    max_size: usize,
    /// Accumulated style edits waiting to be committed.
    pending_style_edits: Vec<Box<dyn UndoableEdit>>,
}

impl UndoRedoKeeper {
    /// Create a new keeper with the given maximum undo/redo depth.
    pub fn new(max_size: usize) -> Self {
        Self {
            undo_stack: VecDeque::new(),
            redo_stack: VecDeque::new(),
            max_size,
            pending_style_edits: Vec::new(),
        }
    }

    /// Whether there is at least one edit to undo.
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Whether there is at least one edit to redo.
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Number of edits on the undo stack.
    pub fn undo_count(&self) -> usize {
        self.undo_stack.len()
    }

    /// Number of edits on the redo stack.
    pub fn redo_count(&self) -> usize {
        self.redo_stack.len()
    }

    /// Add a new undoable edit.
    ///
    /// If the edit is a style edit, it is accumulated with other pending
    /// style edits and only committed when a non-style edit arrives.
    /// Adding any edit clears the redo stack.
    pub fn add_undo(&mut self, edit: Box<dyn UndoableEdit>) {
        if edit.is_style_edit() {
            self.pending_style_edits.push(edit);
            self.redo_stack.clear();
            return;
        }

        // Flush any pending style edits as a single compound entry.
        self.flush_pending_styles();

        self.push_undo(edit);
        self.redo_stack.clear();
    }

    /// Undo the most recent edit.
    ///
    /// If the top of the undo stack is a compound style edit, it is undone
    /// and then the next non-style edit is also undone (matching Ghidra's
    /// behavior of undoing style+text together).
    pub fn undo(&mut self) -> Result<(), UndoError> {
        self.flush_pending_styles();

        if self.undo_stack.is_empty() {
            return Err(UndoError::NothingToUndo);
        }

        let mut edit = self.undo_stack.pop_back().unwrap();
        edit.undo()?;
        let is_style = edit.is_style_edit();
        self.redo_stack.push_back(edit);

        // If this was a style edit, also undo the next real edit.
        if is_style {
            return self.undo();
        }

        Ok(())
    }

    /// Redo the most recently undone edit.
    ///
    /// If the top of the redo stack is a compound style edit, it is redone
    /// and then the next non-style edit is also redone.
    pub fn redo(&mut self) -> Result<(), UndoError> {
        self.flush_pending_styles();

        if self.redo_stack.is_empty() {
            return Err(UndoError::NothingToRedo);
        }

        let mut edit = self.redo_stack.pop_back().unwrap();
        edit.redo()?;
        let is_style = edit.is_style_edit();
        self.push_undo(edit);

        // If this was a style edit, also redo the next real edit.
        if is_style {
            return self.redo();
        }

        Ok(())
    }

    /// Get the presentation name of the next undoable edit.
    pub fn undo_name(&self) -> Option<String> {
        self.undo_stack.back().map(|e| e.presentation_name().to_string())
    }

    /// Get the presentation name of the next redoable edit.
    pub fn redo_name(&self) -> Option<String> {
        self.redo_stack.back().map(|e| e.presentation_name().to_string())
    }

    /// Get all undo names (most recent first).
    pub fn all_undo_names(&self) -> Vec<String> {
        self.undo_stack
            .iter()
            .rev()
            .map(|e| e.presentation_name().to_string())
            .collect()
    }

    /// Get all redo names (most recent first).
    pub fn all_redo_names(&self) -> Vec<String> {
        self.redo_stack
            .iter()
            .rev()
            .map(|e| e.presentation_name().to_string())
            .collect()
    }

    /// Clear all undo and redo state, including pending style edits.
    pub fn clear(&mut self) {
        self.undo_stack.clear();
        self.redo_stack.clear();
        self.pending_style_edits.clear();
    }

    /// Flush pending style edits into a single compound edit on the undo
    /// stack.  Called automatically before non-style edits and before
    /// undo/redo.
    fn flush_pending_styles(&mut self) {
        if self.pending_style_edits.is_empty() {
            return;
        }
        let styles: Vec<Box<dyn UndoableEdit>> = self.pending_style_edits.drain(..).collect();
        let compound = CompoundStyleEdit { edits: styles };
        self.push_undo(Box::new(compound));
    }

    /// Push an edit onto the undo stack, evicting the oldest if at capacity.
    fn push_undo(&mut self, edit: Box<dyn UndoableEdit>) {
        if self.undo_stack.len() >= self.max_size {
            self.undo_stack.pop_front();
        }
        self.undo_stack.push_back(edit);
    }
}

impl fmt::Debug for UndoRedoKeeper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UndoRedoKeeper")
            .field("undo_count", &self.undo_stack.len())
            .field("redo_count", &self.redo_stack.len())
            .field("max_size", &self.max_size)
            .field("pending_style_count", &self.pending_style_edits.len())
            .finish()
    }
}

// ============================================================================
// CompoundStyleEdit
// ============================================================================

/// A compound edit that groups multiple style edits into one undoable unit.
#[derive(Debug)]
struct CompoundStyleEdit {
    edits: Vec<Box<dyn UndoableEdit>>,
}

impl UndoableEdit for CompoundStyleEdit {
    fn presentation_name(&self) -> &str {
        "Style"
    }

    fn undo(&mut self) -> Result<(), UndoError> {
        for edit in self.edits.iter_mut().rev() {
            edit.undo()?;
        }
        Ok(())
    }

    fn redo(&mut self) -> Result<(), UndoError> {
        for edit in self.edits.iter_mut() {
            edit.redo()?;
        }
        Ok(())
    }

    fn is_style_edit(&self) -> bool {
        true
    }

    fn is_significant(&self) -> bool {
        false
    }
}

// ============================================================================
// UndoService trait
// ============================================================================

/// Service interface for undo/redo operations.
///
/// Ported from the undo/redo service contract used by Ghidra's plugin
/// framework.  Plugins consume this service to perform undo/redo on the
/// active domain object and to query the current undo/redo state.
///
/// # Implementing
///
/// ```ignore
/// use ghidra_features::undo::undo_service::*;
///
/// #[derive(Debug)]
/// struct MyUndoService { /* ... */ }
///
/// impl UndoService for MyUndoService {
///     fn can_undo(&self) -> bool { /* ... */ }
///     fn can_redo(&self) -> bool { /* ... */ }
///     fn undo(&mut self) -> Result<(), UndoError> { /* ... */ }
///     fn redo(&mut self) -> Result<(), UndoError> { /* ... */ }
///     fn undo_name(&self) -> Option<String> { /* ... */ }
///     fn redo_name(&self) -> Option<String> { /* ... */ }
///     fn all_undo_names(&self) -> Vec<String> { /* ... */ }
///     fn all_redo_names(&self) -> Vec<String> { /* ... */ }
///     fn clear_undo(&mut self) { /* ... */ }
/// }
/// ```
pub trait UndoService: fmt::Debug + Send + Sync {
    /// Whether undo is currently possible.
    fn can_undo(&self) -> bool;

    /// Whether redo is currently possible.
    fn can_redo(&self) -> bool;

    /// Perform a single undo step.
    fn undo(&mut self) -> Result<(), UndoError>;

    /// Perform a single redo step.
    fn redo(&mut self) -> Result<(), UndoError>;

    /// The name of the next undoable operation.
    fn undo_name(&self) -> Option<String>;

    /// The name of the next redoable operation.
    fn redo_name(&self) -> Option<String>;

    /// All undo names, most recent first.
    fn all_undo_names(&self) -> Vec<String>;

    /// All redo names, most recent first.
    fn all_redo_names(&self) -> Vec<String>;

    /// Clear all undo/redo state.
    fn clear_undo(&mut self);

    /// Perform undo N times.  Stops on the first error.
    fn undo_n(&mut self, count: usize) -> Result<(), UndoError> {
        for _ in 0..count {
            self.undo()?;
        }
        Ok(())
    }

    /// Perform redo N times.  Stops on the first error.
    fn redo_n(&mut self, count: usize) -> Result<(), UndoError> {
        for _ in 0..count {
            self.redo()?;
        }
        Ok(())
    }
}

// ============================================================================
// UndoRedoToolState
// ============================================================================

/// Snapshot of plugin undo/redo state for tool-wide undo/redo.
///
/// Ported from `ghidra.framework.plugintool.util.UndoRedoToolState`.
///
/// When a tool performs an undo or redo, it saves the current state of
/// all plugins before applying the change.  If the undo is itself undone
/// (redo), the saved state is restored.  This allows plugins to maintain
/// their own undo/redo state (e.g., cursor position, selection) in
/// coordination with domain-object undo/redo.
///
/// # Example
///
/// ```
/// use ghidra_features::undo::undo_service::*;
///
/// let mut state = UndoRedoToolState::new();
/// state.save_plugin_state("CodeBrowser", vec![0x40, 0x10, 0x00]);
/// state.save_plugin_state("Listing", vec![0x01, 0x02]);
///
/// let names: Vec<&str> = state.plugin_names().collect();
/// assert_eq!(names.len(), 2);
/// assert_eq!(state.get_plugin_state("CodeBrowser"), Some(&vec![0x40, 0x10, 0x00]));
/// ```
#[derive(Debug, Clone)]
pub struct UndoRedoToolState {
    /// Per-plugin serialized state, keyed by plugin name.
    states: Vec<(String, Vec<u8>)>,
}

impl UndoRedoToolState {
    /// Create a new empty tool state snapshot.
    pub fn new() -> Self {
        Self { states: Vec::new() }
    }

    /// Save a plugin's state (serialized as bytes).
    pub fn save_plugin_state(&mut self, plugin_name: impl Into<String>, state: Vec<u8>) {
        self.states.push((plugin_name.into(), state));
    }

    /// Get the saved state for a given plugin.
    pub fn get_plugin_state(&self, plugin_name: &str) -> Option<&Vec<u8>> {
        self.states
            .iter()
            .find(|(name, _)| name == plugin_name)
            .map(|(_, state)| state)
    }

    /// Iterate over all saved plugin names.
    pub fn plugin_names(&self) -> impl Iterator<Item = &str> {
        self.states.iter().map(|(name, _)| name.as_str())
    }

    /// The number of plugins with saved state.
    pub fn plugin_count(&self) -> usize {
        self.states.len()
    }

    /// Whether this state is empty.
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// Clear all saved states.
    pub fn clear(&mut self) {
        self.states.clear();
    }
}

impl Default for UndoRedoToolState {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// UndoStateInfo
// ============================================================================

/// Summary information about the current undo/redo state.
///
/// This is a lightweight value type suitable for passing to UI code that
/// needs to update menus, tooltips, or button labels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UndoStateInfo {
    /// Whether undo is available.
    pub can_undo: bool,
    /// Whether redo is available.
    pub can_redo: bool,
    /// Name of the next undoable operation.
    pub undo_name: Option<String>,
    /// Name of the next redoable operation.
    pub redo_name: Option<String>,
    /// Number of undoable operations.
    pub undo_count: usize,
    /// Number of redoable operations.
    pub redo_count: usize,
}

impl UndoStateInfo {
    /// Capture the current state from an [`UndoService`] implementation.
    pub fn from_service(service: &dyn UndoService) -> Self {
        Self {
            can_undo: service.can_undo(),
            can_redo: service.can_redo(),
            undo_name: service.undo_name(),
            redo_name: service.redo_name(),
            undo_count: service.all_undo_names().len(),
            redo_count: service.all_redo_names().len(),
        }
    }
}

impl Default for UndoStateInfo {
    fn default() -> Self {
        Self {
            can_undo: false,
            can_redo: false,
            undo_name: None,
            redo_name: None,
            undo_count: 0,
            redo_count: 0,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // --- Test UndoableEdit implementation ---

    #[derive(Debug)]
    struct TestEdit {
        name: String,
        undone: bool,
        style: bool,
    }

    impl TestEdit {
        fn new(name: &str) -> Self {
            Self {
                name: name.to_string(),
                undone: false,
                style: false,
            }
        }

        fn new_style(name: &str) -> Self {
            Self {
                name: name.to_string(),
                undone: false,
                style: true,
            }
        }
    }

    impl UndoableEdit for TestEdit {
        fn presentation_name(&self) -> &str {
            &self.name
        }

        fn undo(&mut self) -> Result<(), UndoError> {
            self.undone = true;
            Ok(())
        }

        fn redo(&mut self) -> Result<(), UndoError> {
            self.undone = false;
            Ok(())
        }

        fn is_style_edit(&self) -> bool {
            self.style
        }
    }

    // --- UndoRedoKeeper tests ---

    #[test]
    fn test_keeper_empty() {
        let keeper = UndoRedoKeeper::new(50);
        assert!(!keeper.can_undo());
        assert!(!keeper.can_redo());
        assert_eq!(keeper.undo_count(), 0);
        assert_eq!(keeper.redo_count(), 0);
    }

    #[test]
    fn test_keeper_add_and_undo() {
        let mut keeper = UndoRedoKeeper::new(50);
        keeper.add_undo(Box::new(TestEdit::new("Insert Data")));

        assert!(keeper.can_undo());
        assert!(!keeper.can_redo());
        assert_eq!(keeper.undo_name(), Some("Insert Data".to_string()));

        keeper.undo().unwrap();
        assert!(!keeper.can_undo());
        assert!(keeper.can_redo());
        assert_eq!(keeper.redo_name(), Some("Insert Data".to_string()));
    }

    #[test]
    fn test_keeper_undo_redo_cycle() {
        let mut keeper = UndoRedoKeeper::new(50);
        keeper.add_undo(Box::new(TestEdit::new("Edit A")));
        keeper.add_undo(Box::new(TestEdit::new("Edit B")));

        assert_eq!(keeper.undo_count(), 2);
        assert_eq!(keeper.undo_name(), Some("Edit B".to_string()));

        keeper.undo().unwrap();
        assert_eq!(keeper.undo_name(), Some("Edit A".to_string()));
        assert_eq!(keeper.redo_name(), Some("Edit B".to_string()));

        keeper.redo().unwrap();
        assert_eq!(keeper.undo_name(), Some("Edit B".to_string()));
        assert!(!keeper.can_redo());
    }

    #[test]
    fn test_keeper_undo_empty_fails() {
        let mut keeper = UndoRedoKeeper::new(50);
        assert!(keeper.undo().is_err());
    }

    #[test]
    fn test_keeper_redo_empty_fails() {
        let mut keeper = UndoRedoKeeper::new(50);
        assert!(keeper.redo().is_err());
    }

    #[test]
    fn test_keeper_new_edit_clears_redo() {
        let mut keeper = UndoRedoKeeper::new(50);
        keeper.add_undo(Box::new(TestEdit::new("A")));
        keeper.undo().unwrap();
        assert!(keeper.can_redo());

        keeper.add_undo(Box::new(TestEdit::new("B")));
        assert!(!keeper.can_redo());
    }

    #[test]
    fn test_keeper_max_size_eviction() {
        let mut keeper = UndoRedoKeeper::new(3);
        keeper.add_undo(Box::new(TestEdit::new("A")));
        keeper.add_undo(Box::new(TestEdit::new("B")));
        keeper.add_undo(Box::new(TestEdit::new("C")));
        keeper.add_undo(Box::new(TestEdit::new("D"))); // evicts A

        assert_eq!(keeper.undo_count(), 3);
        let names = keeper.all_undo_names();
        assert_eq!(names, vec!["D", "C", "B"]);
    }

    #[test]
    fn test_keeper_style_coalescing() {
        let mut keeper = UndoRedoKeeper::new(50);
        keeper.add_undo(Box::new(TestEdit::new("Insert Text")));
        keeper.add_undo(Box::new(TestEdit::new_style("Bold")));
        keeper.add_undo(Box::new(TestEdit::new_style("Color Red")));
        // The next non-style edit should flush the pending styles.
        keeper.add_undo(Box::new(TestEdit::new("Delete Char")));

        // Should have: Insert Text, Style(compound), Delete Char
        assert_eq!(keeper.undo_count(), 3);

        // Undo should work through all of them.
        keeper.undo().unwrap(); // Delete Char
        assert_eq!(keeper.undo_name(), Some("Style".to_string()));
        keeper.undo().unwrap(); // Style compound
        assert_eq!(keeper.undo_name(), Some("Insert Text".to_string()));
    }

    #[test]
    fn test_keeper_clear() {
        let mut keeper = UndoRedoKeeper::new(50);
        keeper.add_undo(Box::new(TestEdit::new("A")));
        keeper.add_undo(Box::new(TestEdit::new("B")));
        keeper.undo().unwrap();

        keeper.clear();
        assert!(!keeper.can_undo());
        assert!(!keeper.can_redo());
    }

    #[test]
    fn test_keeper_all_names() {
        let mut keeper = UndoRedoKeeper::new(50);
        keeper.add_undo(Box::new(TestEdit::new("A")));
        keeper.add_undo(Box::new(TestEdit::new("B")));
        keeper.add_undo(Box::new(TestEdit::new("C")));

        assert_eq!(keeper.all_undo_names(), vec!["C", "B", "A"]);
        assert!(keeper.all_redo_names().is_empty());
    }

    // --- UndoService trait tests ---

    #[derive(Debug)]
    struct MockUndoService {
        undo_stack: Vec<String>,
        redo_stack: Vec<String>,
    }

    impl MockUndoService {
        fn new() -> Self {
            Self {
                undo_stack: Vec::new(),
                redo_stack: Vec::new(),
            }
        }
    }

    impl UndoService for MockUndoService {
        fn can_undo(&self) -> bool {
            !self.undo_stack.is_empty()
        }
        fn can_redo(&self) -> bool {
            !self.redo_stack.is_empty()
        }
        fn undo(&mut self) -> Result<(), UndoError> {
            if let Some(name) = self.undo_stack.pop() {
                self.redo_stack.push(name);
                Ok(())
            } else {
                Err(UndoError::NothingToUndo)
            }
        }
        fn redo(&mut self) -> Result<(), UndoError> {
            if let Some(name) = self.redo_stack.pop() {
                self.undo_stack.push(name);
                Ok(())
            } else {
                Err(UndoError::NothingToRedo)
            }
        }
        fn undo_name(&self) -> Option<String> {
            self.undo_stack.last().cloned()
        }
        fn redo_name(&self) -> Option<String> {
            self.redo_stack.last().cloned()
        }
        fn all_undo_names(&self) -> Vec<String> {
            self.undo_stack.iter().rev().cloned().collect()
        }
        fn all_redo_names(&self) -> Vec<String> {
            self.redo_stack.iter().rev().cloned().collect()
        }
        fn clear_undo(&mut self) {
            self.undo_stack.clear();
            self.redo_stack.clear();
        }
    }

    #[test]
    fn test_undo_service_basic() {
        let mut svc = MockUndoService::new();
        assert!(!svc.can_undo());
        assert!(!svc.can_redo());

        svc.undo_stack.push("Edit A".into());
        svc.undo_stack.push("Edit B".into());
        assert!(svc.can_undo());
        assert_eq!(svc.undo_name(), Some("Edit B".into()));

        svc.undo().unwrap();
        assert!(svc.can_redo());
        assert_eq!(svc.redo_name(), Some("Edit B".into()));
    }

    #[test]
    fn test_undo_service_n() {
        let mut svc = MockUndoService::new();
        svc.undo_stack.push("A".into());
        svc.undo_stack.push("B".into());
        svc.undo_stack.push("C".into());

        svc.undo_n(2).unwrap();
        assert_eq!(svc.undo_name(), Some("A".into()));
        assert_eq!(svc.redo_stack.len(), 2);
    }

    #[test]
    fn test_undo_service_n_too_many() {
        let mut svc = MockUndoService::new();
        svc.undo_stack.push("A".into());
        assert!(svc.undo_n(5).is_err());
    }

    #[test]
    fn test_undo_service_clear() {
        let mut svc = MockUndoService::new();
        svc.undo_stack.push("A".into());
        svc.redo_stack.push("B".into());

        svc.clear_undo();
        assert!(!svc.can_undo());
        assert!(!svc.can_redo());
    }

    // --- UndoRedoToolState tests ---

    #[test]
    fn test_tool_state_empty() {
        let state = UndoRedoToolState::new();
        assert!(state.is_empty());
        assert_eq!(state.plugin_count(), 0);
    }

    #[test]
    fn test_tool_state_save_and_retrieve() {
        let mut state = UndoRedoToolState::new();
        state.save_plugin_state("CodeBrowser", vec![1, 2, 3]);
        state.save_plugin_state("Listing", vec![4, 5, 6]);

        assert_eq!(state.plugin_count(), 2);
        assert_eq!(
            state.get_plugin_state("CodeBrowser"),
            Some(&vec![1, 2, 3])
        );
        assert_eq!(state.get_plugin_state("Listing"), Some(&vec![4, 5, 6]));
        assert_eq!(state.get_plugin_state("Unknown"), None);
    }

    #[test]
    fn test_tool_state_plugin_names() {
        let mut state = UndoRedoToolState::new();
        state.save_plugin_state("Alpha", vec![]);
        state.save_plugin_state("Beta", vec![]);

        let names: Vec<&str> = state.plugin_names().collect();
        assert_eq!(names, vec!["Alpha", "Beta"]);
    }

    #[test]
    fn test_tool_state_clear() {
        let mut state = UndoRedoToolState::new();
        state.save_plugin_state("Plugin", vec![1]);
        state.clear();
        assert!(state.is_empty());
    }

    // --- UndoStateInfo tests ---

    #[test]
    fn test_undo_state_info_default() {
        let info = UndoStateInfo::default();
        assert!(!info.can_undo);
        assert!(!info.can_redo);
        assert_eq!(info.undo_count, 0);
    }

    #[test]
    fn test_undo_state_info_from_service() {
        let mut svc = MockUndoService::new();
        svc.undo_stack.push("A".into());
        svc.undo_stack.push("B".into());

        let info = UndoStateInfo::from_service(&svc);
        assert!(info.can_undo);
        assert!(!info.can_redo);
        assert_eq!(info.undo_count, 2);
        assert_eq!(info.undo_name, Some("B".into()));
    }

    // --- UndoError tests ---

    #[test]
    fn test_undo_error_display() {
        let err = UndoError::NothingToUndo;
        assert_eq!(format!("{}", err), "Nothing to undo");

        let err = UndoError::CannotUndo("locked".into());
        assert_eq!(format!("{}", err), "Cannot undo: locked");
    }
}
