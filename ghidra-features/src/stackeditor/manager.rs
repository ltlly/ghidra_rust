//! Stack editor manager -- ported from
//! `ghidra.app.plugin.core.stackeditor.StackEditorManager` and
//! `StackEditorManagerPlugin`.
//!
//! Manages open stack editor sessions and provides the plugin-level
//! interface for editing function stack frames.

use ghidra_core::Address;
use std::collections::HashMap;

use super::StackEditorModel;
use super::frame_datatype::StackFrameDataType;

/// An edit session for a function's stack frame.
#[derive(Debug)]
pub struct StackEditorSession {
    /// The function address being edited.
    pub function_address: Address,
    /// The stack editor model for this session.
    pub model: StackEditorModel,
    /// The stack frame data type.
    pub frame: StackFrameDataType,
    /// Whether the session has unsaved changes.
    pub dirty: bool,
    /// Whether the session is read-only.
    pub read_only: bool,
}

impl StackEditorSession {
    /// Create a new session for a function.
    pub fn new(
        function_address: Address,
        model: StackEditorModel,
        frame: StackFrameDataType,
    ) -> Self {
        Self {
            function_address,
            model,
            frame,
            dirty: false,
            read_only: false,
        }
    }

    /// Whether the session has unsaved changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty || self.model.is_dirty()
    }

    /// Mark the session as saved.
    pub fn mark_saved(&mut self) {
        self.dirty = false;
        self.model.clear_dirty();
    }
}

/// Options for the stack editor.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorOptionManager`.
#[derive(Debug, Clone)]
pub struct StackEditorOptions {
    /// Whether to show numeric values in hexadecimal.
    pub show_numbers_in_hex: bool,
    /// The editor name.
    pub editor_name: String,
}

impl Default for StackEditorOptions {
    fn default() -> Self {
        Self {
            show_numbers_in_hex: true,
            editor_name: "Stack Editor".into(),
        }
    }
}

impl StackEditorOptions {
    /// Create new default options.
    pub fn new() -> Self {
        Self::default()
    }
}

/// Manages multiple stack editor sessions.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorManager`.
///
/// Tracks which functions currently have open editor sessions, handles
/// session creation, and manages session lifecycle.
#[derive(Debug)]
pub struct StackEditorManager {
    /// Active sessions, keyed by function address.
    sessions: HashMap<u64, StackEditorSession>,
    /// Editor options.
    pub options: StackEditorOptions,
}

impl StackEditorManager {
    /// Create a new stack editor manager.
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            options: StackEditorOptions::default(),
        }
    }

    /// Open a new editor session for a function.
    ///
    /// If a session already exists for this function, it is returned (not duplicated).
    pub fn open_session(
        &mut self,
        function_address: Address,
        frame_size: usize,
        grows_negative: bool,
        return_address_offset: i32,
        parameter_offset: i32,
        local_size: usize,
        param_size: usize,
    ) -> &mut StackEditorSession {
        let offset = function_address.offset;
        if !self.sessions.contains_key(&offset) {
            let model = StackEditorModel::new(function_address, frame_size);
            let frame = StackFrameDataType::new(
                grows_negative,
                return_address_offset,
                parameter_offset,
                local_size,
                param_size,
            );
            let session = StackEditorSession::new(function_address, model, frame);
            self.sessions.insert(offset, session);
        }
        self.sessions.get_mut(&offset).unwrap()
    }

    /// Get an existing session for a function.
    pub fn get_session(&self, function_address: Address) -> Option<&StackEditorSession> {
        self.sessions.get(&function_address.offset)
    }

    /// Get a mutable reference to an existing session.
    pub fn get_session_mut(
        &mut self,
        function_address: Address,
    ) -> Option<&mut StackEditorSession> {
        self.sessions.get_mut(&function_address.offset)
    }

    /// Close the session for a function.
    ///
    /// Returns `true` if a session existed and was closed.
    pub fn close_session(&mut self, function_address: Address) -> bool {
        self.sessions.remove(&function_address.offset).is_some()
    }

    /// Check if any session has unsaved changes.
    pub fn has_dirty_sessions(&self) -> bool {
        self.sessions.values().any(|s| s.is_dirty())
    }

    /// Try to close all sessions.
    ///
    /// Returns `true` if all sessions were closed. Returns `false` if
    /// there are dirty sessions that should be confirmed first.
    pub fn can_close_all(&self) -> bool {
        !self.has_dirty_sessions()
    }

    /// Close all sessions (even dirty ones).
    pub fn close_all(&mut self) {
        self.sessions.clear();
    }

    /// Get the number of open sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Get all open function addresses.
    pub fn open_functions(&self) -> Vec<Address> {
        self.sessions
            .values()
            .map(|s| s.function_address)
            .collect()
    }

    /// Whether a session is open for a function.
    pub fn is_open(&self, function_address: Address) -> bool {
        self.sessions.contains_key(&function_address.offset)
    }
}

impl Default for StackEditorManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_editor_session() {
        let model = StackEditorModel::new(Address::new(0x1000), 64);
        let frame = StackFrameDataType::new(true, 4, 0, 16, 8);
        let mut session = StackEditorSession::new(Address::new(0x1000), model, frame);
        assert!(!session.is_dirty());
        session.model.set_frame_size(128);
        assert!(session.is_dirty());
        session.mark_saved();
        assert!(!session.is_dirty());
    }

    #[test]
    fn test_stack_editor_options_default() {
        let opts = StackEditorOptions::default();
        assert!(opts.show_numbers_in_hex);
        assert_eq!(opts.editor_name, "Stack Editor");
    }

    #[test]
    fn test_manager_open_and_get_session() {
        let mut mgr = StackEditorManager::new();
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        assert_eq!(mgr.session_count(), 1);
        assert!(mgr.is_open(Address::new(0x1000)));
        assert!(!mgr.is_open(Address::new(0x2000)));

        let session = mgr.get_session(Address::new(0x1000)).unwrap();
        assert_eq!(session.function_address, Address::new(0x1000));
    }

    #[test]
    fn test_manager_open_duplicate() {
        let mut mgr = StackEditorManager::new();
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        mgr.open_session(Address::new(0x1000), 128, true, 4, 0, 32, 8);
        // Should not create a second session
        assert_eq!(mgr.session_count(), 1);
    }

    #[test]
    fn test_manager_close_session() {
        let mut mgr = StackEditorManager::new();
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        assert!(mgr.close_session(Address::new(0x1000)));
        assert_eq!(mgr.session_count(), 0);
        assert!(!mgr.close_session(Address::new(0x1000)));
    }

    #[test]
    fn test_manager_has_dirty_sessions() {
        let mut mgr = StackEditorManager::new();
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        assert!(!mgr.has_dirty_sessions());
        // Modify the model
        mgr.get_session_mut(Address::new(0x1000))
            .unwrap()
            .model
            .set_frame_size(128);
        assert!(mgr.has_dirty_sessions());
    }

    #[test]
    fn test_manager_can_close_all() {
        let mut mgr = StackEditorManager::new();
        assert!(mgr.can_close_all());
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        assert!(mgr.can_close_all());
        mgr.get_session_mut(Address::new(0x1000))
            .unwrap()
            .model
            .set_frame_size(128);
        assert!(!mgr.can_close_all());
    }

    #[test]
    fn test_manager_close_all() {
        let mut mgr = StackEditorManager::new();
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        mgr.open_session(Address::new(0x2000), 32, true, 4, 0, 8, 8);
        assert_eq!(mgr.session_count(), 2);
        mgr.close_all();
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_manager_open_functions() {
        let mut mgr = StackEditorManager::new();
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        mgr.open_session(Address::new(0x2000), 32, true, 4, 0, 8, 8);
        let functions = mgr.open_functions();
        assert_eq!(functions.len(), 2);
    }

    #[test]
    fn test_manager_get_session_mut() {
        let mut mgr = StackEditorManager::new();
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        let session = mgr.get_session_mut(Address::new(0x1000)).unwrap();
        session.model.set_frame_size(128);
        assert!(session.model.is_dirty());
    }
}
