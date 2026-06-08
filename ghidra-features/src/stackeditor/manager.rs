//! Stack editor manager -- ported from
//! `ghidra.app.plugin.core.stackeditor.StackEditorManager` and
//! `StackEditorManagerPlugin`.
//!
//! Manages open stack editor sessions, provides program-level close
//! semantics, editor listener integration, and check-before-close logic.

use ghidra_core::Address;
use std::collections::HashMap;

use super::StackEditorModel;
use super::frame_datatype::StackFrameDataType;
use super::provider::StackEditorProvider;

// ============================================================================
// StackEditorSession -- an edit session for one function
// ============================================================================

/// An edit session for a function's stack frame.
///
/// Groups the editor provider, model, and frame data type for a single
/// function being edited.
#[derive(Debug)]
pub struct StackEditorSession {
    /// The function address being edited.
    pub function_address: Address,
    /// The stack editor model for this session.
    pub model: StackEditorModel,
    /// The stack frame data type.
    pub frame: StackFrameDataType,
    /// The editor provider for this session.
    pub provider: StackEditorProvider,
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
        provider: StackEditorProvider,
    ) -> Self {
        Self {
            function_address,
            model,
            frame,
            provider,
            dirty: false,
            read_only: false,
        }
    }

    /// Whether the session has unsaved changes.
    ///
    /// Checks both the session-level dirty flag and the model's dirty state.
    pub fn is_dirty(&self) -> bool {
        self.dirty || self.model.is_dirty() || self.provider.needs_save()
    }

    /// Mark the session as saved.
    pub fn mark_saved(&mut self) {
        self.dirty = false;
        self.model.clear_dirty();
        self.provider.set_changed(false);
    }

    /// Show the editor provider for this session.
    pub fn show(&mut self) {
        self.provider.show();
    }

    /// Dispose of this session, cleaning up the provider.
    pub fn dispose(&mut self) {
        self.provider.dispose();
    }
}

// ============================================================================
// StackEditorOptions -- display options
// ============================================================================

/// Options for the stack editor.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorOptionManager`.
#[derive(Debug, Clone)]
pub struct StackEditorOptions {
    /// Whether to show numeric values in hexadecimal.
    pub show_numbers_in_hex: bool,
    /// The editor name.
    pub editor_name: String,
    /// The hex option name path.
    hex_option_name: String,
}

impl Default for StackEditorOptions {
    fn default() -> Self {
        Self {
            show_numbers_in_hex: true,
            editor_name: "Stack Editor".into(),
            hex_option_name: "Stack Editor/Show Numbers In Hex".into(),
        }
    }
}

impl StackEditorOptions {
    /// Create new default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the hex option name path.
    pub fn hex_option_name(&self) -> &str {
        &self.hex_option_name
    }

    /// Toggle the hex display option.
    pub fn toggle_hex(&mut self) {
        self.show_numbers_in_hex = !self.show_numbers_in_hex;
    }

    /// Set the hex display option.
    pub fn set_show_numbers_in_hex(&mut self, show: bool) {
        self.show_numbers_in_hex = show;
    }

    /// Get the hex display option.
    pub fn show_numbers_in_hex(&self) -> bool {
        self.show_numbers_in_hex
    }
}

// ============================================================================
// StackEditorManager -- manages multiple sessions
// ============================================================================

/// Manages multiple stack editor sessions.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorManager`.
///
/// Tracks which functions currently have open editor sessions, handles
/// session creation, program-level close, and check-before-close logic.
#[derive(Debug)]
pub struct StackEditorManager {
    /// Active sessions, keyed by function address offset.
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

    // -----------------------------------------------------------------------
    // Session lifecycle
    //
    // Ported from StackEditorManager.edit() and related methods.
    // -----------------------------------------------------------------------

    /// Open a new editor session for a function.
    ///
    /// If a session already exists for this function, it is returned (not duplicated).
    /// Corresponds to `StackEditorManager.edit(Function)`.
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
            let provider = StackEditorProvider::new(
                format!("func_{:x}", offset),
                "program",
                offset,
                offset,
            );
            let session = StackEditorSession::new(function_address, model, frame, provider);
            self.sessions.insert(offset, session);
        }
        self.sessions.get_mut(&offset).unwrap()
    }

    /// Open a session with a custom provider.
    ///
    /// Used when the caller already has a `StackEditorProvider` (e.g., from the plugin).
    pub fn open_session_with_provider(
        &mut self,
        function_address: Address,
        frame_size: usize,
        grows_negative: bool,
        return_address_offset: i32,
        parameter_offset: i32,
        local_size: usize,
        param_size: usize,
        provider: StackEditorProvider,
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
            let session = StackEditorSession::new(function_address, model, frame, provider);
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
    /// Corresponds to dismissing a single editor.
    pub fn close_session(&mut self, function_address: Address) -> bool {
        if let Some(mut session) = self.sessions.remove(&function_address.offset) {
            session.dispose();
            true
        } else {
            false
        }
    }

    // -----------------------------------------------------------------------
    // Program-level close
    //
    // Ported from StackEditorManager.programClosed() and
    // StackEditorManager.dismissEditors(Program).
    // -----------------------------------------------------------------------

    /// Close all sessions associated with a program.
    ///
    /// Corresponds to `StackEditorManager.programClosed(Program)`.
    ///
    /// Since we don't have a Program object, this closes sessions matching
    /// the given set of function addresses (i.e., all functions in the program).
    pub fn close_sessions_for_program(&mut self, program_function_addresses: &[Address]) {
        let addresses: Vec<u64> = program_function_addresses
            .iter()
            .map(|a| a.offset)
            .collect();
        let to_remove: Vec<u64> = self
            .sessions
            .keys()
            .filter(|k| addresses.contains(k))
            .copied()
            .collect();
        for addr in to_remove {
            if let Some(mut session) = self.sessions.remove(&addr) {
                session.dispose();
            }
        }
    }

    /// Dismiss all editors for a program (or all if no program specified).
    ///
    /// Corresponds to `StackEditorManager.dismissEditors(Program)`.
    /// When `program_filter` is `None`, all editors are dismissed.
    pub fn dismiss_editors(&mut self, program_filter: Option<&[Address]>) {
        match program_filter {
            Some(addresses) => {
                self.close_sessions_for_program(addresses);
            }
            None => {
                for (_, mut session) in self.sessions.drain() {
                    session.dispose();
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Check-before-close
    //
    // Ported from StackEditorManager.checkEditors(Program) and
    // canCloseDomainObject(DomainObject)/canClose().
    // -----------------------------------------------------------------------

    /// Check if all editors can close (no dirty sessions).
    ///
    /// Corresponds to `StackEditorManager.canClose()` (all programs).
    pub fn can_close_all(&self) -> bool {
        !self.has_dirty_sessions()
    }

    /// Check if editors for a specific program can close.
    ///
    /// Corresponds to `StackEditorManager.canCloseDomainObject(DomainObject)`.
    /// Returns `true` if all editors for the given program are clean.
    pub fn can_close_program(&self, program_function_addresses: &[Address]) -> bool {
        let addresses: Vec<u64> = program_function_addresses
            .iter()
            .map(|a| a.offset)
            .collect();
        !self
            .sessions
            .iter()
            .any(|(k, v)| addresses.contains(k) && v.is_dirty())
    }

    /// Check all editors for unsaved changes.
    ///
    /// For each dirty editor, the caller should prompt the user.
    /// Returns `true` if all editors were resolved (saved or discarded).
    ///
    /// Corresponds to `StackEditorManager.checkEditors(Program)`.
    pub fn check_editors(&mut self, program_filter: Option<&[Address]>) -> EditorCheckResult {
        let dirty_sessions: Vec<u64> = match program_filter {
            Some(addresses) => {
                let addrs: Vec<u64> = addresses.iter().map(|a| a.offset).collect();
                self.sessions
                    .iter()
                    .filter(|(k, v)| addrs.contains(k) && v.is_dirty())
                    .map(|(k, _)| *k)
                    .collect()
            }
            None => self
                .sessions
                .iter()
                .filter(|(_, v)| v.is_dirty())
                .map(|(k, _)| *k)
                .collect(),
        };

        if dirty_sessions.is_empty() {
            return EditorCheckResult::AllClean;
        }

        EditorCheckResult::HasDirtySessions {
            function_addresses: dirty_sessions,
        }
    }

    /// Force-close all sessions (even dirty ones).
    ///
    /// Corresponds to `StackEditorManager.close()`.
    pub fn close_all(&mut self) {
        for (_, mut session) in self.sessions.drain() {
            session.dispose();
        }
    }

    // -----------------------------------------------------------------------
    // Query methods
    // -----------------------------------------------------------------------

    /// Check if any session has unsaved changes.
    pub fn has_dirty_sessions(&self) -> bool {
        self.sessions.values().any(|s| s.is_dirty())
    }

    /// Whether there is at least one edit in progress.
    ///
    /// Corresponds to `StackEditorManager.isEditInProgress()`.
    pub fn is_edit_in_progress(&self) -> bool {
        !self.sessions.is_empty()
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

    /// Show an existing session's editor.
    ///
    /// Corresponds to showing the editor when `edit()` is called for
    /// an already-open function.
    pub fn show_session(&mut self, function_address: Address) -> bool {
        if let Some(session) = self.sessions.get_mut(&function_address.offset) {
            session.show();
            true
        } else {
            false
        }
    }
}

impl Default for StackEditorManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// EditorCheckResult -- result of checking editors before close
// ============================================================================

/// Result of checking editors for unsaved changes before closing.
#[derive(Debug)]
pub enum EditorCheckResult {
    /// All editors are clean (no unsaved changes).
    AllClean,
    /// Some editors have unsaved changes.
    HasDirtySessions {
        /// The function addresses of the dirty sessions.
        function_addresses: Vec<u64>,
    },
}

impl EditorCheckResult {
    /// Whether all editors are clean.
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::AllClean)
    }

    /// Get the dirty function addresses, if any.
    pub fn dirty_addresses(&self) -> &[u64] {
        match self {
            Self::AllClean => &[],
            Self::HasDirtySessions {
                function_addresses, ..
            } => function_addresses,
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_editor_session() {
        let model = StackEditorModel::new(Address::new(0x1000), 64);
        let frame = StackFrameDataType::new(true, 4, 0, 16, 8);
        let provider = StackEditorProvider::new("testFunc", "testProg", 0x1000, 0x1000);
        let mut session = StackEditorSession::new(Address::new(0x1000), model, frame, provider);
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
        assert_eq!(opts.hex_option_name(), "Stack Editor/Show Numbers In Hex");
    }

    #[test]
    fn test_options_toggle_hex() {
        let mut opts = StackEditorOptions::new();
        assert!(opts.show_numbers_in_hex());
        opts.toggle_hex();
        assert!(!opts.show_numbers_in_hex());
        opts.set_show_numbers_in_hex(true);
        assert!(opts.show_numbers_in_hex());
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

    // -----------------------------------------------------------------------
    // Program-level close tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_close_sessions_for_program() {
        let mut mgr = StackEditorManager::new();
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        mgr.open_session(Address::new(0x2000), 32, true, 4, 0, 8, 8);
        mgr.open_session(Address::new(0x3000), 16, true, 4, 0, 4, 4);

        // Close sessions for "program A" (addresses 0x1000 and 0x2000)
        mgr.close_sessions_for_program(&[Address::new(0x1000), Address::new(0x2000)]);
        assert_eq!(mgr.session_count(), 1);
        assert!(mgr.is_open(Address::new(0x3000)));
        assert!(!mgr.is_open(Address::new(0x1000)));
    }

    #[test]
    fn test_can_close_program() {
        let mut mgr = StackEditorManager::new();
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        mgr.open_session(Address::new(0x2000), 32, true, 4, 0, 8, 8);

        // Make session at 0x1000 dirty
        mgr.get_session_mut(Address::new(0x1000))
            .unwrap()
            .model
            .set_frame_size(128);

        // Program with address 0x2000 only -- should be closable
        assert!(mgr.can_close_program(&[Address::new(0x2000)]));

        // Program with addresses 0x1000 and 0x2000 -- has dirty session
        assert!(!mgr.can_close_program(&[
            Address::new(0x1000),
            Address::new(0x2000)
        ]));
    }

    #[test]
    fn test_dismiss_editors_none() {
        let mut mgr = StackEditorManager::new();
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        mgr.open_session(Address::new(0x2000), 32, true, 4, 0, 8, 8);

        mgr.dismiss_editors(None);
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_dismiss_editors_filtered() {
        let mut mgr = StackEditorManager::new();
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        mgr.open_session(Address::new(0x2000), 32, true, 4, 0, 8, 8);

        mgr.dismiss_editors(Some(&[Address::new(0x1000)]));
        assert_eq!(mgr.session_count(), 1);
        assert!(!mgr.is_open(Address::new(0x1000)));
        assert!(mgr.is_open(Address::new(0x2000)));
    }

    // -----------------------------------------------------------------------
    // Check-before-close tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_editors_all_clean() {
        let mut mgr = StackEditorManager::new();
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        let result = mgr.check_editors(None);
        assert!(result.is_clean());
    }

    #[test]
    fn test_check_editors_dirty() {
        let mut mgr = StackEditorManager::new();
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        mgr.open_session(Address::new(0x2000), 32, true, 4, 0, 8, 8);

        mgr.get_session_mut(Address::new(0x1000))
            .unwrap()
            .model
            .set_frame_size(128);

        let result = mgr.check_editors(None);
        assert!(!result.is_clean());
        assert_eq!(result.dirty_addresses().len(), 1);
        assert_eq!(result.dirty_addresses()[0], 0x1000);
    }

    #[test]
    fn test_check_editors_filtered() {
        let mut mgr = StackEditorManager::new();
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        mgr.open_session(Address::new(0x2000), 32, true, 4, 0, 8, 8);

        // Make session at 0x2000 dirty
        mgr.get_session_mut(Address::new(0x2000))
            .unwrap()
            .model
            .set_frame_size(64);

        // Check only "program A" (0x1000) -- should be clean
        let result = mgr.check_editors(Some(&[Address::new(0x1000)]));
        assert!(result.is_clean());

        // Check "program B" (0x2000) -- should be dirty
        let result = mgr.check_editors(Some(&[Address::new(0x2000)]));
        assert!(!result.is_clean());
    }

    #[test]
    fn test_editor_check_result() {
        let clean = EditorCheckResult::AllClean;
        assert!(clean.is_clean());
        assert!(clean.dirty_addresses().is_empty());

        let dirty = EditorCheckResult::HasDirtySessions {
            function_addresses: vec![0x1000, 0x2000],
        };
        assert!(!dirty.is_clean());
        assert_eq!(dirty.dirty_addresses().len(), 2);
    }

    // -----------------------------------------------------------------------
    // Show session test
    // -----------------------------------------------------------------------

    #[test]
    fn test_show_session() {
        let mut mgr = StackEditorManager::new();
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        assert!(mgr.show_session(Address::new(0x1000)));
        assert!(mgr.get_session(Address::new(0x1000)).unwrap().provider.is_visible());
        assert!(!mgr.show_session(Address::new(0x9999)));
    }

    // -----------------------------------------------------------------------
    // is_edit_in_progress test
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_edit_in_progress() {
        let mut mgr = StackEditorManager::new();
        assert!(!mgr.is_edit_in_progress());
        mgr.open_session(Address::new(0x1000), 64, true, 4, 0, 16, 8);
        assert!(mgr.is_edit_in_progress());
        mgr.close_session(Address::new(0x1000));
        assert!(!mgr.is_edit_in_progress());
    }

    // -----------------------------------------------------------------------
    // Session dispose test
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_dispose() {
        let model = StackEditorModel::new(Address::new(0x1000), 64);
        let frame = StackFrameDataType::new(true, 4, 0, 16, 8);
        let mut provider = StackEditorProvider::new("func", "prog", 0x1000, 0x1000);
        provider.show();
        let mut session = StackEditorSession::new(Address::new(0x1000), model, frame, provider);
        assert!(session.provider.is_visible());
        session.dispose();
        assert!(!session.provider.is_visible());
    }
}
