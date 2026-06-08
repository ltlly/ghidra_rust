//! Stack Editor Provider -- editor for a function's stack frame.
//!
//! Ported from `ghidra.app.plugin.core.stackeditor.StackEditorProvider`.
//!
//! Provides the component provider for editing a function's stack frame,
//! including domain-object change handling, delayed update management,
//! function lifecycle tracking, and variable management.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use super::StackEditorAction;

// ============================================================================
// ProgramEvent -- domain object change events (ported from ProgramEvent)
// ============================================================================

/// Events emitted when a program's domain object changes.
///
/// Ported from `ghidra.program.util.ProgramEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramEvent {
    /// A function was removed from the program.
    FunctionRemoved,
    /// A function was changed in the program.
    FunctionChanged,
    /// A symbol was renamed.
    SymbolRenamed,
    /// A symbol's data changed.
    SymbolDataChanged,
    /// A symbol was added.
    SymbolAdded,
    /// A symbol was removed.
    SymbolRemoved,
    /// A symbol's address changed.
    SymbolAddressChanged,
    /// A symbol's primary state changed.
    SymbolPrimaryStateChanged,
}

/// A domain object event type.
///
/// Ported from `ghidra.framework.model.DomainObjectEvent`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainObjectEvent {
    /// The file backing the domain object changed.
    FileChanged,
    /// The domain object was restored (e.g. after undo).
    Restored,
    /// A program-specific event.
    Program(ProgramEvent),
}

/// A change record from a domain object change event.
///
/// Ported from `ghidra.framework.model.DomainObjectChangeRecord`.
#[derive(Debug, Clone)]
pub struct DomainObjectChangeRecord {
    /// The event type.
    pub event_type: DomainObjectEvent,
    /// The affected address (if applicable).
    pub affected_address: Option<u64>,
    /// The affected function entry point (if applicable).
    pub function_entry: Option<u64>,
    /// The affected name (for rename events).
    pub affected_name: Option<String>,
    /// The affected object identifier.
    pub object_id: Option<u64>,
}

impl DomainObjectChangeRecord {
    /// Create a new change record.
    pub fn new(event_type: DomainObjectEvent) -> Self {
        Self {
            event_type,
            affected_address: None,
            function_entry: None,
            affected_name: None,
            object_id: None,
        }
    }

    /// Set the affected address.
    pub fn with_address(mut self, addr: u64) -> Self {
        self.affected_address = Some(addr);
        self
    }

    /// Set the affected function entry point.
    pub fn with_function_entry(mut self, entry: u64) -> Self {
        self.function_entry = Some(entry);
        self
    }

    /// Set the affected name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.affected_name = Some(name.into());
        self
    }

    /// Set the object identifier.
    pub fn with_object_id(mut self, id: u64) -> Self {
        self.object_id = Some(id);
        self
    }
}

// ============================================================================
// DelayedUpdateManager -- coalesces rapid change events
// ============================================================================

/// A coalescing update manager that defers refresh operations.
///
/// Ported from `ghidra.util.task.SwingUpdateManager`. Delays processing
/// of multiple rapid domain-object change events to avoid redundant
/// refreshes.
#[derive(Debug)]
pub struct DelayedUpdateManager {
    /// Minimum delay between updates.
    delay: Duration,
    /// The pending update closure description.
    pending_update: Option<PendingUpdate>,
    /// Timestamp of last processed update.
    last_update: Option<Instant>,
}

/// Describes a pending update that the delayed manager will execute.
#[derive(Debug, Clone)]
pub struct PendingUpdate {
    /// Whether to refresh the title (function renamed).
    pub refresh_name: bool,
    /// Whether to reload the stack model (function changed).
    pub reload: bool,
    /// When the update was scheduled.
    pub scheduled_at: Instant,
}

impl DelayedUpdateManager {
    /// Create a new delayed update manager with the given delay in milliseconds.
    pub fn new(delay_ms: u64) -> Self {
        Self {
            delay: Duration::from_millis(delay_ms),
            pending_update: None,
            last_update: None,
        }
    }

    /// Schedule a name refresh (title update).
    pub fn schedule_refresh_name(&mut self) {
        let now = Instant::now();
        match &mut self.pending_update {
            Some(pending) => {
                pending.refresh_name = true;
                pending.scheduled_at = now;
            }
            None => {
                self.pending_update = Some(PendingUpdate {
                    refresh_name: true,
                    reload: false,
                    scheduled_at: now,
                });
            }
        }
    }

    /// Schedule a full model reload.
    pub fn schedule_reload(&mut self) {
        let now = Instant::now();
        match &mut self.pending_update {
            Some(pending) => {
                pending.reload = true;
                pending.scheduled_at = now;
            }
            None => {
                self.pending_update = Some(PendingUpdate {
                    refresh_name: false,
                    reload: true,
                    scheduled_at: now,
                });
            }
        }
    }

    /// Check if enough time has passed to process the pending update.
    pub fn should_process(&self) -> bool {
        match &self.pending_update {
            Some(pending) => pending.scheduled_at.elapsed() >= self.delay,
            None => false,
        }
    }

    /// Take the pending update if ready to process.
    pub fn take_pending(&mut self) -> Option<PendingUpdate> {
        if self.should_process() {
            self.last_update = Some(Instant::now());
            self.pending_update.take()
        } else {
            None
        }
    }

    /// Check whether there is a pending update.
    pub fn has_pending(&self) -> bool {
        self.pending_update.is_some()
    }

    /// Clear all pending updates.
    pub fn clear(&mut self) {
        self.pending_update = None;
    }

    /// Dispose of the manager.
    pub fn dispose(&mut self) {
        self.pending_update = None;
        self.last_update = None;
    }
}

// ============================================================================
// EditorListener -- callback for editor close events
// ============================================================================

/// A listener for editor lifecycle events.
///
/// Ported from `ghidra.app.plugin.core.compositeeditor.EditorListener`.
pub trait EditorListener {
    /// Called when an editor is closed.
    fn closed(&self, function_address: u64);
}

// ============================================================================
// StackEditorProvider -- the component provider for one function
// ============================================================================

/// The provider that hosts the stack editor UI for a single function.
///
/// Ported from `ghidra.app.plugin.core.stackeditor.StackEditorProvider`.
///
/// Each open function stack editor gets its own `StackEditorProvider`.
/// Handles domain-object change events with a delayed update manager,
/// function lifecycle tracking, and pending edit actions.
pub struct StackEditorProvider {
    /// The function name being edited.
    pub function_name: String,
    /// The program name containing the function.
    pub program_name: String,
    /// The function address.
    pub function_address: u64,
    /// The function entry point (for symbol change matching).
    pub function_entry: u64,
    /// The display title for this provider.
    title: String,
    /// Whether this provider is visible.
    visible: bool,
    /// Whether the editor has unsaved changes.
    has_changes: bool,
    /// Whether the function has been deleted.
    function_deleted: bool,
    /// Pending actions to apply.
    pending_actions: Vec<StackEditorAction>,
    /// Delayed update manager for coalescing change events.
    delayed_update_mgr: DelayedUpdateManager,
    /// Registered editor listeners.
    listeners: Vec<usize>,
    /// Next listener ID.
    next_listener_id: usize,
    /// Map of listener IDs to close callbacks.
    listener_map: HashMap<usize, Box<dyn Fn(u64)>>,
}

impl fmt::Debug for StackEditorProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StackEditorProvider")
            .field("function_name", &self.function_name)
            .field("program_name", &self.program_name)
            .field("function_address", &self.function_address)
            .field("function_entry", &self.function_entry)
            .field("title", &self.title)
            .field("visible", &self.visible)
            .field("has_changes", &self.has_changes)
            .field("function_deleted", &self.function_deleted)
            .field("pending_actions", &self.pending_actions)
            .field("delayed_update_mgr", &self.delayed_update_mgr)
            .field("listeners", &self.listeners)
            .field("listener_count", &self.listener_map.len())
            .finish()
    }
}

impl StackEditorProvider {
    /// Delay in milliseconds for coalescing domain object change events.
    const UPDATE_DELAY_MS: u64 = 200;

    /// Create a new stack editor provider for a function.
    pub fn new(
        function_name: impl Into<String>,
        program_name: impl Into<String>,
        function_address: u64,
        function_entry: u64,
    ) -> Self {
        let fn_name = function_name.into();
        let pgm_name = program_name.into();
        let title = Self::build_title(&fn_name, &pgm_name);
        Self {
            function_name: fn_name,
            program_name: pgm_name,
            function_address,
            function_entry,
            title,
            visible: false,
            has_changes: false,
            function_deleted: false,
            pending_actions: Vec::new(),
            delayed_update_mgr: DelayedUpdateManager::new(Self::UPDATE_DELAY_MS),
            listeners: Vec::new(),
            next_listener_id: 0,
            listener_map: HashMap::new(),
        }
    }

    /// Build the provider title from function and program names.
    fn build_title(function_name: &str, program_name: &str) -> String {
        format!("Stack Editor - {} ({})", function_name, program_name)
    }

    /// Get the provider sub-title (function name + program file).
    ///
    /// Corresponds to `StackEditorProvider.getProviderSubTitle()`.
    pub fn get_provider_sub_title(&self) -> String {
        format!("{} ({})", self.function_name, self.program_name)
    }

    /// Get the display title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Get the display name (function name).
    pub fn display_name(&self) -> String {
        format!("stack frame: {}", self.function_name)
    }

    /// Show the provider.
    pub fn show(&mut self) {
        self.visible = true;
    }

    /// Hide the provider.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Whether the editor has unsaved changes.
    pub fn needs_save(&self) -> bool {
        self.has_changes
    }

    /// Mark the editor as having changes.
    pub fn set_changed(&mut self, changed: bool) {
        self.has_changes = changed;
    }

    /// Whether the function has been deleted.
    pub fn is_function_deleted(&self) -> bool {
        self.function_deleted
    }

    /// Queue an action to be applied.
    pub fn queue_action(&mut self, action: StackEditorAction) {
        self.pending_actions.push(action);
        self.has_changes = true;
    }

    /// Take all pending actions.
    pub fn take_pending_actions(&mut self) -> Vec<StackEditorAction> {
        std::mem::take(&mut self.pending_actions)
    }

    /// Get the help name for context help.
    pub fn help_name(&self) -> &str {
        "Stack_Editor"
    }

    /// Get the help topic.
    pub fn help_topic(&self) -> &str {
        "StackEditor"
    }

    /// Register a listener for editor close events.
    ///
    /// Returns a listener ID that can be used to unregister.
    pub fn add_editor_listener<F: Fn(u64) + 'static>(&mut self, callback: F) -> usize {
        let id = self.next_listener_id;
        self.next_listener_id += 1;
        self.listeners.push(id);
        self.listener_map.insert(id, Box::new(callback));
        id
    }

    /// Remove a listener by ID.
    pub fn remove_editor_listener(&mut self, listener_id: usize) {
        self.listeners.retain(|&id| id != listener_id);
        self.listener_map.remove(&listener_id);
    }

    /// Notify all listeners that this editor has been closed.
    fn notify_closed(&self) {
        for &id in &self.listeners {
            if let Some(callback) = self.listener_map.get(&id) {
                callback(self.function_address);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Domain object change handling
    //
    // Ported from StackEditorProvider.domainObjectChanged() and
    // StackEditorProvider.inCurrentFunction().
    // -----------------------------------------------------------------------

    /// Process a domain object change event.
    ///
    /// This method corresponds to `domainObjectChanged()` in the Java source.
    /// It examines each change record and schedules appropriate delayed updates.
    pub fn domain_object_changed(&mut self, records: &[DomainObjectChangeRecord]) {
        if !self.visible {
            return;
        }

        for rec in records {
            match rec.event_type {
                DomainObjectEvent::FileChanged => {
                    self.delayed_update_mgr.schedule_refresh_name();
                }
                DomainObjectEvent::Program(ProgramEvent::FunctionRemoved) => {
                    if rec.function_entry == Some(self.function_entry) {
                        // The function was deleted -- close the editor.
                        self.function_deleted = true;
                        return;
                    }
                }
                DomainObjectEvent::Program(ProgramEvent::SymbolRenamed)
                | DomainObjectEvent::Program(ProgramEvent::SymbolDataChanged) => {
                    // If the symbol at the function entry was renamed/changed, refresh title.
                    if rec.affected_address == Some(self.function_entry) {
                        self.delayed_update_mgr.schedule_refresh_name();
                    } else if self.in_current_function(rec) {
                        self.delayed_update_mgr.schedule_reload();
                    }
                }
                DomainObjectEvent::Program(ProgramEvent::FunctionChanged)
                | DomainObjectEvent::Program(ProgramEvent::SymbolAdded)
                | DomainObjectEvent::Program(ProgramEvent::SymbolRemoved)
                | DomainObjectEvent::Program(ProgramEvent::SymbolAddressChanged) => {
                    if self.in_current_function(rec) {
                        self.delayed_update_mgr.schedule_reload();
                    }
                }
                DomainObjectEvent::Program(ProgramEvent::SymbolPrimaryStateChanged) => {
                    if rec.affected_address == Some(self.function_entry) {
                        self.delayed_update_mgr.schedule_refresh_name();
                    }
                }
                _ => {}
            }
        }
    }

    /// Check whether a change record affects the current function.
    ///
    /// Corresponds to `StackEditorProvider.inCurrentFunction()`.
    fn in_current_function(&self, record: &DomainObjectChangeRecord) -> bool {
        if self.function_address == 0 {
            return false;
        }

        // If the change record has a function entry point, check if it matches.
        if let Some(entry) = record.function_entry {
            return entry == self.function_entry;
        }

        // If the change has an affected address, check if it is a variable
        // address within the current function. In the Rust model we use
        // function_address as a proxy for the function's namespace scope.
        if let Some(addr) = record.affected_address {
            // Simplified check: variable addresses in the stack space are
            // considered to be within the function. In the full implementation
            // this would check the symbol table's parent namespace.
            return true; // Conservatively assume any variable-address change is relevant
        }

        false
    }

    /// Check if the delayed update manager has a pending update ready.
    ///
    /// Returns the update actions if ready.
    pub fn poll_delayed_update(&mut self) -> Option<(bool, bool)> {
        let pending = self.delayed_update_mgr.take_pending()?;
        Some((pending.refresh_name, pending.reload))
    }

    /// Whether there is a pending delayed update.
    pub fn has_pending_update(&self) -> bool {
        self.delayed_update_mgr.has_pending()
    }

    /// Process the delayed update. Returns (should_refresh_name, should_reload).
    pub fn process_delayed_update(&mut self) -> (bool, bool) {
        match self.delayed_update_mgr.take_pending() {
            Some(pending) => {
                if self.function_deleted {
                    return (false, false);
                }
                (pending.refresh_name, pending.reload)
            }
            None => (false, false),
        }
    }

    /// Update the title after a function rename.
    pub fn update_title(&mut self) {
        self.title = Self::build_title(&self.function_name, &self.program_name);
    }

    /// Update the function name (after a symbol rename event).
    pub fn set_function_name(&mut self, name: impl Into<String>) {
        self.function_name = name.into();
        self.update_title();
    }

    /// Whether this provider is editing the given function path.
    ///
    /// Corresponds to `StackEditorProvider.isEditing(DataTypePath)`.
    pub fn is_editing(&self, function_address: u64) -> bool {
        self.function_address == function_address
    }

    // -----------------------------------------------------------------------
    // Disposal
    // -----------------------------------------------------------------------

    /// Dispose of the provider.
    ///
    /// Corresponds to `StackEditorProvider.dispose()`. Cleans up the delayed
    /// update manager, notifies listeners, and resets state.
    pub fn dispose(&mut self) {
        self.delayed_update_mgr.dispose();
        self.visible = false;
        self.pending_actions.clear();
        self.has_changes = false;
        self.notify_closed();
    }

    /// Check for save (simplified).
    ///
    /// Corresponds to `StackEditorProvider.checkForSave()`.
    /// Returns true if it is safe to close (either no changes, or user confirmed).
    pub fn check_for_save(&mut self, prompt_user: bool) -> bool {
        if !self.has_changes {
            return true;
        }
        if !prompt_user {
            return false; // Can't close without prompt when dirty
        }
        // In a real implementation, this would show a dialog.
        // For the model layer, we return false to indicate the caller should prompt.
        false
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = StackEditorProvider::new("main", "test_program", 0x400000, 0x400100);
        assert_eq!(provider.function_name, "main");
        assert_eq!(provider.program_name, "test_program");
        assert_eq!(provider.function_address, 0x400000);
        assert_eq!(provider.function_entry, 0x400100);
        assert!(!provider.is_visible());
        assert!(!provider.needs_save());
        assert!(!provider.is_function_deleted());
    }

    #[test]
    fn test_provider_title() {
        let provider = StackEditorProvider::new("myFunc", "prog", 0x1000, 0x1000);
        assert!(provider.title().contains("myFunc"));
        assert!(provider.title().contains("prog"));
        assert_eq!(
            provider.get_provider_sub_title(),
            "myFunc (prog)"
        );
    }

    #[test]
    fn test_provider_display_name() {
        let provider = StackEditorProvider::new("main", "test", 0x1000, 0x1000);
        assert_eq!(provider.display_name(), "stack frame: main");
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = StackEditorProvider::new("main", "test", 0x1000, 0x1000);
        assert!(!provider.is_visible());
        provider.show();
        assert!(provider.is_visible());
        provider.hide();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_changes() {
        let mut provider = StackEditorProvider::new("main", "test", 0x1000, 0x1000);
        assert!(!provider.needs_save());
        provider.set_changed(true);
        assert!(provider.needs_save());
        provider.set_changed(false);
        assert!(!provider.needs_save());
    }

    #[test]
    fn test_provider_actions() {
        let mut provider = StackEditorProvider::new("main", "test", 0x1000, 0x1000);
        provider.queue_action(StackEditorAction::AddLocal);
        provider.queue_action(StackEditorAction::AddParameter);
        assert!(provider.needs_save());
        assert_eq!(provider.pending_actions.len(), 2);

        let actions = provider.take_pending_actions();
        assert_eq!(actions.len(), 2);
        assert!(provider.pending_actions.is_empty());
    }

    #[test]
    fn test_provider_dispose() {
        let mut provider = StackEditorProvider::new("main", "test", 0x1000, 0x1000);
        provider.show();
        provider.set_changed(true);
        provider.queue_action(StackEditorAction::AddLocal);
        provider.dispose();
        assert!(!provider.is_visible());
        assert!(!provider.needs_save());
        assert!(provider.pending_actions.is_empty());
    }

    #[test]
    fn test_provider_help() {
        let provider = StackEditorProvider::new("main", "test", 0x1000, 0x1000);
        assert_eq!(provider.help_name(), "Stack_Editor");
        assert_eq!(provider.help_topic(), "StackEditor");
    }

    #[test]
    fn test_provider_is_editing() {
        let provider = StackEditorProvider::new("main", "test", 0x400000, 0x400100);
        assert!(provider.is_editing(0x400000));
        assert!(!provider.is_editing(0x500000));
    }

    // -----------------------------------------------------------------------
    // Domain object change tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_domain_object_change_function_removed() {
        let mut provider = StackEditorProvider::new("main", "test", 0x400000, 0x400100);
        provider.show();

        let records = vec![
            DomainObjectChangeRecord::new(DomainObjectEvent::Program(ProgramEvent::FunctionRemoved))
                .with_function_entry(0x400100),
        ];
        provider.domain_object_changed(&records);
        assert!(provider.is_function_deleted());
    }

    #[test]
    fn test_domain_object_change_function_removed_different_func() {
        let mut provider = StackEditorProvider::new("main", "test", 0x400000, 0x400100);
        provider.show();

        let records = vec![
            DomainObjectChangeRecord::new(DomainObjectEvent::Program(ProgramEvent::FunctionRemoved))
                .with_function_entry(0x500000),
        ];
        provider.domain_object_changed(&records);
        assert!(!provider.is_function_deleted());
    }

    #[test]
    fn test_domain_object_change_symbol_renamed_at_entry() {
        let mut provider = StackEditorProvider::new("main", "test", 0x400000, 0x400100);
        provider.show();

        let records = vec![
            DomainObjectChangeRecord::new(DomainObjectEvent::Program(ProgramEvent::SymbolRenamed))
                .with_address(0x400100),
        ];
        provider.domain_object_changed(&records);
        assert!(provider.has_pending_update());
    }

    #[test]
    fn test_domain_object_change_file_changed() {
        let mut provider = StackEditorProvider::new("main", "test", 0x400000, 0x400100);
        provider.show();

        let records = vec![
            DomainObjectChangeRecord::new(DomainObjectEvent::FileChanged),
        ];
        provider.domain_object_changed(&records);
        assert!(provider.has_pending_update());
    }

    #[test]
    fn test_domain_object_change_not_visible_ignored() {
        let mut provider = StackEditorProvider::new("main", "test", 0x400000, 0x400100);
        // Not visible
        let records = vec![
            DomainObjectChangeRecord::new(DomainObjectEvent::FileChanged),
        ];
        provider.domain_object_changed(&records);
        assert!(!provider.has_pending_update());
    }

    #[test]
    fn test_domain_object_change_function_changed() {
        let mut provider = StackEditorProvider::new("main", "test", 0x400000, 0x400100);
        provider.show();

        let records = vec![
            DomainObjectChangeRecord::new(
                DomainObjectEvent::Program(ProgramEvent::FunctionChanged),
            )
            .with_function_entry(0x400100),
        ];
        provider.domain_object_changed(&records);
        assert!(provider.has_pending_update());
    }

    #[test]
    fn test_domain_object_change_symbol_primary_state() {
        let mut provider = StackEditorProvider::new("main", "test", 0x400000, 0x400100);
        provider.show();

        let records = vec![
            DomainObjectChangeRecord::new(
                DomainObjectEvent::Program(ProgramEvent::SymbolPrimaryStateChanged),
            )
            .with_address(0x400100),
        ];
        provider.domain_object_changed(&records);
        assert!(provider.has_pending_update());
    }

    // -----------------------------------------------------------------------
    // Delayed update tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_delayed_update_manager() {
        let mut mgr = DelayedUpdateManager::new(200);
        assert!(!mgr.has_pending());
        mgr.schedule_refresh_name();
        assert!(mgr.has_pending());
        mgr.clear();
        assert!(!mgr.has_pending());
    }

    #[test]
    fn test_delayed_update_manager_combined() {
        let mut mgr = DelayedUpdateManager::new(0); // zero delay for testing
        mgr.schedule_refresh_name();
        mgr.schedule_reload();
        let pending = mgr.take_pending().unwrap();
        assert!(pending.refresh_name);
        assert!(pending.reload);
    }

    #[test]
    fn test_delayed_update_manager_not_ready() {
        let mut mgr = DelayedUpdateManager::new(60000); // 60 second delay
        mgr.schedule_refresh_name();
        assert!(mgr.has_pending());
        assert!(!mgr.should_process());
        assert!(mgr.take_pending().is_none());
    }

    // -----------------------------------------------------------------------
    // Listener tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_editor_listener_notification() {
        use std::sync::{Arc, Mutex};

        let mut provider = StackEditorProvider::new("main", "test", 0x400000, 0x400100);
        let called = Arc::new(Mutex::new(Vec::new()));
        let called_clone = called.clone();

        provider.add_editor_listener(move |addr| {
            called_clone.lock().unwrap().push(addr);
        });

        provider.dispose();

        let result = called.lock().unwrap();
        assert_eq!(*result, vec![0x400000]);
    }

    #[test]
    fn test_editor_listener_removal() {
        use std::sync::{Arc, Mutex};

        let mut provider = StackEditorProvider::new("main", "test", 0x400000, 0x400100);
        let called = Arc::new(Mutex::new(false));
        let called_clone = called.clone();

        let id = provider.add_editor_listener(move |_| {
            *called_clone.lock().unwrap() = true;
        });
        provider.remove_editor_listener(id);

        provider.dispose();

        assert!(!*called.lock().unwrap());
    }

    // -----------------------------------------------------------------------
    // Check for save tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_check_for_save_no_changes() {
        let mut provider = StackEditorProvider::new("main", "test", 0x1000, 0x1000);
        assert!(provider.check_for_save(true));
    }

    #[test]
    fn test_check_for_save_with_changes() {
        let mut provider = StackEditorProvider::new("main", "test", 0x1000, 0x1000);
        provider.set_changed(true);
        // Without prompt, cannot close dirty editor
        assert!(!provider.check_for_save(false));
    }

    #[test]
    fn test_set_function_name() {
        let mut provider = StackEditorProvider::new("main", "test", 0x1000, 0x1000);
        provider.set_function_name("newMain");
        assert_eq!(provider.function_name, "newMain");
        assert!(provider.title().contains("newMain"));
    }
}
