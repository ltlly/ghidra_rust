//! Domain object listener for analysis.
//!
//! Ported from `AutoAnalysisManager.createDomainObjectListener()`.
//!
//! Provides the listener infrastructure that connects program domain
//! object changes to the auto-analysis manager's event handling. When
//! the program changes (code added, functions created, etc.), the
//! listener translates these into analysis scheduling events.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use super::analysis_event_handler::{AnalysisCategory, AnalysisEventHandler, ChangeRecord, ProgramChangeEvent};

// ---------------------------------------------------------------------------
// DomainObjectEvent -- events from the domain object (program)
// ---------------------------------------------------------------------------

/// Events that can be emitted by a domain object (program).
///
/// Ported from `DomainObjectEvent` enum values used in
/// `AutoAnalysisManager`'s listener builder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DomainObjectEvent {
    /// A memory block was added.
    BlockAdded,
    /// Code was added (instruction defined).
    CodeAdded,
    /// Data was added.
    DataAdded,
    /// A function was added.
    FunctionAdded,
    /// A function's body changed.
    FunctionBodyChanged,
    /// A function was removed.
    FunctionRemoved,
    /// A function changed (signature or modifier).
    FunctionChanged,
    /// The fallthrough was changed.
    FallthroughChanged,
    /// The flow override was changed.
    FlowOverrideChanged,
    /// The length override was changed.
    LengthOverrideChanged,
    /// The language was changed.
    LanguageChanged,
    /// The program was restored.
    Restored,
    /// A property was changed.
    PropertyChanged,
    /// A symbol was added.
    SymbolAdded,
    /// A symbol was renamed.
    SymbolRenamed,
    /// The program was closed.
    Closed,
    /// The program was saved.
    Saved,
}

impl fmt::Display for DomainObjectEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

// ---------------------------------------------------------------------------
// FunctionChangeInfo -- information about a function change
// ---------------------------------------------------------------------------

/// Information about a function change event.
#[derive(Debug, Clone)]
pub struct FunctionChangeInfo {
    /// Entry point of the changed function.
    pub entry_point: u64,
    /// Whether this is a signature change.
    pub is_signature_change: bool,
    /// Whether this is a modifier change.
    pub is_modifier_change: bool,
    /// Whether the function is external.
    pub is_external: bool,
}

impl FunctionChangeInfo {
    /// Create a new function change info.
    pub fn new(entry_point: u64) -> Self {
        Self {
            entry_point,
            is_signature_change: false,
            is_modifier_change: false,
            is_external: false,
        }
    }

    /// Mark as a signature change.
    pub fn with_signature_change(mut self) -> Self {
        self.is_signature_change = true;
        self
    }

    /// Mark as a modifier change.
    pub fn with_modifier_change(mut self) -> Self {
        self.is_modifier_change = true;
        self
    }

    /// Mark as external.
    pub fn with_external(mut self) -> Self {
        self.is_external = true;
        self
    }
}

// ---------------------------------------------------------------------------
// DomainObjectListener -- listens to program changes
// ---------------------------------------------------------------------------

/// Listens to domain object (program) changes and translates them into
/// analysis events.
///
/// Ported from `AutoAnalysisManager.createDomainObjectListener()`.
/// The listener builder pattern from the Java code is replaced with
/// explicit event registration in Rust.
///
/// # Usage
///
/// ```ignore
/// let mut listener = DomainObjectListener::new();
/// listener.on_function_added(|info| {
///     // Handle function added
/// });
/// listener.on_code_added(|start, end| {
///     // Handle code added
/// });
/// ```
pub struct DomainObjectListener {
    /// The event handler to route events to.
    handler: AnalysisEventHandler,
    /// Whether the listener is active.
    active: bool,
    /// Configuration for which events to listen to.
    config: ListenerConfig,
    /// Statistics about events processed.
    stats: ListenerStats,
}

/// Configuration for which events a listener handles.
#[derive(Debug, Clone)]
pub struct ListenerConfig {
    /// Handle block added events.
    pub handle_block_added: bool,
    /// Handle code added events.
    pub handle_code_added: bool,
    /// Handle function events.
    pub handle_function_events: bool,
    /// Handle data events.
    pub handle_data_events: bool,
    /// Handle override events.
    pub handle_override_events: bool,
    /// Handle language changed events.
    pub handle_language_changed: bool,
    /// Handle restore events.
    pub handle_restored: bool,
    /// Handle property changed events.
    pub handle_property_changed: bool,
}

impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            handle_block_added: true,
            handle_code_added: true,
            handle_function_events: true,
            handle_data_events: true,
            handle_override_events: true,
            handle_language_changed: true,
            handle_restored: true,
            handle_property_changed: true,
        }
    }
}

/// Statistics about events processed by a listener.
#[derive(Debug, Clone, Default)]
pub struct ListenerStats {
    /// Total events received.
    pub events_received: u64,
    /// Events processed (not ignored).
    pub events_processed: u64,
    /// Events ignored.
    pub events_ignored: u64,
    /// Re-initializations triggered.
    pub reinits: u64,
    /// Options resets triggered.
    pub option_resets: u64,
}

impl DomainObjectListener {
    /// Create a new domain object listener.
    pub fn new(handler: AnalysisEventHandler) -> Self {
        Self {
            handler,
            active: true,
            config: ListenerConfig::default(),
            stats: ListenerStats::default(),
        }
    }

    /// Create a listener with custom configuration.
    pub fn with_config(handler: AnalysisEventHandler, config: ListenerConfig) -> Self {
        Self {
            handler,
            active: true,
            config,
            stats: ListenerStats::default(),
        }
    }

    /// Activate or deactivate the listener.
    pub fn set_active(&mut self, active: bool) {
        self.active = active;
    }

    /// Whether the listener is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get a reference to the event handler.
    pub fn handler(&self) -> &AnalysisEventHandler {
        &self.handler
    }

    /// Get a mutable reference to the event handler.
    pub fn handler_mut(&mut self) -> &mut AnalysisEventHandler {
        &mut self.handler
    }

    /// Get listener statistics.
    pub fn stats(&self) -> &ListenerStats {
        &self.stats
    }

    /// Process a domain object event.
    ///
    /// Returns the analysis category to notify, if any.
    pub fn process_event(
        &mut self,
        event: DomainObjectEvent,
        start_addr: u64,
        end_addr: u64,
        object_id: Option<u64>,
    ) -> Option<AnalysisCategory> {
        if !self.active {
            return None;
        }

        self.stats.events_received += 1;

        // Check if we should handle this event type
        if !self.should_handle(event) {
            self.stats.events_ignored += 1;
            return None;
        }

        // Map domain object event to program change event
        let change_event = match event {
            DomainObjectEvent::BlockAdded => ProgramChangeEvent::BlockAdded,
            DomainObjectEvent::CodeAdded => ProgramChangeEvent::CodeDefined,
            DomainObjectEvent::DataAdded => ProgramChangeEvent::DataDefined,
            DomainObjectEvent::FunctionAdded => ProgramChangeEvent::FunctionAdded,
            DomainObjectEvent::FunctionBodyChanged => ProgramChangeEvent::FunctionBodyChanged,
            DomainObjectEvent::FunctionRemoved => ProgramChangeEvent::FunctionRemoved,
            DomainObjectEvent::FunctionChanged => {
                // This is a generic function change; the specific type
                // (signature vs modifier) should be determined by the caller
                // and passed via FunctionChangeInfo
                ProgramChangeEvent::FunctionSignatureChanged
            }
            DomainObjectEvent::FallthroughChanged => ProgramChangeEvent::FallthroughChanged,
            DomainObjectEvent::FlowOverrideChanged => ProgramChangeEvent::FlowOverrideChanged,
            DomainObjectEvent::LengthOverrideChanged => ProgramChangeEvent::LengthOverrideChanged,
            DomainObjectEvent::LanguageChanged => {
                self.stats.reinits += 1;
                ProgramChangeEvent::LanguageChanged
            }
            DomainObjectEvent::Restored => {
                self.stats.option_resets += 1;
                ProgramChangeEvent::Restored
            }
            DomainObjectEvent::PropertyChanged => ProgramChangeEvent::PropertyChanged,
            DomainObjectEvent::SymbolAdded => ProgramChangeEvent::SymbolAdded,
            DomainObjectEvent::SymbolRenamed => ProgramChangeEvent::SymbolRenamed,
            DomainObjectEvent::Closed | DomainObjectEvent::Saved => {
                return None;
            }
        };

        let record = ChangeRecord::new(change_event, start_addr, end_addr);
        let result = self.handler.handle_change(&record);

        if result.is_some() {
            self.stats.events_processed += 1;
        } else {
            self.stats.events_ignored += 1;
        }

        result
    }

    /// Process a function change event with detailed info.
    pub fn process_function_change(&mut self, info: &FunctionChangeInfo) -> Option<AnalysisCategory> {
        if !self.active || !self.config.handle_function_events {
            return None;
        }

        self.stats.events_received += 1;

        if info.is_external {
            // External functions don't trigger function analysis
            return None;
        }

        let event = if info.is_signature_change {
            ProgramChangeEvent::FunctionSignatureChanged
        } else if info.is_modifier_change {
            ProgramChangeEvent::FunctionModifierChanged
        } else {
            ProgramChangeEvent::FunctionAdded
        };

        let record = ChangeRecord::new(event, info.entry_point, info.entry_point + 1);
        let result = self.handler.handle_change(&record);

        if result.is_some() {
            self.stats.events_processed += 1;
        }

        result
    }

    /// Check if the listener should handle a given event type.
    fn should_handle(&self, event: DomainObjectEvent) -> bool {
        match event {
            DomainObjectEvent::BlockAdded => self.config.handle_block_added,
            DomainObjectEvent::CodeAdded => self.config.handle_code_added,
            DomainObjectEvent::DataAdded => self.config.handle_data_events,
            DomainObjectEvent::FunctionAdded
            | DomainObjectEvent::FunctionBodyChanged
            | DomainObjectEvent::FunctionRemoved
            | DomainObjectEvent::FunctionChanged => self.config.handle_function_events,
            DomainObjectEvent::FallthroughChanged
            | DomainObjectEvent::FlowOverrideChanged
            | DomainObjectEvent::LengthOverrideChanged => self.config.handle_override_events,
            DomainObjectEvent::LanguageChanged => self.config.handle_language_changed,
            DomainObjectEvent::Restored => self.config.handle_restored,
            DomainObjectEvent::PropertyChanged => self.config.handle_property_changed,
            DomainObjectEvent::SymbolAdded | DomainObjectEvent::SymbolRenamed => false,
            DomainObjectEvent::Closed | DomainObjectEvent::Saved => false,
        }
    }

    /// Reset the listener state.
    pub fn reset(&mut self) {
        self.handler.reset();
        self.stats = ListenerStats::default();
    }
}

impl fmt::Debug for DomainObjectListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DomainObjectListener")
            .field("active", &self.active)
            .field("stats", &self.stats)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// ListenerGuard -- RAII guard for ignoring changes
// ---------------------------------------------------------------------------

/// RAII guard that sets `ignore_changes` on the handler and restores
/// the previous state when dropped.
pub struct ListenerGuard<'a> {
    handler: &'a mut AnalysisEventHandler,
    previous_state: bool,
}

impl<'a> ListenerGuard<'a> {
    /// Create a new guard that sets `ignore_changes` to `true`.
    pub fn new(handler: &'a mut AnalysisEventHandler) -> Self {
        let previous_state = handler.set_ignore_changes(true);
        Self {
            handler,
            previous_state,
        }
    }

    /// Get the previous ignore state.
    pub fn previous_state(&self) -> bool {
        self.previous_state
    }
}

impl<'a> Drop for ListenerGuard<'a> {
    fn drop(&mut self) {
        self.handler.set_ignore_changes(self.previous_state);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_listener() -> DomainObjectListener {
        let handler = AnalysisEventHandler::new();
        DomainObjectListener::new(handler)
    }

    #[test]
    fn test_listener_basic() {
        let mut listener = make_listener();
        assert!(listener.is_active());

        let category = listener.process_event(
            DomainObjectEvent::CodeAdded,
            0x1000,
            0x2000,
            None,
        );
        assert_eq!(category, Some(AnalysisCategory::Instruction));
    }

    #[test]
    fn test_listener_inactive() {
        let mut listener = make_listener();
        listener.set_active(false);

        let category = listener.process_event(
            DomainObjectEvent::CodeAdded,
            0x1000,
            0x2000,
            None,
        );
        assert!(category.is_none());
    }

    #[test]
    fn test_listener_function_added() {
        let mut listener = make_listener();
        let category = listener.process_event(
            DomainObjectEvent::FunctionAdded,
            0x1000,
            0x1001,
            Some(0x1000),
        );
        assert_eq!(category, Some(AnalysisCategory::Function));
    }

    #[test]
    fn test_listener_function_change_info() {
        let mut listener = make_listener();

        let info = FunctionChangeInfo::new(0x1000).with_signature_change();
        let category = listener.process_function_change(&info);
        assert_eq!(category, Some(AnalysisCategory::FunctionSignature));

        let info = FunctionChangeInfo::new(0x2000).with_modifier_change();
        let category = listener.process_function_change(&info);
        assert_eq!(category, Some(AnalysisCategory::FunctionModifier));
    }

    #[test]
    fn test_listener_external_function() {
        let mut listener = make_listener();

        let info = FunctionChangeInfo::new(0x1000).with_external();
        let category = listener.process_function_change(&info);
        assert!(category.is_none());
    }

    #[test]
    fn test_listener_language_changed() {
        let mut listener = make_listener();
        let category = listener.process_event(
            DomainObjectEvent::LanguageChanged,
            0,
            0,
            None,
        );
        assert_eq!(category, Some(AnalysisCategory::All));
        assert_eq!(listener.stats().reinits, 1);
    }

    #[test]
    fn test_listener_restored() {
        let mut listener = make_listener();
        let category = listener.process_event(
            DomainObjectEvent::Restored,
            0,
            0,
            None,
        );
        assert_eq!(category, Some(AnalysisCategory::Options));
        assert_eq!(listener.stats().option_resets, 1);
    }

    #[test]
    fn test_listener_ignored_events() {
        let mut listener = make_listener();
        // Symbol events are not handled
        let category = listener.process_event(
            DomainObjectEvent::SymbolAdded,
            0x1000,
            0x1001,
            None,
        );
        assert!(category.is_none());
        assert_eq!(listener.stats().events_ignored, 1);
    }

    #[test]
    fn test_listener_custom_config() {
        let handler = AnalysisEventHandler::new();
        let config = ListenerConfig {
            handle_function_events: false,
            ..Default::default()
        };
        let mut listener = DomainObjectListener::with_config(handler, config);

        let category = listener.process_event(
            DomainObjectEvent::FunctionAdded,
            0x1000,
            0x1001,
            None,
        );
        assert!(category.is_none());
    }

    #[test]
    fn test_listener_stats() {
        let mut listener = make_listener();
        listener.process_event(DomainObjectEvent::CodeAdded, 0x1000, 0x2000, None);
        listener.process_event(DomainObjectEvent::FunctionAdded, 0x3000, 0x3001, None);
        listener.process_event(DomainObjectEvent::SymbolAdded, 0x4000, 0x4001, None);

        let stats = listener.stats();
        assert_eq!(stats.events_received, 3);
        assert_eq!(stats.events_processed, 2);
        assert_eq!(stats.events_ignored, 1);
    }

    #[test]
    fn test_listener_guard() {
        let mut handler = AnalysisEventHandler::new();
        assert!(!handler.is_ignoring_changes());

        {
            let guard = ListenerGuard::new(&mut handler);
            // Verify via the guard's API instead of borrowing handler
            assert_eq!(guard.previous_state(), false);
        }

        assert!(!handler.is_ignoring_changes());
    }

    #[test]
    fn test_listener_guard_nested() {
        let mut handler = AnalysisEventHandler::new();

        handler.set_ignore_changes(true);
        {
            let guard = ListenerGuard::new(&mut handler);
            // Verify via the guard's API
            assert_eq!(guard.previous_state(), true);
        }
        // Should restore to previous state (true)
        assert!(handler.is_ignoring_changes());
    }

    #[test]
    fn test_listener_reset() {
        let mut listener = make_listener();
        listener.process_event(DomainObjectEvent::CodeAdded, 0x1000, 0x2000, None);

        listener.reset();
        assert_eq!(listener.stats().events_received, 0);
    }

    #[test]
    fn test_domain_object_event_display() {
        assert_eq!(DomainObjectEvent::BlockAdded.to_string(), "BlockAdded");
        assert_eq!(DomainObjectEvent::FunctionAdded.to_string(), "FunctionAdded");
    }

    #[test]
    fn test_function_change_info_builder() {
        let info = FunctionChangeInfo::new(0x1000)
            .with_signature_change()
            .with_modifier_change()
            .with_external();

        assert_eq!(info.entry_point, 0x1000);
        assert!(info.is_signature_change);
        assert!(info.is_modifier_change);
        assert!(info.is_external);
    }
}
