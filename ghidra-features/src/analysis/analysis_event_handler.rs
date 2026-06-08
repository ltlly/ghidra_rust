//! Analysis event handler for program change events.
//!
//! Ported from the `DomainObjectListener` in `AutoAnalysisManager.java`.
//!
//! When a program changes during analysis (e.g., new code is defined,
//! functions are created, or references are added), the auto-analysis
//! manager needs to be notified so it can schedule follow-on analysis
//! passes. This module provides the event handling infrastructure.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// ProgramChangeEvent -- types of program changes that trigger analysis
// ---------------------------------------------------------------------------

/// Types of program change events that can trigger analysis.
///
/// Ported from the event types handled in `AutoAnalysisManager`'s
/// `DomainObjectListener`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProgramChangeEvent {
    /// Memory block was added.
    BlockAdded,
    /// Code (instruction) was defined at an address.
    CodeDefined,
    /// Data was defined at an address range.
    DataDefined,
    /// A function was created or its body changed.
    FunctionAdded,
    /// A function was removed.
    FunctionRemoved,
    /// A function's body changed.
    FunctionBodyChanged,
    /// A function's signature changed.
    FunctionSignatureChanged,
    /// A function's modifier changed (e.g., calling convention).
    FunctionModifierChanged,
    /// An external symbol was added.
    ExternalAdded,
    /// A fallthrough override changed.
    FallthroughChanged,
    /// A flow override changed.
    FlowOverrideChanged,
    /// A length override changed.
    LengthOverrideChanged,
    /// The program's language changed.
    LanguageChanged,
    /// The program was restored from storage.
    Restored,
    /// A property changed on the program.
    PropertyChanged,
    /// A symbol was added.
    SymbolAdded,
    /// A symbol was renamed.
    SymbolRenamed,
}

impl fmt::Display for ProgramChangeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BlockAdded => write!(f, "BlockAdded"),
            Self::CodeDefined => write!(f, "CodeDefined"),
            Self::DataDefined => write!(f, "DataDefined"),
            Self::FunctionAdded => write!(f, "FunctionAdded"),
            Self::FunctionRemoved => write!(f, "FunctionRemoved"),
            Self::FunctionBodyChanged => write!(f, "FunctionBodyChanged"),
            Self::FunctionSignatureChanged => write!(f, "FunctionSignatureChanged"),
            Self::FunctionModifierChanged => write!(f, "FunctionModifierChanged"),
            Self::ExternalAdded => write!(f, "ExternalAdded"),
            Self::FallthroughChanged => write!(f, "FallthroughChanged"),
            Self::FlowOverrideChanged => write!(f, "FlowOverrideChanged"),
            Self::LengthOverrideChanged => write!(f, "LengthOverrideChanged"),
            Self::LanguageChanged => write!(f, "LanguageChanged"),
            Self::Restored => write!(f, "Restored"),
            Self::PropertyChanged => write!(f, "PropertyChanged"),
            Self::SymbolAdded => write!(f, "SymbolAdded"),
            Self::SymbolRenamed => write!(f, "SymbolRenamed"),
        }
    }
}

// ---------------------------------------------------------------------------
// ChangeRecord -- a record of a single program change
// ---------------------------------------------------------------------------

/// A record of a single program change.
#[derive(Debug, Clone)]
pub struct ChangeRecord {
    /// The type of change.
    pub event: ProgramChangeEvent,
    /// Start address affected.
    pub start_address: u64,
    /// End address affected (exclusive).
    pub end_address: u64,
    /// Optional object identifier (e.g., function entry point).
    pub object_id: Option<u64>,
    /// Whether this is a function signature change.
    pub is_signature_change: bool,
    /// Whether this is a function modifier change.
    pub is_modifier_change: bool,
}

impl ChangeRecord {
    /// Create a new change record for an address range.
    pub fn new(event: ProgramChangeEvent, start: u64, end: u64) -> Self {
        Self {
            event,
            start_address: start,
            end_address: end,
            object_id: None,
            is_signature_change: false,
            is_modifier_change: false,
        }
    }

    /// Create a new change record for a single address.
    pub fn at(event: ProgramChangeEvent, addr: u64) -> Self {
        Self::new(event, addr, addr + 1)
    }

    /// Set the object ID.
    pub fn with_object_id(mut self, id: u64) -> Self {
        self.object_id = Some(id);
        self
    }

    /// Mark as a function signature change.
    pub fn with_signature_change(mut self) -> Self {
        self.is_signature_change = true;
        self
    }

    /// Mark as a function modifier change.
    pub fn with_modifier_change(mut self) -> Self {
        self.is_modifier_change = true;
        self
    }
}

// ---------------------------------------------------------------------------
// AnalysisEventHandler -- processes program change events
// ---------------------------------------------------------------------------

/// Handles program change events and routes them to the appropriate
/// analysis task lists.
///
/// Ported from the event handling logic in `AutoAnalysisManager`. The
/// handler receives change records and dispatches them to the correct
/// analysis category (byte, instruction, function, data, etc.).
#[derive(Debug)]
pub struct AnalysisEventHandler {
    /// Whether change events should be ignored.
    ignore_changes: bool,
    /// Event counters for monitoring.
    event_counts: HashMap<ProgramChangeEvent, u64>,
    /// Whether the handler is enabled.
    enabled: bool,
    /// Queued events for batch processing.
    event_queue: Vec<ChangeRecord>,
}

impl AnalysisEventHandler {
    /// Create a new event handler.
    pub fn new() -> Self {
        Self {
            ignore_changes: false,
            event_counts: HashMap::new(),
            enabled: true,
            event_queue: Vec::new(),
        }
    }

    /// Set whether change events should be ignored.
    pub fn set_ignore_changes(&mut self, ignore: bool) -> bool {
        let prev = self.ignore_changes;
        self.ignore_changes = ignore;
        prev
    }

    /// Whether change events are currently being ignored.
    pub fn is_ignoring_changes(&self) -> bool {
        self.ignore_changes
    }

    /// Enable or disable the handler.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether the handler is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Process a change record.
    ///
    /// Returns the analysis category that should be notified, if any.
    pub fn handle_change(&mut self, record: &ChangeRecord) -> Option<AnalysisCategory> {
        if self.ignore_changes || !self.enabled {
            return None;
        }

        // Count the event
        *self.event_counts.entry(record.event).or_insert(0) += 1;

        // Route to the appropriate category
        let category = match record.event {
            ProgramChangeEvent::BlockAdded | ProgramChangeEvent::ExternalAdded => {
                AnalysisCategory::Byte
            }
            ProgramChangeEvent::CodeDefined => AnalysisCategory::Instruction,
            ProgramChangeEvent::DataDefined => AnalysisCategory::Data,
            ProgramChangeEvent::FunctionAdded | ProgramChangeEvent::FunctionBodyChanged => {
                AnalysisCategory::Function
            }
            ProgramChangeEvent::FunctionRemoved => AnalysisCategory::Function,
            ProgramChangeEvent::FunctionSignatureChanged => {
                AnalysisCategory::FunctionSignature
            }
            ProgramChangeEvent::FunctionModifierChanged => {
                AnalysisCategory::FunctionModifier
            }
            ProgramChangeEvent::FallthroughChanged
            | ProgramChangeEvent::FlowOverrideChanged
            | ProgramChangeEvent::LengthOverrideChanged => AnalysisCategory::Instruction,
            ProgramChangeEvent::LanguageChanged => {
                // Re-initialize all analyzers
                return Some(AnalysisCategory::All);
            }
            ProgramChangeEvent::Restored | ProgramChangeEvent::PropertyChanged => {
                // Reset options
                return Some(AnalysisCategory::Options);
            }
            ProgramChangeEvent::SymbolAdded | ProgramChangeEvent::SymbolRenamed => {
                // Currently not handled by a dedicated analyzer type
                return None;
            }
        };

        Some(category)
    }

    /// Queue a change record for batch processing.
    pub fn queue_change(&mut self, record: ChangeRecord) {
        if !self.ignore_changes && self.enabled {
            self.event_queue.push(record);
        }
    }

    /// Drain all queued events.
    pub fn drain_queue(&mut self) -> Vec<ChangeRecord> {
        std::mem::take(&mut self.event_queue)
    }

    /// Get the number of queued events.
    pub fn queue_len(&self) -> usize {
        self.event_queue.len()
    }

    /// Flush the event queue, discarding all events.
    pub fn flush_queue(&mut self) {
        self.event_queue.clear();
    }

    /// Get event counts by type.
    pub fn event_counts(&self) -> &HashMap<ProgramChangeEvent, u64> {
        &self.event_counts
    }

    /// Get the total number of events processed.
    pub fn total_events(&self) -> u64 {
        self.event_counts.values().sum()
    }

    /// Reset all event counters.
    pub fn reset_counts(&mut self) {
        self.event_counts.clear();
    }

    /// Reset the handler state (clear queues and counters).
    pub fn reset(&mut self) {
        self.event_queue.clear();
        self.event_counts.clear();
        self.ignore_changes = false;
    }
}

impl Default for AnalysisEventHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// AnalysisCategory -- categories of analysis that can be triggered
// ---------------------------------------------------------------------------

/// Categories of analysis that can be triggered by program changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnalysisCategory {
    /// Byte-level analysis (memory blocks, external symbols).
    Byte,
    /// Instruction-level analysis.
    Instruction,
    /// Data definition analysis.
    Data,
    /// Function creation/analysis.
    Function,
    /// Function modifier analysis.
    FunctionModifier,
    /// Function signature analysis.
    FunctionSignature,
    /// All analyses (re-initialization).
    All,
    /// Options reset.
    Options,
}

impl fmt::Display for AnalysisCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Byte => write!(f, "Byte"),
            Self::Instruction => write!(f, "Instruction"),
            Self::Data => write!(f, "Data"),
            Self::Function => write!(f, "Function"),
            Self::FunctionModifier => write!(f, "FunctionModifier"),
            Self::FunctionSignature => write!(f, "FunctionSignature"),
            Self::All => write!(f, "All"),
            Self::Options => write!(f, "Options"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_handler_basic() {
        let mut handler = AnalysisEventHandler::new();
        assert!(handler.is_enabled());
        assert!(!handler.is_ignoring_changes());

        let record = ChangeRecord::at(ProgramChangeEvent::CodeDefined, 0x1000);
        let category = handler.handle_change(&record);
        assert_eq!(category, Some(AnalysisCategory::Instruction));
    }

    #[test]
    fn test_event_handler_ignore_changes() {
        let mut handler = AnalysisEventHandler::new();
        handler.set_ignore_changes(true);

        let record = ChangeRecord::at(ProgramChangeEvent::CodeDefined, 0x1000);
        let category = handler.handle_change(&record);
        assert!(category.is_none());
    }

    #[test]
    fn test_event_handler_disabled() {
        let mut handler = AnalysisEventHandler::new();
        handler.set_enabled(false);

        let record = ChangeRecord::at(ProgramChangeEvent::CodeDefined, 0x1000);
        let category = handler.handle_change(&record);
        assert!(category.is_none());
    }

    #[test]
    fn test_event_handler_routing() {
        let mut handler = AnalysisEventHandler::new();

        let cases = vec![
            (ProgramChangeEvent::BlockAdded, AnalysisCategory::Byte),
            (ProgramChangeEvent::ExternalAdded, AnalysisCategory::Byte),
            (ProgramChangeEvent::CodeDefined, AnalysisCategory::Instruction),
            (ProgramChangeEvent::DataDefined, AnalysisCategory::Data),
            (ProgramChangeEvent::FunctionAdded, AnalysisCategory::Function),
            (
                ProgramChangeEvent::FunctionSignatureChanged,
                AnalysisCategory::FunctionSignature,
            ),
            (
                ProgramChangeEvent::FunctionModifierChanged,
                AnalysisCategory::FunctionModifier,
            ),
            (ProgramChangeEvent::LanguageChanged, AnalysisCategory::All),
        ];

        for (event, expected_category) in cases {
            let record = ChangeRecord::at(event, 0x1000);
            let category = handler.handle_change(&record);
            assert_eq!(
                category,
                Some(expected_category),
                "Event {:?} should route to {:?}",
                event,
                expected_category
            );
        }
    }

    #[test]
    fn test_event_handler_counts() {
        let mut handler = AnalysisEventHandler::new();

        handler.handle_change(&ChangeRecord::at(ProgramChangeEvent::CodeDefined, 0x1000));
        handler.handle_change(&ChangeRecord::at(ProgramChangeEvent::CodeDefined, 0x2000));
        handler.handle_change(&ChangeRecord::at(ProgramChangeEvent::FunctionAdded, 0x3000));

        assert_eq!(handler.total_events(), 3);
        assert_eq!(
            handler.event_counts().get(&ProgramChangeEvent::CodeDefined),
            Some(&2)
        );
        assert_eq!(
            handler.event_counts().get(&ProgramChangeEvent::FunctionAdded),
            Some(&1)
        );
    }

    #[test]
    fn test_event_handler_queue() {
        let mut handler = AnalysisEventHandler::new();

        handler.queue_change(ChangeRecord::at(ProgramChangeEvent::CodeDefined, 0x1000));
        handler.queue_change(ChangeRecord::at(ProgramChangeEvent::FunctionAdded, 0x2000));
        assert_eq!(handler.queue_len(), 2);

        let events = handler.drain_queue();
        assert_eq!(events.len(), 2);
        assert_eq!(handler.queue_len(), 0);
    }

    #[test]
    fn test_event_handler_queue_ignored() {
        let mut handler = AnalysisEventHandler::new();
        handler.set_ignore_changes(true);

        handler.queue_change(ChangeRecord::at(ProgramChangeEvent::CodeDefined, 0x1000));
        assert_eq!(handler.queue_len(), 0);
    }

    #[test]
    fn test_event_handler_reset() {
        let mut handler = AnalysisEventHandler::new();
        handler.handle_change(&ChangeRecord::at(ProgramChangeEvent::CodeDefined, 0x1000));
        handler.queue_change(ChangeRecord::at(ProgramChangeEvent::FunctionAdded, 0x2000));
        handler.set_ignore_changes(true);

        handler.reset();
        assert_eq!(handler.total_events(), 0);
        assert_eq!(handler.queue_len(), 0);
        assert!(!handler.is_ignoring_changes());
    }

    #[test]
    fn test_change_record_builder() {
        let record = ChangeRecord::new(ProgramChangeEvent::FunctionAdded, 0x1000, 0x2000)
            .with_object_id(0x1500)
            .with_signature_change();

        assert_eq!(record.event, ProgramChangeEvent::FunctionAdded);
        assert_eq!(record.start_address, 0x1000);
        assert_eq!(record.end_address, 0x2000);
        assert_eq!(record.object_id, Some(0x1500));
        assert!(record.is_signature_change);
    }

    #[test]
    fn test_change_record_at() {
        let record = ChangeRecord::at(ProgramChangeEvent::CodeDefined, 0x1000);
        assert_eq!(record.start_address, 0x1000);
        assert_eq!(record.end_address, 0x1001);
    }

    #[test]
    fn test_program_change_event_display() {
        assert_eq!(ProgramChangeEvent::BlockAdded.to_string(), "BlockAdded");
        assert_eq!(
            ProgramChangeEvent::FunctionSignatureChanged.to_string(),
            "FunctionSignatureChanged"
        );
    }

    #[test]
    fn test_analysis_category_display() {
        assert_eq!(AnalysisCategory::Byte.to_string(), "Byte");
        assert_eq!(AnalysisCategory::Function.to_string(), "Function");
    }

    #[test]
    fn test_event_handler_set_ignore_returns_prev() {
        let mut handler = AnalysisEventHandler::new();
        let prev = handler.set_ignore_changes(true);
        assert!(!prev);

        let prev = handler.set_ignore_changes(false);
        assert!(prev);
    }
}
