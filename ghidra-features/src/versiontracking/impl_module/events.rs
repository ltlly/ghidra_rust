//! Event types for Version Tracking change notifications.

use std::fmt;

/// Event types for version tracking domain object changes.
///
/// These correspond to Ghidra's `VTEvent` Java enum. Each variant
/// represents a type of change that can occur in a VT session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VTEvent {
    /// A match set was added to the session
    MatchSetAdded,
    /// An association's status changed (accepted/blocked/rejected/cleared)
    AssociationStatusChanged,
    /// An association's markup status changed
    AssociationMarkupStatusChanged,
    /// A match was added to a match set
    MatchAdded,
    /// A match was deleted from a match set
    MatchDeleted,
    /// A match's tag changed
    MatchTagChanged,
    /// An association was created
    AssociationAdded,
    /// An association was removed
    AssociationRemoved,
    /// A markup item's status changed
    MarkupItemStatusChanged,
    /// A markup item's destination address changed
    MarkupItemDestinationChanged,
    /// A tag type was created
    TagAdded,
    /// A tag type was removed
    TagRemoved,
    /// A match's vote count changed
    VoteCountChanged,
}

impl VTEvent {
    /// Returns a human-readable name for this event.
    pub fn name(&self) -> &'static str {
        match self {
            VTEvent::MatchSetAdded => "Match Set Added",
            VTEvent::AssociationStatusChanged => "Association Status Changed",
            VTEvent::AssociationMarkupStatusChanged => "Association Markup Status Changed",
            VTEvent::MatchAdded => "Match Added",
            VTEvent::MatchDeleted => "Match Deleted",
            VTEvent::MatchTagChanged => "Match Tag Changed",
            VTEvent::AssociationAdded => "Association Added",
            VTEvent::AssociationRemoved => "Association Removed",
            VTEvent::MarkupItemStatusChanged => "Markup Item Status Changed",
            VTEvent::MarkupItemDestinationChanged => "Markup Item Destination Changed",
            VTEvent::TagAdded => "Tag Added",
            VTEvent::TagRemoved => "Tag Removed",
            VTEvent::VoteCountChanged => "Vote Count Changed",
        }
    }

    /// Returns a numeric ID for this event (for serialization compatibility).
    pub fn id(&self) -> i32 {
        match self {
            VTEvent::MatchSetAdded => 1,
            VTEvent::AssociationStatusChanged => 2,
            VTEvent::AssociationMarkupStatusChanged => 3,
            VTEvent::MatchAdded => 4,
            VTEvent::MatchDeleted => 5,
            VTEvent::MatchTagChanged => 6,
            VTEvent::AssociationAdded => 7,
            VTEvent::AssociationRemoved => 8,
            VTEvent::MarkupItemStatusChanged => 9,
            VTEvent::MarkupItemDestinationChanged => 10,
            VTEvent::TagAdded => 11,
            VTEvent::TagRemoved => 12,
            VTEvent::VoteCountChanged => 13,
        }
    }

    /// Parse an event from its numeric ID.
    pub fn from_id(id: i32) -> Option<Self> {
        match id {
            1 => Some(VTEvent::MatchSetAdded),
            2 => Some(VTEvent::AssociationStatusChanged),
            3 => Some(VTEvent::AssociationMarkupStatusChanged),
            4 => Some(VTEvent::MatchAdded),
            5 => Some(VTEvent::MatchDeleted),
            6 => Some(VTEvent::MatchTagChanged),
            7 => Some(VTEvent::AssociationAdded),
            8 => Some(VTEvent::AssociationRemoved),
            9 => Some(VTEvent::MarkupItemStatusChanged),
            10 => Some(VTEvent::MarkupItemDestinationChanged),
            11 => Some(VTEvent::TagAdded),
            12 => Some(VTEvent::TagRemoved),
            13 => Some(VTEvent::VoteCountChanged),
            _ => None,
        }
    }

    /// All event variants.
    pub fn all() -> &'static [VTEvent] {
        &[
            VTEvent::MatchSetAdded,
            VTEvent::AssociationStatusChanged,
            VTEvent::AssociationMarkupStatusChanged,
            VTEvent::MatchAdded,
            VTEvent::MatchDeleted,
            VTEvent::MatchTagChanged,
            VTEvent::AssociationAdded,
            VTEvent::AssociationRemoved,
            VTEvent::MarkupItemStatusChanged,
            VTEvent::MarkupItemDestinationChanged,
            VTEvent::TagAdded,
            VTEvent::TagRemoved,
            VTEvent::VoteCountChanged,
        ]
    }
}

impl fmt::Display for VTEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Change manager interface for registering and dispatching VT events.
#[derive(Debug)]
pub struct VTChangeManager {
    /// Log of recorded changes
    change_log: Vec<VersionTrackingChangeRecord>,
}

impl VTChangeManager {
    /// Create a new change manager.
    pub fn new() -> Self {
        Self {
            change_log: Vec::new(),
        }
    }

    /// Record a change event.
    pub fn record_change(
        &mut self,
        event: VTEvent,
        affected: Option<String>,
        old_value: Option<String>,
        new_value: Option<String>,
    ) {
        self.change_log.push(VersionTrackingChangeRecord::new(
            event,
            affected,
            old_value,
            new_value,
        ));
    }

    /// Get the change log.
    pub fn change_log(&self) -> &[VersionTrackingChangeRecord] {
        &self.change_log
    }

    /// Clear the change log.
    pub fn clear(&mut self) {
        self.change_log.clear();
    }

    /// Number of recorded changes.
    pub fn change_count(&self) -> usize {
        self.change_log.len()
    }

    /// Get changes for a specific event type.
    pub fn changes_for_event(&self, event: VTEvent) -> Vec<&VersionTrackingChangeRecord> {
        self.change_log
            .iter()
            .filter(|c| c.event_type() == event)
            .collect()
    }
}

impl Default for VTChangeManager {
    fn default() -> Self {
        Self::new()
    }
}

use super::change_record::VersionTrackingChangeRecord;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_name() {
        assert_eq!(VTEvent::MatchSetAdded.name(), "Match Set Added");
        assert_eq!(VTEvent::VoteCountChanged.name(), "Vote Count Changed");
    }

    #[test]
    fn test_event_id_roundtrip() {
        for event in VTEvent::all() {
            assert_eq!(VTEvent::from_id(event.id()), Some(*event));
        }
    }

    #[test]
    fn test_event_display() {
        assert_eq!(format!("{}", VTEvent::MatchAdded), "Match Added");
    }

    #[test]
    fn test_change_manager_record() {
        let mut mgr = VTChangeManager::new();
        mgr.record_change(
            VTEvent::MatchAdded,
            Some("match_set_1".to_string()),
            None,
            Some("new_match".to_string()),
        );
        assert_eq!(mgr.change_count(), 1);
        let changes = mgr.changes_for_event(VTEvent::MatchAdded);
        assert_eq!(changes.len(), 1);
    }

    #[test]
    fn test_change_manager_clear() {
        let mut mgr = VTChangeManager::new();
        mgr.record_change(VTEvent::MatchAdded, None, None, None);
        mgr.record_change(VTEvent::MatchDeleted, None, None, None);
        assert_eq!(mgr.change_count(), 2);
        mgr.clear();
        assert_eq!(mgr.change_count(), 0);
    }
}
