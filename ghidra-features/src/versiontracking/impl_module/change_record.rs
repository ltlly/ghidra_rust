//! Version tracking change records.

use std::fmt;
use super::events::VTEvent;

/// Event data for a domain object change in Version Tracking.
///
/// Corresponds to Ghidra's `VersionTrackingChangeRecord` Java class.
/// Records the event type, the affected object, and old/new values.
#[derive(Debug, Clone)]
pub struct VersionTrackingChangeRecord {
    /// The type of event
    event_type: VTEvent,
    /// The affected object (serialized as string, may be null)
    affected: Option<String>,
    /// The original value (may be null)
    old_value: Option<String>,
    /// The new value (may be null)
    new_value: Option<String>,
}

impl VersionTrackingChangeRecord {
    /// Create a new change record.
    pub fn new(
        event_type: VTEvent,
        affected: Option<String>,
        old_value: Option<String>,
        new_value: Option<String>,
    ) -> Self {
        Self {
            event_type,
            affected,
            old_value,
            new_value,
        }
    }

    /// Returns the event type.
    pub fn event_type(&self) -> VTEvent {
        self.event_type
    }

    /// Returns the affected object reference.
    pub fn affected(&self) -> Option<&str> {
        self.affected.as_deref()
    }

    /// Returns the old value.
    pub fn old_value(&self) -> Option<&str> {
        self.old_value.as_deref()
    }

    /// Returns the new value.
    pub fn new_value(&self) -> Option<&str> {
        self.new_value.as_deref()
    }
}

impl fmt::Display for VersionTrackingChangeRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VTChangeRecord({}", self.event_type)?;
        if let Some(ref obj) = self.affected {
            write!(f, ", affected={}", obj)?;
        }
        if let Some(ref old) = self.old_value {
            write!(f, ", old={}", old)?;
        }
        if let Some(ref new) = self.new_value {
            write!(f, ", new={}", new)?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_record_create() {
        let cr = VersionTrackingChangeRecord::new(
            VTEvent::MatchAdded,
            Some("match_set_1".to_string()),
            None,
            Some("new_match".to_string()),
        );
        assert_eq!(cr.event_type(), VTEvent::MatchAdded);
        assert_eq!(cr.affected(), Some("match_set_1"));
        assert_eq!(cr.old_value(), None);
        assert_eq!(cr.new_value(), Some("new_match"));
    }

    #[test]
    fn test_change_record_display() {
        let cr = VersionTrackingChangeRecord::new(
            VTEvent::AssociationStatusChanged,
            Some("assoc_5".to_string()),
            Some("Available".to_string()),
            Some("Accepted".to_string()),
        );
        let display = format!("{}", cr);
        assert!(display.contains("Association Status Changed"));
        assert!(display.contains("assoc_5"));
        assert!(display.contains("Available"));
        assert!(display.contains("Accepted"));
    }

    #[test]
    fn test_change_record_minimal() {
        let cr = VersionTrackingChangeRecord::new(VTEvent::TagAdded, None, None, None);
        assert_eq!(cr.affected(), None);
        assert_eq!(cr.old_value(), None);
        assert_eq!(cr.new_value(), None);
    }
}
