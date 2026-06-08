//! Event trigger classification.
//!
//! Port of Ghidra's `EventTrigger` enum. Used to provide information regarding
//! the source of an event -- whether the user generated it through the UI, it
//! came from an API call, or it was an internal model change.

/// Indicates the source of a change event.
///
/// This is used throughout Ghidra's widget layer so that event handlers can
/// distinguish between user-initiated actions and programmatic changes. For
/// example, a table model change listener may behave differently when the
/// change was triggered by a GUI click vs. an API call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventTrigger {
    /// Change initiated by a widget from a GUI action (like a mouse click).
    GuiAction,
    /// Change triggered by a programmatic API call.
    ApiCall,
    /// Change triggered by a change to the underlying data model.
    ModelChange,
    /// Change that is for internal use, not to be propagated.
    InternalOnly,
}

impl Default for EventTrigger {
    fn default() -> Self {
        EventTrigger::GuiAction
    }
}

impl std::fmt::Display for EventTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventTrigger::GuiAction => write!(f, "GUI_ACTION"),
            EventTrigger::ApiCall => write!(f, "API_CALL"),
            EventTrigger::ModelChange => write!(f, "MODEL_CHANGE"),
            EventTrigger::InternalOnly => write!(f, "INTERNAL_ONLY"),
        }
    }
}

impl EventTrigger {
    /// Returns `true` if this event was initiated by the user through the GUI.
    pub fn is_gui_action(&self) -> bool {
        *self == EventTrigger::GuiAction
    }

    /// Returns `true` if this event was triggered by an API call.
    pub fn is_api_call(&self) -> bool {
        *self == EventTrigger::ApiCall
    }

    /// Returns `true` if this event was triggered by a model change.
    pub fn is_model_change(&self) -> bool {
        *self == EventTrigger::ModelChange
    }

    /// Returns `true` if this is an internal-only event.
    pub fn is_internal_only(&self) -> bool {
        *self == EventTrigger::InternalOnly
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        assert_eq!(EventTrigger::default(), EventTrigger::GuiAction);
    }

    #[test]
    fn test_is_gui_action() {
        assert!(EventTrigger::GuiAction.is_gui_action());
        assert!(!EventTrigger::ApiCall.is_gui_action());
    }

    #[test]
    fn test_is_api_call() {
        assert!(EventTrigger::ApiCall.is_api_call());
        assert!(!EventTrigger::GuiAction.is_api_call());
    }

    #[test]
    fn test_is_model_change() {
        assert!(EventTrigger::ModelChange.is_model_change());
        assert!(!EventTrigger::InternalOnly.is_model_change());
    }

    #[test]
    fn test_is_internal_only() {
        assert!(EventTrigger::InternalOnly.is_internal_only());
        assert!(!EventTrigger::ModelChange.is_internal_only());
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", EventTrigger::GuiAction), "GUI_ACTION");
        assert_eq!(format!("{}", EventTrigger::ApiCall), "API_CALL");
        assert_eq!(format!("{}", EventTrigger::ModelChange), "MODEL_CHANGE");
        assert_eq!(format!("{}", EventTrigger::InternalOnly), "INTERNAL_ONLY");
    }

    #[test]
    fn test_clone_copy() {
        let e = EventTrigger::ApiCall;
        let e2 = e;
        assert_eq!(e, e2);
    }
}
