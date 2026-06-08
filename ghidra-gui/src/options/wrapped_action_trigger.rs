//! Port of `ghidra.framework.options.WrappedActionTrigger`.
//!
//! A wrapper for persisting action trigger values (key bindings and mouse
//! bindings) as options. Serializes to/from a key/value state map.

use super::action_trigger::ActionTrigger;
use super::option_type::OptionType;
use super::option_value::OptionValue;
use super::wrapped_option::WrappedOption;

/// Wrapper for an [`ActionTrigger`] that can be persisted as an option value.
///
/// Ported from Ghidra's `ghidra.framework.options.WrappedActionTrigger`.
#[derive(Debug, Clone)]
pub struct WrappedActionTrigger {
    /// The wrapped action trigger.
    trigger: ActionTrigger,
}

impl WrappedActionTrigger {
    /// Create a new wrapper around the given action trigger.
    pub fn new(trigger: ActionTrigger) -> Self {
        Self { trigger }
    }

    /// Get a reference to the inner action trigger.
    pub fn trigger(&self) -> &ActionTrigger {
        &self.trigger
    }

    /// Consume the wrapper and return the inner action trigger.
    pub fn into_trigger(self) -> ActionTrigger {
        self.trigger
    }

    /// Set the inner action trigger.
    pub fn set_trigger(&mut self, trigger: ActionTrigger) {
        self.trigger = trigger;
    }
}

impl Default for WrappedActionTrigger {
    fn default() -> Self {
        // Create a trigger with a no-op key stroke representation.
        Self {
            trigger: ActionTrigger::from_key_stroke(
                super::option_value::KeyStroke::new("(none)"),
            ),
        }
    }
}

impl WrappedOption for WrappedActionTrigger {
    fn get_object(&self) -> OptionValue {
        let repr = format!("{}", self.trigger);
        OptionValue::String(repr)
    }

    fn read_state(&mut self, state: &[(String, OptionValue)]) {
        for (key, val) in state {
            if key == "trigger" {
                if let OptionValue::String(s) = val {
                    if let Some(trigger) = ActionTrigger::parse(s) {
                        self.trigger = trigger;
                    }
                }
            }
        }
    }

    fn write_state(&self) -> Vec<(String, OptionValue)> {
        vec![(
            "trigger".to_string(),
            OptionValue::String(format!("{}", self.trigger)),
        )]
    }

    fn option_type(&self) -> OptionType {
        OptionType::ActionTrigger
    }
}

impl std::fmt::Display for WrappedActionTrigger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WrappedActionTrigger: {}", self.trigger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrapped_action_trigger_new() {
        let trigger = ActionTrigger::empty();
        let w = WrappedActionTrigger::new(trigger);
        assert_eq!(w.option_type(), OptionType::ActionTrigger);
    }

    #[test]
    fn test_wrapped_action_trigger_default() {
        let w = WrappedActionTrigger::default();
        assert_eq!(w.option_type(), OptionType::ActionTrigger);
    }

    #[test]
    fn test_wrapped_action_trigger_trigger_ref() {
        let trigger = ActionTrigger::empty();
        let w = WrappedActionTrigger::new(trigger);
        let _ = w.trigger();
    }

    #[test]
    fn test_wrapped_action_trigger_set() {
        let mut w = WrappedActionTrigger::default();
        let trigger = ActionTrigger::empty();
        w.set_trigger(trigger);
    }

    #[test]
    fn test_wrapped_action_trigger_display() {
        let w = WrappedActionTrigger::default();
        let s = format!("{}", w);
        assert!(s.contains("WrappedActionTrigger"));
    }

    #[test]
    fn test_wrapped_action_trigger_get_object() {
        let w = WrappedActionTrigger::default();
        match w.get_object() {
            OptionValue::String(_) => {}
            _ => panic!("Expected String option value"),
        }
    }
}
