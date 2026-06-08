//! Port of `ghidra.framework.options.WrappedKeyStroke`.
//!
//! A wrapper for persisting keyboard shortcut values as options. Stores a
//! key code and modifier bitmask that can be serialized to/from a key/value
//! state map.

use super::action_trigger::ActionTrigger;
use super::option_type::OptionType;
use super::option_value::OptionValue;
use super::wrapped_option::WrappedOption;

/// Representation of a keyboard shortcut (key code + modifier mask).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyStroke {
    /// The virtual key code.
    pub key_code: u32,
    /// Modifier bitmask (Ctrl=1, Shift=2, Alt=4, Meta=8).
    pub modifiers: u32,
}

impl KeyStroke {
    /// Create a new keystroke.
    pub fn new(key_code: u32, modifiers: u32) -> Self {
        Self {
            key_code,
            modifiers,
        }
    }

    /// Whether the Ctrl modifier is set.
    pub fn ctrl(&self) -> bool {
        self.modifiers & 1 != 0
    }

    /// Whether the Shift modifier is set.
    pub fn shift(&self) -> bool {
        self.modifiers & 2 != 0
    }

    /// Whether the Alt modifier is set.
    pub fn alt(&self) -> bool {
        self.modifiers & 4 != 0
    }

    /// Whether the Meta modifier is set.
    pub fn meta(&self) -> bool {
        self.modifiers & 8 != 0
    }

    /// Get a human-readable representation of the modifier keys.
    pub fn modifier_string(&self) -> String {
        let mut parts = Vec::new();
        if self.ctrl() {
            parts.push("Ctrl");
        }
        if self.shift() {
            parts.push("Shift");
        }
        if self.alt() {
            parts.push("Alt");
        }
        if self.meta() {
            parts.push("Meta");
        }
        parts.join("+")
    }
}

impl std::fmt::Display for KeyStroke {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mods = self.modifier_string();
        if mods.is_empty() {
            write!(f, "key(code={})", self.key_code)
        } else {
            write!(f, "{}+key(code={})", mods, self.key_code)
        }
    }
}

/// Wrapper for a [`KeyStroke`] that can be persisted as an option value.
///
/// Ported from Ghidra's `ghidra.framework.options.WrappedKeyStroke`.
#[derive(Debug, Clone)]
pub struct WrappedKeyStroke {
    keystroke: Option<KeyStroke>,
}

impl WrappedKeyStroke {
    /// Create a new wrapper around a keystroke.
    pub fn new(keystroke: KeyStroke) -> Self {
        Self {
            keystroke: Some(keystroke),
        }
    }

    /// Create a wrapper with no keystroke.
    pub fn empty() -> Self {
        Self { keystroke: None }
    }

    /// Get the inner keystroke, if any.
    pub fn keystroke(&self) -> Option<&KeyStroke> {
        self.keystroke.as_ref()
    }

    /// Set the inner keystroke.
    pub fn set_keystroke(&mut self, keystroke: KeyStroke) {
        self.keystroke = Some(keystroke);
    }

    /// Convert to a `WrappedActionTrigger` (for migrating from deprecated
    /// key stroke options to action trigger options).
    ///
    /// Returns `None` if this wrapper has no keystroke.
    pub fn to_wrapped_action_trigger(&self) -> Option<super::wrapped_options::WrappedActionTrigger> {
        self.keystroke.as_ref().map(|ks| {
            let repr = format!("key(code={},mods={})", ks.key_code, ks.modifiers);
            let trigger = ActionTrigger::from_key_stroke(
                super::option_value::KeyStroke::new(&repr),
            );
            super::wrapped_options::WrappedActionTrigger::new(trigger)
        })
    }
}

impl Default for WrappedKeyStroke {
    fn default() -> Self {
        Self::empty()
    }
}

impl WrappedOption for WrappedKeyStroke {
    fn get_object(&self) -> OptionValue {
        match &self.keystroke {
            Some(ks) => OptionValue::String(format!("{}+{}", ks.key_code, ks.modifiers)),
            None => OptionValue::String(String::new()),
        }
    }

    fn read_state(&mut self, state: &[(String, OptionValue)]) {
        let mut key_code: u32 = 0;
        let mut modifiers: u32 = 0;
        let mut has_key = false;
        for (key, val) in state {
            match key.as_str() {
                "KeyCode" => {
                    if let OptionValue::Int(v) = val {
                        key_code = *v as u32;
                        has_key = true;
                    }
                }
                "Modifiers" => {
                    if let OptionValue::Int(v) = val {
                        modifiers = *v as u32;
                    }
                }
                _ => {}
            }
        }
        if has_key {
            self.keystroke = Some(KeyStroke::new(key_code, modifiers));
        }
    }

    fn write_state(&self) -> Vec<(String, OptionValue)> {
        match &self.keystroke {
            Some(ks) => vec![
                ("KeyCode".to_string(), OptionValue::Int(ks.key_code as i32)),
                ("Modifiers".to_string(), OptionValue::Int(ks.modifiers as i32)),
            ],
            None => Vec::new(),
        }
    }

    fn option_type(&self) -> OptionType {
        OptionType::KeyStrokeType
    }
}

impl std::fmt::Display for WrappedKeyStroke {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.keystroke {
            Some(ks) => write!(f, "WrappedKeyStroke: {}", ks),
            None => write!(f, "WrappedKeyStroke: (none)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystroke_new() {
        let ks = KeyStroke::new(65, 1 | 2); // Ctrl+Shift+A
        assert_eq!(ks.key_code, 65);
        assert!(ks.ctrl());
        assert!(ks.shift());
        assert!(!ks.alt());
        assert!(!ks.meta());
    }

    #[test]
    fn test_keystroke_display() {
        let ks = KeyStroke::new(70, 2); // Shift+F
        let s = format!("{}", ks);
        assert!(s.contains("Shift"));
    }

    #[test]
    fn test_wrapped_keystroke_new() {
        let ks = KeyStroke::new(65, 1);
        let w = WrappedKeyStroke::new(ks);
        assert!(w.keystroke().is_some());
        assert_eq!(w.keystroke().unwrap().key_code, 65);
    }

    #[test]
    fn test_wrapped_keystroke_empty() {
        let w = WrappedKeyStroke::empty();
        assert!(w.keystroke().is_none());
        assert!(w.write_state().is_empty());
    }

    #[test]
    fn test_wrapped_keystroke_default() {
        let w = WrappedKeyStroke::default();
        assert!(w.keystroke().is_none());
    }

    #[test]
    fn test_wrapped_keystroke_option_type() {
        let w = WrappedKeyStroke::new(KeyStroke::new(70, 2));
        assert_eq!(w.option_type(), OptionType::KeyStrokeType);
    }

    #[test]
    fn test_wrapped_keystroke_roundtrip() {
        let ks = KeyStroke::new(70, 2); // Shift+F
        let w = WrappedKeyStroke::new(ks);
        let state = w.write_state();
        assert_eq!(state.len(), 2);

        let mut w2 = WrappedKeyStroke::empty();
        w2.read_state(&state);
        let ks2 = w2.keystroke().unwrap();
        assert_eq!(ks2.key_code, 70);
        assert_eq!(ks2.modifiers, 2);
    }

    #[test]
    fn test_wrapped_keystroke_set() {
        let mut w = WrappedKeyStroke::empty();
        assert!(w.keystroke().is_none());
        w.set_keystroke(KeyStroke::new(80, 4));
        assert!(w.keystroke().is_some());
        assert_eq!(w.keystroke().unwrap().key_code, 80);
    }

    #[test]
    fn test_wrapped_keystroke_display() {
        let w = WrappedKeyStroke::new(KeyStroke::new(65, 1));
        let s = format!("{}", w);
        assert!(s.contains("Ctrl"));
    }

    #[test]
    fn test_modifier_string() {
        let ks = KeyStroke::new(0, 0);
        assert_eq!(ks.modifier_string(), "");

        let ks = KeyStroke::new(0, 1 | 4); // Ctrl+Alt
        assert_eq!(ks.modifier_string(), "Ctrl+Alt");
    }
}
