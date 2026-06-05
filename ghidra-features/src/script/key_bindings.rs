//! Script key binding management.
//!
//! Ported from `ghidra.app.plugin.core.script.KeyBindingsInfo`
//! and `KeyBindingInputDialog`.
//!
//! Manages key bindings assigned to Ghidra scripts so users can
//! invoke scripts via keyboard shortcuts.

use std::collections::BTreeMap;

/// A key binding assigned to a script.
///
/// Ported from key binding entries in Ghidra's script manager.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptKeyBinding {
    /// The script name.
    pub script_name: String,
    /// The key combination (e.g., "Ctrl+Shift+A").
    pub key_combo: String,
    /// Optional modifier keys.
    pub modifiers: Vec<String>,
    /// The primary key code.
    pub key: String,
}

impl ScriptKeyBinding {
    /// Create a new key binding.
    pub fn new(
        script_name: impl Into<String>,
        key: impl Into<String>,
        modifiers: Vec<String>,
    ) -> Self {
        let key = key.into();
        let mut parts = modifiers.clone();
        parts.push(key.clone());
        let key_combo = parts.join("+");
        Self {
            script_name: script_name.into(),
            key_combo,
            modifiers,
            key,
        }
    }

    /// Create a simple key binding with a combo string.
    pub fn from_combo(script_name: impl Into<String>, key_combo: impl Into<String>) -> Self {
        let combo = key_combo.into();
        let parts: Vec<String> = combo.split('+').map(|s| s.trim().to_string()).collect();
        let key = parts.last().cloned().unwrap_or_default();
        let modifiers = if parts.len() > 1 {
            parts[..parts.len() - 1].to_vec()
        } else {
            Vec::new()
        };
        Self {
            script_name: script_name.into(),
            key_combo: combo,
            modifiers,
            key,
        }
    }
}

/// Information about all script key bindings.
///
/// Ported from `ghidra.app.plugin.core.script.KeyBindingsInfo`.
#[derive(Debug)]
pub struct KeyBindingsInfo {
    /// Registered key bindings.
    bindings: BTreeMap<String, ScriptKeyBinding>,
    /// Available key slots that are not yet assigned.
    available_keys: Vec<String>,
}

impl KeyBindingsInfo {
    /// Create a new key bindings info.
    pub fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
            available_keys: Self::default_available_keys(),
        }
    }

    fn default_available_keys() -> Vec<String> {
        (1..=12).map(|i| format!("F{}", i)).collect()
    }

    /// Add a key binding.
    pub fn add_binding(&mut self, binding: ScriptKeyBinding) {
        self.available_keys.retain(|k| k != &binding.key_combo);
        self.bindings
            .insert(binding.script_name.clone(), binding);
    }

    /// Remove a key binding for a script.
    pub fn remove_binding(&mut self, script_name: &str) -> Option<ScriptKeyBinding> {
        let removed = self.bindings.remove(script_name);
        if let Some(ref b) = removed {
            self.available_keys.push(b.key_combo.clone());
            self.available_keys.sort();
        }
        removed
    }

    /// Get the key binding for a script.
    pub fn get_binding(&self, script_name: &str) -> Option<&ScriptKeyBinding> {
        self.bindings.get(script_name)
    }

    /// Whether a key combo is already in use.
    pub fn is_combo_in_use(&self, key_combo: &str) -> bool {
        self.bindings.values().any(|b| b.key_combo == key_combo)
    }

    /// Get the next available key.
    pub fn next_available_key(&self) -> Option<String> {
        self.available_keys.first().cloned()
    }

    /// Get all bindings.
    pub fn bindings(&self) -> &BTreeMap<String, ScriptKeyBinding> {
        &self.bindings
    }

    /// Get the number of bindings.
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Whether there are no bindings.
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }

    /// Get all assigned key combos.
    pub fn assigned_combos(&self) -> Vec<&str> {
        self.bindings.values().map(|b| b.key_combo.as_str()).collect()
    }

    /// Serialize bindings to a simple format.
    pub fn to_entries(&self) -> Vec<(String, String)> {
        self.bindings
            .values()
            .map(|b| (b.script_name.clone(), b.key_combo.clone()))
            .collect()
    }

    /// Load bindings from entries.
    pub fn from_entries(entries: &[(String, String)]) -> Self {
        let mut info = Self::new();
        for (script_name, key_combo) in entries {
            info.add_binding(ScriptKeyBinding::from_combo(
                script_name.clone(),
                key_combo.clone(),
            ));
        }
        info
    }
}

impl Default for KeyBindingsInfo {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_binding_new() {
        let kb = ScriptKeyBinding::new("MyScript", "A", vec!["Ctrl".into(), "Shift".into()]);
        assert_eq!(kb.script_name, "MyScript");
        assert_eq!(kb.key, "A");
        assert_eq!(kb.key_combo, "Ctrl+Shift+A");
        assert_eq!(kb.modifiers.len(), 2);
    }

    #[test]
    fn test_key_binding_from_combo() {
        let kb = ScriptKeyBinding::from_combo("MyScript", "Ctrl+F5");
        assert_eq!(kb.script_name, "MyScript");
        assert_eq!(kb.key, "F5");
        assert_eq!(kb.modifiers, vec!["Ctrl"]);
        assert_eq!(kb.key_combo, "Ctrl+F5");
    }

    #[test]
    fn test_key_binding_from_combo_no_modifier() {
        let kb = ScriptKeyBinding::from_combo("MyScript", "F1");
        assert_eq!(kb.key, "F1");
        assert!(kb.modifiers.is_empty());
    }

    #[test]
    fn test_key_bindings_info_lifecycle() {
        let mut info = KeyBindingsInfo::new();
        assert!(info.is_empty());
        assert_eq!(info.len(), 0);

        info.add_binding(ScriptKeyBinding::from_combo("Script1", "F1"));
        info.add_binding(ScriptKeyBinding::from_combo("Script2", "F2"));
        assert_eq!(info.len(), 2);

        assert!(info.get_binding("Script1").is_some());
        assert!(info.get_binding("Missing").is_none());
    }

    #[test]
    fn test_key_bindings_info_combo_check() {
        let mut info = KeyBindingsInfo::new();
        info.add_binding(ScriptKeyBinding::from_combo("Script1", "F1"));
        assert!(info.is_combo_in_use("F1"));
        assert!(!info.is_combo_in_use("F2"));
    }

    #[test]
    fn test_key_bindings_info_remove() {
        let mut info = KeyBindingsInfo::new();
        info.add_binding(ScriptKeyBinding::from_combo("Script1", "F1"));
        let removed = info.remove_binding("Script1");
        assert!(removed.is_some());
        assert!(info.is_empty());
    }

    #[test]
    fn test_key_bindings_info_next_available() {
        let mut info = KeyBindingsInfo::new();
        assert_eq!(info.next_available_key(), Some("F1".to_string()));
        info.add_binding(ScriptKeyBinding::from_combo("S1", "F1"));
        assert_eq!(info.next_available_key(), Some("F2".to_string()));
    }

    #[test]
    fn test_key_bindings_info_serialization() {
        let mut info = KeyBindingsInfo::new();
        info.add_binding(ScriptKeyBinding::from_combo("A", "F1"));
        info.add_binding(ScriptKeyBinding::from_combo("B", "F2"));

        let entries = info.to_entries();
        let restored = KeyBindingsInfo::from_entries(&entries);
        assert_eq!(restored.len(), 2);
        assert!(restored.get_binding("A").is_some());
        assert!(restored.get_binding("B").is_some());
    }

    #[test]
    fn test_key_bindings_info_assigned_combos() {
        let mut info = KeyBindingsInfo::new();
        info.add_binding(ScriptKeyBinding::from_combo("A", "Ctrl+F1"));
        let combos = info.assigned_combos();
        assert_eq!(combos, vec!["Ctrl+F1"]);
    }
}
