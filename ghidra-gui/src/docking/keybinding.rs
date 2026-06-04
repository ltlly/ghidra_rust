//! Key binding precedence and dispatch for the docking framework.
//!
//! Port of Ghidra's `KeyBindingPrecedence`, `ExecutableAction`, and
//! `KeyBindingOverrideKeyEventDispatcher`.  Controls the priority order
//! in which key events are processed.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use super::action::{DockingAction, Key, KeyBinding, Modifiers};

// ---------------------------------------------------------------------------
// KeyBindingPrecedence
// ---------------------------------------------------------------------------

/// Order of key binding precedence, from highest priority to lowest.
///
/// When the same key binding is assigned to multiple actions, the one
/// with the highest precedence wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyBindingPrecedence {
    /// Actions at this level are processed before all others, including
    /// native component key listeners.
    SystemActions,
    /// Actions processed before native key listeners on components.
    KeyListener,
    /// Actions processed before native action map bindings on components.
    ActionMap,
    /// Default level.  Processed after native key listeners and action maps.
    Component,
    /// Lower priority than default; typically used for shared/built-in bindings.
    Shared,
    /// Lowest priority; for actions that only fire when nothing else handles the key.
    Lowest,
}

impl KeyBindingPrecedence {
    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            KeyBindingPrecedence::SystemActions => "SystemActions",
            KeyBindingPrecedence::KeyListener => "KeyListener",
            KeyBindingPrecedence::ActionMap => "ActionMap",
            KeyBindingPrecedence::Component => "Component",
            KeyBindingPrecedence::Shared => "Shared",
            KeyBindingPrecedence::Lowest => "Lowest",
        }
    }

    /// Returns `true` if this precedence level overrides component key handling.
    pub fn overrides_component(&self) -> bool {
        *self < KeyBindingPrecedence::Component
    }
}

impl Default for KeyBindingPrecedence {
    fn default() -> Self {
        KeyBindingPrecedence::Component
    }
}

impl fmt::Display for KeyBindingPrecedence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ---------------------------------------------------------------------------
// ExecutableAction
// ---------------------------------------------------------------------------

/// A trait representing an action that can be executed in response to a
/// key event.
///
/// In Ghidra, `ExecutableAction` wraps a `DockingActionIf` together
/// with its context and precedence.  This Rust trait captures the same
/// interface.
pub trait ExecutableAction: fmt::Debug {
    /// Whether the action and its context are still valid.
    fn is_valid(&self) -> bool;

    /// Whether the action is currently enabled.
    fn is_enabled(&self) -> bool;

    /// The key binding precedence for this action.
    fn key_binding_precedence(&self) -> KeyBindingPrecedence;

    /// Execute the action.
    fn execute(&self);

    /// The name of the action.
    fn action_name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// Concrete ExecutableAction implementation
// ---------------------------------------------------------------------------

/// A simple, concrete implementation of [`ExecutableAction`].
pub struct SimpleExecutableAction {
    /// The action name.
    pub name: String,
    /// Whether the action is currently valid.
    pub valid: bool,
    /// Whether the action is currently enabled.
    pub enabled: bool,
    /// The precedence level.
    pub precedence: KeyBindingPrecedence,
    /// The callback to invoke on execute.
    pub callback: Arc<dyn Fn() + Send + Sync>,
}

impl fmt::Debug for SimpleExecutableAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SimpleExecutableAction")
            .field("name", &self.name)
            .field("valid", &self.valid)
            .field("enabled", &self.enabled)
            .field("precedence", &self.precedence)
            .finish()
    }
}

impl SimpleExecutableAction {
    /// Create a new executable action.
    pub fn new(
        name: impl Into<String>,
        valid: bool,
        enabled: bool,
        precedence: KeyBindingPrecedence,
        callback: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            name: name.into(),
            valid,
            enabled,
            precedence,
            callback,
        }
    }
}

impl ExecutableAction for SimpleExecutableAction {
    fn is_valid(&self) -> bool {
        self.valid
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn key_binding_precedence(&self) -> KeyBindingPrecedence {
        self.precedence
    }

    fn execute(&self) {
        if self.valid && self.enabled {
            (self.callback)();
        }
    }

    fn action_name(&self) -> &str {
        &self.name
    }
}

// ---------------------------------------------------------------------------
// KeyBindingEntry — a binding with its action and precedence
// ---------------------------------------------------------------------------

/// A key binding entry that maps a key chord to an executable action
/// with a specific precedence level.
#[derive(Debug, Clone)]
pub struct KeyBindingEntry {
    /// The key binding (modifiers + key).
    pub binding: KeyBinding,
    /// The name of the associated action.
    pub action_name: String,
    /// The precedence of this binding.
    pub precedence: KeyBindingPrecedence,
    /// Whether this binding is currently enabled.
    pub enabled: bool,
}

impl KeyBindingEntry {
    /// Create a new key binding entry.
    pub fn new(
        binding: KeyBinding,
        action_name: impl Into<String>,
        precedence: KeyBindingPrecedence,
    ) -> Self {
        Self {
            binding,
            action_name: action_name.into(),
            precedence,
            enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// KeyBindingDispatcher
// ---------------------------------------------------------------------------

/// Dispatches key events to registered actions based on key binding
/// precedence.
///
/// When a key event arrives, the dispatcher finds all actions matching
/// the key chord, sorts them by precedence, and returns the highest-
/// priority one.
pub struct KeyBindingDispatcher {
    /// All registered key binding entries.
    entries: Vec<KeyBindingEntry>,
}

impl KeyBindingDispatcher {
    /// Create a new, empty dispatcher.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register a key binding entry.
    pub fn register(&mut self, entry: KeyBindingEntry) {
        self.entries.push(entry);
    }

    /// Unregister a key binding entry for the given action.
    pub fn unregister(&mut self, action_name: &str) {
        self.entries.retain(|e| e.action_name != action_name);
    }

    /// Register all key bindings from a `DockingAction`.
    pub fn register_action(
        &mut self,
        action: &DockingAction,
        precedence: KeyBindingPrecedence,
    ) {
        if let Some(ref binding) = action.key_binding {
            self.register(KeyBindingEntry::new(
                binding.clone(),
                &action.name,
                precedence,
            ));
        }
    }

    /// Find the highest-priority action for a key chord.
    /// Returns the action name and its precedence.
    pub fn dispatch(
        &self,
        modifiers: &Modifiers,
        key: &Key,
    ) -> Option<(&str, KeyBindingPrecedence)> {
        let mut best: Option<(&KeyBindingEntry, KeyBindingPrecedence)> = None;

        for entry in &self.entries {
            if !entry.enabled {
                continue;
            }
            if entry.binding.modifiers == *modifiers && entry.binding.key == *key {
                match &best {
                    Some((_, best_prec)) if *best_prec <= entry.precedence => {
                        // Current best has lower or equal priority; keep current best
                        // if equal (first-registered wins).
                    }
                    _ => {
                        best = Some((entry, entry.precedence));
                    }
                }
            }
        }

        best.map(|(entry, prec)| (entry.action_name.as_str(), prec))
    }

    /// Find all actions matching a key chord (for diagnostic/UI purposes).
    pub fn all_matching(
        &self,
        modifiers: &Modifiers,
        key: &Key,
    ) -> Vec<&KeyBindingEntry> {
        self.entries
            .iter()
            .filter(|e| {
                e.enabled && e.binding.modifiers == *modifiers && e.binding.key == *key
            })
            .collect()
    }

    /// Remove all registered bindings.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Number of registered bindings.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no bindings are registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all registered entries.
    pub fn entries(&self) -> &[KeyBindingEntry] {
        &self.entries
    }

    /// Whether a key binding is already registered for the given action.
    pub fn has_binding_for(&self, action_name: &str) -> bool {
        self.entries.iter().any(|e| e.action_name == action_name)
    }
}

impl Default for KeyBindingDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for KeyBindingDispatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyBindingDispatcher")
            .field("entries_count", &self.entries.len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_precedence_ordering() {
        assert!(
            KeyBindingPrecedence::SystemActions < KeyBindingPrecedence::KeyListener
        );
        assert!(
            KeyBindingPrecedence::KeyListener < KeyBindingPrecedence::ActionMap
        );
        assert!(
            KeyBindingPrecedence::ActionMap < KeyBindingPrecedence::Component
        );
        assert!(
            KeyBindingPrecedence::Component < KeyBindingPrecedence::Shared
        );
        assert!(
            KeyBindingPrecedence::Shared < KeyBindingPrecedence::Lowest
        );
    }

    #[test]
    fn test_precedence_names() {
        assert_eq!(KeyBindingPrecedence::SystemActions.name(), "SystemActions");
        assert_eq!(KeyBindingPrecedence::Component.name(), "Component");
        assert_eq!(KeyBindingPrecedence::Lowest.name(), "Lowest");
    }

    #[test]
    fn test_precedence_overrides_component() {
        assert!(KeyBindingPrecedence::SystemActions.overrides_component());
        assert!(KeyBindingPrecedence::KeyListener.overrides_component());
        assert!(KeyBindingPrecedence::ActionMap.overrides_component());
        assert!(!KeyBindingPrecedence::Component.overrides_component());
        assert!(!KeyBindingPrecedence::Shared.overrides_component());
    }

    #[test]
    fn test_precedence_display() {
        assert_eq!(format!("{}", KeyBindingPrecedence::SystemActions), "SystemActions");
    }

    #[test]
    fn test_precedence_default() {
        assert_eq!(KeyBindingPrecedence::default(), KeyBindingPrecedence::Component);
    }

    #[test]
    fn test_simple_executable_action() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let called = Arc::new(AtomicBool::new(false));
        let called2 = called.clone();

        let action = SimpleExecutableAction::new(
            "test",
            true,
            true,
            KeyBindingPrecedence::Component,
            Arc::new(move || called2.store(true, Ordering::SeqCst)),
        );

        assert!(action.is_valid());
        assert!(action.is_enabled());
        assert_eq!(action.action_name(), "test");
        action.execute();
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_executable_action_disabled() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let called = Arc::new(AtomicBool::new(false));
        let called2 = called.clone();

        let action = SimpleExecutableAction::new(
            "test",
            true,
            false, // disabled
            KeyBindingPrecedence::Component,
            Arc::new(move || called2.store(true, Ordering::SeqCst)),
        );

        assert!(!action.is_enabled());
        action.execute();
        assert!(!called.load(Ordering::SeqCst)); // should not be called
    }

    #[test]
    fn test_executable_action_invalid() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let called = Arc::new(AtomicBool::new(false));
        let called2 = called.clone();

        let action = SimpleExecutableAction::new(
            "test",
            false, // invalid
            true,
            KeyBindingPrecedence::Component,
            Arc::new(move || called2.store(true, Ordering::SeqCst)),
        );

        assert!(!action.is_valid());
        action.execute();
        assert!(!called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_dispatcher_register_and_dispatch() {
        let mut dispatcher = KeyBindingDispatcher::new();
        dispatcher.register(KeyBindingEntry::new(
            KeyBinding::ctrl(Key::S),
            "save",
            KeyBindingPrecedence::Component,
        ));
        dispatcher.register(KeyBindingEntry::new(
            KeyBinding::ctrl(Key::O),
            "open",
            KeyBindingPrecedence::Component,
        ));

        let result = dispatcher.dispatch(&Modifiers::CTRL, &Key::S);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "save");

        let result = dispatcher.dispatch(&Modifiers::CTRL, &Key::O);
        assert_eq!(result.unwrap().0, "open");

        // No match.
        assert!(dispatcher.dispatch(&Modifiers::CTRL, &Key::Z).is_none());
    }

    #[test]
    fn test_dispatcher_precedence_priority() {
        let mut dispatcher = KeyBindingDispatcher::new();
        // Both bind Ctrl+S but at different precedences.
        dispatcher.register(KeyBindingEntry::new(
            KeyBinding::ctrl(Key::S),
            "save-low",
            KeyBindingPrecedence::Shared,
        ));
        dispatcher.register(KeyBindingEntry::new(
            KeyBinding::ctrl(Key::S),
            "save-high",
            KeyBindingPrecedence::SystemActions,
        ));

        let result = dispatcher.dispatch(&Modifiers::CTRL, &Key::S);
        assert!(result.is_some());
        // SystemActions has higher priority.
        assert_eq!(result.unwrap().0, "save-high");
    }

    #[test]
    fn test_dispatcher_disabled_entry() {
        let mut dispatcher = KeyBindingDispatcher::new();
        let mut entry = KeyBindingEntry::new(
            KeyBinding::ctrl(Key::S),
            "save",
            KeyBindingPrecedence::Component,
        );
        entry.enabled = false;
        dispatcher.register(entry);

        assert!(dispatcher.dispatch(&Modifiers::CTRL, &Key::S).is_none());
    }

    #[test]
    fn test_dispatcher_unregister() {
        let mut dispatcher = KeyBindingDispatcher::new();
        dispatcher.register(KeyBindingEntry::new(
            KeyBinding::ctrl(Key::S),
            "save",
            KeyBindingPrecedence::Component,
        ));
        assert!(dispatcher.dispatch(&Modifiers::CTRL, &Key::S).is_some());

        dispatcher.unregister("save");
        assert!(dispatcher.dispatch(&Modifiers::CTRL, &Key::S).is_none());
    }

    #[test]
    fn test_dispatcher_register_action() {
        let action = DockingAction::new("save", "Save")
            .with_key_binding(KeyBinding::ctrl(Key::S));
        let mut dispatcher = KeyBindingDispatcher::new();
        dispatcher.register_action(&action, KeyBindingPrecedence::Component);

        let result = dispatcher.dispatch(&Modifiers::CTRL, &Key::S);
        assert_eq!(result.unwrap().0, "save");
    }

    #[test]
    fn test_dispatcher_all_matching() {
        let mut dispatcher = KeyBindingDispatcher::new();
        dispatcher.register(KeyBindingEntry::new(
            KeyBinding::ctrl(Key::S),
            "save-1",
            KeyBindingPrecedence::Component,
        ));
        dispatcher.register(KeyBindingEntry::new(
            KeyBinding::ctrl(Key::S),
            "save-2",
            KeyBindingPrecedence::Shared,
        ));
        dispatcher.register(KeyBindingEntry::new(
            KeyBinding::ctrl(Key::O),
            "open",
            KeyBindingPrecedence::Component,
        ));

        let matching = dispatcher.all_matching(&Modifiers::CTRL, &Key::S);
        assert_eq!(matching.len(), 2);
    }

    #[test]
    fn test_dispatcher_clear() {
        let mut dispatcher = KeyBindingDispatcher::new();
        dispatcher.register(KeyBindingEntry::new(
            KeyBinding::ctrl(Key::S),
            "save",
            KeyBindingPrecedence::Component,
        ));
        assert!(!dispatcher.is_empty());
        dispatcher.clear();
        assert!(dispatcher.is_empty());
    }

    #[test]
    fn test_dispatcher_has_binding_for() {
        let mut dispatcher = KeyBindingDispatcher::new();
        assert!(!dispatcher.has_binding_for("save"));
        dispatcher.register(KeyBindingEntry::new(
            KeyBinding::ctrl(Key::S),
            "save",
            KeyBindingPrecedence::Component,
        ));
        assert!(dispatcher.has_binding_for("save"));
        assert!(!dispatcher.has_binding_for("open"));
    }
}
