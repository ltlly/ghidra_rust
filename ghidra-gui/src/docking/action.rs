//! Ghidra-inspired action system for the docking framework.
//!
//! Actions represent user-invokable operations that can appear in menus,
//! toolbars, and context menus. Each action has a name, display label,
//! optional key binding, and can be global or contextual.

use std::fmt;
use std::hash::Hash;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// ActionCallback — wraps a boxed closure so actions carry their behaviour
// ---------------------------------------------------------------------------

/// A type-erased callback invoked when an action is triggered.
///
/// Wraps an `Arc<dyn Fn()>` so it can be cloned, debug-printed (as a
/// placeholder), and stored inside [`DockingAction`].
pub struct ActionCallback(Arc<dyn Fn() + Send + Sync>);

impl ActionCallback {
    /// Wrap a closure into an `ActionCallback`.
    pub fn new<F: Fn() + Send + Sync + 'static>(f: F) -> Self {
        Self(Arc::new(f))
    }

    /// Invoke the stored callback.
    pub fn call(&self) {
        (self.0)()
    }
}

impl fmt::Debug for ActionCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActionCallback").finish()
    }
}

impl Clone for ActionCallback {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

// ---------------------------------------------------------------------------
// Key & Modifiers
// ---------------------------------------------------------------------------

/// Keyboard modifiers that may accompany a key binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Modifiers {
    pub ctrl: bool,
    pub alt: bool,
    pub shift: bool,
}

impl Modifiers {
    /// No modifiers.
    pub const NONE: Self = Self {
        ctrl: false,
        alt: false,
        shift: false,
    };

    /// Ctrl only.
    pub const CTRL: Self = Self {
        ctrl: true,
        alt: false,
        shift: false,
    };

    /// Alt only.
    pub const ALT: Self = Self {
        ctrl: false,
        alt: true,
        shift: false,
    };

    /// Shift only.
    pub const SHIFT: Self = Self {
        ctrl: false,
        alt: false,
        shift: true,
    };

    /// Build a new modifiers mask.
    pub fn new(ctrl: bool, alt: bool, shift: bool) -> Self {
        Self { ctrl, alt, shift }
    }

    /// Returns `true` when no modifier is set.
    pub fn is_empty(&self) -> bool {
        !self.ctrl && !self.alt && !self.shift
    }
}

impl fmt::Display for Modifiers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts: Vec<&str> = Vec::new();
        if self.ctrl {
            parts.push("Ctrl");
        }
        if self.alt {
            parts.push("Alt");
        }
        if self.shift {
            parts.push("Shift");
        }
        if parts.is_empty() {
            write!(f, "(none)")
        } else {
            write!(f, "{}", parts.join("+"))
        }
    }
}

/// All keys that can appear in a key binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Key {
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
    I,
    J,
    K,
    L,
    M,
    N,
    O,
    P,
    Q,
    R,
    S,
    T,
    U,
    V,
    W,
    X,
    Y,
    Z,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    Enter,
    Escape,
    Tab,
    Space,
    Delete,
    Backspace,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Semicolon,
    Slash,
    Backslash,
    Comma,
    Period,
    Minus,
    Equals,
    BracketLeft,
    BracketRight,
    Quote,
    Num0,
    Num1,
    Num2,
    Num3,
    Num4,
    Num5,
    Num6,
    Num7,
    Num8,
    Num9,
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Key::A => write!(f, "A"),
            Key::B => write!(f, "B"),
            Key::C => write!(f, "C"),
            Key::D => write!(f, "D"),
            Key::E => write!(f, "E"),
            Key::F => write!(f, "F"),
            Key::G => write!(f, "G"),
            Key::H => write!(f, "H"),
            Key::I => write!(f, "I"),
            Key::J => write!(f, "J"),
            Key::K => write!(f, "K"),
            Key::L => write!(f, "L"),
            Key::M => write!(f, "M"),
            Key::N => write!(f, "N"),
            Key::O => write!(f, "O"),
            Key::P => write!(f, "P"),
            Key::Q => write!(f, "Q"),
            Key::R => write!(f, "R"),
            Key::S => write!(f, "S"),
            Key::T => write!(f, "T"),
            Key::U => write!(f, "U"),
            Key::V => write!(f, "V"),
            Key::W => write!(f, "W"),
            Key::X => write!(f, "X"),
            Key::Y => write!(f, "Y"),
            Key::Z => write!(f, "Z"),
            Key::F1 => write!(f, "F1"),
            Key::F2 => write!(f, "F2"),
            Key::F3 => write!(f, "F3"),
            Key::F4 => write!(f, "F4"),
            Key::F5 => write!(f, "F5"),
            Key::F6 => write!(f, "F6"),
            Key::F7 => write!(f, "F7"),
            Key::F8 => write!(f, "F8"),
            Key::F9 => write!(f, "F9"),
            Key::F10 => write!(f, "F10"),
            Key::F11 => write!(f, "F11"),
            Key::F12 => write!(f, "F12"),
            Key::Enter => write!(f, "Enter"),
            Key::Escape => write!(f, "Escape"),
            Key::Tab => write!(f, "Tab"),
            Key::Space => write!(f, "Space"),
            Key::Delete => write!(f, "Delete"),
            Key::Backspace => write!(f, "Backspace"),
            Key::Up => write!(f, "Up"),
            Key::Down => write!(f, "Down"),
            Key::Left => write!(f, "Left"),
            Key::Right => write!(f, "Right"),
            Key::Home => write!(f, "Home"),
            Key::End => write!(f, "End"),
            Key::PageUp => write!(f, "PageUp"),
            Key::PageDown => write!(f, "PageDown"),
            Key::Semicolon => write!(f, ";"),
            Key::Slash => write!(f, "/"),
            Key::Backslash => write!(f, "\\"),
            Key::Comma => write!(f, ","),
            Key::Period => write!(f, "."),
            Key::Minus => write!(f, "-"),
            Key::Equals => write!(f, "="),
            Key::BracketLeft => write!(f, "["),
            Key::BracketRight => write!(f, "]"),
            Key::Quote => write!(f, "\""),
            Key::Num0 => write!(f, "0"),
            Key::Num1 => write!(f, "1"),
            Key::Num2 => write!(f, "2"),
            Key::Num3 => write!(f, "3"),
            Key::Num4 => write!(f, "4"),
            Key::Num5 => write!(f, "5"),
            Key::Num6 => write!(f, "6"),
            Key::Num7 => write!(f, "7"),
            Key::Num8 => write!(f, "8"),
            Key::Num9 => write!(f, "9"),
        }
    }
}

// ---------------------------------------------------------------------------
// KeyBinding
// ---------------------------------------------------------------------------

/// A keyboard shortcut composed of modifiers and a key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyBinding {
    pub modifiers: Modifiers,
    pub key: Key,
}

impl KeyBinding {
    /// Create a new key binding.
    pub fn new(modifiers: Modifiers, key: Key) -> Self {
        Self { modifiers, key }
    }

    /// Convenience: Ctrl+key.
    pub fn ctrl(key: Key) -> Self {
        Self {
            modifiers: Modifiers::CTRL,
            key,
        }
    }

    /// Convenience: Alt+key.
    pub fn alt(key: Key) -> Self {
        Self {
            modifiers: Modifiers::ALT,
            key,
        }
    }

    /// Convenience: Shift+key.
    pub fn shift(key: Key) -> Self {
        Self {
            modifiers: Modifiers::SHIFT,
            key,
        }
    }

    /// Convenience: Ctrl+Shift+key.
    pub fn ctrl_shift(key: Key) -> Self {
        Self {
            modifiers: Modifiers::new(true, false, true),
            key,
        }
    }

    /// No-modifier binding (e.g. F5 for refresh).
    pub fn plain(key: Key) -> Self {
        Self {
            modifiers: Modifiers::NONE,
            key,
        }
    }
}

impl fmt::Display for KeyBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.modifiers.is_empty() {
            write!(f, "{}", self.key)
        } else {
            write!(f, "{}+{}", self.modifiers, self.key)
        }
    }
}

// ---------------------------------------------------------------------------
// Action context — what the action applies to
// ---------------------------------------------------------------------------

/// Describes what kind of program element an action operates on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionContext {
    /// Operates on the current program.
    Program,
    /// Operates on the current function.
    Function,
    /// Operates on the current instruction.
    Instruction,
    /// Operates on a data item.
    Data,
    /// Operates on a specific address.
    Address,
    /// Operates on a selection range.
    Selection,
    /// Always applicable, no specific context required.
    Any,
}

impl ActionContext {
    /// Returns `true` when this context "matches" another, i.e. the
    /// action can fire in that context.  `Any` matches everything;
    /// concrete contexts only match themselves.
    pub fn matches(&self, other: &ActionContext) -> bool {
        matches!(self, ActionContext::Any) || self == other
    }
}

// ---------------------------------------------------------------------------
// ActionType
// ---------------------------------------------------------------------------

/// The kind of action: global, contextual, toggle, or sub-menu.
#[derive(Debug, Clone, PartialEq)]
pub enum ActionType {
    /// Always-available action.
    Global,
    /// Only available when a specific context is active.
    Contextual {
        /// The required program context.
        context: ActionContext,
    },
    /// A two-state toggle action.
    Toggle {
        /// Current toggle state.
        selected: bool,
    },
    /// A sub-menu that owns child actions.
    Menu {
        /// Child actions displayed in this sub-menu.
        items: Vec<DockingAction>,
    },
}

// ---------------------------------------------------------------------------
// DockingAction
// ---------------------------------------------------------------------------

/// A named, optionally-keybound action that can appear in menus, toolbars,
/// and popup (context) menus.
#[derive(Debug, Clone)]
pub struct DockingAction {
    /// Programmatic identifier (used for lookup and serialization).
    pub name: String,
    /// Human-readable label shown in menus and toolbars.
    pub display_name: String,
    /// Longer help text / tooltip.
    pub description: String,
    /// Optional keyboard shortcut.
    pub key_binding: Option<KeyBinding>,
    /// Menu path hierarchy, e.g. `["File", "Export"]`.
    pub menu_path: Vec<String>,
    /// Optional icon identifier (resource name or path).
    pub icon: Option<String>,
    /// Whether the action is currently enabled.
    pub enabled: bool,
    /// Global / contextual / toggle / sub-menu.
    pub action_type: ActionType,
    /// Optional callback invoked when the action is triggered.
    #[debug("ActionCallback")]
    pub callback: Option<ActionCallback>,
}

// PartialEq must be implemented manually because ActionCallback is not
// Comparable. We ignore the callback field for equality checks.
impl PartialEq for DockingAction {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.display_name == other.display_name
            && self.description == other.description
            && self.key_binding == other.key_binding
            && self.menu_path == other.menu_path
            && self.icon == other.icon
            && self.enabled == other.enabled
            && self.action_type == other.action_type
    }
}

impl DockingAction {
    // ---------------------------------------------------------------
    // Constructors
    // ---------------------------------------------------------------

    /// Create a minimal global action.
    pub fn new(name: impl Into<String>, display_name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            description: String::new(),
            key_binding: None,
            menu_path: Vec::new(),
            icon: None,
            enabled: true,
            action_type: ActionType::Global,
            callback: None,
        }
    }

    /// Create a contextual action.
    pub fn contextual(
        name: impl Into<String>,
        display_name: impl Into<String>,
        context: ActionContext,
    ) -> Self {
        Self {
            action_type: ActionType::Contextual { context },
            ..Self::new(name, display_name)
        }
    }

    /// Create a toggle action with the given initial state.
    pub fn toggle(
        name: impl Into<String>,
        display_name: impl Into<String>,
        selected: bool,
    ) -> Self {
        Self {
            action_type: ActionType::Toggle { selected },
            ..Self::new(name, display_name)
        }
    }

    /// Create a sub-menu action.
    pub fn menu(
        name: impl Into<String>,
        display_name: impl Into<String>,
        items: Vec<DockingAction>,
    ) -> Self {
        Self {
            action_type: ActionType::Menu { items },
            ..Self::new(name, display_name)
        }
    }

    // ---------------------------------------------------------------
    // Builder helpers
    // ---------------------------------------------------------------

    /// Attach a description / tooltip.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Assign a keyboard shortcut.
    pub fn with_key_binding(mut self, binding: KeyBinding) -> Self {
        self.key_binding = Some(binding);
        self
    }

    /// Assign a menu path (e.g. `["Edit", "Undo"]`).
    pub fn with_menu_path(mut self, path: Vec<String>) -> Self {
        self.menu_path = path;
        self
    }

    /// Assign an icon identifier.
    pub fn with_icon(mut self, icon: impl Into<String>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    /// Set the enabled flag.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Attach an invocation callback to this action.
    ///
    /// When the action is triggered (via menu click, toolbar button, or
    /// keyboard shortcut), the callback is invoked.
    pub fn with_callback(mut self, callback: ActionCallback) -> Self {
        self.callback = Some(callback);
        self
    }

    // ---------------------------------------------------------------
    // Queries
    // ---------------------------------------------------------------

    /// Whether this action matches the given key-stroke.
    pub fn matches_key(&self, modifiers: &Modifiers, key: &Key) -> bool {
        match &self.key_binding {
            Some(binding) => &binding.modifiers == modifiers && &binding.key == key,
            None => false,
        }
    }

    /// Whether this action is applicable in the supplied context.
    pub fn is_applicable(&self, current_context: &ActionContext) -> bool {
        if !self.enabled {
            return false;
        }
        match &self.action_type {
            ActionType::Global => true,
            ActionType::Contextual { context } => context.matches(current_context),
            ActionType::Toggle { .. } => true,
            ActionType::Menu { .. } => true,
        }
    }

    /// Get the toggle state (panics if not a toggle).
    pub fn is_selected(&self) -> bool {
        match &self.action_type {
            ActionType::Toggle { selected } => *selected,
            _ => false,
        }
    }

    /// Set the toggle state (no-op if not a toggle).
    pub fn set_selected(&mut self, selected: bool) {
        if let ActionType::Toggle {
            selected: ref mut s,
        } = self.action_type
        {
            *s = selected;
        }
    }

    /// Toggle the toggle state (no-op if not a toggle).
    pub fn toggle_selection(&mut self) {
        if let ActionType::Toggle {
            selected: ref mut s,
        } = self.action_type
        {
            *s = !*s;
        }
    }

    /// Return the child actions if this is a menu action.
    pub fn children(&self) -> Option<&[DockingAction]> {
        match &self.action_type {
            ActionType::Menu { items } => Some(items),
            _ => None,
        }
    }

    /// Return mutable child actions if this is a menu action.
    pub fn children_mut(&mut self) -> Option<&mut Vec<DockingAction>> {
        match &mut self.action_type {
            ActionType::Menu { items } => Some(items),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers for working with action trees
// ---------------------------------------------------------------------------

/// Flatten a tree of actions (including sub-menus) into a depth-first
/// sequence.
pub fn flatten_actions(actions: &[DockingAction]) -> Vec<&DockingAction> {
    let mut out = Vec::new();
    for action in actions {
        out.push(action);
        if let ActionType::Menu { items } = &action.action_type {
            out.extend(flatten_actions(items));
        }
    }
    out
}

/// Find an action by name in a possibly-recursive action list.
pub fn find_action<'a>(actions: &'a [DockingAction], name: &str) -> Option<&'a DockingAction> {
    for action in actions {
        if action.name == name {
            return Some(action);
        }
        if let ActionType::Menu { items } = &action.action_type {
            if let found @ Some(_) = find_action(items, name) {
                return found;
            }
        }
    }
    None
}

/// Find a mutable reference to an action by name.
pub fn find_action_mut<'a>(
    actions: &'a mut [DockingAction],
    name: &str,
) -> Option<&'a mut DockingAction> {
    for action in actions.iter_mut() {
        if action.name == name {
            return Some(action);
        }
        if let ActionType::Menu { items } = &mut action.action_type {
            if let found @ Some(_) = find_action_mut(items, name) {
                return found;
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_display() {
        assert_eq!(Key::F5.to_string(), "F5");
        assert_eq!(Key::Enter.to_string(), "Enter");
        assert_eq!(Key::A.to_string(), "A");
    }

    #[test]
    fn test_modifiers_display() {
        assert_eq!(Modifiers::NONE.to_string(), "(none)");
        assert_eq!(Modifiers::CTRL.to_string(), "Ctrl");
        assert_eq!(Modifiers::new(true, false, true).to_string(), "Ctrl+Shift");
        assert_eq!(
            Modifiers::new(true, true, true).to_string(),
            "Ctrl+Alt+Shift"
        );
    }

    #[test]
    fn test_keybinding_display() {
        let kb = KeyBinding::ctrl(Key::S);
        assert_eq!(kb.to_string(), "Ctrl+S");
        let kb = KeyBinding::plain(Key::F5);
        assert_eq!(kb.to_string(), "F5");
    }

    #[test]
    fn test_action_builder() {
        let action = DockingAction::new("my-action", "My Action")
            .with_description("Does something useful")
            .with_key_binding(KeyBinding::ctrl(Key::A))
            .with_menu_path(vec!["Edit".into(), "Advanced".into()])
            .with_icon("icon/my-action.png");

        assert_eq!(action.name, "my-action");
        assert_eq!(action.display_name, "My Action");
        assert!(action.key_binding.is_some());
        assert_eq!(action.menu_path.len(), 2);
    }

    #[test]
    fn test_toggle_action() {
        let mut action = DockingAction::toggle("toggle-thing", "Toggle Thing", true);
        assert!(action.is_selected());
        action.toggle_selection();
        assert!(!action.is_selected());
        action.set_selected(true);
        assert!(action.is_selected());
    }

    #[test]
    fn test_context_matches() {
        assert!(ActionContext::Any.matches(&ActionContext::Program));
        assert!(ActionContext::Any.matches(&ActionContext::Function));
        assert!(ActionContext::Program.matches(&ActionContext::Program));
        assert!(!ActionContext::Program.matches(&ActionContext::Function));
    }

    #[test]
    fn test_is_applicable() {
        let global = DockingAction::new("global", "Global");
        assert!(global.is_applicable(&ActionContext::Program));
        assert!(global.is_applicable(&ActionContext::Any));

        let ctx = DockingAction::contextual("ctx", "Ctx", ActionContext::Function);
        assert!(ctx.is_applicable(&ActionContext::Function));
        assert!(!ctx.is_applicable(&ActionContext::Program));

        let disabled = DockingAction::new("disabled", "Disabled").with_enabled(false);
        assert!(!disabled.is_applicable(&ActionContext::Any));
    }

    #[test]
    fn test_flatten_and_find() {
        let child = DockingAction::new("child", "Child");
        let parent = DockingAction::menu("parent", "Parent", vec![child.clone()]);
        let actions = vec![parent, DockingAction::new("sibling", "Sibling")];

        let flat = flatten_actions(&actions);
        assert_eq!(flat.len(), 3);

        assert!(find_action(&actions, "child").is_some());
        assert!(find_action(&actions, "parent").is_some());
        assert!(find_action(&actions, "sibling").is_some());
        assert!(find_action(&actions, "nope").is_none());

        let mut actions = actions;
        let found = find_action_mut(&mut actions, "child");
        assert!(found.is_some());
        found.unwrap().enabled = false;
        assert!(!find_action(&actions, "child").unwrap().enabled);
    }
}
