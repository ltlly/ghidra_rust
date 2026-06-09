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
// KeyBindingDataPrecedence — determines the priority of key binding dispatch
// ---------------------------------------------------------------------------

/// The precedence level for key binding data, controlling dispatch priority.
///
/// Port of Ghidra's `docking.KeyBindingPrecedence` as used by
/// `KeyBindingData`.  Actions with higher precedence are checked first
/// when dispatching key strokes.  This is distinct from the
/// [`super::keybinding::KeyBindingPrecedence`] which controls action-level
/// dispatch ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub enum KeyBindingDataPrecedence {
    /// Default precedence for user-defined key bindings.
    #[default]
    DefaultLevel,
    /// Active window precedence — key bindings in the active window are
    /// checked before default ones.
    ActiveWindowLevel,
    /// System actions level — reserved keybindings that cannot be changed
    /// by the user and have the highest precedence.
    SystemActionsLevel,
}

impl KeyBindingDataPrecedence {
    /// Returns `true` if this precedence supports user-assigned key bindings.
    ///
    /// `SystemActionsLevel` key bindings cannot be set by the user.
    pub fn supports_user_key_bindings(&self) -> bool {
        !matches!(self, KeyBindingDataPrecedence::SystemActionsLevel)
    }
}

impl fmt::Display for KeyBindingDataPrecedence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyBindingDataPrecedence::DefaultLevel => write!(f, "DefaultLevel"),
            KeyBindingDataPrecedence::ActiveWindowLevel => write!(f, "ActiveWindowLevel"),
            KeyBindingDataPrecedence::SystemActionsLevel => write!(f, "SystemActionsLevel"),
        }
    }
}

// ---------------------------------------------------------------------------
// KeyBindingData — stores key stroke and/or mouse binding for an action
// ---------------------------------------------------------------------------

/// Data for an action's key stroke and/or mouse binding.
///
/// Port of Ghidra's `docking.action.KeyBindingData`.  Stores a key binding
/// along with its precedence level and an optional mouse binding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyBindingData {
    /// The key binding (modifiers + key).
    pub key_binding: KeyBinding,
    /// The precedence level for this key binding.
    pub precedence: KeyBindingDataPrecedence,
    /// Optional mouse binding identifier (for gesture-based actions).
    pub mouse_binding: Option<String>,
}

impl KeyBindingData {
    /// Create a key binding data with default precedence.
    pub fn new(key_binding: KeyBinding) -> Self {
        Self {
            key_binding,
            precedence: KeyBindingDataPrecedence::DefaultLevel,
            mouse_binding: None,
        }
    }

    /// Create a key binding data with a specific precedence.
    pub fn with_precedence(key_binding: KeyBinding, precedence: KeyBindingDataPrecedence) -> Self {
        Self {
            key_binding,
            precedence,
            mouse_binding: None,
        }
    }

    /// Create a system-level key binding that cannot be changed by the user.
    ///
    /// Port of Ghidra's `KeyBindingData.createSystemKeyBindingData`.
    pub fn system(key_binding: KeyBinding) -> Self {
        Self {
            key_binding,
            precedence: KeyBindingDataPrecedence::SystemActionsLevel,
            mouse_binding: None,
        }
    }

    /// Set a mouse binding identifier.
    pub fn with_mouse_binding(mut self, binding: impl Into<String>) -> Self {
        self.mouse_binding = Some(binding.into());
        self
    }

    /// Whether this key binding can be changed by the user.
    pub fn supports_user_changes(&self) -> bool {
        self.precedence.supports_user_key_bindings()
    }
}

impl fmt::Display for KeyBindingData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KeyBindingData[key={}, precedence={}]",
            self.key_binding, self.precedence
        )
    }
}

// ---------------------------------------------------------------------------
// KeyBindingType — controls key binding support per action
// ---------------------------------------------------------------------------

/// Controls whether and how an action supports key bindings.
///
/// Port of Ghidra's `KeyBindingType` enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum KeyBindingType {
    /// The action has its own individual key binding (default).
    #[default]
    Individual,
    /// The action shares a key binding (e.g. multiple providers can each
    /// have the same shortcut).
    Shared,
    /// The action does not support key bindings at all.
    Unsupported,
}

impl KeyBindingType {
    /// Returns `true` if this type supports user-assigned key bindings.
    pub fn supports_key_bindings(&self) -> bool {
        matches!(self, KeyBindingType::Individual | KeyBindingType::Shared)
    }
}

// ---------------------------------------------------------------------------
// MenuBarData / PopupMenuData / ToolBarData — action presentation metadata
// ---------------------------------------------------------------------------

/// Data for placing an action in a menu bar.
///
/// Port of Ghidra's `MenuBarData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MenuBarData {
    /// Menu path hierarchy, e.g. `["File", "Export"]`.
    pub menu_path: Vec<String>,
    /// The menu item name (last element of path if not overridden).
    pub menu_item_name: Option<String>,
    /// Icon identifier for the menu item.
    pub icon: Option<String>,
    /// Group for ordering within the menu level.
    pub group: String,
    /// Sub-group for finer ordering.
    pub sub_group: String,
    /// Mnemonic character (e.g. 'F' for File).
    pub mnemonic: Option<char>,
}

impl MenuBarData {
    /// Create new menu bar data with a path.
    pub fn new(menu_path: Vec<String>) -> Self {
        Self {
            menu_path,
            menu_item_name: None,
            icon: None,
            group: String::new(),
            sub_group: String::new(),
            mnemonic: None,
        }
    }

    /// Create with a simple single-level path.
    pub fn simple(name: impl Into<String>) -> Self {
        Self::new(vec![name.into()])
    }

    /// The effective display name for the menu item.
    pub fn effective_name(&self) -> &str {
        self.menu_item_name
            .as_deref()
            .or_else(|| self.menu_path.last().map(|s| s.as_str()))
            .unwrap_or("")
    }

    /// The full menu path as a joined string.
    pub fn path_string(&self) -> String {
        self.menu_path.join(" > ")
    }
}

/// Data for placing an action in a popup (context) menu.
///
/// Port of Ghidra's `PopupMenuData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PopupMenuData {
    /// Menu path hierarchy.
    pub menu_path: Vec<String>,
    /// The menu item name.
    pub menu_item_name: Option<String>,
    /// Icon identifier.
    pub icon: Option<String>,
    /// Group for ordering.
    pub group: String,
    /// Sub-group for finer ordering.
    pub sub_group: String,
}

impl PopupMenuData {
    /// Create new popup menu data with a path.
    pub fn new(menu_path: Vec<String>) -> Self {
        Self {
            menu_path,
            menu_item_name: None,
            icon: None,
            group: String::new(),
            sub_group: String::new(),
        }
    }

    /// The effective display name for the menu item.
    pub fn effective_name(&self) -> &str {
        self.menu_item_name
            .as_deref()
            .or_else(|| self.menu_path.last().map(|s| s.as_str()))
            .unwrap_or("")
    }

    /// The full menu path as a joined string.
    pub fn path_string(&self) -> String {
        self.menu_path.join(" > ")
    }
}

/// Data for placing an action on a toolbar.
///
/// Port of Ghidra's `ToolBarData`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolBarData {
    /// Icon identifier for the toolbar button.
    pub icon: String,
    /// The toolbar group this action belongs to.
    pub group: String,
    /// Sub-group for finer ordering within the group.
    pub sub_group: String,
}

impl ToolBarData {
    /// Create new toolbar data with an icon.
    pub fn new(icon: impl Into<String>) -> Self {
        Self {
            icon: icon.into(),
            group: String::new(),
            sub_group: String::new(),
        }
    }

    /// Set the toolbar group.
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = group.into();
        self
    }

    /// Set the sub-group.
    pub fn with_sub_group(mut self, sub_group: impl Into<String>) -> Self {
        self.sub_group = sub_group.into();
        self
    }
}

// ---------------------------------------------------------------------------
// Property change event
// ---------------------------------------------------------------------------

/// Well-known property names that can change on a `DockingAction`.
///
/// Port of Ghidra's property name constants on `DockingActionIf`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ActionProperty {
    /// The enabled state changed.
    Enabled,
    /// The key binding data changed.
    KeyBindingData,
    /// The menu bar data changed.
    MenuBarData,
    /// The popup menu data changed.
    PopupMenuData,
    /// The toolbar data changed.
    ToolBarData,
    /// The description changed.
    Description,
    /// The global context changed.
    GlobalContext,
    /// A custom property name.
    Custom(String),
}

impl fmt::Display for ActionProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActionProperty::Enabled => write!(f, "enabled"),
            ActionProperty::KeyBindingData => write!(f, "KeyBindingData"),
            ActionProperty::MenuBarData => write!(f, "MenuBarData"),
            ActionProperty::PopupMenuData => write!(f, "PopupMenuData"),
            ActionProperty::ToolBarData => write!(f, "ToolBarData"),
            ActionProperty::Description => write!(f, "description"),
            ActionProperty::GlobalContext => write!(f, "globalContext"),
            ActionProperty::Custom(name) => write!(f, "{}", name),
        }
    }
}

/// A property change event fired by a `DockingAction`.
///
/// Port of `java.beans.PropertyChangeEvent` usage in Ghidra's
/// `DockingAction.firePropertyChanged`.
#[derive(Debug, Clone)]
pub struct ActionPropertyChangeEvent {
    /// The property that changed.
    pub property: ActionProperty,
    /// The old value (as a string representation).
    pub old_value: Option<String>,
    /// The new value (as a string representation).
    pub new_value: Option<String>,
}

/// A callback that receives property change events from an action.
pub struct PropertyChangeCallback(Arc<dyn Fn(&ActionPropertyChangeEvent) + Send + Sync>);

impl PropertyChangeCallback {
    /// Wrap a closure into a property change callback.
    pub fn new<F: Fn(&ActionPropertyChangeEvent) + Send + Sync + 'static>(f: F) -> Self {
        Self(Arc::new(f))
    }

    /// Invoke the callback with the given event.
    pub fn invoke(&self, event: &ActionPropertyChangeEvent) {
        (self.0)(event)
    }
}

impl fmt::Debug for PropertyChangeCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PropertyChangeCallback").finish()
    }
}

impl Clone for PropertyChangeCallback {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

// ---------------------------------------------------------------------------
// DockingAction
// ---------------------------------------------------------------------------

/// A named, optionally-keybound action that can appear in menus, toolbars,
/// and popup (context) menus.
///
/// Port of Ghidra's `docking.action.DockingAction` abstract class.
#[derive(Clone)]
pub struct DockingAction {
    /// Programmatic identifier (used for lookup and serialization).
    pub name: String,
    /// The owner of this action (typically a plugin name).
    pub owner: String,
    /// Human-readable label shown in menus and toolbars.
    pub display_name: String,
    /// Longer help text / tooltip.
    pub description: String,
    /// Optional keyboard shortcut.
    pub key_binding: Option<KeyBinding>,
    /// Controls key binding support for this action.
    pub key_binding_type: KeyBindingType,
    /// Menu path hierarchy, e.g. `["File", "Export"]`.
    pub menu_path: Vec<String>,
    /// Optional icon identifier (resource name or path).
    pub icon: Option<String>,
    /// Whether the action is currently enabled.
    pub enabled: bool,
    /// Global / contextual / toggle / sub-menu.
    pub action_type: ActionType,
    /// Optional callback invoked when the action is triggered.
    pub callback: Option<ActionCallback>,
    /// Optional context-aware callback (receives current address,
    /// selection, function, etc.).
    pub context_callback: Option<ContextActionCallback>,
    /// Menu bar data for placing the action in the tool's menu bar.
    pub menu_bar_data: Option<MenuBarData>,
    /// Popup menu data for placing the action in context menus.
    pub popup_menu_data: Option<PopupMenuData>,
    /// Toolbar data for placing the action on the toolbar.
    pub tool_bar_data: Option<ToolBarData>,
    /// Dynamic predicate for enabled state (evaluated against context).
    enabled_predicate: Option<Arc<dyn Fn(&ActionContextInfo) -> bool + Send + Sync>>,
    /// Dynamic predicate for popup inclusion.
    popup_predicate: Option<Arc<dyn Fn(&ActionContextInfo) -> bool + Send + Sync>>,
    /// Dynamic predicate for valid context.
    valid_context_predicate: Option<Arc<dyn Fn(&ActionContextInfo) -> bool + Send + Sync>>,
    /// Property change listeners.
    property_listeners: Vec<PropertyChangeCallback>,
    /// Help location identifier.
    pub help_location: Option<String>,
    /// The context class name this action operates on.
    ///
    /// Port of Ghidra's `DockingAction.getContextClass()`.  When set, the
    /// action can work with a specific `ActionContext` subclass.
    pub context_class: Option<String>,
    /// Whether this action supports default context.
    ///
    /// Port of Ghidra's `DockingAction.supportsDefaultContext()`.  When true,
    /// the action can operate on a default context if the active (focused)
    /// provider's context is not valid for this action.
    pub supports_default_context: bool,
    /// Optional owner description (defaults to owner name if not set).
    ///
    /// Port of Ghidra's `DockingActionIf.getOwnerDescription()`.
    pub owner_description: Option<String>,
    /// Whether this action should be added to all windows (not just the main one).
    ///
    /// Port of Ghidra's `DockingAction.shouldAddToAllWindows`.
    pub add_to_all_windows: bool,
    /// When set, the action is only added to windows that contain providers
    /// producing an `ActionContext` matching this class name.
    ///
    /// Port of Ghidra's `DockingAction.addToWindowWhenContextClass`.
    pub add_to_window_when_context_class: Option<String>,
    /// The default key binding data (set once, not changed by the user).
    ///
    /// Port of Ghidra's `DockingAction.defaultKeyBindingData`.
    pub default_key_binding_data: Option<KeyBindingData>,
    /// The current key binding data (may be changed by the user).
    ///
    /// Port of Ghidra's `DockingAction.keyBindingData`.
    pub key_binding_data: Option<KeyBindingData>,
    /// Inception information — where this action was created (for debugging).
    ///
    /// Port of Ghidra's `DockingAction.inceptionInformation`.
    pub inception_information: Option<String>,
}

impl fmt::Debug for DockingAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DockingAction")
            .field("name", &self.name)
            .field("owner", &self.owner)
            .field("display_name", &self.display_name)
            .field("description", &self.description)
            .field("key_binding", &self.key_binding)
            .field("key_binding_type", &self.key_binding_type)
            .field("menu_path", &self.menu_path)
            .field("icon", &self.icon)
            .field("enabled", &self.enabled)
            .field("action_type", &self.action_type)
            .field("callback", &self.callback)
            .field("context_callback", &self.context_callback)
            .field("menu_bar_data", &self.menu_bar_data)
            .field("popup_menu_data", &self.popup_menu_data)
            .field("tool_bar_data", &self.tool_bar_data)
            .field("enabled_predicate", &self.enabled_predicate.as_ref().map(|_| "<fn>"))
            .field("popup_predicate", &self.popup_predicate.as_ref().map(|_| "<fn>"))
            .field("valid_context_predicate", &self.valid_context_predicate.as_ref().map(|_| "<fn>"))
            .field("help_location", &self.help_location)
            .field("context_class", &self.context_class)
            .field("supports_default_context", &self.supports_default_context)
            .field("owner_description", &self.owner_description)
            .field("add_to_all_windows", &self.add_to_all_windows)
            .field("add_to_window_when_context_class", &self.add_to_window_when_context_class)
            .field("key_binding_data", &self.key_binding_data)
            .field("inception_information", &self.inception_information)
            .finish()
    }
}

// PartialEq must be implemented manually because ActionCallback and closures
// are not comparable. We ignore callback and predicate fields for equality checks.
impl PartialEq for DockingAction {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && self.owner == other.owner
            && self.display_name == other.display_name
            && self.description == other.description
            && self.key_binding == other.key_binding
            && self.key_binding_type == other.key_binding_type
            && self.menu_path == other.menu_path
            && self.icon == other.icon
            && self.enabled == other.enabled
            && self.action_type == other.action_type
            && self.menu_bar_data == other.menu_bar_data
            && self.popup_menu_data == other.popup_menu_data
            && self.tool_bar_data == other.tool_bar_data
            && self.help_location == other.help_location
            && self.context_class == other.context_class
            && self.supports_default_context == other.supports_default_context
            && self.owner_description == other.owner_description
            && self.add_to_all_windows == other.add_to_all_windows
            && self.add_to_window_when_context_class == other.add_to_window_when_context_class
            && self.key_binding_data == other.key_binding_data
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
            owner: String::new(),
            display_name: display_name.into(),
            description: String::new(),
            key_binding: None,
            key_binding_type: KeyBindingType::Individual,
            menu_path: Vec::new(),
            icon: None,
            enabled: true,
            action_type: ActionType::Global,
            callback: None,
            context_callback: None,
            menu_bar_data: None,
            popup_menu_data: None,
            tool_bar_data: None,
            enabled_predicate: None,
            popup_predicate: None,
            valid_context_predicate: None,
            property_listeners: Vec::new(),
            help_location: None,
            context_class: None,
            supports_default_context: false,
            owner_description: None,
            add_to_all_windows: false,
            add_to_window_when_context_class: None,
            default_key_binding_data: None,
            key_binding_data: None,
            inception_information: None,
        }
    }

    /// Create a global action with an owner.
    pub fn with_owner(
        name: impl Into<String>,
        owner: impl Into<String>,
        display_name: impl Into<String>,
    ) -> Self {
        Self {
            owner: owner.into(),
            ..Self::new(name, display_name)
        }
    }

    /// Create a global action with a specific key binding type.
    pub fn with_key_binding_type(
        name: impl Into<String>,
        owner: impl Into<String>,
        display_name: impl Into<String>,
        key_binding_type: KeyBindingType,
    ) -> Self {
        Self {
            owner: owner.into(),
            key_binding_type,
            ..Self::new(name, display_name)
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

    /// Attach a context-aware callback.
    ///
    /// When triggered via [`GuiActionManager::trigger_with_context`], the
    /// context callback is preferred over the simple callback.
    pub fn with_context_callback(mut self, callback: ContextActionCallback) -> Self {
        self.context_callback = Some(callback);
        self
    }

    /// Assign menu bar data.
    pub fn with_menu_bar_data(mut self, data: MenuBarData) -> Self {
        self.menu_bar_data = Some(data);
        self
    }

    /// Assign popup menu data.
    pub fn with_popup_menu_data(mut self, data: PopupMenuData) -> Self {
        self.popup_menu_data = Some(data);
        self
    }

    /// Assign toolbar data.
    pub fn with_tool_bar_data(mut self, data: ToolBarData) -> Self {
        self.tool_bar_data = Some(data);
        self
    }

    /// Set the owner (plugin name).
    pub fn set_owner(&mut self, owner: impl Into<String>) {
        self.owner = owner.into();
    }

    /// The full name: `"name (owner)"`.
    pub fn full_name(&self) -> String {
        if self.owner.is_empty() {
            self.name.clone()
        } else {
            format!("{} ({})", self.name, self.owner)
        }
    }

    /// Set a dynamic predicate for the enabled state.
    ///
    /// When set, the predicate is evaluated against the current context
    /// info instead of using the static `enabled` flag.
    ///
    /// Port of Ghidra's `DockingAction.enabledWhen(Predicate)`.
    pub fn enabled_when<F: Fn(&ActionContextInfo) -> bool + Send + Sync + 'static>(
        mut self,
        predicate: F,
    ) -> Self {
        self.enabled_predicate = Some(Arc::new(predicate));
        self
    }

    /// Set a dynamic predicate for popup menu inclusion.
    ///
    /// Port of Ghidra's `DockingAction.popupWhen(Predicate)`.
    pub fn popup_when<F: Fn(&ActionContextInfo) -> bool + Send + Sync + 'static>(
        mut self,
        predicate: F,
    ) -> Self {
        self.popup_predicate = Some(Arc::new(predicate));
        self
    }

    /// Set a dynamic predicate for valid context.
    ///
    /// Port of Ghidra's `DockingAction.validContextWhen(Predicate)`.
    pub fn valid_context_when<F: Fn(&ActionContextInfo) -> bool + Send + Sync + 'static>(
        mut self,
        predicate: F,
    ) -> Self {
        self.valid_context_predicate = Some(Arc::new(predicate));
        self
    }

    /// Add a property change listener.
    ///
    /// Port of Ghidra's `DockingAction.addPropertyChangeListener`.
    pub fn add_property_listener(&mut self, listener: PropertyChangeCallback) {
        self.property_listeners.push(listener);
    }

    /// Fire a property change event to all registered listeners.
    pub fn fire_property_changed(
        &self,
        property: ActionProperty,
        old_value: Option<String>,
        new_value: Option<String>,
    ) {
        let event = ActionPropertyChangeEvent {
            property,
            old_value,
            new_value,
        };
        for listener in &self.property_listeners {
            listener.invoke(&event);
        }
    }

    /// Set description and fire a property change event.
    pub fn set_description(&mut self, description: impl Into<String>) {
        let new_desc = description.into();
        if self.description == new_desc {
            return;
        }
        let old = std::mem::replace(&mut self.description, new_desc.clone());
        self.fire_property_changed(ActionProperty::Description, Some(old), Some(new_desc));
    }

    /// Set the menu bar data and fire a property change event.
    pub fn set_menu_bar_data(&mut self, data: Option<MenuBarData>) {
        let old = std::mem::replace(&mut self.menu_bar_data, data.clone());
        self.fire_property_changed(
            ActionProperty::MenuBarData,
            old.map(|d| d.path_string()),
            data.map(|d| d.path_string()),
        );
    }

    /// Set the popup menu data and fire a property change event.
    pub fn set_popup_menu_data(&mut self, data: Option<PopupMenuData>) {
        let old = self.popup_menu_data.take();
        self.fire_property_changed(
            ActionProperty::PopupMenuData,
            old.map(|d| d.effective_name().to_owned()),
            data.as_ref().map(|d| d.effective_name().to_owned()),
        );
        self.popup_menu_data = data;
    }

    /// Set the toolbar data and fire a property change event.
    pub fn set_tool_bar_data(&mut self, data: Option<ToolBarData>) {
        let old = self.tool_bar_data.take();
        self.fire_property_changed(
            ActionProperty::ToolBarData,
            old.map(|d| d.icon),
            data.as_ref().map(|d| d.icon.clone()),
        );
        self.tool_bar_data = data;
    }

    /// Set the help location.
    pub fn set_help_location(&mut self, location: impl Into<String>) {
        self.help_location = Some(location.into());
    }

    /// Set the owner description.
    ///
    /// Port of Ghidra's `DockingActionIf.getOwnerDescription()`.
    pub fn set_owner_description(&mut self, desc: impl Into<String>) {
        self.owner_description = Some(desc.into());
    }

    /// Get the owner description, falling back to the owner name.
    ///
    /// Port of Ghidra's `DockingActionIf.getOwnerDescription()`.
    pub fn owner_description(&self) -> &str {
        self.owner_description
            .as_deref()
            .unwrap_or(&self.owner)
    }

    /// Set the context class this action operates on.
    ///
    /// Port of Ghidra's `DockingAction.setContextClass(Class, boolean)`.
    pub fn set_context_class(
        &mut self,
        class_name: impl Into<String>,
        supports_default: bool,
    ) {
        self.context_class = Some(class_name.into());
        self.supports_default_context = supports_default;
    }

    /// Get the context class name this action operates on.
    ///
    /// Port of Ghidra's `DockingActionIf.getContextClass()`.
    pub fn context_class_name(&self) -> Option<&str> {
        self.context_class.as_deref()
    }

    /// Whether this action supports default context.
    ///
    /// Port of Ghidra's `DockingActionIf.supportsDefaultContext()`.
    pub fn supports_default_context(&self) -> bool {
        self.supports_default_context
    }

    /// Whether this action should be added to a window.
    ///
    /// Port of Ghidra's `DockingActionIf.shouldAddToWindow`.
    /// Actions with menu bar or toolbar data are candidates for window
    /// placement; actions without either are popup-only and never added
    /// to a window's top-level chrome.
    pub fn should_add_to_window(&self, is_main_window: bool) -> bool {
        if self.menu_bar_data.is_none() && self.tool_bar_data.is_none() {
            return false;
        }
        is_main_window
    }

    /// Whether this action should be added to a window, considering
    /// the context types of providers currently in that window.
    ///
    /// Port of Ghidra's `DockingActionIf.shouldAddToWindow(boolean, Set<Class<?>>)`.
    /// If this action has a context class set and the window does not contain
    /// any providers that support that context type, the action is not added.
    pub fn should_add_to_window_with_context_types(
        &self,
        is_main_window: bool,
        context_types: &[&str],
    ) -> bool {
        if self.menu_bar_data.is_none() && self.tool_bar_data.is_none() {
            return false;
        }

        // If this action has a specific context class, check that the window
        // contains at least one provider supporting that context type.
        if let Some(ref ctx_class) = self.context_class {
            if !context_types.is_empty()
                && !context_types.iter().any(|ct| ct == ctx_class)
            {
                return false;
            }
        }

        is_main_window || self.context_class.is_none()
    }

    /// Categorize this action into an [`ActionGroup`] based on its
    /// properties (local vs global, menu vs toolbar vs popup).
    ///
    /// This is a helper for the action chooser dialog.
    pub fn categorize(&self, is_local: bool) -> ActionGroup {
        if is_local {
            if self.tool_bar_data.is_some() {
                ActionGroup::LocalToolbar
            } else if self.menu_bar_data.is_some() {
                ActionGroup::LocalMenu
            } else {
                ActionGroup::Popup
            }
        } else if self.tool_bar_data.is_some() {
            ActionGroup::GlobalToolbar
        } else if self.menu_bar_data.is_some() {
            ActionGroup::GlobalMenu
        } else {
            ActionGroup::KeybindingOnly
        }
    }

    /// Whether the action is enabled for the given context.
    ///
    /// If a dynamic `enabled_predicate` has been set, it is evaluated;
    /// otherwise the static `enabled` flag is returned.
    pub fn is_enabled_for_context(&self, ctx: &ActionContextInfo) -> bool {
        if let Some(pred) = &self.enabled_predicate {
            pred(ctx)
        } else {
            self.enabled
        }
    }

    /// Whether the action should appear in a popup for the given context.
    ///
    /// If a dynamic `popup_predicate` has been set, it is evaluated;
    /// otherwise falls back to `is_enabled_for_context`.
    pub fn is_add_to_popup(&self, ctx: &ActionContextInfo) -> bool {
        if let Some(pred) = &self.popup_predicate {
            pred(ctx)
        } else {
            self.is_enabled_for_context(ctx)
        }
    }

    /// Whether the action is valid for the given context.
    ///
    /// If a dynamic `valid_context_predicate` has been set, it is evaluated;
    /// otherwise returns `true`.
    pub fn is_valid_context(&self, ctx: &ActionContextInfo) -> bool {
        if let Some(pred) = &self.valid_context_predicate {
            pred(ctx)
        } else {
            true
        }
    }

    // ---------------------------------------------------------------
    // addToWindowWhen / setAddToAllWindows
    // ---------------------------------------------------------------

    /// Set the context class that determines which windows this action
    /// should be added to.
    ///
    /// When set, the action is only added to windows that contain providers
    /// capable of producing an `ActionContext` matching the given class name.
    ///
    /// Port of Ghidra's `DockingAction.addToWindowWhen(Class)`.
    pub fn add_to_window_when(mut self, context_class_name: impl Into<String>) -> Self {
        self.add_to_window_when_context_class = Some(context_class_name.into());
        self
    }

    /// Signal that this action should appear on all windows, not just
    /// the main window.
    ///
    /// Port of Ghidra's `DockingAction.setAddToAllWindows(boolean)`.
    pub fn set_add_to_all_windows(&mut self, add: bool) {
        self.add_to_all_windows = add;
    }

    // ---------------------------------------------------------------
    // Key binding data
    // ---------------------------------------------------------------

    /// Set the key binding data (with validation).
    ///
    /// Port of Ghidra's `DockingAction.setKeyBindingData`.
    pub fn set_key_binding_data(&mut self, data: Option<KeyBindingData>) {
        if let Some(ref d) = data {
            if !d.precedence.supports_user_key_bindings() {
                return; // cannot set system-level via this method
            }
        }
        let old = self.key_binding_data.clone();
        self.key_binding_data = data.clone();
        if self.default_key_binding_data.is_none() {
            self.default_key_binding_data = data;
        }
        self.fire_property_changed(
            ActionProperty::KeyBindingData,
            old.map(|d| d.to_string()),
            self.key_binding_data.as_ref().map(|d| d.to_string()),
        );
    }

    /// Set the key binding data without validation (for framework use).
    ///
    /// Port of Ghidra's `DockingAction.setUnvalidatedKeyBindingData`.
    pub fn set_unvalidated_key_binding_data(&mut self, data: Option<KeyBindingData>) {
        let old = self.key_binding_data.clone();
        self.key_binding_data = data;
        self.fire_property_changed(
            ActionProperty::KeyBindingData,
            old.map(|d| d.to_string()),
            self.key_binding_data.as_ref().map(|d| d.to_string()),
        );
    }

    /// Get the current key binding data.
    ///
    /// Port of Ghidra's `DockingActionIf.getKeyBindingData()`.
    pub fn get_key_binding_data(&self) -> Option<&KeyBindingData> {
        self.key_binding_data.as_ref()
    }

    /// Get the default key binding data.
    ///
    /// Port of Ghidra's `DockingActionIf.getDefaultKeyBindingData()`.
    pub fn get_default_key_binding_data(&self) -> Option<&KeyBindingData> {
        self.default_key_binding_data.as_ref()
    }

    // ---------------------------------------------------------------
    // Inception tracking
    // ---------------------------------------------------------------

    /// Set inception information (source location where this action was created).
    ///
    /// Port of Ghidra's `DockingAction.recordInception()`.
    pub fn set_inception_information(&mut self, info: impl Into<String>) {
        self.inception_information = Some(info.into());
    }

    /// Get inception information.
    ///
    /// Port of Ghidra's `DockingActionIf.getInceptionInformation()`.
    pub fn get_inception_information(&self) -> Option<&str> {
        self.inception_information.as_deref()
    }

    /// Generate a help info string summarizing this action's configuration.
    ///
    /// Port of Ghidra's `DockingAction.getHelpInfo()`.
    pub fn get_help_info(&self) -> String {
        let mut buf = String::new();
        buf.push_str(&format!("   ACTION:    {} - {}\n", self.owner, self.name));

        if let Some(ref menu_data) = self.menu_bar_data {
            buf.push_str(&format!(
                "        MENU PATH:           {}\n",
                menu_data.path_string()
            ));
            buf.push_str(&format!(
                "        MENU GROUP:        {}\n",
                menu_data.group
            ));
            if !menu_data.sub_group.is_empty() {
                buf.push_str(&format!(
                    "        MENU SUB-GROUP:        {}\n",
                    menu_data.sub_group
                ));
            }
            if let Some(ref mnemonic) = menu_data.mnemonic {
                buf.push_str(&format!("        MENU MNEMONIC:     {}\n", mnemonic));
            }
        }

        if let Some(ref popup_data) = self.popup_menu_data {
            buf.push_str(&format!(
                "        POPUP PATH:         {}\n",
                popup_data.path_string()
            ));
            buf.push_str(&format!(
                "        POPUP GROUP:      {}\n",
                popup_data.group
            ));
            if !popup_data.sub_group.is_empty() {
                buf.push_str(&format!(
                    "        POPUP SUB-GROUP:         {}\n",
                    popup_data.sub_group
                ));
            }
        }

        if let Some(ref tb_data) = self.tool_bar_data {
            buf.push_str(&format!(
                "        TOOLBAR GROUP:  {}\n",
                tb_data.group
            ));
            buf.push_str(&format!(
                "        TOOLBAR ICON:     {}\n",
                tb_data.icon
            ));
        }

        if let Some(ref kb) = self.key_binding {
            buf.push_str(&format!("        KEYBINDING:          {}\n", kb));
        }

        if let Some(ref inception) = self.inception_information {
            buf.push_str("\n    \n");
            buf.push_str(&format!("   CREATED AT: {}\n", inception));
            buf.push_str("    ");
        }

        buf
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
// ActionContextInfo — structured context passed to context-aware actions
// ---------------------------------------------------------------------------

/// Structured context information passed to context-aware action callbacks.
///
/// Ghidra's `ActionContext` carries the address, program, function, and
/// selection state that an action needs to operate.  This Rust equivalent
/// provides the same information in a serializable struct.
#[derive(Debug, Clone)]
pub struct ActionContextInfo {
    /// The address under the cursor, if any.
    pub address: Option<String>,
    /// The name/path of the currently active program.
    pub program: Option<String>,
    /// The name of the currently active function, if any.
    pub function: Option<String>,
    /// The selected address range (start, end), if a selection is active.
    pub selection: Option<(String, String)>,
    /// The component provider that initiated the action.
    pub source_provider: Option<String>,
}

impl ActionContextInfo {
    /// Create an empty context.
    pub fn empty() -> Self {
        Self {
            address: None,
            program: None,
            function: None,
            selection: None,
            source_provider: None,
        }
    }

    /// Create a context with an address.
    pub fn with_address(addr: impl Into<String>) -> Self {
        Self {
            address: Some(addr.into()),
            ..Self::empty()
        }
    }

    /// Whether there is an active program.
    pub fn has_program(&self) -> bool {
        self.program.is_some()
    }

    /// Whether there is an active function context.
    pub fn has_function(&self) -> bool {
        self.function.is_some()
    }

    /// Whether there is a selection.
    pub fn has_selection(&self) -> bool {
        self.selection.is_some()
    }

    /// Whether there is an address context.
    pub fn has_address(&self) -> bool {
        self.address.is_some()
    }

    /// Build a builder for this context.
    pub fn builder() -> ActionContextInfoBuilder {
        ActionContextInfoBuilder::default()
    }
}

impl Default for ActionContextInfo {
    fn default() -> Self {
        Self::empty()
    }
}

/// Builder for [`ActionContextInfo`].
#[derive(Debug, Default)]
pub struct ActionContextInfoBuilder {
    inner: ActionContextInfo,
}

impl ActionContextInfoBuilder {
    pub fn address(mut self, addr: impl Into<String>) -> Self {
        self.inner.address = Some(addr.into());
        self
    }

    pub fn program(mut self, program: impl Into<String>) -> Self {
        self.inner.program = Some(program.into());
        self
    }

    pub fn function(mut self, function: impl Into<String>) -> Self {
        self.inner.function = Some(function.into());
        self
    }

    pub fn selection(mut self, start: impl Into<String>, end: impl Into<String>) -> Self {
        self.inner.selection = Some((start.into(), end.into()));
        self
    }

    pub fn source_provider(mut self, provider: impl Into<String>) -> Self {
        self.inner.source_provider = Some(provider.into());
        self
    }

    pub fn build(self) -> ActionContextInfo {
        self.inner
    }
}

// ---------------------------------------------------------------------------
// ContextActionCallback — context-aware closure for actions
// ---------------------------------------------------------------------------

/// A context-aware callback that receives [`ActionContextInfo`].
///
/// This complements the simple [`ActionCallback`] for actions that need
/// to know the current address, selection, function, etc.
pub struct ContextActionCallback(Arc<dyn Fn(&ActionContextInfo) + Send + Sync>);

impl ContextActionCallback {
    /// Wrap a context-aware closure.
    pub fn new<F: Fn(&ActionContextInfo) + Send + Sync + 'static>(f: F) -> Self {
        Self(Arc::new(f))
    }

    /// Invoke with the given context.
    pub fn invoke(&self, ctx: &ActionContextInfo) {
        (self.0)(ctx)
    }
}

impl fmt::Debug for ContextActionCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContextActionCallback").finish()
    }
}

impl Clone for ContextActionCallback {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

// ---------------------------------------------------------------------------
// GuiActionManager — action registry with undo/redo support
// ---------------------------------------------------------------------------

/// An entry in the undo stack.
#[derive(Clone)]
pub struct UndoEntry {
    /// Human-readable description (e.g. "Rename function").
    pub description: String,
    /// Closure that performs the undo operation.
    pub undo: ActionCallback,
    /// Closure that re-applies the operation (used for redo).
    pub redo: ActionCallback,
}

impl fmt::Debug for UndoEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UndoEntry")
            .field("description", &self.description)
            .finish()
    }
}

/// Action manager with undo/redo support and an action registry.
///
/// Ghidra's `ActionManager` owns the set of registered actions, handles
/// keyboard dispatch, and provides undo/redo through the tool's
/// transaction system.  This Rust equivalent provides the same core
/// functionality.
#[derive(Debug, Default)]
pub struct GuiActionManager {
    /// All registered actions.
    actions: Vec<DockingAction>,
    /// Undo stack (last entry = most recent).
    undo_stack: Vec<UndoEntry>,
    /// Redo stack.
    redo_stack: Vec<UndoEntry>,
    /// Maximum undo depth (0 = unlimited).
    max_undo_depth: usize,
}

impl GuiActionManager {
    /// Create a new, empty action manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of undo entries kept.
    pub fn with_max_undo_depth(mut self, depth: usize) -> Self {
        self.max_undo_depth = depth;
        self
    }

    // ---------------------------------------------------------------
    // Action registration
    // ---------------------------------------------------------------

    /// Register an action.
    pub fn register(&mut self, action: DockingAction) {
        self.actions.push(action);
    }

    /// Register multiple actions.
    pub fn register_all(&mut self, actions: Vec<DockingAction>) {
        self.actions.extend(actions);
    }

    /// Remove an action by name.
    pub fn unregister(&mut self, name: &str) -> Option<DockingAction> {
        let pos = self.actions.iter().position(|a| a.name == name);
        pos.map(|idx| self.actions.remove(idx))
    }

    /// Look up an action by name.
    pub fn get(&self, name: &str) -> Option<&DockingAction> {
        self.actions.iter().find(|a| a.name == name)
    }

    /// Look up a mutable action by name.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut DockingAction> {
        self.actions.iter_mut().find(|a| a.name == name)
    }

    /// All registered actions.
    pub fn actions(&self) -> &[DockingAction] {
        &self.actions
    }

    /// Number of registered actions.
    pub fn len(&self) -> usize {
        self.actions.len()
    }

    /// Whether no actions are registered.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// Return all actions applicable in the given context.
    pub fn applicable_actions(&self, context: &ActionContext) -> Vec<&DockingAction> {
        self.actions
            .iter()
            .filter(|a| a.is_applicable(context))
            .collect()
    }

    // ---------------------------------------------------------------
    // Keyboard dispatch
    // ---------------------------------------------------------------

    /// Find and return the action matching a key-stroke.
    pub fn action_for_key(&self, modifiers: &Modifiers, key: &Key) -> Option<&DockingAction> {
        self.actions
            .iter()
            .find(|a| a.matches_key(modifiers, key) && a.enabled)
    }

    /// Trigger an action by name, invoking its callback if present.
    /// Returns `true` if the action was found and invoked.
    pub fn trigger(&self, name: &str) -> bool {
        if let Some(action) = self.get(name) {
            if action.enabled {
                if let Some(cb) = &action.callback {
                    cb.call();
                    return true;
                }
            }
        }
        false
    }

    /// Trigger an action with context, using the context-aware callback
    /// if available, falling back to the simple callback.
    pub fn trigger_with_context(&self, name: &str, ctx: &ActionContextInfo) -> bool {
        if let Some(action) = self.get(name) {
            if action.enabled {
                // Try context-aware callback first.
                if let Some(cb) = &action.context_callback {
                    cb.invoke(ctx);
                    return true;
                }
                // Fall back to simple callback.
                if let Some(cb) = &action.callback {
                    cb.call();
                    return true;
                }
            }
        }
        false
    }

    // ---------------------------------------------------------------
    // Undo / redo
    // ---------------------------------------------------------------

    /// Push an undo entry onto the undo stack.  Clears the redo stack.
    pub fn push_undo(&mut self, entry: UndoEntry) {
        self.undo_stack.push(entry);
        self.redo_stack.clear();
        // Enforce max depth.
        if self.max_undo_depth > 0 && self.undo_stack.len() > self.max_undo_depth {
            self.undo_stack.remove(0);
        }
    }

    /// Perform undo: pops the most recent undo entry, executes it,
    /// and pushes it onto the redo stack.  Returns the description
    /// of the undone operation, or `None` if the stack is empty.
    pub fn undo(&mut self) -> Option<String> {
        let entry = self.undo_stack.pop()?;
        let desc = entry.description.clone();
        entry.undo.call();
        self.redo_stack.push(entry);
        Some(desc)
    }

    /// Perform redo: pops the most recent redo entry, re-applies it,
    /// and pushes it back onto the undo stack.  Returns the description,
    /// or `None` if the stack is empty.
    pub fn redo(&mut self) -> Option<String> {
        let entry = self.redo_stack.pop()?;
        let desc = entry.description.clone();
        entry.redo.call();
        self.undo_stack.push(entry);
        Some(desc)
    }

    /// Whether undo is available.
    pub fn can_undo(&self) -> bool {
        !self.undo_stack.is_empty()
    }

    /// Whether redo is available.
    pub fn can_redo(&self) -> bool {
        !self.redo_stack.is_empty()
    }

    /// Undo description of the next undoable operation.
    pub fn undo_description(&self) -> Option<&str> {
        self.undo_stack.last().map(|e| e.description.as_str())
    }

    /// Redo description of the next redoable operation.
    pub fn redo_description(&self) -> Option<&str> {
        self.redo_stack.last().map(|e| e.description.as_str())
    }

    /// Clear all undo/redo history.
    pub fn clear_history(&mut self) {
        self.undo_stack.clear();
        self.redo_stack.clear();
    }
}

// ---------------------------------------------------------------------------
// ActionDisplayLevel — controls which actions are shown in ActionChooserDialog
// ---------------------------------------------------------------------------

/// An enum for specifying which actions should be displayed in the action
/// chooser dialog. Each successive level is less restrictive and includes
/// more actions to display.
///
/// Port of Ghidra's `docking.actions.dialog.ActionDisplayLevel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ActionDisplayLevel {
    /// All local menu and toolbar actions, all local and global popup
    /// actions with valid context and addToPopup=true, all local and
    /// global keybinding actions that are valid and enabled.
    #[default]
    Local,
    /// Adds local and global actions with a valid context, even if disabled.
    Global,
    /// Adds local and global actions even if invalid context and disabled.
    All,
}

impl ActionDisplayLevel {
    /// Returns the next display level in the cycle: Local -> Global -> All -> Local.
    pub fn next_level(&self) -> Self {
        match self {
            ActionDisplayLevel::Local => ActionDisplayLevel::Global,
            ActionDisplayLevel::Global => ActionDisplayLevel::All,
            ActionDisplayLevel::All => ActionDisplayLevel::Local,
        }
    }

    /// Whether this level includes disabled actions.
    pub fn includes_disabled(&self) -> bool {
        matches!(self, ActionDisplayLevel::Global | ActionDisplayLevel::All)
    }

    /// Whether this level includes actions with invalid context.
    pub fn includes_invalid_context(&self) -> bool {
        matches!(self, ActionDisplayLevel::All)
    }
}

impl fmt::Display for ActionDisplayLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActionDisplayLevel::Local => write!(f, "Local"),
            ActionDisplayLevel::Global => write!(f, "Global"),
            ActionDisplayLevel::All => write!(f, "All"),
        }
    }
}

// ---------------------------------------------------------------------------
// ActionGroup — category groups for the ActionChooserDialog
// ---------------------------------------------------------------------------

/// Defines action category groups. Actions displayed in the action chooser
/// dialog are organized into these groups.
///
/// Port of Ghidra's `docking.actions.dialog.ActionGroup`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ActionGroup {
    /// Actions local to a provider that appear on the toolbar.
    LocalToolbar,
    /// Actions local to a provider that appear in menus.
    LocalMenu,
    /// Actions that appear in popup (context) menus.
    Popup,
    /// Actions that only have key bindings (no menu/toolbar presence).
    KeybindingOnly,
    /// Global actions that appear on the toolbar.
    GlobalToolbar,
    /// Global actions that appear in menus.
    GlobalMenu,
}

impl ActionGroup {
    /// Returns the human-readable display name for the group.
    pub fn display_name(&self) -> &'static str {
        match self {
            ActionGroup::LocalToolbar => "Local Toolbar",
            ActionGroup::LocalMenu => "Local Menu",
            ActionGroup::Popup => "Popup Menu",
            ActionGroup::KeybindingOnly => "Keybinding Only",
            ActionGroup::GlobalToolbar => "Global Toolbar",
            ActionGroup::GlobalMenu => "Global Menu",
        }
    }

    /// Find the group that has the given display name.
    pub fn from_display_name(name: &str) -> Option<Self> {
        match name {
            "Local Toolbar" => Some(ActionGroup::LocalToolbar),
            "Local Menu" => Some(ActionGroup::LocalMenu),
            "Popup Menu" => Some(ActionGroup::Popup),
            "Keybinding Only" => Some(ActionGroup::KeybindingOnly),
            "Global Toolbar" => Some(ActionGroup::GlobalToolbar),
            "Global Menu" => Some(ActionGroup::GlobalMenu),
            _ => None,
        }
    }

    /// Whether this group is for local (provider-specific) actions.
    pub fn is_local(&self) -> bool {
        matches!(
            self,
            ActionGroup::LocalToolbar | ActionGroup::LocalMenu
        )
    }

    /// Whether this group is for global actions.
    pub fn is_global(&self) -> bool {
        matches!(
            self,
            ActionGroup::GlobalToolbar | ActionGroup::GlobalMenu
        )
    }

    /// Whether this group is for toolbar actions.
    pub fn is_toolbar(&self) -> bool {
        matches!(
            self,
            ActionGroup::LocalToolbar | ActionGroup::GlobalToolbar
        )
    }

    /// Whether this group is for menu actions.
    pub fn is_menu(&self) -> bool {
        matches!(
            self,
            ActionGroup::LocalMenu | ActionGroup::GlobalMenu
        )
    }
}

impl fmt::Display for ActionGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ---------------------------------------------------------------------------
// Action trait — the Ghidra Action interface
// ---------------------------------------------------------------------------

/// The core action interface for the docking framework.
///
/// Port of Ghidra's `docking.Action` interface.  Every action that appears
/// in a menu, toolbar, or context menu implements this trait.  The single
/// required method is `action_performed(context)` which carries the
/// program state the action needs.
///
/// This trait complements the concrete [`DockingAction`] struct.  Use
/// `DockingAction` for simple callback-based actions; implement this
/// trait for richer action types (proxies, scripted actions, etc.).
pub trait Action: fmt::Debug + Send + Sync {
    /// The programmatic name of the action (used for lookup, serialization).
    fn name(&self) -> &str;

    /// Human-readable display name shown in menus and toolbars.
    fn display_name(&self) -> &str;

    /// Longer description / tooltip text.
    fn description(&self) -> &str {
        ""
    }

    /// Whether the action is currently enabled.
    fn is_enabled(&self) -> bool {
        true
    }

    /// Enable or disable the action.
    fn set_enabled(&mut self, _enabled: bool) {}

    /// Whether the action supports the given context.
    ///
    /// Called by the framework before presenting the action in a context
    /// menu.  Return `false` to hide the action.
    fn is_valid_context(&self, _context: &super::action_context::DockingActionContext) -> bool {
        true
    }

    /// Execute the action with the given context.
    ///
    /// This is the primary entry point called when the user triggers the
    /// action (via menu click, toolbar button, or keyboard shortcut).
    fn action_performed(&self, context: &super::action_context::DockingActionContext);

    /// The component provider this action is associated with, if any.
    ///
    /// Global actions return `None`; local actions return the provider
    /// they belong to.
    fn owner_provider(&self) -> Option<super::component::ComponentProvider> {
        None
    }

    /// Whether this action is a toggle (two-state) action.
    fn is_toggle(&self) -> bool {
        false
    }

    /// For toggle actions, the current selected state.
    fn is_selected(&self) -> bool {
        false
    }

    /// For toggle actions, set the selected state.
    fn set_selected(&mut self, _selected: bool) {}

    /// Whether this action is a menu (has child actions).
    fn is_menu(&self) -> bool {
        false
    }

    /// Child actions if this is a menu action.
    fn children(&self) -> Vec<&dyn Action> {
        Vec::new()
    }

    /// Whether this action can be added to a popup (context) menu.
    fn is_add_to_popup(&self, context: &super::action_context::DockingActionContext) -> bool {
        self.is_valid_context(context)
    }

    /// Menu path hierarchy for positioning in the menu bar.
    fn menu_path(&self) -> &[&str] {
        &[]
    }

    /// The menu bar group this action belongs to (for ordering).
    fn menu_bar_group(&self) -> &str {
        ""
    }

    /// Priority within the menu bar group (lower = earlier).
    fn menu_bar_priority(&self) -> u32 {
        100
    }

    /// Whether this action should be disposed when its owner component is
    /// disposed.
    fn dispose_on_owner_dispose(&self) -> bool {
        true
    }

    /// Clean up resources when the action is no longer needed.
    fn dispose(&self) {}
}

/// Extension trait for actions that support keyboard shortcuts.
pub trait KeyBindableAction: Action {
    /// The key binding for this action, if any.
    fn key_binding(&self) -> Option<KeyBinding>;

    /// Whether this action matches the given key-stroke.
    fn matches_key(&self, modifiers: &Modifiers, key: &Key) -> bool {
        self.key_binding()
            .as_ref()
            .map(|kb| &kb.modifiers == modifiers && &kb.key == key)
            .unwrap_or(false)
    }
}

/// Extension trait for toggle (two-state) actions.
pub trait ToggleAction: Action {
    /// Get the current toggle state.
    fn toggle_state(&self) -> bool;

    /// Set the toggle state.
    fn set_toggle_state(&mut self, selected: bool);

    /// Flip the toggle state.
    fn toggle(&mut self) {
        let current = self.toggle_state();
        self.set_toggle_state(!current);
    }
}

// ---------------------------------------------------------------------------
// ComponentBasedDockingAction — action local to a specific component
// ---------------------------------------------------------------------------

/// An action that is local to a specific UI component, rather than
/// being global or provider-level.
///
/// Port of Ghidra's `docking.action.ComponentBasedDockingAction` interface.
/// Standard docking actions are either global tool-based actions or local
/// `ComponentProvider` actions.  This trait allows actions that are
/// effectively local to a specific component.
pub trait ComponentBasedDockingAction: Action {
    /// Returns `true` if the given context contains this action's component.
    fn is_valid_component_context(&self, context: &super::action_context::DockingActionContext) -> bool;
}

// ---------------------------------------------------------------------------
// ContextSpecificAction — generic action for a specific context type
// ---------------------------------------------------------------------------

/// A convenience wrapper that automatically checks the `ActionContext` type
/// and delegates to type-specific methods.
///
/// Port of Ghidra's `docking.action.ContextSpecificAction<T>`.  This
/// simplifies action logic for actions that work with a specific context
/// type.  It automatically checks the context and disables/invalidates/
/// prevents popup if the context is not the expected type.
///
/// In Rust, since there is no generics-based runtime type checking, this
/// is implemented as a `DockingAction` wrapper with a context class name
/// filter.
pub struct ContextSpecificAction {
    /// The wrapped action.
    pub action: DockingAction,
    /// The required context class name.
    pub required_context_class: String,
}

impl ContextSpecificAction {
    /// Create a new context-specific action wrapping the given action.
    pub fn new(action: DockingAction, context_class: impl Into<String>) -> Self {
        let context_class = context_class.into();
        let mut action = action;
        action.set_context_class(&context_class, false);
        Self {
            action,
            required_context_class: context_class,
        }
    }

    /// Whether the given context matches this action's required type.
    pub fn matches_context(&self, context_class_name: &str) -> bool {
        self.required_context_class == context_class_name
    }

    /// Whether this action is enabled for a context with the given class name
    /// and context info.
    pub fn is_enabled_for_typed_context(
        &self,
        context_class_name: &str,
        ctx: &ActionContextInfo,
    ) -> bool {
        if !self.matches_context(context_class_name) {
            return false;
        }
        self.action.is_enabled_for_context(ctx)
    }

    /// Whether this action is valid for a context with the given class name.
    pub fn is_valid_typed_context(&self, context_class_name: &str) -> bool {
        self.matches_context(context_class_name)
    }

    /// Whether this action should be added to a popup for a typed context.
    pub fn is_add_to_typed_popup(
        &self,
        context_class_name: &str,
        ctx: &ActionContextInfo,
    ) -> bool {
        if !self.matches_context(context_class_name) {
            return false;
        }
        self.action.is_add_to_popup(ctx)
    }
}

impl fmt::Debug for ContextSpecificAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContextSpecificAction")
            .field("action", &self.action)
            .field("required_context_class", &self.required_context_class)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// MultiAction — an action that contains multiple sub-actions
// ---------------------------------------------------------------------------

/// An action that contains multiple sub-actions, all of which are
/// presented together (e.g. in a popup menu or toolbar drop-down).
///
/// Port of Ghidra's `docking.action.MultiActionDockingActionIf` interface.
/// When triggered, all sub-actions are presented to the user.
#[derive(Debug, Clone)]
pub struct MultiAction {
    /// The display name for this multi-action group.
    pub display_name: String,
    /// The owner (plugin) that created this multi-action.
    pub owner: String,
    /// The sub-actions.
    pub actions: Vec<DockingAction>,
}

impl MultiAction {
    /// Create a new multi-action.
    pub fn new(display_name: impl Into<String>, owner: impl Into<String>) -> Self {
        Self {
            display_name: display_name.into(),
            owner: owner.into(),
            actions: Vec::new(),
        }
    }

    /// Add a sub-action.
    pub fn add_action(&mut self, action: DockingAction) {
        self.actions.push(action);
    }

    /// Whether this multi-action has any sub-actions.
    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// The number of sub-actions.
    pub fn len(&self) -> usize {
        self.actions.len()
    }
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

    #[test]
    fn test_action_context_info() {
        let ctx = ActionContextInfo::builder()
            .address("0x100000")
            .program("test.exe")
            .function("main")
            .selection("0x100000", "0x100100")
            .source_provider("ListingView")
            .build();

        assert!(ctx.has_address());
        assert!(ctx.has_program());
        assert!(ctx.has_function());
        assert!(ctx.has_selection());
        assert_eq!(ctx.address.as_deref(), Some("0x100000"));
        assert_eq!(ctx.function.as_deref(), Some("main"));
    }

    #[test]
    fn test_action_context_info_empty() {
        let ctx = ActionContextInfo::empty();
        assert!(!ctx.has_address());
        assert!(!ctx.has_program());
        assert!(!ctx.has_function());
        assert!(!ctx.has_selection());
    }

    #[test]
    fn test_context_action_callback() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let called = Arc::new(AtomicBool::new(false));
        let called2 = called.clone();

        let cb = ContextActionCallback::new(move |_ctx| {
            called2.store(true, Ordering::SeqCst);
        });

        let ctx = ActionContextInfo::with_address("0x1000");
        cb.invoke(&ctx);
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_action_with_context_callback() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let called = Arc::new(AtomicBool::new(false));
        let called2 = called.clone();

        let action = DockingAction::new("test", "Test").with_context_callback(
            ContextActionCallback::new(move |_| {
                called2.store(true, Ordering::SeqCst);
            }),
        );

        assert!(action.context_callback.is_some());
        let ctx = ActionContextInfo::empty();
        action.context_callback.as_ref().unwrap().invoke(&ctx);
        assert!(called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_gui_action_manager_register() {
        let mut mgr = GuiActionManager::new();
        assert!(mgr.is_empty());

        mgr.register(DockingAction::new("a", "A"));
        mgr.register(DockingAction::new("b", "B"));
        assert_eq!(mgr.len(), 2);
        assert!(mgr.get("a").is_some());
        assert!(mgr.get("b").is_some());
        assert!(mgr.get("c").is_none());
    }

    #[test]
    fn test_gui_action_manager_trigger() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let called = Arc::new(AtomicBool::new(false));
        let called2 = called.clone();

        let mut mgr = GuiActionManager::new();
        let action = DockingAction::new("do-it", "Do It").with_callback(ActionCallback::new(
            move || {
                called2.store(true, Ordering::SeqCst);
            },
        ));
        mgr.register(action);

        assert!(mgr.trigger("do-it"));
        assert!(called.load(Ordering::SeqCst));
        assert!(!mgr.trigger("nonexistent"));
    }

    #[test]
    fn test_gui_action_manager_trigger_with_context() {
        use std::sync::atomic::{AtomicU64, Ordering};
        let captured_addr = Arc::new(AtomicU64::new(0));

        let captured2 = captured_addr.clone();
        let action =
            DockingAction::new("goto", "Go To").with_context_callback(
                ContextActionCallback::new(move |ctx| {
                    // Just check that we received context.
                    if ctx.has_address() {
                        captured2.store(1, Ordering::SeqCst);
                    }
                }),
            );

        let mut mgr = GuiActionManager::new();
        mgr.register(action);

        let ctx = ActionContextInfo::with_address("0x100000");
        assert!(mgr.trigger_with_context("goto", &ctx));
        assert_eq!(captured_addr.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_gui_action_manager_undo_redo() {
        use std::sync::atomic::{AtomicI32, Ordering};
        let state = Arc::new(AtomicI32::new(0));

        let mut mgr = GuiActionManager::new();

        let s1 = state.clone();
        let undo = ActionCallback::new(move || {
            s1.store(0, Ordering::SeqCst);
        });
        let s2 = state.clone();
        let redo = ActionCallback::new(move || {
            s2.store(42, Ordering::SeqCst);
        });

        assert!(!mgr.can_undo());
        assert!(!mgr.can_redo());

        mgr.push_undo(UndoEntry {
            description: "Set value to 42".to_owned(),
            undo,
            redo,
        });

        assert!(mgr.can_undo());
        assert!(!mgr.can_redo());
        assert_eq!(mgr.undo_description(), Some("Set value to 42"));

        // Undo.
        let desc = mgr.undo();
        assert_eq!(desc.as_deref(), Some("Set value to 42"));
        assert_eq!(state.load(Ordering::SeqCst), 0);
        assert!(mgr.can_redo());

        // Redo.
        let desc = mgr.redo();
        assert_eq!(desc.as_deref(), Some("Set value to 42"));
        assert_eq!(state.load(Ordering::SeqCst), 42);
        assert!(!mgr.can_redo());
    }

    #[test]
    fn test_gui_action_manager_undo_clears_redo() {
        let mut mgr = GuiActionManager::new();

        let noop = || {};
        mgr.push_undo(UndoEntry {
            description: "first".to_owned(),
            undo: ActionCallback::new(noop),
            redo: ActionCallback::new(noop),
        });
        mgr.undo();
        assert!(mgr.can_redo());

        // Pushing a new undo clears the redo stack.
        mgr.push_undo(UndoEntry {
            description: "second".to_owned(),
            undo: ActionCallback::new(noop),
            redo: ActionCallback::new(noop),
        });
        assert!(!mgr.can_redo());
    }

    #[test]
    fn test_gui_action_manager_applicable_actions() {
        let mut mgr = GuiActionManager::new();
        mgr.register(DockingAction::new("global", "Global"));
        mgr.register(DockingAction::contextual(
            "func-ctx",
            "Func Ctx",
            ActionContext::Function,
        ));
        mgr.register(
            DockingAction::new("disabled", "Disabled").with_enabled(false),
        );

        let applicable = mgr.applicable_actions(&ActionContext::Function);
        assert_eq!(applicable.len(), 2); // global + func-ctx

        let applicable = mgr.applicable_actions(&ActionContext::Program);
        assert_eq!(applicable.len(), 1); // global only
    }

    // -- Action trait tests --

    /// A test implementation of the `Action` trait.
    #[derive(Debug)]
    struct TestTraitAction {
        action_name: String,
        action_display: String,
        enabled: bool,
        invoked: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl TestTraitAction {
        fn new(name: &str, display: &str) -> (Self, std::sync::Arc<std::sync::atomic::AtomicBool>) {
            let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let action = Self {
                action_name: name.to_owned(),
                action_display: display.to_owned(),
                enabled: true,
                invoked: flag.clone(),
            };
            (action, flag)
        }
    }

    impl super::Action for TestTraitAction {
        fn name(&self) -> &str { &self.action_name }
        fn display_name(&self) -> &str { &self.action_display }
        fn is_enabled(&self) -> bool { self.enabled }
        fn set_enabled(&mut self, enabled: bool) { self.enabled = enabled; }
        fn action_performed(&self, _ctx: &super::super::action_context::DockingActionContext) {
            self.invoked.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[test]
    fn test_action_trait_basic() {
        let (action, flag) = TestTraitAction::new("test", "Test Action");
        assert_eq!(action.name(), "test");
        assert_eq!(action.display_name(), "Test Action");
        assert!(action.is_enabled());

        let ctx = super::super::action_context::DockingActionContext::new();
        action.action_performed(&ctx);
        assert!(flag.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_action_trait_defaults() {
        let (action, _flag) = TestTraitAction::new("test", "Test");
        assert!(action.description().is_empty());
        assert!(!action.is_toggle());
        assert!(!action.is_selected());
        assert!(!action.is_menu());
        assert!(action.children().is_empty());
        assert!(action.owner_provider().is_none());
        assert!(action.menu_path().is_empty());
        assert!(action.menu_bar_group().is_empty());
        assert_eq!(action.menu_bar_priority(), 100);
        assert!(action.dispose_on_owner_dispose());
    }

    #[test]
    fn test_action_trait_set_enabled() {
        let (mut action, _flag) = TestTraitAction::new("test", "Test");
        assert!(action.is_enabled());
        action.set_enabled(false);
        assert!(!action.is_enabled());
    }

    // -- New feature tests --

    #[test]
    fn test_key_binding_type() {
        assert!(KeyBindingType::Individual.supports_key_bindings());
        assert!(KeyBindingType::Shared.supports_key_bindings());
        assert!(!KeyBindingType::Unsupported.supports_key_bindings());
    }

    #[test]
    fn test_action_owner() {
        let action =
            DockingAction::with_owner("my-action", "MyPlugin", "My Action");
        assert_eq!(action.owner, "MyPlugin");
        assert_eq!(action.full_name(), "my-action (MyPlugin)");

        let action = DockingAction::new("a", "A");
        assert_eq!(action.owner, "");
        assert_eq!(action.full_name(), "a");
    }

    #[test]
    fn test_action_with_key_binding_type() {
        let action = DockingAction::with_key_binding_type(
            "a",
            "Plugin",
            "Action",
            KeyBindingType::Shared,
        );
        assert_eq!(action.key_binding_type, KeyBindingType::Shared);
    }

    #[test]
    fn test_menu_bar_data() {
        let mut data = MenuBarData::new(vec!["Edit".into(), "Undo".into()]);
        data.group = "EditGroup".into();
        assert_eq!(data.effective_name(), "Undo");
        assert_eq!(data.path_string(), "Edit > Undo");

        let data = MenuBarData::simple("File");
        assert_eq!(data.effective_name(), "File");
    }

    #[test]
    fn test_popup_menu_data() {
        let data = PopupMenuData::new(vec!["Copy".into()]);
        assert_eq!(data.effective_name(), "Copy");
    }

    #[test]
    fn test_toolbar_data() {
        let data = ToolBarData::new("icon/save.png")
            .with_group("File")
            .with_sub_group("primary");
        assert_eq!(data.icon, "icon/save.png");
        assert_eq!(data.group, "File");
    }

    #[test]
    fn test_action_with_menu_bar_data() {
        let data = MenuBarData::new(vec!["Edit".into(), "Undo".into()]);
        let action = DockingAction::new("undo", "Undo").with_menu_bar_data(data);
        assert!(action.menu_bar_data.is_some());
        assert_eq!(
            action.menu_bar_data.as_ref().unwrap().effective_name(),
            "Undo"
        );
    }

    #[test]
    fn test_action_with_tool_bar_data() {
        let data = ToolBarData::new("icon/undo.png");
        let action = DockingAction::new("undo", "Undo").with_tool_bar_data(data);
        assert!(action.tool_bar_data.is_some());
    }

    #[test]
    fn test_should_add_to_window() {
        let action = DockingAction::new("a", "A");
        // No menu bar or toolbar data -> never added to a window.
        assert!(!action.should_add_to_window(true));
        assert!(!action.should_add_to_window(false));

        let action = DockingAction::new("b", "B")
            .with_menu_bar_data(MenuBarData::simple("B"));
        // Has menu bar data -> added to main window.
        assert!(action.should_add_to_window(true));
        // Not added to non-main windows.
        assert!(!action.should_add_to_window(false));
    }

    #[test]
    fn test_enabled_when_predicate() {
        let action = DockingAction::new("a", "A")
            .enabled_when(|ctx| ctx.has_address());
        let ctx_empty = ActionContextInfo::empty();
        let ctx_with_addr = ActionContextInfo::with_address("0x1000");

        assert!(!action.is_enabled_for_context(&ctx_empty));
        assert!(action.is_enabled_for_context(&ctx_with_addr));
    }

    #[test]
    fn test_popup_when_predicate() {
        let action = DockingAction::new("a", "A")
            .popup_when(|ctx| ctx.has_selection());
        let ctx = ActionContextInfo::empty();
        assert!(!action.is_add_to_popup(&ctx));

        let ctx = ActionContextInfo::builder()
            .selection("0x1000", "0x2000")
            .build();
        assert!(action.is_add_to_popup(&ctx));
    }

    #[test]
    fn test_valid_context_when_predicate() {
        let action = DockingAction::new("a", "A")
            .valid_context_when(|ctx| ctx.has_function());
        let ctx = ActionContextInfo::empty();
        assert!(!action.is_valid_context(&ctx));

        let ctx = ActionContextInfo::builder().function("main").build();
        assert!(action.is_valid_context(&ctx));
    }

    #[test]
    fn test_property_change_event() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let fired = Arc::new(AtomicBool::new(false));
        let fired2 = fired.clone();

        let mut action = DockingAction::new("a", "A");
        action.add_property_listener(PropertyChangeCallback::new(move |_evt| {
            fired2.store(true, Ordering::SeqCst);
        }));

        action.set_description("new desc");
        assert!(fired.load(Ordering::SeqCst));
        assert_eq!(action.description, "new desc");
    }

    #[test]
    fn test_set_description_no_change() {
        let mut action = DockingAction::new("a", "A").with_description("desc");
        // Setting the same description should not fire.
        action.set_description("desc");
        assert_eq!(action.description, "desc");
    }

    #[test]
    fn test_full_name_display() {
        let action =
            DockingAction::with_owner("test", "TestPlugin", "Test");
        assert_eq!(action.full_name(), "test (TestPlugin)");
    }

    #[test]
    fn test_action_partial_eq_with_new_fields() {
        let a = DockingAction::new("a", "A")
            .with_menu_bar_data(MenuBarData::simple("A"));
        let b = DockingAction::new("a", "A")
            .with_menu_bar_data(MenuBarData::simple("A"));
        assert_eq!(a, b);

        let c = DockingAction::new("a", "A")
            .with_tool_bar_data(ToolBarData::new("icon.png"));
        assert_ne!(a, c);
    }

    // -- ActionDisplayLevel tests --

    #[test]
    fn test_action_display_level_default() {
        assert_eq!(ActionDisplayLevel::default(), ActionDisplayLevel::Local);
    }

    #[test]
    fn test_action_display_level_next() {
        assert_eq!(
            ActionDisplayLevel::Local.next_level(),
            ActionDisplayLevel::Global
        );
        assert_eq!(
            ActionDisplayLevel::Global.next_level(),
            ActionDisplayLevel::All
        );
        assert_eq!(
            ActionDisplayLevel::All.next_level(),
            ActionDisplayLevel::Local
        );
    }

    #[test]
    fn test_action_display_level_includes_disabled() {
        assert!(!ActionDisplayLevel::Local.includes_disabled());
        assert!(ActionDisplayLevel::Global.includes_disabled());
        assert!(ActionDisplayLevel::All.includes_disabled());
    }

    #[test]
    fn test_action_display_level_includes_invalid_context() {
        assert!(!ActionDisplayLevel::Local.includes_invalid_context());
        assert!(!ActionDisplayLevel::Global.includes_invalid_context());
        assert!(ActionDisplayLevel::All.includes_invalid_context());
    }

    #[test]
    fn test_action_display_level_display() {
        assert_eq!(ActionDisplayLevel::Local.to_string(), "Local");
        assert_eq!(ActionDisplayLevel::Global.to_string(), "Global");
        assert_eq!(ActionDisplayLevel::All.to_string(), "All");
    }

    // -- ActionGroup tests --

    #[test]
    fn test_action_group_display_name() {
        assert_eq!(ActionGroup::LocalToolbar.display_name(), "Local Toolbar");
        assert_eq!(ActionGroup::GlobalMenu.display_name(), "Global Menu");
        assert_eq!(ActionGroup::Popup.display_name(), "Popup Menu");
    }

    #[test]
    fn test_action_group_from_display_name() {
        assert_eq!(
            ActionGroup::from_display_name("Local Toolbar"),
            Some(ActionGroup::LocalToolbar)
        );
        assert_eq!(
            ActionGroup::from_display_name("Global Menu"),
            Some(ActionGroup::GlobalMenu)
        );
        assert_eq!(ActionGroup::from_display_name("Nonexistent"), None);
    }

    #[test]
    fn test_action_group_classification() {
        assert!(ActionGroup::LocalToolbar.is_local());
        assert!(!ActionGroup::LocalToolbar.is_global());
        assert!(ActionGroup::LocalToolbar.is_toolbar());
        assert!(!ActionGroup::LocalToolbar.is_menu());

        assert!(!ActionGroup::GlobalMenu.is_local());
        assert!(ActionGroup::GlobalMenu.is_global());
        assert!(!ActionGroup::GlobalMenu.is_toolbar());
        assert!(ActionGroup::GlobalMenu.is_menu());

        assert!(!ActionGroup::Popup.is_local());
        assert!(!ActionGroup::Popup.is_global());
        assert!(!ActionGroup::Popup.is_toolbar());
        assert!(!ActionGroup::Popup.is_menu());
    }

    #[test]
    fn test_action_group_display() {
        assert_eq!(ActionGroup::KeybindingOnly.to_string(), "Keybinding Only");
    }

    // -- categorize tests --

    #[test]
    fn test_categorize_local_with_toolbar() {
        let action = DockingAction::new("a", "A")
            .with_tool_bar_data(ToolBarData::new("icon.png"));
        assert_eq!(action.categorize(true), ActionGroup::LocalToolbar);
    }

    #[test]
    fn test_categorize_local_with_menu() {
        let action = DockingAction::new("a", "A")
            .with_menu_bar_data(MenuBarData::simple("A"));
        assert_eq!(action.categorize(true), ActionGroup::LocalMenu);
    }

    #[test]
    fn test_categorize_local_popup_only() {
        let action = DockingAction::new("a", "A");
        assert_eq!(action.categorize(true), ActionGroup::Popup);
    }

    #[test]
    fn test_categorize_global_with_toolbar() {
        let action = DockingAction::new("a", "A")
            .with_tool_bar_data(ToolBarData::new("icon.png"));
        assert_eq!(action.categorize(false), ActionGroup::GlobalToolbar);
    }

    #[test]
    fn test_categorize_global_menu() {
        let action = DockingAction::new("a", "A")
            .with_menu_bar_data(MenuBarData::simple("A"));
        assert_eq!(action.categorize(false), ActionGroup::GlobalMenu);
    }

    #[test]
    fn test_categorize_global_keybinding_only() {
        let action = DockingAction::new("a", "A");
        assert_eq!(action.categorize(false), ActionGroup::KeybindingOnly);
    }

    // -- should_add_to_window_with_context_types tests --

    #[test]
    fn test_should_add_to_window_with_context_types_no_menu_toolbar() {
        let action = DockingAction::new("a", "A");
        assert!(!action.should_add_to_window_with_context_types(true, &[]));
    }

    #[test]
    fn test_should_add_to_window_with_context_types_matching() {
        let action = DockingAction::new("a", "A")
            .with_menu_bar_data(MenuBarData::simple("A"));
        let mut action = action;
        action.set_context_class("ListingContext", false);
        assert!(action.should_add_to_window_with_context_types(
            true,
            &["ListingContext", "DecompilerContext"]
        ));
    }

    #[test]
    fn test_should_add_to_window_with_context_types_no_match() {
        let action = DockingAction::new("a", "A")
            .with_menu_bar_data(MenuBarData::simple("A"));
        let mut action = action;
        action.set_context_class("ListingContext", false);
        assert!(!action.should_add_to_window_with_context_types(
            true,
            &["DecompilerContext"]
        ));
    }

    #[test]
    fn test_should_add_to_window_with_context_types_no_class() {
        let action = DockingAction::new("a", "A")
            .with_menu_bar_data(MenuBarData::simple("A"));
        // No context class set -> added to main window.
        assert!(action.should_add_to_window_with_context_types(true, &["AnyContext"]));
        // Non-main window: no context class -> added.
        assert!(action.should_add_to_window_with_context_types(false, &["AnyContext"]));
    }

    // -- KeyBindingDataPrecedence tests --

    #[test]
    fn test_key_binding_precedence_ordering() {
        assert!(KeyBindingDataPrecedence::DefaultLevel < KeyBindingDataPrecedence::ActiveWindowLevel);
        assert!(KeyBindingDataPrecedence::ActiveWindowLevel < KeyBindingDataPrecedence::SystemActionsLevel);
    }

    #[test]
    fn test_key_binding_precedence_default() {
        assert_eq!(KeyBindingDataPrecedence::default(), KeyBindingDataPrecedence::DefaultLevel);
    }

    #[test]
    fn test_key_binding_precedence_user_support() {
        assert!(KeyBindingDataPrecedence::DefaultLevel.supports_user_key_bindings());
        assert!(KeyBindingDataPrecedence::ActiveWindowLevel.supports_user_key_bindings());
        assert!(!KeyBindingDataPrecedence::SystemActionsLevel.supports_user_key_bindings());
    }

    #[test]
    fn test_key_binding_precedence_display() {
        assert_eq!(KeyBindingDataPrecedence::DefaultLevel.to_string(), "DefaultLevel");
        assert_eq!(
            KeyBindingDataPrecedence::SystemActionsLevel.to_string(),
            "SystemActionsLevel"
        );
    }

    // -- KeyBindingData tests --

    #[test]
    fn test_key_binding_data_new() {
        let kbd = KeyBindingData::new(KeyBinding::ctrl(Key::S));
        assert_eq!(kbd.precedence, KeyBindingDataPrecedence::DefaultLevel);
        assert!(kbd.mouse_binding.is_none());
        assert!(kbd.supports_user_changes());
    }

    #[test]
    fn test_key_binding_data_system() {
        let kbd = KeyBindingData::system(KeyBinding::plain(Key::F1));
        assert_eq!(kbd.precedence, KeyBindingDataPrecedence::SystemActionsLevel);
        assert!(!kbd.supports_user_changes());
    }

    #[test]
    fn test_key_binding_data_with_mouse() {
        let kbd = KeyBindingData::new(KeyBinding::ctrl(Key::C))
            .with_mouse_binding("LEFT_DOUBLE_CLICK");
        assert_eq!(kbd.mouse_binding.as_deref(), Some("LEFT_DOUBLE_CLICK"));
    }

    #[test]
    fn test_key_binding_data_display() {
        let kbd = KeyBindingData::new(KeyBinding::ctrl(Key::S));
        let s = kbd.to_string();
        assert!(s.contains("Ctrl+S"));
        assert!(s.contains("DefaultLevel"));
    }

    #[test]
    fn test_key_binding_data_with_precedence() {
        let kbd = KeyBindingData::with_precedence(
            KeyBinding::alt(Key::F4),
            KeyBindingDataPrecedence::ActiveWindowLevel,
        );
        assert_eq!(kbd.precedence, KeyBindingDataPrecedence::ActiveWindowLevel);
    }

    // -- addToWindowWhen / setAddToAllWindows tests --

    #[test]
    fn test_add_to_window_when() {
        let action = DockingAction::new("a", "A")
            .add_to_window_when("ListingContext");
        assert_eq!(
            action.add_to_window_when_context_class.as_deref(),
            Some("ListingContext")
        );
    }

    #[test]
    fn test_set_add_to_all_windows() {
        let mut action = DockingAction::new("a", "A");
        assert!(!action.add_to_all_windows);
        action.set_add_to_all_windows(true);
        assert!(action.add_to_all_windows);
    }

    // -- Key binding data on DockingAction tests --

    #[test]
    fn test_set_key_binding_data() {
        let mut action = DockingAction::new("a", "A");
        assert!(action.get_key_binding_data().is_none());

        let kbd = KeyBindingData::new(KeyBinding::ctrl(Key::S));
        action.set_key_binding_data(Some(kbd));
        assert!(action.get_key_binding_data().is_some());
        assert!(action.get_default_key_binding_data().is_some());
    }

    #[test]
    fn test_set_key_binding_data_system_rejected() {
        let mut action = DockingAction::new("a", "A");
        let kbd = KeyBindingData::system(KeyBinding::plain(Key::F1));
        action.set_key_binding_data(Some(kbd));
        // System-level key bindings should be rejected by set_key_binding_data.
        assert!(action.get_key_binding_data().is_none());
    }

    #[test]
    fn test_set_unvalidated_key_binding_data() {
        let mut action = DockingAction::new("a", "A");
        let kbd = KeyBindingData::system(KeyBinding::plain(Key::F1));
        action.set_unvalidated_key_binding_data(Some(kbd));
        // Unvalidated path accepts system-level.
        assert!(action.get_key_binding_data().is_some());
    }

    // -- Inception tests --

    #[test]
    fn test_inception_information() {
        let mut action = DockingAction::new("a", "A");
        assert!(action.get_inception_information().is_none());

        action.set_inception_information("MyPlugin.java:42");
        assert_eq!(
            action.get_inception_information(),
            Some("MyPlugin.java:42")
        );
    }

    // -- get_help_info tests --

    #[test]
    fn test_get_help_info() {
        let action = DockingAction::with_owner("my-action", "MyPlugin", "My Action")
            .with_menu_bar_data(MenuBarData::new(vec!["Edit".into(), "Action".into()]))
            .with_key_binding(KeyBinding::ctrl(Key::Z));
        let info = action.get_help_info();
        assert!(info.contains("MyPlugin"));
        assert!(info.contains("my-action"));
        assert!(info.contains("Edit > Action"));
        assert!(info.contains("Ctrl+Z"));
    }

    // -- MultiAction tests --

    #[test]
    fn test_multi_action() {
        let mut multi = MultiAction::new("Batch Actions", "MyPlugin");
        assert!(multi.is_empty());

        multi.add_action(DockingAction::new("a", "A"));
        multi.add_action(DockingAction::new("b", "B"));
        assert_eq!(multi.len(), 2);
        assert!(!multi.is_empty());
    }

    // -- ContextSpecificAction tests --

    #[test]
    fn test_context_specific_action() {
        let action = DockingAction::new("goto", "Go To");
        let specific = ContextSpecificAction::new(action, "ListingContext");

        assert!(specific.matches_context("ListingContext"));
        assert!(!specific.matches_context("DecompilerContext"));
    }

    #[test]
    fn test_context_specific_action_enabled() {
        let action = DockingAction::new("goto", "Go To");
        let specific = ContextSpecificAction::new(action, "ListingContext");

        let ctx = ActionContextInfo::with_address("0x1000");
        assert!(specific.is_enabled_for_typed_context("ListingContext", &ctx));
        assert!(!specific.is_enabled_for_typed_context("DecompilerContext", &ctx));
    }

    #[test]
    fn test_context_specific_action_valid() {
        let action = DockingAction::new("goto", "Go To");
        let specific = ContextSpecificAction::new(action, "ListingContext");

        assert!(specific.is_valid_typed_context("ListingContext"));
        assert!(!specific.is_valid_typed_context("OtherContext"));
    }

    #[test]
    fn test_context_specific_action_popup() {
        let action = DockingAction::new("copy", "Copy");
        let specific = ContextSpecificAction::new(action, "ListingContext");

        let ctx = ActionContextInfo::with_address("0x1000");
        assert!(specific.is_add_to_typed_popup("ListingContext", &ctx));
        assert!(!specific.is_add_to_typed_popup("OtherContext", &ctx));
    }
}
