//! Mouse and keyboard event bindings.
//!
//! Ports `gui.event.MouseBinding` from the Ghidra Java source into idiomatic
//! Rust types that can be used with egui or any other event system.

use std::fmt;

/// Modifier keys held during a mouse event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MouseModifiers {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
    pub meta: bool,
}

impl Default for MouseModifiers {
    fn default() -> Self {
        Self { shift: false, ctrl: false, alt: false, meta: false }
    }
}

impl fmt::Display for MouseModifiers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if self.ctrl { parts.push("Ctrl"); }
        if self.alt { parts.push("Alt"); }
        if self.shift { parts.push("Shift"); }
        if self.meta { parts.push("Meta"); }
        write!(f, "{}", parts.join("+"))
    }
}

/// Mouse button identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
    /// Extra button (e.g. back/forward).
    Other(u8),
}

impl fmt::Display for MouseButton {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MouseButton::Left => write!(f, "Button1"),
            MouseButton::Middle => write!(f, "Button2"),
            MouseButton::Right => write!(f, "Button3"),
            MouseButton::Other(n) => write!(f, "Button{}", n),
        }
    }
}

/// Represents a mouse binding (button + modifiers) used for triggering actions.
///
/// Ported from Ghidra's `gui.event.MouseBinding`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct MouseBinding {
    button: MouseButton,
    modifiers: MouseModifiers,
    click_count: u8,
}

impl MouseBinding {
    /// Create a new mouse binding.
    pub fn new(button: MouseButton, modifiers: MouseModifiers) -> Self {
        Self { button, modifiers, click_count: 1 }
    }

    /// Set the click count (1 = single click, 2 = double click, etc.).
    pub fn with_click_count(mut self, count: u8) -> Self {
        self.click_count = count;
        self
    }

    /// Get the button.
    pub fn button(&self) -> MouseButton {
        self.button
    }

    /// Get the modifiers.
    pub fn modifiers(&self) -> &MouseModifiers {
        &self.modifiers
    }

    /// Get the click count.
    pub fn click_count(&self) -> u8 {
        self.click_count
    }

    /// Parse a mouse binding from its string representation.
    ///
    /// The expected format is `"Ctrl+Alt+Button1[double]"`.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }

        let mut modifiers = MouseModifiers::default();
        let mut button = MouseButton::Left;
        let mut click_count: u8 = 1;

        let parts: Vec<&str> = s.split('+').map(|p| p.trim()).collect();
        for part in &parts {
            match part.to_lowercase().as_str() {
                "ctrl" | "control" => modifiers.ctrl = true,
                "alt" => modifiers.alt = true,
                "shift" => modifiers.shift = true,
                "meta" | "cmd" | "command" => modifiers.meta = true,
                "button1" | "left" => button = MouseButton::Left,
                "button2" | "middle" => button = MouseButton::Middle,
                "button3" | "right" => button = MouseButton::Right,
                other => {
                    if let Some(n) = other.strip_prefix("button") {
                        if let Ok(n) = n.parse::<u8>() {
                            button = MouseButton::Other(n);
                        }
                    } else if other.contains("double") {
                        click_count = 2;
                    } else if other.contains("triple") {
                        click_count = 3;
                    }
                }
            }
        }

        Some(Self { button, modifiers, click_count })
    }
}

impl fmt::Display for MouseBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mod_str = self.modifiers.to_string();
        if mod_str.is_empty() {
            write!(f, "{}", self.button)
        } else {
            write!(f, "{}+{}", mod_str, self.button)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mouse_binding_basic() {
        let mb = MouseBinding::new(MouseButton::Left, MouseModifiers::default());
        assert_eq!(mb.button(), MouseButton::Left);
        assert_eq!(mb.click_count(), 1);
    }

    #[test]
    fn test_mouse_binding_with_modifiers() {
        let mods = MouseModifiers { ctrl: true, shift: true, ..Default::default() };
        let mb = MouseBinding::new(MouseButton::Right, mods).with_click_count(2);
        assert_eq!(mb.click_count(), 2);
        assert!(mb.modifiers().ctrl);
        assert!(mb.modifiers().shift);
    }

    #[test]
    fn test_mouse_binding_display() {
        let mods = MouseModifiers { ctrl: true, ..Default::default() };
        let mb = MouseBinding::new(MouseButton::Right, mods);
        assert_eq!(mb.to_string(), "Ctrl+Button3");
    }

    #[test]
    fn test_mouse_binding_parse() {
        let mb = MouseBinding::parse("Ctrl+Alt+Button2").unwrap();
        assert!(mb.modifiers().ctrl);
        assert!(mb.modifiers().alt);
        assert_eq!(mb.button(), MouseButton::Middle);
    }

    #[test]
    fn test_mouse_binding_parse_empty() {
        assert!(MouseBinding::parse("").is_none());
    }

    #[test]
    fn test_mouse_modifiers_display() {
        let mods = MouseModifiers { alt: true, meta: true, ..Default::default() };
        assert_eq!(mods.to_string(), "Alt+Meta");
    }

    #[test]
    fn test_mouse_button_display() {
        assert_eq!(MouseButton::Left.to_string(), "Button1");
        assert_eq!(MouseButton::Other(5).to_string(), "Button5");
    }
}
