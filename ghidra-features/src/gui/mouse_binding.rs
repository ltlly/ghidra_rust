//! Mouse binding for input events.
//!
//! Ported from `gui.event.MouseBinding` (Framework/Gui).
//!
//! A simple class that represents a mouse button and any modifiers needed
//! to bind an action to a mouse input event.  The modifiers used by this
//! class include the button-down mask for the given button, matching how
//! Java's `MouseEvent` uses its modifiers.

use std::collections::HashSet;
use std::fmt;

// ---------------------------------------------------------------------------
// Input event modifier constants (mirrors java.awt.event.InputEvent)
// ---------------------------------------------------------------------------

/// Shift key modifier mask.
pub const SHIFT_DOWN_MASK: u32 = 1 << 6;

/// Control key modifier mask.
pub const CTRL_DOWN_MASK: u32 = 1 << 7;

/// Alt key modifier mask.
pub const ALT_DOWN_MASK: u32 = 1 << 8;

/// Meta key modifier mask.
pub const META_DOWN_MASK: u32 = 1 << 9;

/// Button1 down mask (left mouse button).
pub const BUTTON1_DOWN_MASK: u32 = 1 << 10;

/// Button2 down mask (middle mouse button).
pub const BUTTON2_DOWN_MASK: u32 = 1 << 11;

/// Button3 down mask (right mouse button).
pub const BUTTON3_DOWN_MASK: u32 = 1 << 12;

/// Returns the button-down mask for the given button number.
///
/// Button numbers start at 1 (left button).  Returns 0 for an
/// invalid button number.
pub fn get_mask_for_button(button: u32) -> u32 {
    match button {
        1 => BUTTON1_DOWN_MASK,
        2 => BUTTON2_DOWN_MASK,
        3 => BUTTON3_DOWN_MASK,
        // Buttons 4-20 follow the Java convention of BUTTON1_DOWN_MASK + (button-1) << offset
        4..=20 => BUTTON1_DOWN_MASK + ((button - 1) << 4),
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// MouseBinding
// ---------------------------------------------------------------------------

/// A binding of a mouse button number and modifier keys.
///
/// Used to match mouse input events against registered bindings,
/// for example "Ctrl+Button1" or "Shift+Button3".
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MouseBinding {
    /// The mouse button number (1-based: 1 = left, 2 = middle, 3 = right).
    button: u32,
    /// The combined modifier mask including the button-down mask.
    modifiers: u32,
}

impl MouseBinding {
    /// Create a binding for the given mouse button with no extra modifiers.
    ///
    /// # Arguments
    ///
    /// * `button` -- the button number (1 = left, 2 = middle, 3 = right).
    pub fn new(button: u32) -> Self {
        Self::with_modifiers(button, 0)
    }

    /// Create a binding for the given mouse button and additional modifiers.
    ///
    /// The button-down mask for `button` is OR-ed into `modifiers` automatically,
    /// matching how Java `MouseEvent` represents its modifier state.
    ///
    /// # Arguments
    ///
    /// * `button` -- the button number (1 = left, 2 = middle, 3 = right).
    /// * `modifiers` -- additional modifier mask flags (e.g. `SHIFT_DOWN_MASK`).
    pub fn with_modifiers(button: u32, modifiers: u32) -> Self {
        let button_mask = get_mask_for_button(button);
        let combined = if modifiers > 0 {
            button_mask | modifiers
        } else {
            button_mask
        };

        Self {
            button,
            modifiers: combined,
        }
    }

    /// The mouse button number.
    pub fn button(&self) -> u32 {
        self.button
    }

    /// The combined modifier mask (including the button-down mask).
    pub fn modifiers(&self) -> u32 {
        self.modifiers
    }

    /// A user-friendly display string for this binding.
    ///
    /// Produces strings like `"Button1"`, `"Ctrl+Button1"`, `"Shift+Alt+Button3"`.
    pub fn display_text(&self) -> String {
        let mut parts = Vec::new();

        if self.modifiers & SHIFT_DOWN_MASK != 0 {
            parts.push("Shift");
        }
        if self.modifiers & CTRL_DOWN_MASK != 0 {
            parts.push("Ctrl");
        }
        if self.modifiers & ALT_DOWN_MASK != 0 {
            parts.push("Alt");
        }
        if self.modifiers & META_DOWN_MASK != 0 {
            parts.push("Meta");
        }

        parts.push(&format!("Button{}", self.button));
        parts.join("+")
    }

    /// Create a `MouseBinding` from a display-text string.
    ///
    /// The string is expected to be of the form `"Ctrl+Button1"`,
    /// which is the form produced by [`display_text`](Self::display_text).
    ///
    /// Returns `None` if the string does not contain a valid button token.
    pub fn from_string(mouse_string: &str) -> Option<Self> {
        let button = parse_button(mouse_string)?;
        let modifiers = parse_modifiers(mouse_string);
        Some(Self::with_modifiers(button, modifiers))
    }

    /// Returns true if the given button number and event-id represent the
    /// matching release/click event for this binding.
    ///
    /// This ignores modifier state, since modifiers can be pressed and
    /// released independently of the mouse button.
    pub fn is_matching_release(&self, button: u32, is_release_or_click: bool) -> bool {
        if self.button != button {
            return false;
        }
        is_release_or_click
    }

    /// Check whether the given modifier mask matches this binding.
    ///
    /// This checks that all modifier bits in `self.modifiers` are also
    /// set in `event_modifiers`.  Extra bits in `event_modifiers` are
    /// ignored.
    pub fn matches_event(&self, event_button: u32, event_modifiers: u32) -> bool {
        if self.button != event_button {
            return false;
        }
        // All bits in self.modifiers must be present in event_modifiers
        (event_modifiers & self.modifiers) == self.modifiers
    }
}

impl fmt::Display for MouseBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_text())
    }
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Extract the button number from a mouse binding string.
///
/// Looks for the pattern `button<number>` (case-insensitive).
fn parse_button(mouse_string: &str) -> Option<u32> {
    let lower = mouse_string.to_lowercase();
    // Find "button" followed by digits
    if let Some(pos) = lower.find("button") {
        let rest = &lower[pos + 6..];
        let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !num_str.is_empty() {
            if let Ok(n) = num_str.parse::<u32>() {
                if n > 0 {
                    return Some(n);
                }
            }
        }
    }
    None
}

/// Parse modifier keywords from a mouse binding string.
///
/// Recognizes `Shift`, `Ctrl`, `Alt`, `Meta` (case-insensitive).
fn parse_modifiers(mouse_string: &str) -> u32 {
    let mut modifiers: u32 = 0;
    // Split on common delimiters
    let tokens: Vec<&str> = mouse_string
        .split(|c: char| c == '+' || c == '-' || c == ' ')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    // Use a set to deduplicate tokens
    let mut seen = HashSet::new();
    for token in &tokens {
        let lower = token.to_lowercase();
        if seen.contains(&lower) {
            continue;
        }
        seen.insert(lower.clone());

        let lower_ref = lower.as_str();
        if lower_ref.contains("shift") {
            modifiers |= SHIFT_DOWN_MASK;
        } else if lower_ref.contains("ctrl") {
            modifiers |= CTRL_DOWN_MASK;
        } else if lower_ref.contains("alt") {
            modifiers |= ALT_DOWN_MASK;
        } else if lower_ref.contains("meta") {
            modifiers |= META_DOWN_MASK;
        }
    }

    modifiers
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mouse_binding_new() {
        let binding = MouseBinding::new(1);
        assert_eq!(binding.button(), 1);
        assert_eq!(binding.modifiers(), BUTTON1_DOWN_MASK);
    }

    #[test]
    fn test_mouse_binding_with_modifiers() {
        let binding = MouseBinding::with_modifiers(1, SHIFT_DOWN_MASK);
        assert_eq!(binding.button(), 1);
        assert_eq!(binding.modifiers(), BUTTON1_DOWN_MASK | SHIFT_DOWN_MASK);
    }

    #[test]
    fn test_mouse_binding_right_click() {
        let binding = MouseBinding::new(3);
        assert_eq!(binding.button(), 3);
        assert_eq!(binding.modifiers(), BUTTON3_DOWN_MASK);
    }

    #[test]
    fn test_display_text_button_only() {
        let binding = MouseBinding::new(1);
        assert_eq!(binding.display_text(), "Button1");
    }

    #[test]
    fn test_display_text_with_shift() {
        let binding = MouseBinding::with_modifiers(1, SHIFT_DOWN_MASK);
        let text = binding.display_text();
        assert!(text.contains("Shift"));
        assert!(text.contains("Button1"));
    }

    #[test]
    fn test_display_text_with_ctrl() {
        let binding = MouseBinding::with_modifiers(2, CTRL_DOWN_MASK);
        let text = binding.display_text();
        assert!(text.contains("Ctrl"));
        assert!(text.contains("Button2"));
    }

    #[test]
    fn test_display_text_with_multiple_modifiers() {
        let binding = MouseBinding::with_modifiers(1, SHIFT_DOWN_MASK | CTRL_DOWN_MASK);
        let text = binding.display_text();
        assert!(text.contains("Shift"));
        assert!(text.contains("Ctrl"));
        assert!(text.contains("Button1"));
    }

    #[test]
    fn test_display_format() {
        let binding = MouseBinding::new(1);
        assert_eq!(format!("{}", binding), "Button1");
    }

    #[test]
    fn test_from_string_basic() {
        let binding = MouseBinding::from_string("Button1").unwrap();
        assert_eq!(binding.button(), 1);
    }

    #[test]
    fn test_from_string_with_ctrl() {
        let binding = MouseBinding::from_string("Ctrl+Button1").unwrap();
        assert_eq!(binding.button(), 1);
        assert_ne!(binding.modifiers() & CTRL_DOWN_MASK, 0);
    }

    #[test]
    fn test_from_string_with_shift() {
        let binding = MouseBinding::from_string("Shift+Button3").unwrap();
        assert_eq!(binding.button(), 3);
        assert_ne!(binding.modifiers() & SHIFT_DOWN_MASK, 0);
    }

    #[test]
    fn test_from_string_with_multiple_modifiers() {
        let binding = MouseBinding::from_string("Shift+Ctrl+Button1").unwrap();
        assert_eq!(binding.button(), 1);
        assert_ne!(binding.modifiers() & SHIFT_DOWN_MASK, 0);
        assert_ne!(binding.modifiers() & CTRL_DOWN_MASK, 0);
    }

    #[test]
    fn test_from_string_case_insensitive() {
        let binding = MouseBinding::from_string("shift+button2").unwrap();
        assert_eq!(binding.button(), 2);
        assert_ne!(binding.modifiers() & SHIFT_DOWN_MASK, 0);
    }

    #[test]
    fn test_from_string_invalid() {
        assert!(MouseBinding::from_string("no-button-here").is_none());
    }

    #[test]
    fn test_from_string_zero_button() {
        assert!(MouseBinding::from_string("Button0").is_none());
    }

    #[test]
    fn test_from_string_negative_button() {
        assert!(MouseBinding::from_string("Button-1").is_none());
    }

    #[test]
    fn test_is_matching_release() {
        let binding = MouseBinding::new(1);
        assert!(binding.is_matching_release(1, true));
        assert!(!binding.is_matching_release(2, true));
        assert!(!binding.is_matching_release(1, false));
    }

    #[test]
    fn test_matches_event() {
        let binding = MouseBinding::with_modifiers(1, SHIFT_DOWN_MASK);
        assert!(binding.matches_event(1, SHIFT_DOWN_MASK));
        assert!(binding.matches_event(1, SHIFT_DOWN_MASK | BUTTON1_DOWN_MASK));
        assert!(!binding.matches_event(1, 0)); // missing shift
        assert!(!binding.matches_event(2, SHIFT_DOWN_MASK)); // wrong button
    }

    #[test]
    fn test_get_mask_for_button() {
        assert_eq!(get_mask_for_button(1), BUTTON1_DOWN_MASK);
        assert_eq!(get_mask_for_button(2), BUTTON2_DOWN_MASK);
        assert_eq!(get_mask_for_button(3), BUTTON3_DOWN_MASK);
        assert_eq!(get_mask_for_button(0), 0);
        assert_eq!(get_mask_for_button(100), 0);
    }

    #[test]
    fn test_parse_button() {
        assert_eq!(parse_button("Button1"), Some(1));
        assert_eq!(parse_button("Ctrl+Button3"), Some(3));
        assert_eq!(parse_button("button2"), Some(2));
        assert_eq!(parse_button("BUTTON10"), Some(10));
        assert_eq!(parse_button("no button"), None);
        assert_eq!(parse_button("Button0"), None);
    }

    #[test]
    fn test_parse_modifiers() {
        assert_eq!(parse_modifiers("Button1"), 0);
        assert_eq!(parse_modifiers("Shift+Button1"), SHIFT_DOWN_MASK);
        assert_eq!(
            parse_modifiers("Ctrl+Alt+Button1"),
            CTRL_DOWN_MASK | ALT_DOWN_MASK
        );
        assert_eq!(
            parse_modifiers("Shift+Ctrl+Alt+Meta+Button2"),
            SHIFT_DOWN_MASK | CTRL_DOWN_MASK | ALT_DOWN_MASK | META_DOWN_MASK
        );
    }

    #[test]
    fn test_roundtrip_display_parse() {
        let original = MouseBinding::with_modifiers(1, SHIFT_DOWN_MASK | CTRL_DOWN_MASK);
        let text = original.display_text();
        let parsed = MouseBinding::from_string(&text).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn test_equality() {
        let a = MouseBinding::new(1);
        let b = MouseBinding::new(1);
        let c = MouseBinding::new(2);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
