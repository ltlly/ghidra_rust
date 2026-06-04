//! Static theme access facade -- port of Ghidra's `generic.theme.Gui`.
//!
//! Provides convenience methods for globally accessing the application's
//! current theme colors, fonts, and icons by string id.

use std::sync::Mutex;

use super::g_theme::GTheme;
use super::theme_manager::ThemeManager;

use once_cell::sync::Lazy;

/// Global singleton for the active theme manager.
static THEME_MANAGER: Lazy<Mutex<ThemeManager>> =
    Lazy::new(|| Mutex::new(ThemeManager::new(GTheme::new("Default"))));

/// Replace the global theme manager (e.g., at application startup).
///
/// This is the Rust equivalent of Ghidra's `Gui.setThemeManager()`.
pub fn set_theme_manager(mgr: ThemeManager) {
    let mut guard = THEME_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    *guard = mgr;
}

/// Whether a color with the given id is registered.
pub fn has_color(id: &str) -> bool {
    let guard = THEME_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    guard.current_values().get_color(id).is_some()
}

/// Whether a font with the given id is registered.
pub fn has_font(id: &str) -> bool {
    let guard = THEME_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    guard.current_values().get_font(id).is_some()
}

/// Whether an icon with the given id is registered.
pub fn has_icon(id: &str) -> bool {
    let guard = THEME_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    guard.current_values().get_icon(id).is_some()
}

/// Whether the active theme uses dark defaults.
pub fn is_dark_theme() -> bool {
    let guard = THEME_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    guard.uses_dark_defaults()
}

/// Whether the given id is a system-defined id (e.g., starts with `laf.` or `system.`).
pub fn is_system_id(id: &str) -> bool {
    id.starts_with("laf.") || id.starts_with("system.")
}

/// Whether the theme system is currently updating.
pub fn is_updating_theme() -> bool {
    // In Rust we don't track this separately yet; always false.
    false
}

/// Set whether blinking cursors are enabled.
pub fn set_blinking_cursors(b: bool) {
    let mut guard = THEME_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    guard.set_blinking_cursors(b);
}

/// Whether blinking cursors are currently enabled.
pub fn is_blinking_cursors() -> bool {
    let guard = THEME_MANAGER.lock().unwrap_or_else(|e| e.into_inner());
    guard.is_blinking_cursors()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_system_id() {
        assert!(is_system_id("laf.color.Button.background"));
        assert!(is_system_id("system.color.bg"));
        assert!(!is_system_id("color.bg"));
        assert!(!is_system_id("my.custom.id"));
    }

    #[test]
    fn test_default_is_not_dark() {
        assert!(!is_dark_theme());
    }

    #[test]
    fn test_default_not_updating() {
        assert!(!is_updating_theme());
    }

    #[test]
    fn test_set_and_check_blinking_cursors() {
        set_blinking_cursors(false);
        assert!(!is_blinking_cursors());
        set_blinking_cursors(true);
        assert!(is_blinking_cursors());
    }

    #[test]
    fn test_has_color_unknown_returns_false() {
        assert!(!has_color("nonexistent.color.id"));
    }

    #[test]
    fn test_has_font_unknown_returns_false() {
        assert!(!has_font("nonexistent.font.id"));
    }

    #[test]
    fn test_has_icon_unknown_returns_false() {
        assert!(!has_icon("nonexistent.icon.id"));
    }

    #[test]
    fn test_set_theme_manager() {
        let theme = GTheme::new("Test");
        let mgr = ThemeManager::new(theme);
        set_theme_manager(mgr);
        assert!(!is_dark_theme());
    }
}
