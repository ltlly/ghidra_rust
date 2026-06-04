//! Color management for the debugger GUI.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.gui.colors`
//! package in the Debugger module. Provides color assignment and
//! management for debugger elements.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A named color entry used in the debugger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugColor {
    /// The name/identifier for this color.
    pub name: String,
    /// The ARGB color value.
    pub argb: u32,
    /// A description of what this color is for.
    pub description: String,
}

impl DebugColor {
    /// Create a new debug color.
    pub fn new(name: impl Into<String>, argb: u32) -> Self {
        Self {
            name: name.into(),
            argb,
            description: String::new(),
        }
    }

    /// Extract the red component.
    pub fn red(&self) -> u8 {
        ((self.argb >> 16) & 0xff) as u8
    }

    /// Extract the green component.
    pub fn green(&self) -> u8 {
        ((self.argb >> 8) & 0xff) as u8
    }

    /// Extract the blue component.
    pub fn blue(&self) -> u8 {
        (self.argb & 0xff) as u8
    }

    /// Extract the alpha component.
    pub fn alpha(&self) -> u8 {
        ((self.argb >> 24) & 0xff) as u8
    }
}

/// Color scheme for the debugger.
///
/// Manages colors assigned to different types of debugger elements
/// (threads, breakpoints, memory regions, etc.).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DebugColorScheme {
    /// Color assignments by name.
    colors: BTreeMap<String, DebugColor>,
    /// Fallback color for unknown elements.
    pub fallback_color: u32,
}

impl DebugColorScheme {
    /// Create a new color scheme with default colors.
    pub fn new() -> Self {
        let mut scheme = Self {
            colors: BTreeMap::new(),
            fallback_color: 0xff_808080,
        };
        scheme.load_defaults();
        scheme
    }

    fn load_defaults(&mut self) {
        self.set(DebugColor::new("breakpoint.sw", 0xff_ff0000));
        self.set(DebugColor::new("breakpoint.hw", 0xff_ff8800));
        self.set(DebugColor::new("breakpoint.watch", 0xff_ffff00));
        self.set(DebugColor::new("thread.active", 0xff_00ff00));
        self.set(DebugColor::new("thread.running", 0xff_4488cc));
        self.set(DebugColor::new("thread.stopped", 0xff_cc4444));
        self.set(DebugColor::new("pc.current", 0xff_00ffff));
        self.set(DebugColor::new("memory.known", 0xff_dddddd));
        self.set(DebugColor::new("memory.unknown", 0xff_333333));
    }

    /// Set a color.
    pub fn set(&mut self, color: DebugColor) {
        self.colors.insert(color.name.clone(), color);
    }

    /// Get a color by name.
    pub fn get(&self, name: &str) -> Option<&DebugColor> {
        self.colors.get(name)
    }

    /// Get the ARGB value for a name, falling back to the default.
    pub fn color_for(&self, name: &str) -> u32 {
        self.colors
            .get(name)
            .map(|c| c.argb)
            .unwrap_or(self.fallback_color)
    }

    /// Get all color names.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.colors.keys().map(|s| s.as_str())
    }

    /// The number of registered colors.
    pub fn len(&self) -> usize {
        self.colors.len()
    }

    /// Whether the scheme has no colors.
    pub fn is_empty(&self) -> bool {
        self.colors.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_color() {
        let color = DebugColor::new("test", 0xff_804020);
        assert_eq!(color.name, "test");
        assert_eq!(color.red(), 0x80);
        assert_eq!(color.green(), 0x40);
        assert_eq!(color.blue(), 0x20);
        assert_eq!(color.alpha(), 0xff);
    }

    #[test]
    fn test_debug_color_scheme_defaults() {
        let scheme = DebugColorScheme::new();
        assert!(!scheme.is_empty());
        assert!(scheme.get("breakpoint.sw").is_some());
        assert_eq!(scheme.color_for("breakpoint.sw"), 0xff_ff0000);
    }

    #[test]
    fn test_debug_color_scheme_fallback() {
        let scheme = DebugColorScheme::new();
        assert_eq!(scheme.color_for("nonexistent"), 0xff_808080);
    }

    #[test]
    fn test_debug_color_scheme_custom() {
        let mut scheme = DebugColorScheme::new();
        scheme.set(DebugColor::new("custom", 0xff_123456));
        assert_eq!(scheme.color_for("custom"), 0xff_123456);
    }

    #[test]
    fn test_debug_color_scheme_names() {
        let scheme = DebugColorScheme::new();
        let names: Vec<&str> = scheme.names().collect();
        assert!(names.contains(&"breakpoint.sw"));
        assert!(names.contains(&"thread.active"));
    }
}
