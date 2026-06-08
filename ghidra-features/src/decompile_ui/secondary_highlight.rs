//! Secondary highlight actions -- Rust port of the secondary highlight
//! subsystem from `ghidra.app.plugin.core.decompile.actions`.
//!
//! This module models the set/remove/remove-all actions for secondary
//! (middle-mouse) highlights in the decompiler panel, plus a color
//! chooser variant.
//!
//! # Architecture
//!
//! ```text
//! SecondaryHighlightManager
//!   ├── highlights: HashMap<String, SecondaryHighlight>
//!   ├── recent_colors: Vec<(u8, u8, u8, u8)>
//!   ├── set(token) / remove(token) / remove_all(function)
//!   └── has(token) / has_any(function)
//!
//! SetSecondaryHighlightAction
//! RemoveSecondaryHighlightAction
//! RemoveAllSecondaryHighlightsAction
//! SetSecondaryHighlightColorChooserAction
//! ```

use std::collections::HashMap;

use ghidra_core::addr::Address;

// ---------------------------------------------------------------------------
// SecondaryHighlight
// ---------------------------------------------------------------------------

/// A single secondary highlight entry.
///
/// Secondary highlights are user-created marks on tokens (typically via
/// middle-mouse click) that persist across navigation within the same
/// function.  Each highlight has an associated color.
#[derive(Debug, Clone)]
pub struct SecondaryHighlight {
    /// The highlighted token text.
    pub token_text: String,
    /// The highlight color as RGBA (0-255 per channel).
    pub color: (u8, u8, u8, u8),
    /// The function entry point this highlight belongs to.
    pub function_entry: Address,
    /// Optional: the specific address of the token (for disambiguation).
    pub token_address: Option<Address>,
}

impl SecondaryHighlight {
    /// Create a new secondary highlight with a default color.
    pub fn new(
        token_text: impl Into<String>,
        function_entry: Address,
    ) -> Self {
        Self {
            token_text: token_text.into(),
            color: (255, 255, 0, 100), // default: semi-transparent yellow
            function_entry,
            token_address: None,
        }
    }

    /// Create a new secondary highlight with a specific color.
    pub fn with_color(
        token_text: impl Into<String>,
        function_entry: Address,
        color: (u8, u8, u8, u8),
    ) -> Self {
        Self {
            token_text: token_text.into(),
            color,
            function_entry,
            token_address: None,
        }
    }

    /// Set the token address for disambiguation.
    pub fn with_address(mut self, addr: Address) -> Self {
        self.token_address = Some(addr);
        self
    }
}

// ---------------------------------------------------------------------------
// SecondaryHighlightManager
// ---------------------------------------------------------------------------

/// Manages secondary highlights for the decompiler panel.
///
/// Mirrors Ghidra's `ClangHighlightController` secondary highlight
/// functionality.  Supports per-token and per-function operations,
/// color management, and recent color history.
#[derive(Debug)]
pub struct SecondaryHighlightManager {
    /// Active highlights, keyed by token text.
    highlights: HashMap<String, SecondaryHighlight>,
    /// Recently used colors (most recent first).
    recent_colors: Vec<(u8, u8, u8, u8)>,
    /// Maximum number of recent colors to track.
    max_recent_colors: usize,
    /// Default highlight color.
    default_color: (u8, u8, u8, u8),
}

impl SecondaryHighlightManager {
    /// Create a new highlight manager.
    pub fn new() -> Self {
        Self {
            highlights: HashMap::new(),
            recent_colors: Vec::new(),
            max_recent_colors: 10,
            default_color: (255, 255, 0, 100),
        }
    }

    /// Add a secondary highlight for a token with the default color.
    ///
    /// Returns `true` if this is a new highlight; `false` if it replaced
    /// an existing one.
    pub fn set_highlight(
        &mut self,
        token_text: &str,
        function_entry: Address,
    ) -> bool {
        let highlight = SecondaryHighlight::new(token_text, function_entry);
        let is_new = !self.highlights.contains_key(token_text);
        self.highlights.insert(token_text.to_string(), highlight);
        is_new
    }

    /// Add a secondary highlight with a specific color.
    ///
    /// The color is added to the recent colors list.
    pub fn set_highlight_with_color(
        &mut self,
        token_text: &str,
        function_entry: Address,
        color: (u8, u8, u8, u8),
    ) -> bool {
        let highlight = SecondaryHighlight::with_color(token_text, function_entry, color);
        let is_new = !self.highlights.contains_key(token_text);
        self.highlights.insert(token_text.to_string(), highlight);
        self.add_recent_color(color);
        is_new
    }

    /// Remove the secondary highlight for a specific token.
    ///
    /// Returns `true` if the highlight existed and was removed.
    pub fn remove_highlight(&mut self, token_text: &str) -> bool {
        self.highlights.remove(token_text).is_some()
    }

    /// Remove all secondary highlights for a specific function.
    ///
    /// Returns the number of highlights removed.
    pub fn remove_highlights_for_function(&mut self, function_entry: Address) -> usize {
        let before = self.highlights.len();
        self.highlights
            .retain(|_, h| h.function_entry != function_entry);
        before - self.highlights.len()
    }

    /// Remove all secondary highlights.
    pub fn remove_all(&mut self) {
        self.highlights.clear();
    }

    /// Check if a specific token has a secondary highlight.
    pub fn has_highlight(&self, token_text: &str) -> bool {
        self.highlights.contains_key(token_text)
    }

    /// Check if any tokens in the given function have secondary highlights.
    pub fn has_highlights_for_function(&self, function_entry: Address) -> bool {
        self.highlights
            .values()
            .any(|h| h.function_entry == function_entry)
    }

    /// Get the highlight for a specific token.
    pub fn get_highlight(&self, token_text: &str) -> Option<&SecondaryHighlight> {
        self.highlights.get(token_text)
    }

    /// Get the color for a specific token's highlight.
    ///
    /// Returns the default color if no highlight exists.
    pub fn get_color(&self, token_text: &str) -> (u8, u8, u8, u8) {
        self.highlights
            .get(token_text)
            .map(|h| h.color)
            .unwrap_or(self.default_color)
    }

    /// Get the number of active highlights.
    pub fn count(&self) -> usize {
        self.highlights.len()
    }

    /// Check if there are any active highlights.
    pub fn is_empty(&self) -> bool {
        self.highlights.is_empty()
    }

    /// Get all highlights for a specific function.
    pub fn get_highlights_for_function(
        &self,
        function_entry: Address,
    ) -> Vec<&SecondaryHighlight> {
        self.highlights
            .values()
            .filter(|h| h.function_entry == function_entry)
            .collect()
    }

    /// Get the recent colors list.
    pub fn get_recent_colors(&self) -> &[(u8, u8, u8, u8)] {
        &self.recent_colors
    }

    /// Set the default highlight color.
    pub fn set_default_color(&mut self, color: (u8, u8, u8, u8)) {
        self.default_color = color;
    }

    /// Get the default highlight color.
    pub fn default_color(&self) -> (u8, u8, u8, u8) {
        self.default_color
    }

    /// Add a color to the recent colors list.
    fn add_recent_color(&mut self, color: (u8, u8, u8, u8)) {
        // Remove if already present.
        self.recent_colors.retain(|c| *c != color);
        // Add to front.
        self.recent_colors.insert(0, color);
        // Trim to max.
        if self.recent_colors.len() > self.max_recent_colors {
            self.recent_colors.truncate(self.max_recent_colors);
        }
    }
}

impl Default for SecondaryHighlightManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SetSecondaryHighlightAction
// ---------------------------------------------------------------------------

/// Action: Set a secondary highlight on the token at the cursor.
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.SetSecondaryHighlightAction`.
/// Uses the default highlight color.
#[derive(Debug, Default)]
pub struct SetSecondaryHighlightAction;

impl SetSecondaryHighlightAction {
    /// The action name.
    pub const NAME: &'static str = "Set Secondary Highlight";

    /// The menu path.
    pub const MENU_PATH: [&'static str; 2] = ["Secondary Highlight", "Set Highlight"];

    /// Check if this action is enabled for the given context.
    ///
    /// Requires a real function and a token at the cursor.
    pub fn is_enabled(
        &self,
        has_real_function: bool,
        token_text: Option<&str>,
    ) -> bool {
        has_real_function && token_text.is_some()
    }

    /// Execute the action: add a secondary highlight for the token.
    pub fn execute(
        &self,
        manager: &mut SecondaryHighlightManager,
        token_text: &str,
        function_entry: Address,
    ) -> bool {
        manager.set_highlight(token_text, function_entry)
    }
}

// ---------------------------------------------------------------------------
// RemoveSecondaryHighlightAction
// ---------------------------------------------------------------------------

/// Action: Remove the secondary highlight from the token at the cursor.
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.RemoveSecondaryHighlightAction`.
#[derive(Debug, Default)]
pub struct RemoveSecondaryHighlightAction;

impl RemoveSecondaryHighlightAction {
    /// The action name.
    pub const NAME: &'static str = "Remove Secondary Highlight";

    /// The menu path.
    pub const MENU_PATH: [&'static str; 2] = ["Secondary Highlight", "Remove Highlight"];

    /// Check if this action is enabled for the given context.
    ///
    /// Requires a real function, a token at the cursor, and that token
    /// must have an existing secondary highlight.
    pub fn is_enabled(
        &self,
        has_real_function: bool,
        token_text: Option<&str>,
        manager: &SecondaryHighlightManager,
    ) -> bool {
        if !has_real_function {
            return false;
        }
        match token_text {
            Some(text) => manager.has_highlight(text),
            None => false,
        }
    }

    /// Execute the action: remove the secondary highlight for the token.
    pub fn execute(
        &self,
        manager: &mut SecondaryHighlightManager,
        token_text: &str,
    ) -> bool {
        manager.remove_highlight(token_text)
    }
}

// ---------------------------------------------------------------------------
// RemoveAllSecondaryHighlightsAction
// ---------------------------------------------------------------------------

/// Action: Remove all secondary highlights for the current function.
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.RemoveAllSecondaryHighlightsAction`.
#[derive(Debug, Default)]
pub struct RemoveAllSecondaryHighlightsAction;

impl RemoveAllSecondaryHighlightsAction {
    /// The action name.
    pub const NAME: &'static str = "Remove All Secondary Highlights";

    /// The menu path.
    pub const MENU_PATH: [&'static str; 2] = ["Secondary Highlight", "Remove All Highlights"];

    /// Check if this action is enabled for the given context.
    ///
    /// Requires a real function and at least one secondary highlight in
    /// that function.
    pub fn is_enabled(
        &self,
        has_real_function: bool,
        function_entry: Option<Address>,
        manager: &SecondaryHighlightManager,
    ) -> bool {
        if !has_real_function {
            return false;
        }
        match function_entry {
            Some(entry) => manager.has_highlights_for_function(entry),
            None => false,
        }
    }

    /// Execute the action: remove all highlights for the function.
    ///
    /// Returns the number of highlights removed.
    pub fn execute(
        &self,
        manager: &mut SecondaryHighlightManager,
        function_entry: Address,
    ) -> usize {
        manager.remove_highlights_for_function(function_entry)
    }
}

// ---------------------------------------------------------------------------
// SetSecondaryHighlightColorChooserAction
// ---------------------------------------------------------------------------

/// Action: Set a secondary highlight with a user-chosen color.
///
/// Ported from `ghidra.app.plugin.core.decompile.actions.SetSecondaryHighlightColorChooserAction`.
/// Presents a color chooser dialog and applies the chosen color to the
/// token's secondary highlight.
#[derive(Debug, Default)]
pub struct SetSecondaryHighlightColorChooserAction;

impl SetSecondaryHighlightColorChooserAction {
    /// The action name.
    pub const NAME: &'static str = "Set Secondary Highlight With Color";

    /// The menu path.
    pub const MENU_PATH: [&'static str; 2] = ["Secondary Highlight", "Set Highlight..."];

    /// Check if this action is enabled for the given context.
    ///
    /// Same conditions as `SetSecondaryHighlightAction`.
    pub fn is_enabled(
        &self,
        has_real_function: bool,
        token_text: Option<&str>,
    ) -> bool {
        has_real_function && token_text.is_some()
    }

    /// Execute the action: add a secondary highlight with a specific color.
    ///
    /// The color is added to the manager's recent colors list.
    pub fn execute(
        &self,
        manager: &mut SecondaryHighlightManager,
        token_text: &str,
        function_entry: Address,
        color: (u8, u8, u8, u8),
    ) -> bool {
        manager.set_highlight_with_color(token_text, function_entry, color)
    }

    /// Get the current color for a token (for pre-filling the color chooser).
    ///
    /// Returns the token's existing highlight color, or the default color.
    pub fn get_current_color(
        &self,
        manager: &SecondaryHighlightManager,
        token_text: &str,
    ) -> (u8, u8, u8, u8) {
        manager.get_color(token_text)
    }

    /// Get the recent colors for the color chooser history.
    pub fn get_recent_colors<'a>(
        &self,
        manager: &'a SecondaryHighlightManager,
    ) -> &'a [(u8, u8, u8, u8)] {
        manager.get_recent_colors()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- SecondaryHighlight ---

    #[test]
    fn test_highlight_new() {
        let h = SecondaryHighlight::new("x", Address::new(0x1000));
        assert_eq!(h.token_text, "x");
        assert_eq!(h.function_entry, Address::new(0x1000));
        assert_eq!(h.color, (255, 255, 0, 100));
        assert!(h.token_address.is_none());
    }

    #[test]
    fn test_highlight_with_color() {
        let h = SecondaryHighlight::with_color("y", Address::new(0x2000), (255, 0, 0, 200));
        assert_eq!(h.color, (255, 0, 0, 200));
    }

    #[test]
    fn test_highlight_with_address() {
        let h = SecondaryHighlight::new("z", Address::new(0x3000))
            .with_address(Address::new(0x3004));
        assert_eq!(h.token_address, Some(Address::new(0x3004)));
    }

    // --- SecondaryHighlightManager ---

    #[test]
    fn test_manager_new() {
        let mgr = SecondaryHighlightManager::new();
        assert!(mgr.is_empty());
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_manager_set_highlight() {
        let mut mgr = SecondaryHighlightManager::new();
        let is_new = mgr.set_highlight("x", Address::new(0x1000));
        assert!(is_new);
        assert_eq!(mgr.count(), 1);
        assert!(mgr.has_highlight("x"));
    }

    #[test]
    fn test_manager_set_highlight_replace() {
        let mut mgr = SecondaryHighlightManager::new();
        mgr.set_highlight("x", Address::new(0x1000));
        let is_new = mgr.set_highlight("x", Address::new(0x2000));
        assert!(!is_new);
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_manager_set_highlight_with_color() {
        let mut mgr = SecondaryHighlightManager::new();
        mgr.set_highlight_with_color("x", Address::new(0x1000), (255, 0, 0, 128));
        assert_eq!(mgr.get_color("x"), (255, 0, 0, 128));
        assert_eq!(mgr.get_recent_colors().len(), 1);
    }

    #[test]
    fn test_manager_remove_highlight() {
        let mut mgr = SecondaryHighlightManager::new();
        mgr.set_highlight("x", Address::new(0x1000));
        assert!(mgr.remove_highlight("x"));
        assert!(!mgr.has_highlight("x"));
        assert_eq!(mgr.count(), 0);
        assert!(!mgr.remove_highlight("x")); // already removed
    }

    #[test]
    fn test_manager_remove_for_function() {
        let mut mgr = SecondaryHighlightManager::new();
        mgr.set_highlight("a", Address::new(0x1000));
        mgr.set_highlight("b", Address::new(0x1000));
        mgr.set_highlight("c", Address::new(0x2000));

        let removed = mgr.remove_highlights_for_function(Address::new(0x1000));
        assert_eq!(removed, 2);
        assert_eq!(mgr.count(), 1);
        assert!(mgr.has_highlight("c"));
    }

    #[test]
    fn test_manager_remove_all() {
        let mut mgr = SecondaryHighlightManager::new();
        mgr.set_highlight("a", Address::new(0x1000));
        mgr.set_highlight("b", Address::new(0x2000));
        mgr.remove_all();
        assert!(mgr.is_empty());
    }

    #[test]
    fn test_manager_has_highlights_for_function() {
        let mut mgr = SecondaryHighlightManager::new();
        assert!(!mgr.has_highlights_for_function(Address::new(0x1000)));

        mgr.set_highlight("x", Address::new(0x1000));
        assert!(mgr.has_highlights_for_function(Address::new(0x1000)));
        assert!(!mgr.has_highlights_for_function(Address::new(0x2000)));
    }

    #[test]
    fn test_manager_get_highlights_for_function() {
        let mut mgr = SecondaryHighlightManager::new();
        mgr.set_highlight("a", Address::new(0x1000));
        mgr.set_highlight("b", Address::new(0x1000));
        mgr.set_highlight("c", Address::new(0x2000));

        let highlights = mgr.get_highlights_for_function(Address::new(0x1000));
        assert_eq!(highlights.len(), 2);
    }

    #[test]
    fn test_manager_recent_colors() {
        let mut mgr = SecondaryHighlightManager::new();
        mgr.set_highlight_with_color("a", Address::new(0x1000), (255, 0, 0, 100));
        mgr.set_highlight_with_color("b", Address::new(0x1000), (0, 255, 0, 100));
        mgr.set_highlight_with_color("c", Address::new(0x1000), (0, 0, 255, 100));

        let colors = mgr.get_recent_colors();
        assert_eq!(colors.len(), 3);
        // Most recent first.
        assert_eq!(colors[0], (0, 0, 255, 100));
        assert_eq!(colors[1], (0, 255, 0, 100));
        assert_eq!(colors[2], (255, 0, 0, 100));
    }

    #[test]
    fn test_manager_recent_colors_dedup() {
        let mut mgr = SecondaryHighlightManager::new();
        mgr.set_highlight_with_color("a", Address::new(0x1000), (255, 0, 0, 100));
        mgr.set_highlight_with_color("b", Address::new(0x1000), (0, 255, 0, 100));
        mgr.set_highlight_with_color("c", Address::new(0x1000), (255, 0, 0, 100)); // duplicate

        let colors = mgr.get_recent_colors();
        assert_eq!(colors.len(), 2);
        // The duplicate was moved to front.
        assert_eq!(colors[0], (255, 0, 0, 100));
        assert_eq!(colors[1], (0, 255, 0, 100));
    }

    #[test]
    fn test_manager_default_color() {
        let mut mgr = SecondaryHighlightManager::new();
        assert_eq!(mgr.default_color(), (255, 255, 0, 100));

        mgr.set_default_color((0, 255, 255, 200));
        assert_eq!(mgr.default_color(), (0, 255, 255, 200));
    }

    #[test]
    fn test_manager_get_color_default() {
        let mgr = SecondaryHighlightManager::new();
        assert_eq!(mgr.get_color("nonexistent"), (255, 255, 0, 100));
    }

    // --- SetSecondaryHighlightAction ---

    #[test]
    fn test_set_action_metadata() {
        let action = SetSecondaryHighlightAction;
        assert_eq!(SetSecondaryHighlightAction::NAME, "Set Secondary Highlight");
    }

    #[test]
    fn test_set_action_enabled() {
        let action = SetSecondaryHighlightAction;
        assert!(action.is_enabled(true, Some("x")));
        assert!(!action.is_enabled(false, Some("x")));
        assert!(!action.is_enabled(true, None));
    }

    #[test]
    fn test_set_action_execute() {
        let action = SetSecondaryHighlightAction;
        let mut mgr = SecondaryHighlightManager::new();
        let is_new = action.execute(&mut mgr, "x", Address::new(0x1000));
        assert!(is_new);
        assert!(mgr.has_highlight("x"));
    }

    // --- RemoveSecondaryHighlightAction ---

    #[test]
    fn test_remove_action_enabled() {
        let action = RemoveSecondaryHighlightAction;
        let mut mgr = SecondaryHighlightManager::new();
        mgr.set_highlight("x", Address::new(0x1000));

        assert!(action.is_enabled(true, Some("x"), &mgr));
        assert!(!action.is_enabled(true, Some("y"), &mgr));
        assert!(!action.is_enabled(false, Some("x"), &mgr));
        assert!(!action.is_enabled(true, None, &mgr));
    }

    #[test]
    fn test_remove_action_execute() {
        let action = RemoveSecondaryHighlightAction;
        let mut mgr = SecondaryHighlightManager::new();
        mgr.set_highlight("x", Address::new(0x1000));

        assert!(action.execute(&mut mgr, "x"));
        assert!(!mgr.has_highlight("x"));
    }

    // --- RemoveAllSecondaryHighlightsAction ---

    #[test]
    fn test_remove_all_action_enabled() {
        let action = RemoveAllSecondaryHighlightsAction;
        let mut mgr = SecondaryHighlightManager::new();
        mgr.set_highlight("x", Address::new(0x1000));

        assert!(action.is_enabled(true, Some(Address::new(0x1000)), &mgr));
        assert!(!action.is_enabled(true, Some(Address::new(0x2000)), &mgr));
        assert!(!action.is_enabled(false, Some(Address::new(0x1000)), &mgr));
    }

    #[test]
    fn test_remove_all_action_execute() {
        let action = RemoveAllSecondaryHighlightsAction;
        let mut mgr = SecondaryHighlightManager::new();
        mgr.set_highlight("a", Address::new(0x1000));
        mgr.set_highlight("b", Address::new(0x1000));
        mgr.set_highlight("c", Address::new(0x2000));

        let removed = action.execute(&mut mgr, Address::new(0x1000));
        assert_eq!(removed, 2);
        assert_eq!(mgr.count(), 1);
    }

    // --- SetSecondaryHighlightColorChooserAction ---

    #[test]
    fn test_color_chooser_action_enabled() {
        let action = SetSecondaryHighlightColorChooserAction;
        assert!(action.is_enabled(true, Some("x")));
        assert!(!action.is_enabled(false, Some("x")));
        assert!(!action.is_enabled(true, None));
    }

    #[test]
    fn test_color_chooser_action_execute() {
        let action = SetSecondaryHighlightColorChooserAction;
        let mut mgr = SecondaryHighlightManager::new();
        let is_new = action.execute(
            &mut mgr,
            "x",
            Address::new(0x1000),
            (255, 0, 0, 200),
        );
        assert!(is_new);
        assert_eq!(mgr.get_color("x"), (255, 0, 0, 200));
    }

    #[test]
    fn test_color_chooser_get_current_color() {
        let action = SetSecondaryHighlightColorChooserAction;
        let mut mgr = SecondaryHighlightManager::new();
        mgr.set_highlight_with_color("x", Address::new(0x1000), (0, 255, 0, 128));

        assert_eq!(action.get_current_color(&mgr, "x"), (0, 255, 0, 128));
        assert_eq!(
            action.get_current_color(&mgr, "y"),
            mgr.default_color()
        );
    }

    #[test]
    fn test_color_chooser_get_recent_colors() {
        let action = SetSecondaryHighlightColorChooserAction;
        let mut mgr = SecondaryHighlightManager::new();
        mgr.set_highlight_with_color("a", Address::new(0x1000), (255, 0, 0, 100));
        mgr.set_highlight_with_color("b", Address::new(0x1000), (0, 255, 0, 100));

        let colors = action.get_recent_colors(&mgr);
        assert_eq!(colors.len(), 2);
    }
}
