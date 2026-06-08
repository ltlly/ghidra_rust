//! Secondary highlight actions -- Rust port of
//! `AbstractSetSecondaryHighlightAction`, `SetSecondaryHighlightAction`,
//! `RemoveSecondaryHighlightAction`, `RemoveAllSecondaryHighlightsAction`,
//! and `SetSecondaryHighlightColorChooserAction` from
//! `ghidra.app.plugin.core.decompile.actions`.
//!
//! These actions manage "secondary highlights" in the decompiler panel.
//! Secondary highlights are user-applied colour marks on individual tokens,
//! distinct from the primary (middle-mouse) highlights.
//!
//! # Architecture
//!
//! ```text
//! AbstractSetSecondaryHighlightAction (trait)
//!   ├── SetSecondaryHighlightAction       -- adds a default-color highlight
//!   └── SetSecondaryHighlightColorChooserAction -- adds with user-chosen colour
//!
//! RemoveSecondaryHighlightAction   -- removes highlight from cursor token
//! RemoveAllSecondaryHighlightsAction -- removes all highlights in function
//! ```

use super::action_context::DecompilerActionContext;
use super::actions::DecompilerAction;

// ---------------------------------------------------------------------------
// SecondaryHighlightColor -- represents an RGBA highlight colour
// ---------------------------------------------------------------------------

/// An RGBA colour used for secondary highlights.
///
/// In the Java source this maps to `java.awt.Color`; we represent it as
/// four `u8` components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SecondaryHighlightColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl SecondaryHighlightColor {
    /// Create a new colour.
    pub const fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Create from an RGB value with full opacity.
    pub const fn from_rgb(r: u8, g: u8, b: u8) -> Self {
        Self::new(r, g, b, 255)
    }

    /// A warm yellow, the default secondary highlight colour in Ghidra.
    pub const DEFAULT: Self = Self::from_rgb(255, 255, 180);
}

impl Default for SecondaryHighlightColor {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl std::fmt::Display for SecondaryHighlightColor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{:02x}{:02x}{:02x}{:02x}", self.r, self.g, self.b, self.a)
    }
}

// ---------------------------------------------------------------------------
// TokenHighlightRecord -- a stored highlight on a specific token
// ---------------------------------------------------------------------------

/// Record of a secondary highlight applied to a token.
#[derive(Debug, Clone)]
pub struct TokenHighlightRecord {
    /// The text of the token that was highlighted.
    pub token_text: String,
    /// The colour used for this highlight.
    pub color: SecondaryHighlightColor,
    /// Address of the function this highlight belongs to.
    pub function_entry: u64,
}

// ---------------------------------------------------------------------------
// RecentColorList -- tracks recently used highlight colours
// ---------------------------------------------------------------------------

/// A bounded list of recently used highlight colours, mirroring
/// `TokenHighlightColors.getRecentColors()`.
#[derive(Debug, Clone)]
pub struct RecentColorList {
    colors: Vec<SecondaryHighlightColor>,
    max_size: usize,
}

impl RecentColorList {
    /// Create a new list with the given capacity.
    pub fn new(max_size: usize) -> Self {
        Self {
            colors: Vec::with_capacity(max_size),
            max_size,
        }
    }

    /// Record a colour as recently used.  Moves it to the front if it
    /// already exists.
    pub fn record(&mut self, color: SecondaryHighlightColor) {
        self.colors.retain(|c| *c != color);
        self.colors.insert(0, color);
        if self.colors.len() > self.max_size {
            self.colors.truncate(self.max_size);
        }
    }

    /// Return the list of recent colours, most-recent first.
    pub fn recent(&self) -> &[SecondaryHighlightColor] {
        &self.colors
    }

    /// Number of recorded colours.
    pub fn len(&self) -> usize {
        self.colors.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.colors.is_empty()
    }
}

impl Default for RecentColorList {
    fn default() -> Self {
        Self::new(16)
    }
}

// ---------------------------------------------------------------------------
// SecondaryHighlightStore -- the backing store for all secondary highlights
// ---------------------------------------------------------------------------

/// Central store for secondary highlight records, keyed by function entry
/// address and token text.
///
/// Mirrors the behaviour of `DecompilerPanel`'s internal highlight maps.
#[derive(Debug, Clone, Default)]
pub struct SecondaryHighlightStore {
    /// `function_entry -> (token_text -> colour)`.
    highlights: std::collections::HashMap<u64, std::collections::HashMap<String, SecondaryHighlightColor>>,
    recent_colors: RecentColorList,
}

impl SecondaryHighlightStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a highlight for a token in a function with the default colour.
    pub fn add_highlight(&mut self, function_entry: u64, token_text: &str) {
        self.add_highlight_with_color(function_entry, token_text, SecondaryHighlightColor::DEFAULT);
    }

    /// Add a highlight for a token in a function with a specific colour.
    pub fn add_highlight_with_color(
        &mut self,
        function_entry: u64,
        token_text: &str,
        color: SecondaryHighlightColor,
    ) {
        self.recent_colors.record(color);
        self.highlights
            .entry(function_entry)
            .or_default()
            .insert(token_text.to_string(), color);
    }

    /// Remove the highlight for a specific token in a function.
    ///
    /// Returns `true` if a highlight was actually removed.
    pub fn remove_highlight(&mut self, function_entry: u64, token_text: &str) -> bool {
        if let Some(func_highlights) = self.highlights.get_mut(&function_entry) {
            return func_highlights.remove(token_text).is_some();
        }
        false
    }

    /// Remove all highlights for a function.
    ///
    /// Returns `true` if any highlights were removed.
    pub fn remove_all_for_function(&mut self, function_entry: u64) -> bool {
        self.highlights.remove(&function_entry).is_some()
    }

    /// Check whether a specific token in a function has a secondary highlight.
    pub fn has_highlight(&self, function_entry: u64, token_text: &str) -> bool {
        self.highlights
            .get(&function_entry)
            .map_or(false, |m| m.contains_key(token_text))
    }

    /// Check whether a function has any secondary highlights.
    pub fn has_any_highlight(&self, function_entry: u64) -> bool {
        self.highlights
            .get(&function_entry)
            .map_or(false, |m| !m.is_empty())
    }

    /// Get the colour for a highlighted token, if present.
    pub fn get_color(&self, function_entry: u64, token_text: &str) -> Option<SecondaryHighlightColor> {
        self.highlights
            .get(&function_entry)
            .and_then(|m| m.get(token_text).copied())
    }

    /// Get the recent colour list.
    pub fn recent_colors(&self) -> &RecentColorList {
        &self.recent_colors
    }

    /// Get a mutable reference to the recent colour list.
    pub fn recent_colors_mut(&mut self) -> &mut RecentColorList {
        &mut self.recent_colors
    }

    /// Total number of highlighted tokens across all functions.
    pub fn total_highlight_count(&self) -> usize {
        self.highlights.values().map(|m| m.len()).sum()
    }

    /// Clear all highlights in the store.
    pub fn clear(&mut self) {
        self.highlights.clear();
    }

    /// Whether any highlights exist across all functions.
    pub fn has_highlights(&self) -> bool {
        !self.highlights.is_empty() && self.highlights.values().any(|m| !m.is_empty())
    }
}

// ---------------------------------------------------------------------------
// SetSecondaryHighlightAction
// ---------------------------------------------------------------------------

/// Sets the secondary highlight on the token at the cursor position
/// using the default colour.
///
/// Corresponds to Java's `SetSecondaryHighlightAction`.
#[derive(Debug, Clone, Default)]
pub struct SetSecondaryHighlightAction;

impl SetSecondaryHighlightAction {
    pub const NAME: &'static str = "Set Secondary Highlight";
    pub const MENU_PATH: &[&str] = &["Secondary Highlight", "Set Highlight"];

    pub fn new() -> Self {
        Self
    }
}

impl DecompilerAction for SetSecondaryHighlightAction {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        "Set a secondary highlight on the token at the cursor"
    }

    fn is_enabled(&self, context: &DecompilerActionContext) -> bool {
        if !context.has_real_function() {
            return false;
        }
        context.token_at_cursor().is_some()
    }

    fn perform(&self, context: &mut DecompilerActionContext) -> bool {
        if let Some(token_text) = context.token_text_at_cursor() {
            let entry = context.function_entry();
            context
                .secondary_highlight_store_mut()
                .add_highlight(entry, &token_text);
            return true;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// SetSecondaryHighlightColorChooserAction
// ---------------------------------------------------------------------------

/// Sets the secondary highlight on the token at the cursor position,
/// prompting the user to choose a colour via a colour-chooser dialog.
///
/// Corresponds to Java's `SetSecondaryHighlightColorChooserAction`.
#[derive(Debug, Clone, Default)]
pub struct SetSecondaryHighlightColorChooserAction;

impl SetSecondaryHighlightColorChooserAction {
    pub const NAME: &'static str = "Set Secondary Highlight With Color";
    pub const MENU_PATH: &[&str] = &["Secondary Highlight", "Set Highlight..."];

    pub fn new() -> Self {
        Self
    }
}

impl DecompilerAction for SetSecondaryHighlightColorChooserAction {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        "Set a secondary highlight with a user-chosen color"
    }

    fn is_enabled(&self, context: &DecompilerActionContext) -> bool {
        if !context.has_real_function() {
            return false;
        }
        context.token_at_cursor().is_some()
    }

    fn perform(&self, context: &mut DecompilerActionContext) -> bool {
        if let Some(token_text) = context.token_text_at_cursor() {
            // In a full GUI integration this would open a GhidraColorChooser.
            // Here we apply the default colour; the caller can override by
            // providing a chosen colour through the context's dialog mechanism.
            let entry = context.function_entry();
            let store = context.secondary_highlight_store_mut();
            let current_color = store
                .get_color(entry, &token_text)
                .unwrap_or(SecondaryHighlightColor::DEFAULT);

            // Record the current colour in the recent list so the chooser
            // can present it as a starting point.
            store.recent_colors_mut().record(current_color);
            store.add_highlight_with_color(entry, &token_text, current_color);
            return true;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// RemoveSecondaryHighlightAction
// ---------------------------------------------------------------------------

/// Removes the secondary highlight from the token at the cursor position.
///
/// Corresponds to Java's `RemoveSecondaryHighlightAction`.
#[derive(Debug, Clone, Default)]
pub struct RemoveSecondaryHighlightAction;

impl RemoveSecondaryHighlightAction {
    pub const NAME: &'static str = "Remove Secondary Highlight";
    pub const MENU_PATH: &[&str] = &["Secondary Highlight", "Remove Highlight"];

    pub fn new() -> Self {
        Self
    }
}

impl DecompilerAction for RemoveSecondaryHighlightAction {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        "Remove the secondary highlight from the token at the cursor"
    }

    fn is_enabled(&self, context: &DecompilerActionContext) -> bool {
        if !context.has_real_function() {
            return false;
        }
        if let Some(token_text) = context.token_text_at_cursor() {
            let entry = context.function_entry();
            return context
                .secondary_highlight_store()
                .has_highlight(entry, &token_text);
        }
        false
    }

    fn perform(&self, context: &mut DecompilerActionContext) -> bool {
        if let Some(token_text) = context.token_text_at_cursor() {
            let entry = context.function_entry();
            return context
                .secondary_highlight_store_mut()
                .remove_highlight(entry, &token_text);
        }
        false
    }
}

// ---------------------------------------------------------------------------
// RemoveAllSecondaryHighlightsAction
// ---------------------------------------------------------------------------

/// Removes all secondary highlights for the current function.
///
/// Corresponds to Java's `RemoveAllSecondaryHighlightsAction`.
#[derive(Debug, Clone, Default)]
pub struct RemoveAllSecondaryHighlightsAction;

impl RemoveAllSecondaryHighlightsAction {
    pub const NAME: &'static str = "Remove All Secondary Highlights";
    pub const MENU_PATH: &[&str] = &["Secondary Highlight", "Remove All Highlights"];

    pub fn new() -> Self {
        Self
    }
}

impl DecompilerAction for RemoveAllSecondaryHighlightsAction {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        "Remove all secondary highlights for the current function"
    }

    fn is_enabled(&self, context: &DecompilerActionContext) -> bool {
        if !context.has_real_function() {
            return false;
        }
        let entry = context.function_entry();
        context
            .secondary_highlight_store()
            .has_any_highlight(entry)
    }

    fn perform(&self, context: &mut DecompilerActionContext) -> bool {
        let entry = context.function_entry();
        context
            .secondary_highlight_store_mut()
            .remove_all_for_function(entry)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secondary_highlight_color_display() {
        let c = SecondaryHighlightColor::from_rgb(0xAB, 0xCD, 0xEF);
        assert_eq!(c.to_string(), "#abcdefff");
        let c2 = SecondaryHighlightColor::new(0, 0, 0, 255);
        assert_eq!(c2.to_string(), "#000000ff");
    }

    #[test]
    fn recent_color_list_records_and_deduplicates() {
        let mut list = RecentColorList::new(3);
        let red = SecondaryHighlightColor::from_rgb(255, 0, 0);
        let green = SecondaryHighlightColor::from_rgb(0, 255, 0);
        let blue = SecondaryHighlightColor::from_rgb(0, 0, 255);

        list.record(red);
        list.record(green);
        assert_eq!(list.len(), 2);

        // Re-recording red moves it to front.
        list.record(red);
        assert_eq!(list.len(), 2);
        assert_eq!(list.recent()[0], red);
        assert_eq!(list.recent()[1], green);

        list.record(blue);
        assert_eq!(list.len(), 3);

        // One more pushes the oldest out.
        let yellow = SecondaryHighlightColor::from_rgb(255, 255, 0);
        list.record(yellow);
        assert_eq!(list.len(), 3);
        assert_eq!(list.recent()[0], yellow);
    }

    #[test]
    fn highlight_store_add_remove() {
        let mut store = SecondaryHighlightStore::new();
        let entry = 0x1000u64;

        assert!(!store.has_highlight(entry, "x"));
        assert!(!store.has_any_highlight(entry));

        store.add_highlight(entry, "x");
        assert!(store.has_highlight(entry, "x"));
        assert!(store.has_any_highlight(entry));
        assert_eq!(store.total_highlight_count(), 1);

        store.add_highlight_with_color(
            entry,
            "y",
            SecondaryHighlightColor::from_rgb(255, 0, 0),
        );
        assert_eq!(store.total_highlight_count(), 2);

        assert!(store.remove_highlight(entry, "x"));
        assert!(!store.has_highlight(entry, "x"));
        assert!(store.has_highlight(entry, "y"));

        assert!(store.remove_all_for_function(entry));
        assert!(!store.has_any_highlight(entry));
        assert_eq!(store.total_highlight_count(), 0);
    }

    #[test]
    fn highlight_store_get_color() {
        let mut store = SecondaryHighlightStore::new();
        let entry = 0x2000u64;
        let color = SecondaryHighlightColor::from_rgb(10, 20, 30);

        store.add_highlight_with_color(entry, "foo", color);
        assert_eq!(store.get_color(entry, "foo"), Some(color));
        assert_eq!(store.get_color(entry, "bar"), None);
    }

    #[test]
    fn highlight_store_separate_functions() {
        let mut store = SecondaryHighlightStore::new();
        store.add_highlight(0x1000, "x");
        store.add_highlight(0x2000, "x");

        assert!(store.has_highlight(0x1000, "x"));
        assert!(store.has_highlight(0x2000, "x"));

        store.remove_highlight(0x1000, "x");
        assert!(!store.has_highlight(0x1000, "x"));
        assert!(store.has_highlight(0x2000, "x"));
    }
}
