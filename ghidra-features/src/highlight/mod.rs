//! Highlight Plugin -- highlight matching text and patterns.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.highlight` Java package.
//!
//! Provides logic for highlighting addresses in the listing based on
//! text matching, address ranges, and named highlight groups. Supports
//! a provider-based system where different highlight sources can
//! contribute colors independently.
//!
//! # Key Types
//!
//! - [`HighlightColor`] -- RGBA highlight color
//! - [`HighlightEntry`] -- a single highlighted address
//! - [`HighlightGroup`] -- a named group of highlights that can be toggled
//! - [`HighlightManager`] -- manages highlights with group support

use ghidra_core::Address;
use std::collections::HashMap;

/// A highlight color specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HighlightColor {
    /// Red component (0-255).
    pub r: u8,
    /// Green component (0-255).
    pub g: u8,
    /// Blue component (0-255).
    pub b: u8,
    /// Alpha (transparency) component (0-255).
    pub a: u8,
}

impl HighlightColor {
    /// Create a new highlight color.
    pub fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Yellow highlight.
    pub fn yellow() -> Self {
        Self::new(255, 255, 0, 128)
    }

    /// Green highlight.
    pub fn green() -> Self {
        Self::new(0, 255, 0, 128)
    }

    /// Red highlight.
    pub fn red() -> Self {
        Self::new(255, 0, 0, 128)
    }

    /// Cyan highlight.
    pub fn cyan() -> Self {
        Self::new(0, 255, 255, 128)
    }

    /// Blue highlight.
    pub fn blue() -> Self {
        Self::new(0, 100, 255, 128)
    }

    /// Orange highlight.
    pub fn orange() -> Self {
        Self::new(255, 165, 0, 128)
    }

    /// Whether two highlight colors have the same RGBA values.
    pub fn rgba_equals(&self, other: &HighlightColor) -> bool {
        self.r == other.r && self.g == other.g && self.b == other.b && self.a == other.a
    }
}

/// A highlight entry at a specific address.
#[derive(Debug, Clone)]
pub struct HighlightEntry {
    /// The address to highlight.
    pub address: Address,
    /// The highlight color.
    pub color: HighlightColor,
    /// The highlighted text (optional).
    pub text: Option<String>,
    /// The group this entry belongs to.
    pub group: String,
}

// ---------------------------------------------------------------------------
// HighlightGroup -- a named, toggleable group of highlights
// ---------------------------------------------------------------------------

/// A named group of highlights that can be independently toggled on/off.
#[derive(Debug, Clone)]
pub struct HighlightGroup {
    /// The group name.
    pub name: String,
    /// Whether this group is currently visible.
    pub enabled: bool,
    /// The default color for highlights in this group.
    pub default_color: HighlightColor,
}

impl HighlightGroup {
    /// Create a new highlight group.
    pub fn new(name: impl Into<String>, default_color: HighlightColor) -> Self {
        Self {
            name: name.into(),
            enabled: true,
            default_color,
        }
    }
}

// ---------------------------------------------------------------------------
// HighlightManager
// ---------------------------------------------------------------------------

/// Manages highlights in the listing with group support.
///
/// Ported from `ghidra.app.plugin.core.highlight.HighlightManager`.
#[derive(Debug, Default)]
pub struct HighlightManager {
    /// All highlight entries keyed by address offset.
    entries: HashMap<u64, HighlightEntry>,
    /// Named groups for organizing highlights.
    groups: HashMap<String, HighlightGroup>,
}

impl HighlightManager {
    /// Create a new highlight manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a highlight group.
    pub fn register_group(&mut self, group: HighlightGroup) {
        self.groups.insert(group.name.clone(), group);
    }

    /// Toggle a group on/off.
    pub fn set_group_enabled(&mut self, group_name: &str, enabled: bool) {
        if let Some(group) = self.groups.get_mut(group_name) {
            group.enabled = enabled;
        }
    }

    /// Check if a group is enabled.
    pub fn is_group_enabled(&self, group_name: &str) -> bool {
        self.groups
            .get(group_name)
            .map(|g| g.enabled)
            .unwrap_or(false)
    }

    /// Set a highlight at an address in the default group.
    pub fn set_highlight(&mut self, address: Address, color: HighlightColor) {
        self.set_highlight_in_group(address, color, "default");
    }

    /// Set a highlight at an address in a specific group.
    pub fn set_highlight_in_group(
        &mut self,
        address: Address,
        color: HighlightColor,
        group_name: &str,
    ) {
        self.entries.insert(
            address.offset,
            HighlightEntry {
                address,
                color,
                text: None,
                group: group_name.to_string(),
            },
        );
    }

    /// Set a highlight with associated text.
    pub fn set_highlight_with_text(
        &mut self,
        address: Address,
        color: HighlightColor,
        text: impl Into<String>,
    ) {
        self.entries.insert(
            address.offset,
            HighlightEntry {
                address,
                color,
                text: Some(text.into()),
                group: "default".to_string(),
            },
        );
    }

    /// Remove a highlight at an address.
    pub fn remove_highlight(&mut self, address: Address) {
        self.entries.remove(&address.offset);
    }

    /// Get the highlight at an address (respects group visibility).
    pub fn get_highlight(&self, address: Address) -> Option<&HighlightEntry> {
        self.entries.get(&address.offset).filter(|e| {
            self.groups
                .get(&e.group)
                .map(|g| g.enabled)
                .unwrap_or(true)
        })
    }

    /// Get the raw highlight at an address (ignoring group visibility).
    pub fn get_raw_highlight(&self, address: Address) -> Option<&HighlightEntry> {
        self.entries.get(&address.offset)
    }

    /// Check if an address has a visible highlight.
    pub fn is_highlighted(&self, address: Address) -> bool {
        self.get_highlight(address).is_some()
    }

    /// Clear all highlights in a specific group.
    pub fn clear_group(&mut self, group_name: &str) {
        self.entries.retain(|_, e| e.group != group_name);
    }

    /// Clear all highlights.
    pub fn clear_all(&mut self) {
        self.entries.clear();
    }

    /// Return the number of highlighted addresses (all groups).
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Return the number of highlighted addresses in a specific group.
    pub fn count_in_group(&self, group_name: &str) -> usize {
        self.entries.values().filter(|e| e.group == group_name).count()
    }

    /// Search for highlights whose text contains the given query
    /// (case-insensitive).
    pub fn search_by_text(&self, query: &str) -> Vec<&HighlightEntry> {
        let q = query.to_lowercase();
        self.entries
            .values()
            .filter(|e| {
                e.text
                    .as_ref()
                    .map(|t| t.to_lowercase().contains(&q))
                    .unwrap_or(false)
            })
            .collect()
    }

    /// Get all highlighted addresses in a range, sorted.
    pub fn get_highlights_in_range(
        &self,
        start: Address,
        end: Address,
    ) -> Vec<&HighlightEntry> {
        let mut result: Vec<&HighlightEntry> = self
            .entries
            .values()
            .filter(|e| e.address.offset >= start.offset && e.address.offset <= end.offset)
            .collect();
        result.sort_by_key(|e| e.address.offset);
        result
    }

    /// Get all registered group names.
    pub fn group_names(&self) -> Vec<&str> {
        self.groups.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get_highlight() {
        let mut mgr = HighlightManager::new();
        mgr.set_highlight(Address::new(0x1000), HighlightColor::yellow());
        assert!(mgr.is_highlighted(Address::new(0x1000)));
        let entry = mgr.get_highlight(Address::new(0x1000)).unwrap();
        assert_eq!(entry.color, HighlightColor::yellow());
    }

    #[test]
    fn test_remove_highlight() {
        let mut mgr = HighlightManager::new();
        mgr.set_highlight(Address::new(0x1000), HighlightColor::red());
        mgr.remove_highlight(Address::new(0x1000));
        assert!(!mgr.is_highlighted(Address::new(0x1000)));
    }

    #[test]
    fn test_clear_all() {
        let mut mgr = HighlightManager::new();
        mgr.set_highlight(Address::new(0x1000), HighlightColor::green());
        mgr.set_highlight(Address::new(0x2000), HighlightColor::cyan());
        mgr.clear_all();
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_highlight_with_text() {
        let mut mgr = HighlightManager::new();
        mgr.set_highlight_with_text(
            Address::new(0x1000),
            HighlightColor::yellow(),
            "function main",
        );
        let entry = mgr.get_highlight(Address::new(0x1000)).unwrap();
        assert_eq!(entry.text.as_deref(), Some("function main"));
    }

    #[test]
    fn test_highlight_groups() {
        let mut mgr = HighlightManager::new();
        mgr.register_group(HighlightGroup::new("search", HighlightColor::yellow()));
        mgr.register_group(HighlightGroup::new("bookmarks", HighlightColor::green()));

        mgr.set_highlight_in_group(
            Address::new(0x1000),
            HighlightColor::yellow(),
            "search",
        );
        assert_eq!(mgr.count_in_group("search"), 1);
        assert_eq!(mgr.count_in_group("bookmarks"), 0);
    }

    #[test]
    fn test_group_toggle() {
        let mut mgr = HighlightManager::new();
        mgr.register_group(HighlightGroup::new("search", HighlightColor::yellow()));
        mgr.set_highlight_in_group(
            Address::new(0x1000),
            HighlightColor::yellow(),
            "search",
        );
        assert!(mgr.is_highlighted(Address::new(0x1000)));
        mgr.set_group_enabled("search", false);
        assert!(!mgr.is_highlighted(Address::new(0x1000)));
        // raw highlight still exists
        assert!(mgr.get_raw_highlight(Address::new(0x1000)).is_some());
    }

    #[test]
    fn test_clear_group() {
        let mut mgr = HighlightManager::new();
        mgr.register_group(HighlightGroup::new("g1", HighlightColor::red()));
        mgr.register_group(HighlightGroup::new("g2", HighlightColor::blue()));
        mgr.set_highlight_in_group(Address::new(0x1000), HighlightColor::red(), "g1");
        mgr.set_highlight_in_group(Address::new(0x2000), HighlightColor::blue(), "g2");
        mgr.clear_group("g1");
        assert_eq!(mgr.count_in_group("g1"), 0);
        assert_eq!(mgr.count_in_group("g2"), 1);
    }

    #[test]
    fn test_search_by_text() {
        let mut mgr = HighlightManager::new();
        mgr.set_highlight_with_text(
            Address::new(0x1000),
            HighlightColor::yellow(),
            "function main",
        );
        mgr.set_highlight_with_text(
            Address::new(0x2000),
            HighlightColor::green(),
            "data table",
        );
        let results = mgr.search_by_text("main");
        assert_eq!(results.len(), 1);
        let results2 = mgr.search_by_text("TABLE");
        assert_eq!(results2.len(), 1);
    }

    #[test]
    fn test_get_highlights_in_range() {
        let mut mgr = HighlightManager::new();
        mgr.set_highlight(Address::new(0x1000), HighlightColor::red());
        mgr.set_highlight(Address::new(0x2000), HighlightColor::blue());
        mgr.set_highlight(Address::new(0x3000), HighlightColor::green());
        let in_range = mgr.get_highlights_in_range(Address::new(0x1000), Address::new(0x2FFF));
        assert_eq!(in_range.len(), 2);
        assert_eq!(in_range[0].address.offset, 0x1000);
        assert_eq!(in_range[1].address.offset, 0x2000);
    }

    #[test]
    fn test_highlight_color_presets() {
        assert_eq!(HighlightColor::yellow().r, 255);
        assert_eq!(HighlightColor::blue().b, 255);
        assert_eq!(HighlightColor::orange().r, 255);
    }

    #[test]
    fn test_rgba_equals() {
        let a = HighlightColor::new(10, 20, 30, 40);
        let b = HighlightColor::new(10, 20, 30, 40);
        let c = HighlightColor::new(10, 20, 30, 41);
        assert!(a.rgba_equals(&b));
        assert!(!a.rgba_equals(&c));
    }

    #[test]
    fn test_group_names() {
        let mut mgr = HighlightManager::new();
        mgr.register_group(HighlightGroup::new("search", HighlightColor::yellow()));
        mgr.register_group(HighlightGroup::new("custom", HighlightColor::cyan()));
        assert_eq!(mgr.group_names().len(), 2);
    }

    #[test]
    fn test_set_highlight_plugin() {
        let mut plugin = SetHighlightPlugin::new("test_program");
        assert_eq!(plugin.program_name(), "test_program");
        assert!(plugin.is_enabled());

        plugin.set_highlight(Address::new(0x401000), Some(HighlightColor::yellow()));
        assert!(plugin.current_highlight().is_some());
        let (addr, color) = plugin.current_highlight().unwrap();
        assert_eq!(addr.offset, 0x401000);
        assert_eq!(color.r, 255);

        plugin.clear_highlight();
        assert!(plugin.current_highlight().is_none());
    }

    #[test]
    fn test_set_highlight_plugin_toggle() {
        let mut plugin = SetHighlightPlugin::new("test_program");
        plugin.set_highlight(Address::new(0x401000), Some(HighlightColor::yellow()));
        // Setting same address again should clear
        plugin.toggle_highlight(Address::new(0x401000), HighlightColor::yellow());
        assert!(plugin.current_highlight().is_none());
        // Setting different address should set
        plugin.toggle_highlight(Address::new(0x402000), HighlightColor::cyan());
        assert!(plugin.current_highlight().is_some());
    }

    #[test]
    fn test_set_highlight_plugin_dispose() {
        let mut plugin = SetHighlightPlugin::new("test_program");
        plugin.set_highlight(Address::new(0x401000), Some(HighlightColor::yellow()));
        plugin.dispose();
        assert!(!plugin.is_enabled());
        assert!(plugin.current_highlight().is_none());
    }
}

// ---------------------------------------------------------------------------
// SetHighlightPlugin
//
// Ported from `ghidra.app.plugin.core.highlight.SetHighlightPlugin`.
//
// Provides the ability to highlight the current address in the code listing
// using the middle mouse button or a keyboard shortcut.  Highlights are
// temporary and are cleared when the user clicks a different address or
// explicitly clears the highlight.
// ---------------------------------------------------------------------------

/// Plugin for setting and clearing highlights in the code listing.
///
/// Supports middle-mouse-button highlighting: clicking on an address
/// sets a highlight; clicking again on the same address clears it.
#[derive(Debug, Clone)]
pub struct SetHighlightPlugin {
    /// The currently highlighted address and its color.
    highlight: Option<(Address, HighlightColor)>,
    /// Name of the program this plugin is associated with.
    program_name: String,
    /// Whether the plugin is enabled.
    enabled: bool,
}

impl SetHighlightPlugin {
    /// Create a new SetHighlightPlugin.
    pub fn new(program_name: impl Into<String>) -> Self {
        Self {
            highlight: None,
            program_name: program_name.into(),
            enabled: true,
        }
    }

    /// Get the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Whether the plugin is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get the current highlight (address, color) if set.
    pub fn current_highlight(&self) -> Option<(Address, &HighlightColor)> {
        self.highlight.as_ref().map(|(addr, color)| (*addr, color))
    }

    /// Set a highlight at the given address with the given color.
    ///
    /// If a highlight already exists at a different address, it is replaced.
    pub fn set_highlight(&mut self, address: Address, color: Option<HighlightColor>) {
        match color {
            Some(c) => self.highlight = Some((address, c)),
            None => self.highlight = None,
        }
    }

    /// Clear the current highlight.
    pub fn clear_highlight(&mut self) {
        self.highlight = None;
    }

    /// Toggle highlight at the given address.
    ///
    /// If the address is already highlighted, the highlight is cleared.
    /// If a different address was highlighted, it is replaced.
    pub fn toggle_highlight(&mut self, address: Address, color: HighlightColor) {
        if let Some((current_addr, _)) = &self.highlight {
            if *current_addr == address {
                self.highlight = None;
                return;
            }
        }
        self.highlight = Some((address, color));
    }

    /// Dispose of the plugin.
    pub fn dispose(&mut self) {
        self.enabled = false;
        self.highlight = None;
    }
}
