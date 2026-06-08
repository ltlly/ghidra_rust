//! Token highlighting infrastructure for the decompiler.
//!
//! Ports several Ghidra Java classes:
//! - `ghidra.app.decompiler.component.highlight.HighlightToken`
//! - `ghidra.app.decompiler.component.highlight.TokenHighlights`
//! - `ghidra.app.decompiler.component.highlight.UserHighlights`
//! - `ghidra.app.decompiler.component.highlight.LocationClangHighlightController`
//! - `ghidra.app.decompiler.component.highlight.ClangHighlightController`
//!
//! Provides token-level highlighting used to colorize decompiler output.

use std::collections::HashMap;

use ghidra_core::addr::Address;


/// A highlight applied to a specific token or address range.
///
/// Ports `ghidra.app.decompiler.component.highlight.HighlightToken`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HighlightToken {
    /// The address of the token to highlight.
    pub address: Address,
    /// The highlight color (as an RGBA value or color name).
    pub color: HighlightColor,
    /// Whether the highlight is a primary (active) highlight.
    pub is_primary: bool,
    /// An optional tooltip for the highlight.
    pub tooltip: Option<String>,
}

/// Colors available for highlighting in the decompiler view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HighlightColor {
    /// Yellow highlight (default).
    Yellow,
    /// Green highlight.
    Green,
    /// Cyan/light blue highlight.
    Cyan,
    /// Orange highlight.
    Orange,
    /// Pink/magenta highlight.
    Pink,
    /// Custom color by theme id.
    Custom(u32),
}

impl Default for HighlightColor {
    fn default() -> Self {
        Self::Yellow
    }
}

impl HighlightColor {
    /// Get the CSS hex string for this color.
    pub fn hex_string(&self) -> &'static str {
        match self {
            Self::Yellow => "#FFFF00",
            Self::Green => "#00FF00",
            Self::Cyan => "#00FFFF",
            Self::Orange => "#FFA500",
            Self::Pink => "#FF69B4",
            Self::Custom(_) => "#FFFFFF",
        }
    }
}

impl HighlightToken {
    /// Create a new highlight token.
    pub fn new(address: Address, color: HighlightColor) -> Self {
        Self {
            address,
            color,
            is_primary: false,
            tooltip: None,
        }
    }

    /// Create a primary highlight.
    pub fn primary(address: Address, color: HighlightColor) -> Self {
        Self {
            address,
            color,
            is_primary: true,
            tooltip: None,
        }
    }

    /// Set the tooltip text.
    pub fn with_tooltip(mut self, tooltip: impl Into<String>) -> Self {
        self.tooltip = Some(tooltip.into());
        self
    }
}

/// Collection of token highlights, keyed by address.
///
/// Ports `ghidra.app.decompiler.component.highlight.TokenHighlights`.
/// This manages all current highlights in a decompiler view.
#[derive(Debug, Clone, Default)]
pub struct TokenHighlights {
    /// Highlights indexed by address.
    highlights: HashMap<u64, HighlightToken>,
    /// The currently "active" (focused) highlight address.
    active_address: Option<Address>,
}

impl TokenHighlights {
    /// Create a new empty token highlights collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a highlight.
    pub fn add(&mut self, highlight: HighlightToken) {
        let addr = highlight.address;
        self.highlights.insert(addr.offset, highlight);
    }

    /// Remove the highlight at the given address.
    pub fn remove(&mut self, address: &Address) -> Option<HighlightToken> {
        self.highlights.remove(&address.offset)
    }

    /// Get the highlight at the given address.
    pub fn get(&self, address: &Address) -> Option<&HighlightToken> {
        self.highlights.get(&address.offset)
    }

    /// Clear all highlights.
    pub fn clear(&mut self) {
        self.highlights.clear();
        self.active_address = None;
    }

    /// Number of highlights.
    pub fn len(&self) -> usize {
        self.highlights.len()
    }

    /// Whether there are no highlights.
    pub fn is_empty(&self) -> bool {
        self.highlights.is_empty()
    }

    /// Set the active highlight address.
    pub fn set_active(&mut self, address: Option<Address>) {
        self.active_address = address;
    }

    /// Get the active highlight address.
    pub fn active_address(&self) -> Option<Address> {
        self.active_address
    }

    /// Iterate over all highlights.
    pub fn iter(&self) -> impl Iterator<Item = &HighlightToken> {
        self.highlights.values()
    }

    /// Check if an address has a highlight.
    pub fn contains(&self, address: &Address) -> bool {
        self.highlights.contains_key(&address.offset)
    }

    /// Get all highlighted addresses.
    pub fn addresses(&self) -> Vec<Address> {
        self.highlights
            .values()
            .map(|h| h.address)
            .collect()
    }
}

/// User-defined highlights that persist across decompilation runs.
///
/// Ports `ghidra.app.decompiler.component.highlight.UserHighlights`.
/// These are highlights that the user has manually added by clicking on tokens.
#[derive(Debug, Clone, Default)]
pub struct UserHighlights {
    /// User highlights keyed by function entry point and then by token address.
    highlights: HashMap<u64, HashMap<u64, HighlightColor>>,
}

impl UserHighlights {
    /// Create a new empty user highlights collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a user highlight for a token in a function.
    pub fn add_highlight(
        &mut self,
        function_entry: Address,
        token_address: Address,
        color: HighlightColor,
    ) {
        let func_map = self
            .highlights
            .entry(function_entry.offset)
            .or_insert_with(HashMap::new);
        func_map.insert(token_address.offset, color);
    }

    /// Remove a user highlight.
    pub fn remove_highlight(&mut self, function_entry: &Address, token_address: &Address) -> bool {
        if let Some(func_map) = self.highlights.get_mut(&function_entry.offset) {
            func_map.remove(&token_address.offset).is_some()
        } else {
            false
        }
    }

    /// Get the color of a user highlight, if set.
    pub fn get_highlight_color(
        &self,
        function_entry: &Address,
        token_address: &Address,
    ) -> Option<HighlightColor> {
        self.highlights
            .get(&function_entry.offset)
            .and_then(|m| m.get(&token_address.offset))
            .copied()
    }

    /// Get all user highlights for a function.
    pub fn get_function_highlights(
        &self,
        function_entry: &Address,
    ) -> Vec<(Address, HighlightColor)> {
        self.highlights
            .get(&function_entry.offset)
            .map(|m| {
                m.iter()
                    .map(|(&offset, &color)| (Address::new(offset), color))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Clear all highlights for a function.
    pub fn clear_function(&mut self, function_entry: &Address) {
        self.highlights.remove(&function_entry.offset);
    }

    /// Clear all highlights for all functions.
    pub fn clear_all(&mut self) {
        self.highlights.clear();
    }

    /// Whether there are any user highlights for a function.
    pub fn has_highlights(&self, function_entry: &Address) -> bool {
        self.highlights
            .get(&function_entry.offset)
            .map_or(false, |m| !m.is_empty())
    }

    /// Total number of user-highlighted tokens across all functions.
    pub fn total_count(&self) -> usize {
        self.highlights.values().map(|m| m.len()).sum()
    }
}

/// The highlight controller manages the overall highlighting state
/// of a decompiler panel.
///
/// Ports `ghidra.app.decompiler.component.highlight.ClangHighlightController`.
#[derive(Debug, Clone, Default)]
pub struct ClangHighlightController {
    /// Current token highlights.
    token_highlights: TokenHighlights,
    /// User-defined persistent highlights.
    user_highlights: UserHighlights,
    /// Whether syntax highlighting is enabled.
    syntax_highlighting_enabled: bool,
    /// Whether cursor highlight matching is enabled.
    cursor_highlight_enabled: bool,
}

impl ClangHighlightController {
    /// Create a new highlight controller.
    pub fn new() -> Self {
        Self {
            token_highlights: TokenHighlights::new(),
            user_highlights: UserHighlights::new(),
            syntax_highlighting_enabled: true,
            cursor_highlight_enabled: true,
        }
    }

    /// Get a reference to the token highlights.
    pub fn token_highlights(&self) -> &TokenHighlights {
        &self.token_highlights
    }

    /// Get a mutable reference to the token highlights.
    pub fn token_highlights_mut(&mut self) -> &mut TokenHighlights {
        &mut self.token_highlights
    }

    /// Get a reference to the user highlights.
    pub fn user_highlights(&self) -> &UserHighlights {
        &self.user_highlights
    }

    /// Get a mutable reference to the user highlights.
    pub fn user_highlights_mut(&mut self) -> &mut UserHighlights {
        &mut self.user_highlights
    }

    /// Set whether syntax highlighting is enabled.
    pub fn set_syntax_highlighting(&mut self, enabled: bool) {
        self.syntax_highlighting_enabled = enabled;
    }

    /// Whether syntax highlighting is enabled.
    pub fn is_syntax_highlighting_enabled(&self) -> bool {
        self.syntax_highlighting_enabled
    }

    /// Set whether cursor highlight matching is enabled.
    pub fn set_cursor_highlight(&mut self, enabled: bool) {
        self.cursor_highlight_enabled = enabled;
    }

    /// Whether cursor highlight matching is enabled.
    pub fn is_cursor_highlight_enabled(&self) -> bool {
        self.cursor_highlight_enabled
    }

    /// Clear all highlights.
    pub fn clear_all(&mut self) {
        self.token_highlights.clear();
        // User highlights are preserved across clears.
    }

    /// Add a token highlight.
    pub fn add_highlight(&mut self, highlight: HighlightToken) {
        self.token_highlights.add(highlight);
    }

    /// Apply user highlights for a function to the token highlights.
    pub fn apply_user_highlights(&mut self, function_entry: &Address) {
        let user_highlights = self
            .user_highlights
            .get_function_highlights(function_entry);
        for (addr, color) in user_highlights {
            self.token_highlights
                .add(HighlightToken::new(addr, color));
        }
    }
}

/// A highlight controller specialized for address-based highlighting.
///
/// Ports `ghidra.app.decompiler.component.highlight.LocationClangHighlightController`.
/// This controller highlights tokens based on their address rather than
/// their AST position, which is useful for cross-referencing with other views.
#[derive(Debug, Clone, Default)]
pub struct LocationClangHighlightController {
    /// Base highlight controller.
    base: ClangHighlightController,
    /// Address-to-color mapping for address-based highlights.
    address_highlights: HashMap<u64, HighlightColor>,
    /// The current program counter or cursor address.
    current_address: Option<Address>,
}

impl LocationClangHighlightController {
    /// Create a new location-based highlight controller.
    pub fn new() -> Self {
        Self {
            base: ClangHighlightController::new(),
            address_highlights: HashMap::new(),
            current_address: None,
        }
    }

    /// Set a highlight at a specific address.
    pub fn highlight_address(&mut self, address: Address, color: HighlightColor) {
        self.address_highlights.insert(address.offset, color);
    }

    /// Remove a highlight at a specific address.
    pub fn unhighlight_address(&mut self, address: &Address) -> bool {
        self.address_highlights.remove(&address.offset).is_some()
    }

    /// Get the highlight color for an address, if any.
    pub fn get_highlight_color(&self, address: &Address) -> Option<HighlightColor> {
        self.address_highlights.get(&address.offset).copied()
    }

    /// Set the current address (cursor position).
    pub fn set_current_address(&mut self, address: Option<Address>) {
        self.current_address = address;
    }

    /// Get the current address.
    pub fn current_address(&self) -> Option<Address> {
        self.current_address
    }

    /// Clear all address highlights.
    pub fn clear_address_highlights(&mut self) {
        self.address_highlights.clear();
    }

    /// Get a reference to the base controller.
    pub fn base(&self) -> &ClangHighlightController {
        &self.base
    }

    /// Get a mutable reference to the base controller.
    pub fn base_mut(&mut self) -> &mut ClangHighlightController {
        &mut self.base
    }

    /// Apply all address-based highlights to the token highlights.
    pub fn apply_address_highlights(&mut self) {
        for (&offset, &color) in &self.address_highlights {
            let addr = Address::new(offset);
            self.base.add_highlight(HighlightToken::new(addr, color));
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn highlight_token_basic() {
        let ht = HighlightToken::new(Address::new(0x1000), HighlightColor::Yellow);
        assert_eq!(ht.address.offset, 0x1000);
        assert_eq!(ht.color, HighlightColor::Yellow);
        assert!(!ht.is_primary);
    }

    #[test]
    fn highlight_token_primary() {
        let ht = HighlightToken::primary(Address::new(0x2000), HighlightColor::Green);
        assert!(ht.is_primary);
    }

    #[test]
    fn highlight_token_with_tooltip() {
        let ht = HighlightToken::new(Address::new(0x1000), HighlightColor::Cyan)
            .with_tooltip("test tooltip");
        assert_eq!(ht.tooltip.as_deref(), Some("test tooltip"));
    }

    #[test]
    fn highlight_color_hex() {
        assert_eq!(HighlightColor::Yellow.hex_string(), "#FFFF00");
        assert_eq!(HighlightColor::Green.hex_string(), "#00FF00");
    }

    #[test]
    fn token_highlights_add_remove() {
        let mut th = TokenHighlights::new();
        assert!(th.is_empty());

        th.add(HighlightToken::new(Address::new(0x1000), HighlightColor::Yellow));
        th.add(HighlightToken::new(Address::new(0x2000), HighlightColor::Green));
        assert_eq!(th.len(), 2);

        assert!(th.contains(&Address::new(0x1000)));
        assert!(!th.contains(&Address::new(0x3000)));

        th.remove(&Address::new(0x1000));
        assert_eq!(th.len(), 1);
    }

    #[test]
    fn token_highlights_active() {
        let mut th = TokenHighlights::new();
        assert!(th.active_address().is_none());

        th.set_active(Some(Address::new(0x1000)));
        assert_eq!(th.active_address(), Some(Address::new(0x1000)));
    }

    #[test]
    fn token_highlights_clear() {
        let mut th = TokenHighlights::new();
        th.add(HighlightToken::new(Address::new(0x1000), HighlightColor::Yellow));
        th.set_active(Some(Address::new(0x1000)));
        th.clear();
        assert!(th.is_empty());
        assert!(th.active_address().is_none());
    }

    #[test]
    fn user_highlights_add_get() {
        let mut uh = UserHighlights::new();
        let func_entry = Address::new(0x1000);
        let token_addr = Address::new(0x1004);

        uh.add_highlight(func_entry, token_addr, HighlightColor::Pink);
        assert!(uh.has_highlights(&func_entry));

        let color = uh.get_highlight_color(&func_entry, &token_addr);
        assert_eq!(color, Some(HighlightColor::Pink));
    }

    #[test]
    fn user_highlights_remove() {
        let mut uh = UserHighlights::new();
        let func_entry = Address::new(0x1000);
        let token_addr = Address::new(0x1004);

        uh.add_highlight(func_entry, token_addr, HighlightColor::Green);
        assert!(uh.remove_highlight(&func_entry, &token_addr));
        assert!(!uh.has_highlights(&func_entry));
    }

    #[test]
    fn user_highlights_clear_function() {
        let mut uh = UserHighlights::new();
        let f1 = Address::new(0x1000);
        let f2 = Address::new(0x2000);
        uh.add_highlight(f1, Address::new(0x1004), HighlightColor::Yellow);
        uh.add_highlight(f2, Address::new(0x2004), HighlightColor::Green);
        assert_eq!(uh.total_count(), 2);

        uh.clear_function(&f1);
        assert_eq!(uh.total_count(), 1);
        assert!(!uh.has_highlights(&f1));
        assert!(uh.has_highlights(&f2));
    }

    #[test]
    fn user_highlights_get_function_highlights() {
        let mut uh = UserHighlights::new();
        let func = Address::new(0x1000);
        uh.add_highlight(func, Address::new(0x1004), HighlightColor::Yellow);
        uh.add_highlight(func, Address::new(0x1008), HighlightColor::Green);

        let highlights = uh.get_function_highlights(&func);
        assert_eq!(highlights.len(), 2);
    }

    #[test]
    fn clang_highlight_controller_basic() {
        let mut ctrl = ClangHighlightController::new();
        assert!(ctrl.is_syntax_highlighting_enabled());
        assert!(ctrl.is_cursor_highlight_enabled());

        ctrl.add_highlight(HighlightToken::new(
            Address::new(0x1000),
            HighlightColor::Yellow,
        ));
        assert_eq!(ctrl.token_highlights().len(), 1);
    }

    #[test]
    fn clang_highlight_controller_clear_all() {
        let mut ctrl = ClangHighlightController::new();
        ctrl.add_highlight(HighlightToken::new(
            Address::new(0x1000),
            HighlightColor::Yellow,
        ));
        ctrl.clear_all();
        assert!(ctrl.token_highlights().is_empty());
    }

    #[test]
    fn clang_highlight_controller_apply_user_highlights() {
        let mut ctrl = ClangHighlightController::new();
        let func = Address::new(0x1000);
        ctrl.user_highlights_mut()
            .add_highlight(func, Address::new(0x1004), HighlightColor::Pink);

        ctrl.apply_user_highlights(&func);
        assert!(ctrl.token_highlights().contains(&Address::new(0x1004)));
    }

    #[test]
    fn location_highlight_controller_basic() {
        let mut ctrl = LocationClangHighlightController::new();
        ctrl.highlight_address(Address::new(0x1000), HighlightColor::Cyan);

        let color = ctrl.get_highlight_color(&Address::new(0x1000));
        assert_eq!(color, Some(HighlightColor::Cyan));
    }

    #[test]
    fn location_highlight_controller_unhighlight() {
        let mut ctrl = LocationClangHighlightController::new();
        let addr = Address::new(0x1000);
        ctrl.highlight_address(addr, HighlightColor::Orange);
        assert!(ctrl.unhighlight_address(&addr));
        assert!(ctrl.get_highlight_color(&addr).is_none());
    }

    #[test]
    fn location_highlight_controller_current_address() {
        let mut ctrl = LocationClangHighlightController::new();
        assert!(ctrl.current_address().is_none());

        ctrl.set_current_address(Some(Address::new(0x2000)));
        assert_eq!(ctrl.current_address(), Some(Address::new(0x2000)));
    }

    #[test]
    fn location_highlight_controller_apply_address_highlights() {
        let mut ctrl = LocationClangHighlightController::new();
        ctrl.highlight_address(Address::new(0x1000), HighlightColor::Yellow);
        ctrl.highlight_address(Address::new(0x2000), HighlightColor::Green);

        ctrl.apply_address_highlights();
        assert_eq!(ctrl.base().token_highlights().len(), 2);
    }

    #[test]
    fn location_highlight_controller_clear() {
        let mut ctrl = LocationClangHighlightController::new();
        ctrl.highlight_address(Address::new(0x1000), HighlightColor::Yellow);
        ctrl.clear_address_highlights();
        assert!(ctrl.get_highlight_color(&Address::new(0x1000)).is_none());
    }
}
