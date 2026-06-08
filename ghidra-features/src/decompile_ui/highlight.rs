//! Decompiler highlight service and highlighter -- Rust port of
//! `ghidra.app.decompiler.DecompilerHighlightService` and
//! `ghidra.app.decompiler.DecompilerHighlighter`.
//!
//! The highlight service allows external clients to create token
//! highlights in the decompiler panel.  Each highlighter is associated
//! with a matcher that determines which tokens to highlight, and
//! optionally scoped to a specific function.
//!
//! # Architecture
//!
//! ```text
//! DecompilerHighlightService (trait)
//!   ├── create_highlighter(matcher) -> Highlighter
//!   ├── create_highlighter_for_fn(function, matcher) -> Highlighter
//!   ├── create_highlighter_with_id(id, matcher) -> Highlighter
//!   └── create_highlighter_with_id_for_fn(id, function, matcher) -> Highlighter
//!
//! DecompilerHighlighter (trait)
//!   ├── apply_highlights()
//!   ├── clear_highlights()
//!   ├── dispose()
//!   └── get_id() -> String
//! ```

use ghidra_core::addr::Address;

// ---------------------------------------------------------------------------
// CTokenHighlightMatcher
// ---------------------------------------------------------------------------

/// Determines which tokens should be highlighted.
///
/// In Ghidra this is an interface (`CTokenHighlightMatcher`) that
/// clients implement to decide which `ClangToken`s receive a
/// background color.  Here we model it as a trait.
pub trait CTokenHighlightMatcher: std::fmt::Debug {
    /// Returns `true` if the token with the given text and address
    /// should be highlighted.
    fn matches(&self, token_text: &str, token_address: Option<Address>) -> bool;

    /// Returns the highlight color to use for matching tokens.
    /// Represented as an RGBA tuple (0-255 per channel).
    fn highlight_color(&self) -> (u8, u8, u8, u8) {
        (255, 255, 0, 100) // default: semi-transparent yellow
    }
}

/// A simple text-matching highlighter.
///
/// Highlights all tokens whose text equals (or contains) a given string.
#[derive(Debug)]
pub struct TextHighlightMatcher {
    /// The text to match.
    pub match_text: String,
    /// Whether to use substring matching (vs. exact match).
    pub substring: bool,
    /// The highlight color.
    pub color: (u8, u8, u8, u8),
}

impl TextHighlightMatcher {
    /// Create an exact-match highlighter.
    pub fn exact(text: impl Into<String>) -> Self {
        Self {
            match_text: text.into(),
            substring: false,
            color: (255, 255, 0, 100),
        }
    }

    /// Create a substring-match highlighter.
    pub fn substring(text: impl Into<String>) -> Self {
        Self {
            match_text: text.into(),
            substring: true,
            color: (255, 255, 0, 100),
        }
    }

    /// Set the highlight color.
    pub fn with_color(mut self, r: u8, g: u8, b: u8, a: u8) -> Self {
        self.color = (r, g, b, a);
        self
    }
}

impl CTokenHighlightMatcher for TextHighlightMatcher {
    fn matches(&self, token_text: &str, _token_address: Option<Address>) -> bool {
        if self.substring {
            token_text.contains(&self.match_text)
        } else {
            token_text == self.match_text
        }
    }

    fn highlight_color(&self) -> (u8, u8, u8, u8) {
        self.color
    }
}

/// An address-range highlighter.
///
/// Highlights all tokens whose source address falls within a given range.
#[derive(Debug)]
pub struct AddressRangeHighlightMatcher {
    /// The start of the address range (inclusive).
    pub start: Address,
    /// The end of the address range (inclusive).
    pub end: Address,
    /// The highlight color.
    pub color: (u8, u8, u8, u8),
}

impl AddressRangeHighlightMatcher {
    /// Create a new address-range highlighter.
    pub fn new(start: Address, end: Address) -> Self {
        Self {
            start,
            end,
            color: (0, 200, 255, 100),
        }
    }

    /// Set the highlight color.
    pub fn with_color(mut self, r: u8, g: u8, b: u8, a: u8) -> Self {
        self.color = (r, g, b, a);
        self
    }
}

impl CTokenHighlightMatcher for AddressRangeHighlightMatcher {
    fn matches(&self, _token_text: &str, token_address: Option<Address>) -> bool {
        match token_address {
            Some(addr) => addr >= self.start && addr <= self.end,
            None => false,
        }
    }

    fn highlight_color(&self) -> (u8, u8, u8, u8) {
        self.color
    }
}

// ---------------------------------------------------------------------------
// DecompilerHighlighter (trait)
// ---------------------------------------------------------------------------

/// The highlighter interface passed to clients of the
/// [`DecompilerHighlightService`].
///
/// The expected workflow is:
/// 1. Create the highlighter via the service.
/// 2. Call `apply_highlights()` to activate.
/// 3. Call `clear_highlights()` to remove.
/// 4. Call `dispose()` to remove the highlighter entirely.
pub trait DecompilerHighlighter: std::fmt::Debug {
    /// Apply the highlights to the decompiler panel.
    fn apply_highlights(&self);

    /// Clear the highlights from the decompiler panel.
    fn clear_highlights(&self);

    /// Dispose of this highlighter, removing it from the service.
    fn dispose(&mut self);

    /// Returns the ID of this highlighter.
    fn get_id(&self) -> &str;
}

// ---------------------------------------------------------------------------
// HighlighterRecord (concrete implementation)
// ---------------------------------------------------------------------------

/// A concrete highlighter that tracks its state.
#[derive(Debug)]
pub struct HighlighterRecord {
    /// Unique identifier.
    id: String,
    /// The function entry point this highlighter is scoped to, or
    /// `None` for global highlights.
    function_entry: Option<Address>,
    /// Whether the highlights are currently applied.
    applied: bool,
    /// The highlight color.
    color: (u8, u8, u8, u8),
    /// The matched token texts (for tracking).
    matched_tokens: Vec<(String, Option<Address>)>,
}

impl HighlighterRecord {
    /// Create a new highlighter record.
    pub fn new(
        id: impl Into<String>,
        function_entry: Option<Address>,
        color: (u8, u8, u8, u8),
    ) -> Self {
        Self {
            id: id.into(),
            function_entry,
            applied: false,
            color,
            matched_tokens: Vec::new(),
        }
    }

    /// Returns `true` if this highlighter is scoped to a specific function.
    pub fn is_function_scoped(&self) -> bool {
        self.function_entry.is_some()
    }

    /// Returns the function entry point, if scoped.
    pub fn function_entry(&self) -> Option<Address> {
        self.function_entry
    }

    /// Returns `true` if the highlights are currently applied.
    pub fn is_applied(&self) -> bool {
        self.applied
    }

    /// Returns the highlight color.
    pub fn color(&self) -> (u8, u8, u8, u8) {
        self.color
    }

    /// Set the matched tokens.
    pub fn set_matched_tokens(&mut self, tokens: Vec<(String, Option<Address>)>) {
        self.matched_tokens = tokens;
    }

    /// Get the matched tokens.
    pub fn matched_tokens(&self) -> &[(String, Option<Address>)] {
        &self.matched_tokens
    }
}

impl DecompilerHighlighter for HighlighterRecord {
    fn apply_highlights(&self) {
        // In a full implementation, this would update the panel's
        // highlight state.  Here we just mark the conceptual state.
    }

    fn clear_highlights(&self) {
        // Clear the highlight state.
    }

    fn dispose(&mut self) {
        self.applied = false;
        self.matched_tokens.clear();
    }

    fn get_id(&self) -> &str {
        &self.id
    }
}

// ---------------------------------------------------------------------------
// DecompilerHighlightService (trait)
// ---------------------------------------------------------------------------

/// A service that allows clients to create highlights in the decompiler UI.
///
/// Highlights apply to whole tokens, not substrings.  Multiple
/// highlighters can be installed; overlapping highlights are blended.
pub trait DecompilerHighlightService: std::fmt::Debug {
    /// Create a global highlighter (applied to all functions).
    fn create_highlighter_global(
        &mut self,
        matcher: &dyn CTokenHighlightMatcher,
    ) -> String;

    /// Create a function-scoped highlighter.
    fn create_highlighter_for_function(
        &mut self,
        function_entry: Address,
        matcher: &dyn CTokenHighlightMatcher,
    ) -> String;

    /// Create a global highlighter with a specific ID.
    fn create_highlighter_with_id_global(
        &mut self,
        id: &str,
        matcher: &dyn CTokenHighlightMatcher,
    ) -> String;

    /// Create a function-scoped highlighter with a specific ID.
    fn create_highlighter_with_id_for_function(
        &mut self,
        id: &str,
        function_entry: Address,
        matcher: &dyn CTokenHighlightMatcher,
    ) -> String;
}

// ---------------------------------------------------------------------------
// HighlightServiceManager
// ---------------------------------------------------------------------------

/// Manages all installed highlighters for a decompiler provider.
///
/// This is the concrete implementation of the highlight service that
/// stores highlighter records and manages their lifecycle.
#[derive(Debug)]
pub struct HighlightServiceManager {
    /// All installed highlighters.
    highlighters: Vec<HighlighterRecord>,
    /// Counter for generating unique IDs.
    next_id: usize,
}

impl HighlightServiceManager {
    /// Create a new highlight service manager.
    pub fn new() -> Self {
        Self {
            highlighters: Vec::new(),
            next_id: 0,
        }
    }

    /// Returns the number of installed highlighters.
    pub fn count(&self) -> usize {
        self.highlighters.len()
    }

    /// Get a reference to a highlighter by ID.
    pub fn get_highlighter(&self, id: &str) -> Option<&HighlighterRecord> {
        self.highlighters.iter().find(|h| h.id == id)
    }

    /// Get a mutable reference to a highlighter by ID.
    pub fn get_highlighter_mut(&mut self, id: &str) -> Option<&mut HighlighterRecord> {
        self.highlighters.iter_mut().find(|h| h.id == id)
    }

    /// Remove a highlighter by ID.  Returns `true` if found and removed.
    pub fn remove_highlighter(&mut self, id: &str) -> bool {
        let len_before = self.highlighters.len();
        self.highlighters.retain(|h| h.id != id);
        self.highlighters.len() < len_before
    }

    /// Remove all highlighters scoped to the given function.
    pub fn remove_for_function(&mut self, function_entry: Address) {
        self.highlighters
            .retain(|h| h.function_entry != Some(function_entry));
    }

    /// Remove all highlighters.
    pub fn clear(&mut self) {
        self.highlighters.clear();
    }

    /// Iterate over all highlighters.
    pub fn iter(&self) -> impl Iterator<Item = &HighlighterRecord> {
        self.highlighters.iter()
    }

    /// Get all highlighters that apply to the given function (including global).
    pub fn for_function(&self, function_entry: Address) -> Vec<&HighlighterRecord> {
        self.highlighters
            .iter()
            .filter(|h| h.function_entry.is_none() || h.function_entry == Some(function_entry))
            .collect()
    }

    /// Generate a unique ID.
    fn generate_id(&mut self) -> String {
        self.next_id += 1;
        format!("highlighter_{}", self.next_id)
    }

    /// Remove an existing highlighter with the given ID (for replacement).
    fn replace_by_id(&mut self, id: &str, record: HighlighterRecord) {
        if let Some(existing) = self.highlighters.iter_mut().find(|h| h.id == id) {
            *existing = record;
        } else {
            self.highlighters.push(record);
        }
    }
}

impl Default for HighlightServiceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DecompilerHighlightService for HighlightServiceManager {
    fn create_highlighter_global(
        &mut self,
        matcher: &dyn CTokenHighlightMatcher,
    ) -> String {
        let id = self.generate_id();
        let record = HighlighterRecord::new(&id, None, matcher.highlight_color());
        self.highlighters.push(record);
        id
    }

    fn create_highlighter_for_function(
        &mut self,
        function_entry: Address,
        matcher: &dyn CTokenHighlightMatcher,
    ) -> String {
        let id = self.generate_id();
        let record =
            HighlighterRecord::new(&id, Some(function_entry), matcher.highlight_color());
        self.highlighters.push(record);
        id
    }

    fn create_highlighter_with_id_global(
        &mut self,
        id: &str,
        matcher: &dyn CTokenHighlightMatcher,
    ) -> String {
        let record = HighlighterRecord::new(id, None, matcher.highlight_color());
        self.replace_by_id(id, record);
        id.to_string()
    }

    fn create_highlighter_with_id_for_function(
        &mut self,
        id: &str,
        function_entry: Address,
        matcher: &dyn CTokenHighlightMatcher,
    ) -> String {
        let record =
            HighlighterRecord::new(id, Some(function_entry), matcher.highlight_color());
        self.replace_by_id(id, record);
        id.to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- TextHighlightMatcher ---

    #[test]
    fn test_text_matcher_exact() {
        let matcher = TextHighlightMatcher::exact("x");
        assert!(matcher.matches("x", None));
        assert!(!matcher.matches("y", None));
        assert!(!matcher.matches("xy", None));
    }

    #[test]
    fn test_text_matcher_substring() {
        let matcher = TextHighlightMatcher::substring("x");
        assert!(matcher.matches("x", None));
        assert!(matcher.matches("xy", None));
        assert!(matcher.matches("yx", None));
        assert!(!matcher.matches("abc", None));
    }

    #[test]
    fn test_text_matcher_color() {
        let matcher = TextHighlightMatcher::exact("a").with_color(255, 0, 0, 128);
        assert_eq!(matcher.highlight_color(), (255, 0, 0, 128));
    }

    // --- AddressRangeHighlightMatcher ---

    #[test]
    fn test_address_matcher_in_range() {
        let matcher = AddressRangeHighlightMatcher::new(Address::new(0x1000), Address::new(0x2000));
        assert!(matcher.matches("x", Some(Address::new(0x1500))));
        assert!(matcher.matches("x", Some(Address::new(0x1000))));
        assert!(matcher.matches("x", Some(Address::new(0x2000))));
    }

    #[test]
    fn test_address_matcher_out_of_range() {
        let matcher = AddressRangeHighlightMatcher::new(Address::new(0x1000), Address::new(0x2000));
        assert!(!matcher.matches("x", Some(Address::new(0x0500))));
        assert!(!matcher.matches("x", Some(Address::new(0x3000))));
        assert!(!matcher.matches("x", None));
    }

    #[test]
    fn test_address_matcher_color() {
        let matcher =
            AddressRangeHighlightMatcher::new(Address::new(0), Address::new(0xFFFF))
                .with_color(0, 255, 0, 200);
        assert_eq!(matcher.highlight_color(), (0, 255, 0, 200));
    }

    // --- HighlighterRecord ---

    #[test]
    fn test_highlighter_record_new() {
        let h = HighlighterRecord::new("h1", Some(Address::new(0x1000)), (255, 255, 0, 100));
        assert_eq!(h.get_id(), "h1");
        assert!(h.is_function_scoped());
        assert_eq!(h.function_entry(), Some(Address::new(0x1000)));
        assert!(!h.is_applied());
    }

    #[test]
    fn test_highlighter_record_global() {
        let h = HighlighterRecord::new("h2", None, (0, 0, 255, 50));
        assert!(!h.is_function_scoped());
        assert!(h.function_entry().is_none());
    }

    #[test]
    fn test_highlighter_record_matched_tokens() {
        let mut h = HighlighterRecord::new("h3", None, (255, 0, 0, 100));
        h.set_matched_tokens(vec![
            ("x".into(), Some(Address::new(0x100))),
            ("y".into(), Some(Address::new(0x200))),
        ]);
        assert_eq!(h.matched_tokens().len(), 2);
    }

    #[test]
    fn test_highlighter_record_dispose() {
        let mut h = HighlighterRecord::new("h4", None, (0, 0, 0, 0));
        h.set_matched_tokens(vec![("a".into(), None)]);
        h.dispose();
        assert!(h.matched_tokens().is_empty());
    }

    // --- HighlightServiceManager ---

    #[test]
    fn test_manager_new() {
        let mgr = HighlightServiceManager::new();
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_manager_create_global() {
        let mut mgr = HighlightServiceManager::new();
        let matcher = TextHighlightMatcher::exact("x");
        let id = mgr.create_highlighter_global(&matcher);
        assert_eq!(mgr.count(), 1);
        assert!(mgr.get_highlighter(&id).is_some());
        assert!(!mgr.get_highlighter(&id).unwrap().is_function_scoped());
    }

    #[test]
    fn test_manager_create_for_function() {
        let mut mgr = HighlightServiceManager::new();
        let matcher = TextHighlightMatcher::exact("y");
        let id = mgr.create_highlighter_for_function(Address::new(0x1000), &matcher);
        assert_eq!(mgr.count(), 1);
        assert!(mgr.get_highlighter(&id).unwrap().is_function_scoped());
    }

    #[test]
    fn test_manager_create_with_id_replaces() {
        let mut mgr = HighlightServiceManager::new();
        let matcher = TextHighlightMatcher::exact("a");

        mgr.create_highlighter_with_id_global("my_id", &matcher);
        assert_eq!(mgr.count(), 1);

        // Creating with the same ID should replace, not add.
        mgr.create_highlighter_with_id_global("my_id", &matcher);
        assert_eq!(mgr.count(), 1);
    }

    #[test]
    fn test_manager_remove_highlighter() {
        let mut mgr = HighlightServiceManager::new();
        let matcher = TextHighlightMatcher::exact("x");
        let id = mgr.create_highlighter_global(&matcher);
        assert_eq!(mgr.count(), 1);

        assert!(mgr.remove_highlighter(&id));
        assert_eq!(mgr.count(), 0);
        assert!(!mgr.remove_highlighter(&id)); // already removed
    }

    #[test]
    fn test_manager_remove_for_function() {
        let mut mgr = HighlightServiceManager::new();
        let matcher = TextHighlightMatcher::exact("a");
        mgr.create_highlighter_for_function(Address::new(0x1000), &matcher);
        mgr.create_highlighter_for_function(Address::new(0x2000), &matcher);
        mgr.create_highlighter_global(&matcher);
        assert_eq!(mgr.count(), 3);

        mgr.remove_for_function(Address::new(0x1000));
        assert_eq!(mgr.count(), 2); // one fn-scoped removed, one fn-scoped + one global remain
    }

    #[test]
    fn test_manager_clear() {
        let mut mgr = HighlightServiceManager::new();
        let matcher = TextHighlightMatcher::exact("x");
        mgr.create_highlighter_global(&matcher);
        mgr.create_highlighter_global(&matcher);
        mgr.clear();
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn test_manager_for_function() {
        let mut mgr = HighlightServiceManager::new();
        let matcher = TextHighlightMatcher::exact("x");
        mgr.create_highlighter_for_function(Address::new(0x1000), &matcher);
        mgr.create_highlighter_for_function(Address::new(0x2000), &matcher);
        mgr.create_highlighter_global(&matcher);

        // Query for 0x1000 should return 2: the fn-scoped one + the global one.
        let applicable = mgr.for_function(Address::new(0x1000));
        assert_eq!(applicable.len(), 2);

        // Query for 0x3000 should return 1: only the global one.
        let applicable = mgr.for_function(Address::new(0x3000));
        assert_eq!(applicable.len(), 1);
    }

    #[test]
    fn test_manager_iter() {
        let mut mgr = HighlightServiceManager::new();
        let matcher = TextHighlightMatcher::exact("x");
        mgr.create_highlighter_global(&matcher);
        mgr.create_highlighter_global(&matcher);
        assert_eq!(mgr.iter().count(), 2);
    }

    #[test]
    fn test_manager_get_mut() {
        let mut mgr = HighlightServiceManager::new();
        let matcher = TextHighlightMatcher::exact("x");
        let id = mgr.create_highlighter_global(&matcher);

        {
            let h = mgr.get_highlighter_mut(&id).unwrap();
            h.set_matched_tokens(vec![("x".into(), None)]);
        }

        assert_eq!(mgr.get_highlighter(&id).unwrap().matched_tokens().len(), 1);
    }
}
