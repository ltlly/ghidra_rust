//! Highlighted-token navigation actions -- Rust port of
//! `NextHighlightedTokenAction` and `PreviousHighlightedTokenAction`
//! from `ghidra.app.plugin.core.decompile.actions`.
//!
//! These actions allow the user to jump between tokens that have been
//! highlighted via the middle-mouse button.  Navigation wraps around
//! when the end (or beginning) of the decompiled text is reached.
//!
//! # Architecture
//!
//! ```text
//! NextHighlightedTokenAction     Ctrl+.  -- forward search
//! PreviousHighlightedTokenAction Ctrl+,  -- backward search
//!
//! Both iterate over the token stream starting from the cursor token
//! and stop at the first token that appears in the highlight set.
//! If no match is found in the current direction, the search wraps
//! from the first (or last) line.
//! ```

use super::action_context::DecompilerActionContext;
use super::actions::DecompilerAction;

// ---------------------------------------------------------------------------
// HighlightedTokenNavigator -- shared navigation logic
// ---------------------------------------------------------------------------

/// Direction of token navigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavigationDirection {
    /// Move forward through the token stream.
    Forward,
    /// Move backward through the token stream.
    Backward,
}

/// A reference to a token at a specific position in the decompiled output.
///
/// In the Java source this corresponds to a `ClangToken` obtained from
/// a `TokenIterator`.  We model the essential identity fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenRef {
    /// The text content of the token.
    pub text: String,
    /// Zero-based line index in the decompiled output.
    pub line_index: usize,
    /// Zero-based column offset within the line.
    pub column_offset: usize,
}

/// A set of tokens that have been highlighted via middle-mouse.
///
/// Corresponds to `TokenHighlights` in the Java source.
#[derive(Debug, Clone, Default)]
pub struct MiddleMouseHighlightSet {
    tokens: std::collections::HashSet<String>,
}

impl MiddleMouseHighlightSet {
    /// Create an empty highlight set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a highlight set from an iterator of token texts.
    pub fn from_texts<I: IntoIterator<Item = String>>(iter: I) -> Self {
        Self {
            tokens: iter.into_iter().collect(),
        }
    }

    /// Add a token text to the highlight set.
    pub fn insert(&mut self, token_text: String) {
        self.tokens.insert(token_text);
    }

    /// Check whether a token text is in the highlight set.
    pub fn contains(&self, token_text: &str) -> bool {
        self.tokens.contains(token_text)
    }

    /// Number of highlighted token texts.
    pub fn size(&self) -> usize {
        self.tokens.len()
    }

    /// Whether the set has more than one entry (needed for the action to
    /// be meaningful -- with only one highlight there is nothing to
    /// navigate to).
    pub fn has_multiple(&self) -> bool {
        self.tokens.len() > 1
    }

    /// Iterate over the contained token texts.
    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.tokens.iter()
    }
}

/// An ordered list of tokens from the decompiled output, used for
/// sequential navigation.
///
/// In the Java source this corresponds to the linearised token stream
/// obtained by iterating over `ClangTextField` lines.
#[derive(Debug, Clone, Default)]
pub struct TokenStream {
    tokens: Vec<TokenRef>,
}

impl TokenStream {
    /// Create an empty token stream.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a token stream from a vector of token references.
    pub fn from_tokens(tokens: Vec<TokenRef>) -> Self {
        Self { tokens }
    }

    /// Push a token onto the stream.
    pub fn push(&mut self, token: TokenRef) {
        self.tokens.push(token);
    }

    /// Total number of tokens in the stream.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Whether the stream is empty.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Find the index of a token by its text and position.
    pub fn index_of(&self, token: &TokenRef) -> Option<usize> {
        self.tokens.iter().position(|t| t == token)
    }

    /// Get the first token in the stream.
    pub fn first(&self) -> Option<&TokenRef> {
        self.tokens.first()
    }

    /// Get the last token in the stream.
    pub fn last(&self) -> Option<&TokenRef> {
        self.tokens.last()
    }

    /// Get a token by index.
    pub fn get(&self, index: usize) -> Option<&TokenRef> {
        self.tokens.get(index)
    }

    /// Search forward from `start_index` (exclusive) for a token whose
    /// text is in the highlight set.  Returns the token reference if
    /// found.
    pub fn find_next_highlighted(
        &self,
        start_index: usize,
        highlights: &MiddleMouseHighlightSet,
    ) -> Option<&TokenRef> {
        if self.tokens.is_empty() {
            return None;
        }
        let len = self.tokens.len();
        // Search from start_index+1 to end.
        for i in (start_index + 1)..len {
            if highlights.contains(&self.tokens[i].text) {
                return Some(&self.tokens[i]);
            }
        }
        // Wrap: search from beginning to start_index.
        for i in 0..=start_index {
            if highlights.contains(&self.tokens[i].text) {
                return Some(&self.tokens[i]);
            }
        }
        None
    }

    /// Search backward from `start_index` (exclusive) for a token whose
    /// text is in the highlight set.  Returns the token reference if
    /// found.
    pub fn find_previous_highlighted(
        &self,
        start_index: usize,
        highlights: &MiddleMouseHighlightSet,
    ) -> Option<&TokenRef> {
        if self.tokens.is_empty() {
            return None;
        }
        let len = self.tokens.len();
        // Search from start_index-1 down to 0.
        for i in (0..start_index).rev() {
            if highlights.contains(&self.tokens[i].text) {
                return Some(&self.tokens[i]);
            }
        }
        // Wrap: search from end down to start_index+1.
        for i in (start_index + 1..len).rev() {
            if highlights.contains(&self.tokens[i].text) {
                return Some(&self.tokens[i]);
            }
        }
        None
    }
}

// ---------------------------------------------------------------------------
// NextHighlightedTokenAction
// ---------------------------------------------------------------------------

/// Navigate to the next token highlighted via the middle-mouse button.
///
/// Key binding: `Ctrl+.` (period).  Wraps to the beginning of the
/// decompiled output when the end is reached.
///
/// Corresponds to Java's `NextHighlightedTokenAction`.
#[derive(Debug, Clone, Default)]
pub struct NextHighlightedTokenAction;

impl NextHighlightedTokenAction {
    pub const NAME: &'static str = "Next Highlighted Token";
    pub const MENU_PATH: &[&str] = &["Next Highlight"];
    pub const KEY_BINDING: &str = "Ctrl period";

    pub fn new() -> Self {
        Self
    }
}

impl DecompilerAction for NextHighlightedTokenAction {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        "Navigate to the next token highlighted via middle-mouse button"
    }

    fn is_enabled(&self, context: &DecompilerActionContext) -> bool {
        if !context.has_real_function() {
            return false;
        }
        context
            .middle_mouse_highlights()
            .map_or(false, |h| h.has_multiple())
    }

    fn perform(&self, context: &mut DecompilerActionContext) -> bool {
        let highlights = match context.middle_mouse_highlights() {
            Some(h) => h.clone(),
            None => return false,
        };

        let stream = match context.token_stream() {
            Some(s) => s.clone(),
            None => return false,
        };

        let cursor_token = match context.token_at_cursor() {
            Some(t) => TokenRef {
                text: t.text.clone(),
                line_index: t.line_number.saturating_sub(1),
                column_offset: t.column,
            },
            None => return false,
        };

        let start_index = stream.index_of(&cursor_token).unwrap_or(0);
        if let Some(target) = stream.find_next_highlighted(start_index, &highlights) {
            let target = target.clone();
            context.go_to_token(&target);
            return true;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// PreviousHighlightedTokenAction
// ---------------------------------------------------------------------------

/// Navigate to the previous token highlighted via the middle-mouse button.
///
/// Key binding: `Ctrl+,` (comma).  Wraps to the end of the decompiled
/// output when the beginning is reached.
///
/// Corresponds to Java's `PreviousHighlightedTokenAction`.
#[derive(Debug, Clone, Default)]
pub struct PreviousHighlightedTokenAction;

impl PreviousHighlightedTokenAction {
    pub const NAME: &'static str = "Previous Highlighted Token";
    pub const MENU_PATH: &[&str] = &["Previous Highlight"];
    pub const KEY_BINDING: &str = "Ctrl comma";

    pub fn new() -> Self {
        Self
    }
}

impl DecompilerAction for PreviousHighlightedTokenAction {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        "Navigate to the previous token highlighted via middle-mouse button"
    }

    fn is_enabled(&self, context: &DecompilerActionContext) -> bool {
        if !context.has_real_function() {
            return false;
        }
        context
            .middle_mouse_highlights()
            .map_or(false, |h| h.has_multiple())
    }

    fn perform(&self, context: &mut DecompilerActionContext) -> bool {
        let highlights = match context.middle_mouse_highlights() {
            Some(h) => h.clone(),
            None => return false,
        };

        let stream = match context.token_stream() {
            Some(s) => s.clone(),
            None => return false,
        };

        let cursor_token = match context.token_at_cursor() {
            Some(t) => TokenRef {
                text: t.text.clone(),
                line_index: t.line_number.saturating_sub(1),
                column_offset: t.column,
            },
            None => return false,
        };

        let start_index = stream.index_of(&cursor_token).unwrap_or(0);
        if let Some(target) = stream.find_previous_highlighted(start_index, &highlights) {
            let target = target.clone();
            context.go_to_token(&target);
            return true;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// HighlightNavigationAction -- unified action for next/previous highlight
// ---------------------------------------------------------------------------

/// A unified navigation action that can move forward or backward through
/// middle-mouse-highlighted tokens.
///
/// This is a convenience wrapper; concrete actions like
/// [`NextHighlightedTokenAction`] and [`PreviousHighlightedTokenAction`]
/// use this internally.
#[derive(Debug, Clone)]
pub struct HighlightNavigationAction {
    direction: NavigationDirection,
}

impl HighlightNavigationAction {
    /// Create a forward navigation action.
    pub fn forward() -> Self {
        Self {
            direction: NavigationDirection::Forward,
        }
    }

    /// Create a backward navigation action.
    pub fn backward() -> Self {
        Self {
            direction: NavigationDirection::Backward,
        }
    }

    /// The direction of this navigation action.
    pub fn direction(&self) -> NavigationDirection {
        self.direction
    }
}

impl DecompilerAction for HighlightNavigationAction {
    fn name(&self) -> &str {
        match self.direction {
            NavigationDirection::Forward => "Next Highlighted Token",
            NavigationDirection::Backward => "Previous Highlighted Token",
        }
    }

    fn description(&self) -> &str {
        match self.direction {
            NavigationDirection::Forward => "Navigate to the next highlighted token",
            NavigationDirection::Backward => "Navigate to the previous highlighted token",
        }
    }

    fn is_enabled(&self, context: &DecompilerActionContext) -> bool {
        if !context.has_real_function() {
            return false;
        }
        context
            .middle_mouse_highlights()
            .map_or(false, |h| h.has_multiple())
    }

    fn perform(&self, context: &mut DecompilerActionContext) -> bool {
        match self.direction {
            NavigationDirection::Forward => NextHighlightedTokenAction.perform(context),
            NavigationDirection::Backward => PreviousHighlightedTokenAction.perform(context),
        }
    }
}

// ---------------------------------------------------------------------------
// TokenHighlight -- a highlighted token with its assigned colour
// ---------------------------------------------------------------------------

/// A token that has been highlighted, together with its display colour.
///
/// Corresponds to `HighlightToken` in the Java decompiler component.
#[derive(Debug, Clone)]
pub struct TokenHighlight {
    /// The text of the highlighted token.
    pub token_text: String,
    /// The index of the line containing this token.
    pub line_index: usize,
    /// Column offset of the token within its line.
    pub column_offset: usize,
    /// The highlight colour as an RGBA tuple.
    pub color: (u8, u8, u8, u8),
}

impl TokenHighlight {
    /// Create a new token highlight.
    pub fn new(token_text: String, line_index: usize, column_offset: usize, color: (u8, u8, u8, u8)) -> Self {
        Self {
            token_text,
            line_index,
            column_offset,
            color,
        }
    }

    /// Get a `TokenRef` for this highlight.
    pub fn token_ref(&self) -> TokenRef {
        TokenRef {
            text: self.token_text.clone(),
            line_index: self.line_index,
            column_offset: self.column_offset,
        }
    }
}

// ---------------------------------------------------------------------------
// SliceHighlightColorProvider -- maps varnodes to slice colours
// ---------------------------------------------------------------------------

/// Provides highlight colours during forward/backward slicing operations.
///
/// In the Java source this is `SliceHighlightColorProvider`, which
/// assigns a rotating palette of colours to varnodes encountered during
/// a data-flow or control-flow slice.
#[derive(Debug, Clone)]
pub struct SliceHighlightColorProvider {
    /// The palette of colours to cycle through.
    palette: Vec<(u8, u8, u8, u8)>,
    /// Index of the next colour to assign.
    next_index: usize,
}

impl SliceHighlightColorProvider {
    /// Default slice highlight palette (warm tones).
    pub const DEFAULT_PALETTE: &[(u8, u8, u8, u8)] = &[
        (255, 200, 200, 180), // light red
        (200, 255, 200, 180), // light green
        (200, 200, 255, 180), // light blue
        (255, 255, 200, 180), // light yellow
        (255, 200, 255, 180), // light magenta
        (200, 255, 255, 180), // light cyan
        (255, 230, 200, 180), // light orange
        (230, 200, 255, 180), // light purple
    ];

    /// Create a provider with the default palette.
    pub fn new() -> Self {
        Self {
            palette: Self::DEFAULT_PALETTE.to_vec(),
            next_index: 0,
        }
    }

    /// Create a provider with a custom palette.
    pub fn with_palette(palette: Vec<(u8, u8, u8, u8)>) -> Self {
        Self {
            palette,
            next_index: 0,
        }
    }

    /// Get the next colour from the palette, cycling back to the start
    /// when exhausted.
    pub fn next_color(&mut self) -> (u8, u8, u8, u8) {
        let color = self.palette[self.next_index % self.palette.len()];
        self.next_index += 1;
        color
    }

    /// Reset the colour cycle.
    pub fn reset(&mut self) {
        self.next_index = 0;
    }

    /// Number of colours in the palette.
    pub fn palette_size(&self) -> usize {
        self.palette.len()
    }
}

impl Default for SliceHighlightColorProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_token(text: &str, line: usize, col: usize) -> TokenRef {
        TokenRef {
            text: text.to_string(),
            line_index: line,
            column_offset: col,
        }
    }

    fn sample_stream() -> TokenStream {
        TokenStream::from_tokens(vec![
            make_token("int", 0, 0),
            make_token("x", 0, 4),
            make_token("=", 0, 6),
            make_token("0", 0, 8),
            make_token(";", 0, 9),
            make_token("int", 1, 0),
            make_token("y", 1, 4),
            make_token("=", 1, 6),
            make_token("1", 1, 8),
            make_token(";", 1, 9),
        ])
    }

    #[test]
    fn highlight_set_basics() {
        let mut set = MiddleMouseHighlightSet::new();
        assert_eq!(set.size(), 0);
        assert!(!set.has_multiple());

        set.insert("x".to_string());
        assert_eq!(set.size(), 1);
        assert!(!set.has_multiple());

        set.insert("y".to_string());
        assert_eq!(set.size(), 2);
        assert!(set.has_multiple());
        assert!(set.contains("x"));
        assert!(set.contains("y"));
        assert!(!set.contains("z"));
    }

    #[test]
    fn token_stream_find_next_wraps() {
        let stream = sample_stream();
        let mut highlights = MiddleMouseHighlightSet::new();
        highlights.insert("int".to_string());
        highlights.insert("y".to_string());

        // Starting at index 0 ("int"), next highlighted after it is "int" at index 5.
        let result = stream.find_next_highlighted(0, &highlights);
        assert!(result.is_some());
        assert_eq!(result.unwrap().text, "int");

        // Starting at index 6 ("y"), next highlighted wraps to "int" at index 0.
        let result = stream.find_next_highlighted(6, &highlights);
        assert!(result.is_some());
        assert_eq!(result.unwrap().text, "int");
    }

    #[test]
    fn token_stream_find_previous_wraps() {
        let stream = sample_stream();
        let mut highlights = MiddleMouseHighlightSet::new();
        highlights.insert("int".to_string());
        highlights.insert("y".to_string());

        // Starting at index 6 ("y"), previous highlighted is "int" at index 5 or 0.
        let result = stream.find_previous_highlighted(6, &highlights);
        assert!(result.is_some());
        assert_eq!(result.unwrap().text, "int");

        // Starting at index 0 ("int"), previous wraps to "y" at index 6.
        let result = stream.find_previous_highlighted(0, &highlights);
        assert!(result.is_some());
        assert_eq!(result.unwrap().text, "y");
    }

    #[test]
    fn token_stream_empty() {
        let stream = TokenStream::new();
        let highlights = MiddleMouseHighlightSet::new();
        assert!(stream.find_next_highlighted(0, &highlights).is_none());
        assert!(stream.find_previous_highlighted(0, &highlights).is_none());
    }

    #[test]
    fn token_stream_index_of() {
        let stream = sample_stream();
        let token = make_token("x", 0, 4);
        assert_eq!(stream.index_of(&token), Some(1));

        let missing = make_token("z", 5, 0);
        assert_eq!(stream.index_of(&missing), None);
    }
}
