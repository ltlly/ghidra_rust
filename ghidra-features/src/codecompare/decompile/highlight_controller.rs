//! Decompiler diff highlight controller.
//!
//! Ported from Ghidra's `DiffClangHighlightController` and
//! `DiffClangHighlightListener` Java classes in
//! `ghidra.features.codecompare.decompile`.
//!
//! Manages the highlighting of matched/mismatched tokens in a dual
//! decompiler comparison view. When the user selects a token in one
//! panel, this controller highlights the corresponding token (if any)
//! in the other panel, and also highlights all diff tokens.
//!
//! In the original Java, `DiffClangHighlightController` extends
//! `LocationClangHighlightController` and manages three highlighter
//! layers: diff color, current token, and matching token bin. In this
//! Rust port, we capture the logical state and highlight computation
//! without the Swing/decompiler-panel dependency.
//!
//! # Key types
//!
//! - [`DiffClangHighlightListener`] -- trait for highlight change notifications
//! - [`DiffClangHighlightController`] -- the main highlight controller
//! - [`HighlightLayerKind`] -- the kind of highlight layer
//! - [`TokenHighlight`] -- a computed highlight for a token
//! - [`FocusedTokenColor`] -- color category for the focused token

use std::collections::HashSet;

use super::token_pair::TokenPair;
use crate::codecompare::graphanalysis::{DecompilerToken, Side, TokenBin, TokenKind};

/// Trait for receiving notifications when the focused token changes.
///
/// Ported from Ghidra's `DiffClangHighlightListener` Java interface.
///
/// When the user moves the cursor to a different token in one decompiler
/// panel, the highlight controller notifies its listener so that the
/// paired controller can update its matching-token highlight.
pub trait DiffClangHighlightListener: Send + Sync {
    /// Called when the focused location token changes.
    ///
    /// `token_bin` is the bin containing the new token, or `None` if the
    /// token is not part of any bin.
    fn location_token_changed(&self, token_bin: Option<&TokenBinState>);
}

/// A no-op listener used when no real listener is installed.
struct DummyListener;

impl DiffClangHighlightListener for DummyListener {
    fn location_token_changed(&self, _token_bin: Option<&TokenBinState>) {}
}

/// The color category for the focused (selected) token.
///
/// In Ghidra, the focused token is highlighted with a color that depends
/// on whether the token is part of a matched bin, an unmatched bin, or
/// not in any bin at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FocusedTokenColor {
    /// The token is part of a matched bin (has a corresponding bin on the
    /// other side).
    Matched,
    /// The token is in a bin but the bin has no match on the other side.
    Unmatched,
    /// The token is not in any bin (e.g., a syntax token).
    Ineligible,
}

/// The kind of highlight layer.
///
/// In Ghidra, three layers of highlights are maintained simultaneously:
/// diff highlights (all differing tokens), current-token highlights
/// (the token under the cursor), and matching-token highlights (the
/// corresponding token on the other side).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HighlightLayerKind {
    /// Highlights all tokens that differ between the two sides.
    DiffColor,
    /// Highlights the token currently under the cursor.
    CurrentToken,
    /// Highlights the matching token bin on the other side.
    MatchingToken,
}

/// A computed highlight for a token address range.
///
/// Each highlight covers a contiguous range of addresses and carries
/// a color identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenHighlight {
    /// Start address (inclusive).
    pub start_address: u64,
    /// End address (inclusive).
    pub end_address: u64,
    /// The highlight layer this belongs to.
    pub layer: HighlightLayerKind,
    /// The color identifier (e.g., an RGB hex string).
    pub color: String,
}

impl TokenHighlight {
    /// Create a new token highlight.
    pub fn new(
        start_address: u64,
        end_address: u64,
        layer: HighlightLayerKind,
        color: impl Into<String>,
    ) -> Self {
        Self {
            start_address,
            end_address,
            layer,
            color: color.into(),
        }
    }

    /// Check if this highlight covers the given address.
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start_address && address <= self.end_address
    }

    /// The number of addresses covered.
    pub fn size(&self) -> u64 {
        self.end_address - self.start_address + 1
    }
}

/// A simplified representation of a token in the decompiler output.
///
/// This corresponds to Ghidra's `ClangToken` concept but without the
/// Swing component dependency.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DecompilerTokenRef {
    /// Unique token identifier.
    pub id: u64,
    /// The token text.
    pub text: String,
    /// The kind of token (syntax, variable, constant, etc.).
    pub kind: TokenRefKind,
    /// The address this token is associated with.
    pub address: u64,
    /// The character offset within the line.
    pub char_offset: usize,
}

/// The kind of a decompiler token reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenRefKind {
    /// A syntax token (parenthesis, brace, semicolon, etc.).
    Syntax,
    /// A variable name.
    Variable,
    /// A function name.
    FunctionName,
    /// A numeric constant.
    Constant,
    /// A type name.
    TypeName,
    /// A field name (struct member access).
    FieldName,
    /// A keyword (if, while, return, etc.).
    Keyword,
    /// An operator (+, -, *, etc.).
    Operator,
    /// Other/unclassified.
    Other,
}

/// A simplified representation of a token bin, stored as state for the
/// highlight controller.
///
/// This mirrors the essential fields of Ghidra's `TokenBin` that the
/// highlight controller needs: the set of tokens, the match status,
/// and the match reference.
#[derive(Debug, Clone)]
pub struct TokenBinState {
    /// Unique bin identifier.
    pub id: u64,
    /// The tokens in this bin.
    pub tokens: Vec<DecompilerTokenRef>,
    /// The side this bin belongs to.
    pub side: Side,
    /// The ID of the matched bin on the other side, if any.
    pub match_bin_id: Option<u64>,
}

impl TokenBinState {
    /// Create a new token bin state.
    pub fn new(id: u64, side: Side) -> Self {
        Self {
            id,
            tokens: Vec::new(),
            side,
            match_bin_id: None,
        }
    }

    /// Add a token to this bin.
    pub fn add_token(&mut self, token: DecompilerTokenRef) {
        self.tokens.push(token);
    }

    /// Check if this bin contains a token with the given ID.
    pub fn contains_token(&self, token_id: u64) -> bool {
        self.tokens.iter().any(|t| t.id == token_id)
    }

    /// Get the token with the given ID, if present.
    pub fn get_token(&self, token_id: u64) -> Option<&DecompilerTokenRef> {
        self.tokens.iter().find(|t| t.id == token_id)
    }

    /// Check if this bin is matched with a bin on the other side.
    pub fn is_matched(&self) -> bool {
        self.match_bin_id.is_some()
    }

    /// Get the number of tokens in this bin.
    pub fn size(&self) -> usize {
        self.tokens.len()
    }

    /// Check if this bin is empty.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Get all token addresses in this bin.
    pub fn token_addresses(&self) -> Vec<u64> {
        self.tokens.iter().map(|t| t.address).collect()
    }
}

/// Options for the decompiler code comparison view.
///
/// Ported from Ghidra's `DecompilerCodeComparisonOptions` Java class.
/// Stores the configurable colors used for diff highlighting in the
/// dual decompiler comparison view.
#[derive(Debug, Clone)]
pub struct DecompilerComparisonOptions {
    /// Color for tokens that differ between the two sides.
    pub diff_highlight_color: String,
    /// Color for the focused token when it is part of a matched bin.
    pub focused_token_match_color: String,
    /// Color for the focused token when it is in an unmatched bin.
    pub focused_token_unmatched_color: String,
    /// Color for the focused token when it is not in any bin.
    pub focused_token_ineligible_color: String,
    /// Color for matching parenthesis/brace highlighting.
    pub paren_match_color: String,
}

impl DecompilerComparisonOptions {
    /// Create options with default colors.
    pub fn new() -> Self {
        Self {
            diff_highlight_color: "#ffffcc".to_string(),
            focused_token_match_color: "#b3d9ff".to_string(),
            focused_token_unmatched_color: "#ffcccc".to_string(),
            focused_token_ineligible_color: "#e0e0e0".to_string(),
            paren_match_color: "#ccccff".to_string(),
        }
    }

    /// Get the color for the focused token based on its bin status.
    pub fn focused_token_color(&self, color_kind: FocusedTokenColor) -> &str {
        match color_kind {
            FocusedTokenColor::Matched => &self.focused_token_match_color,
            FocusedTokenColor::Unmatched => &self.focused_token_unmatched_color,
            FocusedTokenColor::Ineligible => &self.focused_token_ineligible_color,
        }
    }
}

impl Default for DecompilerComparisonOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// The main controller for managing diff highlights in a decompiler
/// comparison panel.
///
/// Ported from Ghidra's `DiffClangHighlightController` Java class.
///
/// This controller manages three layers of highlights:
/// 1. **Diff highlights** -- all tokens that differ between the two sides
/// 2. **Current token highlight** -- the token currently under the cursor
/// 3. **Matching token highlight** -- the corresponding token on the other side
///
/// When the user moves the cursor, the controller:
/// - Clears the current-token and matching-token highlights
/// - Determines which bin (if any) the new token belongs to
/// - Applies the current-token highlight with the appropriate color
/// - Notifies its listener so the paired controller can highlight the match
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::decompile::highlight_controller::*;
/// use ghidra_features::codecompare::graphanalysis::Side;
///
/// let options = DecompilerComparisonOptions::new();
/// let mut controller = DiffClangHighlightController::new(options);
///
/// // Set diff highlights from matched bins
/// let diff_tokens = vec![];
/// controller.set_diff_highlights(diff_tokens);
///
/// // Simulate a location change
/// controller.field_location_changed(Some(42));
/// ```
pub struct DiffClangHighlightController {
    /// The comparison options (colors).
    options: DecompilerComparisonOptions,
    /// Which side this controller manages.
    side: Side,
    /// The token bins for both sides.
    all_token_bins: Vec<TokenBinState>,
    /// IDs of tokens that should be highlighted as diffs.
    diff_token_ids: HashSet<u64>,
    /// The currently focused token.
    location_token: Option<DecompilerTokenRef>,
    /// The bin containing the currently focused token.
    location_token_bin: Option<TokenBinState>,
    /// Current highlights for the diff layer.
    diff_highlights: Vec<TokenHighlight>,
    /// Current highlights for the current-token layer.
    current_token_highlights: Vec<TokenHighlight>,
    /// Current highlights for the matching-token layer.
    matching_token_highlights: Vec<TokenHighlight>,
    /// Listener for token change notifications.
    listener: Box<dyn DiffClangHighlightListener>,
    /// Whether this controller is linked to a paired controller.
    linked: bool,
}

impl std::fmt::Debug for DiffClangHighlightController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiffClangHighlightController")
            .field("side", &self.side)
            .field("all_token_bins", &self.all_token_bins)
            .field("diff_token_ids", &self.diff_token_ids)
            .field("diff_highlights", &self.diff_highlights)
            .field("linked", &self.linked)
            .finish_non_exhaustive()
    }
}

impl DiffClangHighlightController {
    /// Create a new highlight controller.
    ///
    /// When called with options only, defaults the side to `Left`.
    /// Use [`with_side`](Self::with_side) to specify both options and side.
    pub fn new(options: DecompilerComparisonOptions) -> Self {
        Self {
            options,
            side: Side::Left,
            all_token_bins: Vec::new(),
            diff_token_ids: HashSet::new(),
            location_token: None,
            location_token_bin: None,
            diff_highlights: Vec::new(),
            current_token_highlights: Vec::new(),
            matching_token_highlights: Vec::new(),
            listener: Box::new(DummyListener),
            linked: false,
        }
    }

    /// Create a new highlight controller with specific options and side.
    pub fn with_side(options: DecompilerComparisonOptions, side: Side) -> Self {
        Self {
            options,
            side,
            all_token_bins: Vec::new(),
            diff_token_ids: HashSet::new(),
            location_token: None,
            location_token_bin: None,
            diff_highlights: Vec::new(),
            current_token_highlights: Vec::new(),
            matching_token_highlights: Vec::new(),
            listener: Box::new(DummyListener),
            linked: false,
        }
    }

    /// Whether this controller is linked to a paired controller.
    pub fn is_linked(&self) -> bool {
        self.linked
    }

    /// Set whether this controller is linked to a paired controller.
    pub fn set_linked(&mut self, linked: bool) {
        self.linked = linked;
    }

    /// Clear all highlights and state.
    pub fn clear(&mut self) {
        self.all_token_bins.clear();
        self.diff_token_ids.clear();
        self.location_token = None;
        self.location_token_bin = None;
        self.diff_highlights.clear();
        self.current_token_highlights.clear();
        self.matching_token_highlights.clear();
    }

    /// Set the token bins for both sides.
    pub fn set_token_bins(&mut self, bins: Vec<TokenBinState>) {
        self.all_token_bins = bins;
    }

    /// Set the diff highlights from a set of tokens that differ.
    ///
    /// `diff_tokens` contains the token IDs that should be highlighted
    /// with the diff color.
    pub fn set_diff_highlights(&mut self, diff_token_ids: Vec<u64>) {
        self.clear_diff_highlights();
        self.diff_token_ids = diff_token_ids.into_iter().collect();
        self.rebuild_diff_highlights();
        self.notify_listener();
    }

    /// Set diff highlights from a [`DiffResult`].
    ///
    /// Extracts the relevant token bin IDs from the result for the given
    /// `side` and sets them as diff highlights.
    pub fn set_diff_highlights_from_result(
        &mut self,
        result: &super::determine_differences_task::DiffResult,
        side: Side,
    ) {
        let diff_ids: Vec<u64> = result
            .token_bins
            .iter()
            .filter(|b| b.side == side && !b.is_matched())
            .flat_map(|b| b.iter().map(|t| t.address))
            .collect();
        self.set_diff_highlights(diff_ids);
    }

    /// Handle a change in the cursor location.
    ///
    /// `token_id` is the ID of the token at the new cursor position,
    /// or `None` if the cursor moved to a position without a token.
    pub fn field_location_changed(&mut self, token_id: Option<u64>) {
        // Check if the token actually changed
        let current_id = self.location_token.as_ref().map(|t| t.id);
        if current_id == token_id {
            return;
        }

        self.clear_current_token_highlight();
        self.clear_matching_token_highlight();

        // Find the token and its bin
        let token = token_id.and_then(|id| self.find_token(id));
        let token_bin = token_id.and_then(|id| self.find_bin_containing_token(id));

        // Determine the highlight color for the current token
        let color_kind = match &token_bin {
            Some(bin) => {
                if bin.is_matched() {
                    FocusedTokenColor::Matched
                } else {
                    FocusedTokenColor::Unmatched
                }
            }
            None => FocusedTokenColor::Ineligible,
        };

        let color = self.options.focused_token_color(color_kind).to_string();

        // Apply the current-token highlight
        if let Some(ref bin) = token_bin {
            self.apply_current_token_highlight_bin(bin, &color);
        } else if let Some(ref tok) = token {
            self.apply_current_token_highlight_single(tok, &color);
        }

        self.location_token = token;
        self.location_token_bin = token_bin;

        // Refresh diff highlights (they skip the current token)
        self.rebuild_diff_highlights();

        // Notify the listener
        self.notify_listener();
    }

    /// Handle a notification from the paired controller that its
    /// location token changed.
    ///
    /// This is called when the user moves the cursor in the OTHER
    /// decompiler panel. We need to highlight the matching token bin
    /// in THIS panel.
    pub fn on_paired_location_changed(&mut self, paired_bin: Option<&TokenBinState>) {
        self.clear_matching_token_highlight();
        self.rebuild_diff_highlights();

        if let Some(bin) = paired_bin {
            if let Some(match_bin_id) = bin.match_bin_id {
                let color = self.options.focused_token_match_color.clone();
                self.apply_matching_token_highlight(match_bin_id, &color);
            }
        }
    }

    /// Set the listener for token change notifications.
    pub fn set_listener(&mut self, listener: Box<dyn DiffClangHighlightListener>) {
        self.listener = listener;
    }

    /// Get the currently focused token.
    pub fn location_token(&self) -> Option<&DecompilerTokenRef> {
        self.location_token.as_ref()
    }

    /// Get the bin containing the currently focused token.
    pub fn location_token_bin(&self) -> Option<&TokenBinState> {
        self.location_token_bin.as_ref()
    }

    /// Get all current highlights across all layers.
    pub fn all_highlights(&self) -> Vec<&TokenHighlight> {
        let mut result = Vec::new();
        result.extend(self.diff_highlights.iter());
        result.extend(self.current_token_highlights.iter());
        result.extend(self.matching_token_highlights.iter());
        result
    }

    /// Get highlights for a specific layer.
    pub fn highlights_for_layer(&self, layer: HighlightLayerKind) -> &[TokenHighlight] {
        match layer {
            HighlightLayerKind::DiffColor => &self.diff_highlights,
            HighlightLayerKind::CurrentToken => &self.current_token_highlights,
            HighlightLayerKind::MatchingToken => &self.matching_token_highlights,
        }
    }

    /// Get the side this controller manages.
    pub fn side(&self) -> Side {
        self.side
    }

    /// Get the comparison options.
    pub fn options(&self) -> &DecompilerComparisonOptions {
        &self.options
    }

    /// Clear all highlights.
    pub fn clear_all(&mut self) {
        self.clear_diff_highlights();
        self.clear_current_token_highlight();
        self.clear_matching_token_highlight();
    }

    /// Compute a `TokenPair` from the currently focused token and its match.
    ///
    /// Returns `None` if the focused token is not part of a matched pair.
    pub fn compute_token_pair(&self) -> Option<TokenPair> {
        let bin = self.location_token_bin.as_ref()?;
        let match_bin_id = bin.match_bin_id?;
        let focused_token = self.location_token.as_ref()?;

        // Find the matching bin
        let match_bin = self.all_token_bins.iter().find(|b| b.id == match_bin_id)?;

        // Find a token in the matching bin with the same kind
        let matching_token = match_bin
            .tokens
            .iter()
            .find(|t| t.kind == focused_token.kind)?;

        use crate::codecompare::graphanalysis::DecompilerToken;
        use crate::codecompare::graphanalysis::TokenKind;

        let left_token = DecompilerToken {
            text: focused_token.text.clone(),
            kind: Self::token_ref_kind_to_token_kind(focused_token.kind),
            address: focused_token.address,
            side: Side::Left,
        };
        let right_token = DecompilerToken {
            text: matching_token.text.clone(),
            kind: Self::token_ref_kind_to_token_kind(matching_token.kind),
            address: matching_token.address,
            side: Side::Right,
        };

        Some(TokenPair::new(left_token, right_token))
    }

    fn token_ref_kind_to_token_kind(kind: TokenRefKind) -> TokenKind {
        match kind {
            TokenRefKind::Syntax => TokenKind::Other,
            TokenRefKind::Variable => TokenKind::Variable,
            TokenRefKind::FunctionName => TokenKind::FunctionName,
            TokenRefKind::Constant => TokenKind::Constant,
            TokenRefKind::TypeName => TokenKind::TypeName,
            TokenRefKind::FieldName => TokenKind::FieldName,
            TokenRefKind::Keyword => TokenKind::Keyword,
            TokenRefKind::Operator => TokenKind::Operator,
            TokenRefKind::Other => TokenKind::Other,
        }
    }

    // --- Private helpers ---

    fn find_token(&self, token_id: u64) -> Option<DecompilerTokenRef> {
        for bin in &self.all_token_bins {
            if let Some(token) = bin.get_token(token_id) {
                return Some(token.clone());
            }
        }
        None
    }

    fn find_bin_containing_token(&self, token_id: u64) -> Option<TokenBinState> {
        self.all_token_bins
            .iter()
            .find(|bin| bin.contains_token(token_id))
            .cloned()
    }

    fn rebuild_diff_highlights(&self) {
        // This is a placeholder that would be rebuilt by the controller.
        // In the full implementation, this iterates over diff_token_ids
        // and creates highlights for each, skipping the current location token.
        // The actual highlight Vec is stored in self.diff_highlights.
    }

    fn clear_diff_highlights(&mut self) {
        self.diff_highlights.clear();
        self.diff_token_ids.clear();
    }

    fn clear_current_token_highlight(&mut self) {
        self.current_token_highlights.clear();
        self.location_token = None;
        self.location_token_bin = None;
    }

    fn clear_matching_token_highlight(&mut self) {
        self.matching_token_highlights.clear();
    }

    fn apply_current_token_highlight_bin(&mut self, bin: &TokenBinState, color: &str) {
        for token in &bin.tokens {
            self.current_token_highlights.push(TokenHighlight::new(
                token.address,
                token.address,
                HighlightLayerKind::CurrentToken,
                color,
            ));
        }
    }

    fn apply_current_token_highlight_single(&mut self, token: &DecompilerTokenRef, color: &str) {
        self.current_token_highlights.push(TokenHighlight::new(
            token.address,
            token.address,
            HighlightLayerKind::CurrentToken,
            color,
        ));
    }

    fn apply_matching_token_highlight(&mut self, match_bin_id: u64, color: &str) {
        if let Some(match_bin) = self.all_token_bins.iter().find(|b| b.id == match_bin_id) {
            for token in &match_bin.tokens {
                self.matching_token_highlights.push(TokenHighlight::new(
                    token.address,
                    token.address,
                    HighlightLayerKind::MatchingToken,
                    color,
                ));
            }
        }
    }

    fn notify_listener(&self) {
        self.listener
            .location_token_changed(self.location_token_bin.as_ref());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_token(id: u64, text: &str, kind: TokenRefKind, address: u64) -> DecompilerTokenRef {
        DecompilerTokenRef {
            id,
            text: text.to_string(),
            kind,
            address,
            char_offset: 0,
        }
    }

    fn make_bin(id: u64, side: Side, tokens: Vec<DecompilerTokenRef>) -> TokenBinState {
        let mut bin = TokenBinState::new(id, side);
        for t in tokens {
            bin.add_token(t);
        }
        bin
    }

    // --- DecompilerComparisonOptions tests ---

    #[test]
    fn test_options_defaults() {
        let opts = DecompilerComparisonOptions::new();
        assert_eq!(opts.diff_highlight_color, "#ffffcc");
        assert_eq!(opts.focused_token_match_color, "#b3d9ff");
        assert_eq!(opts.focused_token_unmatched_color, "#ffcccc");
        assert_eq!(opts.focused_token_ineligible_color, "#e0e0e0");
        assert_eq!(opts.paren_match_color, "#ccccff");
    }

    #[test]
    fn test_options_focused_token_color() {
        let opts = DecompilerComparisonOptions::new();
        assert_eq!(
            opts.focused_token_color(FocusedTokenColor::Matched),
            "#b3d9ff"
        );
        assert_eq!(
            opts.focused_token_color(FocusedTokenColor::Unmatched),
            "#ffcccc"
        );
        assert_eq!(
            opts.focused_token_color(FocusedTokenColor::Ineligible),
            "#e0e0e0"
        );
    }

    #[test]
    fn test_options_default_trait() {
        let opts = DecompilerComparisonOptions::default();
        assert_eq!(opts.diff_highlight_color, "#ffffcc");
    }

    // --- TokenHighlight tests ---

    #[test]
    fn test_token_highlight_new() {
        let h = TokenHighlight::new(0x1000, 0x100f, HighlightLayerKind::DiffColor, "#ff0000");
        assert_eq!(h.start_address, 0x1000);
        assert_eq!(h.end_address, 0x100f);
        assert_eq!(h.layer, HighlightLayerKind::DiffColor);
        assert_eq!(h.color, "#ff0000");
    }

    #[test]
    fn test_token_highlight_contains() {
        let h = TokenHighlight::new(0x1000, 0x100f, HighlightLayerKind::CurrentToken, "#00ff00");
        assert!(h.contains(0x1000));
        assert!(h.contains(0x1008));
        assert!(h.contains(0x100f));
        assert!(!h.contains(0x0fff));
        assert!(!h.contains(0x1010));
    }

    #[test]
    fn test_token_highlight_size() {
        let h = TokenHighlight::new(0x1000, 0x100f, HighlightLayerKind::MatchingToken, "#0000ff");
        assert_eq!(h.size(), 0x10);
    }

    // --- TokenBinState tests ---

    #[test]
    fn test_token_bin_state_new() {
        let bin = TokenBinState::new(1, Side::Left);
        assert_eq!(bin.id, 1);
        assert_eq!(bin.side, Side::Left);
        assert!(bin.is_empty());
        assert!(!bin.is_matched());
    }

    #[test]
    fn test_token_bin_state_add_token() {
        let mut bin = TokenBinState::new(1, Side::Left);
        bin.add_token(make_token(10, "x", TokenRefKind::Variable, 0x1000));
        bin.add_token(make_token(11, "y", TokenRefKind::Variable, 0x1004));
        assert_eq!(bin.size(), 2);
        assert!(!bin.is_empty());
    }

    #[test]
    fn test_token_bin_state_contains_token() {
        let mut bin = TokenBinState::new(1, Side::Left);
        bin.add_token(make_token(10, "x", TokenRefKind::Variable, 0x1000));
        assert!(bin.contains_token(10));
        assert!(!bin.contains_token(99));
    }

    #[test]
    fn test_token_bin_state_get_token() {
        let mut bin = TokenBinState::new(1, Side::Left);
        bin.add_token(make_token(10, "x", TokenRefKind::Variable, 0x1000));
        let token = bin.get_token(10).unwrap();
        assert_eq!(token.text, "x");
        assert!(bin.get_token(99).is_none());
    }

    #[test]
    fn test_token_bin_state_matched() {
        let mut bin = TokenBinState::new(1, Side::Left);
        assert!(!bin.is_matched());
        bin.match_bin_id = Some(2);
        assert!(bin.is_matched());
    }

    #[test]
    fn test_token_bin_state_addresses() {
        let mut bin = TokenBinState::new(1, Side::Left);
        bin.add_token(make_token(10, "x", TokenRefKind::Variable, 0x1000));
        bin.add_token(make_token(11, "y", TokenRefKind::Variable, 0x1004));
        let addrs = bin.token_addresses();
        assert_eq!(addrs, vec![0x1000, 0x1004]);
    }

    // --- DiffClangHighlightController tests ---

    #[test]
    fn test_controller_new() {
        let opts = DecompilerComparisonOptions::new();
        let controller = DiffClangHighlightController::with_side(opts, Side::Left);
        assert_eq!(controller.side(), Side::Left);
        assert!(controller.location_token().is_none());
        assert!(controller.location_token_bin().is_none());
        assert!(controller.all_highlights().is_empty());
    }

    #[test]
    fn test_controller_set_token_bins() {
        let opts = DecompilerComparisonOptions::new();
        let mut controller = DiffClangHighlightController::with_side(opts, Side::Left);

        let bin1 = make_bin(1, Side::Left, vec![
            make_token(10, "x", TokenRefKind::Variable, 0x1000),
        ]);
        let bin2 = make_bin(2, Side::Right, vec![
            make_token(20, "y", TokenRefKind::Variable, 0x2000),
        ]);

        controller.set_token_bins(vec![bin1, bin2]);
        assert_eq!(controller.all_token_bins.len(), 2);
    }

    #[test]
    fn test_controller_location_change() {
        let opts = DecompilerComparisonOptions::new();
        let mut controller = DiffClangHighlightController::with_side(opts, Side::Left);

        let mut bin = make_bin(1, Side::Left, vec![
            make_token(10, "x", TokenRefKind::Variable, 0x1000),
        ]);
        bin.match_bin_id = Some(2);

        controller.set_token_bins(vec![bin]);

        // Move cursor to token 10
        controller.field_location_changed(Some(10));
        assert!(controller.location_token().is_some());
        assert_eq!(controller.location_token().unwrap().id, 10);
        assert!(controller.location_token_bin().is_some());
    }

    #[test]
    fn test_controller_location_change_no_token() {
        let opts = DecompilerComparisonOptions::new();
        let mut controller = DiffClangHighlightController::with_side(opts, Side::Right);

        controller.field_location_changed(None);
        assert!(controller.location_token().is_none());
        assert!(controller.location_token_bin().is_none());
    }

    #[test]
    fn test_controller_location_change_same_token() {
        let opts = DecompilerComparisonOptions::new();
        let mut controller = DiffClangHighlightController::with_side(opts, Side::Left);

        let bin = make_bin(1, Side::Left, vec![
            make_token(10, "x", TokenRefKind::Variable, 0x1000),
        ]);
        controller.set_token_bins(vec![bin]);

        controller.field_location_changed(Some(10));
        controller.field_location_changed(Some(10)); // same token, should be no-op

        // Should still have the token
        assert!(controller.location_token().is_some());
    }

    #[test]
    fn test_controller_clear_all() {
        let opts = DecompilerComparisonOptions::new();
        let mut controller = DiffClangHighlightController::with_side(opts, Side::Left);

        let bin = make_bin(1, Side::Left, vec![
            make_token(10, "x", TokenRefKind::Variable, 0x1000),
        ]);
        controller.set_token_bins(vec![bin]);
        controller.set_diff_highlights(vec![10]);
        controller.field_location_changed(Some(10));

        controller.clear_all();
        assert!(controller.location_token().is_none());
        assert!(controller.all_highlights().is_empty());
    }

    #[test]
    fn test_controller_highlights_for_layer() {
        let opts = DecompilerComparisonOptions::new();
        let controller = DiffClangHighlightController::with_side(opts, Side::Left);

        assert!(controller
            .highlights_for_layer(HighlightLayerKind::DiffColor)
            .is_empty());
        assert!(controller
            .highlights_for_layer(HighlightLayerKind::CurrentToken)
            .is_empty());
        assert!(controller
            .highlights_for_layer(HighlightLayerKind::MatchingToken)
            .is_empty());
    }

    // --- DiffClangHighlightListener tests ---

    struct TestListener {
        called: std::sync::Mutex<bool>,
    }

    impl TestListener {
        fn new() -> Self {
            Self {
                called: std::sync::Mutex::new(false),
            }
        }

        fn was_called(&self) -> bool {
            *self.called.lock().unwrap()
        }
    }

    impl DiffClangHighlightListener for TestListener {
        fn location_token_changed(&self, _token_bin: Option<&TokenBinState>) {
            *self.called.lock().unwrap() = true;
        }
    }

    #[test]
    fn test_controller_listener_notification() {
        let opts = DecompilerComparisonOptions::new();
        let mut controller = DiffClangHighlightController::with_side(opts, Side::Left);

        let listener = Box::new(TestListener::new());
        // We need to check if the listener was called, but since we move it
        // into the controller, we use Arc instead.
        let called = std::sync::Arc::new(std::sync::Mutex::new(false));
        let called_clone = called.clone();

        struct ArcListener {
            called: std::sync::Arc<std::sync::Mutex<bool>>,
        }
        impl DiffClangHighlightListener for ArcListener {
            fn location_token_changed(&self, _token_bin: Option<&TokenBinState>) {
                *self.called.lock().unwrap() = true;
            }
        }

        controller.set_listener(Box::new(ArcListener { called: called_clone }));

        let bin = make_bin(1, Side::Left, vec![
            make_token(10, "x", TokenRefKind::Variable, 0x1000),
        ]);
        controller.set_token_bins(vec![bin]);
        controller.field_location_changed(Some(10));

        assert!(*called.lock().unwrap());
    }

    // --- TokenPair computation tests ---

    #[test]
    fn test_controller_compute_token_pair_no_match() {
        let opts = DecompilerComparisonOptions::new();
        let mut controller = DiffClangHighlightController::with_side(opts, Side::Left);

        let bin = make_bin(1, Side::Left, vec![
            make_token(10, "x", TokenRefKind::Variable, 0x1000),
        ]);
        controller.set_token_bins(vec![bin]);
        controller.field_location_changed(Some(10));

        // No match_bin_id set, so no token pair
        assert!(controller.compute_token_pair().is_none());
    }

    #[test]
    fn test_controller_compute_token_pair_with_match() {
        let opts = DecompilerComparisonOptions::new();
        let mut controller = DiffClangHighlightController::with_side(opts, Side::Left);

        let mut left_bin = make_bin(1, Side::Left, vec![
            make_token(10, "x", TokenRefKind::Variable, 0x1000),
        ]);
        left_bin.match_bin_id = Some(2);

        let mut right_bin = make_bin(2, Side::Right, vec![
            make_token(20, "y", TokenRefKind::Variable, 0x2000),
        ]);
        right_bin.match_bin_id = Some(1);

        controller.set_token_bins(vec![left_bin, right_bin]);
        controller.field_location_changed(Some(10));

        let pair = controller.compute_token_pair();
        assert!(pair.is_some());
        let pair = pair.unwrap();
        assert_eq!(pair.left_token().text, "x");
        assert_eq!(pair.right_token().text, "y");
    }

    // --- HighlightLayerKind tests ---

    #[test]
    fn test_highlight_layer_kind_ordering() {
        assert!(HighlightLayerKind::DiffColor < HighlightLayerKind::CurrentToken);
        assert!(HighlightLayerKind::CurrentToken < HighlightLayerKind::MatchingToken);
    }

    // --- FocusedTokenColor tests ---

    #[test]
    fn test_focused_token_color_variants() {
        assert_ne!(FocusedTokenColor::Matched, FocusedTokenColor::Unmatched);
        assert_ne!(FocusedTokenColor::Matched, FocusedTokenColor::Ineligible);
        assert_ne!(FocusedTokenColor::Unmatched, FocusedTokenColor::Ineligible);
    }

    // --- TokenRefKind tests ---

    #[test]
    fn test_token_ref_kind_variants() {
        assert_eq!(TokenRefKind::Variable, TokenRefKind::Variable);
        assert_ne!(TokenRefKind::Variable, TokenRefKind::Constant);
        assert_ne!(TokenRefKind::Syntax, TokenRefKind::Keyword);
    }

    // --- DecompilerTokenRef tests ---

    #[test]
    fn test_decompiler_token_ref() {
        let token = make_token(42, "myVar", TokenRefKind::Variable, 0x1000);
        assert_eq!(token.id, 42);
        assert_eq!(token.text, "myVar");
        assert_eq!(token.kind, TokenRefKind::Variable);
        assert_eq!(token.address, 0x1000);
    }
}
