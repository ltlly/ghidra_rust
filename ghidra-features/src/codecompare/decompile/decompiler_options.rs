//! Configurable options for the decompiler code comparison view.
//!
//! Ported from Ghidra's `DecompilerCodeComparisonOptions` Java class in
//! `ghidra.features.codecompare.decompile`.
//!
//! This module holds the configurable highlight colors used in the
//! decompiler comparison view. There are four categories of highlights:
//!
//! - **Matching token** -- when a focused token has a matched pair on the other side
//! - **Unmatched token** -- when a focused token has no match
//! - **Ineligible token** -- when a focused token cannot be matched (e.g. whitespace)
//! - **Diff** -- when the two decompiled functions differ
//!
//! Options can be loaded from a persistent store and a change listener
//! can be registered so the UI updates when options change.
//!
//! # Key types
//!
//! - [`DecompilerCodeComparisonOptions`] -- the options holder
//! - [`DecompilerHighlightColor`] -- the category of highlight color

use std::fmt;
use std::sync::{Arc, Mutex};

/// The category of highlight color in the decompiler comparison view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DecompilerHighlightColor {
    /// Color for focused token and its match on the other side.
    MatchingToken,
    /// Color for a focused token with no match on the other side.
    UnmatchedToken,
    /// Color for a focused token that is ineligible for matching (e.g. whitespace).
    IneligibleToken,
    /// Color for general differences between the two functions.
    Diff,
}

impl DecompilerHighlightColor {
    /// The option key string for this highlight color.
    pub fn option_key(&self) -> &'static str {
        match self {
            Self::MatchingToken => "Focused Token Match Highlight",
            Self::UnmatchedToken => "Focused Token Unmatched Highlight",
            Self::IneligibleToken => "Focused Token Ineligible Highlight",
            Self::Diff => "Difference Highlight",
        }
    }

    /// A human-readable description of this highlight color.
    pub fn description(&self) -> &'static str {
        match self {
            Self::MatchingToken => "Highlight Color for Focused Token and Match",
            Self::UnmatchedToken => {
                "Highlight Color for a Focused Token with no Match"
            }
            Self::IneligibleToken => {
                "Highlight Color for a Focused Token which is ineligible for a match (e.g., whitespace)"
            }
            Self::Diff => "Highlight Color for Differences",
        }
    }

    /// The default color (as an RGB hex string) for this highlight.
    pub fn default_color_hex(&self) -> &'static str {
        match self {
            // Matching token: a soft green
            Self::MatchingToken => "#b3e6b3",
            // Unmatched token: a soft red
            Self::UnmatchedToken => "#ffcccc",
            // Ineligible token: a light gray
            Self::IneligibleToken => "#e0e0e0",
            // Diff: a soft blue
            Self::Diff => "#cce0ff",
        }
    }

    /// The theme color key for this highlight.
    pub fn theme_color_key(&self) -> &'static str {
        match self {
            Self::MatchingToken => "color.bg.codecompare.highlight.field.diff.matching",
            Self::UnmatchedToken => "color.bg.codecompare.highlight.field.diff.not.matching",
            Self::IneligibleToken => "color.bg.codecompare.highlight.field.diff.other",
            Self::Diff => "color.bg.codecompare.highlight.diff",
        }
    }

    /// All highlight color variants.
    pub fn all() -> [DecompilerHighlightColor; 4] {
        [
            Self::MatchingToken,
            Self::UnmatchedToken,
            Self::IneligibleToken,
            Self::Diff,
        ]
    }
}

impl fmt::Display for DecompilerHighlightColor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.option_key())
    }
}

/// An RGB color value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RgbColor {
    /// Red component (0-255).
    pub r: u8,
    /// Green component (0-255).
    pub g: u8,
    /// Blue component (0-255).
    pub b: u8,
}

impl RgbColor {
    /// Create a new RGB color.
    pub fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b }
    }

    /// Parse a color from a hex string like "#rrggbb".
    ///
    /// Returns None if the string is not a valid hex color.
    pub fn from_hex(hex: &str) -> Option<Self> {
        let hex = hex.trim_start_matches('#');
        if hex.len() != 6 {
            return None;
        }
        let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
        let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
        let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
        Some(Self { r, g, b })
    }

    /// Convert to a hex string like "#rrggbb".
    pub fn to_hex(&self) -> String {
        format!("#{:02x}{:02x}{:02x}", self.r, self.g, self.b)
    }

    /// Convert to a packed 32-bit RGBA value (alpha = 255).
    pub fn to_rgba(&self) -> u32 {
        ((self.r as u32) << 24) | ((self.g as u32) << 16) | ((self.b as u32) << 8) | 0xFF
    }
}

impl fmt::Display for RgbColor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Trait for receiving notifications when options change.
pub trait DecompilerOptionsChangeListener: Send + Sync {
    /// Called when any decompiler comparison option changes.
    fn options_changed(&self);
}

/// The options category name used for persisting options.
pub const OPTIONS_CATEGORY_NAME: &str = "Decompiler Code Comparison";

/// The help topic for the options.
pub const HELP_TOPIC: &str = "FunctionComparison";

/// Holds the configurable highlight colors for the decompiler code comparison view.
///
/// Ported from Ghidra's `DecompilerCodeComparisonOptions` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::decompile::decompiler_options::*;
///
/// let mut options = DecompilerCodeComparisonOptions::new();
/// assert_eq!(
///     options.get_matching_token_color(),
///     RgbColor::from_hex("#b3e6b3").unwrap()
/// );
///
/// // Change a color
/// options.set_color(DecompilerHighlightColor::MatchingToken, RgbColor::new(0, 255, 0));
/// assert_eq!(options.get_matching_token_color(), RgbColor::new(0, 255, 0));
/// ```
pub struct DecompilerCodeComparisonOptions {
    /// The matching token highlight color.
    matching_token_highlight: RgbColor,
    /// The unmatched token highlight color.
    unmatched_token_highlight: RgbColor,
    /// The ineligible token highlight color.
    ineligible_token_highlight: RgbColor,
    /// The diff highlight color.
    diff_highlight: RgbColor,
    /// Listeners for option changes.
    listeners: Vec<Arc<dyn DecompilerOptionsChangeListener>>,
}

impl DecompilerCodeComparisonOptions {
    /// Create new options with default colors.
    pub fn new() -> Self {
        Self {
            matching_token_highlight: RgbColor::from_hex(
                DecompilerHighlightColor::MatchingToken.default_color_hex(),
            )
            .unwrap(),
            unmatched_token_highlight: RgbColor::from_hex(
                DecompilerHighlightColor::UnmatchedToken.default_color_hex(),
            )
            .unwrap(),
            ineligible_token_highlight: RgbColor::from_hex(
                DecompilerHighlightColor::IneligibleToken.default_color_hex(),
            )
            .unwrap(),
            diff_highlight: RgbColor::from_hex(
                DecompilerHighlightColor::Diff.default_color_hex(),
            )
            .unwrap(),
            listeners: Vec::new(),
        }
    }

    /// Get the matching token highlight color.
    pub fn get_matching_token_color(&self) -> RgbColor {
        self.matching_token_highlight
    }

    /// Get the unmatched token highlight color.
    pub fn get_unmatched_token_color(&self) -> RgbColor {
        self.unmatched_token_highlight
    }

    /// Get the ineligible token highlight color.
    pub fn get_ineligible_token_color(&self) -> RgbColor {
        self.ineligible_token_highlight
    }

    /// Get the diff highlight color.
    pub fn get_diff_color(&self) -> RgbColor {
        self.diff_highlight
    }

    /// Get the highlight color for a specific category.
    pub fn get_color(&self, kind: DecompilerHighlightColor) -> RgbColor {
        match kind {
            DecompilerHighlightColor::MatchingToken => self.matching_token_highlight,
            DecompilerHighlightColor::UnmatchedToken => self.unmatched_token_highlight,
            DecompilerHighlightColor::IneligibleToken => self.ineligible_token_highlight,
            DecompilerHighlightColor::Diff => self.diff_highlight,
        }
    }

    /// Set the highlight color for a specific category.
    pub fn set_color(&mut self, kind: DecompilerHighlightColor, color: RgbColor) {
        match kind {
            DecompilerHighlightColor::MatchingToken => {
                self.matching_token_highlight = color;
            }
            DecompilerHighlightColor::UnmatchedToken => {
                self.unmatched_token_highlight = color;
            }
            DecompilerHighlightColor::IneligibleToken => {
                self.ineligible_token_highlight = color;
            }
            DecompilerHighlightColor::Diff => {
                self.diff_highlight = color;
            }
        }
        self.fire_options_changed();
    }

    /// Add a listener for option changes.
    pub fn add_listener(&mut self, listener: Arc<dyn DecompilerOptionsChangeListener>) {
        self.listeners.push(listener);
    }

    /// Remove all listeners.
    pub fn clear_listeners(&mut self) {
        self.listeners.clear();
    }

    /// Fire the options changed event.
    fn fire_options_changed(&self) {
        for listener in &self.listeners {
            listener.options_changed();
        }
    }

    /// Load options from a key-value store.
    ///
    /// The store maps option keys to hex color strings. Keys that are
    /// not present in the store keep their current values.
    pub fn load_from_store(&mut self, store: &std::collections::HashMap<String, String>) {
        for kind in DecompilerHighlightColor::all() {
            if let Some(hex) = store.get(kind.option_key()) {
                if let Some(color) = RgbColor::from_hex(hex) {
                    match kind {
                        DecompilerHighlightColor::MatchingToken => {
                            self.matching_token_highlight = color;
                        }
                        DecompilerHighlightColor::UnmatchedToken => {
                            self.unmatched_token_highlight = color;
                        }
                        DecompilerHighlightColor::IneligibleToken => {
                            self.ineligible_token_highlight = color;
                        }
                        DecompilerHighlightColor::Diff => {
                            self.diff_highlight = color;
                        }
                    }
                }
            }
        }
    }

    /// Save options to a key-value store.
    pub fn save_to_store(&self) -> std::collections::HashMap<String, String> {
        let mut store = std::collections::HashMap::new();
        for kind in DecompilerHighlightColor::all() {
            store.insert(
                kind.option_key().to_string(),
                self.get_color(kind).to_hex(),
            );
        }
        store
    }

    /// Check if these options differ from the defaults.
    pub fn is_modified(&self) -> bool {
        let defaults = Self::new();
        self.matching_token_highlight != defaults.matching_token_highlight
            || self.unmatched_token_highlight != defaults.unmatched_token_highlight
            || self.ineligible_token_highlight != defaults.ineligible_token_highlight
            || self.diff_highlight != defaults.diff_highlight
    }

    /// Reset all colors to their defaults.
    pub fn reset_to_defaults(&mut self) {
        let defaults = Self::new();
        self.matching_token_highlight = defaults.matching_token_highlight;
        self.unmatched_token_highlight = defaults.unmatched_token_highlight;
        self.ineligible_token_highlight = defaults.ineligible_token_highlight;
        self.diff_highlight = defaults.diff_highlight;
        self.fire_options_changed();
    }
}

impl Default for DecompilerCodeComparisonOptions {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for DecompilerCodeComparisonOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecompilerCodeComparisonOptions")
            .field("matching_token", &self.matching_token_highlight)
            .field("unmatched_token", &self.unmatched_token_highlight)
            .field("ineligible_token", &self.ineligible_token_highlight)
            .field("diff", &self.diff_highlight)
            .finish()
    }
}

/// A simple listener that tracks option changes.
#[derive(Debug, Default)]
pub struct TrackingOptionsListener {
    /// Number of times options_changed was called.
    pub change_count: Mutex<usize>,
}

impl TrackingOptionsListener {
    /// Create a new tracking listener.
    pub fn new() -> Self {
        Self::default()
    }
}

impl DecompilerOptionsChangeListener for TrackingOptionsListener {
    fn options_changed(&self) {
        *self.change_count.lock().unwrap() += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // --- DecompilerHighlightColor tests ---

    #[test]
    fn test_highlight_color_option_key() {
        assert_eq!(
            DecompilerHighlightColor::MatchingToken.option_key(),
            "Focused Token Match Highlight"
        );
        assert_eq!(
            DecompilerHighlightColor::UnmatchedToken.option_key(),
            "Focused Token Unmatched Highlight"
        );
        assert_eq!(
            DecompilerHighlightColor::IneligibleToken.option_key(),
            "Focused Token Ineligible Highlight"
        );
        assert_eq!(
            DecompilerHighlightColor::Diff.option_key(),
            "Difference Highlight"
        );
    }

    #[test]
    fn test_highlight_color_description() {
        for kind in DecompilerHighlightColor::all() {
            assert!(!kind.description().is_empty());
        }
    }

    #[test]
    fn test_highlight_color_default_hex() {
        for kind in DecompilerHighlightColor::all() {
            let hex = kind.default_color_hex();
            assert!(hex.starts_with('#'));
            assert_eq!(hex.len(), 7);
            assert!(RgbColor::from_hex(hex).is_some());
        }
    }

    #[test]
    fn test_highlight_color_theme_key() {
        for kind in DecompilerHighlightColor::all() {
            assert!(!kind.theme_color_key().is_empty());
        }
    }

    #[test]
    fn test_highlight_color_all() {
        let all = DecompilerHighlightColor::all();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0], DecompilerHighlightColor::MatchingToken);
        assert_eq!(all[1], DecompilerHighlightColor::UnmatchedToken);
        assert_eq!(all[2], DecompilerHighlightColor::IneligibleToken);
        assert_eq!(all[3], DecompilerHighlightColor::Diff);
    }

    #[test]
    fn test_highlight_color_display() {
        assert_eq!(
            format!("{}", DecompilerHighlightColor::MatchingToken),
            "Focused Token Match Highlight"
        );
    }

    // --- RgbColor tests ---

    #[test]
    fn test_rgb_color_new() {
        let c = RgbColor::new(255, 128, 0);
        assert_eq!(c.r, 255);
        assert_eq!(c.g, 128);
        assert_eq!(c.b, 0);
    }

    #[test]
    fn test_rgb_color_from_hex() {
        let c = RgbColor::from_hex("#ff8000").unwrap();
        assert_eq!(c.r, 255);
        assert_eq!(c.g, 128);
        assert_eq!(c.b, 0);
    }

    #[test]
    fn test_rgb_color_from_hex_no_hash() {
        let c = RgbColor::from_hex("ff8000").unwrap();
        assert_eq!(c.r, 255);
        assert_eq!(c.g, 128);
        assert_eq!(c.b, 0);
    }

    #[test]
    fn test_rgb_color_from_hex_invalid() {
        assert!(RgbColor::from_hex("").is_none());
        assert!(RgbColor::from_hex("#ff").is_none());
        assert!(RgbColor::from_hex("#gggggg").is_none());
        assert!(RgbColor::from_hex("#ff80001122").is_none());
    }

    #[test]
    fn test_rgb_color_to_hex() {
        let c = RgbColor::new(255, 128, 0);
        assert_eq!(c.to_hex(), "#ff8000");
    }

    #[test]
    fn test_rgb_color_to_rgba() {
        let c = RgbColor::new(255, 0, 0);
        assert_eq!(c.to_rgba(), 0xFF0000FF);
    }

    #[test]
    fn test_rgb_color_roundtrip() {
        let original = "#b3e6b3";
        let c = RgbColor::from_hex(original).unwrap();
        assert_eq!(c.to_hex(), original);
    }

    #[test]
    fn test_rgb_color_display() {
        let c = RgbColor::new(0, 0, 255);
        assert_eq!(format!("{}", c), "#0000ff");
    }

    #[test]
    fn test_rgb_color_eq() {
        let c1 = RgbColor::new(100, 200, 50);
        let c2 = RgbColor::new(100, 200, 50);
        let c3 = RgbColor::new(100, 200, 51);
        assert_eq!(c1, c2);
        assert_ne!(c1, c3);
    }

    #[test]
    fn test_rgb_color_copy() {
        let c1 = RgbColor::new(10, 20, 30);
        let c2 = c1;
        assert_eq!(c1, c2);
    }

    // --- DecompilerCodeComparisonOptions tests ---

    #[test]
    fn test_options_new_defaults() {
        let options = DecompilerCodeComparisonOptions::new();

        assert_eq!(
            options.get_matching_token_color(),
            RgbColor::from_hex("#b3e6b3").unwrap()
        );
        assert_eq!(
            options.get_unmatched_token_color(),
            RgbColor::from_hex("#ffcccc").unwrap()
        );
        assert_eq!(
            options.get_ineligible_token_color(),
            RgbColor::from_hex("#e0e0e0").unwrap()
        );
        assert_eq!(
            options.get_diff_color(),
            RgbColor::from_hex("#cce0ff").unwrap()
        );
    }

    #[test]
    fn test_options_default() {
        let options = DecompilerCodeComparisonOptions::default();
        assert_eq!(
            options.get_matching_token_color(),
            DecompilerCodeComparisonOptions::new().get_matching_token_color()
        );
    }

    #[test]
    fn test_options_debug() {
        let options = DecompilerCodeComparisonOptions::new();
        let debug = format!("{:?}", options);
        assert!(debug.contains("DecompilerCodeComparisonOptions"));
    }

    #[test]
    fn test_options_get_color() {
        let options = DecompilerCodeComparisonOptions::new();

        assert_eq!(
            options.get_color(DecompilerHighlightColor::MatchingToken),
            options.get_matching_token_color()
        );
        assert_eq!(
            options.get_color(DecompilerHighlightColor::UnmatchedToken),
            options.get_unmatched_token_color()
        );
        assert_eq!(
            options.get_color(DecompilerHighlightColor::IneligibleToken),
            options.get_ineligible_token_color()
        );
        assert_eq!(
            options.get_color(DecompilerHighlightColor::Diff),
            options.get_diff_color()
        );
    }

    #[test]
    fn test_options_set_color() {
        let mut options = DecompilerCodeComparisonOptions::new();
        let new_color = RgbColor::new(255, 0, 255);

        options.set_color(DecompilerHighlightColor::MatchingToken, new_color);
        assert_eq!(options.get_matching_token_color(), new_color);
        assert_eq!(
            options.get_color(DecompilerHighlightColor::MatchingToken),
            new_color
        );
    }

    #[test]
    fn test_options_set_all_colors() {
        let mut options = DecompilerCodeComparisonOptions::new();

        let colors = [
            RgbColor::new(1, 2, 3),
            RgbColor::new(4, 5, 6),
            RgbColor::new(7, 8, 9),
            RgbColor::new(10, 11, 12),
        ];

        for (i, kind) in DecompilerHighlightColor::all().iter().enumerate() {
            options.set_color(*kind, colors[i]);
        }

        assert_eq!(options.get_matching_token_color(), colors[0]);
        assert_eq!(options.get_unmatched_token_color(), colors[1]);
        assert_eq!(options.get_ineligible_token_color(), colors[2]);
        assert_eq!(options.get_diff_color(), colors[3]);
    }

    #[test]
    fn test_options_is_modified_default() {
        let options = DecompilerCodeComparisonOptions::new();
        assert!(!options.is_modified());
    }

    #[test]
    fn test_options_is_modified_after_change() {
        let mut options = DecompilerCodeComparisonOptions::new();
        options.set_color(DecompilerHighlightColor::Diff, RgbColor::new(0, 0, 0));
        assert!(options.is_modified());
    }

    #[test]
    fn test_options_reset_to_defaults() {
        let mut options = DecompilerCodeComparisonOptions::new();
        options.set_color(DecompilerHighlightColor::Diff, RgbColor::new(0, 0, 0));
        assert!(options.is_modified());

        options.reset_to_defaults();
        assert!(!options.is_modified());
        assert_eq!(
            options.get_diff_color(),
            RgbColor::from_hex(DecompilerHighlightColor::Diff.default_color_hex()).unwrap()
        );
    }

    #[test]
    fn test_options_save_and_load() {
        let mut options = DecompilerCodeComparisonOptions::new();
        options.set_color(
            DecompilerHighlightColor::MatchingToken,
            RgbColor::new(10, 20, 30),
        );
        options.set_color(
            DecompilerHighlightColor::Diff,
            RgbColor::new(40, 50, 60),
        );

        let store = options.save_to_store();
        assert_eq!(store.len(), 4);

        let mut restored = DecompilerCodeComparisonOptions::new();
        restored.load_from_store(&store);

        assert_eq!(
            restored.get_matching_token_color(),
            RgbColor::new(10, 20, 30)
        );
        assert_eq!(restored.get_diff_color(), RgbColor::new(40, 50, 60));
    }

    #[test]
    fn test_options_load_partial() {
        let mut store = HashMap::new();
        store.insert(
            "Difference Highlight".to_string(),
            "#aabbcc".to_string(),
        );

        let mut options = DecompilerCodeComparisonOptions::new();
        options.load_from_store(&store);

        // Only the diff color should change
        assert_eq!(options.get_diff_color(), RgbColor::from_hex("#aabbcc").unwrap());
        // Others should remain default
        assert_eq!(
            options.get_matching_token_color(),
            RgbColor::from_hex("#b3e6b3").unwrap()
        );
    }

    #[test]
    fn test_options_load_invalid_hex() {
        let mut store = HashMap::new();
        store.insert(
            "Difference Highlight".to_string(),
            "invalid".to_string(),
        );

        let original = DecompilerCodeComparisonOptions::new();
        let mut options = DecompilerCodeComparisonOptions::new();
        options.load_from_store(&store);

        // Invalid hex should be ignored; color stays at default
        assert_eq!(options.get_diff_color(), original.get_diff_color());
    }

    #[test]
    fn test_options_listener() {
        let mut options = DecompilerCodeComparisonOptions::new();
        let listener = Arc::new(TrackingOptionsListener::new());
        options.add_listener(listener.clone());

        options.set_color(DecompilerHighlightColor::Diff, RgbColor::new(0, 0, 0));
        assert_eq!(*listener.change_count.lock().unwrap(), 1);

        options.set_color(
            DecompilerHighlightColor::MatchingToken,
            RgbColor::new(255, 255, 255),
        );
        assert_eq!(*listener.change_count.lock().unwrap(), 2);
    }

    #[test]
    fn test_options_clear_listeners() {
        let mut options = DecompilerCodeComparisonOptions::new();
        let listener = Arc::new(TrackingOptionsListener::new());
        options.add_listener(listener.clone());

        options.set_color(DecompilerHighlightColor::Diff, RgbColor::new(0, 0, 0));
        assert_eq!(*listener.change_count.lock().unwrap(), 1);

        options.clear_listeners();
        options.set_color(DecompilerHighlightColor::Diff, RgbColor::new(255, 255, 255));
        // Should still be 1 since listener was removed
        assert_eq!(*listener.change_count.lock().unwrap(), 1);
    }

    #[test]
    fn test_options_reset_fires_listener() {
        let mut options = DecompilerCodeComparisonOptions::new();
        let listener = Arc::new(TrackingOptionsListener::new());
        options.add_listener(listener.clone());

        options.set_color(DecompilerHighlightColor::Diff, RgbColor::new(0, 0, 0));
        assert_eq!(*listener.change_count.lock().unwrap(), 1);

        options.reset_to_defaults();
        assert_eq!(*listener.change_count.lock().unwrap(), 2);
    }

    // --- TrackingOptionsListener tests ---

    #[test]
    fn test_tracking_options_listener() {
        let listener = TrackingOptionsListener::new();
        assert_eq!(*listener.change_count.lock().unwrap(), 0);

        listener.options_changed();
        listener.options_changed();
        assert_eq!(*listener.change_count.lock().unwrap(), 2);
    }

    // --- Constants tests ---

    #[test]
    fn test_options_category_name() {
        assert_eq!(OPTIONS_CATEGORY_NAME, "Decompiler Code Comparison");
    }

    #[test]
    fn test_help_topic() {
        assert_eq!(HELP_TOPIC, "FunctionComparison");
    }
}
