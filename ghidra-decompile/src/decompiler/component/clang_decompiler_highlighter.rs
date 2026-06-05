//! Clang decompiler highlighter -- combines syntax highlighting with user highlights.
//!
//! Port of Ghidra's `ghidra.app.decompiler.component.ClangDecompilerHighlighter`.
//!
//! Coordinates between:
//! - Syntax-based coloring (keywords, comments, types, etc.)
//! - User primary/secondary highlights (click-to-highlight matching tokens)
//! - Slice highlights (data-flow slice coloring)
//! - Service highlights (external plugin highlights)

use super::highlight_controller::TokenHighlight;
use super::{ClangHighlightController, ColorProvider, DefaultColorProvider, TokenHighlightColors};
use super::super::clang_node::{ClangNodeId, SyntaxType};

/// Coordinates all highlight layers in the decompiler display.
///
/// This is the top-level highlighter that the decompiler panel uses
/// to determine the final color of each token, combining:
/// 1. Syntax highlighting (base color from syntax type)
/// 2. Primary highlight (clicked token and text matches)
/// 3. Secondary highlights (user bookmarks)
/// 4. Slice highlights (data-flow coloring)
/// 5. Service highlights (external plugin highlights)
///
/// Port of `ghidra.app.decompiler.component.ClangDecompilerHighlighter`.
#[derive(Debug, Clone)]
pub struct ClangDecompilerHighlighter {
    /// Syntax-based color provider.
    color_provider: Box<DefaultColorProvider>,
    /// User highlight controller.
    highlight_controller: ClangHighlightController,
    /// Pre-defined highlight colors.
    highlight_colors: TokenHighlightColors,
    /// Service highlights from external plugins.
    service_highlights: Vec<TokenHighlight>,
    /// Whether syntax highlighting is enabled.
    syntax_highlighting_enabled: bool,
    /// Default background color.
    background_color: String,
}

impl ClangDecompilerHighlighter {
    /// Create a new decompiler highlighter.
    pub fn new() -> Self {
        Self {
            color_provider: Box::new(DefaultColorProvider),
            highlight_controller: ClangHighlightController::new(),
            highlight_colors: TokenHighlightColors::default(),
            service_highlights: Vec::new(),
            syntax_highlighting_enabled: true,
            background_color: "#ffffff".to_string(),
        }
    }

    /// Get the effective color for a token at the given position.
    ///
    /// This method resolves all highlight layers to produce a final color.
    /// The priority order is:
    /// 1. Primary highlight (highest priority)
    /// 2. Service highlights
    /// 3. Slice highlights
    /// 4. Secondary highlights (blended with syntax color)
    /// 5. Syntax highlighting (base color)
    pub fn get_token_color(
        &self,
        node_id: ClangNodeId,
        text: &str,
        syntax_type: SyntaxType,
        is_matching_token: bool,
    ) -> String {
        // Check primary highlight (highest priority).
        if let Some(primary_id) = self.highlight_controller.primary_highlight {
            if node_id == primary_id {
                return self.highlight_colors.primary.clone();
            }
        }

        // Check if this token matches the primary highlight text.
        if is_matching_token && self.highlight_controller.highlight_matching {
            return blend_colors(
                &self.highlight_colors.primary,
                self.background_color(),
                0.4,
            );
        }

        // Check service highlights.
        for sh in &self.service_highlights {
            if sh.node_id == node_id as u64 {
                return sh.color.clone();
            }
        }

        // Check slice highlights.
        if self.highlight_controller.slice_highlights.contains(&node_id) {
            return self.highlight_colors.slice.clone();
        }

        // Check secondary highlights.
        if self.highlight_controller.secondary_highlights.contains(&node_id) {
            // Find the secondary color for this node.
            let idx = self.highlight_controller.secondary_highlights
                .iter()
                .position(|&id| id == node_id)
                .unwrap_or(0);
            return self.highlight_colors.secondary_color(idx).to_string();
        }

        // Fall back to syntax highlighting.
        if self.syntax_highlighting_enabled {
            self.color_provider.color_for_type(syntax_type).to_string()
        } else {
            "#000000".to_string()
        }
    }

    /// Get the background color for a token.
    pub fn background_color(&self) -> &str {
        &self.background_color
    }

    /// Set the background color.
    pub fn set_background_color(&mut self, color: impl Into<String>) {
        self.background_color = color.into();
    }

    /// Enable or disable syntax highlighting.
    pub fn set_syntax_highlighting(&mut self, enabled: bool) {
        self.syntax_highlighting_enabled = enabled;
    }

    /// Get the highlight controller.
    pub fn highlight_controller(&self) -> &ClangHighlightController {
        &self.highlight_controller
    }

    /// Get a mutable reference to the highlight controller.
    pub fn highlight_controller_mut(&mut self) -> &mut ClangHighlightController {
        &mut self.highlight_controller
    }

    /// Add a service highlight from an external plugin.
    pub fn add_service_highlight(&mut self, highlight: TokenHighlight) {
        self.service_highlights.push(highlight);
    }

    /// Remove all service highlights.
    pub fn clear_service_highlights(&mut self) {
        self.service_highlights.clear();
    }

    /// Set the highlight colors.
    pub fn set_highlight_colors(&mut self, colors: TokenHighlightColors) {
        self.highlight_colors = colors;
    }

    /// Clear all highlights (primary, secondary, slice, service).
    pub fn clear_all(&mut self) {
        self.highlight_controller.clear_all();
        self.service_highlights.clear();
    }
}

impl Default for ClangDecompilerHighlighter {
    fn default() -> Self {
        Self::new()
    }
}

/// Blend two hex colors together.
///
/// `factor` is the weight of `color_a` (0.0 = all color_b, 1.0 = all color_a).
fn blend_colors(color_a: &str, color_b: &str, factor: f64) -> String {
    let a = parse_hex_color(color_a).unwrap_or((255, 255, 0));
    let b = parse_hex_color(color_b).unwrap_or((255, 255, 255));
    let f = factor.clamp(0.0, 1.0);
    let r = (a.0 as f64 * f + b.0 as f64 * (1.0 - f)) as u8;
    let g = (a.1 as f64 * f + b.1 as f64 * (1.0 - f)) as u8;
    let bl = (a.2 as f64 * f + b.2 as f64 * (1.0 - f)) as u8;
    format!("#{:02x}{:02x}{:02x}", r, g, bl)
}

/// Parse a hex color string like "#RRGGBB" into (r, g, b).
fn parse_hex_color(hex: &str) -> Option<(u8, u8, u8)> {
    let hex = hex.trim_start_matches('#');
    if hex.len() == 6 {
        let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
        let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
        let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
        Some((r, g, b))
    } else if hex.len() == 8 {
        // Handle #RRGGBBAA by ignoring alpha
        let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
        let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
        let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
        Some((r, g, b))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_highlighter_default() {
        let h = ClangDecompilerHighlighter::new();
        assert!(h.syntax_highlighting_enabled);
        assert_eq!(h.background_color(), "#ffffff");
        assert!(h.service_highlights.is_empty());
    }

    #[test]
    fn test_syntax_color() {
        let h = ClangDecompilerHighlighter::new();
        let color = h.get_token_color(1, "int", SyntaxType::Keyword, false);
        assert_eq!(color, "#0000ff"); // keyword color
    }

    #[test]
    fn test_primary_highlight() {
        let mut h = ClangDecompilerHighlighter::new();
        h.highlight_controller_mut().set_primary(42);
        let color = h.get_token_color(42, "foo", SyntaxType::Variable, false);
        assert_eq!(color, "#ffff00"); // primary highlight color
    }

    #[test]
    fn test_matching_token_highlight() {
        let mut h = ClangDecompilerHighlighter::new();
        h.highlight_controller_mut().set_primary(1);
        let color = h.get_token_color(99, "foo", SyntaxType::Variable, true);
        // Should be blended color
        assert!(color.starts_with('#'));
        assert_ne!(color, "#000000");
    }

    #[test]
    fn test_slice_highlight() {
        let mut h = ClangDecompilerHighlighter::new();
        h.highlight_controller_mut().slice_highlights.push(5);
        let color = h.get_token_color(5, "x", SyntaxType::Variable, false);
        assert_eq!(color, "#c0c0ff"); // slice color
    }

    #[test]
    fn test_secondary_highlight() {
        let mut h = ClangDecompilerHighlighter::new();
        h.highlight_controller_mut().add_secondary(10);
        let color = h.get_token_color(10, "y", SyntaxType::Variable, false);
        assert_eq!(color, "#00ffff"); // first secondary color
    }

    #[test]
    fn test_service_highlight() {
        let mut h = ClangDecompilerHighlighter::new();
        h.add_service_highlight(TokenHighlight::new(7, "#ff00ff".to_string(), 5));
        let color = h.get_token_color(7, "z", SyntaxType::Variable, false);
        assert_eq!(color, "#ff00ff");
    }

    #[test]
    fn test_no_syntax_highlighting() {
        let mut h = ClangDecompilerHighlighter::new();
        h.set_syntax_highlighting(false);
        let color = h.get_token_color(1, "int", SyntaxType::Keyword, false);
        assert_eq!(color, "#000000"); // default when syntax off
    }

    #[test]
    fn test_clear_all() {
        let mut h = ClangDecompilerHighlighter::new();
        h.highlight_controller_mut().set_primary(1);
        h.highlight_controller_mut().add_secondary(2);
        h.add_service_highlight(TokenHighlight::new(3, "#ff0000".to_string(), 1));
        h.clear_all();
        assert!(!h.highlight_controller().has_highlights());
        assert!(h.service_highlights.is_empty());
    }

    #[test]
    fn test_blend_colors() {
        let blended = blend_colors("#ff0000", "#0000ff", 0.5);
        // Should be purple-ish: (127, 0, 127) or (128, 0, 128) depending on rounding
        let parsed = parse_hex_color(&blended).unwrap();
        assert!((parsed.0 as i32 - 127).unsigned_abs() <= 1);
        assert_eq!(parsed.1, 0);
        assert!((parsed.2 as i32 - 127).unsigned_abs() <= 1);
    }

    #[test]
    fn test_blend_colors_full() {
        assert_eq!(blend_colors("#ff0000", "#0000ff", 1.0), "#ff0000");
        assert_eq!(blend_colors("#ff0000", "#0000ff", 0.0), "#0000ff");
    }

    #[test]
    fn test_parse_hex_color() {
        assert_eq!(parse_hex_color("#ff0000"), Some((255, 0, 0)));
        assert_eq!(parse_hex_color("#00ff00"), Some((0, 255, 0)));
        assert_eq!(parse_hex_color("ff0000"), Some((255, 0, 0)));
        assert_eq!(parse_hex_color("#ff0000ff"), Some((255, 0, 0)));
        assert_eq!(parse_hex_color("invalid"), None);
    }
}
