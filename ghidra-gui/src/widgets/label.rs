//! Label widgets.
//!
//! Port of Ghidra's `docking.widgets.label` package. Provides label variants
//! with different mutability and HTML rendering semantics, adapted for egui.
//!
//! # Label variants
//!
//! | Widget | Mutable | HTML | Description |
//! |--------|---------|------|-------------|
//! | `GLabel` | No | No | Immutable plain-text label |
//! | `GDLabel` | Yes | No | Mutable plain-text label |
//! | `GHtmlLabel` | No | Yes | Immutable HTML-rendered label |
//! | `GDHtmlLabel` | Yes | Yes | Mutable HTML-rendered label |
//!
//! In egui, the distinction between mutable and immutable is enforced by the
//! Rust type system: `GLabel` stores a fixed `String` and does not expose a
//! `set_text` method, while `GDLabel` allows updating the text at any time.

use egui::{Color32, RichText, Ui};

// ---------------------------------------------------------------------------
// GLabel -- immutable plain-text label
// ---------------------------------------------------------------------------

/// An immutable plain-text label.
///
/// Once created, the text cannot be changed. HTML rendering is disabled.
/// This is the Rust equivalent of Ghidra's `GLabel`.
#[derive(Debug, Clone)]
pub struct GLabel {
    text: String,
    alignment: LabelAlignment,
    color: Option<Color32>,
    font_size: Option<f32>,
}

impl GLabel {
    /// Create a new immutable label with the given text.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            alignment: LabelAlignment::Left,
            color: None,
            font_size: None,
        }
    }

    /// Create a label with center alignment.
    pub fn centered(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            alignment: LabelAlignment::Center,
            color: None,
            font_size: None,
        }
    }

    /// Create a label with right alignment.
    pub fn right_aligned(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            alignment: LabelAlignment::Right,
            color: None,
            font_size: None,
        }
    }

    /// Set the text color.
    pub fn with_color(mut self, color: Color32) -> Self {
        self.color = Some(color);
        self
    }

    /// Set the font size.
    pub fn with_font_size(mut self, size: f32) -> Self {
        self.font_size = Some(size);
        self
    }

    /// Get the label text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Render the label in the given egui UI.
    pub fn show(&self, ui: &mut Ui) -> egui::Response {
        let mut rich = RichText::new(&self.text);
        if let Some(color) = self.color {
            rich = rich.color(color);
        }
        if let Some(size) = self.font_size {
            rich = rich.size(size);
        }
        match self.alignment {
            LabelAlignment::Left => ui.label(rich),
            LabelAlignment::Center => {
                let resp = ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        ui.label(rich)
                    })
                    .inner
                });
                resp.inner
            }
            LabelAlignment::Right => {
                let resp = ui.horizontal(|ui| {
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(rich)
                    })
                    .inner
                });
                resp.inner
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GDLabel -- mutable plain-text label
// ---------------------------------------------------------------------------

/// A mutable plain-text label.
///
/// The text can be changed after creation. HTML rendering is disabled.
/// This is the Rust equivalent of Ghidra's `GDLabel`.
#[derive(Debug, Clone)]
pub struct GDLabel {
    text: String,
    alignment: LabelAlignment,
    color: Option<Color32>,
    font_size: Option<f32>,
}

impl GDLabel {
    /// Create a new mutable label with the given text.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            alignment: LabelAlignment::Left,
            color: None,
            font_size: None,
        }
    }

    /// Create a mutable label with center alignment.
    pub fn centered(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            alignment: LabelAlignment::Center,
            color: None,
            font_size: None,
        }
    }

    /// Set the text color.
    pub fn with_color(mut self, color: Color32) -> Self {
        self.color = Some(color);
        self
    }

    /// Set the font size.
    pub fn with_font_size(mut self, size: f32) -> Self {
        self.font_size = Some(size);
        self
    }

    /// Get the label text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Update the label text.
    pub fn set_text(&mut self, text: impl Into<String>) {
        self.text = text.into();
    }

    /// Render the label in the given egui UI.
    pub fn show(&self, ui: &mut Ui) -> egui::Response {
        let mut rich = RichText::new(&self.text);
        if let Some(color) = self.color {
            rich = rich.color(color);
        }
        if let Some(size) = self.font_size {
            rich = rich.size(size);
        }
        ui.label(rich)
    }
}

// ---------------------------------------------------------------------------
// GHtmlLabel -- immutable HTML-rendered label
// ---------------------------------------------------------------------------

/// An immutable label with HTML rendering.
///
/// In egui, this uses `egui::RichText` to render styled text. True HTML
/// rendering is approximated through egui's text formatting capabilities.
/// This is the Rust equivalent of Ghidra's `GHtmlLabel`.
#[derive(Debug, Clone)]
pub struct GHtmlLabel {
    text: String,
    alignment: LabelAlignment,
}

impl GHtmlLabel {
    /// Create a new immutable HTML label.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            alignment: LabelAlignment::Left,
        }
    }

    /// Create a centered HTML label.
    pub fn centered(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            alignment: LabelAlignment::Center,
        }
    }

    /// Get the label text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Render the label in the given egui UI.
    ///
    /// Uses egui's markup-like formatting. Supports a subset of HTML:
    /// - `<b>text</b>` for bold
    /// - `<i>text</i>` for italic
    /// - `<code>text</code>` for monospace
    pub fn show(&self, ui: &mut Ui) -> egui::Response {
        let rich = parse_simple_html(&self.text);
        ui.label(rich)
    }
}

// ---------------------------------------------------------------------------
// GDHtmlLabel -- mutable HTML-rendered label
// ---------------------------------------------------------------------------

/// A mutable label with HTML rendering.
///
/// The text can be changed after creation. Uses egui's text formatting
/// to approximate HTML rendering. This is the Rust equivalent of Ghidra's
/// `GDHtmlLabel`.
#[derive(Debug, Clone)]
pub struct GDHtmlLabel {
    text: String,
    alignment: LabelAlignment,
}

impl GDHtmlLabel {
    /// Create a new mutable HTML label.
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            alignment: LabelAlignment::Left,
        }
    }

    /// Get the label text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Update the label text.
    pub fn set_text(&mut self, text: impl Into<String>) {
        self.text = text.into();
    }

    /// Render the label in the given egui UI.
    pub fn show(&self, ui: &mut Ui) -> egui::Response {
        let rich = parse_simple_html(&self.text);
        ui.label(rich)
    }
}

// ---------------------------------------------------------------------------
// GIconLabel -- icon-only label
// ---------------------------------------------------------------------------

/// A label that displays only an icon image, with no text.
///
/// In egui, this is rendered using `ui.image()` or a custom paint callback.
/// This is the Rust equivalent of Ghidra's `GIconLabel`.
#[derive(Debug, Clone)]
pub struct GIconLabel {
    icon_name: String,
    size: Option<egui::Vec2>,
    tooltip: Option<String>,
}

impl GIconLabel {
    /// Create a new icon label by name.
    pub fn new(icon_name: impl Into<String>) -> Self {
        Self {
            icon_name: icon_name.into(),
            size: None,
            tooltip: None,
        }
    }

    /// Set the icon display size.
    pub fn with_size(mut self, size: egui::Vec2) -> Self {
        self.size = Some(size);
        self
    }

    /// Set a tooltip for the icon.
    pub fn with_tooltip(mut self, tooltip: impl Into<String>) -> Self {
        self.tooltip = Some(tooltip.into());
        self
    }

    /// Get the icon name.
    pub fn icon_name(&self) -> &str {
        &self.icon_name
    }

    /// Render the icon label in the given egui UI.
    ///
    /// Returns the response from the egui widget. In a full implementation,
    /// this would load the icon texture from the resource manager. For now,
    /// it displays the icon name as a placeholder.
    pub fn show(&self, ui: &mut Ui) -> egui::Response {
        let size = self.size.unwrap_or(egui::Vec2::splat(16.0));
        // Placeholder: render icon name as text with monospace font
        let rich = RichText::new(&self.icon_name)
            .size(size.x)
            .monospace();
        let resp = ui.label(rich);
        if let Some(ref tip) = self.tooltip {
            resp.on_hover_text(tip)
        } else {
            resp
        }
    }
}

// ---------------------------------------------------------------------------
// LabelAlignment
// ---------------------------------------------------------------------------

/// Horizontal alignment for labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelAlignment {
    Left,
    Center,
    Right,
}

impl Default for LabelAlignment {
    fn default() -> Self {
        LabelAlignment::Left
    }
}

// ---------------------------------------------------------------------------
// Helper: simple HTML parsing for egui
// ---------------------------------------------------------------------------

/// Parse a simple HTML string into an egui `RichText`.
///
/// Supports a very limited subset of HTML tags:
/// - `<b>...</b>` for bold
/// - `<i>...</i>` for italic
/// - `<code>...</code>` for monospace
///
/// All other tags are stripped, and the text content is preserved.
fn parse_simple_html(html: &str) -> RichText {
    let mut rich = RichText::new("");
    let mut text = html.to_string();

    // Check for bold
    if text.contains("<b>") {
        text = text.replace("<b>", "").replace("</b>", "");
        rich = rich.strong();
    }

    // Check for italic
    if text.contains("<i>") {
        text = text.replace("<i>", "").replace("</i>", "");
        rich = rich.italics();
    }

    // Check for code
    if text.contains("<code>") {
        text = text.replace("<code>", "").replace("</code>", "");
        rich = rich.code();
    }

    // Strip any remaining HTML tags
    let stripped = strip_html_tags(&text);
    rich.text(stripped)
}

/// Strip all HTML tags from a string, returning only the text content.
fn strip_html_tags(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut in_tag = false;
    for ch in s.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // GLabel tests
    #[test]
    fn test_glabel_new() {
        let label = GLabel::new("Hello");
        assert_eq!(label.text(), "Hello");
    }

    #[test]
    fn test_glabel_centered() {
        let label = GLabel::centered("Center");
        assert_eq!(label.text(), "Center");
        assert_eq!(label.alignment, LabelAlignment::Center);
    }

    #[test]
    fn test_glabel_right_aligned() {
        let label = GLabel::right_aligned("Right");
        assert_eq!(label.alignment, LabelAlignment::Right);
    }

    #[test]
    fn test_glabel_with_color() {
        let label = GLabel::new("Colored").with_color(Color32::RED);
        assert_eq!(label.color, Some(Color32::RED));
    }

    #[test]
    fn test_glabel_with_font_size() {
        let label = GLabel::new("Big").with_font_size(24.0);
        assert_eq!(label.font_size, Some(24.0));
    }

    // GDLabel tests
    #[test]
    fn test_gdlabel_new() {
        let label = GDLabel::new("Hello");
        assert_eq!(label.text(), "Hello");
    }

    #[test]
    fn test_gdlabel_set_text() {
        let mut label = GDLabel::new("Initial");
        assert_eq!(label.text(), "Initial");

        label.set_text("Updated");
        assert_eq!(label.text(), "Updated");
    }

    #[test]
    fn test_gdlabel_centered() {
        let label = GDLabel::centered("Center");
        assert_eq!(label.alignment, LabelAlignment::Center);
    }

    #[test]
    fn test_gdlabel_with_color() {
        let label = GDLabel::new("C").with_color(Color32::BLUE);
        assert_eq!(label.color, Some(Color32::BLUE));
    }

    // GHtmlLabel tests
    #[test]
    fn test_ghtmllabel_new() {
        let label = GHtmlLabel::new("<b>Bold</b>");
        assert_eq!(label.text(), "<b>Bold</b>");
    }

    #[test]
    fn test_ghtmllabel_centered() {
        let label = GHtmlLabel::centered("Center");
        assert_eq!(label.alignment, LabelAlignment::Center);
    }

    // GDHtmlLabel tests
    #[test]
    fn test_gdhtmllabel_new() {
        let label = GDHtmlLabel::new("<i>Italic</i>");
        assert_eq!(label.text(), "<i>Italic</i>");
    }

    #[test]
    fn test_gdhtmllabel_set_text() {
        let mut label = GDHtmlLabel::new("Old");
        label.set_text("<b>New</b>");
        assert_eq!(label.text(), "<b>New</b>");
    }

    // GIconLabel tests
    #[test]
    fn test_giconlabel_new() {
        let label = GIconLabel::new("icon_save");
        assert_eq!(label.icon_name(), "icon_save");
    }

    #[test]
    fn test_giconlabel_with_size() {
        let label = GIconLabel::new("icon").with_size(egui::Vec2::new(32.0, 32.0));
        assert_eq!(label.size, Some(egui::Vec2::new(32.0, 32.0)));
    }

    #[test]
    fn test_giconlabel_with_tooltip() {
        let label = GIconLabel::new("icon").with_tooltip("Save file");
        assert_eq!(label.tooltip, Some("Save file".to_string()));
    }

    // LabelAlignment tests
    #[test]
    fn test_label_alignment_default() {
        assert_eq!(LabelAlignment::default(), LabelAlignment::Left);
    }

    // HTML parsing tests
    #[test]
    fn test_strip_html_tags() {
        assert_eq!(strip_html_tags("Hello"), "Hello");
        assert_eq!(strip_html_tags("<b>Bold</b>"), "Bold");
        assert_eq!(strip_html_tags("<i>Italic</i>"), "Italic");
        assert_eq!(strip_html_tags("<b><i>Bold Italic</i></b>"), "Bold Italic");
        assert_eq!(strip_html_tags("No tags"), "No tags");
        assert_eq!(strip_html_tags(""), "");
    }

    #[test]
    fn test_parse_simple_html_plain() {
        let rich = parse_simple_html("Hello");
        // Just verify it doesn't panic
        let _ = rich;
    }

    #[test]
    fn test_parse_simple_html_bold() {
        let rich = parse_simple_html("<b>Bold</b>");
        let _ = rich;
    }

    #[test]
    fn test_parse_simple_html_italic() {
        let rich = parse_simple_html("<i>Italic</i>");
        let _ = rich;
    }

    #[test]
    fn test_parse_simple_html_code() {
        let rich = parse_simple_html("<code>code</code>");
        let _ = rich;
    }
}
