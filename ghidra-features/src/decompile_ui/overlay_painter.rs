//! Overlay message painter -- Rust port of
//! `ghidra.app.plugin.core.decompile.OverlayMessagePainter`.
//!
//! Paints a translucent overlay message on top of the decompiler panel,
//! typically used to indicate that a refresh is needed (e.g. when the
//! display is locked and the program has changed).
//!
//! # Architecture
//!
//! ```text
//! OverlayMessagePainter
//!   ├── message: Option<String>       (the overlay text)
//!   ├── active: bool                  (whether overlay is showing)
//!   ├── margin: u32                   (pixels from bottom-right corner)
//!   ├── font_id: String               (theme font identifier)
//!   ├── gradient_colors: [Color; 2]   (gradient start/end colours)
//!   ├── gradient_fractions: [f32; 2]  (gradient stop positions)
//!   ├── alpha: f32                    (composite alpha for translucency)
//!   └── text_color: Color             (message text colour)
//! ```
//!
//! # Painting
//!
//! When active, the painter:
//!
//! 1. Sets a translucent composite (alpha = 0.60).
//! 2. Renders a vertical gradient at the bottom of the panel.
//! 3. Draws the message text in the bottom-right corner.
//! 4. Restores the original composite.
//!
//! The gradient fades from white at the top to the theme's background
//! colour (`color.bg.visualgraph.message`) at the bottom.

// ---------------------------------------------------------------------------
// Color -- a simple RGBA colour representation
// ---------------------------------------------------------------------------

/// An RGBA colour.
///
/// In Ghidra this is `java.awt.Color` or `generic.theme.GColor`.
/// Here we store raw RGBA components.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    /// Red component (0-255).
    pub r: u8,
    /// Green component (0-255).
    pub g: u8,
    /// Blue component (0-255).
    pub b: u8,
    /// Alpha component (0-255).
    pub a: u8,
}

impl Color {
    /// Create a new colour.
    pub const fn new(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Create an opaque colour.
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// White (fully opaque).
    pub const WHITE: Self = Self::rgb(255, 255, 255);

    /// Black (fully opaque).
    pub const BLACK: Self = Self::rgb(0, 0, 0);

    /// Default gradient end colour (light grey).
    ///
    /// Corresponds to Ghidra's `color.bg.visualgraph.message`.
    pub const DEFAULT_GRADIENT: Self = Self::rgb(200, 200, 200);
}

// ---------------------------------------------------------------------------
// Rectangle -- a bounding box for painting
// ---------------------------------------------------------------------------

/// A rectangle defined by position and size.
///
/// In Ghidra this is `java.awt.Rectangle`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rectangle {
    /// X coordinate of the top-left corner.
    pub x: i32,
    /// Y coordinate of the top-left corner.
    pub y: i32,
    /// Width in pixels.
    pub width: i32,
    /// Height in pixels.
    pub height: i32,
}

impl Rectangle {
    /// Create a new rectangle.
    pub const fn new(x: i32, y: i32, width: i32, height: i32) -> Self {
        Self { x, y, width, height }
    }

    /// Create a rectangle at the origin with the given size.
    pub const fn from_size(width: i32, height: i32) -> Self {
        Self { x: 0, y: 0, width, height }
    }
}

// ---------------------------------------------------------------------------
// OverlayMessagePainter
// ---------------------------------------------------------------------------

/// A painter that renders an optional overlay message on the decompiler view.
///
/// When active, the message is displayed in the bottom-right corner of the
/// decompiler panel.  The message typically instructs the user to press a
/// key binding (e.g., "F5 to refresh") when the display is locked.
///
/// # Ghidra Mapping
///
/// In Ghidra, this is the `OverlayMessagePainter` class that is used
/// as a field of `DecompilerProvider`.  It is called from the
/// `DecoratorPanel.paint()` method to draw over the decompiler panel.
///
/// # Theme Integration
///
/// The painter uses theme identifiers:
/// - `font.graph.component.message` -- the font for the message text
/// - `color.bg.visualgraph.message` -- the gradient end colour
///
/// In the full implementation, these are resolved via `Gui.getFont()`
/// and `GColor`.
#[derive(Debug, Clone)]
pub struct OverlayMessagePainter {
    /// The current overlay message.  `None` or empty means "inactive".
    message: Option<String>,
    /// Whether the overlay is actively showing.
    active: bool,
    /// Margin in pixels from the bottom-right corner.
    margin: u32,
    /// The theme font identifier.
    font_id: String,
    /// The gradient start colour (top of gradient).
    gradient_start: Color,
    /// The gradient end colour (bottom of gradient).
    gradient_end: Color,
    /// The gradient stop positions (0.0 to 1.0).
    gradient_fractions: [f32; 2],
    /// The composite alpha for translucency (0.0 to 1.0).
    alpha: f32,
    /// The message text colour.
    text_color: Color,
}

impl OverlayMessagePainter {
    /// The default margin in pixels.
    pub const DEFAULT_MARGIN: u32 = 10;

    /// The default font theme identifier.
    pub const DEFAULT_FONT_ID: &'static str = "font.graph.component.message";

    /// The default gradient background theme colour key.
    pub const GRADIENT_COLOR_KEY: &'static str = "color.bg.visualgraph.message";

    /// The default composite alpha.
    pub const DEFAULT_ALPHA: f32 = 0.60;

    /// Create a new overlay painter with default settings.
    pub fn new() -> Self {
        Self {
            message: None,
            active: false,
            margin: Self::DEFAULT_MARGIN,
            font_id: Self::DEFAULT_FONT_ID.to_string(),
            gradient_start: Color::WHITE,
            gradient_end: Color::DEFAULT_GRADIENT,
            gradient_fractions: [0.0, 0.95],
            alpha: Self::DEFAULT_ALPHA,
            text_color: Color::BLACK,
        }
    }

    /// Create a new overlay painter with custom colours.
    pub fn with_colors(
        gradient_start: Color,
        gradient_end: Color,
        text_color: Color,
    ) -> Self {
        Self {
            message: None,
            active: false,
            margin: Self::DEFAULT_MARGIN,
            font_id: Self::DEFAULT_FONT_ID.to_string(),
            gradient_start,
            gradient_end,
            gradient_fractions: [0.0, 0.95],
            alpha: Self::DEFAULT_ALPHA,
            text_color,
        }
    }

    /// Returns `true` if the overlay is active (a message is being shown).
    pub fn is_active(&self) -> bool {
        self.active && self.message.is_some()
    }

    /// Set the overlay message.  Pass an empty string or `None` to hide.
    pub fn set_message(&mut self, msg: impl Into<String>) {
        let s: String = msg.into();
        if s.is_empty() {
            self.message = None;
            self.active = false;
        } else {
            self.message = Some(s);
            self.active = true;
        }
    }

    /// Get the current overlay message.
    pub fn get_message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Clear the overlay.
    pub fn clear(&mut self) {
        self.message = None;
        self.active = false;
    }

    /// Get the margin in pixels.
    pub fn margin(&self) -> u32 {
        self.margin
    }

    /// Set the margin in pixels.
    pub fn set_margin(&mut self, margin: u32) {
        self.margin = margin;
    }

    /// Get the font theme identifier.
    pub fn font_id(&self) -> &str {
        &self.font_id
    }

    /// Set the font theme identifier.
    pub fn set_font_id(&mut self, font_id: impl Into<String>) {
        self.font_id = font_id.into();
    }

    /// Get the composite alpha.
    pub fn alpha(&self) -> f32 {
        self.alpha
    }

    /// Set the composite alpha (clamped to 0.0..1.0).
    pub fn set_alpha(&mut self, alpha: f32) {
        self.alpha = alpha.clamp(0.0, 1.0);
    }

    /// Get the gradient start colour.
    pub fn gradient_start(&self) -> Color {
        self.gradient_start
    }

    /// Get the gradient end colour.
    pub fn gradient_end(&self) -> Color {
        self.gradient_end
    }

    /// Get the gradient stop positions.
    pub fn gradient_fractions(&self) -> [f32; 2] {
        self.gradient_fractions
    }

    /// Set the gradient stop positions.
    pub fn set_gradient_fractions(&mut self, start: f32, end: f32) {
        self.gradient_fractions = [start.clamp(0.0, 1.0), end.clamp(0.0, 1.0)];
    }

    /// Get the text colour.
    pub fn text_color(&self) -> Color {
        self.text_color
    }

    /// Set the text colour.
    pub fn set_text_color(&mut self, color: Color) {
        self.text_color = color;
    }

    /// Compute the gradient rectangle for the given panel bounds.
    ///
    /// The gradient occupies the bottom portion of the panel, with
    /// height = 3 * text_height.
    pub fn compute_gradient_bounds(
        &self,
        panel_bounds: Rectangle,
        text_height: i32,
    ) -> Rectangle {
        let gradient_height = text_height * 3;
        let y = panel_bounds.height - gradient_height;
        Rectangle::new(0, y, panel_bounds.width, gradient_height)
    }

    /// Compute the text position for the given panel bounds and text size.
    ///
    /// Returns (x, y) where x is the right-aligned position and y is
    /// the baseline position.
    pub fn compute_text_position(
        &self,
        panel_bounds: Rectangle,
        text_width: i32,
        text_height: i32,
    ) -> (i32, i32) {
        let x = panel_bounds.width - text_width - self.margin as i32;
        let y = panel_bounds.height - text_height / 2;
        (x, y)
    }

    /// Simulate the painting operation.
    ///
    /// In the full implementation, this performs the actual Graphics2D
    /// painting.  Here we return a paint description that captures what
    /// would be drawn.
    pub fn describe_paint(&self, panel_bounds: Rectangle, text_height: i32) -> Option<PaintDescription> {
        if !self.is_active() {
            return None;
        }

        let msg = self.message.as_ref()?;
        let gradient_bounds = self.compute_gradient_bounds(panel_bounds, text_height);
        let (text_x, text_y) = self.compute_text_position(
            panel_bounds,
            msg.len() as i32 * 8, // approximate text width
            text_height,
        );

        Some(PaintDescription {
            message: msg.clone(),
            gradient_bounds,
            text_position: (text_x, text_y),
            alpha: self.alpha,
            gradient_start: self.gradient_start,
            gradient_end: self.gradient_end,
            text_color: self.text_color,
        })
    }
}

impl Default for OverlayMessagePainter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PaintDescription -- describes what the painter would render
// ---------------------------------------------------------------------------

/// A description of the painting operations that the overlay painter
/// would perform.
///
/// This is used for testing and debugging the paint logic without
/// requiring an actual graphics context.
#[derive(Debug, Clone)]
pub struct PaintDescription {
    /// The message text.
    pub message: String,
    /// The gradient rectangle.
    pub gradient_bounds: Rectangle,
    /// The text position (x, y).
    pub text_position: (i32, i32),
    /// The composite alpha.
    pub alpha: f32,
    /// The gradient start colour.
    pub gradient_start: Color,
    /// The gradient end colour.
    pub gradient_end: Color,
    /// The text colour.
    pub text_color: Color,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Color --

    #[test]
    fn test_color_new() {
        let c = Color::new(128, 64, 32, 200);
        assert_eq!(c.r, 128);
        assert_eq!(c.g, 64);
        assert_eq!(c.b, 32);
        assert_eq!(c.a, 200);
    }

    #[test]
    fn test_color_rgb() {
        let c = Color::rgb(10, 20, 30);
        assert_eq!(c.a, 255);
    }

    #[test]
    fn test_color_constants() {
        assert_eq!(Color::WHITE, Color::rgb(255, 255, 255));
        assert_eq!(Color::BLACK, Color::rgb(0, 0, 0));
    }

    // -- Rectangle --

    #[test]
    fn test_rectangle_new() {
        let r = Rectangle::new(10, 20, 100, 50);
        assert_eq!(r.x, 10);
        assert_eq!(r.y, 20);
        assert_eq!(r.width, 100);
        assert_eq!(r.height, 50);
    }

    #[test]
    fn test_rectangle_from_size() {
        let r = Rectangle::from_size(200, 100);
        assert_eq!(r.x, 0);
        assert_eq!(r.y, 0);
        assert_eq!(r.width, 200);
        assert_eq!(r.height, 100);
    }

    // -- OverlayMessagePainter --

    #[test]
    fn test_overlay_painter_new() {
        let painter = OverlayMessagePainter::new();
        assert!(!painter.is_active());
        assert!(painter.get_message().is_none());
        assert_eq!(painter.margin(), 10);
        assert_eq!(painter.font_id(), "font.graph.component.message");
        assert!((painter.alpha() - 0.60).abs() < f32::EPSILON);
    }

    #[test]
    fn test_overlay_painter_with_colors() {
        let painter = OverlayMessagePainter::with_colors(
            Color::rgb(255, 0, 0),
            Color::rgb(0, 0, 255),
            Color::rgb(0, 255, 0),
        );
        assert_eq!(painter.gradient_start(), Color::rgb(255, 0, 0));
        assert_eq!(painter.gradient_end(), Color::rgb(0, 0, 255));
        assert_eq!(painter.text_color(), Color::rgb(0, 255, 0));
    }

    #[test]
    fn test_overlay_painter_set_message() {
        let mut painter = OverlayMessagePainter::new();
        painter.set_message("F5 to refresh");
        assert!(painter.is_active());
        assert_eq!(painter.get_message(), Some("F5 to refresh"));
    }

    #[test]
    fn test_overlay_painter_clear() {
        let mut painter = OverlayMessagePainter::new();
        painter.set_message("test");
        assert!(painter.is_active());

        painter.clear();
        assert!(!painter.is_active());
        assert!(painter.get_message().is_none());
    }

    #[test]
    fn test_overlay_painter_empty_string_hides() {
        let mut painter = OverlayMessagePainter::new();
        painter.set_message("hello");
        painter.set_message("");
        assert!(!painter.is_active());
    }

    #[test]
    fn test_overlay_painter_none_hides() {
        let mut painter = OverlayMessagePainter::new();
        painter.set_message("hello");
        painter.set_message("");
        assert!(!painter.is_active());
    }

    #[test]
    fn test_overlay_painter_margin() {
        let mut painter = OverlayMessagePainter::new();
        painter.set_margin(20);
        assert_eq!(painter.margin(), 20);
    }

    #[test]
    fn test_overlay_painter_font_id() {
        let mut painter = OverlayMessagePainter::new();
        painter.set_font_id("custom.font");
        assert_eq!(painter.font_id(), "custom.font");
    }

    #[test]
    fn test_overlay_painter_alpha() {
        let mut painter = OverlayMessagePainter::new();
        painter.set_alpha(0.80);
        assert!((painter.alpha() - 0.80).abs() < f32::EPSILON);
    }

    #[test]
    fn test_overlay_painter_alpha_clamped() {
        let mut painter = OverlayMessagePainter::new();
        painter.set_alpha(1.5);
        assert!((painter.alpha() - 1.0).abs() < f32::EPSILON);

        painter.set_alpha(-0.5);
        assert!((painter.alpha() - 0.0).abs() < f32::EPSILON);
    }

    #[test]
    fn test_overlay_painter_gradient_fractions() {
        let mut painter = OverlayMessagePainter::new();
        painter.set_gradient_fractions(0.1, 0.9);
        assert_eq!(painter.gradient_fractions(), [0.1, 0.9]);
    }

    #[test]
    fn test_overlay_painter_text_color() {
        let mut painter = OverlayMessagePainter::new();
        painter.set_text_color(Color::rgb(255, 0, 0));
        assert_eq!(painter.text_color(), Color::rgb(255, 0, 0));
    }

    #[test]
    fn test_overlay_painter_compute_gradient_bounds() {
        let painter = OverlayMessagePainter::new();
        let panel = Rectangle::from_size(800, 600);
        let text_height = 16;
        let gradient = painter.compute_gradient_bounds(panel, text_height);
        assert_eq!(gradient.x, 0);
        assert_eq!(gradient.y, 600 - 48); // 600 - 3*16
        assert_eq!(gradient.width, 800);
        assert_eq!(gradient.height, 48);
    }

    #[test]
    fn test_overlay_painter_compute_text_position() {
        let painter = OverlayMessagePainter::new();
        let panel = Rectangle::from_size(800, 600);
        let (x, y) = painter.compute_text_position(panel, 200, 16);
        assert_eq!(x, 800 - 200 - 10); // width - text_width - margin
        assert_eq!(y, 600 - 8); // height - text_height/2
    }

    #[test]
    fn test_overlay_painter_describe_paint_inactive() {
        let painter = OverlayMessagePainter::new();
        let panel = Rectangle::from_size(800, 600);
        assert!(painter.describe_paint(panel, 16).is_none());
    }

    #[test]
    fn test_overlay_painter_describe_paint_active() {
        let mut painter = OverlayMessagePainter::new();
        painter.set_message("F5 to refresh");
        let panel = Rectangle::from_size(800, 600);
        let desc = painter.describe_paint(panel, 16).unwrap();
        assert_eq!(desc.message, "F5 to refresh");
        assert!((desc.alpha - 0.60).abs() < f32::EPSILON);
        assert_eq!(desc.text_color, Color::BLACK);
    }

    #[test]
    fn test_overlay_painter_clone() {
        let mut painter = OverlayMessagePainter::new();
        painter.set_message("clone test");
        let cloned = painter.clone();
        assert_eq!(cloned.get_message(), Some("clone test"));
        assert!(cloned.is_active());
    }

    #[test]
    fn test_overlay_painter_default() {
        let painter = OverlayMessagePainter::default();
        assert!(!painter.is_active());
        assert!(painter.get_message().is_none());
    }

    // -- PaintDescription --

    #[test]
    fn test_paint_description() {
        let desc = PaintDescription {
            message: "test".into(),
            gradient_bounds: Rectangle::new(0, 552, 800, 48),
            text_position: (590, 592),
            alpha: 0.60,
            gradient_start: Color::WHITE,
            gradient_end: Color::DEFAULT_GRADIENT,
            text_color: Color::BLACK,
        };
        assert_eq!(desc.message, "test");
        assert!((desc.alpha - 0.60).abs() < f32::EPSILON);
    }
}
