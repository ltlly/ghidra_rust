//! Close icon rendered as an X in a circle.
//!
//! Ports `generic.theme.CloseIcon`.

/// A close icon (X) that renders as a small X shape.
///
/// In the Rust port, this is a data model describing the icon's
/// geometry rather than a Swing paintable component.
#[derive(Debug, Clone)]
pub struct CloseIcon {
    /// The icon width in pixels.
    pub width: u32,
    /// The icon height in pixels.
    pub height: u32,
    /// The stroke width for the X lines.
    pub stroke_width: f32,
    /// The color (CSS hex string).
    pub color: String,
}

impl CloseIcon {
    /// Create a new CloseIcon with default 16x16 dimensions.
    pub fn new() -> Self {
        Self {
            width: 16,
            height: 16,
            stroke_width: 2.0,
            color: "#666666".to_string(),
        }
    }

    /// Create with specific dimensions.
    pub fn with_size(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            ..Self::new()
        }
    }

    /// Get the render commands for this icon.
    ///
    /// Returns (x1,y1,x2,y2) pairs for the two diagonal lines of the X.
    pub fn render_lines(&self) -> [(f64, f64, f64, f64); 2] {
        let padding = 2.0;
        let w = self.width as f64;
        let h = self.height as f64;
        [
            (padding, padding, w - padding, h - padding),
            (w - padding, padding, padding, h - padding),
        ]
    }
}

impl Default for CloseIcon {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_close_icon_default() {
        let icon = CloseIcon::new();
        assert_eq!(icon.width, 16);
        assert_eq!(icon.height, 16);
    }

    #[test]
    fn test_close_icon_with_size() {
        let icon = CloseIcon::with_size(32, 32);
        assert_eq!(icon.width, 32);
    }

    #[test]
    fn test_render_lines() {
        let icon = CloseIcon::new();
        let lines = icon.render_lines();
        assert_eq!(lines.len(), 2);
        // First line: top-left to bottom-right
        assert_eq!(lines[0], (2.0, 2.0, 14.0, 14.0));
        // Second line: top-right to bottom-left
        assert_eq!(lines[1], (14.0, 2.0, 2.0, 14.0));
    }
}
