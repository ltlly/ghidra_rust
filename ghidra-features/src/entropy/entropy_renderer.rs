//! Entropy field renderer for the listing view -- ported from Ghidra's
//! `ghidra.examples.EntropyFieldFactory` and `EntropyFieldLocation`.
//!
//! The [`EntropyRenderer`] computes Shannon entropy for a code unit's
//! byte window and produces a colour-coded display string suitable for
//! inclusion in a listing field column.
//!
//! # Example
//!
//! ```
//! use ghidra_features::entropy::renderer::{EntropyRenderer, EntropyRenderResult};
//!
//! let renderer = EntropyRenderer::new();
//! let data = vec![0xAAu8; 256];
//! let result = renderer.render(&data);
//! assert_eq!(result.text, "0");  // zero entropy -> 0%
//! ```

// ---------------------------------------------------------------------------
// EntropyRenderResult
// ---------------------------------------------------------------------------

/// The result of rendering an entropy field for a single code unit.
///
/// Contains the display text, an RGB colour value, and the raw entropy
/// score for downstream consumers.
#[derive(Debug, Clone, PartialEq)]
pub struct EntropyRenderResult {
    /// Display text (e.g. `"72"` for 72% of maximum entropy).
    pub text: String,
    /// Red component of the rendered colour (0-255).
    pub color_r: u8,
    /// Green component of the rendered colour (0-255).
    pub color_g: u8,
    /// Blue component of the rendered colour (0-255).
    pub color_b: u8,
    /// Raw Shannon entropy in bits per byte (0.0 to 8.0).
    pub raw_entropy: f64,
    /// Quantised entropy percentage (0 to 100).
    pub percentage: u32,
}

// ---------------------------------------------------------------------------
// EntropyFieldLocation
// ---------------------------------------------------------------------------

/// Location within an entropy field in the listing.
///
/// Ported from `ghidra.examples.EntropyFieldLocation`.
///
/// This is a lightweight value type used to represent the cursor
/// position when a user clicks on the entropy column in the listing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntropyFieldLocation {
    /// Address of the code unit.
    pub address: u64,
    /// Character offset within the entropy field text.
    pub char_offset: usize,
}

impl EntropyFieldLocation {
    /// Create a new entropy field location.
    pub fn new(address: u64, char_offset: usize) -> Self {
        Self {
            address,
            char_offset,
        }
    }
}

// ---------------------------------------------------------------------------
// EntropyRenderer
// ---------------------------------------------------------------------------

/// Renders entropy values for listing field display.
///
/// Ported from `ghidra.examples.EntropyFieldFactory`.
///
/// Given a window of bytes (typically 256 bytes starting at a code unit's
/// address), the renderer computes Shannon entropy, converts it to a
/// percentage, and maps the value to a heat-map colour.
///
/// The window size is configurable; the default (256) matches the Java
/// implementation.
#[derive(Debug, Clone)]
pub struct EntropyRenderer {
    /// Number of bytes to read for each entropy computation.
    window_size: usize,
    /// Whether the renderer is enabled.
    enabled: bool,
}

impl EntropyRenderer {
    /// Create a new renderer with default settings (256-byte window).
    pub fn new() -> Self {
        Self {
            window_size: 256,
            enabled: true,
        }
    }

    /// Create a renderer with a custom window size.
    pub fn with_window_size(window_size: usize) -> Self {
        assert!(window_size > 0, "window_size must be > 0");
        Self {
            window_size,
            enabled: true,
        }
    }

    // ------------------------------------------------------------------
    // Configuration
    // ------------------------------------------------------------------

    /// Get the window size.
    pub fn window_size(&self) -> usize {
        self.window_size
    }

    /// Set the window size.
    pub fn set_window_size(&mut self, size: usize) {
        assert!(size > 0, "window_size must be > 0");
        self.window_size = size;
    }

    /// Whether the renderer is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable or disable the renderer.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    // ------------------------------------------------------------------
    // Rendering
    // ------------------------------------------------------------------

    /// Render an entropy field for the given byte data.
    ///
    /// If `data` is shorter than the configured window size, the
    /// renderer works with whatever bytes are available.
    ///
    /// Returns `None` if the renderer is disabled or no data is provided.
    pub fn render(&self, data: &[u8]) -> EntropyRenderResult {
        let entropy = self.compute_entropy(data);
        let percentage = ((entropy / 8.0) * 100.0) as u32;
        let (r, g, b) = entropy_to_color(entropy);

        EntropyRenderResult {
            text: percentage.to_string(),
            color_r: r,
            color_g: g,
            color_b: b,
            raw_entropy: entropy,
            percentage,
        }
    }

    /// Render an entropy field, returning `None` if the data is too
    /// short or the renderer is disabled.
    ///
    /// The Java implementation returns `null` from `getField()` when
    /// fewer than `window_size` bytes are available.  This method
    /// mirrors that behaviour.
    pub fn render_strict(&self, data: &[u8]) -> Option<EntropyRenderResult> {
        if !self.enabled || data.len() < self.window_size {
            return None;
        }
        Some(self.render(data))
    }

    /// Compute the raw Shannon entropy (bits per byte) for the given
    /// data window.
    fn compute_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let len = data.len() as f64;
        let mut counts = [0u32; 256];
        for &b in data {
            counts[b as usize] += 1;
        }
        let mut entropy = 0.0f64;
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}

impl Default for EntropyRenderer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Colour mapping
// ---------------------------------------------------------------------------

/// Map a Shannon entropy value (0.0 to 8.0) to an RGB colour.
///
/// Uses a blue-to-red heat-map gradient:
///   - 0.0 bits/byte (all identical) -> blue  (0, 0, 255)
///   - 4.0 bits/byte (moderate)      -> green (0, 255, 0)
///   - 8.0 bits/byte (maximum)       -> red   (255, 0, 0)
///
/// This mirrors the Java implementation's HSB-based colour mapping:
/// `Color.getHSBColor(hue, saturation, brightness * (entropy / 8.0))`.
fn entropy_to_color(entropy: f64) -> (u8, u8, u8) {
    let t = (entropy / 8.0).clamp(0.0, 1.0);

    // Blue -> Green -> Red gradient (same as OverviewPalette)
    let r = if t < 0.5 {
        (t * 2.0 * 255.0) as u8
    } else {
        255
    };
    let g = if t < 0.5 {
        255
    } else {
        ((1.0 - (t - 0.5) * 2.0) * 255.0) as u8
    };
    let b = if t < 0.5 {
        ((0.5 - t) * 2.0 * 255.0) as u8
    } else {
        0
    };

    (r, g, b)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- EntropyRenderResult --

    #[test]
    fn test_render_result_equality() {
        let a = EntropyRenderResult {
            text: "50".into(),
            color_r: 128,
            color_g: 255,
            color_b: 0,
            raw_entropy: 4.0,
            percentage: 50,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    // -- EntropyFieldLocation --

    #[test]
    fn test_field_location() {
        let loc = EntropyFieldLocation::new(0x401000, 3);
        assert_eq!(loc.address, 0x401000);
        assert_eq!(loc.char_offset, 3);
    }

    #[test]
    fn test_field_location_equality() {
        let a = EntropyFieldLocation::new(0x1000, 0);
        let b = EntropyFieldLocation::new(0x1000, 0);
        assert_eq!(a, b);
    }

    // -- EntropyRenderer: creation --

    #[test]
    fn test_renderer_default() {
        let r = EntropyRenderer::new();
        assert_eq!(r.window_size(), 256);
        assert!(r.is_enabled());
    }

    #[test]
    fn test_renderer_custom_window() {
        let r = EntropyRenderer::with_window_size(512);
        assert_eq!(r.window_size(), 512);
    }

    #[test]
    fn test_renderer_set_window_size() {
        let mut r = EntropyRenderer::new();
        r.set_window_size(128);
        assert_eq!(r.window_size(), 128);
    }

    #[test]
    #[should_panic(expected = "window_size must be > 0")]
    fn test_renderer_zero_window_panics() {
        EntropyRenderer::with_window_size(0);
    }

    #[test]
    #[should_panic(expected = "window_size must be > 0")]
    fn test_renderer_set_zero_window_panics() {
        let mut r = EntropyRenderer::new();
        r.set_window_size(0);
    }

    #[test]
    fn test_renderer_enable_disable() {
        let mut r = EntropyRenderer::new();
        assert!(r.is_enabled());
        r.set_enabled(false);
        assert!(!r.is_enabled());
        r.set_enabled(true);
        assert!(r.is_enabled());
    }

    // -- EntropyRenderer: rendering --

    #[test]
    fn test_render_zero_entropy() {
        let r = EntropyRenderer::new();
        let data = vec![0xAAu8; 256];
        let result = r.render(&data);
        assert_eq!(result.text, "0");
        assert_eq!(result.percentage, 0);
        assert!((result.raw_entropy - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_render_max_entropy() {
        let r = EntropyRenderer::new();
        let data: Vec<u8> = (0..=255).collect();
        let result = r.render(&data);
        assert_eq!(result.text, "100");
        assert_eq!(result.percentage, 100);
        assert!((result.raw_entropy - 8.0).abs() < 1e-10);
    }

    #[test]
    fn test_render_partial_data() {
        let r = EntropyRenderer::new();
        // 128 identical bytes -> entropy = 0
        let data = vec![0u8; 128];
        let result = r.render(&data);
        assert_eq!(result.percentage, 0);
    }

    #[test]
    fn test_render_empty_data() {
        let r = EntropyRenderer::new();
        let result = r.render(&[]);
        assert_eq!(result.percentage, 0);
        assert!((result.raw_entropy).abs() < 1e-10);
    }

    #[test]
    fn test_render_strict_sufficient_data() {
        let r = EntropyRenderer::new();
        let data = vec![0xAAu8; 256];
        assert!(r.render_strict(&data).is_some());
    }

    #[test]
    fn test_render_strict_insufficient_data() {
        let r = EntropyRenderer::new();
        let data = vec![0xAAu8; 100];
        assert!(r.render_strict(&data).is_none());
    }

    #[test]
    fn test_render_strict_disabled() {
        let mut r = EntropyRenderer::new();
        r.set_enabled(false);
        let data = vec![0xAAu8; 256];
        assert!(r.render_strict(&data).is_none());
    }

    // -- Colour mapping --

    #[test]
    fn test_color_zero_entropy_is_cyan() {
        // t=0.0 -> r=0, g=255, b=255 (cyan end of the gradient)
        let (r, g, b) = entropy_to_color(0.0);
        assert_eq!(r, 0);
        assert_eq!(g, 255);
        assert_eq!(b, 255);
    }

    #[test]
    fn test_color_max_entropy_is_red() {
        let (r, g, b) = entropy_to_color(8.0);
        assert_eq!(r, 255);
        assert_eq!(g, 0);
        assert_eq!(b, 0);
    }

    #[test]
    fn test_color_mid_entropy() {
        let (r, g, b) = entropy_to_color(4.0);
        assert_eq!(r, 255);
        assert_eq!(g, 255);
        assert_eq!(b, 0);
    }

    #[test]
    fn test_color_clamping() {
        // Negative and > 8.0 should clamp
        let (r1, g1, b1) = entropy_to_color(-1.0);
        let (r2, g2, b2) = entropy_to_color(0.0);
        assert_eq!((r1, g1, b1), (r2, g2, b2));

        let (r3, g3, b3) = entropy_to_color(100.0);
        let (r4, g4, b4) = entropy_to_color(8.0);
        assert_eq!((r3, g3, b3), (r4, g4, b4));
    }

    #[test]
    fn test_render_color_consistency() {
        let r = EntropyRenderer::new();
        let data: Vec<u8> = (0..=255).collect();
        let result = r.render(&data);
        // Max entropy -> red
        assert_eq!(result.color_r, 255);
        assert_eq!(result.color_g, 0);
        assert_eq!(result.color_b, 0);
    }

    // -- Two-value distribution --

    #[test]
    fn test_render_two_value_distribution() {
        let r = EntropyRenderer::new();
        // 128 of 0x00 + 128 of 0xFF -> entropy = 1.0 bit
        let mut data = vec![0x00u8; 128];
        data.extend(vec![0xFFu8; 128]);
        let result = r.render(&data);
        // percentage = floor(1.0/8.0 * 100) = 12
        assert_eq!(result.percentage, 12);
        assert!((result.raw_entropy - 1.0).abs() < 1e-10);
    }
}
