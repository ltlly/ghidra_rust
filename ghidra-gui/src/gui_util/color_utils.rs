//! Color manipulation utilities.
//!
//! Ports `ghidra.util.ColorUtils` methods into static helper functions.

use super::web_colors::RgbaColor;

/// Hue constants (fraction of a full turn).
pub const HUE_RED: f32 = 0.0;
pub const HUE_ORANGE: f32 = 1.0 / 12.0;
pub const HUE_YELLOW: f32 = 2.0 / 12.0;
pub const HUE_GREEN: f32 = 4.0 / 12.0;
pub const HUE_CYAN: f32 = 6.0 / 12.0;
pub const HUE_BLUE: f32 = 8.0 / 12.0;
pub const HUE_VIOLET: f32 = 10.0 / 12.0;

/// Color manipulation utility functions.
pub struct ColorUtils;

impl ColorUtils {
    /// Produce a contrasting foreground color (black or white) for the given
    /// background.
    pub fn contrast_color(bg: RgbaColor) -> RgbaColor {
        bg.contrast_foreground()
    }

    /// Average two colors.
    pub fn average(c1: RgbaColor, c2: RgbaColor) -> RgbaColor {
        RgbaColor::average(c1, c2)
    }

    /// Check whether two colors share the same RGB values (ignoring alpha).
    pub fn has_same_rgb(c1: RgbaColor, c2: RgbaColor) -> bool {
        c1.r == c2.r && c1.g == c2.g && c1.b == c2.b
    }

    /// Derive a color by blending toward a target hue while preserving
    /// brightness.
    pub fn derive_color(base: RgbaColor, target_hue: f32, saturation_scale: f32) -> RgbaColor {
        let (h, s, b) = base.to_hsb();
        let new_h = target_hue;
        let new_s = (s * saturation_scale).clamp(0.0, 1.0);
        hsb_to_rgba(new_h, new_s, b)
    }

    /// Derive a lighter variant of a color (nudge toward white).
    pub fn brighter(color: RgbaColor, factor: f32) -> RgbaColor {
        let factor = factor.max(0.0);
        RgbaColor::new(
            (color.r as f32 + (255.0 - color.r as f32) * factor).min(255.0) as u8,
            (color.g as f32 + (255.0 - color.g as f32) * factor).min(255.0) as u8,
            (color.b as f32 + (255.0 - color.b as f32) * factor).min(255.0) as u8,
            color.a,
        )
    }

    /// Derive a darker variant of a color (nudge toward black).
    pub fn darker(color: RgbaColor, factor: f32) -> RgbaColor {
        let factor = factor.max(0.0);
        RgbaColor::new(
            (color.r as f32 * (1.0 - factor)).max(0.0) as u8,
            (color.g as f32 * (1.0 - factor)).max(0.0) as u8,
            (color.b as f32 * (1.0 - factor)).max(0.0) as u8,
            color.a,
        )
    }

    /// Blend two colors with a given alpha (0.0 = fully c1, 1.0 = fully c2).
    pub fn blend(c1: RgbaColor, c2: RgbaColor, alpha: f32) -> RgbaColor {
        let alpha = alpha.clamp(0.0, 1.0);
        let inv = 1.0 - alpha;
        RgbaColor::new(
            (c1.r as f32 * inv + c2.r as f32 * alpha) as u8,
            (c1.g as f32 * inv + c2.g as f32 * alpha) as u8,
            (c1.b as f32 * inv + c2.b as f32 * alpha) as u8,
            (c1.a as f32 * inv + c2.a as f32 * alpha) as u8,
        )
    }
}

/// Convert HSB (each in [0,1]) to RGBA.
fn hsb_to_rgba(h: f32, s: f32, b: f32) -> RgbaColor {
    let h = h.rem_euclid(1.0);
    let i = (h * 6.0).floor() as i32;
    let f = h * 6.0 - i as f32;
    let p = b * (1.0 - s);
    let q = b * (1.0 - f * s);
    let t = b * (1.0 - (1.0 - f) * s);

    let (r, g, bl) = match i % 6 {
        0 => (b, t, p),
        1 => (q, b, p),
        2 => (p, b, t),
        3 => (p, q, b),
        4 => (t, p, b),
        5 => (b, p, q),
        _ => (b, p, q),
    };
    RgbaColor::new((r * 255.0) as u8, (g * 255.0) as u8, (bl * 255.0) as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contrast_color() {
        assert_eq!(ColorUtils::contrast_color(RgbaColor::new(0, 0, 0)), RgbaColor::new(255, 255, 255));
        assert_eq!(ColorUtils::contrast_color(RgbaColor::new(255, 255, 255)), RgbaColor::new(0, 0, 0));
    }

    #[test]
    fn test_average_colors() {
        let c = ColorUtils::average(RgbaColor::new(0, 0, 0), RgbaColor::new(254, 254, 254));
        assert_eq!(c, RgbaColor::new(127, 127, 127));
    }

    #[test]
    fn test_has_same_rgb() {
        let c1 = RgbaColor::with_alpha(255, 0, 0, 255);
        let c2 = RgbaColor::with_alpha(255, 0, 0, 128);
        assert!(ColorUtils::has_same_rgb(c1, c2));
    }

    #[test]
    fn test_brighter() {
        let c = RgbaColor::new(100, 100, 100);
        let b = ColorUtils::brighter(c, 0.5);
        assert!(b.r > 100);
        assert!(b.g > 100);
        assert!(b.b > 100);
    }

    #[test]
    fn test_darker() {
        let c = RgbaColor::new(100, 100, 100);
        let d = ColorUtils::darker(c, 0.5);
        assert!(d.r < 100);
        assert!(d.g < 100);
        assert!(d.b < 100);
    }

    #[test]
    fn test_blend() {
        let c1 = RgbaColor::new(0, 0, 0);
        let c2 = RgbaColor::new(255, 255, 255);
        let mid = ColorUtils::blend(c1, c2, 0.5);
        assert_eq!(mid.r, 127);
    }

    #[test]
    fn test_derive_color() {
        let base = RgbaColor::new(200, 100, 50);
        let derived = ColorUtils::derive_color(base, HUE_BLUE, 1.0);
        // Should have same brightness but different hue
        let (_, _, b_orig) = base.to_hsb();
        let (_, _, b_der) = derived.to_hsb();
        assert!((b_orig - b_der).abs() < 0.05);
    }
}
