//! Color manipulation utilities.
//!
//! Port of `ghidra.util.ColorUtils` and related color helpers.

use std::fmt;

/// An RGBA color value.
///
/// Port of Ghidra's color representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl Color {
    /// Create a new color with full opacity.
    pub const fn rgb(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// Create a new color with an alpha channel.
    pub const fn rgba(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Create a color from a 32-bit packed ARGB integer (as used by Java's `java.awt.Color`).
    pub const fn from_argb(argb: u32) -> Self {
        Self {
            a: ((argb >> 24) & 0xFF) as u8,
            r: ((argb >> 16) & 0xFF) as u8,
            g: ((argb >> 8) & 0xFF) as u8,
            b: (argb & 0xFF) as u8,
        }
    }

    /// Create a color from a 32-bit packed RGB integer (alpha = 255).
    pub const fn from_rgb_int(rgb: u32) -> Self {
        Self {
            a: 255,
            r: ((rgb >> 16) & 0xFF) as u8,
            g: ((rgb >> 8) & 0xFF) as u8,
            b: (rgb & 0xFF) as u8,
        }
    }

    /// Pack this color as a 32-bit ARGB integer.
    pub const fn to_argb(&self) -> u32 {
        ((self.a as u32) << 24) | ((self.r as u32) << 16) | ((self.g as u32) << 8) | (self.b as u32)
    }

    /// Pack this color as a 32-bit RGB integer (discards alpha).
    pub const fn to_rgb_int(&self) -> u32 {
        ((self.r as u32) << 16) | ((self.g as u32) << 8) | (self.b as u32)
    }

    /// Get the red component.
    pub const fn red(&self) -> u8 {
        self.r
    }

    /// Get the green component.
    pub const fn green(&self) -> u8 {
        self.g
    }

    /// Get the blue component.
    pub const fn blue(&self) -> u8 {
        self.b
    }

    /// Get the alpha component.
    pub const fn alpha(&self) -> u8 {
        self.a
    }

    /// Check if the color is fully opaque.
    pub const fn is_opaque(&self) -> bool {
        self.a == 255
    }

    /// Check if the color is fully transparent.
    pub const fn is_transparent(&self) -> bool {
        self.a == 0
    }

    /// Get the brightness (perceived luminance) of the color.
    ///
    /// Uses the standard luminance formula: 0.299*R + 0.587*G + 0.114*B.
    pub fn brightness(&self) -> f64 {
        0.299 * self.r as f64 + 0.587 * self.g as f64 + 0.114 * self.b as f64
    }

    /// Check if the color is "dark" (brightness < 128).
    pub fn is_dark(&self) -> bool {
        self.brightness() < 128.0
    }

    /// Get a contrasting color (black or white) based on the brightness.
    pub fn contrasting_color(&self) -> Color {
        if self.is_dark() {
            Color::rgb(255, 255, 255)
        } else {
            Color::rgb(0, 0, 0)
        }
    }

    /// Invert this color.
    pub fn invert(&self) -> Color {
        Color::rgba(255 - self.r, 255 - self.g, 255 - self.b, self.a)
    }

    /// Create a new color with a different alpha value.
    pub const fn with_alpha(&self, alpha: u8) -> Color {
        Color::rgba(self.r, self.g, self.b, alpha)
    }

    /// Linearly interpolate between two colors.
    ///
    /// `t` should be in the range [0.0, 1.0]. At t=0 returns `self`, at t=1 returns `other`.
    pub fn lerp(&self, other: &Color, t: f64) -> Color {
        let t = t.clamp(0.0, 1.0);
        let inv_t = 1.0 - t;
        Color::rgba(
            (self.r as f64 * inv_t + other.r as f64 * t) as u8,
            (self.g as f64 * inv_t + other.g as f64 * t) as u8,
            (self.b as f64 * inv_t + other.b as f64 * t) as u8,
            (self.a as f64 * inv_t + other.a as f64 * t) as u8,
        )
    }

    /// Blend this color over another color (alpha compositing, "over" operation).
    pub fn blend_over(&self, background: &Color) -> Color {
        let src_a = self.a as f64 / 255.0;
        let dst_a = background.a as f64 / 255.0;
        let out_a = src_a + dst_a * (1.0 - src_a);
        if out_a < 0.001 {
            return Color::rgba(0, 0, 0, 0);
        }
        let r = (self.r as f64 * src_a + background.r as f64 * dst_a * (1.0 - src_a)) / out_a;
        let g = (self.g as f64 * src_a + background.g as f64 * dst_a * (1.0 - src_a)) / out_a;
        let b = (self.b as f64 * src_a + background.b as f64 * dst_a * (1.0 - src_a)) / out_a;
        Color::rgba(r as u8, g as u8, b as u8, (out_a * 255.0) as u8)
    }

    /// Convert to an HSL representation.
    pub fn to_hsl(&self) -> (f64, f64, f64) {
        let r = self.r as f64 / 255.0;
        let g = self.g as f64 / 255.0;
        let b = self.b as f64 / 255.0;

        let max = r.max(g).max(b);
        let min = r.min(g).min(b);
        let l = (max + min) / 2.0;

        if max == min {
            return (0.0, 0.0, l);
        }

        let d = max - min;
        let s = if l > 0.5 {
            d / (2.0 - max - min)
        } else {
            d / (max + min)
        };

        let h = if max == r {
            ((g - b) / d + if g < b { 6.0 } else { 0.0 }) / 6.0
        } else if max == g {
            ((b - r) / d + 2.0) / 6.0
        } else {
            ((r - g) / d + 4.0) / 6.0
        };

        (h * 360.0, s, l)
    }

    /// Create a color from HSL values.
    ///
    /// `h` is in degrees [0, 360), `s` and `l` are in [0, 1].
    pub fn from_hsl(h: f64, s: f64, l: f64) -> Color {
        let h = ((h % 360.0) + 360.0) % 360.0;
        let s = s.clamp(0.0, 1.0);
        let l = l.clamp(0.0, 1.0);

        if s == 0.0 {
            let v = (l * 255.0) as u8;
            return Color::rgb(v, v, v);
        }

        let q = if l < 0.5 {
            l * (1.0 + s)
        } else {
            l + s - l * s
        };
        let p = 2.0 * l - q;
        let h_norm = h / 360.0;

        let r = hue_to_rgb(p, q, h_norm + 1.0 / 3.0);
        let g = hue_to_rgb(p, q, h_norm);
        let b = hue_to_rgb(p, q, h_norm - 1.0 / 3.0);

        Color::rgb((r * 255.0) as u8, (g * 255.0) as u8, (b * 255.0) as u8)
    }
}

fn hue_to_rgb(p: f64, q: f64, t: f64) -> f64 {
    let t = if t < 0.0 { t + 1.0 } else if t > 1.0 { t - 1.0 } else { t };
    if t < 1.0 / 6.0 {
        p + (q - p) * 6.0 * t
    } else if t < 1.0 / 2.0 {
        q
    } else if t < 2.0 / 3.0 {
        p + (q - p) * (2.0 / 3.0 - t) * 6.0
    } else {
        p
    }
}

impl fmt::Display for Color {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.a == 255 {
            write!(f, "#{:02x}{:02x}{:02x}", self.r, self.g, self.b)
        } else {
            write!(
                f,
                "#{:02x}{:02x}{:02x}{:02x}",
                self.r, self.g, self.b, self.a
            )
        }
    }
}

/// Color utility functions.
///
/// Port of `ghidra.util.ColorUtils`.
pub struct ColorUtils;

impl ColorUtils {
    /// Parse a CSS-style hex color string (e.g., "#FF0000", "#ff0000aa", "0xFF0000").
    pub fn parse_color(s: &str) -> Option<Color> {
        let s = s.trim();
        let s = s.strip_prefix('#').or_else(|| s.strip_prefix("0x")).unwrap_or(s);

        match s.len() {
            6 => {
                let r = u8::from_str_radix(&s[0..2], 16).ok()?;
                let g = u8::from_str_radix(&s[2..4], 16).ok()?;
                let b = u8::from_str_radix(&s[4..6], 16).ok()?;
                Some(Color::rgb(r, g, b))
            }
            8 => {
                let r = u8::from_str_radix(&s[0..2], 16).ok()?;
                let g = u8::from_str_radix(&s[2..4], 16).ok()?;
                let b = u8::from_str_radix(&s[4..6], 16).ok()?;
                let a = u8::from_str_radix(&s[6..8], 16).ok()?;
                Some(Color::rgba(r, g, b, a))
            }
            3 => {
                let r = u8::from_str_radix(&s[0..1], 16).ok()? * 17;
                let g = u8::from_str_radix(&s[1..2], 16).ok()? * 17;
                let b = u8::from_str_radix(&s[2..3], 16).ok()? * 17;
                Some(Color::rgb(r, g, b))
            }
            _ => None,
        }
    }

    /// Format a color as a hex string with "#" prefix.
    pub fn to_hex_string(color: &Color) -> String {
        format!("{}", color)
    }

    /// Get a set of predefined distinct colors for chart/graph coloring.
    pub fn distinct_colors() -> Vec<Color> {
        vec![
            Color::rgb(0, 0, 255),       // blue
            Color::rgb(255, 0, 0),       // red
            Color::rgb(0, 200, 0),       // green
            Color::rgb(255, 165, 0),     // orange
            Color::rgb(128, 0, 128),     // purple
            Color::rgb(0, 200, 200),     // cyan
            Color::rgb(255, 0, 255),     // magenta
            Color::rgb(128, 128, 0),     // olive
            Color::rgb(0, 128, 128),     // teal
            Color::rgb(255, 192, 203),   // pink
            Color::rgb(0, 0, 128),       // navy
            Color::rgb(165, 42, 42),     // brown
            Color::rgb(128, 128, 128),   // gray
            Color::rgb(0, 128, 0),       // dark green
            Color::rgb(255, 215, 0),     // gold
        ]
    }

    /// Get a distinct color by index, cycling through the palette.
    pub fn distinct_color(index: usize) -> Color {
        let colors = Self::distinct_colors();
        colors[index % colors.len()]
    }

    /// Compute the Euclidean distance between two colors in RGB space.
    pub fn color_distance(a: &Color, b: &Color) -> f64 {
        let dr = a.r as f64 - b.r as f64;
        let dg = a.g as f64 - b.g as f64;
        let db = a.b as f64 - b.b as f64;
        (dr * dr + dg * dg + db * db).sqrt()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_construction() {
        let c = Color::rgb(255, 0, 0);
        assert_eq!(c.red(), 255);
        assert_eq!(c.green(), 0);
        assert_eq!(c.blue(), 0);
        assert_eq!(c.alpha(), 255);
        assert!(c.is_opaque());
    }

    #[test]
    fn test_argb_roundtrip() {
        let c = Color::rgba(128, 64, 32, 200);
        let argb = c.to_argb();
        let c2 = Color::from_argb(argb);
        assert_eq!(c, c2);
    }

    #[test]
    fn test_color_from_rgb_int() {
        let c = Color::from_rgb_int(0xFF8800);
        assert_eq!(c, Color::rgb(255, 136, 0));
    }

    #[test]
    fn test_brightness() {
        assert!(Color::rgb(255, 255, 255).brightness() > Color::rgb(0, 0, 0).brightness());
        assert!(Color::rgb(0, 0, 0).is_dark());
        assert!(!Color::rgb(255, 255, 255).is_dark());
    }

    #[test]
    fn test_contrasting_color() {
        assert_eq!(Color::rgb(0, 0, 0).contrasting_color(), Color::rgb(255, 255, 255));
        assert_eq!(Color::rgb(255, 255, 255).contrasting_color(), Color::rgb(0, 0, 0));
    }

    #[test]
    fn test_invert() {
        let c = Color::rgb(0, 128, 255);
        let inv = c.invert();
        assert_eq!(inv, Color::rgb(255, 127, 0));
    }

    #[test]
    fn test_lerp() {
        let a = Color::rgb(0, 0, 0);
        let b = Color::rgb(255, 255, 255);
        let mid = a.lerp(&b, 0.5);
        assert_eq!(mid.r, 127);
        assert_eq!(mid.g, 127);
        assert_eq!(mid.b, 127);
    }

    #[test]
    fn test_hsl_roundtrip() {
        let c = Color::rgb(255, 0, 0);
        let (h, s, l) = c.to_hsl();
        let c2 = Color::from_hsl(h, s, l);
        // Allow small rounding differences
        assert!((c.r as i16 - c2.r as i16).abs() <= 1);
        assert!((c.g as i16 - c2.g as i16).abs() <= 1);
        assert!((c.b as i16 - c2.b as i16).abs() <= 1);
    }

    #[test]
    fn test_display() {
        assert_eq!(format!("{}", Color::rgb(255, 0, 0)), "#ff0000");
        assert_eq!(format!("{}", Color::rgba(0, 0, 0, 128)), "#00000080");
    }

    #[test]
    fn test_parse_color() {
        assert_eq!(ColorUtils::parse_color("#FF0000"), Some(Color::rgb(255, 0, 0)));
        assert_eq!(ColorUtils::parse_color("0x00FF00"), Some(Color::rgb(0, 255, 0)));
        assert_eq!(ColorUtils::parse_color("#f00"), Some(Color::rgb(255, 0, 0)));
        assert_eq!(ColorUtils::parse_color("#ff000080"), Some(Color::rgba(255, 0, 0, 128)));
        assert!(ColorUtils::parse_color("invalid").is_none());
    }

    #[test]
    fn test_distinct_colors() {
        let colors = ColorUtils::distinct_colors();
        assert!(colors.len() >= 10);
        // All should be different from each other (at least the first few)
        assert_ne!(colors[0], colors[1]);
        assert_ne!(colors[0], colors[2]);
    }

    #[test]
    fn test_color_distance() {
        let d = ColorUtils::color_distance(&Color::rgb(0, 0, 0), &Color::rgb(255, 255, 255));
        assert!(d > 400.0);
        let d = ColorUtils::color_distance(&Color::rgb(0, 0, 0), &Color::rgb(0, 0, 0));
        assert_eq!(d, 0.0);
    }
}
