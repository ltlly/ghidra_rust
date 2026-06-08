//! Named web color definitions and parsing.
//!
//! Ports `ghidra.util.WebColors` which defines standard HTML/CSS web colors
//! and provides lookup by name and hex string.

use std::collections::HashMap;
use std::sync::LazyLock;

/// RGBA color representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RgbaColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
    pub a: u8,
}

impl RgbaColor {
    /// Create a new opaque color.
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Self { r, g, b, a: 255 }
    }

    /// Create a color with alpha.
    pub const fn with_alpha(r: u8, g: u8, b: u8, a: u8) -> Self {
        Self { r, g, b, a }
    }

    /// Create from a packed 0xRRGGBB value (fully opaque).
    pub const fn from_rgb(rgb: u32) -> Self {
        Self {
            r: ((rgb >> 16) & 0xFF) as u8,
            g: ((rgb >> 8) & 0xFF) as u8,
            b: (rgb & 0xFF) as u8,
            a: 255,
        }
    }

    /// Create from a packed 0xAARRGGBB value.
    pub const fn from_argb(argb: u32) -> Self {
        Self {
            r: ((argb >> 16) & 0xFF) as u8,
            g: ((argb >> 8) & 0xFF) as u8,
            b: (argb & 0xFF) as u8,
            a: ((argb >> 24) & 0xFF) as u8,
        }
    }

    /// Pack to 0xRRGGBB.
    pub const fn to_rgb(&self) -> u32 {
        ((self.r as u32) << 16) | ((self.g as u32) << 8) | (self.b as u32)
    }

    /// Pack to 0xAARRGGBB.
    pub const fn to_argb(&self) -> u32 {
        ((self.a as u32) << 24) | ((self.r as u32) << 16) | ((self.g as u32) << 8) | (self.b as u32)
    }

    /// Convert to a hex string "#RRGGBB".
    pub fn to_hex_string(&self) -> String {
        format!("#{:02X}{:02X}{:02X}", self.r, self.g, self.b)
    }

    /// Convert to a hex string with alpha "#AARRGGBB".
    pub fn to_hex_string_with_alpha(&self) -> String {
        format!("#{:02X}{:02X}{:02X}{:02X}", self.a, self.r, self.g, self.b)
    }

    /// Convert to HSB (hue, saturation, brightness), each in [0.0, 1.0].
    pub fn to_hsb(&self) -> (f32, f32, f32) {
        let r = self.r as f32 / 255.0;
        let g = self.g as f32 / 255.0;
        let b = self.b as f32 / 255.0;
        let max = r.max(g).max(b);
        let min = r.min(g).min(b);
        let brightness = max;
        let saturation = if max == 0.0 { 0.0 } else { (max - min) / max };
        let hue = if max == min {
            0.0
        } else if max == r {
            60.0 * ((g - b) / (max - min)) + if g < b { 360.0 } else { 0.0 }
        } else if max == g {
            60.0 * ((b - r) / (max - min)) + 120.0
        } else {
            60.0 * ((r - g) / (max - min)) + 240.0
        };
        (hue / 360.0, saturation, brightness)
    }

    /// Derive a foreground color (black or white) that contrasts with this
    /// background.
    pub fn contrast_foreground(&self) -> Self {
        let lum = 0.299 * self.r as f32 + 0.587 * self.g as f32 + 0.114 * self.b as f32;
        if lum > 128.0 { RgbaColor::new(0, 0, 0) } else { RgbaColor::new(255, 255, 255) }
    }

    /// Average two colors.
    pub fn average(c1: RgbaColor, c2: RgbaColor) -> Self {
        Self {
            r: ((c1.r as u16 + c2.r as u16) / 2) as u8,
            g: ((c1.g as u16 + c2.g as u16) / 2) as u8,
            b: ((c1.b as u16 + c2.b as u16) / 2) as u8,
            a: ((c1.a as u16 + c2.a as u16) / 2) as u8,
        }
    }
}

impl std::fmt::Display for RgbaColor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex_string())
    }
}

/// Web color name lookup and registration.
///
/// Provides access to all standard CSS/HTML named colors and methods to
/// convert between names, hex strings, and RGBA values.
pub struct WebColors;

/// Lazily-initialized name-to-color map.
static NAME_TO_COLOR: LazyLock<HashMap<String, RgbaColor>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    for &(name, rgb) in WEB_COLORS_DATA {
        m.insert(name.to_lowercase(), RgbaColor::from_rgb(rgb));
    }
    m
});

/// Lazily-initialized color-to-name map (rgb -> name).
static _COLOR_TO_NAME: LazyLock<HashMap<u32, String>> = LazyLock::new(|| {
    let mut m = HashMap::new();
    for &(name, rgb) in WEB_COLORS_DATA {
        m.entry(rgb).or_insert_with(|| name.to_string());
    }
    m
});

impl WebColors {
    /// Look up a web color by its CSS name (case-insensitive).
    pub fn lookup(name: &str) -> Option<RgbaColor> {
        NAME_TO_COLOR.get(&name.to_lowercase()).copied()
    }

    /// Get the web color name for an RGB value, if it matches a known color.
    pub fn to_web_color_name(color: RgbaColor) -> Option<&'static str> {
        let rgb = color.to_rgb();
        // Search backwards so we can return a &'static str through the data array
        for &(name, c) in WEB_COLORS_DATA.iter().rev() {
            if c == rgb {
                return Some(name);
            }
        }
        None
    }

    /// Convert a color to its hex string representation.
    pub fn to_string(color: RgbaColor, include_alpha: bool) -> String {
        if include_alpha {
            color.to_hex_string_with_alpha()
        } else {
            color.to_hex_string()
        }
    }

    /// Parse a color from a hex string or web color name.
    pub fn parse(s: &str) -> Option<RgbaColor> {
        let s = s.trim();
        // Try hex
        if let Some(hex) = s.strip_prefix('#') {
            return parse_hex(hex);
        }
        if s.starts_with("0x") || s.starts_with("0X") {
            let hex = &s[2..];
            return parse_hex(hex);
        }
        // Try name
        Self::lookup(s)
    }
}

fn parse_hex(hex: &str) -> Option<RgbaColor> {
    match hex.len() {
        6 => {
            let rgb = u32::from_str_radix(hex, 16).ok()?;
            Some(RgbaColor::from_rgb(rgb))
        }
        8 => {
            let argb = u32::from_str_radix(hex, 16).ok()?;
            Some(RgbaColor::from_argb(argb))
        }
        3 => {
            // Short form: #RGB -> #RRGGBB
            let r = u8::from_str_radix(&hex[0..1], 16).ok()?;
            let g = u8::from_str_radix(&hex[1..2], 16).ok()?;
            let b = u8::from_str_radix(&hex[2..3], 16).ok()?;
            Some(RgbaColor::new(r * 17, g * 17, b * 17))
        }
        _ => None,
    }
}

/// All standard CSS/HTML named web colors.
/// (name, 0xRRGGBB)
static WEB_COLORS_DATA: &[(&str, u32)] = &[
    ("Black", 0x000000),
    ("Navy", 0x000080),
    ("DarkBlue", 0x00008B),
    ("MediumBlue", 0x0000CD),
    ("Blue", 0x0000FF),
    ("DarkGreen", 0x006400),
    ("Green", 0x008000),
    ("Teal", 0x008080),
    ("DarkCyan", 0x008B8B),
    ("DeepSkyBlue", 0x00BFFF),
    ("DarkTurquoise", 0x00CED1),
    ("Lime", 0x00FF00),
    ("SpringGreen", 0x00FF7F),
    ("Aqua", 0x00FFFF),
    ("Cyan", 0x00FFFF),
    ("MidnightBlue", 0x191970),
    ("DodgerBlue", 0x1E90FF),
    ("LightSeaGreen", 0x20B2AA),
    ("ForestGreen", 0x228B22),
    ("SeaGreen", 0x2E8B57),
    ("DarkSlateGray", 0x2F4F4F),
    ("LimeGreen", 0x32CD32),
    ("Turquoise", 0x40E0D0),
    ("RoyalBlue", 0x4169E1),
    ("SteelBlue", 0x4682B4),
    ("DarkSlateBlue", 0x483D8B),
    ("Indigo", 0x4B0082),
    ("CadetBlue", 0x5F9EA0),
    ("RebeccaPurple", 0x663399),
    ("DimGray", 0x696969),
    ("SlateBlue", 0x6A5ACD),
    ("OliveDrab", 0x6B8E23),
    ("SlateGray", 0x708090),
    ("LawnGreen", 0x7CFC00),
    ("Chartreuse", 0x7FFF00),
    ("Aquamarine", 0x7FFFD4),
    ("Maroon", 0x800000),
    ("Purple", 0x800080),
    ("Olive", 0x808000),
    ("Gray", 0x808080),
    ("SkyBlue", 0x87CEEB),
    ("LightSkyBlue", 0x87CEFA),
    ("BlueViolet", 0x8A2BE2),
    ("DarkRed", 0x8B0000),
    ("DarkMagenta", 0x8B008B),
    ("SaddleBrown", 0x8B4513),
    ("DarkSeaGreen", 0x8FBC8F),
    ("LightGreen", 0x90EE90),
    ("MediumPurple", 0x9370DB),
    ("DarkViolet", 0x9400D3),
    ("PaleGreen", 0x98FB98),
    ("DarkOrchid", 0x9932CC),
    ("YellowGreen", 0x9ACD32),
    ("Sienna", 0xA0522D),
    ("Brown", 0xA52A2A),
    ("DarkGray", 0xA9A9A9),
    ("LightBlue", 0xADD8E6),
    ("GreenYellow", 0xADFF2F),
    ("PaleTurquoise", 0xAFEEEE),
    ("Maroon2", 0xB03060),
    ("LightSteelBlue", 0xB0C4DE),
    ("PowderBlue", 0xB0E0E6),
    ("Firebrick", 0xB22222),
    ("DarkGoldenrod", 0xB8860B),
    ("MediumOrchid", 0xBA55D3),
    ("RosyBrown", 0xBC8F8F),
    ("DarkKhaki", 0xBDB76B),
    ("Silver", 0xC0C0C0),
    ("MediumVioletRed", 0xC71585),
    ("IndianRed", 0xCD5C5C),
    ("Peru", 0xCD853F),
    ("Chocolate", 0xD2691E),
    ("Tan", 0xD2B48C),
    ("LightGray", 0xD3D3D3),
    ("Thistle", 0xD8BFD8),
    ("Orchid", 0xDA70D6),
    ("Goldenrod", 0xDAA520),
    ("PaleVioletRed", 0xDB7093),
    ("Crimson", 0xDC143C),
    ("Gainsboro", 0xDCDCDC),
    ("Plum", 0xDDA0DD),
    ("BurlyWood", 0xDEB887),
    ("LightCyan", 0xE0FFFF),
    ("Lavender", 0xE6E6FA),
    ("DarkSalmon", 0xE9967A),
    ("Violet", 0xEE82EE),
    ("PaleGoldenrod", 0xEEE8AA),
    ("LightCoral", 0xF08080),
    ("Khaki", 0xF0E68C),
    ("AliceBlue", 0xF0F8FF),
    ("HoneyDew", 0xF0FFF0),
    ("Azure", 0xF0FFFF),
    ("SandyBrown", 0xF4A460),
    ("Wheat", 0xF5DEB3),
    ("Beige", 0xF5F5DC),
    ("WhiteSmoke", 0xF5F5F5),
    ("MintCream", 0xF5FFFA),
    ("GhostWhite", 0xF8F8FF),
    ("Salmon", 0xFA8072),
    ("AntiqueWhite", 0xFAEBD7),
    ("Linen", 0xFAF0E6),
    ("LightGoldenrodYellow", 0xFAFAD2),
    ("OldLace", 0xFDF5E6),
    ("Red", 0xFF0000),
    ("Fuchsia", 0xFF00FF),
    ("Magenta", 0xFF00FF),
    ("DeepPink", 0xFF1493),
    ("OrangeRed", 0xFF4500),
    ("Tomato", 0xFF6347),
    ("HotPink", 0xFF69B4),
    ("Coral", 0xFF7F50),
    ("DarkOrange", 0xFF8C00),
    ("LightSalmon", 0xFFA07A),
    ("Orange", 0xFFA500),
    ("LightPink", 0xFFB6C1),
    ("Pink", 0xFFC0CB),
    ("Gold", 0xFFD700),
    ("PeachPuff", 0xFFDAB9),
    ("NavajoWhite", 0xFFDEAD),
    ("Moccasin", 0xFFE4B5),
    ("Bisque", 0xFFE4C4),
    ("MistyRose", 0xFFE4E1),
    ("BlanchedAlmond", 0xFFEBCD),
    ("PapayaWhip", 0xFFEFD5),
    ("LavenderBlush", 0xFFF0F5),
    ("SeaShell", 0xFFF5EE),
    ("Cornsilk", 0xFFF8DC),
    ("LemonChiffon", 0xFFFACD),
    ("FloralWhite", 0xFFFAF0),
    ("Snow", 0xFFFAFA),
    ("Yellow", 0xFFFF00),
    ("LightYellow", 0xFFFFE0),
    ("Ivory", 0xFFFFF0),
    ("White", 0xFFFFFF),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rgba_color_new() {
        let c = RgbaColor::new(255, 0, 0);
        assert_eq!(c.r, 255);
        assert_eq!(c.a, 255);
    }

    #[test]
    fn test_rgba_from_rgb() {
        let c = RgbaColor::from_rgb(0x00FF00);
        assert_eq!(c.r, 0);
        assert_eq!(c.g, 255);
        assert_eq!(c.b, 0);
    }

    #[test]
    fn test_rgba_to_hex() {
        let c = RgbaColor::new(0xAB, 0xCD, 0xEF);
        assert_eq!(c.to_hex_string(), "#ABCDEF");
    }

    #[test]
    fn test_web_colors_lookup() {
        let red = WebColors::lookup("Red").unwrap();
        assert_eq!(red, RgbaColor::new(255, 0, 0));
    }

    #[test]
    fn test_web_colors_case_insensitive() {
        assert_eq!(WebColors::lookup("black"), WebColors::lookup("BLACK"));
    }

    #[test]
    fn test_web_colors_to_name() {
        let c = RgbaColor::new(255, 255, 255);
        assert_eq!(WebColors::to_web_color_name(c), Some("White"));
    }

    #[test]
    fn test_web_colors_parse_hex() {
        let c = WebColors::parse("#FF0000").unwrap();
        assert_eq!(c, RgbaColor::new(255, 0, 0));
    }

    #[test]
    fn test_web_colors_parse_name() {
        let c = WebColors::parse("Blue").unwrap();
        assert_eq!(c, RgbaColor::new(0, 0, 255));
    }

    #[test]
    fn test_web_colors_parse_short_hex() {
        let c = WebColors::parse("#F00").unwrap();
        assert_eq!(c, RgbaColor::new(255, 0, 0));
    }

    #[test]
    fn test_contrast_foreground() {
        let black = RgbaColor::new(0, 0, 0);
        assert_eq!(black.contrast_foreground(), RgbaColor::new(255, 255, 255));
        let white = RgbaColor::new(255, 255, 255);
        assert_eq!(white.contrast_foreground(), RgbaColor::new(0, 0, 0));
    }

    #[test]
    fn test_average() {
        let c = RgbaColor::average(RgbaColor::new(0, 0, 0), RgbaColor::new(254, 254, 254));
        assert_eq!(c, RgbaColor::new(127, 127, 127));
    }

    #[test]
    fn test_to_hsb() {
        let red = RgbaColor::new(255, 0, 0);
        let (h, s, b) = red.to_hsb();
        assert!((h - 0.0).abs() < 0.01);
        assert!((s - 1.0).abs() < 0.01);
        assert!((b - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_to_string_with_alpha() {
        let c = RgbaColor::with_alpha(255, 0, 0, 128);
        let s = WebColors::to_string(c, true);
        assert_eq!(s, "#80FF0000");
    }
}
