//! ANSI color resolution.
//!
//! Ported from Ghidra's `AnsiColorResolver.java`.
//!
//! Converts ANSI color specifications (standard, bright, 256-color, RGB)
//! into concrete RGB values for rendering, handling foreground/background
//! distinction, intensity, and reverse-video attributes.

use super::attributes::{AnsiColor, Intensity};

/// Whether the color is used for the foreground or the background.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WhichGround {
    /// The foreground (text) color.
    Foreground,
    /// The background color.
    Background,
}

/// How reverse-video affects the foreground/background swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReverseVideo {
    /// Normal -- no swap.
    Normal,
    /// Reversed -- foreground and background are swapped.
    Reversed,
}

impl ReverseVideo {
    /// Get the effective foreground ANSI color, accounting for reverse.
    pub fn fg(&self, fg: AnsiColor, bg: AnsiColor) -> AnsiColor {
        match self {
            Self::Normal => fg,
            Self::Reversed => bg,
        }
    }

    /// Get the effective background ANSI color, accounting for reverse.
    pub fn bg(&self, fg: AnsiColor, bg: AnsiColor) -> AnsiColor {
        match self {
            Self::Normal => bg,
            Self::Reversed => fg,
        }
    }
}

/// Convert an ANSI color to a concrete RGB value for rendering.
///
/// This resolves the color based on the intensity and reverse-video
/// settings, mapping named and indexed colors to 24-bit RGB values.
///
/// Ported from Ghidra's `AnsiColorResolver.resolveColor`.
///
/// # Parameters
/// - `color` -- the ANSI color to resolve
/// - `ground` -- whether this is for foreground or background
/// - `intensity` -- the intensity level (Normal, Bold, Dim)
/// - `reverse` -- reverse-video state
/// - `default_fg` -- default foreground RGB (0xRRGGBB)
/// - `default_bg` -- default background RGB (0xRRGGBB), or `None` for transparent
///
/// # Returns
/// An RGB value (0xRRGGBB), or `None` if the background should be
/// transparent (e.g., default background with no explicit color).
pub fn resolve_color(
    color: AnsiColor,
    ground: WhichGround,
    intensity: Intensity,
    reverse: ReverseVideo,
    default_fg: u32,
    default_bg: Option<u32>,
) -> Option<u32> {
    // First resolve the effective color name based on reverse video
    let effective_color = match reverse {
        ReverseVideo::Normal => color,
        ReverseVideo::Reversed => {
            // Swap will be handled by the caller passing swapped fg/bg defaults
            color
        }
    };

    match effective_color {
        AnsiColor::Default => {
            match reverse {
                ReverseVideo::Normal => match ground {
                    WhichGround::Foreground => Some(default_fg),
                    WhichGround::Background => default_bg,
                },
                ReverseVideo::Reversed => match ground {
                    WhichGround::Foreground => default_bg.or(Some(default_fg)),
                    WhichGround::Background => Some(default_fg),
                },
            }
        }
        // Standard 8 colors: apply bold -> brighten
        AnsiColor::Black | AnsiColor::Red | AnsiColor::Green | AnsiColor::Yellow
        | AnsiColor::Blue | AnsiColor::Magenta | AnsiColor::Cyan | AnsiColor::White => {
            let base = effective_color.to_rgb();
            if matches!(intensity, Intensity::Bold) {
                Some(brighten(base))
            } else {
                Some(base)
            }
        }
        // Bright variants are already bright
        AnsiColor::BrightBlack | AnsiColor::BrightRed | AnsiColor::BrightGreen
        | AnsiColor::BrightYellow | AnsiColor::BrightBlue | AnsiColor::BrightMagenta
        | AnsiColor::BrightCyan | AnsiColor::BrightWhite => Some(effective_color.to_rgb()),
        // 256-color indexed
        AnsiColor::Indexed(idx) => Some(indexed_color_to_rgb(idx)),
        // 24-bit RGB
        AnsiColor::Rgb(r, g, b) => Some(rgb_to_u32(r, g, b)),
    }
}

/// Brighten an RGB color by adding 0x55 to each channel, capped at 0xFF.
fn brighten(color: u32) -> u32 {
    let r = ((color >> 16) & 0xFF).saturating_add(0x55).min(0xFF);
    let g = ((color >> 8) & 0xFF).saturating_add(0x55).min(0xFF);
    let b = (color & 0xFF).saturating_add(0x55).min(0xFF);
    (r << 16) | (g << 8) | b
}

/// Convert a 256-color palette index to RGB.
fn indexed_color_to_rgb(idx: u8) -> u32 {
    match idx {
        // 0-7: Standard colors
        0 => 0x000000,
        1 => 0xAA0000,
        2 => 0x00AA00,
        3 => 0xAA5500,
        4 => 0x0000AA,
        5 => 0xAA00AA,
        6 => 0x00AAAA,
        7 => 0xAAAAAA,
        // 8-15: Bright colors
        8 => 0x555555,
        9 => 0xFF5555,
        10 => 0x55FF55,
        11 => 0xFFFF55,
        12 => 0x5555FF,
        13 => 0xFF55FF,
        14 => 0x55FFFF,
        15 => 0xFFFFFF,
        // 16-231: 6x6x6 color cube
        16..=231 => {
            let adjusted = idx - 16;
            let b_idx = adjusted % 6;
            let g_idx = (adjusted / 6) % 6;
            let r_idx = adjusted / 36;
            let r = color_cube_component(r_idx);
            let g = color_cube_component(g_idx);
            let b = color_cube_component(b_idx);
            rgb_to_u32(r, g, b)
        }
        // 232-255: Grayscale ramp
        232..=255 => {
            let gray = 8 + (idx - 232) * 10;
            rgb_to_u32(gray, gray, gray)
        }
    }
}

/// Map a 6x6x6 color cube index (0-5) to a component value.
fn color_cube_component(idx: u8) -> u8 {
    match idx {
        0 => 0,
        1 => 95,
        2 => 135,
        3 => 175,
        4 => 215,
        5 => 255,
        _ => 0,
    }
}

/// Convert R, G, B components to a packed u32 (0xRRGGBB).
fn rgb_to_u32(r: u8, g: u8, b: u8) -> u32 {
    ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_video_normal() {
        assert_eq!(
            ReverseVideo::Normal.fg(AnsiColor::Red, AnsiColor::Blue),
            AnsiColor::Red
        );
        assert_eq!(
            ReverseVideo::Normal.bg(AnsiColor::Red, AnsiColor::Blue),
            AnsiColor::Blue
        );
    }

    #[test]
    fn test_reverse_video_reversed() {
        assert_eq!(
            ReverseVideo::Reversed.fg(AnsiColor::Red, AnsiColor::Blue),
            AnsiColor::Blue
        );
        assert_eq!(
            ReverseVideo::Reversed.bg(AnsiColor::Red, AnsiColor::Blue),
            AnsiColor::Red
        );
    }

    #[test]
    fn test_resolve_default_fg() {
        let result = resolve_color(
            AnsiColor::Default,
            WhichGround::Foreground,
            Intensity::Normal,
            ReverseVideo::Normal,
            0xE5E5E5,
            Some(0x1E1E1E),
        );
        assert_eq!(result, Some(0xE5E5E5));
    }

    #[test]
    fn test_resolve_default_bg() {
        let result = resolve_color(
            AnsiColor::Default,
            WhichGround::Background,
            Intensity::Normal,
            ReverseVideo::Normal,
            0xE5E5E5,
            Some(0x1E1E1E),
        );
        assert_eq!(result, Some(0x1E1E1E));
    }

    #[test]
    fn test_resolve_default_bg_transparent() {
        let result = resolve_color(
            AnsiColor::Default,
            WhichGround::Background,
            Intensity::Normal,
            ReverseVideo::Normal,
            0xE5E5E5,
            None,
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_resolve_default_reversed() {
        let result = resolve_color(
            AnsiColor::Default,
            WhichGround::Foreground,
            Intensity::Normal,
            ReverseVideo::Reversed,
            0xE5E5E5,
            Some(0x1E1E1E),
        );
        // Reversed: foreground takes background's value
        assert_eq!(result, Some(0x1E1E1E));
    }

    #[test]
    fn test_resolve_red_normal() {
        let result = resolve_color(
            AnsiColor::Red,
            WhichGround::Foreground,
            Intensity::Normal,
            ReverseVideo::Normal,
            0xE5E5E5,
            Some(0x1E1E1E),
        );
        // Red's to_rgb() is 0xCD3131
        assert_eq!(result, Some(0xCD3131));
    }

    #[test]
    fn test_resolve_red_bold() {
        let result = resolve_color(
            AnsiColor::Red,
            WhichGround::Foreground,
            Intensity::Bold,
            ReverseVideo::Normal,
            0xE5E5E5,
            Some(0x1E1E1E),
        );
        // Red brightened: 0xCD3131 -> add 0x55 to each channel, capped at 0xFF
        // R: 0xCD + 0x55 = 0xFF (cap), G: 0x31 + 0x55 = 0x86, B: 0x31 + 0x55 = 0x86
        assert_eq!(result, Some(0xFF8686));
    }

    #[test]
    fn test_resolve_bright_color() {
        let result = resolve_color(
            AnsiColor::BrightBlue,
            WhichGround::Foreground,
            Intensity::Normal,
            ReverseVideo::Normal,
            0xE5E5E5,
            Some(0x1E1E1E),
        );
        // BrightBlue.to_rgb() is 0x3B8EEA
        assert_eq!(result, Some(0x3B8EEA));
    }

    #[test]
    fn test_resolve_indexed_color() {
        // Index 196 = r_idx=5, g_idx=0, b_idx=0 -> red=255, green=0, blue=0
        let result = resolve_color(
            AnsiColor::Indexed(196),
            WhichGround::Foreground,
            Intensity::Normal,
            ReverseVideo::Normal,
            0xE5E5E5,
            Some(0x1E1E1E),
        );
        assert_eq!(result, Some(0xFF0000));
    }

    #[test]
    fn test_resolve_rgb_color() {
        let result = resolve_color(
            AnsiColor::Rgb(0x12, 0x34, 0x56),
            WhichGround::Foreground,
            Intensity::Normal,
            ReverseVideo::Normal,
            0xE5E5E5,
            Some(0x1E1E1E),
        );
        assert_eq!(result, Some(0x123456));
    }

    #[test]
    fn test_brighten() {
        assert_eq!(brighten(0x000000), 0x555555);
        // Red (0xAA0000) -> (0xFF5555)
        assert_eq!(brighten(0xAA0000), 0xFF5555);
        // Already white -> capped
        assert_eq!(brighten(0xFFFFFF), 0xFFFFFF);
    }

    #[test]
    fn test_color_cube_component() {
        assert_eq!(color_cube_component(0), 0);
        assert_eq!(color_cube_component(1), 95);
        assert_eq!(color_cube_component(5), 255);
    }

    #[test]
    fn test_indexed_grayscale() {
        // Index 232 = darkest gray
        let result = indexed_color_to_rgb(232);
        assert_eq!(result, rgb_to_u32(8, 8, 8));
        // Index 255 = lightest gray
        let result = indexed_color_to_rgb(255);
        assert_eq!(result, rgb_to_u32(238, 238, 238));
    }

    #[test]
    fn test_rgb_to_u32() {
        assert_eq!(rgb_to_u32(0, 0, 0), 0x000000);
        assert_eq!(rgb_to_u32(255, 255, 255), 0xFFFFFF);
        assert_eq!(rgb_to_u32(0x12, 0x34, 0x56), 0x123456);
    }

    #[test]
    fn test_indexed_color_standard_range_values() {
        // Verify indices 0-7 map to known xterm-256 values
        assert_eq!(indexed_color_to_rgb(0), 0x000000); // Black
        assert_eq!(indexed_color_to_rgb(1), 0xAA0000); // Red
        assert_eq!(indexed_color_to_rgb(2), 0x00AA00); // Green
        assert_eq!(indexed_color_to_rgb(7), 0xAAAAAA); // White (gray)
    }

    #[test]
    fn test_indexed_color_bright_range() {
        // Verify 8-15 are bright enough (>= 0x555555)
        for i in 8..16u8 {
            let color = indexed_color_to_rgb(i);
            assert!(color >= 0x555555, "Bright color {} too dark: 0x{:06X}", i, color);
        }
    }

    #[test]
    fn test_which_ground_debug() {
        assert_eq!(format!("{:?}", WhichGround::Foreground), "Foreground");
        assert_eq!(format!("{:?}", WhichGround::Background), "Background");
    }

    #[test]
    fn test_reverse_video_debug() {
        assert_eq!(format!("{:?}", ReverseVideo::Normal), "Normal");
        assert_eq!(format!("{:?}", ReverseVideo::Reversed), "Reversed");
    }
}
