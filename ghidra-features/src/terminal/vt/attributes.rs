//! VT100 terminal attributes (SGR -- Select Graphic Rendition).
//!
//! Ported from `ghidra.app.plugin.core.terminal.vt.VtAttributes`.
//!
//! Attributes are immutable records describing the visual style of characters
//! placed into the terminal buffer. They include foreground/background colors,
//! intensity, underline, blink, reverse-video, hidden, strike-through, etc.

/// An ANSI terminal color.
///
/// Supports the standard 8 colors, bright variants, 256-color indexed palette,
/// and 24-bit RGB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnsiColor {
    /// Default terminal foreground/background.
    Default,
    /// Standard black (index 0).
    Black,
    /// Standard red (index 1).
    Red,
    /// Standard green (index 2).
    Green,
    /// Standard yellow (index 3).
    Yellow,
    /// Standard blue (index 4).
    Blue,
    /// Standard magenta (index 5).
    Magenta,
    /// Standard cyan (index 6).
    Cyan,
    /// Standard white (index 7).
    White,
    /// Bright black / dark gray (index 8).
    BrightBlack,
    /// Bright red (index 9).
    BrightRed,
    /// Bright green (index 10).
    BrightGreen,
    /// Bright yellow (index 11).
    BrightYellow,
    /// Bright blue (index 12).
    BrightBlue,
    /// Bright magenta (index 13).
    BrightMagenta,
    /// Bright cyan (index 14).
    BrightCyan,
    /// Bright white (index 15).
    BrightWhite,
    /// 256-color palette index (0..=255).
    Indexed(u8),
    /// 24-bit true color (R, G, B).
    Rgb(u8, u8, u8),
}

impl AnsiColor {
    /// Convert a standard SGR color parameter (30..37, 40..47) to an `AnsiColor`.
    pub fn from_sgr_fg(code: u16) -> Self {
        match code {
            30 => Self::Black,
            31 => Self::Red,
            32 => Self::Green,
            33 => Self::Yellow,
            34 => Self::Blue,
            35 => Self::Magenta,
            36 => Self::Cyan,
            37 => Self::White,
            _ => Self::Default,
        }
    }

    /// Convert a standard SGR background color parameter (40..47) to an `AnsiColor`.
    pub fn from_sgr_bg(code: u16) -> Self {
        Self::from_sgr_fg(code - 10)
    }

    /// Convert a bright SGR color parameter (90..97 or 100..107) to an `AnsiColor`.
    pub fn from_sgr_bright_fg(code: u16) -> Self {
        match code {
            90 => Self::BrightBlack,
            91 => Self::BrightRed,
            92 => Self::BrightGreen,
            93 => Self::BrightYellow,
            94 => Self::BrightBlue,
            95 => Self::BrightMagenta,
            96 => Self::BrightCyan,
            97 => Self::BrightWhite,
            _ => Self::Default,
        }
    }

    /// Convert a bright SGR background color parameter (100..107) to an `AnsiColor`.
    pub fn from_sgr_bright_bg(code: u16) -> Self {
        Self::from_sgr_bright_fg(code - 10)
    }

    /// Convert to a 24-bit RGB value (0xRRGGBB).
    pub fn to_rgb(&self) -> u32 {
        match self {
            Self::Default => 0xD4D4D4,
            Self::Black => 0x000000,
            Self::Red => 0xCD3131,
            Self::Green => 0x0DBC79,
            Self::Yellow => 0xE5E510,
            Self::Blue => 0x2472C8,
            Self::Magenta => 0xBC3FBC,
            Self::Cyan => 0x11A8CD,
            Self::White => 0xE5E5E5,
            Self::BrightBlack => 0x666666,
            Self::BrightRed => 0xF14C4C,
            Self::BrightGreen => 0x23D18B,
            Self::BrightYellow => 0xF5F543,
            Self::BrightBlue => 0x3B8EEA,
            Self::BrightMagenta => 0xD670D6,
            Self::BrightCyan => 0x29B8DB,
            Self::BrightWhite => 0xFFFFFF,
            Self::Indexed(_) => 0xD4D4D4, // simplified
            Self::Rgb(r, g, b) => ((*r as u32) << 16) | ((*g as u32) << 8) | (*b as u32),
        }
    }
}

/// Intensity (brightness) of text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Intensity {
    /// Normal intensity.
    Normal,
    /// Bold / bright.
    Bold,
    /// Dim / faint.
    Dim,
}

/// Font selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnsiFont {
    /// Normal font.
    Normal,
    /// Alternative font 1.
    Font1,
    /// Alternative font 2.
    Font2,
    /// Alternative font 3.
    Font3,
    /// Alternative font 4.
    Font4,
    /// Alternative font 5.
    Font5,
    /// Alternative font 6.
    Font6,
    /// Alternative font 7.
    Font7,
    /// Alternative font 8.
    Font8,
    /// Alternative font 9.
    Font9,
    /// Fraktur / Gothic.
    Fraktur,
}

/// Underline style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Underline {
    /// No underline.
    None,
    /// Single underline.
    Single,
    /// Double underline.
    Double,
    /// Curly underline.
    Curly,
    /// Dotted underline.
    Dotted,
    /// Dashed underline.
    Dashed,
}

/// Blink mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Blink {
    /// No blink.
    None,
    /// Slow blink (< 150/min).
    Slow,
    /// Rapid blink (>= 150/min).
    Rapid,
}

/// Reverse-video mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReverseVideo {
    /// Normal (not reversed).
    Normal,
    /// Reversed foreground and background.
    Reversed,
}

impl ReverseVideo {
    /// Get the effective foreground, swapping if reversed.
    pub fn fg(&self, fg: AnsiColor, bg: AnsiColor) -> AnsiColor {
        match self {
            Self::Normal => fg,
            Self::Reversed => bg,
        }
    }

    /// Get the effective background, swapping if reversed.
    pub fn bg(&self, fg: AnsiColor, bg: AnsiColor) -> AnsiColor {
        match self {
            Self::Normal => bg,
            Self::Reversed => fg,
        }
    }
}

/// The full set of VT100/VT220 character attributes.
///
/// Ported from `ghidra.app.plugin.core.terminal.vt.VtAttributes`.
/// This is an immutable value type. Each `with_*` method returns a new copy
/// with the specified field changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VtAttributes {
    /// Foreground color.
    pub fg: AnsiColor,
    /// Background color.
    pub bg: AnsiColor,
    /// Text intensity.
    pub intensity: Intensity,
    /// Font selection.
    pub font: AnsiFont,
    /// Underline style.
    pub underline: Underline,
    /// Blink mode.
    pub blink: Blink,
    /// Reverse-video mode.
    pub reverse: ReverseVideo,
    /// Whether text is hidden (invisible).
    pub hidden: bool,
    /// Whether text has strike-through.
    pub strike_through: bool,
    /// Proportional spacing (rare).
    pub proportional_spacing: bool,
}

impl VtAttributes {
    /// Default attributes: normal white-on-black.
    pub const DEFAULTS: Self = Self {
        fg: AnsiColor::Default,
        bg: AnsiColor::Default,
        intensity: Intensity::Normal,
        font: AnsiFont::Normal,
        underline: Underline::None,
        blink: Blink::None,
        reverse: ReverseVideo::Normal,
        hidden: false,
        strike_through: false,
        proportional_spacing: false,
    };

    /// Return a copy with the foreground color replaced.
    pub fn with_fg(&self, fg: AnsiColor) -> Self {
        Self { fg, ..self.clone() }
    }

    /// Return a copy with the background color replaced.
    pub fn with_bg(&self, bg: AnsiColor) -> Self {
        Self { bg, ..self.clone() }
    }

    /// Return a copy with the intensity replaced.
    pub fn with_intensity(&self, intensity: Intensity) -> Self {
        Self { intensity, ..self.clone() }
    }

    /// Return a copy with the font replaced.
    pub fn with_font(&self, font: AnsiFont) -> Self {
        Self { font, ..self.clone() }
    }

    /// Return a copy with the underline style replaced.
    pub fn with_underline(&self, underline: Underline) -> Self {
        Self { underline, ..self.clone() }
    }

    /// Return a copy with the blink mode replaced.
    pub fn with_blink(&self, blink: Blink) -> Self {
        Self { blink, ..self.clone() }
    }

    /// Return a copy with the reverse-video mode replaced.
    pub fn with_reverse(&self, reverse: ReverseVideo) -> Self {
        Self { reverse, ..self.clone() }
    }

    /// Return a copy with the hidden flag replaced.
    pub fn with_hidden(&self, hidden: bool) -> Self {
        Self { hidden, ..self.clone() }
    }

    /// Return a copy with the strike-through flag replaced.
    pub fn with_strike_through(&self, strike_through: bool) -> Self {
        Self { strike_through, ..self.clone() }
    }

    /// Apply SGR (Select Graphic Rendition) parameters to produce new attributes.
    ///
    /// `params` is the list of numeric SGR codes (e.g., `[1, 31]` for bold red).
    pub fn apply_sgr(&self, params: &[u16]) -> Self {
        let mut result = self.clone();
        let mut i = 0;
        while i < params.len() {
            match params[i] {
                0 => result = Self::DEFAULTS,
                1 => result = result.with_intensity(Intensity::Bold),
                2 => result = result.with_intensity(Intensity::Dim),
                3 => result = result.with_font(AnsiFont::Normal), // italic mapped to normal
                4 => {
                    let ul = if i + 1 < params.len() {
                        match params[i + 1] {
                            0 => { i += 1; Underline::None }
                            1 => { i += 1; Underline::Single }
                            2 => { i += 1; Underline::Double }
                            3 => { i += 1; Underline::Curly }
                            4 => { i += 1; Underline::Dotted }
                            5 => { i += 1; Underline::Dashed }
                            _ => Underline::Single,
                        }
                    } else {
                        Underline::Single
                    };
                    result = result.with_underline(ul);
                }
                5 => result = result.with_blink(Blink::Slow),
                6 => result = result.with_blink(Blink::Rapid),
                7 => result = result.with_reverse(ReverseVideo::Reversed),
                8 => result = result.with_hidden(true),
                9 => result = result.with_strike_through(true),
                22 => result = result.with_intensity(Intensity::Normal),
                23 => result = result.with_font(AnsiFont::Normal),
                24 => result = result.with_underline(Underline::None),
                25 => result = result.with_blink(Blink::None),
                27 => result = result.with_reverse(ReverseVideo::Normal),
                28 => result = result.with_hidden(false),
                29 => result = result.with_strike_through(false),
                30..=37 => result = result.with_fg(AnsiColor::from_sgr_fg(params[i])),
                38 => {
                    // Extended foreground: 38;5;n or 38;2;r;g;b
                    if i + 1 < params.len() {
                        match params[i + 1] {
                            5 if i + 2 < params.len() => {
                                result = result.with_fg(AnsiColor::Indexed(params[i + 2] as u8));
                                i += 2;
                            }
                            2 if i + 4 < params.len() => {
                                result = result.with_fg(AnsiColor::Rgb(
                                    params[i + 2] as u8,
                                    params[i + 3] as u8,
                                    params[i + 4] as u8,
                                ));
                                i += 4;
                            }
                            _ => {}
                        }
                    }
                }
                39 => result = result.with_fg(AnsiColor::Default),
                40..=47 => result = result.with_bg(AnsiColor::from_sgr_bg(params[i])),
                48 => {
                    // Extended background: 48;5;n or 48;2;r;g;b
                    if i + 1 < params.len() {
                        match params[i + 1] {
                            5 if i + 2 < params.len() => {
                                result = result.with_bg(AnsiColor::Indexed(params[i + 2] as u8));
                                i += 2;
                            }
                            2 if i + 4 < params.len() => {
                                result = result.with_bg(AnsiColor::Rgb(
                                    params[i + 2] as u8,
                                    params[i + 3] as u8,
                                    params[i + 4] as u8,
                                ));
                                i += 4;
                            }
                            _ => {}
                        }
                    }
                }
                49 => result = result.with_bg(AnsiColor::Default),
                90..=97 => result = result.with_fg(AnsiColor::from_sgr_bright_fg(params[i])),
                100..=107 => result = result.with_bg(AnsiColor::from_sgr_bright_bg(params[i])),
                _ => {} // unknown SGR code, ignore
            }
            i += 1;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_attributes() {
        let attrs = VtAttributes::DEFAULTS;
        assert_eq!(attrs.fg, AnsiColor::Default);
        assert_eq!(attrs.intensity, Intensity::Normal);
        assert_eq!(attrs.underline, Underline::None);
        assert!(!attrs.hidden);
        assert!(!attrs.strike_through);
    }

    #[test]
    fn test_sgr_bold_red() {
        let attrs = VtAttributes::DEFAULTS.apply_sgr(&[1, 31]);
        assert_eq!(attrs.intensity, Intensity::Bold);
        assert_eq!(attrs.fg, AnsiColor::Red);
    }

    #[test]
    fn test_sgr_reset() {
        let attrs = VtAttributes::DEFAULTS
            .apply_sgr(&[1, 31])
            .apply_sgr(&[0]);
        assert_eq!(attrs, VtAttributes::DEFAULTS);
    }

    #[test]
    fn test_sgr_extended_fg_256() {
        let attrs = VtAttributes::DEFAULTS.apply_sgr(&[38, 5, 196]);
        assert_eq!(attrs.fg, AnsiColor::Indexed(196));
    }

    #[test]
    fn test_sgr_extended_fg_rgb() {
        let attrs = VtAttributes::DEFAULTS.apply_sgr(&[38, 2, 255, 128, 0]);
        assert_eq!(attrs.fg, AnsiColor::Rgb(255, 128, 0));
    }

    #[test]
    fn test_sgr_underline_variants() {
        let attrs = VtAttributes::DEFAULTS.apply_sgr(&[4, 3]);
        assert_eq!(attrs.underline, Underline::Curly);
    }

    #[test]
    fn test_reverse_video_swap() {
        let rev = ReverseVideo::Reversed;
        assert_eq!(rev.fg(AnsiColor::Red, AnsiColor::Blue), AnsiColor::Blue);
        assert_eq!(rev.bg(AnsiColor::Red, AnsiColor::Blue), AnsiColor::Red);
    }

    #[test]
    fn test_ansi_color_to_rgb() {
        assert_eq!(AnsiColor::Black.to_rgb(), 0x000000);
        assert_eq!(AnsiColor::BrightWhite.to_rgb(), 0xFFFFFF);
        assert_eq!(AnsiColor::Rgb(255, 0, 0).to_rgb(), 0xFF0000);
    }

    #[test]
    fn test_with_methods_create_new_instances() {
        let a = VtAttributes::DEFAULTS;
        let b = a.with_fg(AnsiColor::Red);
        assert_eq!(a.fg, AnsiColor::Default);
        assert_eq!(b.fg, AnsiColor::Red);
    }

    #[test]
    fn test_sgr_dim_and_strike() {
        let attrs = VtAttributes::DEFAULTS.apply_sgr(&[2, 9]);
        assert_eq!(attrs.intensity, Intensity::Dim);
        assert!(attrs.strike_through);
    }

    #[test]
    fn test_sgr_hide_and_unhide() {
        let attrs = VtAttributes::DEFAULTS.apply_sgr(&[8]);
        assert!(attrs.hidden);
        let attrs2 = attrs.apply_sgr(&[28]);
        assert!(!attrs2.hidden);
    }
}
