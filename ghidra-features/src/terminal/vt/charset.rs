//! VT100 character set designation.
//!
//! Ported from `ghidra.app.plugin.core.terminal.vt.VtCharset`.

/// The G-set (G0, G1, G2, G3) a charset is designated to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GSet {
    /// G0 -- the default character set.
    G0,
    /// G1 -- alternate character set.
    G1,
    /// G2 -- lock-shift character set.
    G2,
    /// G3 -- lock-shift character set.
    G3,
}

impl GSet {
    /// The byte that selects this G-set in a charset designation sequence.
    pub fn byte(&self) -> u8 {
        match self {
            Self::G0 => b'(',
            Self::G1 => b')',
            Self::G2 => b'*',
            Self::G3 => b'+',
        }
    }
}

/// A named character set for VT100/VT220 terminals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VtCharset {
    /// The short name.
    pub name: &'static str,
    /// The final byte in the designation sequence.
    pub byte: u8,
}

impl VtCharset {
    /// UK character set.
    pub const UK: Self = Self { name: "UK", byte: b'A' };
    /// ASCII (US) character set.
    pub const ASCII: Self = Self { name: "ASCII", byte: b'B' };
    /// DEC Special Graphics (line drawing).
    pub const DEC_SPECIAL_GRAPHICS: Self = Self { name: "DECSpecialGraphics", byte: b'0' };
    /// DEC Supplemental.
    pub const DEC_SUPPLEMENTAL: Self = Self { name: "DEC Supplemental", byte: b'<' };
    /// DEC Technical.
    pub const DEC_TECHNICAL: Self = Self { name: "DEC Technical", byte: b'>' };
    /// Dutch.
    pub const DUTCH: Self = Self { name: "Dutch", byte: b'4' };
    /// Finnish.
    pub const FINNISH: Self = Self { name: "Finnish", byte: b'5' };
    /// French.
    pub const FRENCH: Self = Self { name: "French", byte: b'R' };
    /// French Canadian.
    pub const FRENCH_CANADIAN: Self = Self { name: "French Canadian", byte: b'Q' };
    /// German.
    pub const GERMAN: Self = Self { name: "German", byte: b'K' };
    /// Italian.
    pub const ITALIAN: Self = Self { name: "Italian", byte: b'Y' };
    /// Norwegian/Danish.
    pub const NORWEGIAN_DANISH: Self = Self { name: "Norwegian/Danish", byte: b'E' };
    /// Spanish.
    pub const SPANISH: Self = Self { name: "Spanish", byte: b'Z' };
    /// Swedish.
    pub const SWEDISH: Self = Self { name: "Swedish", byte: b'H' };
    /// Swiss.
    pub const SWISS: Self = Self { name: "Swiss", byte: b'=' };
    /// Greek.
    pub const GREEK: Self = Self { name: "Greek", byte: b'>' };
    /// DEC Hebrew.
    pub const DEC_HEBREW: Self = Self { name: "DEC Hebrew", byte: b'4' };
    /// DEC Turkish.
    pub const TURKISH: Self = Self { name: "Turkish", byte: b'2' };
    /// DEC Portugese.
    pub const PORTUGESE: Self = Self { name: "Portugese", byte: b'6' };
    /// DEC Cyrillic.
    pub const DEC_CYRILLIC: Self = Self { name: "DEC Cyrillic", byte: b'4' };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_g_set_bytes() {
        assert_eq!(GSet::G0.byte(), b'(');
        assert_eq!(GSet::G1.byte(), b')');
        assert_eq!(GSet::G2.byte(), b'*');
        assert_eq!(GSet::G3.byte(), b'+');
    }

    #[test]
    fn test_charset_names() {
        assert_eq!(VtCharset::ASCII.name, "ASCII");
        assert_eq!(VtCharset::UK.name, "UK");
        assert_eq!(VtCharset::DEC_SPECIAL_GRAPHICS.name, "DECSpecialGraphics");
    }

    #[test]
    fn test_charset_bytes() {
        assert_eq!(VtCharset::ASCII.byte, b'B');
        assert_eq!(VtCharset::UK.byte, b'A');
        assert_eq!(VtCharset::DEC_SPECIAL_GRAPHICS.byte, b'0');
    }
}
