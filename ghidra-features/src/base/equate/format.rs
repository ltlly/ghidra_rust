//! Scalar format conversion -- mirrors `ghidra.app.plugin.core.equate.ConvertCommand`
//! and the various `ConvertTo*Action` classes.
//!
//! Provides the [`FormatChoice`] enum and [`format_scalar`] function that
//! convert a [`Scalar`] into a human-readable string in a chosen format.

use super::Scalar;
use std::fmt;

// ---------------------------------------------------------------------------
// FormatChoice -- mirrors FormatSettingsDefinition format constants
// ---------------------------------------------------------------------------

/// The display format for a scalar value.
///
/// Corresponds to the constants in Ghidra's `FormatSettingsDefinition`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FormatChoice {
    /// Unsigned hexadecimal (`0x` prefix for instructions, `h` suffix for data).
    Hex,
    /// Signed hexadecimal (`-0x` prefix for negative values).
    SignedHex,
    /// Unsigned decimal.
    UnsignedDecimal,
    /// Signed decimal.
    SignedDecimal,
    /// Unsigned octal (`o` suffix).
    Octal,
    /// Unsigned binary (`b` suffix).
    Binary,
    /// Character/byte representation.
    Char,
    /// Float (32-bit IEEE 754 interpretation of the value).
    Float,
    /// Double (64-bit IEEE 754 interpretation of the value).
    Double,
}

impl FormatChoice {
    /// Returns the Ghidra `FormatSettingsDefinition` constant value, or -1 if
    /// unsupported for data.
    pub fn format_id(self) -> i32 {
        match self {
            FormatChoice::Hex => 0,
            FormatChoice::SignedHex => 0, // same setting, different rendering
            FormatChoice::UnsignedDecimal => 1,
            FormatChoice::SignedDecimal => 1,
            FormatChoice::Octal => 2,
            FormatChoice::Binary => 3,
            FormatChoice::Char => 4,
            FormatChoice::Float => -1,
            FormatChoice::Double => -1,
        }
    }

    /// Returns `true` if this format requires the scalar to be negative to
    /// produce a meaningfully different display (e.g., signed hex, signed decimal).
    pub fn requires_negative(&self) -> bool {
        matches!(self, FormatChoice::SignedHex | FormatChoice::SignedDecimal)
    }

    /// Returns `true` if this format is supported on data items.
    pub fn is_supported_on_data(&self) -> bool {
        !matches!(self, FormatChoice::Float | FormatChoice::Double)
    }
}

impl fmt::Display for FormatChoice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatChoice::Hex => write!(f, "Unsigned Hex"),
            FormatChoice::SignedHex => write!(f, "Signed Hex"),
            FormatChoice::UnsignedDecimal => write!(f, "Unsigned Decimal"),
            FormatChoice::SignedDecimal => write!(f, "Signed Decimal"),
            FormatChoice::Octal => write!(f, "Unsigned Octal"),
            FormatChoice::Binary => write!(f, "Unsigned Binary"),
            FormatChoice::Char => write!(f, "Char"),
            FormatChoice::Float => write!(f, "Float"),
            FormatChoice::Double => write!(f, "Double"),
        }
    }
}

// ---------------------------------------------------------------------------
// format_scalar -- the core conversion function
// ---------------------------------------------------------------------------

/// Format a scalar in the given format.
///
/// For instruction operands, the result is used as an equate display name.
/// For data items, the result sets the display format setting.
///
/// Returns `None` when the format is unsupported for the given context
/// (e.g., Float on data items).
pub fn format_scalar(scalar: &Scalar, format: FormatChoice, is_data: bool) -> Option<String> {
    match format {
        FormatChoice::Hex => Some(format_unsigned_hex(scalar, is_data)),
        FormatChoice::SignedHex => {
            if is_data {
                return None; // unsupported on data
            }
            Some(format_signed_hex(scalar))
        }
        FormatChoice::UnsignedDecimal => Some(format_unsigned_decimal(scalar)),
        FormatChoice::SignedDecimal => Some(format_signed_decimal(scalar)),
        FormatChoice::Octal => Some(format_octal(scalar)),
        FormatChoice::Binary => Some(format_binary(scalar)),
        FormatChoice::Char => Some(format_char(scalar)),
        FormatChoice::Float => {
            if is_data {
                return None;
            }
            format_float(scalar)
        }
        FormatChoice::Double => {
            if is_data {
                return None;
            }
            format_double(scalar)
        }
    }
}

/// Compute the menu label for a format conversion action.
///
/// Returns `None` when the action is disabled (e.g., signed formats on
/// non-negative scalars).
pub fn menu_label(scalar: &Scalar, format: FormatChoice, is_data: bool) -> Option<String> {
    if format.requires_negative() && scalar.signed_value() >= 0 {
        return None;
    }
    let value_str = format_scalar(scalar, format, is_data)?;
    let label = match format {
        FormatChoice::Hex => "Unsigned Hex:",
        FormatChoice::SignedHex => "Signed Hex:",
        FormatChoice::UnsignedDecimal => "Unsigned Decimal:",
        FormatChoice::SignedDecimal => "Signed Decimal:",
        FormatChoice::Octal => "Unsigned Octal:",
        FormatChoice::Binary => "Unsigned Binary:",
        FormatChoice::Char => {
            if scalar.bit_length() > 8 {
                "Char Sequence:"
            } else {
                "Char"
            }
        }
        FormatChoice::Float => "Float:",
        FormatChoice::Double => "Double:",
    };
    // Pad to standard width (~18 chars) for consistent menu rendering.
    Some(format_padded(label, &value_str))
}

// ---------------------------------------------------------------------------
// Private formatting helpers
// ---------------------------------------------------------------------------

fn format_unsigned_hex(scalar: &Scalar, is_data: bool) -> String {
    let hex = format!("{:X}", scalar.unsigned_value());
    if is_data {
        format!("{}h", hex)
    } else {
        format!("0x{}", hex)
    }
}

fn format_signed_hex(scalar: &Scalar) -> String {
    let v = scalar.signed_value();
    if v < 0 {
        format!("-0x{:X}", (-v) as u64)
    } else {
        format!("0x{:X}", v)
    }
}

fn format_unsigned_decimal(scalar: &Scalar) -> String {
    scalar.unsigned_value().to_string()
}

fn format_signed_decimal(scalar: &Scalar) -> String {
    scalar.signed_value().to_string()
}

fn format_octal(scalar: &Scalar) -> String {
    format!("{:o}o", scalar.unsigned_value())
}

fn format_binary(scalar: &Scalar) -> String {
    let raw = format!("{:b}", scalar.unsigned_value());
    // Pad to the scalar's bit length.
    let padded = if raw.len() < scalar.bit_length() as usize {
        format!(
            "{}{}",
            "0".repeat(scalar.bit_length() as usize - raw.len()),
            raw
        )
    } else {
        raw
    };
    format!("{}b", padded)
}

fn format_char(scalar: &Scalar) -> String {
    let bytes = scalar.byte_array_value();
    // Render each byte as a character if printable, else as escape.
    let mut result = String::new();
    for &b in &bytes {
        if b >= 0x20 && b <= 0x7E {
            if b == b'\'' {
                result.push_str("\\'");
            } else if b == b'\\' {
                result.push_str("\\\\");
            } else {
                result.push(b as char);
            }
        } else {
            result.push_str(&format!("\\x{:02x}", b));
        }
    }
    format!("'{}'", result)
}

fn format_float(scalar: &Scalar) -> Option<String> {
    if scalar.bit_length() < 32 {
        return None;
    }
    let bits = scalar.unsigned_value() as u32;
    let f = f32::from_bits(bits);
    Some(format!("{}", f))
}

fn format_double(scalar: &Scalar) -> Option<String> {
    if scalar.bit_length() < 64 {
        return None;
    }
    let bits = scalar.unsigned_value();
    let d = f64::from_bits(bits);
    Some(format!("{}", d))
}

fn format_padded(label: &str, value: &str) -> String {
    let target_width = 18;
    let padding = if label.len() < target_width {
        " ".repeat(target_width - label.len())
    } else {
        String::new()
    };
    format!("{}{}{}", label, padding, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_hex_unsigned() {
        let s = Scalar::unsigned(32, 0xDEAD);
        assert_eq!(format_scalar(&s, FormatChoice::Hex, false).unwrap(), "0xDEAD");
        assert_eq!(format_scalar(&s, FormatChoice::Hex, true).unwrap(), "DEADh");
    }

    #[test]
    fn test_format_signed_hex_negative() {
        let s = Scalar::signed(8, -1);
        assert_eq!(
            format_scalar(&s, FormatChoice::SignedHex, false).unwrap(),
            "-0x1"
        );
    }

    #[test]
    fn test_format_signed_decimal() {
        let s = Scalar::signed(8, -42);
        assert_eq!(
            format_scalar(&s, FormatChoice::SignedDecimal, false).unwrap(),
            "-42"
        );
    }

    #[test]
    fn test_format_unsigned_decimal() {
        let s = Scalar::unsigned(16, 255);
        assert_eq!(
            format_scalar(&s, FormatChoice::UnsignedDecimal, false).unwrap(),
            "255"
        );
    }

    #[test]
    fn test_format_octal() {
        let s = Scalar::unsigned(16, 255);
        assert_eq!(
            format_scalar(&s, FormatChoice::Octal, false).unwrap(),
            "377o"
        );
    }

    #[test]
    fn test_format_binary() {
        let s = Scalar::unsigned(8, 0b1010);
        assert_eq!(
            format_scalar(&s, FormatChoice::Binary, false).unwrap(),
            "00001010b"
        );
    }

    #[test]
    fn test_format_char() {
        let s = Scalar::unsigned(8, b'A' as u64);
        assert_eq!(
            format_scalar(&s, FormatChoice::Char, false).unwrap(),
            "'A'"
        );
    }

    #[test]
    fn test_format_char_non_printable() {
        let s = Scalar::unsigned(8, 0x0A);
        assert_eq!(
            format_scalar(&s, FormatChoice::Char, false).unwrap(),
            "'\\x0a'"
        );
    }

    #[test]
    fn test_format_float() {
        // 1.0f32 = 0x3F800000
        let s = Scalar::unsigned(32, 0x3F800000);
        assert_eq!(
            format_scalar(&s, FormatChoice::Float, false).unwrap(),
            "1"
        );
    }

    #[test]
    fn test_format_float_unsupported_on_data() {
        let s = Scalar::unsigned(32, 0x3F800000);
        assert!(format_scalar(&s, FormatChoice::Float, true).is_none());
    }

    #[test]
    fn test_menu_label_unsigned_hex() {
        let s = Scalar::unsigned(32, 0xFF);
        let label = menu_label(&s, FormatChoice::Hex, false).unwrap();
        assert!(label.contains("Unsigned Hex:"));
        assert!(label.contains("0xFF"));
    }

    #[test]
    fn test_menu_label_signed_hex_disabled_for_positive() {
        let s = Scalar::unsigned(32, 42);
        assert!(menu_label(&s, FormatChoice::SignedHex, false).is_none());
    }

    #[test]
    fn test_menu_label_signed_hex_enabled_for_negative() {
        let s = Scalar::signed(32, -1);
        let label = menu_label(&s, FormatChoice::SignedHex, false).unwrap();
        assert!(label.contains("Signed Hex:"));
    }
}
