//! Data-format conversion command — converts scalar operand display format.
//!
//! Ported from `ConvertCommand` and `AbstractConvertAction` in Ghidra's
//! `ghidra.app.plugin.core.equate`.
//!
//! This module provides [`ConvertCommand`], a background-capable command
//! that converts the display format of scalar operands in a listing.
//! Supported conversions include binary, octal, decimal (signed/unsigned),
//! hex (signed/unsigned), character (char), float, and double.
//!
//! Each conversion creates a concrete action struct (e.g.,
//! [`ConvertToBinaryAction`]) that can be triggered from the UI.

use std::fmt;

/// Display format for scalar operand conversion.
///
/// Mirrors the `FormatSettingsDefinition` format constants in Ghidra.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScalarFormat {
    /// Binary representation (e.g., "10101010").
    Binary,
    /// Character representation (single character if printable).
    Char,
    /// Signed decimal (e.g., "-128").
    SignedDecimal,
    /// Unsigned decimal (e.g., "255").
    UnsignedDecimal,
    /// Octal representation (e.g., "0377").
    Octal,
    /// Signed hexadecimal (e.g., "-0x80").
    SignedHex,
    /// Unsigned hexadecimal (e.g., "0xFF").
    UnsignedHex,
    /// IEEE 754 single-precision float.
    Float,
    /// IEEE 754 double-precision double.
    Double,
}

impl ScalarFormat {
    /// All supported formats in display order.
    pub const ALL: [ScalarFormat; 9] = [
        Self::Binary,
        Self::Char,
        Self::SignedDecimal,
        Self::UnsignedDecimal,
        Self::Octal,
        Self::SignedHex,
        Self::UnsignedHex,
        Self::Float,
        Self::Double,
    ];

    /// Human-readable name of this format.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Binary => "Binary",
            Self::Char => "Char",
            Self::SignedDecimal => "Signed Decimal",
            Self::UnsignedDecimal => "Unsigned Decimal",
            Self::Octal => "Octal",
            Self::SignedHex => "Signed Hex",
            Self::UnsignedHex => "Unsigned Hex",
            Self::Float => "Float",
            Self::Double => "Double",
        }
    }

    /// Abbreviated format name (for menu items).
    pub fn short_name(&self) -> &'static str {
        match self {
            Self::Binary => "Bin",
            Self::Char => "Char",
            Self::SignedDecimal => "Dec",
            Self::UnsignedDecimal => "UDec",
            Self::Octal => "Oct",
            Self::SignedHex => "Hex",
            Self::UnsignedHex => "UHex",
            Self::Float => "Float",
            Self::Double => "Double",
        }
    }
}

impl fmt::Display for ScalarFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Result of a scalar format conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvertedValue {
    /// The original scalar value (as u64 for integer formats).
    pub original_value: u64,
    /// The byte width of the original value.
    pub byte_width: u8,
    /// The formatted string representation.
    pub formatted: String,
    /// The format used.
    pub format: ScalarFormat,
}

/// Convert a scalar value to the specified display format.
///
/// This is the core conversion function, equivalent to Java's
/// `ConvertCommand.run()`.
///
/// # Arguments
///
/// * `value` - The raw scalar value (interpreted as unsigned).
/// * `byte_width` - Number of bytes in the original value (1, 2, 4, or 8).
/// * `format` - The target display format.
pub fn convert_scalar(value: u64, byte_width: u8, format: ScalarFormat) -> ConvertedValue {
    let formatted = match format {
        ScalarFormat::Binary => format_binary(value, byte_width),
        ScalarFormat::Char => format_char(value, byte_width),
        ScalarFormat::SignedDecimal => format_signed_decimal(value, byte_width),
        ScalarFormat::UnsignedDecimal => format_unsigned_decimal(value),
        ScalarFormat::Octal => format_octal(value),
        ScalarFormat::SignedHex => format_signed_hex(value, byte_width),
        ScalarFormat::UnsignedHex => format_unsigned_hex(value),
        ScalarFormat::Float => format_float(value, byte_width),
        ScalarFormat::Double => format_double(value, byte_width),
    };

    ConvertedValue {
        original_value: value,
        byte_width,
        formatted,
        format,
    }
}

fn format_binary(value: u64, byte_width: u8) -> String {
    let bits = (byte_width as u32) * 8;
    let masked = value & ((1u64.wrapping_shl(bits)).wrapping_sub(1));
    format!("{:0>width$b}", masked, width = bits as usize)
}

fn format_char(value: u64, _byte_width: u8) -> String {
    let ch = (value & 0xFF) as u8;
    if ch.is_ascii_graphic() || ch == b' ' {
        format!("'{}'", ch as char)
    } else {
        format!("'\\x{:02x}'", ch)
    }
}

fn format_signed_decimal(value: u64, byte_width: u8) -> String {
    let bits = (byte_width as u32) * 8;
    if bits >= 64 {
        return format!("{}", value as i64);
    }
    let mask = (1u64 << bits) - 1;
    let masked = value & mask;
    let sign_bit = 1u64 << (bits - 1);
    if masked >= sign_bit {
        let signed = (masked as i64) - (1i64 << bits);
        format!("{}", signed)
    } else {
        format!("{}", masked as i64)
    }
}

fn format_unsigned_decimal(value: u64) -> String {
    format!("{}", value)
}

fn format_octal(value: u64) -> String {
    format!("{:o}", value)
}

fn format_signed_hex(value: u64, byte_width: u8) -> String {
    let bits = (byte_width as u32) * 8;
    if bits >= 64 {
        let signed = value as i64;
        if signed < 0 {
            return format!("-0x{:x}", signed.unsigned_abs());
        }
        return format!("0x{:x}", signed);
    }
    let mask = (1u64 << bits) - 1;
    let masked = value & mask;
    let sign_bit = 1u64 << (bits - 1);
    if masked >= sign_bit {
        let signed = (1i64 << bits) - masked as i64;
        format!("-0x{:x}", signed)
    } else {
        format!("0x{:x}", masked)
    }
}

fn format_unsigned_hex(value: u64) -> String {
    format!("0x{:x}", value)
}

fn format_float(value: u64, byte_width: u8) -> String {
    if byte_width >= 4 {
        let bits = (value & 0xFFFFFFFF) as u32;
        let f = f32::from_bits(bits);
        format!("{}", f)
    } else {
        // For < 4 bytes, convert via widening
        let bits = (value & 0xFFFFFFFF) as u32;
        let f = f32::from_bits(bits);
        format!("{}", f)
    }
}

fn format_double(value: u64, byte_width: u8) -> String {
    if byte_width >= 8 {
        let d = f64::from_bits(value);
        format!("{}", d)
    } else {
        // For < 8 bytes, zero-extend
        let d = f64::from_bits(value);
        format!("{}", d)
    }
}

/// A conversion action: combines a target format with the ability to
/// apply it to an address/operand in a listing.
///
/// Ported from the various `ConvertToXxxAction` classes in Java.
#[derive(Debug, Clone)]
pub struct FormatConvertAction {
    /// The target format.
    pub format: ScalarFormat,
    /// The action name (e.g., "Convert to Binary").
    pub name: String,
    /// The menu path.
    pub menu_path: String,
}

impl FormatConvertAction {
    /// Create a new convert action for the given format.
    pub fn new(format: ScalarFormat) -> Self {
        Self {
            format,
            name: format!("Convert to {}", format.name()),
            menu_path: format!("Convert/{}", format.name()),
        }
    }

    /// Convert a scalar value using this action's format.
    pub fn convert(&self, value: u64, byte_width: u8) -> ConvertedValue {
        convert_scalar(value, byte_width, self.format)
    }
}

/// Pre-built actions for each supported format.
pub fn all_convert_actions() -> Vec<FormatConvertAction> {
    ScalarFormat::ALL.iter().map(|f| FormatConvertAction::new(*f)).collect()
}

/// Format a scalar value for display in a given format.
///
/// This is a convenience wrapper around [`convert_scalar`] that returns
/// only the formatted string, suitable for menu labels and tooltips.
pub fn format_scalar_value(scalar: &super::Scalar, format: ScalarFormat) -> String {
    let byte_width = ((scalar.bit_length() + 7) / 8) as u8;
    let value = scalar.unsigned_value();
    convert_scalar(value, byte_width, format).formatted
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_binary() {
        let result = convert_scalar(0xAA, 1, ScalarFormat::Binary);
        assert_eq!(result.formatted, "10101010");
    }

    #[test]
    fn test_format_binary_16bit() {
        let result = convert_scalar(0xFF00, 2, ScalarFormat::Binary);
        assert_eq!(result.formatted, "1111111100000000");
    }

    #[test]
    fn test_format_char_printable() {
        let result = convert_scalar(b'A' as u64, 1, ScalarFormat::Char);
        assert_eq!(result.formatted, "'A'");
    }

    #[test]
    fn test_format_char_non_printable() {
        let result = convert_scalar(0x0A, 1, ScalarFormat::Char);
        assert_eq!(result.formatted, "'\\x0a'");
    }

    #[test]
    fn test_format_signed_decimal_positive() {
        let result = convert_scalar(42, 1, ScalarFormat::SignedDecimal);
        assert_eq!(result.formatted, "42");
    }

    #[test]
    fn test_format_signed_decimal_negative() {
        let result = convert_scalar(0xFF, 1, ScalarFormat::SignedDecimal);
        assert_eq!(result.formatted, "-1");
    }

    #[test]
    fn test_format_signed_decimal_16bit_negative() {
        let result = convert_scalar(0xFFFF, 2, ScalarFormat::SignedDecimal);
        assert_eq!(result.formatted, "-1");
    }

    #[test]
    fn test_format_unsigned_decimal() {
        let result = convert_scalar(255, 1, ScalarFormat::UnsignedDecimal);
        assert_eq!(result.formatted, "255");
    }

    #[test]
    fn test_format_octal() {
        let result = convert_scalar(255, 1, ScalarFormat::Octal);
        assert_eq!(result.formatted, "377");
    }

    #[test]
    fn test_format_signed_hex() {
        let result = convert_scalar(0xFF, 1, ScalarFormat::SignedHex);
        assert_eq!(result.formatted, "-0x1");
    }

    #[test]
    fn test_format_unsigned_hex() {
        let result = convert_scalar(0xDEAD, 2, ScalarFormat::UnsignedHex);
        assert_eq!(result.formatted, "0xdead");
    }

    #[test]
    fn test_format_float() {
        let bits = 1.0f32.to_bits();
        let result = convert_scalar(bits as u64, 4, ScalarFormat::Float);
        assert_eq!(result.formatted, "1");
    }

    #[test]
    fn test_format_double() {
        let bits = 1.0f64.to_bits();
        let result = convert_scalar(bits, 8, ScalarFormat::Double);
        assert_eq!(result.formatted, "1");
    }

    #[test]
    fn test_convert_action_name() {
        let action = FormatConvertAction::new(ScalarFormat::Binary);
        assert_eq!(action.name, "Convert to Binary");
        assert_eq!(action.menu_path, "Convert/Binary");
    }

    #[test]
    fn test_convert_action_apply() {
        let action = FormatConvertAction::new(ScalarFormat::UnsignedHex);
        let result = action.convert(0xFF, 1);
        assert_eq!(result.formatted, "0xff");
        assert_eq!(result.format, ScalarFormat::UnsignedHex);
    }

    #[test]
    fn test_all_actions_count() {
        let actions = all_convert_actions();
        assert_eq!(actions.len(), 9);
    }

    #[test]
    fn test_format_name_display() {
        assert_eq!(format!("{}", ScalarFormat::Binary), "Binary");
        assert_eq!(format!("{}", ScalarFormat::Float), "Float");
    }

    #[test]
    fn test_format_short_name() {
        assert_eq!(ScalarFormat::UnsignedHex.short_name(), "UHex");
        assert_eq!(ScalarFormat::SignedDecimal.short_name(), "Dec");
    }

    #[test]
    fn test_converted_value_fields() {
        let result = convert_scalar(42, 4, ScalarFormat::UnsignedDecimal);
        assert_eq!(result.original_value, 42);
        assert_eq!(result.byte_width, 4);
        assert_eq!(result.format, ScalarFormat::UnsignedDecimal);
    }

    #[test]
    fn test_format_binary_zero() {
        let result = convert_scalar(0, 1, ScalarFormat::Binary);
        assert_eq!(result.formatted, "00000000");
    }

    #[test]
    fn test_format_signed_hex_positive() {
        let result = convert_scalar(42, 1, ScalarFormat::SignedHex);
        assert_eq!(result.formatted, "0x2a");
    }
}
