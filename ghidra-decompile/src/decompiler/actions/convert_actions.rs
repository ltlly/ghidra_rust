//! Constant format conversion actions for the decompiler.
//!
//! Ports Ghidra's `ConvertHexAction`, `ConvertDecAction`, `ConvertOctAction`,
//! `ConvertCharAction`, `ConvertFloatAction`, `ConvertDoubleAction`,
//! `ConvertBinaryAction`, and `ConvertConstantAction` from the
//! `ghidra.app.plugin.core.decompile.actions` package.
//!
//! Each action converts a selected constant in the decompiler output to a
//! different numeric representation. In Java these are separate subclasses
//! of `ConvertConstantAction`; in Rust we use a single struct parameterised
//! by [`ConstantFormat`].

use std::fmt;

/// The numeric format to convert a constant into.
///
/// Mirrors the Java `EquateSymbol.FORMAT_*` constants and each
/// `ConvertXxxAction` subclass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstantFormat {
    /// Hexadecimal (`0x...`).
    Hex,
    /// Signed or unsigned decimal.
    Decimal,
    /// Octal (`0...` / `...o` suffix).
    Octal,
    /// Binary (`0b...`).
    Binary,
    /// Character literal (`'A'`, `'\n'`, `'\x41'`).
    Char,
    /// 32-bit IEEE 754 floating-point.
    Float,
    /// 64-bit IEEE 754 floating-point (double).
    Double,
}

impl ConstantFormat {
    /// Human-readable display name (menu label).
    pub fn display_name(&self) -> &str {
        match self {
            Self::Hex => "Hexadecimal",
            Self::Decimal => "Decimal",
            Self::Octal => "Octal",
            Self::Binary => "Binary",
            Self::Char => "Char",
            Self::Float => "Float",
            Self::Double => "Double",
        }
    }

    /// The Ghidra action identifier string.
    pub fn action_name(&self) -> &str {
        match self {
            Self::Hex => "ConvertHexAction",
            Self::Decimal => "ConvertDecAction",
            Self::Octal => "ConvertOctAction",
            Self::Binary => "ConvertBinaryAction",
            Self::Char => "ConvertCharAction",
            Self::Float => "ConvertFloatAction",
            Self::Double => "ConvertDoubleAction",
        }
    }

    /// Menu prefix shown in the popup (e.g. `"Hexadecimal: "`).
    pub fn menu_prefix(&self) -> &str {
        match self {
            Self::Hex => "Hexadecimal: ",
            Self::Decimal => "Decimal: ",
            Self::Octal => "Octal: ",
            Self::Binary => "Binary: ",
            Self::Char => "Char: ",
            Self::Float => "Float: ",
            Self::Double => "Double: ",
        }
    }

    /// Menu group used in the popup menu hierarchy.
    pub fn menu_group(&self) -> &str {
        "Decompile"
    }

    /// Menu path for the popup.
    pub fn menu_path(&self) -> &[&str] {
        match self {
            Self::Hex => &["Hexadecimal"],
            Self::Decimal => &["Decimal"],
            Self::Octal => &["Octal"],
            Self::Binary => &["Binary"],
            Self::Char => &["Char"],
            Self::Float => &["Float"],
            Self::Double => &["Double"],
        }
    }

    /// Format a raw 64-bit value according to this format.
    ///
    /// `size` is the width in bytes of the original constant (1, 2, 4, or 8).
    pub fn format_value(&self, value: u64, size: usize) -> String {
        match self {
            Self::Hex => {
                let width = size * 2;
                format!("0x{:0width$x}", value, width = width)
            }
            Self::Decimal => format!("{}", value as i64),
            Self::Octal => format!("0o{:o}", value),
            Self::Binary => format!("0b{:b}", value),
            Self::Char => format_char(value, size),
            Self::Float => format_float(value, 4),
            Self::Double => format_float(value, 8),
        }
    }

    /// Generate the equate name string for this format.
    ///
    /// Equate names are used when assigning a named constant to a value
    /// in the decompiler output.
    pub fn equate_name(&self, value: u64) -> String {
        match self {
            Self::Hex => format!("0x{:X}", value),
            Self::Decimal => format!("{}", value as i64),
            Self::Octal => format!("{}o", value),
            Self::Binary => format!("0b{:b}", value),
            Self::Char => {
                if value >= 0x20 && value <= 0x7E {
                    format!("'{}'", value as u8 as char)
                } else {
                    format!("'\\x{:02x}'", value as u8)
                }
            }
            Self::Float | Self::Double => self.format_value(value, 8),
        }
    }
}

impl fmt::Display for ConstantFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

/// A concrete conversion action to be applied to a selected constant.
///
/// This is the Rust equivalent of Ghidra's `ConvertConstantAction` and its
/// subclasses (`ConvertHexAction`, `ConvertDecAction`, etc.).
#[derive(Debug, Clone)]
pub struct ConvertConstantAction {
    /// The target format.
    pub format: ConstantFormat,
    /// The address of the constant in the program.
    pub address: u64,
    /// The original integer value of the constant.
    pub original_value: u64,
    /// The byte size of the original constant (1, 2, 4, or 8).
    pub size: usize,
}

impl ConvertConstantAction {
    /// Create a new conversion action.
    pub fn new(format: ConstantFormat, address: u64, original_value: u64, size: usize) -> Self {
        Self {
            format,
            address,
            original_value,
            size,
        }
    }

    /// Convenience constructor for hex conversion.
    pub fn hex(address: u64, value: u64, size: usize) -> Self {
        Self::new(ConstantFormat::Hex, address, value, size)
    }

    /// Convenience constructor for decimal conversion.
    pub fn decimal(address: u64, value: u64, size: usize) -> Self {
        Self::new(ConstantFormat::Decimal, address, value, size)
    }

    /// Convenience constructor for octal conversion.
    pub fn octal(address: u64, value: u64, size: usize) -> Self {
        Self::new(ConstantFormat::Octal, address, value, size)
    }

    /// Convenience constructor for binary conversion.
    pub fn binary(address: u64, value: u64, size: usize) -> Self {
        Self::new(ConstantFormat::Binary, address, value, size)
    }

    /// Convenience constructor for char conversion.
    pub fn char(address: u64, value: u64, size: usize) -> Self {
        Self::new(ConstantFormat::Char, address, value, size)
    }

    /// Convenience constructor for float conversion.
    pub fn float(address: u64, value: u64, size: usize) -> Self {
        Self::new(ConstantFormat::Float, address, value, size)
    }

    /// Convenience constructor for double conversion.
    pub fn double(address: u64, value: u64, size: usize) -> Self {
        Self::new(ConstantFormat::Double, address, value, size)
    }

    /// Get the action name.
    pub fn action_name(&self) -> &str {
        self.format.action_name()
    }

    /// Get the menu prefix.
    pub fn menu_prefix(&self) -> &str {
        self.format.menu_prefix()
    }

    /// Format the original value in the target format.
    pub fn formatted_value(&self) -> String {
        self.format.format_value(self.original_value, self.size)
    }

    /// Generate the equate name for this constant.
    pub fn equate_name(&self) -> String {
        self.format.equate_name(self.original_value)
    }
}

/// Format a value as a character literal.
fn format_char(value: u64, size: usize) -> String {
    if size > 1 {
        // Wide character
        return format!("L'{}'", escape_char(value));
    }
    let ch = value as u8;
    match ch {
        0 => "'\\0'".to_string(),
        7 => "'\\a'".to_string(),
        8 => "'\\b'".to_string(),
        9 => "'\\t'".to_string(),
        10 => "'\\n'".to_string(),
        11 => "'\\v'".to_string(),
        12 => "'\\f'".to_string(),
        13 => "'\\r'".to_string(),
        b'\\' => "'\\\\'".to_string(),
        b'\'' => "'\\''".to_string(),
        b'"' => "'\\\"'".to_string(),
        0x20..=0x7E => format!("'{}'", ch as char),
        _ => format!("'\\x{:02x}'", ch),
    }
}

/// Escape a character value for display.
fn escape_char(value: u64) -> String {
    let ch = value as u8;
    match ch {
        0 => "\\0".to_string(),
        7 => "\\a".to_string(),
        8 => "\\b".to_string(),
        9 => "\\t".to_string(),
        10 => "\\n".to_string(),
        11 => "\\v".to_string(),
        12 => "\\f".to_string(),
        13 => "\\r".to_string(),
        b'\\' => "\\\\".to_string(),
        b'\'' => "\\'".to_string(),
        0x20..=0x7E => (ch as char).to_string(),
        _ => format!("\\x{:02x}", ch),
    }
}

/// Format an integer's bit pattern as a floating-point number.
fn format_float(value: u64, size: usize) -> String {
    match size {
        4 => {
            let f = f32::from_bits(value as u32);
            if f.is_nan() {
                "NaN".to_string()
            } else if f.is_infinite() {
                if f.is_sign_negative() {
                    "-inf".to_string()
                } else {
                    "inf".to_string()
                }
            } else {
                format!("{}", f)
            }
        }
        8 => {
            let d = f64::from_bits(value);
            if d.is_nan() {
                "NaN".to_string()
            } else if d.is_infinite() {
                if d.is_sign_negative() {
                    "-inf".to_string()
                } else {
                    "inf".to_string()
                }
            } else {
                format!("{}", d)
            }
        }
        _ => format!("0x{:X}", value),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ---- ConstantFormat tests ----

    #[test]
    fn format_hex() {
        assert_eq!(ConstantFormat::Hex.format_value(255, 4), "0x000000ff");
        assert_eq!(ConstantFormat::Hex.format_value(0xAB, 1), "0xab");
        assert_eq!(
            ConstantFormat::Hex.format_value(0xDEADBEEF, 4),
            "0xdeadbeef"
        );
    }

    #[test]
    fn format_hex_width() {
        // 1 byte -> 2 hex chars, 2 bytes -> 4, 4 bytes -> 8, 8 bytes -> 16
        assert_eq!(ConstantFormat::Hex.format_value(0xFF, 1), "0xff");
        assert_eq!(ConstantFormat::Hex.format_value(0xFF, 2), "0x00ff");
        assert_eq!(ConstantFormat::Hex.format_value(0xFF, 4), "0x000000ff");
        assert_eq!(
            ConstantFormat::Hex.format_value(0xFF, 8),
            "0x00000000000000ff"
        );
    }

    #[test]
    fn format_decimal() {
        assert_eq!(ConstantFormat::Decimal.format_value(42, 4), "42");
        assert_eq!(ConstantFormat::Decimal.format_value(0, 1), "0");
    }

    #[test]
    fn format_octal() {
        assert_eq!(ConstantFormat::Octal.format_value(8, 1), "0o10");
        assert_eq!(ConstantFormat::Octal.format_value(64, 1), "0o100");
    }

    #[test]
    fn format_binary() {
        assert_eq!(ConstantFormat::Binary.format_value(5, 1), "0b101");
        assert_eq!(ConstantFormat::Binary.format_value(0xFF, 1), "0b11111111");
    }

    #[test]
    fn format_char_printable() {
        assert_eq!(ConstantFormat::Char.format_value(65, 1), "'A'");
        assert_eq!(ConstantFormat::Char.format_value(32, 1), "' '");
    }

    #[test]
    fn format_char_escape_sequences() {
        assert_eq!(ConstantFormat::Char.format_value(0, 1), "'\\0'");
        assert_eq!(ConstantFormat::Char.format_value(10, 1), "'\\n'");
        assert_eq!(ConstantFormat::Char.format_value(9, 1), "'\\t'");
        assert_eq!(ConstantFormat::Char.format_value(13, 1), "'\\r'");
        assert_eq!(ConstantFormat::Char.format_value(92, 1), "'\\\\'");
        assert_eq!(ConstantFormat::Char.format_value(39, 1), "'\\''");
    }

    #[test]
    fn format_char_non_printable() {
        // Control character
        assert_eq!(ConstantFormat::Char.format_value(1, 1), "'\\x01'");
        // High byte
        assert_eq!(ConstantFormat::Char.format_value(0x7F, 1), "'\\x7f'");
    }

    #[test]
    fn format_char_wide() {
        assert_eq!(ConstantFormat::Char.format_value(65, 2), "L'A'");
    }

    #[test]
    fn format_float_basic() {
        let val = 1.0f32.to_bits() as u64;
        let result = ConstantFormat::Float.format_value(val, 4);
        assert_eq!(result, "1");
    }

    #[test]
    fn format_float_zero() {
        let val = 0.0f32.to_bits() as u64;
        let result = ConstantFormat::Float.format_value(val, 4);
        assert_eq!(result, "0");
    }

    #[test]
    fn format_float_nan() {
        let val = f32::NAN.to_bits() as u64;
        let result = ConstantFormat::Float.format_value(val, 4);
        assert_eq!(result, "NaN");
    }

    #[test]
    fn format_float_inf() {
        let val = f32::INFINITY.to_bits() as u64;
        let result = ConstantFormat::Float.format_value(val, 4);
        assert_eq!(result, "inf");
    }

    #[test]
    fn format_float_neg_inf() {
        let val = f32::NEG_INFINITY.to_bits() as u64;
        let result = ConstantFormat::Float.format_value(val, 4);
        assert_eq!(result, "-inf");
    }

    #[test]
    fn format_double_basic() {
        let val = 1.0f64.to_bits();
        let result = ConstantFormat::Double.format_value(val, 8);
        assert_eq!(result, "1");
    }

    #[test]
    fn format_double_nan() {
        let val = f64::NAN.to_bits();
        let result = ConstantFormat::Double.format_value(val, 8);
        assert_eq!(result, "NaN");
    }

    // ---- ConstantFormat metadata tests ----

    #[test]
    fn display_names() {
        assert_eq!(ConstantFormat::Hex.display_name(), "Hexadecimal");
        assert_eq!(ConstantFormat::Decimal.display_name(), "Decimal");
        assert_eq!(ConstantFormat::Octal.display_name(), "Octal");
        assert_eq!(ConstantFormat::Binary.display_name(), "Binary");
        assert_eq!(ConstantFormat::Char.display_name(), "Char");
        assert_eq!(ConstantFormat::Float.display_name(), "Float");
        assert_eq!(ConstantFormat::Double.display_name(), "Double");
    }

    #[test]
    fn action_names() {
        assert_eq!(ConstantFormat::Hex.action_name(), "ConvertHexAction");
        assert_eq!(ConstantFormat::Decimal.action_name(), "ConvertDecAction");
        assert_eq!(ConstantFormat::Octal.action_name(), "ConvertOctAction");
        assert_eq!(ConstantFormat::Binary.action_name(), "ConvertBinaryAction");
        assert_eq!(ConstantFormat::Char.action_name(), "ConvertCharAction");
        assert_eq!(ConstantFormat::Float.action_name(), "ConvertFloatAction");
        assert_eq!(ConstantFormat::Double.action_name(), "ConvertDoubleAction");
    }

    #[test]
    fn menu_prefixes() {
        assert_eq!(ConstantFormat::Hex.menu_prefix(), "Hexadecimal: ");
        assert_eq!(ConstantFormat::Decimal.menu_prefix(), "Decimal: ");
        assert_eq!(ConstantFormat::Octal.menu_prefix(), "Octal: ");
        assert_eq!(ConstantFormat::Binary.menu_prefix(), "Binary: ");
        assert_eq!(ConstantFormat::Char.menu_prefix(), "Char: ");
        assert_eq!(ConstantFormat::Float.menu_prefix(), "Float: ");
        assert_eq!(ConstantFormat::Double.menu_prefix(), "Double: ");
    }

    #[test]
    fn menu_group_and_path() {
        assert_eq!(ConstantFormat::Hex.menu_group(), "Decompile");
        assert_eq!(ConstantFormat::Hex.menu_path(), &["Hexadecimal"]);
    }

    // ---- Equate name tests ----

    #[test]
    fn equate_name_hex() {
        assert_eq!(ConstantFormat::Hex.equate_name(0xFF), "0xFF");
        assert_eq!(ConstantFormat::Hex.equate_name(0x10), "0x10");
    }

    #[test]
    fn equate_name_decimal() {
        assert_eq!(ConstantFormat::Decimal.equate_name(42), "42");
    }

    #[test]
    fn equate_name_octal() {
        assert_eq!(ConstantFormat::Octal.equate_name(8), "8o");
    }

    #[test]
    fn equate_name_binary() {
        assert_eq!(ConstantFormat::Binary.equate_name(5), "0b101");
    }

    #[test]
    fn equate_name_char_printable() {
        assert_eq!(ConstantFormat::Char.equate_name(65), "'A'");
    }

    #[test]
    fn equate_name_char_non_printable() {
        assert_eq!(ConstantFormat::Char.equate_name(0), "'\\x00'");
    }

    // ---- ConvertConstantAction tests ----

    #[test]
    fn convert_hex_action() {
        let action = ConvertConstantAction::hex(0x1000, 0xFF, 1);
        assert_eq!(action.action_name(), "ConvertHexAction");
        assert_eq!(action.formatted_value(), "0xff");
        assert_eq!(action.equate_name(), "0xFF");
    }

    #[test]
    fn convert_dec_action() {
        let action = ConvertConstantAction::decimal(0x1000, 42, 4);
        assert_eq!(action.action_name(), "ConvertDecAction");
        assert_eq!(action.formatted_value(), "42");
    }

    #[test]
    fn convert_oct_action() {
        let action = ConvertConstantAction::octal(0x1000, 64, 1);
        assert_eq!(action.action_name(), "ConvertOctAction");
        assert_eq!(action.formatted_value(), "0o100");
    }

    #[test]
    fn convert_binary_action() {
        let action = ConvertConstantAction::binary(0x1000, 5, 1);
        assert_eq!(action.action_name(), "ConvertBinaryAction");
        assert_eq!(action.formatted_value(), "0b101");
    }

    #[test]
    fn convert_char_action() {
        let action = ConvertConstantAction::char(0x1000, 65, 1);
        assert_eq!(action.action_name(), "ConvertCharAction");
        assert_eq!(action.formatted_value(), "'A'");
    }

    #[test]
    fn convert_float_action() {
        let val = 3.14f32.to_bits() as u64;
        let action = ConvertConstantAction::float(0x1000, val, 4);
        assert_eq!(action.action_name(), "ConvertFloatAction");
        let formatted = action.formatted_value();
        // Should be a decimal representation
        assert!(formatted.contains('.'));
    }

    #[test]
    fn convert_double_action() {
        let val = 2.718281828f64.to_bits();
        let action = ConvertConstantAction::double(0x1000, val, 8);
        assert_eq!(action.action_name(), "ConvertDoubleAction");
        let formatted = action.formatted_value();
        assert!(formatted.contains('.'));
    }

    #[test]
    fn convert_action_new() {
        let action = ConvertConstantAction::new(ConstantFormat::Hex, 0x4000, 0xABCD, 2);
        assert_eq!(action.address, 0x4000);
        assert_eq!(action.original_value, 0xABCD);
        assert_eq!(action.size, 2);
        assert_eq!(action.formatted_value(), "0xabcd");
    }

    #[test]
    fn convert_action_menu_prefix() {
        let action = ConvertConstantAction::hex(0, 0, 1);
        assert_eq!(action.menu_prefix(), "Hexadecimal: ");
    }

    // ---- Display trait ----

    #[test]
    fn constant_format_display() {
        assert_eq!(format!("{}", ConstantFormat::Hex), "Hexadecimal");
        assert_eq!(format!("{}", ConstantFormat::Double), "Double");
    }
}
