//! Built-in format models for the byte viewer.
//!
//! Provides ready-to-use [`FormatModel`] instances for the most common
//! byte display formats used in reverse engineering.

use super::{ByteFormat, FormatModel};

/// Standard hex format: 16 bytes per row, 1 byte per group, ASCII sidebar.
pub fn hex_model() -> FormatModel {
    FormatModel::hex()
}

/// Hex format with 2-byte groups: 16 bytes per row, 2 bytes per group.
pub fn hex_16bit_model() -> FormatModel {
    FormatModel {
        format: ByteFormat::Hex,
        bytes_per_row: 16,
        bytes_per_group: 2,
        show_ascii: true,
        show_address: true,
    }
}

/// Hex format with 4-byte groups: 16 bytes per row, 4 bytes per group.
pub fn hex_32bit_model() -> FormatModel {
    FormatModel {
        format: ByteFormat::Hex,
        bytes_per_row: 16,
        bytes_per_group: 4,
        show_ascii: true,
        show_address: true,
    }
}

/// Octal format: 16 bytes per row.
pub fn octal_model() -> FormatModel {
    FormatModel {
        format: ByteFormat::Octal,
        bytes_per_row: 16,
        bytes_per_group: 1,
        show_ascii: true,
        show_address: true,
    }
}

/// Decimal format: 16 bytes per row.
pub fn decimal_model() -> FormatModel {
    FormatModel {
        format: ByteFormat::Decimal,
        bytes_per_row: 16,
        bytes_per_group: 1,
        show_ascii: true,
        show_address: true,
    }
}

/// Binary format: 8 bytes per row (64 bits = one 8-byte word).
pub fn binary_model() -> FormatModel {
    FormatModel::binary()
}

/// Get all available format models.
pub fn all_models() -> Vec<(&'static str, FormatModel)> {
    vec![
        ("Hex (8-bit)", hex_model()),
        ("Hex (16-bit)", hex_16bit_model()),
        ("Hex (32-bit)", hex_32bit_model()),
        ("Octal", octal_model()),
        ("Decimal", decimal_model()),
        ("Binary", binary_model()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_model_output() {
        let model = hex_model();
        let data = [0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F];
        let row = model.format_row(0x1000, &data);
        assert!(row.contains("48"));
        assert!(row.contains("Hello Wo"));
    }

    #[test]
    fn test_hex_16bit_grouping() {
        let model = hex_16bit_model();
        let data = [0x48, 0x65, 0x6C, 0x6C];
        let row = model.format_row(0x1000, &data);
        // Should have "4865 6C6C" or similar grouping
        assert!(row.contains("48"));
        assert!(row.contains("65"));
    }

    #[test]
    fn test_binary_model() {
        let model = binary_model();
        let data = [0xFF, 0x00, 0xA5];
        let row = model.format_row(0, &data);
        assert!(row.contains("11111111"));
        assert!(row.contains("00000000"));
        assert!(row.contains("10100101"));
    }

    #[test]
    fn test_all_models_returns_nonempty() {
        let models = all_models();
        assert!(!models.is_empty());
        for (name, model) in &models {
            let data = [0x41, 0x42];
            let _row = model.format_row(0, &data);
            assert!(!name.is_empty());
        }
    }

    #[test]
    fn test_octal_model() {
        let model = octal_model();
        let data = [0xFF, 0x00];
        let row = model.format_row(0, &data);
        assert!(row.contains("377"));
        assert!(row.contains("000"));
    }

    #[test]
    fn test_decimal_model() {
        let model = decimal_model();
        let data = [0xFF, 0x0A];
        let row = model.format_row(0, &data);
        assert!(row.contains("255"));
        assert!(row.contains(" 10"));
    }
}
