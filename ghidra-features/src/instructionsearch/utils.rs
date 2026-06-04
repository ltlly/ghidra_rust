//! Instruction search utility functions.
//!
//! Ported from `ghidra.app.plugin.core.instructionsearch.util.InstructionSearchUtils`.

use super::model::InstructionMetadata;
use ghidra_core::Address;

// ============================================================================
// InputMode -- format of instruction search input
// ============================================================================

/// The input mode for instruction search strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    /// Input is in binary (base-2) format.
    Binary,
    /// Input is in hexadecimal (base-16) format.
    Hex,
}

/// Helper functions for instruction search.
pub struct InstructionSearchUtils;

impl InstructionSearchUtils {
    /// Convert a byte to an 8-character binary string.
    pub fn to_binary_string(byteval: u8) -> String {
        format!("{:08b}", byteval)
    }

    /// Check if the input string is a valid binary string (only `0` and `1`).
    pub fn is_binary(input: &str) -> bool {
        let stripped: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        !stripped.is_empty() && stripped.chars().all(|c| c == '0' || c == '1')
    }

    /// Convert a hex string to a binary string (padded to full bytes).
    ///
    /// Spaces in the input are ignored.
    pub fn to_binary(hex: &str) -> Result<String, String> {
        let stripped: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
        if stripped.is_empty() {
            return Ok(String::new());
        }
        if stripped.len() % 2 != 0 {
            return Err("Hex string must have even number of characters".into());
        }
        let mut result = String::with_capacity(stripped.len() * 4);
        for chunk in stripped.as_bytes().chunks(2) {
            let hex_str = std::str::from_utf8(chunk).map_err(|_| "Invalid hex")?;
            let val = u8::from_str_radix(hex_str, 16)
                .map_err(|e| format!("Invalid hex '{}': {}", hex_str, e))?;
            result.push_str(&format!("{:08b}", val));
        }
        Ok(result)
    }

    /// Check if the input is a valid hex string.
    pub fn is_hex(input: &str) -> bool {
        let stripped: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        !stripped.is_empty()
            && stripped
                .chars()
                .all(|c| c.is_ascii_hexdigit())
    }

    /// Check if the input represents a full hex byte (even number of hex chars).
    pub fn is_full_hex_byte(input: &str) -> bool {
        let stripped: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        stripped.len() % 2 == 0 && !stripped.is_empty()
    }

    /// Check if the input represents a full binary byte (multiple of 8 bits).
    pub fn is_full_binary_byte(input: &str) -> bool {
        let stripped: String = input.chars().filter(|c| !c.is_whitespace()).collect();
        stripped.len() % 8 == 0 && !stripped.is_empty()
    }

    /// Return `true` if any bit in the given byte array is set.
    pub fn contains_on_bit(bytearray: &[u8]) -> bool {
        bytearray.iter().any(|&b| b != 0)
    }

    /// Convert a byte array to a binary string.
    pub fn to_binary_str(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:08b}", b)).collect()
    }

    /// Format a search string by replacing masked-out bits with `.`.
    ///
    /// `search_str` and `mask` must have the same length and contain only `'0'`/`'1'`.
    pub fn format_search_string(search_str: &str, mask: &str) -> Result<String, String> {
        if search_str.len() != mask.len() {
            return Err("Mask and search string not the same length.".into());
        }

        let mut result = String::with_capacity(search_str.len());
        for (val_ch, mask_ch) in search_str.chars().zip(mask.chars()) {
            match (val_ch, mask_ch) {
                ('1', _) => result.push('1'),
                ('0', '1') => result.push('0'),
                ('0', '0') => result.push('.'),
                _ => result.push('0'),
            }
        }
        Ok(result)
    }

    /// Perform a bitwise OR on two byte arrays.
    ///
    /// Returns `None` if the arrays have different lengths.
    pub fn byte_array_or(arr1: &[u8], arr2: &[u8]) -> Option<Vec<u8>> {
        if arr1.len() != arr2.len() {
            return None;
        }
        Some(arr1.iter().zip(arr2.iter()).map(|(a, b)| a | b).collect())
    }

    /// Perform a bitwise AND on two byte arrays.
    pub fn byte_array_and(mask: &[u8], bytes: &[u8]) -> Result<Vec<u8>, String> {
        if mask.len() != bytes.len() {
            return Err("Inappropriate mask length".into());
        }
        Ok(mask.iter().zip(bytes.iter()).map(|(m, b)| m & b).collect())
    }

    /// Convert a binary string to hex.
    ///
    /// Masked characters (`'.'`) are preserved in brackets.
    pub fn to_hex(binary_str: &str, zero_fill: bool) -> String {
        let stripped: String = binary_str.chars().filter(|c| !c.is_whitespace()).collect();
        let spaced = Self::add_space_on_byte_boundary(&stripped, InputMode::Binary);

        let mut result = String::new();
        for binary in spaced.split_whitespace() {
            if binary.contains('.') {
                result.push_str(&format!("[{}] ", binary));
            } else {
                let decimal = u8::from_str_radix(binary, 2).unwrap_or(0);
                let hex = if zero_fill {
                    format!("{:02x}", decimal)
                } else {
                    format!("{:x}", decimal)
                };
                result.push_str(&hex);
                result.push(' ');
            }
        }
        result
    }

    /// Convert a binary string to hex at the nibble level.
    ///
    /// If a nibble has any masked bit, the entire nibble becomes a wildcard.
    /// Used for YARA-style patterns.
    pub fn to_hex_nibbles_only(instr: &str) -> String {
        let stripped: String = instr.chars().filter(|c| !c.is_whitespace()).collect();
        let spaced = Self::add_space_on_byte_boundary(&stripped, InputMode::Binary);

        let mut result = String::new();
        for binary in spaced.split_whitespace() {
            if binary.contains('.') {
                let nibble1 = &binary[0..4];
                let nibble2 = &binary[4..8];
                let n1 = if nibble1.contains('.') {
                    ".".to_string()
                } else {
                    let d = u8::from_str_radix(nibble1, 2).unwrap_or(0);
                    format!("{:x}", d)
                };
                let n2 = if nibble2.contains('.') {
                    ".".to_string()
                } else {
                    let d = u8::from_str_radix(nibble2, 2).unwrap_or(0);
                    format!("{:x}", d)
                };
                result.push_str(&format!("{}{} ", n1, n2));
            } else {
                let decimal = u8::from_str_radix(binary, 2).unwrap_or(0);
                result.push_str(&format!("{:02x} ", decimal));
            }
        }
        result
    }

    /// Add spaces at byte boundaries.
    pub fn add_space_on_byte_boundary(str: &str, mode: InputMode) -> String {
        let stripped: String = str.chars().filter(|c| !c.is_whitespace()).collect();
        let byte_length = match mode {
            InputMode::Hex => 2,
            InputMode::Binary => 8,
        };

        let mut result = String::with_capacity(stripped.len() + stripped.len() / byte_length);
        for (i, ch) in stripped.chars().enumerate() {
            result.push(ch);
            if (i + 1) % byte_length == 0 && i + 1 < stripped.len() {
                result.push(' ');
            }
        }
        result
    }

    /// Extract addresses from a list of instruction metadata results.
    pub fn to_address_list(search_results: &[InstructionMetadata]) -> Vec<Address> {
        search_results.iter().map(|m| m.addr).collect()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_binary_string() {
        assert_eq!(InstructionSearchUtils::to_binary_string(0xFF), "11111111");
        assert_eq!(InstructionSearchUtils::to_binary_string(0x00), "00000000");
        assert_eq!(InstructionSearchUtils::to_binary_string(0x48), "01001000");
    }

    #[test]
    fn test_is_binary() {
        assert!(InstructionSearchUtils::is_binary("01001000"));
        assert!(InstructionSearchUtils::is_binary("0100 1000"));
        assert!(!InstructionSearchUtils::is_binary("01002000"));
        assert!(!InstructionSearchUtils::is_binary(""));
    }

    #[test]
    fn test_is_hex() {
        assert!(InstructionSearchUtils::is_hex("4889"));
        assert!(InstructionSearchUtils::is_hex("48 89"));
        assert!(InstructionSearchUtils::is_hex("AB CD EF"));
        assert!(!InstructionSearchUtils::is_hex("GHIJ"));
        assert!(!InstructionSearchUtils::is_hex(""));
    }

    #[test]
    fn test_to_binary_from_hex() {
        let result = InstructionSearchUtils::to_binary("48").unwrap();
        assert_eq!(result, "01001000");
    }

    #[test]
    fn test_contains_on_bit() {
        assert!(InstructionSearchUtils::contains_on_bit(&[0x00, 0x01, 0x00]));
        assert!(!InstructionSearchUtils::contains_on_bit(&[0x00, 0x00, 0x00]));
    }

    #[test]
    fn test_byte_array_or() {
        let result =
            InstructionSearchUtils::byte_array_or(&[0xF0, 0x0F], &[0x0F, 0xF0]).unwrap();
        assert_eq!(result, vec![0xFF, 0xFF]);
    }

    #[test]
    fn test_byte_array_and() {
        let result =
            InstructionSearchUtils::byte_array_and(&[0xFF, 0x0F], &[0xF0, 0xFF]).unwrap();
        assert_eq!(result, vec![0xF0, 0x0F]);
    }

    #[test]
    fn test_byte_array_or_length_mismatch() {
        assert!(InstructionSearchUtils::byte_array_or(&[0xFF], &[0x0F, 0xF0]).is_none());
    }

    #[test]
    fn test_format_search_string() {
        let result =
            InstructionSearchUtils::format_search_string("10100000", "11110000").unwrap();
        assert_eq!(result, "1010....");
    }

    #[test]
    fn test_format_search_string_mismatched_lengths() {
        assert!(InstructionSearchUtils::format_search_string("1010", "11").is_err());
    }

    #[test]
    fn test_add_space_on_byte_boundary_binary() {
        let result =
            InstructionSearchUtils::add_space_on_byte_boundary("0100100001001000", InputMode::Binary);
        assert_eq!(result, "01001000 01001000");
    }

    #[test]
    fn test_add_space_on_byte_boundary_hex() {
        let result =
            InstructionSearchUtils::add_space_on_byte_boundary("4889", InputMode::Hex);
        assert_eq!(result, "48 89");
    }

    #[test]
    fn test_is_full_hex_byte() {
        assert!(InstructionSearchUtils::is_full_hex_byte("48"));
        assert!(InstructionSearchUtils::is_full_hex_byte("4889"));
        assert!(!InstructionSearchUtils::is_full_hex_byte("4"));
    }

    #[test]
    fn test_is_full_binary_byte() {
        assert!(InstructionSearchUtils::is_full_binary_byte("01001000"));
        assert!(!InstructionSearchUtils::is_full_binary_byte("0100100"));
    }

    #[test]
    fn test_to_hex_basic() {
        let hex = InstructionSearchUtils::to_hex("01001000", true);
        assert_eq!(hex.trim(), "48");
    }

    #[test]
    fn test_to_hex_with_masking() {
        let hex = InstructionSearchUtils::to_hex("0100100.", false);
        assert!(hex.contains("[0100100.]"));
    }

    #[test]
    fn test_to_hex_nibbles_only() {
        let result = InstructionSearchUtils::to_hex_nibbles_only("01001000");
        assert_eq!(result.trim(), "48");
    }

    #[test]
    fn test_to_binary_str() {
        assert_eq!(
            InstructionSearchUtils::to_binary_str(&[0x48, 0x89]),
            "0100100010001001"
        );
    }
}
