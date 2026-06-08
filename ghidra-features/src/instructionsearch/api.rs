//! Instruction Search API.
//!
//! Ported from `ghidra.app.plugin.core.instructionsearch.InstructionSearchApi`.
//!
//! Provides headless (non-GUI) instruction searching. Users specify a
//! program and an address range; the API loads instructions, builds
//! combined mask/value arrays, and searches for byte-pattern matches.
//!
//! # Limitations
//!
//! 1. Searches may only be performed on a single program.
//! 2. Only a single address range may be searched at a time.

use super::model::{MaskContainer, MaskSettings};
use super::utils::InstructionSearchUtils;
use ghidra_core::Address;

// ============================================================================
// InstructionSearchApi -- high-level search API
// ============================================================================

/// API for performing instruction pattern searches.
///
/// Can be used to search for byte patterns in a program without GUI.
pub struct InstructionSearchApi {
    /// Mask settings controlling which operands to wildcard.
    pub mask_settings: MaskSettings,
}

impl InstructionSearchApi {
    /// Create a new search API with default mask settings.
    pub fn new() -> Self {
        Self {
            mask_settings: MaskSettings::default(),
        }
    }

    /// Create a new search API with the given mask settings.
    pub fn with_settings(mask_settings: MaskSettings) -> Self {
        Self { mask_settings }
    }

    /// Search for a byte pattern (mask + value) in a memory buffer.
    ///
    /// Returns the offsets (relative to `buffer_start`) of all matches.
    ///
    /// # Arguments
    ///
    /// * `mask_container` -- the mask/value pattern to search for.
    /// * `memory` -- the memory buffer to search in.
    /// * `buffer_start` -- the base address of the memory buffer.
    /// * `forward` -- if `true`, search forward; otherwise backward.
    pub fn search_bytes(
        &self,
        mask_container: &MaskContainer,
        memory: &[u8],
        buffer_start: u64,
        forward: bool,
    ) -> Vec<Address> {
        let mask = &mask_container.mask;
        let value = &mask_container.value;

        if !InstructionSearchUtils::contains_on_bit(mask) {
            return Vec::new();
        }

        let pattern_len = mask.len();
        if pattern_len == 0 || memory.len() < pattern_len {
            return Vec::new();
        }

        let mut results = Vec::new();

        if forward {
            let mut offset = 0usize;
            while offset + pattern_len <= memory.len() {
                if self.matches_at(memory, offset, value, mask) {
                    results.push(Address::new(buffer_start + offset as u64));
                }
                offset += 1;
            }
        } else {
            let mut offset = memory.len().saturating_sub(pattern_len);
            loop {
                if self.matches_at(memory, offset, value, mask) {
                    results.push(Address::new(buffer_start + offset as u64));
                }
                if offset == 0 {
                    break;
                }
                offset -= 1;
            }
        }

        results
    }

    /// Search for a byte pattern represented as a hex string.
    ///
    /// Hex characters are converted to a mask/value pair where:
    /// - Specified hex nibbles have mask bits set to 1.
    /// - The `.` character represents a wildcard nibble (mask = 0).
    pub fn search_hex_pattern(
        &self,
        hex_pattern: &str,
        memory: &[u8],
        buffer_start: u64,
        forward: bool,
    ) -> Vec<Address> {
        match Self::parse_hex_pattern(hex_pattern) {
            Some(mc) => self.search_bytes(&mc, memory, buffer_start, forward),
            None => Vec::new(),
        }
    }

    /// Parse a hex pattern string into a `MaskContainer`.
    ///
    /// Supports `.` as a wildcard nibble and spaces as separators.
    /// Example: `"48 89 .."` produces mask `[0xFF, 0xFF, 0x00]` and
    /// value `[0x48, 0x89, 0x00]`.
    pub fn parse_hex_pattern(hex_pattern: &str) -> Option<MaskContainer> {
        let stripped: String = hex_pattern
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();

        if stripped.is_empty() || stripped.len() % 2 != 0 {
            return None;
        }

        let mut mask = Vec::with_capacity(stripped.len() / 2);
        let mut value = Vec::with_capacity(stripped.len() / 2);

        let bytes: Vec<char> = stripped.chars().collect();
        for pair in bytes.chunks(2) {
            let hi = pair[0];
            let lo = pair[1];

            let (mask_byte, value_byte) = match (hi, lo) {
                ('.', '.') => (0x00u8, 0x00u8),
                ('.', lo_ch) => {
                    if let Some(d) = lo_ch.to_digit(16) {
                        (0x0F, d as u8)
                    } else {
                        return None;
                    }
                }
                (hi_ch, '.') => {
                    if let Some(d) = hi_ch.to_digit(16) {
                        (0xF0, (d as u8) << 4)
                    } else {
                        return None;
                    }
                }
                (hi_ch, lo_ch) => {
                    let hi_val = hi_ch.to_digit(16)? as u8;
                    let lo_val = lo_ch.to_digit(16)? as u8;
                    (0xFF, (hi_val << 4) | lo_val)
                }
            };
            mask.push(mask_byte);
            value.push(value_byte);
        }

        MaskContainer::new(mask, value).ok()
    }

    /// Build a YARA-style hex rule from a mask container.
    ///
    /// Masked bytes become `[..]` in the YARA hex string.
    pub fn to_yara_hex_string(mask_container: &MaskContainer) -> String {
        let mut result = String::new();
        for i in 0..mask_container.mask.len() {
            if i > 0 {
                result.push(' ');
            }
            if mask_container.mask[i] == 0x00 {
                result.push_str("[..]");
            } else if mask_container.mask[i] == 0xFF {
                result.push_str(&format!("{:02X}", mask_container.value[i]));
            } else {
                // Partial mask -- use nibble-level wildcards
                let hi_mask = mask_container.mask[i] & 0xF0;
                let lo_mask = mask_container.mask[i] & 0x0F;
                let hi = if hi_mask != 0 {
                    format!("{:X}", (mask_container.value[i] >> 4) & 0x0F)
                } else {
                    "?".to_string()
                };
                let lo = if lo_mask != 0 {
                    format!("{:X}", mask_container.value[i] & 0x0F)
                } else {
                    "?".to_string()
                };
                result.push_str(&format!("{}{}", hi, lo));
            }
        }
        result
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn matches_at(&self, memory: &[u8], offset: usize, value: &[u8], mask: &[u8]) -> bool {
        for i in 0..mask.len() {
            if (memory[offset + i] & mask[i]) != (value[i] & mask[i]) {
                return false;
            }
        }
        true
    }
}

impl Default for InstructionSearchApi {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_bytes_forward() {
        let api = InstructionSearchApi::new();
        let mc = MaskContainer::new(vec![0xFF, 0xFF], vec![0x48, 0x89]).unwrap();
        let memory = vec![0x00, 0x00, 0x48, 0x89, 0x00, 0x48, 0x89, 0xFF];
        let results = api.search_bytes(&mc, &memory, 0x1000, true);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], Address::new(0x1002));
        assert_eq!(results[1], Address::new(0x1005));
    }

    #[test]
    fn test_search_bytes_backward() {
        let api = InstructionSearchApi::new();
        let mc = MaskContainer::new(vec![0xFF, 0xFF], vec![0x48, 0x89]).unwrap();
        let memory = vec![0x48, 0x89, 0x00, 0x48, 0x89, 0x00];
        let results = api.search_bytes(&mc, &memory, 0x0, false);
        assert_eq!(results.len(), 2);
        // Backward order: last found first
        assert_eq!(results[0], Address::new(0x3));
        assert_eq!(results[1], Address::new(0x0));
    }

    #[test]
    fn test_search_bytes_with_wildcard() {
        let api = InstructionSearchApi::new();
        // Mask 0xFF, 0xF0: match high nibble of byte 1
        let mc = MaskContainer::new(vec![0xFF, 0xF0], vec![0x48, 0x80]).unwrap();
        let memory = vec![0x48, 0x89, 0x48, 0x8F, 0x49, 0x80];
        let results = api.search_bytes(&mc, &memory, 0x0, true);
        assert_eq!(results.len(), 2); // byte pairs at offset 0 and 2 match
    }

    #[test]
    fn test_search_bytes_no_match() {
        let api = InstructionSearchApi::new();
        let mc = MaskContainer::new(vec![0xFF, 0xFF], vec![0xDE, 0xAD]).unwrap();
        let memory = vec![0x00, 0x00, 0x00];
        let results = api.search_bytes(&mc, &memory, 0x0, true);
        assert!(results.is_empty());
    }

    #[test]
    fn test_search_bytes_all_masked() {
        let api = InstructionSearchApi::new();
        // All mask bits 0 = match nothing
        let mc = MaskContainer::new(vec![0x00, 0x00], vec![0x00, 0x00]).unwrap();
        let memory = vec![0xFF, 0xFF, 0xFF];
        let results = api.search_bytes(&mc, &memory, 0x0, true);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_hex_pattern_simple() {
        let mc = InstructionSearchApi::parse_hex_pattern("4889").unwrap();
        assert_eq!(mc.mask, vec![0xFF, 0xFF]);
        assert_eq!(mc.value, vec![0x48, 0x89]);
    }

    #[test]
    fn test_parse_hex_pattern_with_spaces() {
        let mc = InstructionSearchApi::parse_hex_pattern("48 89").unwrap();
        assert_eq!(mc.mask, vec![0xFF, 0xFF]);
        assert_eq!(mc.value, vec![0x48, 0x89]);
    }

    #[test]
    fn test_parse_hex_pattern_with_wildcards() {
        let mc = InstructionSearchApi::parse_hex_pattern("48 ..").unwrap();
        assert_eq!(mc.mask, vec![0xFF, 0x00]);
        assert_eq!(mc.value, vec![0x48, 0x00]);
    }

    #[test]
    fn test_parse_hex_pattern_partial_wildcard() {
        let mc = InstructionSearchApi::parse_hex_pattern("4.").unwrap();
        assert_eq!(mc.mask, vec![0xF0]);
        assert_eq!(mc.value, vec![0x40]);
    }

    #[test]
    fn test_parse_hex_pattern_nibble_wildcard_low() {
        let mc = InstructionSearchApi::parse_hex_pattern(".8").unwrap();
        assert_eq!(mc.mask, vec![0x0F]);
        assert_eq!(mc.value, vec![0x08]);
    }

    #[test]
    fn test_parse_hex_pattern_invalid() {
        assert!(InstructionSearchApi::parse_hex_pattern("").is_none());
        assert!(InstructionSearchApi::parse_hex_pattern("4").is_none()); // odd length
        assert!(InstructionSearchApi::parse_hex_pattern("GG").is_none());
    }

    #[test]
    fn test_search_hex_pattern() {
        let api = InstructionSearchApi::new();
        let memory = vec![0x00, 0x48, 0x89, 0x00];
        let results = api.search_hex_pattern("48 89", &memory, 0x0, true);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], Address::new(0x1));
    }

    #[test]
    fn test_to_yara_hex_string() {
        let mc = MaskContainer::new(vec![0xFF, 0x00, 0xFF], vec![0x48, 0x00, 0x89]).unwrap();
        let yara = InstructionSearchApi::to_yara_hex_string(&mc);
        assert_eq!(yara, "48 [..] 89");
    }

    #[test]
    fn test_to_yara_hex_string_partial() {
        let mc = MaskContainer::new(vec![0xFF, 0xF0], vec![0x48, 0x80]).unwrap();
        let yara = InstructionSearchApi::to_yara_hex_string(&mc);
        // Partial mask: high nibble matched, low nibble wildcard
        assert_eq!(yara, "48 8?");
    }
}
