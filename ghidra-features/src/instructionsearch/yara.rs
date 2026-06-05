//! YARA-compatible search API.
//!
//! Ported from `ghidra.app.plugin.core.instructionsearch.api.InstructionSearchApi_Yara`.
//!
//! Provides a higher-level API that formats instruction search patterns
//! into YARA-compatible rule syntax for use with external tools.

use super::model::MaskContainer;
use super::SearchResult;

/// A YARA-compatible hex string rule generated from an instruction search.
///
/// This represents the output of converting Ghidra instruction patterns
/// into YARA hex pattern syntax.
#[derive(Debug, Clone)]
pub struct YaraHexPattern {
    /// Pattern name/identifier.
    pub name: String,
    /// The hex pattern string (e.g., "89 E5 83 EC ??").
    pub hex_pattern: String,
    /// The rule description.
    pub description: String,
}

impl YaraHexPattern {
    /// Create a new YARA hex pattern.
    pub fn new(name: impl Into<String>, hex_pattern: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            hex_pattern: hex_pattern.into(),
            description: String::new(),
        }
    }

    /// Format as a YARA rule fragment.
    pub fn to_rule_fragment(&self) -> String {
        format!("${} = {{{} }}", self.name, self.hex_pattern)
    }
}

/// A YARA rule generated from Ghidra instruction search patterns.
#[derive(Debug, Clone)]
pub struct YaraRule {
    /// Rule name.
    pub name: String,
    /// Rule description/meta.
    pub description: String,
    /// Hex patterns.
    pub patterns: Vec<YaraHexPattern>,
    /// Condition expression.
    pub condition: String,
}

impl YaraRule {
    /// Create a new YARA rule.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            patterns: Vec::new(),
            condition: "any of them".to_string(),
        }
    }

    /// Add a pattern.
    pub fn add_pattern(&mut self, pattern: YaraHexPattern) {
        self.patterns.push(pattern);
    }

    /// Render the complete YARA rule.
    pub fn to_rule_text(&self) -> String {
        let mut out = format!("rule {} {{\n", self.name);
        if !self.description.is_empty() {
            out.push_str(&format!("    meta:\n        description = \"{}\"\n", self.description));
        }
        out.push_str("    strings:\n");
        for p in &self.patterns {
            out.push_str(&format!("        {}\n", p.to_rule_fragment()));
        }
        out.push_str(&format!("    condition:\n        {}\n", self.condition));
        out.push_str("}\n");
        out
    }
}

/// API for generating YARA rules from instruction search patterns.
///
/// Ported from `ghidra.app.plugin.core.instructionsearch.api.InstructionSearchApi_Yara`.
pub struct InstructionSearchApiYara;

impl InstructionSearchApiYara {
    /// Convert a mask container to a YARA hex string.
    pub fn mask_to_yara_hex(container: &MaskContainer) -> String {
        let mut parts = Vec::new();
        for i in 0..container.value.len() {
            let v = container.value[i];
            let m = container.mask[i];
            if m == 0xFF {
                parts.push(format!("{:02X}", v));
            } else {
                // Partially masked byte
                let masked_val = v & m;
                let mut hex_chars = String::new();
                for nibble_idx in (0..2).rev() {
                    let shift = nibble_idx * 4;
                    let nibble_mask = (m >> shift) & 0x0F;
                    if nibble_mask == 0x0F {
                        hex_chars.push_str(&format!("{:X}", (masked_val >> shift) & 0x0F));
                    } else {
                        hex_chars.push('?');
                    }
                }
                parts.push(hex_chars);
            }
        }
        parts.join(" ")
    }

    /// Generate a YARA rule from search results.
    pub fn generate_rule(
        name: &str,
        patterns: &[MaskContainer],
        results: &[SearchResult],
    ) -> YaraRule {
        let mut rule = YaraRule::new(name);
        rule.description = format!(
            "Generated from {} patterns with {} matches",
            patterns.len(),
            results.len()
        );

        for (i, container) in patterns.iter().enumerate() {
            let hex = Self::mask_to_yara_hex(container);
            rule.add_pattern(YaraHexPattern::new(format!("pat{}", i), hex));
        }

        if patterns.len() > 1 {
            rule.condition = "all of them".to_string();
        }

        rule
    }

    /// Convert a raw hex string with wildcards to YARA format.
    pub fn hex_string_to_yara(hex_str: &str) -> String {
        hex_str
            .split_whitespace()
            .map(|token| {
                if token == "?" || token == "??" {
                    "??".to_string()
                } else {
                    token.to_uppercase()
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_core::Address;

    #[test]
    fn test_yara_hex_pattern() {
        let p = YaraHexPattern::new("pat0", "89 E5 83 EC ??");
        assert_eq!(p.name, "pat0");
        assert_eq!(p.to_rule_fragment(), "$pat0 = {89 E5 83 EC ?? }");
    }

    #[test]
    fn test_yara_rule_render() {
        let mut rule = YaraRule::new("my_rule");
        rule.description = "Test rule".to_string();
        rule.add_pattern(YaraHexPattern::new("pat0", "89 E5"));

        let text = rule.to_rule_text();
        assert!(text.contains("rule my_rule"));
        assert!(text.contains("$pat0"));
        assert!(text.contains("any of them"));
    }

    #[test]
    fn test_yara_rule_condition() {
        let mut rule = YaraRule::new("multi");
        rule.add_pattern(YaraHexPattern::new("a", "89 E5"));
        rule.add_pattern(YaraHexPattern::new("b", "83 EC"));
        rule.condition = "all of them".to_string();

        let text = rule.to_rule_text();
        assert!(text.contains("all of them"));
    }

    #[test]
    fn test_mask_to_yara_hex_full_mask() {
        let container = MaskContainer {
            mask: vec![0xFF, 0xFF, 0xFF],
            value: vec![0x89, 0xE5, 0x83],
        };
        let hex = InstructionSearchApiYara::mask_to_yara_hex(&container);
        assert_eq!(hex, "89 E5 83");
    }

    #[test]
    fn test_mask_to_yara_hex_partial_mask() {
        let container = MaskContainer {
            mask: vec![0xFF, 0xF0],
            value: vec![0x89, 0xE5],
        };
        let hex = InstructionSearchApiYara::mask_to_yara_hex(&container);
        assert_eq!(hex, "89 E?");
    }

    #[test]
    fn test_mask_to_yara_hex_wildcard() {
        let container = MaskContainer {
            mask: vec![0xFF, 0x00],
            value: vec![0x89, 0xE5],
        };
        let hex = InstructionSearchApiYara::mask_to_yara_hex(&container);
        assert_eq!(hex, "89 ??");
    }

    #[test]
    fn test_generate_rule() {
        let patterns = vec![
            MaskContainer {
                mask: vec![0xFF, 0xFF],
                value: vec![0x89, 0xE5],
            },
            MaskContainer {
                mask: vec![0xFF, 0xFF],
                value: vec![0x83, 0xEC],
            },
        ];
        let results = vec![
            SearchResult::new(Address::new(0x1000), 2, vec![0x89, 0xE5]),
            SearchResult::new(Address::new(0x1002), 2, vec![0x83, 0xEC]),
        ];

        let rule = InstructionSearchApiYara::generate_rule("test_rule", &patterns, &results);
        assert_eq!(rule.name, "test_rule");
        assert_eq!(rule.patterns.len(), 2);
        assert_eq!(rule.condition, "all of them");
    }

    #[test]
    fn test_generate_rule_single_pattern() {
        let patterns = vec![MaskContainer {
            mask: vec![0xFF],
            value: vec![0x90],
        }];
        let rule = InstructionSearchApiYara::generate_rule("nop", &patterns, &[]);
        assert_eq!(rule.condition, "any of them");
    }

    #[test]
    fn test_hex_string_to_yara() {
        assert_eq!(
            InstructionSearchApiYara::hex_string_to_yara("89 e5 83 ec"),
            "89 E5 83 EC"
        );
        assert_eq!(
            InstructionSearchApiYara::hex_string_to_yara("89 ? ec"),
            "89 ?? EC"
        );
    }
}
