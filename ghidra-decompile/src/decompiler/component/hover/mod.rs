//! Decompiler hover provider system.
//!
//! Ports `ghidra.app.decompiler.component.hover` package.

pub mod providers_ext;

use ghidra_core::addr::Address;

/// A hover result displayed when the user hovers over a token.
#[derive(Debug, Clone)]
pub struct HoverResult {
    /// HTML content to display.
    pub html_content: String,
    /// The address associated with the hovered element.
    pub address: Option<Address>,
    /// Priority of this hover result (higher = preferred).
    pub priority: i32,
}

impl HoverResult {
    /// Create a new hover result.
    pub fn new(html_content: impl Into<String>) -> Self {
        Self {
            html_content: html_content.into(),
            address: None,
            priority: 0,
        }
    }

    /// Set the associated address.
    pub fn with_address(mut self, addr: Address) -> Self {
        self.address = Some(addr);
        self
    }

    /// Set the priority.
    pub fn with_priority(mut self, priority: i32) -> Self {
        self.priority = priority;
        self
    }
}

/// Trait for decompiler hover service providers.
pub trait DecompilerHoverService: Send + Sync {
    /// Get a hover result for a token at the given address.
    fn get_hover(&self, token_text: &str, address: Address) -> Option<HoverResult>;

    /// The name of this hover provider.
    fn name(&self) -> &str;

    /// Priority of this provider (higher = checked first).
    fn priority(&self) -> i32;
}

/// Data type hover provider -- shows type information on hover.
#[derive(Debug, Clone, Default)]
pub struct DataTypeHoverProvider;

impl DecompilerHoverService for DataTypeHoverProvider {
    fn get_hover(&self, token_text: &str, _address: Address) -> Option<HoverResult> {
        // In a real implementation, this would look up data type info
        // For now, return a simple type hint for common types
        let type_info = match token_text {
            "int" | "int32_t" => "32-bit signed integer",
            "uint" | "uint32_t" | "unsigned" => "32-bit unsigned integer",
            "char" | "int8_t" => "8-bit signed integer",
            "short" | "int16_t" => "16-bit signed integer",
            "long" | "int64_t" => "64-bit signed integer",
            "float" => "32-bit IEEE 754 floating point",
            "double" => "64-bit IEEE 754 floating point",
            "void" => "No type / empty type",
            "bool" | "_Bool" => "Boolean (true/false)",
            "size_t" => "Platform-dependent unsigned size type",
            "ptrdiff_t" => "Platform-dependent pointer difference type",
            _ => return None,
        };
        Some(HoverResult::new(format!("<b>{}</b>: {}", token_text, type_info)).with_priority(10))
    }

    fn name(&self) -> &str {
        "DataType Hover"
    }

    fn priority(&self) -> i32 {
        10
    }
}

/// Function signature hover provider -- shows function signatures on hover.
#[derive(Debug, Clone, Default)]
pub struct FunctionSignatureHoverProvider;

impl DecompilerHoverService for FunctionSignatureHoverProvider {
    fn get_hover(&self, token_text: &str, address: Address) -> Option<HoverResult> {
        // In a real implementation, this would look up the function
        // For now, provide a simple hover for potential function names
        if token_text.chars().next().map(|c| c.is_lowercase()).unwrap_or(false) {
            Some(
                HoverResult::new(format!("<i>function</i>: {}()", token_text))
                    .with_address(address)
                    .with_priority(5),
            )
        } else {
            None
        }
    }

    fn name(&self) -> &str {
        "Function Signature Hover"
    }

    fn priority(&self) -> i32 {
        5
    }
}

/// Scalar value hover provider -- shows numeric representations on hover.
#[derive(Debug, Clone, Default)]
pub struct ScalarValueHoverProvider;

impl DecompilerHoverService for ScalarValueHoverProvider {
    fn get_hover(&self, token_text: &str, _address: Address) -> Option<HoverResult> {
        // Try to parse as a number and show alternative representations
        let value = if token_text.starts_with("0x") || token_text.starts_with("0X") {
            u64::from_str_radix(&token_text[2..], 16).ok()
        } else {
            token_text.parse::<u64>().ok()
        };

        if let Some(v) = value {
            let hex = format!("0x{:x}", v);
            let dec = format!("{}", v);
            let oct = format!("0o{:o}", v);
            let bin = format!("0b{:b}", v);

            let content = if token_text.starts_with("0x") {
                format!("<b>hex:</b> {} <b>dec:</b> {} <b>oct:</b> {}", hex, dec, oct)
            } else {
                format!("<b>dec:</b> {} <b>hex:</b> {} <b>bin:</b> {}", dec, hex, bin)
            };
            Some(HoverResult::new(content).with_priority(8))
        } else {
            None
        }
    }

    fn name(&self) -> &str {
        "Scalar Value Hover"
    }

    fn priority(&self) -> i32 {
        8
    }
}

/// Reference hover provider -- shows cross-reference info on hover.
#[derive(Debug, Clone, Default)]
pub struct ReferenceHoverProvider;

impl DecompilerHoverService for ReferenceHoverProvider {
    fn get_hover(&self, _token_text: &str, address: Address) -> Option<HoverResult> {
        // In a real implementation, this would look up cross-references
        if address.offset > 0 {
            Some(
                HoverResult::new(format!(
                    "<i>Address:</i> 0x{:x}",
                    address.offset
                ))
                .with_address(address)
                .with_priority(3),
            )
        } else {
            None
        }
    }

    fn name(&self) -> &str {
        "Reference Hover"
    }

    fn priority(&self) -> i32 {
        3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_type_hover_known_types() {
        let provider = DataTypeHoverProvider;
        let result = provider.get_hover("int", Address::new(0));
        assert!(result.is_some());
        assert!(result.unwrap().html_content.contains("32-bit"));
    }

    #[test]
    fn data_type_hover_unknown_type() {
        let provider = DataTypeHoverProvider;
        let result = provider.get_hover("MyStruct", Address::new(0));
        assert!(result.is_none());
    }

    #[test]
    fn scalar_hover_hex() {
        let provider = ScalarValueHoverProvider;
        let result = provider.get_hover("0xFF", Address::new(0));
        assert!(result.is_some());
        let html = &result.unwrap().html_content;
        assert!(html.contains("dec:"));
        assert!(html.contains("255"));
    }

    #[test]
    fn scalar_hover_decimal() {
        let provider = ScalarValueHoverProvider;
        let result = provider.get_hover("42", Address::new(0));
        assert!(result.is_some());
        let html = &result.unwrap().html_content;
        assert!(html.contains("hex:"));
        assert!(html.contains("0x2a"));
    }

    #[test]
    fn scalar_hover_not_number() {
        let provider = ScalarValueHoverProvider;
        let result = provider.get_hover("abc", Address::new(0));
        assert!(result.is_none());
    }

    #[test]
    fn function_hover() {
        let provider = FunctionSignatureHoverProvider;
        let result = provider.get_hover("printf", Address::new(0x1000));
        assert!(result.is_some());
        assert!(result.unwrap().html_content.contains("printf"));
    }

    #[test]
    fn reference_hover() {
        let provider = ReferenceHoverProvider;
        let result = provider.get_hover("x", Address::new(0x1000));
        assert!(result.is_some());
        assert!(result.unwrap().html_content.contains("0x1000"));
    }

    #[test]
    fn hover_result_builder() {
        let result = HoverResult::new("test")
            .with_address(Address::new(0x100))
            .with_priority(5);
        assert_eq!(result.address, Some(Address::new(0x100)));
        assert_eq!(result.priority, 5);
    }

    #[test]
    fn provider_names() {
        assert_eq!(DataTypeHoverProvider.name(), "DataType Hover");
        assert_eq!(ScalarValueHoverProvider.name(), "Scalar Value Hover");
    }
}
