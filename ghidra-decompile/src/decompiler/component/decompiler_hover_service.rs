//! Decompiler hover service -- provides hover tooltips in the decompiler view.
//!
//! Port of Ghidra's `ghidra.app.decompiler.component.DecompilerHoverService`,
//! `DecompilerHoverProvider`, and the various hover provider implementations
//! (DataType, FunctionSignature, Reference, ScalarValue).

use super::super::clang_node::SyntaxType;

/// A tooltip result from a hover provider.
#[derive(Debug, Clone)]
pub struct HoverResult {
    /// The HTML or plain-text tooltip content.
    pub content: String,
    /// Whether the content is HTML.
    pub is_html: bool,
    /// The address associated with the hovered token (if any).
    pub address: Option<u64>,
}

impl HoverResult {
    /// Create a plain text tooltip.
    pub fn text(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            is_html: false,
            address: None,
        }
    }

    /// Create an HTML tooltip.
    pub fn html(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            is_html: true,
            address: None,
        }
    }

    /// Set the associated address.
    pub fn with_address(mut self, address: u64) -> Self {
        self.address = Some(address);
        self
    }
}

/// Trait for providing hover tooltips in the decompiler view.
///
/// Port of `ghidra.app.decompiler.component.DecompilerHoverProvider`.
pub trait DecompilerHoverProvider: std::fmt::Debug + Send + Sync {
    /// Get the name of this hover provider.
    fn name(&self) -> &str;

    /// Generate a tooltip for the token at the given position.
    ///
    /// # Arguments
    /// * `token_text` - The text of the token being hovered.
    /// * `syntax_type` - The syntax type of the token.
    /// * `node_id` - The ClangNodeId of the token.
    /// * `address` - The address represented by the token (if known).
    /// * `context` - Additional context data as key-value pairs.
    fn get_tooltip(
        &self,
        token_text: &str,
        syntax_type: SyntaxType,
        node_id: u64,
        address: Option<u64>,
        context: &[(&str, &str)],
    ) -> Option<HoverResult>;

    /// Whether this provider handles the given syntax type.
    fn accepts(&self, syntax_type: SyntaxType) -> bool;
}

/// Data type hover provider -- shows data type information on hover.
///
/// Port of `ghidra.app.decompiler.component.DataTypeDecompilerHover`.
#[derive(Debug, Clone, Default)]
pub struct DataTypeDecompilerHover;

impl DecompilerHoverProvider for DataTypeDecompilerHover {
    fn name(&self) -> &str {
        "DataType"
    }

    fn get_tooltip(
        &self,
        token_text: &str,
        syntax_type: SyntaxType,
        _node_id: u64,
        _address: Option<u64>,
        context: &[(&str, &str)],
    ) -> Option<HoverResult> {
        match syntax_type {
            SyntaxType::Type => {
                let mut tooltip = format!("Type: {}", token_text);
                // Look for additional type info in context.
                for (key, value) in context {
                    if *key == "type_size" {
                        tooltip.push_str(&format!(" ({} bytes)", value));
                    } else if *key == "type_category" {
                        tooltip.push_str(&format!("\nCategory: {}", value));
                    }
                }
                Some(HoverResult::html(tooltip))
            }
            _ => None,
        }
    }

    fn accepts(&self, syntax_type: SyntaxType) -> bool {
        matches!(syntax_type, SyntaxType::Type)
    }
}

/// Function signature hover provider -- shows function signatures on hover.
///
/// Port of `ghidra.app.decompiler.component.FunctionSignatureDecompilerHover`.
#[derive(Debug, Clone, Default)]
pub struct FunctionSignatureDecompilerHover;

impl DecompilerHoverProvider for FunctionSignatureDecompilerHover {
    fn name(&self) -> &str {
        "FunctionSignature"
    }

    fn get_tooltip(
        &self,
        token_text: &str,
        syntax_type: SyntaxType,
        _node_id: u64,
        _address: Option<u64>,
        context: &[(&str, &str)],
    ) -> Option<HoverResult> {
        match syntax_type {
            SyntaxType::Function => {
                let mut tooltip = format!("Function: {}", token_text);
                for (key, value) in context {
                    if *key == "return_type" {
                        tooltip = format!("{} {}", value, tooltip);
                    } else if *key == "param_count" {
                        tooltip.push_str(&format!(" ({} params)", value));
                    } else if *key == "calling_convention" {
                        tooltip.push_str(&format!(" [{}]", value));
                    }
                }
                Some(HoverResult::html(tooltip))
            }
            _ => None,
        }
    }

    fn accepts(&self, syntax_type: SyntaxType) -> bool {
        matches!(syntax_type, SyntaxType::Function)
    }
}

/// Reference hover provider -- shows reference information on hover.
///
/// Port of `ghidra.app.decompiler.component.ReferenceDecompilerHover`.
#[derive(Debug, Clone, Default)]
pub struct ReferenceDecompilerHover;

impl DecompilerHoverProvider for ReferenceDecompilerHover {
    fn name(&self) -> &str {
        "Reference"
    }

    fn get_tooltip(
        &self,
        token_text: &str,
        syntax_type: SyntaxType,
        _node_id: u64,
        address: Option<u64>,
        context: &[(&str, &str)],
    ) -> Option<HoverResult> {
        match syntax_type {
            SyntaxType::Variable | SyntaxType::Global | SyntaxType::Parameter => {
                let mut result = HoverResult::text(format!("{}: {}", token_text, syntax_type_name(syntax_type)));
                if let Some(addr) = address {
                    result = result.with_address(addr);
                }
                // Add reference count if available.
                for (key, value) in context {
                    if *key == "ref_count" {
                        result.content = format!("{}\nReferences: {}", result.content, value);
                    }
                }
                Some(result)
            }
            _ => None,
        }
    }

    fn accepts(&self, syntax_type: SyntaxType) -> bool {
        matches!(
            syntax_type,
            SyntaxType::Variable | SyntaxType::Global | SyntaxType::Parameter
        )
    }
}

/// Scalar value hover provider -- shows scalar value details on hover.
///
/// Port of `ghidra.app.decompiler.component.ScalarValueDecompilerHover`.
#[derive(Debug, Clone, Default)]
pub struct ScalarValueDecompilerHover;

impl DecompilerHoverProvider for ScalarValueDecompilerHover {
    fn name(&self) -> &str {
        "ScalarValue"
    }

    fn get_tooltip(
        &self,
        token_text: &str,
        syntax_type: SyntaxType,
        _node_id: u64,
        _address: Option<u64>,
        _context: &[(&str, &str)],
    ) -> Option<HoverResult> {
        match syntax_type {
            SyntaxType::Const => {
                // Try to parse as integer for different representations.
                let tooltip = if let Some(hex_val) = parse_int_value(token_text) {
                    format!(
                        "Decimal: {}\nHex: 0x{:x}\nOctal: 0o{:o}\nBinary: 0b{:b}",
                        hex_val, hex_val, hex_val, hex_val
                    )
                } else {
                    format!("Value: {}", token_text)
                };
                Some(HoverResult::html(tooltip))
            }
            _ => None,
        }
    }

    fn accepts(&self, syntax_type: SyntaxType) -> bool {
        matches!(syntax_type, SyntaxType::Const)
    }
}

/// The hover service that manages all registered hover providers.
///
/// Port of `ghidra.app.decompiler.component.DecompilerHoverService`.
#[derive(Debug)]
pub struct DecompilerHoverService {
    providers: Vec<Box<dyn DecompilerHoverProvider>>,
    enabled: bool,
}

impl DecompilerHoverService {
    /// Create a new hover service.
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
            enabled: true,
        }
    }

    /// Create a hover service with default providers.
    pub fn with_defaults() -> Self {
        let mut service = Self::new();
        service.register(Box::new(DataTypeDecompilerHover));
        service.register(Box::new(FunctionSignatureDecompilerHover));
        service.register(Box::new(ReferenceDecompilerHover));
        service.register(Box::new(ScalarValueDecompilerHover));
        service
    }

    /// Register a hover provider.
    pub fn register(&mut self, provider: Box<dyn DecompilerHoverProvider>) {
        self.providers.push(provider);
    }

    /// Enable or disable hover tooltips.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether hover tooltips are enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Try to get a tooltip from any registered provider.
    pub fn get_tooltip(
        &self,
        token_text: &str,
        syntax_type: SyntaxType,
        node_id: u64,
        address: Option<u64>,
        context: &[(&str, &str)],
    ) -> Option<HoverResult> {
        if !self.enabled {
            return None;
        }
        for provider in &self.providers {
            if provider.accepts(syntax_type) {
                if let Some(result) = provider.get_tooltip(
                    token_text,
                    syntax_type,
                    node_id,
                    address,
                    context,
                ) {
                    return Some(result);
                }
            }
        }
        None
    }

    /// Get the names of all registered providers.
    pub fn provider_names(&self) -> Vec<&str> {
        self.providers.iter().map(|p| p.name()).collect()
    }

    /// Get the number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.providers.len()
    }
}

impl Default for DecompilerHoverService {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Get a human-readable name for a syntax type.
fn syntax_type_name(syntax_type: SyntaxType) -> &'static str {
    match syntax_type {
        SyntaxType::Keyword => "keyword",
        SyntaxType::Comment => "comment",
        SyntaxType::Type => "type",
        SyntaxType::Function => "function",
        SyntaxType::Variable => "variable",
        SyntaxType::Const => "constant",
        SyntaxType::Parameter => "parameter",
        SyntaxType::Global => "global",
        SyntaxType::Default => "token",
        SyntaxType::Error => "error",
        SyntaxType::Special => "special",
        SyntaxType::Field => "field",
    }
}

/// Try to parse an integer value from a token (supports hex, octal, decimal).
fn parse_int_value(text: &str) -> Option<u64> {
    let text = text.trim();
    if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else if let Some(oct) = text.strip_prefix("0o").or_else(|| text.strip_prefix("0O")) {
        u64::from_str_radix(oct, 8).ok()
    } else if let Some(bin) = text.strip_prefix("0b").or_else(|| text.strip_prefix("0B")) {
        u64::from_str_radix(bin, 2).ok()
    } else {
        text.parse::<u64>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_type_hover() {
        let provider = DataTypeDecompilerHover;
        assert!(provider.accepts(SyntaxType::Type));
        assert!(!provider.accepts(SyntaxType::Variable));

        let result = provider.get_tooltip("int", SyntaxType::Type, 1, None, &[]);
        assert!(result.is_some());
        assert!(result.unwrap().content.contains("int"));
    }

    #[test]
    fn test_data_type_hover_with_context() {
        let provider = DataTypeDecompilerHover;
        let ctx = vec![("type_size", "4"), ("type_category", "primitive")];
        let result = provider.get_tooltip("int", SyntaxType::Type, 1, None, &ctx);
        let content = result.unwrap().content;
        assert!(content.contains("4 bytes"));
        assert!(content.contains("primitive"));
    }

    #[test]
    fn test_function_signature_hover() {
        let provider = FunctionSignatureDecompilerHover;
        assert!(provider.accepts(SyntaxType::Function));

        let ctx = vec![("return_type", "int"), ("param_count", "2")];
        let result = provider.get_tooltip("main", SyntaxType::Function, 1, Some(0x1000), &ctx);
        let content = result.unwrap().content;
        assert!(content.contains("int Function: main"));
        assert!(content.contains("2 params"));
    }

    #[test]
    fn test_reference_hover() {
        let provider = ReferenceDecompilerHover;
        assert!(provider.accepts(SyntaxType::Variable));
        assert!(provider.accepts(SyntaxType::Global));

        let result = provider.get_tooltip("x", SyntaxType::Variable, 1, Some(0x2000), &[]);
        let result = result.unwrap();
        assert!(result.content.contains("variable"));
        assert_eq!(result.address, Some(0x2000));
    }

    #[test]
    fn test_scalar_hover() {
        let provider = ScalarValueDecompilerHover;
        assert!(provider.accepts(SyntaxType::Const));

        let result = provider.get_tooltip("255", SyntaxType::Const, 1, None, &[]);
        let content = result.unwrap().content;
        assert!(content.contains("Decimal: 255"));
        assert!(content.contains("Hex: 0xff"));
        assert!(content.contains("Octal: 0o377"));
    }

    #[test]
    fn test_scalar_hover_hex() {
        let provider = ScalarValueDecompilerHover;
        let result = provider.get_tooltip("0x100", SyntaxType::Const, 1, None, &[]);
        let content = result.unwrap().content;
        assert!(content.contains("Decimal: 256"));
    }

    #[test]
    fn test_hover_service_defaults() {
        let service = DecompilerHoverService::default();
        assert!(service.is_enabled());
        assert_eq!(service.provider_count(), 4);
        let names = service.provider_names();
        assert!(names.contains(&"DataType"));
        assert!(names.contains(&"FunctionSignature"));
        assert!(names.contains(&"Reference"));
        assert!(names.contains(&"ScalarValue"));
    }

    #[test]
    fn test_hover_service_disabled() {
        let mut service = DecompilerHoverService::with_defaults();
        service.set_enabled(false);
        let result = service.get_tooltip("int", SyntaxType::Type, 1, None, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_hover_service_dispatch() {
        let service = DecompilerHoverService::with_defaults();
        let result = service.get_tooltip("main", SyntaxType::Function, 1, None, &[]);
        assert!(result.is_some());
    }

    #[test]
    fn test_hover_service_no_match() {
        let service = DecompilerHoverService::with_defaults();
        // Comment type has no provider.
        let result = service.get_tooltip("// comment", SyntaxType::Comment, 1, None, &[]);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_int_value() {
        assert_eq!(parse_int_value("42"), Some(42));
        assert_eq!(parse_int_value("0xff"), Some(255));
        assert_eq!(parse_int_value("0xFF"), Some(255));
        assert_eq!(parse_int_value("0o10"), Some(8));
        assert_eq!(parse_int_value("0b1010"), Some(10));
        assert_eq!(parse_int_value("not_a_number"), None);
    }

    #[test]
    fn test_hover_result() {
        let r = HoverResult::text("hello");
        assert!(!r.is_html);
        assert_eq!(r.content, "hello");
        assert!(r.address.is_none());

        let r = HoverResult::html("<b>bold</b>").with_address(0x1000);
        assert!(r.is_html);
        assert_eq!(r.address, Some(0x1000));
    }
}
