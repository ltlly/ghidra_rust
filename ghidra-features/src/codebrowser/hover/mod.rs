//! Hover service interfaces for the listing.
//!
//! Ports the `ghidra.app.plugin.core.codebrowser.hover` package, which
//! defines the `ListingHoverService` interface and several concrete hover
//! provider plugins for showing tooltips when the user hovers over listing
//! elements (data types, function signatures, labels, references, etc.).

use std::fmt;

/// Trait for listing hover services.
///
/// A `ListingHoverService` provides tooltip / popup content when the user
/// hovers over a specific element in the code listing.  This is a marker
/// interface in Ghidra (extends `HoverService`); in Rust we give it a
/// method for producing hover text.
///
/// Ported from Ghidra's `ListingHoverService`.
pub trait ListingHoverService: Send + Sync + fmt::Debug {
    /// Name of this hover service.
    fn name(&self) -> &str;

    /// Produce hover text for the given context.
    ///
    /// Return `None` if this service has nothing to show.
    fn get_hover_text(&self, ctx: &HoverContext) -> Option<String>;
}

/// Context provided to a hover service.
#[derive(Debug, Clone)]
pub struct HoverContext {
    /// The program name.
    pub program: Option<String>,
    /// The address under the cursor.
    pub address: Option<String>,
    /// The field text under the cursor.
    pub text: Option<String>,
    /// Cursor offset within the field text.
    pub cursor_text_offset: usize,
    /// The field name (e.g., "Label", "Mnemonic", "Operand").
    pub field_name: Option<String>,
}

impl HoverContext {
    /// Create a new hover context.
    pub fn new() -> Self {
        Self {
            program: None,
            address: None,
            text: None,
            cursor_text_offset: 0,
            field_name: None,
        }
    }
}

impl Default for HoverContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Concrete hover services
// ---------------------------------------------------------------------------

/// Hover service that shows the data type of the item under the cursor.
///
/// When the cursor is over a data type field in the listing, this hover
/// provider shows the data type definition including size, alignment,
/// and structure layout.
///
/// Ports `DataTypeListingHover`.
#[derive(Debug)]
pub struct DataTypeListingHover;

impl ListingHoverService for DataTypeListingHover {
    fn name(&self) -> &str {
        "DataTypeListingHover"
    }

    fn get_hover_text(&self, ctx: &HoverContext) -> Option<String> {
        // Only show when the field is a data-type-related field
        let field = ctx.field_name.as_deref()?;
        match field {
            "DataType" | "DataTypeName" | "TypeDef" => {
                // In a full implementation, we would look up the actual data type
                // at the address from the program listing. For now, return the
                // field text as a type preview.
                ctx.text.as_ref().map(|t| format!("Data Type: {}", t))
            }
            _ => None,
        }
    }
}

/// Hover service that shows the function signature at the cursor.
///
/// When the cursor is over a function name in the listing, shows the
/// full return type, parameter types, and calling convention.
///
/// Ports `FunctionSignatureListingHover`.
#[derive(Debug)]
pub struct FunctionSignatureListingHover;

impl ListingHoverService for FunctionSignatureListingHover {
    fn name(&self) -> &str {
        "FunctionSignatureListingHover"
    }

    fn get_hover_text(&self, ctx: &HoverContext) -> Option<String> {
        let field = ctx.field_name.as_deref()?;
        match field {
            "Label" | "FunctionSignature" => {
                // In a full implementation, look up the function at this address
                // and return its full signature.
                ctx.text.as_ref().filter(|t| !t.is_empty()).map(|t| {
                    format!("Function: {}", t)
                })
            }
            _ => None,
        }
    }
}

/// Hover service that shows the label (symbol name) at the cursor.
///
/// When the cursor is over a label field, shows the full qualified
/// name and namespace path of the symbol.
///
/// Ports `LabelListingHover`.
#[derive(Debug)]
pub struct LabelListingHover;

impl ListingHoverService for LabelListingHover {
    fn name(&self) -> &str {
        "LabelListingHover"
    }

    fn get_hover_text(&self, ctx: &HoverContext) -> Option<String> {
        let field = ctx.field_name.as_deref()?;
        match field {
            "Label" => {
                // In a full implementation, look up the symbol at this address
                // and return its fully qualified name.
                ctx.text.as_ref().filter(|t| !t.is_empty()).map(|t| {
                    format!("Label: {}", t)
                })
            }
            _ => None,
        }
    }
}

/// Hover service that shows references to/from the address.
///
/// When the cursor is over an operand or label, shows the number of
/// cross-references to that address and a summary of where they come from.
///
/// Ports `ReferenceListingHover`.
#[derive(Debug)]
pub struct ReferenceListingHover;

impl ListingHoverService for ReferenceListingHover {
    fn name(&self) -> &str {
        "ReferenceListingHover"
    }

    fn get_hover_text(&self, ctx: &HoverContext) -> Option<String> {
        let _addr = ctx.address.as_ref()?;
        let _program = ctx.program.as_ref()?;
        // In a full implementation, query the reference manager for the address
        // and return a summary like "3 references (READ from 0x1000, CALL from 0x2000, ...)".
        // For now, just indicate the address has references.
        ctx.address.as_ref().map(|a| format!("References to {}", a))
    }
}

/// Hover service that shows scalar operand values in different bases.
///
/// When the cursor is over a numeric operand, shows the value in decimal,
/// hexadecimal, octal, binary, and ASCII character interpretations.
///
/// Ports `ScalarOperandListingHover`.
#[derive(Debug)]
pub struct ScalarOperandListingHover;

impl ListingHoverService for ScalarOperandListingHover {
    fn name(&self) -> &str {
        "ScalarOperandListingHover"
    }

    fn get_hover_text(&self, ctx: &HoverContext) -> Option<String> {
        let field = ctx.field_name.as_deref()?;
        match field {
            "Operand" => {
                // Try to parse the operand text as a numeric value
                let text = ctx.text.as_ref()?;
                if let Some(value) = parse_operand_value(text) {
                    return Some(format_scalar_hover(value));
                }
                None
            }
            _ => None,
        }
    }
}

/// Try to parse an operand text as a numeric value.
///
/// Handles hex (0x...), decimal, and plain numbers.
fn parse_operand_value(text: &str) -> Option<u64> {
    let trimmed = text.trim();
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        trimmed.parse::<u64>().ok()
    }
}

/// Format a scalar value in multiple representations.
fn format_scalar_hover(value: u64) -> String {
    let mut parts = Vec::new();
    parts.push(format!("Dec: {}", value));
    parts.push(format!("Hex: 0x{:X}", value));
    parts.push(format!("Oct: 0o{:o}", value));

    // Show as ASCII if all bytes are printable
    if value > 0 && value <= u64::MAX {
        let bytes = value.to_le_bytes();
        let ascii: String = bytes
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| {
                if b >= 0x20 && b < 0x7F {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        if !ascii.is_empty() {
            parts.push(format!("ASCII: \"{}\"", ascii));
        }
    }

    // Show as different byte widths
    parts.push(format!("1-byte: 0x{:02X}", value & 0xFF));
    if value > 0xFF {
        parts.push(format!("2-byte: 0x{:04X}", value & 0xFFFF));
    }
    if value > 0xFFFF {
        parts.push(format!("4-byte: 0x{:08X}", value & 0xFFFF_FFFF));
    }

    parts.join(" | ")
}

/// Hover service that shows the full text when the listing text is truncated.
///
/// Ports `TruncatedTextListingHover`.
#[derive(Debug)]
pub struct TruncatedTextListingHover;

impl ListingHoverService for TruncatedTextListingHover {
    fn name(&self) -> &str {
        "TruncatedTextListingHover"
    }

    fn get_hover_text(&self, ctx: &HoverContext) -> Option<String> {
        // In a full implementation, check if the text is truncated and return
        // the full text.
        ctx.text.clone()
    }
}

/// Hover service that shows address relationship information.
///
/// Ports `ProgramAddressRelationshipListingHover`.
#[derive(Debug)]
pub struct ProgramAddressRelationshipListingHover;

impl ListingHoverService for ProgramAddressRelationshipListingHover {
    fn name(&self) -> &str {
        "ProgramAddressRelationshipListingHover"
    }

    fn get_hover_text(&self, _ctx: &HoverContext) -> Option<String> {
        None
    }
}

/// A registry of hover services.
#[derive(Debug)]
pub struct HoverServiceRegistry {
    services: Vec<Box<dyn ListingHoverService>>,
}

impl HoverServiceRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            services: Vec::new(),
        }
    }

    /// Register a hover service.
    pub fn register(&mut self, service: Box<dyn ListingHoverService>) {
        self.services.push(service);
    }

    /// Query all registered services and return the first hover text found.
    pub fn get_hover_text(&self, ctx: &HoverContext) -> Option<String> {
        for service in &self.services {
            if let Some(text) = service.get_hover_text(ctx) {
                return Some(text);
            }
        }
        None
    }

    /// Number of registered services.
    pub fn len(&self) -> usize {
        self.services.len()
    }

    /// Whether no services are registered.
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// Get all registered service names.
    pub fn service_names(&self) -> Vec<&str> {
        self.services.iter().map(|s| s.name()).collect()
    }

    /// Remove a service by name.
    pub fn remove(&mut self, name: &str) -> bool {
        let len_before = self.services.len();
        self.services.retain(|s| s.name() != name);
        self.services.len() < len_before
    }
}

impl Default for HoverServiceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hover_context_default() {
        let ctx = HoverContext::default();
        assert!(ctx.program.is_none());
        assert!(ctx.address.is_none());
        assert!(ctx.text.is_none());
        assert_eq!(ctx.cursor_text_offset, 0);
    }

    #[test]
    fn test_hover_service_registry() {
        let mut registry = HoverServiceRegistry::new();
        assert!(registry.is_empty());

        registry.register(Box::new(DataTypeListingHover));
        registry.register(Box::new(FunctionSignatureListingHover));
        assert_eq!(registry.len(), 2);

        let names = registry.service_names();
        assert!(names.contains(&"DataTypeListingHover"));
        assert!(names.contains(&"FunctionSignatureListingHover"));
    }

    #[test]
    fn test_hover_service_registry_remove() {
        let mut registry = HoverServiceRegistry::new();
        registry.register(Box::new(LabelListingHover));
        registry.register(Box::new(ReferenceListingHover));

        assert!(registry.remove("LabelListingHover"));
        assert_eq!(registry.len(), 1);
        assert!(!registry.remove("NonExistent"));
    }

    #[test]
    fn test_truncated_text_hover_returns_text() {
        let hover = TruncatedTextListingHover;
        let ctx = HoverContext {
            text: Some("Hello World".into()),
            ..Default::default()
        };
        assert_eq!(hover.get_hover_text(&ctx), Some("Hello World".into()));
    }

    #[test]
    fn test_concrete_hover_services_names() {
        assert_eq!(DataTypeListingHover.name(), "DataTypeListingHover");
        assert_eq!(
            FunctionSignatureListingHover.name(),
            "FunctionSignatureListingHover"
        );
        assert_eq!(LabelListingHover.name(), "LabelListingHover");
        assert_eq!(ReferenceListingHover.name(), "ReferenceListingHover");
        assert_eq!(ScalarOperandListingHover.name(), "ScalarOperandListingHover");
        assert_eq!(TruncatedTextListingHover.name(), "TruncatedTextListingHover");
        assert_eq!(
            ProgramAddressRelationshipListingHover.name(),
            "ProgramAddressRelationshipListingHover"
        );
    }

    #[test]
    fn test_hover_registry_get_text_none() {
        let registry = HoverServiceRegistry::new();
        let ctx = HoverContext::default();
        assert!(registry.get_hover_text(&ctx).is_none());
    }

    #[test]
    fn test_data_type_hover_with_field() {
        let ctx = HoverContext {
            field_name: Some("DataType".into()),
            text: Some("int".into()),
            ..Default::default()
        };
        let text = DataTypeListingHover.get_hover_text(&ctx);
        assert_eq!(text, Some("Data Type: int".into()));
    }

    #[test]
    fn test_data_type_hover_wrong_field() {
        let ctx = HoverContext {
            field_name: Some("Mnemonic".into()),
            text: Some("MOV".into()),
            ..Default::default()
        };
        let text = DataTypeListingHover.get_hover_text(&ctx);
        assert!(text.is_none());
    }

    #[test]
    fn test_function_signature_hover() {
        let ctx = HoverContext {
            field_name: Some("Label".into()),
            text: Some("void main(int argc)".into()),
            ..Default::default()
        };
        let text = FunctionSignatureListingHover.get_hover_text(&ctx);
        assert_eq!(text, Some("Function: void main(int argc)".into()));
    }

    #[test]
    fn test_label_hover() {
        let ctx = HoverContext {
            field_name: Some("Label".into()),
            text: Some("main".into()),
            ..Default::default()
        };
        let text = LabelListingHover.get_hover_text(&ctx);
        assert_eq!(text, Some("Label: main".into()));
    }

    #[test]
    fn test_reference_hover() {
        let ctx = HoverContext {
            address: Some("0x401000".into()),
            program: Some("test.exe".into()),
            ..Default::default()
        };
        let text = ReferenceListingHover.get_hover_text(&ctx);
        assert_eq!(text, Some("References to 0x401000".into()));
    }

    #[test]
    fn test_scalar_operand_hover_hex() {
        let ctx = HoverContext {
            field_name: Some("Operand".into()),
            text: Some("0xFF".into()),
            ..Default::default()
        };
        let text = ScalarOperandListingHover.get_hover_text(&ctx);
        assert!(text.is_some());
        let text = text.unwrap();
        assert!(text.contains("Dec: 255"));
        assert!(text.contains("Hex: 0xFF"));
    }

    #[test]
    fn test_scalar_operand_hover_decimal() {
        let ctx = HoverContext {
            field_name: Some("Operand".into()),
            text: Some("42".into()),
            ..Default::default()
        };
        let text = ScalarOperandListingHover.get_hover_text(&ctx);
        assert!(text.is_some());
        let text = text.unwrap();
        assert!(text.contains("Dec: 42"));
        assert!(text.contains("Hex: 0x2A"));
    }

    #[test]
    fn test_scalar_operand_hover_wrong_field() {
        let ctx = HoverContext {
            field_name: Some("Label".into()),
            text: Some("42".into()),
            ..Default::default()
        };
        let text = ScalarOperandListingHover.get_hover_text(&ctx);
        assert!(text.is_none());
    }

    #[test]
    fn test_parse_operand_value_hex() {
        assert_eq!(parse_operand_value("0xFF"), Some(255));
        assert_eq!(parse_operand_value("0X10"), Some(16));
        assert_eq!(parse_operand_value("0x0"), Some(0));
    }

    #[test]
    fn test_parse_operand_value_decimal() {
        assert_eq!(parse_operand_value("42"), Some(42));
        assert_eq!(parse_operand_value("0"), Some(0));
        assert_eq!(parse_operand_value(" 123 "), Some(123));
    }

    #[test]
    fn test_parse_operand_value_invalid() {
        assert_eq!(parse_operand_value("abc"), None);
        assert_eq!(parse_operand_value(""), None);
    }

    #[test]
    fn test_format_scalar_hover() {
        let text = format_scalar_hover(0x41);
        assert!(text.contains("Dec: 65"));
        assert!(text.contains("Hex: 0x41"));
        assert!(text.contains("Oct: 0o101"));
        assert!(text.contains("ASCII:"));
    }

    #[test]
    fn test_format_scalar_hover_zero() {
        let text = format_scalar_hover(0);
        assert!(text.contains("Dec: 0"));
    }

    #[test]
    fn test_hover_registry_priority_order() {
        let mut registry = HoverServiceRegistry::new();
        registry.register(Box::new(DataTypeListingHover));
        registry.register(Box::new(LabelListingHover));

        // DataType hover doesn't match Operand field
        let ctx = HoverContext {
            field_name: Some("Operand".into()),
            text: Some("0x10".into()),
            ..Default::default()
        };
        // Both return None since field doesn't match
        assert!(registry.get_hover_text(&ctx).is_none());
    }

    #[test]
    fn test_label_hover_empty_text() {
        let ctx = HoverContext {
            field_name: Some("Label".into()),
            text: Some(String::new()),
            ..Default::default()
        };
        // Empty text should be filtered out
        let text = LabelListingHover.get_hover_text(&ctx);
        assert!(text.is_none());
    }
}
