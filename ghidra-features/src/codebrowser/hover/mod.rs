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
/// Ports `DataTypeListingHover`.
#[derive(Debug)]
pub struct DataTypeListingHover;

impl ListingHoverService for DataTypeListingHover {
    fn name(&self) -> &str {
        "DataTypeListingHover"
    }

    fn get_hover_text(&self, _ctx: &HoverContext) -> Option<String> {
        // In a full implementation, this would look up the data type at the
        // address and return its definition.
        None
    }
}

/// Hover service that shows the function signature at the cursor.
///
/// Ports `FunctionSignatureListingHover`.
#[derive(Debug)]
pub struct FunctionSignatureListingHover;

impl ListingHoverService for FunctionSignatureListingHover {
    fn name(&self) -> &str {
        "FunctionSignatureListingHover"
    }

    fn get_hover_text(&self, _ctx: &HoverContext) -> Option<String> {
        None
    }
}

/// Hover service that shows the label (symbol name) at the cursor.
///
/// Ports `LabelListingHover`.
#[derive(Debug)]
pub struct LabelListingHover;

impl ListingHoverService for LabelListingHover {
    fn name(&self) -> &str {
        "LabelListingHover"
    }

    fn get_hover_text(&self, _ctx: &HoverContext) -> Option<String> {
        None
    }
}

/// Hover service that shows references to/from the address.
///
/// Ports `ReferenceListingHover`.
#[derive(Debug)]
pub struct ReferenceListingHover;

impl ListingHoverService for ReferenceListingHover {
    fn name(&self) -> &str {
        "ReferenceListingHover"
    }

    fn get_hover_text(&self, _ctx: &HoverContext) -> Option<String> {
        None
    }
}

/// Hover service that shows scalar operand values in different bases.
///
/// Ports `ScalarOperandListingHover`.
#[derive(Debug)]
pub struct ScalarOperandListingHover;

impl ListingHoverService for ScalarOperandListingHover {
    fn name(&self) -> &str {
        "ScalarOperandListingHover"
    }

    fn get_hover_text(&self, _ctx: &HoverContext) -> Option<String> {
        None
    }
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
}
