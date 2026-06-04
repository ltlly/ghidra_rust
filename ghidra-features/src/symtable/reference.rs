//! Symbol reference model -- ported from `SymbolReferenceModel`,
//! `ReferencePanel`, and `ReferenceProvider`.
//!
//! Shows cross-references to a selected symbol in the symbol table.

/// The direction of a reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceDirection {
    /// References TO this symbol (incoming).
    Incoming,
    /// References FROM this symbol (outgoing).
    Outgoing,
}

/// A single reference to/from a symbol.
///
/// Ported from Ghidra's `SymbolReferenceModel` row data.
#[derive(Debug, Clone)]
pub struct SymbolReference {
    /// The source address of the reference.
    from_address: u64,
    /// The target address of the reference.
    to_address: u64,
    /// The reference type (read, write, etc.).
    ref_type: String,
    /// The direction.
    direction: ReferenceDirection,
    /// The label at the from address.
    from_label: Option<String>,
    /// The label at the to address.
    to_label: Option<String>,
}

impl SymbolReference {
    /// Creates a new symbol reference.
    pub fn new(
        from_address: u64,
        to_address: u64,
        ref_type: impl Into<String>,
        direction: ReferenceDirection,
    ) -> Self {
        Self {
            from_address,
            to_address,
            ref_type: ref_type.into(),
            direction,
            from_label: None,
            to_label: None,
        }
    }

    /// Returns the source address.
    pub fn from_address(&self) -> u64 {
        self.from_address
    }

    /// Returns the target address.
    pub fn to_address(&self) -> u64 {
        self.to_address
    }

    /// Returns the reference type.
    pub fn ref_type(&self) -> &str {
        &self.ref_type
    }

    /// Returns the direction.
    pub fn direction(&self) -> ReferenceDirection {
        self.direction
    }

    /// Sets the from label.
    pub fn set_from_label(&mut self, label: Option<String>) {
        self.from_label = label;
    }

    /// Returns the from label.
    pub fn from_label(&self) -> Option<&str> {
        self.from_label.as_deref()
    }

    /// Sets the to label.
    pub fn set_to_label(&mut self, label: Option<String>) {
        self.to_label = label;
    }

    /// Returns the to label.
    pub fn to_label(&self) -> Option<&str> {
        self.to_label.as_deref()
    }
}

/// The reference model that tracks cross-references for a symbol.
///
/// Ported from `SymbolReferenceModel.java`.
#[derive(Debug, Clone)]
pub struct SymbolReferenceModel {
    /// The references.
    references: Vec<SymbolReference>,
    /// The address of the symbol being viewed.
    symbol_address: u64,
}

impl SymbolReferenceModel {
    /// Creates a new reference model.
    pub fn new(symbol_address: u64) -> Self {
        Self {
            references: Vec::new(),
            symbol_address,
        }
    }

    /// Adds a reference.
    pub fn add_reference(&mut self, reference: SymbolReference) {
        self.references.push(reference);
    }

    /// Returns all references.
    pub fn references(&self) -> &[SymbolReference] {
        &self.references
    }

    /// Returns only incoming references.
    pub fn incoming_references(&self) -> Vec<&SymbolReference> {
        self.references
            .iter()
            .filter(|r| r.direction() == ReferenceDirection::Incoming)
            .collect()
    }

    /// Returns only outgoing references.
    pub fn outgoing_references(&self) -> Vec<&SymbolReference> {
        self.references
            .iter()
            .filter(|r| r.direction() == ReferenceDirection::Outgoing)
            .collect()
    }

    /// Returns the total reference count.
    pub fn reference_count(&self) -> usize {
        self.references.len()
    }

    /// Returns the symbol address.
    pub fn symbol_address(&self) -> u64 {
        self.symbol_address
    }

    /// Clears all references.
    pub fn clear(&mut self) {
        self.references.clear();
    }
}

/// The reference provider (panel controller).
///
/// Ported from `ReferenceProvider.java`.
#[derive(Debug)]
pub struct SymbolReferenceProvider {
    /// The current reference model.
    model: Option<SymbolReferenceModel>,
    /// Whether the provider is visible.
    visible: bool,
}

impl SymbolReferenceProvider {
    /// Creates a new reference provider.
    pub fn new() -> Self {
        Self {
            model: None,
            visible: false,
        }
    }

    /// Sets the reference model.
    pub fn set_model(&mut self, model: SymbolReferenceModel) {
        self.model = Some(model);
    }

    /// Returns the reference model.
    pub fn model(&self) -> Option<&SymbolReferenceModel> {
        self.model.as_ref()
    }

    /// Clears the model.
    pub fn clear(&mut self) {
        self.model = None;
    }

    /// Returns whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Sets the visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }
}

impl Default for SymbolReferenceProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbol_reference() {
        let mut r = SymbolReference::new(
            0x401000,
            0x402000,
            "CALL",
            ReferenceDirection::Outgoing,
        );
        assert_eq!(r.from_address(), 0x401000);
        assert_eq!(r.to_address(), 0x402000);
        assert_eq!(r.ref_type(), "CALL");
        assert_eq!(r.direction(), ReferenceDirection::Outgoing);

        r.set_from_label(Some("main".to_string()));
        assert_eq!(r.from_label(), Some("main"));
    }

    #[test]
    fn test_reference_model() {
        let mut model = SymbolReferenceModel::new(0x401000);
        model.add_reference(SymbolReference::new(
            0x401050,
            0x401000,
            "CALL",
            ReferenceDirection::Incoming,
        ));
        model.add_reference(SymbolReference::new(
            0x401000,
            0x402000,
            "JMP",
            ReferenceDirection::Outgoing,
        ));

        assert_eq!(model.reference_count(), 2);
        assert_eq!(model.incoming_references().len(), 1);
        assert_eq!(model.outgoing_references().len(), 1);
    }

    #[test]
    fn test_reference_model_clear() {
        let mut model = SymbolReferenceModel::new(0x401000);
        model.add_reference(SymbolReference::new(
            0x401050,
            0x401000,
            "CALL",
            ReferenceDirection::Incoming,
        ));
        model.clear();
        assert_eq!(model.reference_count(), 0);
    }

    #[test]
    fn test_reference_provider() {
        let mut provider = SymbolReferenceProvider::new();
        assert!(!provider.is_visible());
        assert!(provider.model().is_none());

        let model = SymbolReferenceModel::new(0x401000);
        provider.set_model(model);
        assert!(provider.model().is_some());

        provider.clear();
        assert!(provider.model().is_none());
    }
}
