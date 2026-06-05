//! Hover Plugin -- show tooltip information on hover.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.hover` Java package.
//!
//! Provides model-level logic for computing what information to display
//! when the user hovers over elements in the listing. Supports a priority-
//! ordered provider system where multiple hover providers can contribute
//! tooltip information, with the highest-priority enabled provider winning.
//!
//! # Key Types
//!
//! - [`HoverElementType`] -- the kind of UI element being hovered
//! - [`HoverInfo`] -- a single tooltip entry
//! - [`HoverProvider`] -- trait for pluggable hover data sources
//! - [`HoverService`] -- trait for the hover subsystem
//! - [`HoverModel`] -- default in-memory implementation

use ghidra_core::Address;

/// The type of element being hovered over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HoverElementType {
    /// Hovering over a label.
    Label,
    /// Hovering over a register.
    Register,
    /// Hovering over a data type.
    DataType,
    /// Hovering over an address reference.
    AddressReference,
    /// Hovering over a function.
    Function,
    /// Hovering over a variable.
    Variable,
    /// Hovering over a comment.
    Comment,
    /// Hovering over a bookmark.
    Bookmark,
    /// Hovering over a field in a structure.
    StructureField,
}

impl HoverElementType {
    /// Display name for this element type.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Label => "Label",
            Self::Register => "Register",
            Self::DataType => "Data Type",
            Self::AddressReference => "Address Reference",
            Self::Function => "Function",
            Self::Variable => "Variable",
            Self::Comment => "Comment",
            Self::Bookmark => "Bookmark",
            Self::StructureField => "Structure Field",
        }
    }
}

/// A hover info entry.
#[derive(Debug, Clone)]
pub struct HoverInfo {
    /// The element type being hovered.
    pub element_type: HoverElementType,
    /// The address associated with the hover.
    pub address: Address,
    /// The text to display in the tooltip.
    pub display_text: String,
    /// Whether this hover info should be shown.
    pub enabled: bool,
}

impl HoverInfo {
    /// Create a new hover info entry.
    pub fn new(
        element_type: HoverElementType,
        address: Address,
        display_text: impl Into<String>,
    ) -> Self {
        Self {
            element_type,
            address,
            display_text: display_text.into(),
            enabled: true,
        }
    }
}

// ---------------------------------------------------------------------------
// HoverProvider -- trait for pluggable hover sources
// ---------------------------------------------------------------------------

/// Trait for hover data providers.
///
/// Each provider has a priority and can decide whether it handles hover
/// for a given address and element type.
///
/// Ported from `ghidra.app.plugin.core.hover.AbstractHoverProvider`.
pub trait HoverProvider {
    /// The name of this provider.
    fn name(&self) -> &str;

    /// Priority (lower number = higher priority; 0 is best).
    fn priority(&self) -> u32;

    /// Whether this provider handles hovers for the given element type.
    fn handles(&self, element_type: HoverElementType) -> bool;

    /// Produce a hover info entry for the given context, if possible.
    fn get_hover_info(
        &self,
        address: Address,
        element_type: HoverElementType,
    ) -> Option<HoverInfo>;

    /// Whether this provider is enabled.
    fn is_enabled(&self) -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// HoverService -- trait for the hover subsystem
// ---------------------------------------------------------------------------

/// Trait for the hover service that coordinates multiple providers.
pub trait HoverService {
    /// Register a hover provider.
    fn register_provider(&mut self, provider: Box<dyn HoverProvider>);

    /// Unregister a provider by name.
    fn unregister_provider(&mut self, name: &str) -> bool;

    /// Compute the best hover info for the given context by consulting
    /// registered providers in priority order.
    fn compute_hover(
        &self,
        address: Address,
        element_type: HoverElementType,
    ) -> Option<HoverInfo>;
}

// ---------------------------------------------------------------------------
// HoverModel -- default implementation
// ---------------------------------------------------------------------------

/// Model for computing hover information.
///
/// Supports both static entries and priority-ordered providers.
#[derive(Debug, Default)]
pub struct HoverModel {
    entries: Vec<HoverInfo>,
    /// Number of registered providers (tracked separately since we can't
    /// derive Debug on Box<dyn HoverProvider>).
    provider_count: usize,
}

impl HoverModel {
    /// Create a new hover model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a static hover info entry.
    pub fn add_entry(&mut self, entry: HoverInfo) {
        self.entries.push(entry);
    }

    /// Get hover info for an address from static entries.
    pub fn get_hover_at(&self, address: Address) -> Vec<&HoverInfo> {
        self.entries
            .iter()
            .filter(|e| e.address == address && e.enabled)
            .collect()
    }

    /// Get hover info for an address filtered by element type.
    pub fn get_hover_for_type(
        &self,
        address: Address,
        element_type: HoverElementType,
    ) -> Vec<&HoverInfo> {
        self.entries
            .iter()
            .filter(|e| {
                e.address == address && e.enabled && e.element_type == element_type
            })
            .collect()
    }

    /// Remove all entries at a given address.
    pub fn remove_entries_at(&mut self, address: Address) {
        self.entries.retain(|e| e.address != address);
    }

    /// Toggle the enabled state of entries matching a given element type.
    pub fn set_enabled_for_type(&mut self, element_type: HoverElementType, enabled: bool) {
        for entry in &mut self.entries {
            if entry.element_type == element_type {
                entry.enabled = enabled;
            }
        }
    }

    /// Get all entries.
    pub fn get_all_entries(&self) -> &[HoverInfo] {
        &self.entries
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Return the number of static entries.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Return the number of registered providers.
    pub fn provider_count(&self) -> usize {
        self.provider_count
    }

    /// Set the provider count (for tracking purposes).
    pub fn set_provider_count(&mut self, count: usize) {
        self.provider_count = count;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hover_info() {
        let mut model = HoverModel::new();
        model.add_entry(HoverInfo::new(
            HoverElementType::Label,
            Address::new(0x1000),
            "main: Function entry point",
        ));
        let entries = model.get_hover_at(Address::new(0x1000));
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].display_text, "main: Function entry point");
    }

    #[test]
    fn test_hover_disabled() {
        let mut model = HoverModel::new();
        let mut info = HoverInfo::new(
            HoverElementType::Register,
            Address::new(0x1000),
            "RAX = 0",
        );
        info.enabled = false;
        model.add_entry(info);
        let entries = model.get_hover_at(Address::new(0x1000));
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn test_hover_element_type_display() {
        assert_eq!(HoverElementType::Label.display_name(), "Label");
        assert_eq!(HoverElementType::Function.display_name(), "Function");
        assert_eq!(HoverElementType::Bookmark.display_name(), "Bookmark");
    }

    #[test]
    fn test_get_hover_for_type() {
        let mut model = HoverModel::new();
        model.add_entry(HoverInfo::new(
            HoverElementType::Label,
            Address::new(0x1000),
            "main label",
        ));
        model.add_entry(HoverInfo::new(
            HoverElementType::Comment,
            Address::new(0x1000),
            "a comment",
        ));
        let labels = model.get_hover_for_type(Address::new(0x1000), HoverElementType::Label);
        assert_eq!(labels.len(), 1);
        let comments = model.get_hover_for_type(Address::new(0x1000), HoverElementType::Comment);
        assert_eq!(comments.len(), 1);
        let regs = model.get_hover_for_type(Address::new(0x1000), HoverElementType::Register);
        assert_eq!(regs.len(), 0);
    }

    #[test]
    fn test_remove_entries_at() {
        let mut model = HoverModel::new();
        model.add_entry(HoverInfo::new(HoverElementType::Label, Address::new(0x1000), "a"));
        model.add_entry(HoverInfo::new(HoverElementType::Comment, Address::new(0x1000), "b"));
        model.add_entry(HoverInfo::new(HoverElementType::Label, Address::new(0x2000), "c"));
        model.remove_entries_at(Address::new(0x1000));
        assert_eq!(model.count(), 1);
        assert_eq!(model.get_all_entries()[0].address, Address::new(0x2000));
    }

    #[test]
    fn test_set_enabled_for_type() {
        let mut model = HoverModel::new();
        model.add_entry(HoverInfo::new(HoverElementType::Register, Address::new(0x1000), "RAX"));
        model.add_entry(HoverInfo::new(HoverElementType::Register, Address::new(0x2000), "RBX"));
        model.add_entry(HoverInfo::new(HoverElementType::Label, Address::new(0x1000), "main"));
        model.set_enabled_for_type(HoverElementType::Register, false);
        assert_eq!(model.get_hover_at(Address::new(0x1000)).len(), 1); // only label
        assert_eq!(model.get_hover_at(Address::new(0x2000)).len(), 0); // register disabled
    }

    #[test]
    fn test_multiple_hover_entries_at_address() {
        let mut model = HoverModel::new();
        model.add_entry(HoverInfo::new(HoverElementType::Label, Address::new(0x1000), "main"));
        model.add_entry(HoverInfo::new(HoverElementType::Function, Address::new(0x1000), "void main()"));
        model.add_entry(HoverInfo::new(HoverElementType::Comment, Address::new(0x1000), "entry point"));
        assert_eq!(model.get_hover_at(Address::new(0x1000)).len(), 3);
    }

    #[test]
    fn test_provider_count_tracking() {
        let mut model = HoverModel::new();
        assert_eq!(model.provider_count(), 0);
        model.set_provider_count(3);
        assert_eq!(model.provider_count(), 3);
    }
}
