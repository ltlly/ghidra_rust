//! Location references service and panel model.
//!
//! Ported from Ghidra's
//! `ghidra.app.plugin.core.navigation.locationreferences` package.
//!
//! Provides the service interface and panel/table model for the
//! "Find References To" feature.
//!
//! # Key Types
//!
//! - [`LocationReferencesService`] -- trait for finding references
//! - [`LocationReferencesPanelModel`] -- table model for search results
//! - [`LocationReferenceRowMapper`] -- maps row objects to different views
//! - [`LocationReferencesHighlighter`] -- highlights references in the listing

use ghidra_core::Address;

use super::locationreferences::{DescriptorKind, LocationDescriptor, LocationReference};

// ---------------------------------------------------------------------------
// LocationReferencesService
// ---------------------------------------------------------------------------

/// Service interface for finding references to program locations.
///
/// Ported from `ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesService`.
///
/// This service is used by the "Find References To" action to search
/// for all references to the entity at the current cursor location.
pub trait LocationReferencesService: Send + Sync {
    /// Find all references to the entity described by the given descriptor.
    fn find_references(&self, descriptor: &LocationDescriptor) -> Vec<LocationReference>;

    /// Check whether the service can find references for the given descriptor kind.
    fn supports_kind(&self, kind: &DescriptorKind) -> bool;

    /// Get all supported descriptor kinds.
    fn supported_kinds(&self) -> Vec<DescriptorKind>;
}

// ---------------------------------------------------------------------------
// LocationReferencesPanelModel
// ---------------------------------------------------------------------------

/// Table model for displaying location reference search results.
///
/// Ported from `ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesTableModel`.
#[derive(Debug)]
pub struct LocationReferencesPanelModel {
    /// The collected references.
    references: Vec<LocationReference>,
    /// The kind of entity being referenced.
    kind: DescriptorKind,
    /// The label for the entity.
    label: String,
    /// Column headers.
    columns: Vec<String>,
    /// Whether the search is complete.
    complete: bool,
    /// Whether the search was cancelled.
    cancelled: bool,
}

impl LocationReferencesPanelModel {
    /// Column index for the address.
    pub const ADDRESS_COL: usize = 0;
    /// Column index for the reference type.
    pub const REF_TYPE_COL: usize = 1;
    /// Column index for the context/code snippet.
    pub const CONTEXT_COL: usize = 2;
    /// Column index for the function name.
    pub const FUNCTION_COL: usize = 3;
    /// Column index for whether this is an offcut reference.
    pub const OFFCUT_COL: usize = 4;

    /// Create a new panel model.
    pub fn new(kind: DescriptorKind, label: impl Into<String>) -> Self {
        Self {
            references: Vec::new(),
            kind,
            label: label.into(),
            columns: vec![
                "Address".into(),
                "Ref Type".into(),
                "Context".into(),
                "Function".into(),
                "Offcut".into(),
            ],
            complete: false,
            cancelled: false,
        }
    }

    /// Set the references (e.g., after a search completes).
    pub fn set_references(&mut self, refs: Vec<LocationReference>) {
        self.references = refs;
    }

    /// Get all references.
    pub fn references(&self) -> &[LocationReference] {
        &self.references
    }

    /// Number of references.
    pub fn row_count(&self) -> usize {
        self.references.len()
    }

    /// Get the column count.
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Get the column name at the given index.
    pub fn column_name(&self, col: usize) -> &str {
        self.columns.get(col).map(|s| s.as_str()).unwrap_or("")
    }

    /// Get a reference at the given row index.
    pub fn get_row(&self, row: usize) -> Option<&LocationReference> {
        self.references.get(row)
    }

    /// Get the value at a specific cell.
    pub fn get_value_at(&self, row: usize, col: usize) -> Option<String> {
        let reference = self.references.get(row)?;
        match col {
            Self::ADDRESS_COL => Some(format!("{:#x}", reference.location_of_use().offset)),
            Self::REF_TYPE_COL => Some(reference.ref_type_string().to_string()),
            Self::CONTEXT_COL => reference.context().map(|s| s.to_string()),
            Self::FUNCTION_COL => reference.field_name().map(|s| s.to_string()),
            Self::OFFCUT_COL => Some(reference.is_offcut_reference().to_string()),
            _ => None,
        }
    }

    /// The kind of entity being referenced.
    pub fn kind(&self) -> &DescriptorKind {
        &self.kind
    }

    /// The label for the entity.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Mark the search as complete.
    pub fn set_complete(&mut self, complete: bool) {
        self.complete = complete;
    }

    /// Whether the search is complete.
    pub fn is_complete(&self) -> bool {
        self.complete
    }

    /// Mark the search as cancelled.
    pub fn set_cancelled(&mut self, cancelled: bool) {
        self.cancelled = cancelled;
    }

    /// Whether the search was cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Clear all references.
    pub fn clear(&mut self) {
        self.references.clear();
        self.complete = false;
        self.cancelled = false;
    }

    /// Add a reference to the model.
    pub fn add_reference(&mut self, reference: LocationReference) {
        self.references.push(reference);
    }

    /// Get the address of a specific row.
    pub fn get_address(&self, row: usize) -> Option<Address> {
        self.references
            .get(row)
            .map(|r| r.location_of_use())
    }
}

// ---------------------------------------------------------------------------
// LocationReferenceRowMapper
// ---------------------------------------------------------------------------

/// Maps a location reference to an address for table display.
///
/// Ported from `ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceToAddressTableRowMapper`.
#[derive(Debug)]
pub struct LocationReferenceToAddressMapper;

impl LocationReferenceToAddressMapper {
    /// Map a location reference to its address.
    pub fn map_to_address(reference: &LocationReference) -> Address {
        reference.location_of_use()
    }
}

/// Maps a location reference to its containing function name.
///
/// Ported from `ghidra.app.plugin.core.navigation.locationreferences.LocationReferenceToFunctionContainingTableRowMapper`.
#[derive(Debug)]
pub struct LocationReferenceToFunctionMapper;

impl LocationReferenceToFunctionMapper {
    /// Map a location reference to its field name (representing function context).
    pub fn map_to_function(reference: &LocationReference) -> Option<&str> {
        reference.field_name()
    }
}

// ---------------------------------------------------------------------------
// LocationReferencesHighlighter
// ---------------------------------------------------------------------------

/// Highlights referenced addresses in the listing.
///
/// Ported from `ghidra.app.plugin.core.navigation.locationreferences.LocationReferencesHighlighter`.
#[derive(Debug)]
pub struct LocationReferencesHighlighter {
    /// Addresses to highlight.
    addresses: Vec<Address>,
    /// Whether the highlighter is active.
    active: bool,
}

impl LocationReferencesHighlighter {
    /// Create a new highlighter.
    pub fn new() -> Self {
        Self {
            addresses: Vec::new(),
            active: false,
        }
    }

    /// Set the addresses to highlight.
    pub fn set_addresses(&mut self, addresses: Vec<Address>) {
        self.addresses = addresses;
    }

    /// Activate the highlighter.
    pub fn activate(&mut self) {
        self.active = true;
    }

    /// Deactivate the highlighter.
    pub fn deactivate(&mut self) {
        self.active = false;
        self.addresses.clear();
    }

    /// Whether the highlighter is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get the highlighted addresses.
    pub fn addresses(&self) -> &[Address] {
        &self.addresses
    }

    /// Whether an address should be highlighted.
    pub fn is_highlighted(&self, address: Address) -> bool {
        self.active && self.addresses.contains(&address)
    }
}

impl Default for LocationReferencesHighlighter {
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
    use super::super::locationreferences::DescriptorKind;

    fn make_ref(addr: u64, ref_type: &str, offcut: bool) -> LocationReference {
        LocationReference::with_ref_type(Address::new(addr), ref_type, offcut)
    }

    #[test]
    fn test_panel_model_creation() {
        let model = LocationReferencesPanelModel::new(DescriptorKind::Address, "0x1000");
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.column_count(), 5);
        assert_eq!(model.label(), "0x1000");
        assert!(!model.is_complete());
        assert!(!model.is_cancelled());
    }

    #[test]
    fn test_panel_model_column_names() {
        let model = LocationReferencesPanelModel::new(DescriptorKind::Label, "myLabel");
        assert_eq!(model.column_name(0), "Address");
        assert_eq!(model.column_name(1), "Ref Type");
        assert_eq!(model.column_name(2), "Context");
        assert_eq!(model.column_name(3), "Function");
        assert_eq!(model.column_name(4), "Offcut");
        assert_eq!(model.column_name(5), ""); // out of bounds
    }

    #[test]
    fn test_panel_model_set_references() {
        let mut model = LocationReferencesPanelModel::new(DescriptorKind::Address, "0x1000");
        model.set_references(vec![
            make_ref(0x1000, "READ", false),
            make_ref(0x2000, "WRITE", true),
        ]);
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_panel_model_get_value_at() {
        let mut model = LocationReferencesPanelModel::new(DescriptorKind::Address, "0x1000");
        model.set_references(vec![make_ref(0x1000, "READ", false)]);

        let addr_val = model.get_value_at(0, 0);
        assert!(addr_val.is_some());
        assert!(addr_val.unwrap().contains("1000"));

        let ref_type_val = model.get_value_at(0, 1);
        assert_eq!(ref_type_val.as_deref(), Some("READ"));

        let offcut_val = model.get_value_at(0, 4);
        assert_eq!(offcut_val.as_deref(), Some("false"));
    }

    #[test]
    fn test_panel_model_out_of_bounds() {
        let model = LocationReferencesPanelModel::new(DescriptorKind::Address, "0x1000");
        assert!(model.get_row(0).is_none());
        assert!(model.get_value_at(0, 0).is_none());
    }

    #[test]
    fn test_panel_model_complete_cancelled() {
        let mut model = LocationReferencesPanelModel::new(DescriptorKind::Address, "test");
        model.set_complete(true);
        assert!(model.is_complete());

        model.set_cancelled(true);
        assert!(model.is_cancelled());
    }

    #[test]
    fn test_panel_model_clear() {
        let mut model = LocationReferencesPanelModel::new(DescriptorKind::Address, "test");
        model.set_references(vec![make_ref(0x1000, "READ", false)]);
        model.set_complete(true);

        model.clear();
        assert_eq!(model.row_count(), 0);
        assert!(!model.is_complete());
    }

    #[test]
    fn test_panel_model_add_reference() {
        let mut model = LocationReferencesPanelModel::new(DescriptorKind::Label, "myLabel");
        model.add_reference(make_ref(0x1000, "READ", false));
        model.add_reference(make_ref(0x2000, "WRITE", true));
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_panel_model_get_address() {
        let mut model = LocationReferencesPanelModel::new(DescriptorKind::Address, "test");
        model.set_references(vec![make_ref(0x4000, "READ", false)]);

        assert_eq!(model.get_address(0), Some(Address::new(0x4000)));
        assert_eq!(model.get_address(1), None);
    }

    #[test]
    fn test_row_mapper_to_address() {
        let reference = make_ref(0x5000, "READ", false);
        let addr = LocationReferenceToAddressMapper::map_to_address(&reference);
        assert_eq!(addr, Address::new(0x5000));
    }

    #[test]
    fn test_row_mapper_to_function() {
        let reference = LocationReference::with_field_name(
            Address::new(0x5000), "READ", false, "main",
        );
        let func = LocationReferenceToFunctionMapper::map_to_function(&reference);
        assert_eq!(func, Some("main"));
    }

    #[test]
    fn test_highlighter() {
        let mut hl = LocationReferencesHighlighter::new();
        assert!(!hl.is_active());
        assert!(hl.addresses().is_empty());

        hl.set_addresses(vec![Address::new(0x1000), Address::new(0x2000)]);
        hl.activate();
        assert!(hl.is_active());
        assert!(hl.is_highlighted(Address::new(0x1000)));
        assert!(hl.is_highlighted(Address::new(0x2000)));
        assert!(!hl.is_highlighted(Address::new(0x3000)));

        hl.deactivate();
        assert!(!hl.is_active());
        assert!(!hl.is_highlighted(Address::new(0x1000)));
    }
}
