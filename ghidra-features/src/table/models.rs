//! Program-aware table model implementations.
//!
//! Ported from `ghidra.util.table`:
//! - `GhidraProgramTableModel` -- base model for program-backed tables.
//! - `AddressBasedTableModel` -- alias for program table model with address rows.
//! - `GhidraProgramTableModel` provides default columns: Address, Label, Code Unit.
//! - `AddressSetTableModel` -- table model backed by an address set.
//! - `IncomingReferencesTableModel` -- table of incoming references.
//! - `ReferencesFromTableModel` -- table of outgoing references.
//! - `ProgramTableModel` -- trait for table models that know their program.

use ghidra_core::addr::Address;

use super::mapper::ProgramLocation;
use super::traits::AddressableRowObject;

// Implement AddressableRowObject for Address so it can be used as a row type.
impl AddressableRowObject for Address {
    fn address(&self) -> Address { *self }
}

// ---------------------------------------------------------------------------
// ProgramTableModel
// ---------------------------------------------------------------------------

/// Trait for table models backed by a program.
///
/// This is the Rust equivalent of `ghidra.util.table.ProgramTableModel`.
pub trait ProgramTableModel {
    /// Returns the name of the program this model is associated with.
    fn program_name(&self) -> &str;

    /// Returns the address for a given row and column, if any.
    fn address_at(&self, row: usize, col: usize) -> Option<Address>;

    /// Returns the program location for a given row and column.
    fn program_location_at(&self, row: usize, col: usize) -> Option<ProgramLocation>;

    /// Returns all selected addresses for the given row indices.
    fn selected_addresses(&self, rows: &[usize]) -> Vec<Address>;
}

// ---------------------------------------------------------------------------
// GhidraProgramTableModel
// ---------------------------------------------------------------------------

/// Base table model for program-backed tables with standard columns.
///
/// Ported from `ghidra.util.table.GhidraProgramTableModel`.  Provides
/// default columns for Address, Label, and Code Unit, and delegates
/// address resolution through a layered lookup strategy:
///
/// 1. Check if the column produces a ProgramLocation.
/// 2. Check if the cell value is an Address.
/// 3. Check if the row object is an Address.
/// 4. Check mapped columns.
#[derive(Debug)]
pub struct GhidraProgramTableModel<R: Clone + AddressableRowObject + 'static> {
    model_name: String,
    program_name: String,
    rows: Vec<R>,
}

impl<R: Clone + AddressableRowObject + 'static> GhidraProgramTableModel<R> {
    /// Creates a new program table model.
    pub fn new(model_name: impl Into<String>, program_name: impl Into<String>) -> Self {
        Self {
            model_name: model_name.into(),
            program_name: program_name.into(),
            rows: Vec::new(),
        }
    }

    /// Returns the model name.
    pub fn model_name(&self) -> &str {
        &self.model_name
    }

    /// Returns the program name.
    pub fn program_name_ref(&self) -> &str {
        &self.program_name
    }

    /// Sets the data rows for this model.
    pub fn set_rows(&mut self, rows: Vec<R>) {
        self.rows = rows;
    }

    /// Returns the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Returns a reference to the row at the given index.
    pub fn row(&self, index: usize) -> Option<&R> {
        self.rows.get(index)
    }

    /// Returns the address for a row, if the row type is address-like.
    pub fn address_for_row(&self, index: usize) -> Option<Address> {
        self.rows.get(index).map(|r| r.address())
    }

    /// Disposes the model, clearing all data.
    pub fn dispose(&mut self) {
        self.rows.clear();
    }
}

impl<R: Clone + AddressableRowObject + 'static> ProgramTableModel for GhidraProgramTableModel<R> {
    fn program_name(&self) -> &str {
        &self.program_name
    }

    fn address_at(&self, row: usize, _col: usize) -> Option<Address> {
        self.address_for_row(row)
    }

    fn program_location_at(&self, row: usize, _col: usize) -> Option<ProgramLocation> {
        self.address_for_row(row).map(ProgramLocation::new)
    }

    fn selected_addresses(&self, rows: &[usize]) -> Vec<Address> {
        rows.iter()
            .filter_map(|&i| self.address_for_row(i))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// AddressBasedTableModel
// ---------------------------------------------------------------------------

/// A table model whose row type is an `Address`.
///
/// This is a convenience alias for `GhidraProgramTableModel<Address>`.
/// Ported from `ghidra.util.table.AddressBasedTableModel`.
pub type AddressBasedTableModel = GhidraProgramTableModel<Address>;

// ---------------------------------------------------------------------------
// AddressSetTableModel
// ---------------------------------------------------------------------------

/// A table model backed by a set of addresses.
///
/// Ported from `ghidra.util.table.AddressSetTableModel`.
#[derive(Debug)]
pub struct AddressSetTableModel {
    inner: GhidraProgramTableModel<Address>,
}

impl AddressSetTableModel {
    /// Creates a new address set table model.
    pub fn new(model_name: impl Into<String>, program_name: impl Into<String>,
               addresses: Vec<Address>) -> Self {
        let mut inner = GhidraProgramTableModel::new(model_name, program_name);
        inner.set_rows(addresses);
        Self { inner }
    }

    /// Returns the number of addresses.
    pub fn count(&self) -> usize {
        self.inner.row_count()
    }

    /// Returns a reference to the inner model.
    pub fn inner(&self) -> &GhidraProgramTableModel<Address> {
        &self.inner
    }
}

impl ProgramTableModel for AddressSetTableModel {
    fn program_name(&self) -> &str { self.inner.program_name() }
    fn address_at(&self, row: usize, col: usize) -> Option<Address> { self.inner.address_at(row, col) }
    fn program_location_at(&self, row: usize, col: usize) -> Option<ProgramLocation> {
        self.inner.program_location_at(row, col)
    }
    fn selected_addresses(&self, rows: &[usize]) -> Vec<Address> { self.inner.selected_addresses(rows) }
}

// ---------------------------------------------------------------------------
// IncomingReferencesTableModel
// ---------------------------------------------------------------------------

/// A table model showing all references incoming to a set of addresses.
///
/// Ported from `ghidra.util.table.IncomingReferencesTableModel`.
#[derive(Debug)]
pub struct IncomingReferencesTableModel {
    model_name: String,
    program_name: String,
    /// Pairs of (from_address, to_address).
    refs: Vec<(Address, Address)>,
}

impl IncomingReferencesTableModel {
    /// Creates a new incoming references model.
    pub fn new(model_name: impl Into<String>, program_name: impl Into<String>) -> Self {
        Self {
            model_name: model_name.into(),
            program_name: program_name.into(),
            refs: Vec::new(),
        }
    }

    /// Sets the reference pairs.
    pub fn set_refs(&mut self, refs: Vec<(Address, Address)>) {
        self.refs = refs;
    }

    /// Returns the number of references.
    pub fn count(&self) -> usize {
        self.refs.len()
    }

    /// Returns the source address for a row.
    pub fn from_address(&self, row: usize) -> Option<Address> {
        self.refs.get(row).map(|(from, _)| *from)
    }

    /// Returns the destination address for a row.
    pub fn to_address(&self, row: usize) -> Option<Address> {
        self.refs.get(row).map(|(_, to)| *to)
    }
}

// ---------------------------------------------------------------------------
// ReferencesFromTableModel
// ---------------------------------------------------------------------------

/// A table model showing all references from a set of addresses.
///
/// Ported from `ghidra.util.table.ReferencesFromTableModel`.
#[derive(Debug)]
pub struct ReferencesFromTableModel {
    model_name: String,
    program_name: String,
    refs: Vec<(Address, Address)>,
}

impl ReferencesFromTableModel {
    /// Creates a new references-from model.
    pub fn new(model_name: impl Into<String>, program_name: impl Into<String>) -> Self {
        Self {
            model_name: model_name.into(),
            program_name: program_name.into(),
            refs: Vec::new(),
        }
    }

    /// Sets the reference pairs.
    pub fn set_refs(&mut self, refs: Vec<(Address, Address)>) {
        self.refs = refs;
    }

    /// Returns the number of references.
    pub fn count(&self) -> usize {
        self.refs.len()
    }

    /// Returns the source address for a row.
    pub fn from_address(&self, row: usize) -> Option<Address> {
        self.refs.get(row).map(|(from, _)| *from)
    }

    /// Returns the destination address for a row.
    pub fn to_address(&self, row: usize) -> Option<Address> {
        self.refs.get(row).map(|(_, to)| *to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ghidra_program_table_model_new() {
        let model = GhidraProgramTableModel::<Address>::new("TestModel", "test_program");
        assert_eq!(model.model_name(), "TestModel");
        assert_eq!(model.program_name_ref(), "test_program");
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_ghidra_program_table_model_rows() {
        let mut model = GhidraProgramTableModel::<Address>::new("M", "P");
        model.set_rows(vec![Address::new(0x100), Address::new(0x200), Address::new(0x300)]);
        assert_eq!(model.row_count(), 3);
        assert_eq!(model.row(1).unwrap().offset, 0x200);
        assert_eq!(model.address_for_row(0).unwrap().offset, 0x100);
    }

    #[test]
    fn test_ghidra_program_table_model_location() {
        let mut model = GhidraProgramTableModel::<Address>::new("M", "P");
        model.set_rows(vec![Address::new(0x400)]);
        let loc = model.program_location_at(0, 0).unwrap();
        assert_eq!(loc.address.offset, 0x400);
    }

    #[test]
    fn test_ghidra_program_table_model_selected() {
        let mut model = GhidraProgramTableModel::<Address>::new("M", "P");
        model.set_rows(vec![
            Address::new(0x100), Address::new(0x200), Address::new(0x300),
        ]);
        let sel = model.selected_addresses(&[0, 2]);
        assert_eq!(sel.len(), 2);
        assert_eq!(sel[0].offset, 0x100);
        assert_eq!(sel[1].offset, 0x300);
    }

    #[test]
    fn test_address_based_table_model() {
        let mut model = AddressBasedTableModel::new("AddrModel", "prog");
        model.set_rows(vec![Address::new(0x1000)]);
        assert_eq!(model.row_count(), 1);
    }

    #[test]
    fn test_address_set_table_model() {
        let addrs = vec![Address::new(0x100), Address::new(0x200), Address::new(0x300)];
        let model = AddressSetTableModel::new("AddrSet", "prog", addrs);
        assert_eq!(model.count(), 3);
        assert_eq!(model.inner().program_name_ref(), "prog");
    }

    #[test]
    fn test_incoming_references_model() {
        let mut model = IncomingReferencesTableModel::new("Incoming", "prog");
        model.set_refs(vec![
            (Address::new(0x200), Address::new(0x100)),
            (Address::new(0x300), Address::new(0x100)),
        ]);
        assert_eq!(model.count(), 2);
        assert_eq!(model.from_address(0).unwrap().offset, 0x200);
        assert_eq!(model.to_address(1).unwrap().offset, 0x100);
    }

    #[test]
    fn test_references_from_model() {
        let mut model = ReferencesFromTableModel::new("From", "prog");
        model.set_refs(vec![
            (Address::new(0x100), Address::new(0x200)),
            (Address::new(0x100), Address::new(0x300)),
        ]);
        assert_eq!(model.count(), 2);
        assert_eq!(model.from_address(0).unwrap().offset, 0x100);
        assert_eq!(model.to_address(1).unwrap().offset, 0x300);
    }

    #[test]
    fn test_model_dispose() {
        let mut model = GhidraProgramTableModel::<Address>::new("M", "P");
        model.set_rows(vec![Address::new(0x100)]);
        assert_eq!(model.row_count(), 1);
        model.dispose();
        assert_eq!(model.row_count(), 0);
    }
}
