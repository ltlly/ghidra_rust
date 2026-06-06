//! Field format model -- ported from `ghidra.app.util.viewer.format`.
//!
//! Manages the layout and ordering of field factories in the listing display.

use crate::viewer::field::FieldFactory;

/// A field format model that manages the layout of fields in the listing.
///
/// Ported from `FieldFormatModel.java`.
#[derive(Debug)]
pub struct FieldFormatModel {
    /// The name of this format model (e.g., "Listing Fields").
    name: String,
    /// The ordered list of field factories.
    factories: Vec<Box<dyn FieldFactory>>,
    /// The current row within the model.
    current_row: usize,
}

impl FieldFormatModel {
    /// Create a new field format model.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            factories: Vec::new(),
            current_row: 0,
        }
    }

    /// Get the model name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Add a field factory to the model.
    pub fn add_factory(&mut self, factory: Box<dyn FieldFactory>) {
        self.factories.push(factory);
    }

    /// Remove a field factory by name.
    pub fn remove_factory(&mut self, name: &str) {
        self.factories.retain(|f| f.name() != name);
    }

    /// Get the number of factories.
    pub fn num_factories(&self) -> usize {
        self.factories.len()
    }

    /// Get a factory by index.
    pub fn factory_at(&self, index: usize) -> Option<&dyn FieldFactory> {
        self.factories.get(index).map(|f| f.as_ref())
    }

    /// Get a factory by name.
    pub fn factory_by_name(&self, name: &str) -> Option<&dyn FieldFactory> {
        self.factories.iter().find(|f| f.name() == name).map(|f| f.as_ref())
    }

    /// Get the current row.
    pub fn current_row(&self) -> usize {
        self.current_row
    }

    /// Set the current row.
    pub fn set_current_row(&mut self, row: usize) {
        self.current_row = row;
    }

    /// Get all factory names.
    pub fn factory_names(&self) -> Vec<&str> {
        self.factories.iter().map(|f| f.name()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::viewer::field::address_field_factory::AddressFieldFactory;
    use crate::viewer::field::mnemonic_field_factory::MnemonicFieldFactory;

    #[test]
    fn test_format_model() {
        let mut model = FieldFormatModel::new("Listing");
        assert_eq!(model.name(), "Listing");
        assert_eq!(model.num_factories(), 0);

        model.add_factory(Box::new(AddressFieldFactory::new()));
        model.add_factory(Box::new(MnemonicFieldFactory::new()));
        assert_eq!(model.num_factories(), 2);
    }

    #[test]
    fn test_factory_by_name() {
        let mut model = FieldFormatModel::new("Listing");
        model.add_factory(Box::new(AddressFieldFactory::new()));
        assert!(model.factory_by_name("Address").is_some());
        assert!(model.factory_by_name("Missing").is_none());
    }

    #[test]
    fn test_remove_factory() {
        let mut model = FieldFormatModel::new("Listing");
        model.add_factory(Box::new(AddressFieldFactory::new()));
        model.remove_factory("Address");
        assert_eq!(model.num_factories(), 0);
    }
}
