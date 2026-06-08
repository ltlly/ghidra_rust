//! Base implementation for data types with common functionality.
//!
//! Ported from Ghidra's `AbstractDataType.java`. Provides default
//! implementations for many [`DataType`] trait methods so that concrete
//! type classes only need to implement the core identity and sizing logic.

use std::fmt;
use std::sync::Arc;

use super::types::DataType;
use super::{CategoryPath, DataOrganization};

// ============================================================================
// AbstractDataType — base for all data type implementations
// ============================================================================

/// Base struct providing common fields and default behavior for data types.
///
/// Mirrors Ghidra's `AbstractDataType` abstract class. Concrete data type
/// structs can embed this as a field or use its methods directly to get
/// standard implementations of the [`DataType`] trait's default methods.
///
/// # Usage
///
/// ```rust
/// use ghidra_core::data::{AbstractDataType, CategoryPath};
///
/// let base = AbstractDataType::new(CategoryPath::new("my"), "MyType");
/// assert_eq!(base.name, "MyType");
/// assert_eq!(format!("{}/{}", base.category_path.display_name(), base.name), "/my/MyType");
/// ```
#[derive(Debug, Clone)]
pub struct AbstractDataType {
    /// The type name.
    pub name: String,
    /// The category path in a type manager.
    pub category_path: CategoryPath,
    /// Optional description.
    pub description: String,
    /// The data organization (type sizes, endianness) if known.
    pub data_organization: Option<DataOrganization>,
}

impl AbstractDataType {
    /// Create a new abstract data type with the given category path and name.
    ///
    /// # Panics
    ///
    /// Panics if `name` is empty.
    pub fn new(category_path: CategoryPath, name: impl Into<String>) -> Self {
        let name = name.into();
        assert!(!name.is_empty(), "DataType name must not be empty");
        Self {
            name,
            category_path,
            description: String::new(),
            data_organization: None,
        }
    }

    /// Create with a description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Create with a data organization.
    pub fn with_organization(mut self, org: DataOrganization) -> Self {
        self.data_organization = Some(org);
        self
    }

    /// Get the display name (same as name for most types).
    pub fn get_display_name(&self) -> &str {
        &self.name
    }

    /// Get the mnemonic for this data type.
    pub fn get_mnemonic(&self, _settings: Option<&str>) -> &str {
        &self.name
    }

    /// Returns `true` if this type has not yet been fully defined.
    pub fn is_not_yet_defined(&self) -> bool {
        false
    }

    /// Returns `true` if this type is defined with zero length.
    pub fn is_zero_length(&self) -> bool {
        false
    }

    /// Returns `true` if this type has been deleted.
    pub fn is_deleted(&self) -> bool {
        false
    }

    /// Indicates if the length is language/compiler dependent.
    pub fn has_language_dependent_length(&self) -> bool {
        false
    }

    /// Returns the default label prefix for display.
    pub fn get_default_label_prefix(&self) -> Option<&str> {
        None
    }

    /// Returns the abbreviated label prefix.
    pub fn get_default_abbreviated_label_prefix(&self) -> Option<&str> {
        self.get_default_label_prefix()
    }

    /// Check if this type depends on another type's existence.
    pub fn depends_on(&self, _dt: &dyn DataType) -> bool {
        false
    }

    /// Notification that a dependent type's size changed.
    pub fn data_type_size_changed(&mut self, _dt: &dyn DataType) {}

    /// Notification that a dependent type's alignment changed.
    pub fn data_type_alignment_changed(&mut self, _dt: &dyn DataType) {}

    /// Notification that a dependent type was deleted.
    pub fn data_type_deleted(&mut self, _dt: &dyn DataType) {}

    /// Notification that a dependent type was replaced.
    pub fn data_type_replaced(&mut self, _old_dt: &dyn DataType, _new_dt: &dyn DataType) {}

    /// Add a parent reference.
    pub fn add_parent(&mut self, _dt: &dyn DataType) {}

    /// Remove a parent reference.
    pub fn remove_parent(&mut self, _dt: &dyn DataType) {}

    /// Get the parents of this type.
    pub fn get_parents(&self) -> Vec<Arc<dyn DataType>> {
        Vec::new()
    }

    /// Set the description.
    pub fn set_description(&mut self, description: impl Into<String>) {
        self.description = description.into();
    }

    /// Set the category path.
    pub fn set_category_path(&mut self, path: CategoryPath) {
        self.category_path = path;
    }

    /// Set the name.
    pub fn set_name(&mut self, name: impl Into<String>) {
        self.name = name.into();
    }

    /// Set both name and category path.
    pub fn set_name_and_category(&mut self, path: CategoryPath, name: impl Into<String>) {
        self.category_path = path;
        self.name = name.into();
    }

    /// Replace the internals of this type with another.
    ///
    /// Default implementation does nothing. Concrete types should override.
    pub fn replace_with(&mut self, _other: &dyn DataType) {}

    /// Get the [`DataOrganization`] for this type.
    pub fn get_data_organization(&self) -> Option<&DataOrganization> {
        self.data_organization.as_ref()
    }
}

impl fmt::Display for AbstractDataType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abstract_data_type_new() {
        let base = AbstractDataType::new(CategoryPath::new("test"), "MyType");
        assert_eq!(base.name(), "MyType");
        assert_eq!(base.get_path_name(), "/test/MyType");
    }

    #[test]
    fn test_abstract_data_type_root() {
        let base = AbstractDataType::new(CategoryPath::ROOT, "RootType");
        assert_eq!(base.get_path_name(), "/RootType");
    }

    #[test]
    fn test_abstract_data_type_with_description() {
        let base = AbstractDataType::new(CategoryPath::ROOT, "T")
            .with_description("A test type");
        assert_eq!(base.description, "A test type");
    }

    #[test]
    fn test_abstract_data_type_set_name() {
        let mut base = AbstractDataType::new(CategoryPath::ROOT, "Old");
        base.set_name("New");
        assert_eq!(base.name(), "New");
    }

    #[test]
    fn test_abstract_data_type_set_category() {
        let mut base = AbstractDataType::new(CategoryPath::ROOT, "T");
        base.set_category_path(CategoryPath::new("other"));
        assert_eq!(base.get_path_name(), "/other/T");
    }

    #[test]
    fn test_abstract_data_type_defaults() {
        let base = AbstractDataType::new(CategoryPath::ROOT, "T");
        assert!(!base.is_not_yet_defined());
        assert!(!base.is_zero_length());
        assert!(!base.is_deleted());
        assert!(!base.has_language_dependent_length());
        assert!(!base.depends_on(&base));
        assert!(base.get_parents().is_empty());
        assert!(base.get_default_label_prefix().is_none());
    }

    #[test]
    fn test_abstract_data_type_display() {
        let base = AbstractDataType::new(CategoryPath::ROOT, "Display");
        assert_eq!(format!("{}", base), "Display");
    }

    #[test]
    #[should_panic(expected = "DataType name must not be empty")]
    fn test_abstract_data_type_empty_name_panics() {
        AbstractDataType::new(CategoryPath::ROOT, "");
    }

    #[test]
    fn test_abstract_data_type_with_organization() {
        let org = DataOrganization::default_32bit_le();
        let base = AbstractDataType::new(CategoryPath::ROOT, "T")
            .with_organization(org.clone());
        assert!(base.get_data_organization().is_some());
        assert_eq!(base.get_data_organization().unwrap().get_pointer_size(), 4);
    }

    #[test]
    fn test_abstract_data_type_set_name_and_category() {
        let mut base = AbstractDataType::new(CategoryPath::ROOT, "Old");
        base.set_name_and_category(CategoryPath::new("ns"), "New");
        assert_eq!(base.name(), "New");
        assert_eq!(base.get_path_name(), "/ns/New");
    }

    // Implement DataType trait for AbstractDataType to test trait methods.
    impl DataType for AbstractDataType {
        fn as_any(&self) -> &dyn std::any::Any { self }
        fn name(&self) -> &str { &self.name }
        fn description(&self) -> &str { &self.description }
        fn get_size(&self) -> usize { 0 }
        fn clone_type(&self) -> Box<dyn DataType> { Box::new(self.clone()) }
        fn get_category_path(&self) -> &CategoryPath { &self.category_path }
        fn set_category_path(&mut self, path: CategoryPath) { self.category_path = path; }
    }

    #[test]
    fn test_abstract_data_type_as_trait_object() {
        let base = AbstractDataType::new(CategoryPath::new("test"), "Dyn");
        let dt: &dyn DataType = &base;
        assert_eq!(dt.name(), "Dyn");
        assert_eq!(dt.get_size(), 0);
        assert_eq!(dt.get_path_name(), "/test/Dyn");
    }
}
