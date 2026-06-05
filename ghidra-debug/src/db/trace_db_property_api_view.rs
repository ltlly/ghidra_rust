//! API view for the trace address property manager.
//!
//! Ported from Ghidra's `DBTraceAddressPropertyManagerApiView` in
//! `ghidra.trace.database.property`. Provides a clean public API over
//! the internal database-backed property manager, hiding implementation
//! details like locking and database record management.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};

use super::trace_db_property_impl::{DbTraceAddressPropertyManager, PropertyMapValue};

/// A property map exposed through the API view.
///
/// This is the public-facing view of a property map, hiding the
/// database internals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropertyMapApiView {
    /// Name of the property.
    pub name: String,
    /// The property type (bool, int, string, void, address).
    pub value_type: PropertyValueType,
}

/// The type of values in a property map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PropertyValueType {
    /// Boolean property.
    Bool,
    /// Integer property.
    Int,
    /// String property.
    String,
    /// Void (presence-only) property.
    Void,
    /// Address property.
    Address,
}

impl PropertyValueType {
    /// Get the type name as a string.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Bool => "Boolean",
            Self::Int => "Integer",
            Self::String => "String",
            Self::Void => "Void",
            Self::Address => "Address",
        }
    }
}

/// API view for the address property manager.
///
/// Provides read and write access to named property maps without
/// exposing the underlying database implementation.
///
/// Ported from Ghidra's `DBTraceAddressPropertyManagerApiView`.
/// Uses a default space name of "ram" for simple property management.
#[derive(Debug)]
pub struct PropertyManagerApiView {
    /// The underlying property manager.
    manager: Arc<RwLock<DbTraceAddressPropertyManager>>,
    /// The default space name.
    space_name: String,
}

impl PropertyManagerApiView {
    /// Create a new API view wrapping the given property manager.
    pub fn new(manager: Arc<RwLock<DbTraceAddressPropertyManager>>) -> Self {
        Self {
            manager,
            space_name: "ram".to_string(),
        }
    }

    /// Create with a specific space name.
    pub fn with_space(manager: Arc<RwLock<DbTraceAddressPropertyManager>>, space: impl Into<String>) -> Self {
        Self {
            manager,
            space_name: space.into(),
        }
    }

    /// Create a new property map with the given name and type.
    pub fn create_property_map(
        &self,
        name: &str,
        _value_type: PropertyValueType,
    ) -> Result<(), PropertyApiError> {
        let mut mgr = self
            .manager
            .write()
            .map_err(|_| PropertyApiError::LockError)?;
        mgr.get_or_create_map(&self.space_name, name);
        Ok(())
    }

    /// Get a property map by name.
    pub fn get_property_map(&self, name: &str) -> Result<Option<PropertyMapApiView>, PropertyApiError> {
        let mgr = self
            .manager
            .read()
            .map_err(|_| PropertyApiError::LockError)?;
        Ok(mgr.get_map(&self.space_name, name).map(|_| PropertyMapApiView {
            name: name.to_string(),
            value_type: PropertyValueType::Void, // Type is not stored on the map itself
        }))
    }

    /// Get or create a property map.
    pub fn get_or_create_property_map(
        &self,
        name: &str,
        _value_type: PropertyValueType,
    ) -> Result<PropertyMapApiView, PropertyApiError> {
        let mut mgr = self
            .manager
            .write()
            .map_err(|_| PropertyApiError::LockError)?;
        mgr.get_or_create_map(&self.space_name, name);
        Ok(PropertyMapApiView {
            name: name.to_string(),
            value_type: PropertyValueType::Void,
        })
    }

    /// Get all defined property names.
    pub fn get_all_property_names(&self) -> Result<Vec<String>, PropertyApiError> {
        let mgr = self
            .manager
            .read()
            .map_err(|_| PropertyApiError::LockError)?;
        Ok(mgr.map_names(&self.space_name).iter().map(|s| s.to_string()).collect())
    }

    /// Get all property maps.
    pub fn get_all_properties(&self) -> Result<BTreeMap<String, PropertyValueType>, PropertyApiError> {
        let names = self.get_all_property_names()?;
        Ok(names.into_iter().map(|n| (n, PropertyValueType::Void)).collect())
    }

    /// Set a boolean value in a property map at the given address.
    pub fn set_bool(
        &self,
        name: &str,
        address: u64,
        value: bool,
    ) -> Result<(), PropertyApiError> {
        let mut mgr = self
            .manager
            .write()
            .map_err(|_| PropertyApiError::LockError)?;
        mgr.set_bool(&self.space_name, name, address, value);
        Ok(())
    }

    /// Set an integer value in a property map at the given address.
    pub fn set_int(
        &self,
        name: &str,
        address: u64,
        value: i64,
    ) -> Result<(), PropertyApiError> {
        let mut mgr = self
            .manager
            .write()
            .map_err(|_| PropertyApiError::LockError)?;
        mgr.set_int(&self.space_name, name, address, value);
        Ok(())
    }

    /// Set a string value in a property map at the given address.
    pub fn set_string(
        &self,
        name: &str,
        address: u64,
        value: impl Into<String>,
    ) -> Result<(), PropertyApiError> {
        let mut mgr = self
            .manager
            .write()
            .map_err(|_| PropertyApiError::LockError)?;
        mgr.set_string(&self.space_name, name, address, value);
        Ok(())
    }

    /// Set a void (presence) value in a property map at the given address.
    pub fn set_void(
        &self,
        name: &str,
        address: u64,
    ) -> Result<(), PropertyApiError> {
        let mut mgr = self
            .manager
            .write()
            .map_err(|_| PropertyApiError::LockError)?;
        mgr.set_void(&self.space_name, name, address);
        Ok(())
    }

    /// Remove a value from a property map at the given address.
    pub fn remove_value(&self, name: &str, address: u64) -> Result<Option<PropertyMapValue>, PropertyApiError> {
        let mut mgr = self
            .manager
            .write()
            .map_err(|_| PropertyApiError::LockError)?;
        Ok(mgr.remove_property(&self.space_name, name, address))
    }

    /// Delete an entire property map.
    pub fn delete_property_map(&self, name: &str) -> Result<bool, PropertyApiError> {
        let mut mgr = self
            .manager
            .write()
            .map_err(|_| PropertyApiError::LockError)?;
        Ok(mgr.remove_map(&self.space_name, name).is_some())
    }

    /// Get the space name.
    pub fn space_name(&self) -> &str {
        &self.space_name
    }
}

/// Errors from the property manager API.
#[derive(Debug, Clone, thiserror::Error)]
pub enum PropertyApiError {
    /// Could not acquire the lock.
    #[error("Failed to acquire property manager lock")]
    LockError,
    /// Property map not found.
    #[error("Property map not found: {0}")]
    MapNotFound(String),
    /// Type mismatch.
    #[error("Type mismatch: expected {expected}, got {actual}")]
    TypeMismatch {
        /// Expected type name.
        expected: String,
        /// Actual type name.
        actual: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_api_view() -> PropertyManagerApiView {
        let mgr = DbTraceAddressPropertyManager::new();
        PropertyManagerApiView::new(Arc::new(RwLock::new(mgr)))
    }

    #[test]
    fn test_create_property_map() {
        let api = make_api_view();
        api.create_property_map("TestBool", PropertyValueType::Bool).unwrap();
        let map = api.get_property_map("TestBool").unwrap();
        assert!(map.is_some());
        assert_eq!(map.unwrap().name, "TestBool");
    }

    #[test]
    fn test_get_nonexistent_map() {
        let api = make_api_view();
        let map = api.get_property_map("NoMap").unwrap();
        assert!(map.is_none());
    }

    #[test]
    fn test_get_or_create() {
        let api = make_api_view();
        let map1 = api.get_or_create_property_map("TestInt", PropertyValueType::Int).unwrap();
        assert_eq!(map1.name, "TestInt");

        // Get existing
        let map2 = api.get_or_create_property_map("TestInt", PropertyValueType::Int).unwrap();
        assert_eq!(map2.name, "TestInt");
    }

    #[test]
    fn test_set_bool() {
        let api = make_api_view();
        api.create_property_map("Flag", PropertyValueType::Bool).unwrap();
        api.set_bool("Flag", 0x1000, true).unwrap();
    }

    #[test]
    fn test_set_int() {
        let api = make_api_view();
        api.create_property_map("Counter", PropertyValueType::Int).unwrap();
        api.set_int("Counter", 0x1000, 42).unwrap();
    }

    #[test]
    fn test_set_string() {
        let api = make_api_view();
        api.create_property_map("Label", PropertyValueType::String).unwrap();
        api.set_string("Label", 0x100, "hello").unwrap();
    }

    #[test]
    fn test_set_void() {
        let api = make_api_view();
        api.create_property_map("Bookmark", PropertyValueType::Void).unwrap();
        api.set_void("Bookmark", 0x200).unwrap();
    }

    #[test]
    fn test_remove_value() {
        let api = make_api_view();
        api.create_property_map("Flag", PropertyValueType::Bool).unwrap();
        api.set_bool("Flag", 0x2000, true).unwrap();
        let removed = api.remove_value("Flag", 0x2000).unwrap();
        assert!(removed.is_some());
    }

    #[test]
    fn test_delete_map() {
        let api = make_api_view();
        api.create_property_map("Old", PropertyValueType::Void).unwrap();
        assert!(api.delete_property_map("Old").unwrap());
        assert!(api.get_property_map("Old").unwrap().is_none());
    }

    #[test]
    fn test_all_property_names() {
        let api = make_api_view();
        api.create_property_map("A", PropertyValueType::Bool).unwrap();
        api.create_property_map("B", PropertyValueType::String).unwrap();
        let names = api.get_all_property_names().unwrap();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"A".to_string()));
        assert!(names.contains(&"B".to_string()));
    }

    #[test]
    fn test_all_properties_types() {
        let api = make_api_view();
        api.create_property_map("X", PropertyValueType::Int).unwrap();
        let props = api.get_all_properties().unwrap();
        assert!(props.contains_key("X"));
    }

    #[test]
    fn test_value_type_name() {
        assert_eq!(PropertyValueType::Bool.type_name(), "Boolean");
        assert_eq!(PropertyValueType::Int.type_name(), "Integer");
        assert_eq!(PropertyValueType::String.type_name(), "String");
        assert_eq!(PropertyValueType::Void.type_name(), "Void");
        assert_eq!(PropertyValueType::Address.type_name(), "Address");
    }

    #[test]
    fn test_with_space() {
        let mgr = DbTraceAddressPropertyManager::new();
        let api = PropertyManagerApiView::with_space(Arc::new(RwLock::new(mgr)), "register");
        assert_eq!(api.space_name(), "register");
    }
}
