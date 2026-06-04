//! DataTypePropertyManager -- ported from `DataTypePropertyManager.java`.
//!
//! Manages properties associated with data types, such as display
//! format, alignment, and other metadata.

use std::collections::HashMap;
use std::fmt;

/// The property key for data type display settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DataTypeProperty {
    /// Display numbers in hex.
    HexDisplay,
    /// Show comments in the data type.
    ShowComments,
    /// The alignment override.
    Alignment,
    /// The minimum alignment.
    MinAlignment,
    /// The maximum alignment.
    MaxAlignment,
    /// Whether the type is opaque (hides internal structure).
    Opaque,
    /// A custom user-defined property.
    Custom,
}

impl fmt::Display for DataTypeProperty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HexDisplay => write!(f, "HexDisplay"),
            Self::ShowComments => write!(f, "ShowComments"),
            Self::Alignment => write!(f, "Alignment"),
            Self::MinAlignment => write!(f, "MinAlignment"),
            Self::MaxAlignment => write!(f, "MaxAlignment"),
            Self::Opaque => write!(f, "Opaque"),
            Self::Custom => write!(f, "Custom"),
        }
    }
}

/// The value of a data type property.
#[derive(Debug, Clone)]
pub enum PropertyValue {
    /// A boolean value.
    Bool(bool),
    /// An integer value.
    Int(i64),
    /// A string value.
    String(String),
}

impl fmt::Display for PropertyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bool(v) => write!(f, "{}", v),
            Self::Int(v) => write!(f, "{}", v),
            Self::String(v) => write!(f, "{}", v),
        }
    }
}

/// Manages properties for data types.
///
/// Ported from `DataTypePropertyManager.java`.
///
/// # Example
///
/// ```
/// use ghidra_features::datamgr::property_manager::*;
///
/// let mut mgr = DataTypePropertyManager::new();
/// mgr.set_property(0x1234, DataTypeProperty::HexDisplay, PropertyValue::Bool(true));
/// let val = mgr.get_property(0x1234, DataTypeProperty::HexDisplay);
/// assert!(val.is_some());
/// ```
#[derive(Debug, Clone)]
pub struct DataTypePropertyManager {
    /// Properties keyed by (data_type_id, property).
    properties: HashMap<(u64, DataTypeProperty), PropertyValue>,
}

impl DataTypePropertyManager {
    /// Creates a new property manager.
    pub fn new() -> Self {
        Self {
            properties: HashMap::new(),
        }
    }

    /// Sets a property for a data type.
    pub fn set_property(
        &mut self,
        data_type_id: u64,
        property: DataTypeProperty,
        value: PropertyValue,
    ) {
        self.properties.insert((data_type_id, property), value);
    }

    /// Gets a property for a data type.
    pub fn get_property(
        &self,
        data_type_id: u64,
        property: DataTypeProperty,
    ) -> Option<&PropertyValue> {
        self.properties.get(&(data_type_id, property))
    }

    /// Removes a property for a data type.
    pub fn remove_property(
        &mut self,
        data_type_id: u64,
        property: DataTypeProperty,
    ) -> Option<PropertyValue> {
        self.properties.remove(&(data_type_id, property))
    }

    /// Returns `true` if the data type has the given property.
    pub fn has_property(&self, data_type_id: u64, property: DataTypeProperty) -> bool {
        self.properties.contains_key(&(data_type_id, property))
    }

    /// Returns all properties for a data type.
    pub fn properties_for_type(&self, data_type_id: u64) -> Vec<(&DataTypeProperty, &PropertyValue)> {
        self.properties
            .iter()
            .filter(|((id, _), _)| *id == data_type_id)
            .map(|((_, prop), val)| (prop, val))
            .collect()
    }

    /// Returns the total number of property entries.
    pub fn len(&self) -> usize {
        self.properties.len()
    }

    /// Returns `true` if there are no properties.
    pub fn is_empty(&self) -> bool {
        self.properties.is_empty()
    }

    /// Removes all properties for a data type.
    pub fn clear_for_type(&mut self, data_type_id: u64) {
        self.properties.retain(|(id, _), _| *id != data_type_id);
    }

    /// Clears all properties.
    pub fn clear(&mut self) {
        self.properties.clear();
    }
}

impl Default for DataTypePropertyManager {
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
    fn test_property_manager_set_get() {
        let mut mgr = DataTypePropertyManager::new();
        mgr.set_property(1, DataTypeProperty::HexDisplay, PropertyValue::Bool(true));
        let val = mgr.get_property(1, DataTypeProperty::HexDisplay);
        assert!(val.is_some());
    }

    #[test]
    fn test_property_manager_has() {
        let mut mgr = DataTypePropertyManager::new();
        assert!(!mgr.has_property(1, DataTypeProperty::HexDisplay));
        mgr.set_property(1, DataTypeProperty::HexDisplay, PropertyValue::Bool(true));
        assert!(mgr.has_property(1, DataTypeProperty::HexDisplay));
    }

    #[test]
    fn test_property_manager_remove() {
        let mut mgr = DataTypePropertyManager::new();
        mgr.set_property(1, DataTypeProperty::Alignment, PropertyValue::Int(8));
        let removed = mgr.remove_property(1, DataTypeProperty::Alignment);
        assert!(removed.is_some());
        assert!(!mgr.has_property(1, DataTypeProperty::Alignment));
    }

    #[test]
    fn test_property_manager_properties_for_type() {
        let mut mgr = DataTypePropertyManager::new();
        mgr.set_property(1, DataTypeProperty::HexDisplay, PropertyValue::Bool(true));
        mgr.set_property(1, DataTypeProperty::Alignment, PropertyValue::Int(4));
        mgr.set_property(2, DataTypeProperty::Opaque, PropertyValue::Bool(false));

        let props = mgr.properties_for_type(1);
        assert_eq!(props.len(), 2);
    }

    #[test]
    fn test_property_manager_clear_for_type() {
        let mut mgr = DataTypePropertyManager::new();
        mgr.set_property(1, DataTypeProperty::HexDisplay, PropertyValue::Bool(true));
        mgr.set_property(2, DataTypeProperty::Alignment, PropertyValue::Int(4));

        mgr.clear_for_type(1);
        assert!(!mgr.has_property(1, DataTypeProperty::HexDisplay));
        assert!(mgr.has_property(2, DataTypeProperty::Alignment));
    }

    #[test]
    fn test_property_manager_len() {
        let mut mgr = DataTypePropertyManager::new();
        assert!(mgr.is_empty());
        mgr.set_property(1, DataTypeProperty::HexDisplay, PropertyValue::Bool(true));
        assert_eq!(mgr.len(), 1);
    }

    #[test]
    fn test_property_display() {
        assert_eq!(DataTypeProperty::HexDisplay.to_string(), "HexDisplay");
        assert_eq!(DataTypeProperty::Alignment.to_string(), "Alignment");
    }

    #[test]
    fn test_property_value_display() {
        assert_eq!(PropertyValue::Bool(true).to_string(), "true");
        assert_eq!(PropertyValue::Int(42).to_string(), "42");
        assert_eq!(PropertyValue::String("test".into()).to_string(), "test");
    }
}
