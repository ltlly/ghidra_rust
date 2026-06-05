//! Data settings management -- ported from Ghidra's data settings dialog code.
//!
//! Provides [`DataSettingsManager`] for managing default and per-instance
//! settings for data types, and [`DataTypeFavorite`] for tracking favorites.

use std::collections::{BTreeMap, HashMap};

/// A setting key-value pair for a data type.
#[derive(Debug, Clone, PartialEq)]
pub struct DataSetting {
    /// The setting name.
    pub name: String,
    /// The setting value as a string.
    pub value: String,
    /// The setting description.
    pub description: String,
    /// Whether the setting is read-only.
    pub read_only: bool,
}

impl DataSetting {
    /// Create a new data setting.
    pub fn new(
        name: impl Into<String>,
        value: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            description: description.into(),
            read_only: false,
        }
    }
}

/// Manages default and per-instance data type settings.
///
/// Ported from the settings dialog and management code in
/// `ghidra.app.plugin.core.data.DataSettingsDialog`,
/// `ghidra.app.plugin.core.data.DataTypeSettingsDialog`, and
/// `ghidra.app.plugin.core.data.AbstractSettingsDialog`.
#[derive(Debug, Default)]
pub struct DataSettingsManager {
    /// Default settings per data type name.
    default_settings: HashMap<String, Vec<DataSetting>>,
    /// Per-address instance settings. Key is address offset.
    instance_settings: BTreeMap<u64, HashMap<String, String>>,
    /// Recently used data types (most recent first).
    recently_used: Vec<String>,
    /// Favorite data types.
    favorites: Vec<DataTypeFavorite>,
}

/// A favorite data type entry.
#[derive(Debug, Clone)]
pub struct DataTypeFavorite {
    /// The data type name.
    pub name: String,
    /// Category (e.g. "BuiltIn", "Structure", "Pointer").
    pub category: String,
    /// The order/priority in the favorites list.
    pub order: usize,
}

impl DataTypeFavorite {
    /// Create a new favorite.
    pub fn new(name: impl Into<String>, category: impl Into<String>, order: usize) -> Self {
        Self {
            name: name.into(),
            category: category.into(),
            order,
        }
    }
}

impl DataSettingsManager {
    /// Create a new settings manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register default settings for a data type.
    pub fn register_default_settings(
        &mut self,
        data_type_name: impl Into<String>,
        settings: Vec<DataSetting>,
    ) {
        self.default_settings.insert(data_type_name.into(), settings);
    }

    /// Get the default settings for a data type.
    pub fn get_default_settings(&self, data_type_name: &str) -> Option<&Vec<DataSetting>> {
        self.default_settings.get(data_type_name)
    }

    /// Get a mutable reference to the default settings for a data type.
    pub fn get_default_settings_mut(
        &mut self,
        data_type_name: &str,
    ) -> Option<&mut Vec<DataSetting>> {
        self.default_settings.get_mut(data_type_name)
    }

    /// Update a specific default setting value.
    pub fn update_default_setting(
        &mut self,
        data_type_name: &str,
        setting_name: &str,
        new_value: impl Into<String>,
    ) -> Result<(), String> {
        let settings = self
            .default_settings
            .get_mut(data_type_name)
            .ok_or_else(|| format!("No settings for data type '{}'", data_type_name))?;
        let setting = settings
            .iter_mut()
            .find(|s| s.name == setting_name)
            .ok_or_else(|| format!("No setting '{}' for '{}'", setting_name, data_type_name))?;
        if setting.read_only {
            return Err(format!("Setting '{}' is read-only", setting_name));
        }
        setting.value = new_value.into();
        Ok(())
    }

    /// Set instance-specific settings at an address.
    pub fn set_instance_settings(
        &mut self,
        address_offset: u64,
        settings: HashMap<String, String>,
    ) {
        self.instance_settings.insert(address_offset, settings);
    }

    /// Get instance-specific settings at an address.
    pub fn get_instance_settings(&self, address_offset: u64) -> Option<&HashMap<String, String>> {
        self.instance_settings.get(&address_offset)
    }

    /// Clear instance settings at an address.
    pub fn clear_instance_settings(&mut self, address_offset: u64) {
        self.instance_settings.remove(&address_offset);
    }

    /// Add a data type to the recently used list.
    pub fn set_recently_used(&mut self, data_type_name: impl Into<String>) {
        let name = data_type_name.into();
        self.recently_used.retain(|n| n != &name);
        self.recently_used.insert(0, name);
        if self.recently_used.len() > 20 {
            self.recently_used.truncate(20);
        }
    }

    /// Get the most recently used data type.
    pub fn get_most_recently_used(&self) -> Option<&str> {
        self.recently_used.first().map(|s| s.as_str())
    }

    /// Get all recently used data types.
    pub fn get_recently_used(&self) -> &[String] {
        &self.recently_used
    }

    /// Add a data type to the favorites list.
    pub fn add_favorite(&mut self, name: impl Into<String>, category: impl Into<String>) {
        let name_str = name.into();
        if self.favorites.iter().any(|f| f.name == name_str) {
            return;
        }
        let order = self.favorites.len();
        self.favorites
            .push(DataTypeFavorite::new(name_str, category, order));
    }

    /// Remove a data type from the favorites list.
    pub fn remove_favorite(&mut self, name: &str) -> bool {
        let len_before = self.favorites.len();
        self.favorites.retain(|f| f.name != name);
        self.favorites.len() < len_before
    }

    /// Get the favorites list.
    pub fn get_favorites(&self) -> &[DataTypeFavorite] {
        &self.favorites
    }

    /// Whether a data type is a favorite.
    pub fn is_favorite(&self, name: &str) -> bool {
        self.favorites.iter().any(|f| f.name == name)
    }

    /// Get the default settings map (for testing/debugging).
    pub fn default_settings_count(&self) -> usize {
        self.default_settings.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_setting_new() {
        let s = DataSetting::new("Length", "4", "The length of the data type");
        assert_eq!(s.name, "Length");
        assert_eq!(s.value, "4");
        assert!(!s.read_only);
    }

    #[test]
    fn test_register_and_get_default_settings() {
        let mut mgr = DataSettingsManager::new();
        mgr.register_default_settings(
            "byte",
            vec![
                DataSetting::new("Length", "1", "Size in bytes"),
                DataSetting::new("Endian", "Little", "Byte order"),
            ],
        );
        let settings = mgr.get_default_settings("byte").unwrap();
        assert_eq!(settings.len(), 2);
        assert_eq!(settings[0].name, "Length");
    }

    #[test]
    fn test_update_default_setting() {
        let mut mgr = DataSettingsManager::new();
        mgr.register_default_settings(
            "word",
            vec![DataSetting::new("Endian", "Little", "Byte order")],
        );
        mgr.update_default_setting("word", "Endian", "Big").unwrap();
        assert_eq!(
            mgr.get_default_settings("word").unwrap()[0].value,
            "Big"
        );
    }

    #[test]
    fn test_update_default_setting_read_only() {
        let mut mgr = DataSettingsManager::new();
        let mut setting = DataSetting::new("Fixed", "42", "Not changeable");
        setting.read_only = true;
        mgr.register_default_settings("const", vec![setting]);
        assert!(mgr.update_default_setting("const", "Fixed", "99").is_err());
    }

    #[test]
    fn test_update_default_setting_not_found() {
        let mut mgr = DataSettingsManager::new();
        assert!(mgr.update_default_setting("nonexistent", "foo", "bar").is_err());
    }

    #[test]
    fn test_instance_settings() {
        let mut mgr = DataSettingsManager::new();
        let mut settings = HashMap::new();
        settings.insert("Format".into(), "Hex".into());
        mgr.set_instance_settings(0x1000, settings);
        let inst = mgr.get_instance_settings(0x1000).unwrap();
        assert_eq!(inst.get("Format").unwrap(), "Hex");
        mgr.clear_instance_settings(0x1000);
        assert!(mgr.get_instance_settings(0x1000).is_none());
    }

    #[test]
    fn test_recently_used() {
        let mut mgr = DataSettingsManager::new();
        mgr.set_recently_used("float");
        mgr.set_recently_used("dword");
        assert_eq!(mgr.get_most_recently_used(), Some("dword"));
        assert_eq!(mgr.get_recently_used().len(), 2);
        // Duplicate is moved to front
        mgr.set_recently_used("float");
        assert_eq!(mgr.get_most_recently_used(), Some("float"));
        assert_eq!(mgr.get_recently_used().len(), 2);
    }

    #[test]
    fn test_recently_used_max() {
        let mut mgr = DataSettingsManager::new();
        for i in 0..25 {
            mgr.set_recently_used(format!("type_{}", i));
        }
        assert_eq!(mgr.get_recently_used().len(), 20);
    }

    #[test]
    fn test_favorites() {
        let mut mgr = DataSettingsManager::new();
        mgr.add_favorite("int", "BuiltIn");
        mgr.add_favorite("float", "BuiltIn");
        assert_eq!(mgr.get_favorites().len(), 2);
        assert!(mgr.is_favorite("int"));
        assert!(!mgr.is_favorite("byte"));
        // Duplicate add is ignored
        mgr.add_favorite("int", "BuiltIn");
        assert_eq!(mgr.get_favorites().len(), 2);
        assert!(mgr.remove_favorite("int"));
        assert!(!mgr.is_favorite("int"));
        assert_eq!(mgr.get_favorites().len(), 1);
        assert!(!mgr.remove_favorite("nonexistent"));
    }
}
