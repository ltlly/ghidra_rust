//! Data settings dialogs -- ported from `DataSettingsDialog.java`,
//! `DataTypeSettingsDialog.java`, and `AbstractSettingsDialog.java`.
//!
//! These types manage the settings (display format, endianness, etc.)
//! for data instances and data types.
//!
//! In the non-GUI Rust port, these are modeled as data holders that
//! track the settings state; actual rendering is deferred to the GUI layer.

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// SettingsDefinition
// ---------------------------------------------------------------------------

/// A definition for a single data type setting.
///
/// Ported from Ghidra's `SettingsDefinition` Java class hierarchy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsEntry {
    /// The setting name (e.g., "Format", "Endianness").
    pub name: String,
    /// The current value.
    pub value: String,
    /// The allowed values for this setting (if constrained to a list).
    pub allowed_values: Vec<String>,
    /// Whether this setting applies to the data type itself (vs. instance).
    pub is_type_setting: bool,
    /// Whether this setting has been modified from the default.
    pub is_modified: bool,
}

impl SettingsEntry {
    /// Creates a new settings entry.
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            allowed_values: Vec::new(),
            is_type_setting: false,
            is_modified: false,
        }
    }

    /// Creates a settings entry with allowed values.
    pub fn with_allowed(
        name: impl Into<String>,
        value: impl Into<String>,
        allowed: Vec<String>,
    ) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            allowed_values: allowed,
            is_type_setting: false,
            is_modified: false,
        }
    }

    /// Sets the value.
    pub fn set_value(&mut self, value: impl Into<String>) {
        self.value = value.into();
        self.is_modified = true;
    }

    /// Resets the setting to its default.
    pub fn reset(&mut self) {
        if !self.allowed_values.is_empty() {
            self.value = self.allowed_values[0].clone();
        }
        self.is_modified = false;
    }
}

// ---------------------------------------------------------------------------
// DataSettings
// ---------------------------------------------------------------------------

/// Settings for a data instance in the listing.
///
/// Ported from the settings model used by `DataSettingsDialog`.
#[derive(Debug, Clone, Default)]
pub struct DataSettings {
    /// Map from setting name to entry.
    entries: HashMap<String, SettingsEntry>,
}

impl DataSettings {
    /// Creates empty data settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a setting entry.
    pub fn add(&mut self, entry: SettingsEntry) {
        self.entries.insert(entry.name.clone(), entry);
    }

    /// Gets a setting value by name.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries.get(name).map(|e| e.value.as_str())
    }

    /// Gets a mutable reference to a setting entry.
    pub fn get_mut(&mut self, name: &str) -> Option<&mut SettingsEntry> {
        self.entries.get_mut(name)
    }

    /// Sets a setting value by name.
    pub fn set(&mut self, name: &str, value: &str) {
        if let Some(entry) = self.entries.get_mut(name) {
            entry.set_value(value);
        }
    }

    /// Returns the number of settings.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if there are no settings.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns `true` if any settings have been modified.
    pub fn has_modifications(&self) -> bool {
        self.entries.values().any(|e| e.is_modified)
    }

    /// Returns all modified setting names.
    pub fn modified_names(&self) -> Vec<&str> {
        self.entries
            .values()
            .filter(|e| e.is_modified)
            .map(|e| e.name.as_str())
            .collect()
    }

    /// Resets all settings to their defaults.
    pub fn reset_all(&mut self) {
        for entry in self.entries.values_mut() {
            entry.reset();
        }
    }

    /// Returns an iterator over all setting entries.
    pub fn iter(&self) -> impl Iterator<Item = &SettingsEntry> {
        self.entries.values()
    }

    /// Returns the intersection of settings across multiple data items.
    ///
    /// Used when displaying settings for a selection of data items.
    pub fn common_settings(settings_list: &[DataSettings]) -> DataSettings {
        if settings_list.is_empty() {
            return DataSettings::new();
        }
        if settings_list.len() == 1 {
            return settings_list[0].clone();
        }

        let first = &settings_list[0];
        let mut common = DataSettings::new();

        for (name, entry) in &first.entries {
            let all_match = settings_list[1..]
                .iter()
                .all(|s| s.get(name) == Some(entry.value.as_str()));
            if all_match {
                common.add(entry.clone());
            }
        }
        common
    }
}

impl fmt::Display for DataSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DataSettings({} entries)", self.entries.len())
    }
}

// ---------------------------------------------------------------------------
// DataTypeSettings
// ---------------------------------------------------------------------------

/// Default settings for a data type.
///
/// Ported from the model used by `DataTypeSettingsDialog`.
#[derive(Debug, Clone, Default)]
pub struct DataTypeSettings {
    /// The data type name these settings apply to.
    data_type_name: String,
    /// The settings entries.
    entries: HashMap<String, SettingsEntry>,
    /// Whether these settings are for a composite type's component.
    is_component: bool,
}

impl DataTypeSettings {
    /// Creates new data type settings.
    pub fn new(data_type_name: impl Into<String>) -> Self {
        Self {
            data_type_name: data_type_name.into(),
            entries: HashMap::new(),
            is_component: false,
        }
    }

    /// Creates settings for a composite type's component.
    pub fn for_component(data_type_name: impl Into<String>) -> Self {
        Self {
            data_type_name: data_type_name.into(),
            entries: HashMap::new(),
            is_component: true,
        }
    }

    /// Returns the data type name.
    pub fn data_type_name(&self) -> &str {
        &self.data_type_name
    }

    /// Returns whether these settings are for a component.
    pub fn is_component(&self) -> bool {
        self.is_component
    }

    /// Adds a setting entry.
    pub fn add(&mut self, entry: SettingsEntry) {
        self.entries.insert(entry.name.clone(), entry);
    }

    /// Gets a setting value by name.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries.get(name).map(|e| e.value.as_str())
    }

    /// Sets a setting value by name.
    pub fn set(&mut self, name: &str, value: &str) {
        if let Some(entry) = self.entries.get_mut(name) {
            entry.set_value(value);
        }
    }

    /// Returns the number of settings.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if there are no settings.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns all settings as a DataSettings.
    pub fn to_data_settings(&self) -> DataSettings {
        let mut ds = DataSettings::new();
        for entry in self.entries.values() {
            ds.add(entry.clone());
        }
        ds
    }
}

// ---------------------------------------------------------------------------
// AbstractSettingsDialog (model)
// ---------------------------------------------------------------------------

/// The base model for settings dialog logic.
///
/// In the full Ghidra implementation, `AbstractSettingsDialog` is a Swing
/// dialog.  Here we model only the state and logic; rendering is in the
/// GUI layer.
#[derive(Debug, Clone)]
pub struct SettingsDialogModel {
    /// The dialog title.
    title: String,
    /// The current settings being edited.
    settings: DataSettings,
    /// Whether the dialog was accepted.
    accepted: bool,
    /// Help location category.
    help_category: Option<String>,
    /// Help location topic.
    help_topic: Option<String>,
}

impl SettingsDialogModel {
    /// Creates a new settings dialog model.
    pub fn new(title: impl Into<String>, settings: DataSettings) -> Self {
        Self {
            title: title.into(),
            settings,
            accepted: false,
            help_category: None,
            help_topic: None,
        }
    }

    /// Returns the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the current settings.
    pub fn settings(&self) -> &DataSettings {
        &self.settings
    }

    /// Returns a mutable reference to the settings.
    pub fn settings_mut(&mut self) -> &mut DataSettings {
        &mut self.settings
    }

    /// Sets whether the dialog was accepted.
    pub fn set_accepted(&mut self, accepted: bool) {
        self.accepted = accepted;
    }

    /// Returns whether the dialog was accepted.
    pub fn is_accepted(&self) -> bool {
        self.accepted
    }

    /// Sets the help location.
    pub fn set_help(&mut self, category: impl Into<String>, topic: impl Into<String>) {
        self.help_category = Some(category.into());
        self.help_topic = Some(topic.into());
    }

    /// Returns the help category, if set.
    pub fn help_category(&self) -> Option<&str> {
        self.help_category.as_deref()
    }

    /// Returns the help topic, if set.
    pub fn help_topic(&self) -> Option<&str> {
        self.help_topic.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_settings_entry() {
        let mut entry = SettingsEntry::new("Format", "hex");
        assert_eq!(entry.name, "Format");
        assert_eq!(entry.value, "hex");
        assert!(!entry.is_modified);

        entry.set_value("decimal");
        assert_eq!(entry.value, "decimal");
        assert!(entry.is_modified);
    }

    #[test]
    fn test_settings_entry_with_allowed() {
        let entry = SettingsEntry::with_allowed(
            "Endian",
            "little",
            vec!["little".into(), "big".into()],
        );
        assert_eq!(entry.allowed_values.len(), 2);
    }

    #[test]
    fn test_settings_entry_reset() {
        let mut entry = SettingsEntry::with_allowed(
            "Endian",
            "big",
            vec!["little".into(), "big".into()],
        );
        entry.reset();
        assert_eq!(entry.value, "little");
        assert!(!entry.is_modified);
    }

    #[test]
    fn test_data_settings() {
        let mut ds = DataSettings::new();
        assert!(ds.is_empty());

        ds.add(SettingsEntry::new("Format", "hex"));
        ds.add(SettingsEntry::new("Endian", "little"));
        assert_eq!(ds.len(), 2);

        assert_eq!(ds.get("Format"), Some("hex"));
        assert_eq!(ds.get("Missing"), None);

        ds.set("Format", "decimal");
        assert_eq!(ds.get("Format"), Some("decimal"));
        assert!(ds.has_modifications());
        assert_eq!(ds.modified_names(), vec!["Format"]);
    }

    #[test]
    fn test_data_settings_reset_all() {
        let mut ds = DataSettings::new();
        ds.add(SettingsEntry::with_allowed("Format", "hex", vec!["hex".into(), "dec".into()]));
        ds.set("Format", "dec");
        assert!(ds.has_modifications());

        ds.reset_all();
        assert!(!ds.has_modifications());
        assert_eq!(ds.get("Format"), Some("hex"));
    }

    #[test]
    fn test_common_settings() {
        let mut ds1 = DataSettings::new();
        ds1.add(SettingsEntry::new("Format", "hex"));
        ds1.add(SettingsEntry::new("Endian", "little"));

        let mut ds2 = DataSettings::new();
        ds2.add(SettingsEntry::new("Format", "hex"));
        ds2.add(SettingsEntry::new("Endian", "big"));

        let common = DataSettings::common_settings(&[ds1, ds2]);
        assert_eq!(common.get("Format"), Some("hex"));
        assert_eq!(common.get("Endian"), None); // differs
    }

    #[test]
    fn test_common_settings_empty() {
        let common = DataSettings::common_settings(&[]);
        assert!(common.is_empty());
    }

    #[test]
    fn test_common_settings_single() {
        let mut ds = DataSettings::new();
        ds.add(SettingsEntry::new("Format", "hex"));
        let common = DataSettings::common_settings(&[ds]);
        assert_eq!(common.get("Format"), Some("hex"));
    }

    #[test]
    fn test_data_type_settings() {
        let mut dts = DataTypeSettings::new("int");
        assert_eq!(dts.data_type_name(), "int");
        assert!(!dts.is_component());

        dts.add(SettingsEntry::new("Format", "hex"));
        assert_eq!(dts.get("Format"), Some("hex"));

        dts.set("Format", "decimal");
        assert_eq!(dts.get("Format"), Some("decimal"));
    }

    #[test]
    fn test_data_type_settings_component() {
        let dts = DataTypeSettings::for_component("myStruct");
        assert!(dts.is_component());
    }

    #[test]
    fn test_data_type_settings_to_data_settings() {
        let mut dts = DataTypeSettings::new("int");
        dts.add(SettingsEntry::new("Format", "hex"));
        let ds = dts.to_data_settings();
        assert_eq!(ds.get("Format"), Some("hex"));
    }

    #[test]
    fn test_settings_dialog_model() {
        let ds = DataSettings::new();
        let mut model = SettingsDialogModel::new("Edit Settings", ds);
        assert_eq!(model.title(), "Edit Settings");
        assert!(!model.is_accepted());

        model.set_accepted(true);
        assert!(model.is_accepted());

        model.set_help("DataPlugin", "Data_Settings");
        assert_eq!(model.help_category(), Some("DataPlugin"));
        assert_eq!(model.help_topic(), Some("Data_Settings"));
    }
}
