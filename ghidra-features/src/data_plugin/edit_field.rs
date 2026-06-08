//! Edit data field dialogs -- ported from Ghidra's data plugin.
//!
//! Provides dialog models for editing individual data fields within
//! composite types, and renaming data field components.
//!
//! Ported from:
//! - `ghidra.app.plugin.core.data.EditDataFieldDialog`
//! - `ghidra.app.plugin.core.data.RenameDataFieldDialog`
//! - `ghidra.app.plugin.core.data.DataTypeSettingsDialog`
//! - `ghidra.app.plugin.core.data.AbstractSettingsDialog`

use std::collections::HashMap;

use super::settings::DataSetting;

// ---------------------------------------------------------------------------
// EditDataFieldDialog -- edit a data field within a composite
// ---------------------------------------------------------------------------

/// Dialog model for editing a single data field within a composite type.
///
/// Ported from `ghidra.app.plugin.core.data.EditDataFieldDialog`.
///
/// This dialog allows the user to change the data type, name, and
/// comment for a specific component within a structure or union.
#[derive(Debug, Clone)]
pub struct EditDataFieldDialog {
    /// The title of the dialog.
    pub title: String,
    /// The composite (structure/union) name.
    pub composite_name: String,
    /// The component index within the composite.
    pub component_index: usize,
    /// The current field name.
    pub field_name: String,
    /// The current data type name.
    pub data_type_name: String,
    /// The current field comment.
    pub comment: Option<String>,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
}

impl EditDataFieldDialog {
    /// Create a new edit data field dialog.
    pub fn new(
        composite_name: impl Into<String>,
        component_index: usize,
        field_name: impl Into<String>,
        data_type_name: impl Into<String>,
    ) -> Self {
        let cn = composite_name.into();
        let fn_ = field_name.into();
        let dt = data_type_name.into();
        Self {
            title: format!("Edit Field: {}", fn_),
            composite_name: cn,
            component_index,
            field_name: fn_,
            data_type_name: dt,
            comment: None,
            confirmed: false,
        }
    }

    /// Set the comment for this field.
    pub fn set_comment(&mut self, comment: impl Into<String>) {
        self.comment = Some(comment.into());
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Cancel the dialog.
    pub fn cancel(&mut self) {
        self.confirmed = false;
    }

    /// Get the result as a field edit.
    pub fn to_edit_result(&self) -> Option<FieldEditResult> {
        if !self.confirmed {
            return None;
        }
        Some(FieldEditResult {
            component_index: self.component_index,
            new_field_name: self.field_name.clone(),
            new_data_type_name: self.data_type_name.clone(),
            new_comment: self.comment.clone(),
        })
    }
}

/// The result of a field edit dialog.
#[derive(Debug, Clone)]
pub struct FieldEditResult {
    /// The component index.
    pub component_index: usize,
    /// The new field name.
    pub new_field_name: String,
    /// The new data type name.
    pub new_data_type_name: String,
    /// The new comment.
    pub new_comment: Option<String>,
}

// ---------------------------------------------------------------------------
// RenameDataFieldDialog -- rename a field in a composite
// ---------------------------------------------------------------------------

/// Dialog model for renaming a data field.
///
/// Ported from `ghidra.app.plugin.core.data.RenameDataFieldDialog`.
#[derive(Debug, Clone)]
pub struct RenameDataFieldDialog {
    /// The composite name.
    pub composite_name: String,
    /// The component index.
    pub component_index: usize,
    /// The current name.
    pub current_name: String,
    /// The new name (editable).
    pub new_name: String,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
}

impl RenameDataFieldDialog {
    /// Create a new rename dialog.
    pub fn new(
        composite_name: impl Into<String>,
        component_index: usize,
        current_name: impl Into<String>,
    ) -> Self {
        let cur = current_name.into();
        Self {
            composite_name: composite_name.into(),
            component_index,
            new_name: cur.clone(),
            current_name: cur,
            confirmed: false,
        }
    }

    /// Set the new name.
    pub fn set_new_name(&mut self, name: impl Into<String>) {
        self.new_name = name.into();
    }

    /// Confirm the rename.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Validate the new name.
    pub fn validate(&self) -> Result<(), String> {
        if self.new_name.is_empty() {
            return Err("Name cannot be empty".into());
        }
        if self.new_name == self.current_name {
            return Err("New name is the same as the current name".into());
        }
        if self.new_name.contains(' ') {
            return Err("Name cannot contain spaces".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DataTypeSettingsDialog -- default settings for a data type
// ---------------------------------------------------------------------------

/// Dialog model for editing default settings of a data type.
///
/// Ported from `ghidra.app.plugin.core.data.DataTypeSettingsDialog`.
///
/// This dialog shows the default settings for a data type and allows
/// the user to modify them. Changes affect all instances of that
/// data type that use default settings.
#[derive(Debug, Clone)]
pub struct DataTypeSettingsDialog {
    /// The data type name.
    pub data_type_name: String,
    /// The category path.
    pub category_path: String,
    /// The settings to edit.
    pub settings: Vec<DataSetting>,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
}

impl DataTypeSettingsDialog {
    /// Create a new data type settings dialog.
    pub fn new(
        data_type_name: impl Into<String>,
        category_path: impl Into<String>,
        settings: Vec<DataSetting>,
    ) -> Self {
        Self {
            data_type_name: data_type_name.into(),
            category_path: category_path.into(),
            settings,
            confirmed: false,
        }
    }

    /// Get the title for the dialog.
    pub fn title(&self) -> String {
        format!("Settings for: {}", self.data_type_name)
    }

    /// Get a mutable reference to a setting by name.
    pub fn get_setting_mut(&mut self, name: &str) -> Option<&mut DataSetting> {
        self.settings.iter_mut().find(|s| s.name == name)
    }

    /// Update a setting value.
    pub fn set_setting_value(&mut self, name: &str, value: impl Into<String>) -> bool {
        if let Some(setting) = self.get_setting_mut(name) {
            if !setting.read_only {
                setting.value = value.into();
                return true;
            }
        }
        false
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Get the modified settings.
    pub fn get_modified_settings(&self) -> Vec<&DataSetting> {
        self.settings.iter().filter(|s| !s.read_only).collect()
    }
}

// ---------------------------------------------------------------------------
// AbstractSettingsDialog -- base settings dialog model
// ---------------------------------------------------------------------------

/// Abstract base for settings dialogs.
///
/// Ported from `ghidra.app.plugin.core.data.AbstractSettingsDialog`.
///
/// Provides the common structure for data settings dialogs, including
/// settings accumulation across selections and per-instance editing.
#[derive(Debug, Clone)]
pub struct AbstractSettingsDialog {
    /// The dialog title.
    pub title: String,
    /// The settings definitions available.
    pub settings_definitions: Vec<SettingsDefinition>,
    /// The initial values (key = setting name, value = value).
    pub initial_values: HashMap<String, String>,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
}

/// A settings definition entry.
#[derive(Debug, Clone)]
pub struct SettingsDefinition {
    /// The setting name.
    pub name: String,
    /// The setting description.
    pub description: String,
    /// Whether this setting has boolean values.
    pub is_boolean: bool,
    /// The allowed values (for non-boolean settings).
    pub allowed_values: Vec<String>,
    /// The default value.
    pub default_value: String,
    /// Whether this setting is immutable.
    pub immutable: bool,
}

impl SettingsDefinition {
    /// Create a boolean settings definition.
    pub fn boolean(name: impl Into<String>, description: impl Into<String>, default: bool) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            is_boolean: true,
            allowed_values: vec!["true".into(), "false".into()],
            default_value: default.to_string(),
            immutable: false,
        }
    }

    /// Create a choice settings definition.
    pub fn choice(
        name: impl Into<String>,
        description: impl Into<String>,
        allowed: Vec<String>,
        default: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            is_boolean: false,
            allowed_values: allowed,
            default_value: default.into(),
            immutable: false,
        }
    }

    /// Whether the given value is valid for this definition.
    pub fn is_valid_value(&self, value: &str) -> bool {
        self.allowed_values.contains(&value.to_string())
    }
}

impl AbstractSettingsDialog {
    /// Create a new abstract settings dialog.
    pub fn new(title: impl Into<String>, definitions: Vec<SettingsDefinition>) -> Self {
        let initial_values: HashMap<String, String> = definitions
            .iter()
            .map(|d| (d.name.clone(), d.default_value.clone()))
            .collect();
        Self {
            title: title.into(),
            settings_definitions: definitions,
            initial_values,
            confirmed: false,
        }
    }

    /// Set an initial value.
    pub fn set_value(&mut self, name: &str, value: impl Into<String>) {
        self.initial_values.insert(name.into(), value.into());
    }

    /// Get a value.
    pub fn get_value(&self, name: &str) -> Option<&str> {
        self.initial_values.get(name).map(|s| s.as_str())
    }

    /// Get non-immutable definitions.
    pub fn editable_definitions(&self) -> Vec<&SettingsDefinition> {
        self.settings_definitions.iter().filter(|d| !d.immutable).collect()
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edit_data_field_dialog() {
        let mut dialog = EditDataFieldDialog::new("my_struct", 0, "field_0", "int");
        assert_eq!(dialog.component_index, 0);
        assert_eq!(dialog.field_name, "field_0");
        assert!(!dialog.confirmed);

        dialog.set_comment("A test field");
        dialog.confirm();
        assert!(dialog.confirmed);

        let result = dialog.to_edit_result().unwrap();
        assert_eq!(result.new_field_name, "field_0");
        assert_eq!(result.new_comment, Some("A test field".into()));
    }

    #[test]
    fn test_edit_data_field_dialog_cancelled() {
        let dialog = EditDataFieldDialog::new("my_struct", 1, "x", "byte");
        assert!(dialog.to_edit_result().is_none());
    }

    #[test]
    fn test_rename_data_field_dialog() {
        let mut dialog = RenameDataFieldDialog::new("my_struct", 0, "old_name");
        assert!(dialog.validate().is_err()); // same name

        dialog.set_new_name("new_name");
        assert!(dialog.validate().is_ok());

        dialog.confirm();
        assert!(dialog.confirmed);
    }

    #[test]
    fn test_rename_data_field_empty_name() {
        let mut dialog = RenameDataFieldDialog::new("my_struct", 0, "old_name");
        dialog.set_new_name("");
        assert!(dialog.validate().is_err());
    }

    #[test]
    fn test_rename_data_field_spaces() {
        let mut dialog = RenameDataFieldDialog::new("my_struct", 0, "old_name");
        dialog.set_new_name("has space");
        assert!(dialog.validate().is_err());
    }

    #[test]
    fn test_data_type_settings_dialog() {
        let settings = vec![
            DataSetting::new("Length", "4", "The length"),
            DataSetting::new("Unicode", "false", "Is unicode"),
        ];
        let mut dialog = DataTypeSettingsDialog::new("int", "/BuiltIn", settings);
        assert_eq!(dialog.title(), "Settings for: int");
        assert!(dialog.set_setting_value("Length", "8"));
        assert!(!dialog.set_setting_value("NonExistent", "x"));

        dialog.confirm();
        assert!(dialog.confirmed);
        assert_eq!(dialog.get_modified_settings().len(), 2);
    }

    #[test]
    fn test_data_type_settings_read_only() {
        let mut setting = DataSetting::new("ReadOnly", "val", "desc");
        setting.read_only = true;
        let mut dialog = DataTypeSettingsDialog::new("type", "/", vec![setting]);
        assert!(!dialog.set_setting_value("ReadOnly", "new"));
    }

    #[test]
    fn test_abstract_settings_dialog() {
        let defs = vec![
            SettingsDefinition::boolean("ShowHex", "Display in hex", false),
            SettingsDefinition::choice(
                "Encoding",
                "Text encoding",
                vec!["ASCII".into(), "UTF-8".into()],
                "ASCII",
            ),
        ];
        let mut dialog = AbstractSettingsDialog::new("Test Settings", defs);
        assert_eq!(dialog.settings_definitions.len(), 2);
        assert_eq!(dialog.get_value("ShowHex"), Some("false"));

        dialog.set_value("ShowHex", "true");
        assert_eq!(dialog.get_value("ShowHex"), Some("true"));

        let editable = dialog.editable_definitions();
        assert_eq!(editable.len(), 2);
    }

    #[test]
    fn test_settings_definition_validation() {
        let def = SettingsDefinition::choice(
            "Endian",
            "Byte order",
            vec!["Little".into(), "Big".into()],
            "Little",
        );
        assert!(def.is_valid_value("Little"));
        assert!(def.is_valid_value("Big"));
        assert!(!def.is_valid_value("Middle"));
    }

    #[test]
    fn test_settings_definition_immutable() {
        let mut def = SettingsDefinition::boolean("Locked", "Locked setting", true);
        def.immutable = true;
        let dialog = AbstractSettingsDialog::new("Test", vec![def]);
        assert_eq!(dialog.editable_definitions().len(), 0);
    }
}
