//! Cycle group action and data type settings dialog model.
//!
//! Ported from `ghidra.app.plugin.core.data.CycleGroupAction`,
//! `ghidra.app.plugin.core.data.AbstractSettingsDialog`,
//! `ghidra.app.plugin.core.data.DataSettingsDialog`,
//! `ghidra.app.plugin.core.data.DataTypeSettingsDialog`,
//! `ghidra.app.plugin.core.data.RecentlyUsedAction`,
//! `ghidra.app.plugin.core.data.ChooseDataTypeAction`,
//! `ghidra.app.plugin.core.data.PointerDataAction`,
//! `ghidra.app.plugin.core.data.RenameDataFieldDialog`,
//! and `ghidra.app.plugin.core.data.EditDataFieldDialog`.

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Cycle group definition for toggling through related data types.
///
/// Ported from `ghidra.app.plugin.core.data.CycleGroupAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleGroupDef {
    /// Display name of the cycle group.
    pub name: String,
    /// Data types in this group, ordered by display preference.
    pub types: Vec<String>,
}

impl CycleGroupDef {
    /// Create a new cycle group definition.
    pub fn new(name: impl Into<String>, types: Vec<String>) -> Self {
        Self {
            name: name.into(),
            types,
        }
    }

    /// Find the next type in the cycle after the given current type.
    pub fn next_type(&self, current: &str) -> Option<&str> {
        if let Some(idx) = self.types.iter().position(|t| t == current) {
            let next = (idx + 1) % self.types.len();
            self.types.get(next).map(|s| s.as_str())
        } else {
            self.types.first().map(|s| s.as_str())
        }
    }

    /// Find the previous type in the cycle before the given current type.
    pub fn previous_type(&self, current: &str) -> Option<&str> {
        if let Some(idx) = self.types.iter().position(|t| t == current) {
            let prev = if idx == 0 {
                self.types.len() - 1
            } else {
                idx - 1
            };
            self.types.get(prev).map(|s| s.as_str())
        } else {
            self.types.last().map(|s| s.as_str())
        }
    }

    /// Get the index of the given type in the group.
    pub fn index_of(&self, type_name: &str) -> Option<usize> {
        self.types.iter().position(|t| t == type_name)
    }

    /// The number of types in this group.
    pub fn len(&self) -> usize {
        self.types.len()
    }

    /// Whether this group is empty.
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }
}

/// Cycle group action for toggling data types.
///
/// Ported from `ghidra.app.plugin.core.data.CycleGroupAction`.
#[derive(Debug, Clone)]
pub struct CycleGroupAction {
    /// The cycle group definition.
    pub group: CycleGroupDef,
    /// Whether the action is enabled.
    enabled: bool,
}

impl CycleGroupAction {
    /// Create a new cycle group action.
    pub fn new(group: CycleGroupDef) -> Self {
        Self {
            group,
            enabled: true,
        }
    }

    /// Get the next type in the cycle.
    pub fn get_next_type(&self, current: &str) -> Option<&str> {
        self.group.next_type(current)
    }

    /// Whether the action is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set whether the action is enabled.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get the action name.
    pub fn name(&self) -> String {
        format!("Cycle Group: {}", self.group.name)
    }
}

// ---------------------------------------------------------------------------
// Built-in cycle groups
// ---------------------------------------------------------------------------

/// Get the built-in cycle groups matching Ghidra's defaults.
pub fn builtin_cycle_groups() -> Vec<CycleGroupDef> {
    vec![
        CycleGroupDef::new("byte", vec!["byte".into(), "char".into()]),
        CycleGroupDef::new("word", vec!["word".into(), "short".into(), "ushort".into()]),
        CycleGroupDef::new(
            "dword",
            vec!["dword".into(), "int".into(), "uint".into(), "float".into()],
        ),
        CycleGroupDef::new(
            "qword",
            vec![
                "qword".into(),
                "longlong".into(),
                "ulonglong".into(),
                "double".into(),
            ],
        ),
        CycleGroupDef::new(
            "string",
            vec!["string".into(), "unicode".into()],
        ),
    ]
}

// ---------------------------------------------------------------------------
// RecentlyUsedAction
// ---------------------------------------------------------------------------

/// Manages a list of recently used data types.
///
/// Ported from `ghidra.app.plugin.core.data.RecentlyUsedAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentlyUsedDataTypes {
    /// Recently used type names, most recent first.
    recent: VecDeque<String>,
    /// Maximum number of recent types to track.
    max_size: usize,
}

impl RecentlyUsedDataTypes {
    /// Create a new recently used tracker.
    pub fn new(max_size: usize) -> Self {
        Self {
            recent: VecDeque::with_capacity(max_size),
            max_size,
        }
    }

    /// Record a data type as recently used.
    pub fn use_type(&mut self, type_name: &str) {
        self.recent.retain(|t| t != type_name);
        self.recent.push_front(type_name.to_string());
        while self.recent.len() > self.max_size {
            self.recent.pop_back();
        }
    }

    /// Get the list of recently used types.
    pub fn recent_types(&self) -> &VecDeque<String> {
        &self.recent
    }

    /// Get the most recently used type.
    pub fn most_recent(&self) -> Option<&str> {
        self.recent.front().map(|s| s.as_str())
    }

    /// Clear the recently used list.
    pub fn clear(&mut self) {
        self.recent.clear();
    }

    /// Number of recently used types.
    pub fn len(&self) -> usize {
        self.recent.len()
    }

    /// Whether the list is empty.
    pub fn is_empty(&self) -> bool {
        self.recent.is_empty()
    }
}

impl Default for RecentlyUsedDataTypes {
    fn default() -> Self {
        Self::new(10)
    }
}

// ---------------------------------------------------------------------------
// AbstractSettingsDialog
// ---------------------------------------------------------------------------

/// Model for a data type settings dialog.
///
/// Ported from `ghidra.app.plugin.core.data.AbstractSettingsDialog`,
/// `ghidra.app.plugin.core.data.DataSettingsDialog`,
/// and `ghidra.app.plugin.core.data.DataTypeSettingsDialog`.
#[derive(Debug, Clone)]
pub struct DataTypeSettingsDialog {
    /// The data type name being configured.
    pub type_name: String,
    /// Settings key-value pairs.
    settings: Vec<SettingEntry>,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
    /// Whether settings have been modified.
    dirty: bool,
}

/// A single setting entry in the dialog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingEntry {
    /// Setting key (identifier).
    pub key: String,
    /// Display name for the setting.
    pub display_name: String,
    /// Current value.
    pub value: SettingValue,
    /// Default value.
    pub default_value: SettingValue,
    /// Whether this setting has been modified.
    pub modified: bool,
    /// Tooltip text.
    pub tooltip: Option<String>,
}

/// Possible setting values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettingValue {
    /// Boolean setting.
    Bool(bool),
    /// Integer setting.
    Int(i64),
    /// String setting.
    String(String),
    /// Enum/choice setting (index into choices).
    Enum { index: usize, choices: Vec<String> },
}

impl SettingValue {
    /// Get as boolean if applicable.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as integer if applicable.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Get as string if applicable.
    pub fn as_string(&self) -> Option<&str> {
        match self {
            Self::String(v) => Some(v.as_str()),
            _ => None,
        }
    }
}

impl DataTypeSettingsDialog {
    /// Create a new settings dialog for a data type.
    pub fn new(type_name: impl Into<String>) -> Self {
        Self {
            type_name: type_name.into(),
            settings: Vec::new(),
            confirmed: false,
            dirty: false,
        }
    }

    /// Add a boolean setting.
    pub fn add_bool_setting(
        &mut self,
        key: impl Into<String>,
        display_name: impl Into<String>,
        default: bool,
        tooltip: Option<String>,
    ) {
        self.settings.push(SettingEntry {
            key: key.into(),
            display_name: display_name.into(),
            value: SettingValue::Bool(default),
            default_value: SettingValue::Bool(default),
            modified: false,
            tooltip,
        });
    }

    /// Add an integer setting.
    pub fn add_int_setting(
        &mut self,
        key: impl Into<String>,
        display_name: impl Into<String>,
        default: i64,
        tooltip: Option<String>,
    ) {
        self.settings.push(SettingEntry {
            key: key.into(),
            display_name: display_name.into(),
            value: SettingValue::Int(default),
            default_value: SettingValue::Int(default),
            modified: false,
            tooltip,
        });
    }

    /// Add an enum/choice setting.
    pub fn add_enum_setting(
        &mut self,
        key: impl Into<String>,
        display_name: impl Into<String>,
        default_index: usize,
        choices: Vec<String>,
        tooltip: Option<String>,
    ) {
        self.settings.push(SettingEntry {
            key: key.into(),
            display_name: display_name.into(),
            value: SettingValue::Enum {
                index: default_index,
                choices: choices.clone(),
            },
            default_value: SettingValue::Enum {
                index: default_index,
                choices,
            },
            modified: false,
            tooltip,
        });
    }

    /// Set a boolean setting value.
    pub fn set_bool(&mut self, key: &str, value: bool) {
        if let Some(entry) = self.settings.iter_mut().find(|e| e.key == key) {
            entry.value = SettingValue::Bool(value);
            entry.modified = entry.value != entry.default_value;
            self.dirty = true;
        }
    }

    /// Set an integer setting value.
    pub fn set_int(&mut self, key: &str, value: i64) {
        if let Some(entry) = self.settings.iter_mut().find(|e| e.key == key) {
            entry.value = SettingValue::Int(value);
            entry.modified = entry.value != entry.default_value;
            self.dirty = true;
        }
    }

    /// Set an enum setting value by index.
    pub fn set_enum_index(&mut self, key: &str, index: usize) {
        if let Some(entry) = self.settings.iter_mut().find(|e| e.key == key) {
            if let SettingValue::Enum { ref choices, .. } = entry.default_value {
                let choices_clone = choices.clone();
                entry.value = SettingValue::Enum {
                    index,
                    choices: choices_clone,
                };
                entry.modified = entry.value != entry.default_value;
                self.dirty = true;
            }
        }
    }

    /// Get all settings.
    pub fn settings(&self) -> &[SettingEntry] {
        &self.settings
    }

    /// Get a setting by key.
    pub fn get_setting(&self, key: &str) -> Option<&SettingEntry> {
        self.settings.iter().find(|e| e.key == key)
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Whether settings have been modified.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Reset all settings to their defaults.
    pub fn reset_to_defaults(&mut self) {
        for entry in &mut self.settings {
            entry.value = entry.default_value.clone();
            entry.modified = false;
        }
        self.dirty = false;
    }

    /// Get the number of settings.
    pub fn len(&self) -> usize {
        self.settings.len()
    }

    /// Whether there are any settings.
    pub fn is_empty(&self) -> bool {
        self.settings.is_empty()
    }
}

// ---------------------------------------------------------------------------
// RenameDataFieldDialog
// ---------------------------------------------------------------------------

/// Dialog model for renaming a data field.
///
/// Ported from `ghidra.app.plugin.core.data.RenameDataFieldDialog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameDataFieldDialog {
    /// The current field name.
    pub current_name: String,
    /// The new field name (entered by user).
    pub new_name: String,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
}

impl RenameDataFieldDialog {
    /// Create a new rename dialog.
    pub fn new(current_name: impl Into<String>) -> Self {
        let name = current_name.into();
        Self {
            current_name: name.clone(),
            new_name: name,
            confirmed: false,
        }
    }

    /// Set the new name.
    pub fn set_new_name(&mut self, name: impl Into<String>) {
        self.new_name = name.into();
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Validate the new name.
    pub fn validate(&self) -> Result<(), String> {
        if self.new_name.is_empty() {
            return Err("Field name cannot be empty".to_string());
        }
        if self.new_name == self.current_name {
            return Err("New name is the same as the current name".to_string());
        }
        // Check for valid identifier characters
        if !self
            .new_name
            .chars()
            .next()
            .map_or(false, |c| c.is_ascii_alphabetic() || c == '_')
        {
            return Err("Field name must start with a letter or underscore".to_string());
        }
        if !self
            .new_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err("Field name must contain only letters, digits, and underscores".to_string());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// EditDataFieldDialog
// ---------------------------------------------------------------------------

/// Dialog model for editing a data field's type and properties.
///
/// Ported from `ghidra.app.plugin.core.data.EditDataFieldDialog`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EditDataFieldDialog {
    /// The field name.
    pub field_name: String,
    /// The current data type name.
    pub type_name: String,
    /// The new data type name.
    pub new_type_name: String,
    /// The comment on this field.
    pub comment: String,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
    /// The offset of this field within the parent.
    pub offset: u64,
    /// The size of this field in bytes.
    pub size: u32,
}

impl EditDataFieldDialog {
    /// Create a new edit data field dialog.
    pub fn new(
        field_name: impl Into<String>,
        type_name: impl Into<String>,
        offset: u64,
        size: u32,
    ) -> Self {
        let tn = type_name.into();
        Self {
            field_name: field_name.into(),
            type_name: tn.clone(),
            new_type_name: tn,
            comment: String::new(),
            confirmed: false,
            offset,
            size,
        }
    }

    /// Set the new type name.
    pub fn set_new_type(&mut self, type_name: impl Into<String>) {
        self.new_type_name = type_name.into();
    }

    /// Set the comment.
    pub fn set_comment(&mut self, comment: impl Into<String>) {
        self.comment = comment.into();
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Whether the type was changed.
    pub fn type_changed(&self) -> bool {
        self.type_name != self.new_type_name
    }

    /// Validate the dialog state.
    pub fn validate(&self) -> Result<(), String> {
        if self.new_type_name.is_empty() {
            return Err("Type name cannot be empty".to_string());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CreateArrayDialog
// ---------------------------------------------------------------------------

/// Dialog model for creating an array data type.
///
/// Ported from `ghidra.app.plugin.core.data.CreateArrayAction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateArrayDialog {
    /// The element data type name.
    pub element_type: String,
    /// The number of elements.
    pub element_count: usize,
    /// The element size in bytes.
    pub element_size: u32,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
}

impl CreateArrayDialog {
    /// Create a new array dialog.
    pub fn new(element_type: impl Into<String>, element_count: usize, element_size: u32) -> Self {
        Self {
            element_type: element_type.into(),
            element_count,
            element_size,
            confirmed: false,
        }
    }

    /// Get the total array size in bytes.
    pub fn total_size(&self) -> u64 {
        self.element_count as u64 * self.element_size as u64
    }

    /// Set the element count.
    pub fn set_element_count(&mut self, count: usize) {
        self.element_count = count;
    }

    /// Set the element type.
    pub fn set_element_type(&mut self, type_name: impl Into<String>) {
        self.element_type = type_name.into();
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Validate the dialog state.
    pub fn validate(&self) -> Result<(), String> {
        if self.element_type.is_empty() {
            return Err("Element type cannot be empty".to_string());
        }
        if self.element_count == 0 {
            return Err("Element count must be > 0".to_string());
        }
        if self.element_size == 0 {
            return Err("Element size must be > 0".to_string());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// CreateStructureDialog
// ---------------------------------------------------------------------------

/// Dialog model for creating a structure data type.
///
/// Ported from `ghidra.app.plugin.core.data.CreateStructureDialog`.
#[derive(Debug, Clone)]
pub struct CreateStructureDialog {
    /// The structure name.
    pub name: String,
    /// Component entries: (field_name, type_name, size).
    pub components: Vec<(String, String, u32)>,
    /// Whether the dialog was confirmed.
    pub confirmed: bool,
    /// The total size in bytes.
    pub total_size: u32,
}

impl CreateStructureDialog {
    /// Create a new structure dialog.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            components: Vec::new(),
            confirmed: false,
            total_size: 0,
        }
    }

    /// Add a component.
    pub fn add_component(
        &mut self,
        field_name: impl Into<String>,
        type_name: impl Into<String>,
        size: u32,
    ) {
        self.components
            .push((field_name.into(), type_name.into(), size));
        self.total_size += size;
    }

    /// Remove a component by index.
    pub fn remove_component(&mut self, index: usize) -> Option<(String, String, u32)> {
        if index < self.components.len() {
            let removed = self.components.remove(index);
            self.total_size -= removed.2;
            Some(removed)
        } else {
            None
        }
    }

    /// Get the number of components.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Confirm the dialog.
    pub fn confirm(&mut self) {
        self.confirmed = true;
    }

    /// Validate the dialog state.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.is_empty() {
            return Err("Structure name cannot be empty".to_string());
        }
        if self.components.is_empty() {
            return Err("Structure must have at least one component".to_string());
        }
        for (i, (fname, tname, _)) in self.components.iter().enumerate() {
            if fname.is_empty() {
                return Err(format!("Component {} field name cannot be empty", i));
            }
            if tname.is_empty() {
                return Err(format!("Component {} type name cannot be empty", i));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cycle_group_next() {
        let g = CycleGroupDef::new("byte", vec!["byte".into(), "char".into()]);
        assert_eq!(g.next_type("byte"), Some("char"));
        assert_eq!(g.next_type("char"), Some("byte"));
        assert_eq!(g.next_type("unknown"), Some("byte"));
    }

    #[test]
    fn test_cycle_group_previous() {
        let g = CycleGroupDef::new("byte", vec!["byte".into(), "char".into()]);
        assert_eq!(g.previous_type("char"), Some("byte"));
        assert_eq!(g.previous_type("byte"), Some("char"));
    }

    #[test]
    fn test_cycle_group_action() {
        let g = CycleGroupDef::new("word", vec!["word".into(), "short".into()]);
        let action = CycleGroupAction::new(g);
        assert!(action.is_enabled());
        assert_eq!(action.get_next_type("word"), Some("short"));
        assert_eq!(action.name(), "Cycle Group: word");
    }

    #[test]
    fn test_builtin_cycle_groups() {
        let groups = builtin_cycle_groups();
        assert_eq!(groups.len(), 5);
        assert_eq!(groups[0].name, "byte");
        assert_eq!(groups[3].name, "qword");
    }

    #[test]
    fn test_recently_used() {
        let mut recent = RecentlyUsedDataTypes::new(3);
        assert!(recent.is_empty());

        recent.use_type("int");
        recent.use_type("char");
        recent.use_type("float");
        recent.use_type("double");
        assert_eq!(recent.len(), 3);
        assert_eq!(recent.most_recent(), Some("double"));

        // "int" should have been evicted
        let types: Vec<&str> = recent.recent_types().iter().map(|s| s.as_str()).collect();
        assert_eq!(types, vec!["double", "float", "char"]);
    }

    #[test]
    fn test_recently_used_no_duplicates() {
        let mut recent = RecentlyUsedDataTypes::new(5);
        recent.use_type("int");
        recent.use_type("char");
        recent.use_type("int");
        assert_eq!(recent.len(), 2);
        assert_eq!(recent.most_recent(), Some("int"));
    }

    #[test]
    fn test_data_type_settings_dialog_bool() {
        let mut dialog = DataTypeSettingsDialog::new("int");
        dialog.add_bool_setting("signed", "Signed", true, None);
        assert_eq!(dialog.len(), 1);
        assert!(!dialog.is_dirty());

        dialog.set_bool("signed", false);
        assert!(dialog.is_dirty());
        let entry = dialog.get_setting("signed").unwrap();
        assert_eq!(entry.value, SettingValue::Bool(false));
        assert!(entry.modified);
    }

    #[test]
    fn test_data_type_settings_dialog_enum() {
        let mut dialog = DataTypeSettingsDialog::new("int");
        dialog.add_enum_setting(
            "format",
            "Display Format",
            0,
            vec!["Hex".into(), "Decimal".into(), "Octal".into()],
            Some("Choose display format".to_string()),
        );
        dialog.set_enum_index("format", 1);
        let entry = dialog.get_setting("format").unwrap();
        assert!(entry.modified);
    }

    #[test]
    fn test_data_type_settings_dialog_reset() {
        let mut dialog = DataTypeSettingsDialog::new("int");
        dialog.add_bool_setting("signed", "Signed", true, None);
        dialog.set_bool("signed", false);
        assert!(dialog.is_dirty());

        dialog.reset_to_defaults();
        assert!(!dialog.is_dirty());
        let entry = dialog.get_setting("signed").unwrap();
        assert_eq!(entry.value, SettingValue::Bool(true));
        assert!(!entry.modified);
    }

    #[test]
    fn test_rename_data_field_dialog() {
        let mut dialog = RenameDataFieldDialog::new("old_name");
        dialog.set_new_name("new_name");
        assert!(dialog.validate().is_ok());
        dialog.confirm();
        assert!(dialog.confirmed);
    }

    #[test]
    fn test_rename_data_field_dialog_validation() {
        let dialog = RenameDataFieldDialog::new("name");
        assert!(dialog.validate().is_err()); // same name

        let mut dialog = RenameDataFieldDialog::new("name");
        dialog.set_new_name("");
        assert!(dialog.validate().is_err()); // empty

        let mut dialog = RenameDataFieldDialog::new("name");
        dialog.set_new_name("123invalid");
        assert!(dialog.validate().is_err()); // starts with digit

        let mut dialog = RenameDataFieldDialog::new("name");
        dialog.set_new_name("valid_name1");
        assert!(dialog.validate().is_ok());
    }

    #[test]
    fn test_edit_data_field_dialog() {
        let mut dialog = EditDataFieldDialog::new("field1", "int", 0, 4);
        assert!(!dialog.type_changed());

        dialog.set_new_type("float");
        assert!(dialog.type_changed());
        assert!(dialog.validate().is_ok());

        dialog.confirm();
        assert!(dialog.confirmed);
    }

    #[test]
    fn test_create_array_dialog() {
        let mut dialog = CreateArrayDialog::new("int", 10, 4);
        assert_eq!(dialog.total_size(), 40);
        assert!(dialog.validate().is_ok());

        dialog.set_element_count(0);
        assert!(dialog.validate().is_err());
    }

    #[test]
    fn test_create_structure_dialog() {
        let mut dialog = CreateStructureDialog::new("MyStruct");
        dialog.add_component("x", "int", 4);
        dialog.add_component("y", "char", 1);
        assert_eq!(dialog.component_count(), 2);
        assert_eq!(dialog.total_size, 5);
        assert!(dialog.validate().is_ok());
        dialog.confirm();
        assert!(dialog.confirmed);
    }

    #[test]
    fn test_create_structure_dialog_validation() {
        let mut dialog = CreateStructureDialog::new("");
        assert!(dialog.validate().is_err()); // empty name

        let mut dialog = CreateStructureDialog::new("S");
        assert!(dialog.validate().is_err()); // no components

        let mut dialog = CreateStructureDialog::new("S");
        dialog.add_component("", "int", 4);
        assert!(dialog.validate().is_err()); // empty field name
    }

    #[test]
    fn test_setting_value_types() {
        let b = SettingValue::Bool(true);
        assert_eq!(b.as_bool(), Some(true));
        assert!(b.as_int().is_none());

        let i = SettingValue::Int(42);
        assert_eq!(i.as_int(), Some(42));
        assert!(i.as_bool().is_none());

        let s = SettingValue::String("hello".to_string());
        assert_eq!(s.as_string(), Some("hello"));
    }
}
