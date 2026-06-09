//! Data settings dialog -- ported from `DataSettingsDialog.java` and
//! `DataTypeSettingsDialog.java`.
//!
//! This module provides the dialog logic for editing data instance
//! settings (display format, endianness, etc.) and data type default
//! settings.  It builds on the settings data model in [`super::settings`]
//! by adding dialog-specific state such as validation, apply/cancel
//! lifecycle, and per-setting change tracking.
//!
//! # Relationship to `settings.rs`
//!
//! The sibling [`super::settings`] module provides the data model types
//! (`DataSettings`, `DataTypeSettings`, `SettingsDialogModel`).  This
//! module provides the richer dialog-level logic that wraps those models
//! with validation, undo, and apply semantics.

use std::collections::HashMap;

use super::settings::{DataSettings, DataTypeSettings, SettingsEntry};

// ---------------------------------------------------------------------------
// SettingsChangeKind
// ---------------------------------------------------------------------------

/// The kind of change applied to a setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsChangeKind {
    /// A setting value was modified.
    Modified,
    /// A setting was reset to its default.
    Reset,
    /// All settings were reset to defaults.
    ResetAll,
}

// ---------------------------------------------------------------------------
// SettingsChangeRecord
// ---------------------------------------------------------------------------

/// A record of a single settings change.
#[derive(Debug, Clone)]
pub struct SettingsChangeRecord {
    /// The name of the setting that changed.
    pub setting_name: String,
    /// The kind of change.
    pub kind: SettingsChangeKind,
    /// The old value (before the change).
    pub old_value: String,
    /// The new value (after the change).
    pub new_value: String,
}

impl SettingsChangeRecord {
    /// Creates a new change record.
    pub fn new(
        setting_name: impl Into<String>,
        kind: SettingsChangeKind,
        old_value: impl Into<String>,
        new_value: impl Into<String>,
    ) -> Self {
        Self {
            setting_name: setting_name.into(),
            kind,
            old_value: old_value.into(),
            new_value: new_value.into(),
        }
    }

    /// Returns a human-readable summary of this change.
    pub fn summary(&self) -> String {
        match self.kind {
            SettingsChangeKind::Modified => {
                format!("{}: {} -> {}", self.setting_name, self.old_value, self.new_value)
            }
            SettingsChangeKind::Reset => {
                format!("{}: reset to {}", self.setting_name, self.new_value)
            }
            SettingsChangeKind::ResetAll => "All settings reset to defaults".to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// SettingsValidation
// ---------------------------------------------------------------------------

/// The result of validating a settings change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsValidation {
    /// The change is valid.
    Valid,
    /// The change is invalid with a reason.
    Invalid(String),
    /// The change requires confirmation (e.g., will affect multiple items).
    RequiresConfirmation(String),
}

impl SettingsValidation {
    /// Returns `true` if the validation passed.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns `true` if the validation requires user confirmation.
    pub fn requires_confirmation(&self) -> bool {
        matches!(self, Self::RequiresConfirmation(_))
    }

    /// Returns the error/confirmation message, if any.
    pub fn message(&self) -> Option<&str> {
        match self {
            Self::Valid => None,
            Self::Invalid(msg) | Self::RequiresConfirmation(msg) => Some(msg),
        }
    }
}

// ---------------------------------------------------------------------------
// DataSettingsDialogModel
// ---------------------------------------------------------------------------

/// Model for the Data Settings dialog.
///
/// Ported from `DataSettingsDialog.java`.  This dialog lets the user
/// edit the settings for a specific data instance in the listing.
///
/// # Lifecycle
///
/// 1. Create with [`DataSettingsDialogModel::new`].
/// 2. The user edits settings via [`set_value`].
/// 3. Each edit is validated and recorded as a change.
/// 4. The user confirms with [`apply`] or cancels with [`cancel`].
/// 5. If applied, the changes can be retrieved via [`changes`].
///
/// # Example
///
/// ```
/// use ghidra_features::base::data::data_settings_dialog::*;
/// use ghidra_features::base::data::settings::SettingsEntry;
///
/// let mut initial = DataSettings::new();
/// initial.add(SettingsEntry::with_allowed("Format", "hex", vec!["hex".into(), "dec".into()]));
///
/// let mut dialog = DataSettingsDialogModel::new("Data Settings", initial);
/// assert_eq!(dialog.title(), "Data Settings");
///
/// dialog.set_value("Format", "dec");
/// assert!(dialog.has_changes());
///
/// dialog.apply();
/// assert!(dialog.is_applied());
/// ```
#[derive(Debug, Clone)]
pub struct DataSettingsDialogModel {
    /// The dialog title.
    title: String,
    /// The original settings (before edits).
    original: DataSettings,
    /// The current (edited) settings.
    current: DataSettings,
    /// Whether the dialog has been applied.
    applied: bool,
    /// Whether the dialog has been cancelled.
    cancelled: bool,
    /// The change history.
    changes: Vec<SettingsChangeRecord>,
    /// Validation overrides (setting name -> custom allowed values).
    allowed_value_overrides: HashMap<String, Vec<String>>,
    /// Help location category.
    help_category: Option<String>,
    /// Help location topic.
    help_topic: Option<String>,
}

impl DataSettingsDialogModel {
    /// Creates a new data settings dialog model.
    pub fn new(title: impl Into<String>, settings: DataSettings) -> Self {
        Self {
            title: title.into(),
            original: settings.clone(),
            current: settings,
            applied: false,
            cancelled: false,
            changes: Vec::new(),
            allowed_value_overrides: HashMap::new(),
            help_category: None,
            help_topic: None,
        }
    }

    /// Returns the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the current (edited) settings.
    pub fn current(&self) -> &DataSettings {
        &self.current
    }

    /// Returns the original (unedited) settings.
    pub fn original(&self) -> &DataSettings {
        &self.original
    }

    /// Returns the current settings value for a given name.
    pub fn get_value(&self, name: &str) -> Option<&str> {
        self.current.get(name)
    }

    /// Sets a setting value with validation.
    ///
    /// Returns a validation result.  If the change is invalid, the
    /// setting is not modified.
    pub fn set_value(&mut self, name: &str, value: &str) -> SettingsValidation {
        let validation = self.validate(name, value);
        if !validation.is_valid() {
            return validation;
        }

        let old_value = self.current.get(name).unwrap_or("").to_string();

        // Record the change
        self.changes.push(SettingsChangeRecord::new(
            name,
            SettingsChangeKind::Modified,
            &old_value,
            value,
        ));

        // Apply the change
        self.current.set(name, value);

        validation
    }

    /// Validates a potential setting change.
    fn validate(&self, name: &str, value: &str) -> SettingsValidation {
        // Check if the setting exists
        if self.current.get(name).is_none() {
            return SettingsValidation::Invalid(format!("Unknown setting: {}", name));
        }

        // Check against allowed values override
        if let Some(allowed) = self.allowed_value_overrides.get(name) {
            if !allowed.iter().any(|v| v == value) {
                return SettingsValidation::Invalid(format!(
                    "Value '{}' not in allowed values for '{}'",
                    value, name
                ));
            }
        }

        SettingsValidation::Valid
    }

    /// Resets a single setting to its original value.
    pub fn reset_setting(&mut self, name: &str) -> bool {
        if let Some(original_value) = self.original.get(name) {
            let current_value = self.current.get(name).unwrap_or("").to_string();
            let original = original_value.to_string();

            self.changes.push(SettingsChangeRecord::new(
                name,
                SettingsChangeKind::Reset,
                &current_value,
                &original,
            ));

            self.current.set(name, &original);
            true
        } else {
            false
        }
    }

    /// Resets all settings to their original values.
    pub fn reset_all(&mut self) {
        self.changes.push(SettingsChangeRecord::new(
            "",
            SettingsChangeKind::ResetAll,
            "",
            "",
        ));
        self.current = self.original.clone();
    }

    /// Returns the change history.
    pub fn changes(&self) -> &[SettingsChangeRecord] {
        &self.changes
    }

    /// Returns `true` if any settings have been changed from the original.
    pub fn has_changes(&self) -> bool {
        self.changes.iter().any(|c| c.kind != SettingsChangeKind::ResetAll)
            && self.current.modified_names() != self.original.modified_names()
            || self.current.iter().any(|entry| {
                self.original
                    .get(&entry.name)
                    .map_or(true, |orig| orig != entry.value)
            })
    }

    /// Applies the dialog, accepting all changes.
    pub fn apply(&mut self) {
        self.applied = true;
    }

    /// Cancels the dialog, discarding all changes.
    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.current = self.original.clone();
        self.changes.clear();
    }

    /// Returns whether the dialog has been applied.
    pub fn is_applied(&self) -> bool {
        self.applied
    }

    /// Returns whether the dialog has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Returns whether the dialog is finished (applied or cancelled).
    pub fn is_finished(&self) -> bool {
        self.applied || self.cancelled
    }

    /// Sets allowed value overrides for a setting.
    pub fn set_allowed_values(&mut self, name: impl Into<String>, values: Vec<String>) {
        self.allowed_value_overrides.insert(name.into(), values);
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

// ---------------------------------------------------------------------------
// DataTypeSettingsDialogModel
// ---------------------------------------------------------------------------

/// Model for the Data Type Settings dialog.
///
/// Ported from `DataTypeSettingsDialog.java`.  This dialog lets the user
/// edit the default settings for a data type (as opposed to a specific
/// data instance).
///
/// # Example
///
/// ```
/// use ghidra_features::base::data::data_settings_dialog::*;
/// use ghidra_features::base::data::settings::SettingsEntry;
///
/// let mut dts = DataTypeSettings::new("int");
/// dts.add(SettingsEntry::with_allowed("Format", "hex", vec!["hex".into(), "dec".into()]));
///
/// let mut dialog = DataTypeSettingsDialogModel::new("int Settings", dts);
/// dialog.set_value("Format", "dec");
/// dialog.apply();
/// assert!(dialog.is_applied());
/// ```
#[derive(Debug, Clone)]
pub struct DataTypeSettingsDialogModel {
    /// The dialog title.
    title: String,
    /// The data type name.
    data_type_name: String,
    /// The original settings.
    original: DataTypeSettings,
    /// The current (edited) settings.
    current: DataTypeSettings,
    /// Whether the dialog has been applied.
    applied: bool,
    /// Whether the dialog has been cancelled.
    cancelled: bool,
    /// The change history.
    changes: Vec<SettingsChangeRecord>,
    /// Help location category.
    help_category: Option<String>,
    /// Help location topic.
    help_topic: Option<String>,
}

impl DataTypeSettingsDialogModel {
    /// Creates a new data type settings dialog model.
    pub fn new(title: impl Into<String>, settings: DataTypeSettings) -> Self {
        let data_type_name = settings.data_type_name().to_string();
        Self {
            title: title.into(),
            data_type_name,
            original: settings.clone(),
            current: settings,
            applied: false,
            cancelled: false,
            changes: Vec::new(),
            help_category: None,
            help_topic: None,
        }
    }

    /// Returns the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the data type name.
    pub fn data_type_name(&self) -> &str {
        &self.data_type_name
    }

    /// Returns the current settings value for a given name.
    pub fn get_value(&self, name: &str) -> Option<&str> {
        self.current.get(name)
    }

    /// Sets a setting value.
    pub fn set_value(&mut self, name: &str, value: &str) -> bool {
        if self.current.get(name).is_none() {
            return false;
        }

        let old_value = self.current.get(name).unwrap_or("").to_string();

        self.changes.push(SettingsChangeRecord::new(
            name,
            SettingsChangeKind::Modified,
            &old_value,
            value,
        ));

        self.current.set(name, value);
        true
    }

    /// Resets all settings to their original values.
    pub fn reset_all(&mut self) {
        self.changes.push(SettingsChangeRecord::new(
            "",
            SettingsChangeKind::ResetAll,
            "",
            "",
        ));
        // Clone the original entries back
        for entry in self.original.to_data_settings().iter() {
            self.current.set(&entry.name, &entry.value);
        }
    }

    /// Returns the change history.
    pub fn changes(&self) -> &[SettingsChangeRecord] {
        &self.changes
    }

    /// Returns whether any settings have been changed.
    pub fn has_changes(&self) -> bool {
        self.current.to_data_settings().has_modifications()
    }

    /// Applies the dialog, accepting all changes.
    pub fn apply(&mut self) {
        self.applied = true;
    }

    /// Cancels the dialog, discarding all changes.
    pub fn cancel(&mut self) {
        self.cancelled = true;
        for entry in self.original.to_data_settings().iter() {
            self.current.set(&entry.name, &entry.value);
        }
        self.changes.clear();
    }

    /// Returns whether the dialog has been applied.
    pub fn is_applied(&self) -> bool {
        self.applied
    }

    /// Returns whether the dialog has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Returns whether the dialog is finished (applied or cancelled).
    pub fn is_finished(&self) -> bool {
        self.applied || self.cancelled
    }

    /// Returns the current data type settings.
    pub fn current_settings(&self) -> &DataTypeSettings {
        &self.current
    }

    /// Returns the original data type settings.
    pub fn original_settings(&self) -> &DataTypeSettings {
        &self.original
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

// ---------------------------------------------------------------------------
// MultiDataSettingsDialogModel
// ---------------------------------------------------------------------------

/// Model for editing settings across multiple data items.
///
/// When the user selects multiple data items and opens the settings
/// dialog, this model computes the common settings and applies changes
/// to all selected items.
///
/// # Example
///
/// ```
/// use ghidra_features::base::data::data_settings_dialog::*;
/// use ghidra_features::base::data::settings::SettingsEntry;
///
/// let mut ds1 = DataSettings::new();
/// ds1.add(SettingsEntry::with_allowed("Format", "hex", vec!["hex".into(), "dec".into()]));
///
/// let mut ds2 = DataSettings::new();
/// ds2.add(SettingsEntry::with_allowed("Format", "hex", vec!["hex".into(), "dec".into()]));
///
/// let mut dialog = MultiDataSettingsDialogModel::new("Settings", vec![ds1, ds2]);
/// dialog.set_common_value("Format", "dec");
/// dialog.apply();
/// assert!(dialog.is_applied());
/// assert_eq!(dialog.applied_settings().len(), 2);
/// ```
#[derive(Debug, Clone)]
pub struct MultiDataSettingsDialogModel {
    /// The dialog title.
    title: String,
    /// The number of items being edited.
    item_count: usize,
    /// The common settings computed from all items.
    common: DataSettings,
    /// The current (edited) common settings.
    current: DataSettings,
    /// Whether the dialog has been applied.
    applied: bool,
    /// Whether the dialog has been cancelled.
    cancelled: bool,
    /// The change history.
    changes: Vec<SettingsChangeRecord>,
    /// Help location category.
    help_category: Option<String>,
    /// Help location topic.
    help_topic: Option<String>,
}

impl MultiDataSettingsDialogModel {
    /// Creates a new multi-data settings dialog model.
    ///
    /// Computes the common settings from the provided list.
    pub fn new(title: impl Into<String>, settings_list: Vec<DataSettings>) -> Self {
        let item_count = settings_list.len();
        let common = DataSettings::common_settings(&settings_list);
        Self {
            title: title.into(),
            item_count,
            common: common.clone(),
            current: common,
            applied: false,
            cancelled: false,
            changes: Vec::new(),
            help_category: None,
            help_topic: None,
        }
    }

    /// Returns the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the number of items being edited.
    pub fn item_count(&self) -> usize {
        self.item_count
    }

    /// Returns the common settings.
    pub fn common_settings(&self) -> &DataSettings {
        &self.common
    }

    /// Returns the current (edited) settings.
    pub fn current(&self) -> &DataSettings {
        &self.current
    }

    /// Gets a common setting value.
    pub fn get_common_value(&self, name: &str) -> Option<&str> {
        self.current.get(name)
    }

    /// Sets a common setting value.
    pub fn set_common_value(&mut self, name: &str, value: &str) -> bool {
        if self.current.get(name).is_none() {
            return false;
        }

        let old_value = self.current.get(name).unwrap_or("").to_string();

        self.changes.push(SettingsChangeRecord::new(
            name,
            SettingsChangeKind::Modified,
            &old_value,
            value,
        ));

        self.current.set(name, value);
        true
    }

    /// Returns the change history.
    pub fn changes(&self) -> &[SettingsChangeRecord] {
        &self.changes
    }

    /// Returns whether any settings have been changed.
    pub fn has_changes(&self) -> bool {
        self.current.has_modifications()
    }

    /// Applies the dialog, accepting all changes.
    ///
    /// After applying, the changed settings can be retrieved via
    /// [`applied_settings`].
    pub fn apply(&mut self) {
        self.applied = true;
    }

    /// Cancels the dialog.
    pub fn cancel(&mut self) {
        self.cancelled = true;
        self.current = self.common.clone();
        self.changes.clear();
    }

    /// Returns whether the dialog has been applied.
    pub fn is_applied(&self) -> bool {
        self.applied
    }

    /// Returns whether the dialog has been cancelled.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled
    }

    /// Returns the settings to apply to each item after a successful apply.
    ///
    /// Returns `None` if the dialog has not been applied.
    pub fn applied_settings(&self) -> Option<Vec<DataSettings>> {
        if !self.applied {
            return None;
        }
        Some(vec![self.current.clone(); self.item_count])
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_settings() -> DataSettings {
        let mut ds = DataSettings::new();
        ds.add(SettingsEntry::with_allowed("Format", "hex", vec!["hex".into(), "dec".into()]));
        ds.add(SettingsEntry::with_allowed("Endian", "little", vec!["little".into(), "big".into()]));
        ds
    }

    // -- DataSettingsDialogModel --

    #[test]
    fn test_dialog_new() {
        let dialog = DataSettingsDialogModel::new("Test Dialog", make_settings());
        assert_eq!(dialog.title(), "Test Dialog");
        assert!(!dialog.is_applied());
        assert!(!dialog.is_cancelled());
        assert!(!dialog.has_changes());
    }

    #[test]
    fn test_dialog_get_value() {
        let dialog = DataSettingsDialogModel::new("Test", make_settings());
        assert_eq!(dialog.get_value("Format"), Some("hex"));
        assert_eq!(dialog.get_value("Missing"), None);
    }

    #[test]
    fn test_dialog_set_value() {
        let mut dialog = DataSettingsDialogModel::new("Test", make_settings());
        let result = dialog.set_value("Format", "dec");
        assert!(result.is_valid());
        assert_eq!(dialog.get_value("Format"), Some("dec"));
        assert!(dialog.has_changes());
        assert_eq!(dialog.changes().len(), 1);
    }

    #[test]
    fn test_dialog_set_value_unknown() {
        let mut dialog = DataSettingsDialogModel::new("Test", make_settings());
        let result = dialog.set_value("Unknown", "value");
        assert!(!result.is_valid());
    }

    #[test]
    fn test_dialog_allowed_value_override() {
        let mut dialog = DataSettingsDialogModel::new("Test", make_settings());
        dialog.set_allowed_values("Format", vec!["hex".into(), "oct".into()]);

        // "dec" is not in the override
        let result = dialog.set_value("Format", "dec");
        assert!(!result.is_valid());

        // "oct" is in the override (but not in the original allowed values)
        let result = dialog.set_value("Format", "oct");
        assert!(result.is_valid());
    }

    #[test]
    fn test_dialog_reset_setting() {
        let mut dialog = DataSettingsDialogModel::new("Test", make_settings());
        dialog.set_value("Format", "dec");
        assert_eq!(dialog.get_value("Format"), Some("dec"));

        assert!(dialog.reset_setting("Format"));
        assert_eq!(dialog.get_value("Format"), Some("hex"));
    }

    #[test]
    fn test_dialog_reset_all() {
        let mut dialog = DataSettingsDialogModel::new("Test", make_settings());
        dialog.set_value("Format", "dec");
        dialog.set_value("Endian", "big");

        dialog.reset_all();
        assert_eq!(dialog.get_value("Format"), Some("hex"));
        assert_eq!(dialog.get_value("Endian"), Some("little"));
    }

    #[test]
    fn test_dialog_apply() {
        let mut dialog = DataSettingsDialogModel::new("Test", make_settings());
        dialog.set_value("Format", "dec");
        dialog.apply();
        assert!(dialog.is_applied());
        assert!(dialog.is_finished());
    }

    #[test]
    fn test_dialog_cancel() {
        let mut dialog = DataSettingsDialogModel::new("Test", make_settings());
        dialog.set_value("Format", "dec");
        dialog.cancel();
        assert!(dialog.is_cancelled());
        assert!(dialog.is_finished());
        // Value should be reverted
        assert_eq!(dialog.get_value("Format"), Some("hex"));
    }

    #[test]
    fn test_dialog_help() {
        let mut dialog = DataSettingsDialogModel::new("Test", make_settings());
        dialog.set_help("DataPlugin", "Data_Settings");
        assert_eq!(dialog.help_category(), Some("DataPlugin"));
        assert_eq!(dialog.help_topic(), Some("Data_Settings"));
    }

    #[test]
    fn test_dialog_original_preserved() {
        let mut dialog = DataSettingsDialogModel::new("Test", make_settings());
        dialog.set_value("Format", "dec");
        // Original should not change
        assert_eq!(dialog.original().get("Format"), Some("hex"));
    }

    // -- DataTypeSettingsDialogModel --

    #[test]
    fn test_dt_dialog_new() {
        let mut dts = DataTypeSettings::new("int");
        dts.add(SettingsEntry::with_allowed("Format", "hex", vec!["hex".into(), "dec".into()]));

        let dialog = DataTypeSettingsDialogModel::new("int Settings", dts);
        assert_eq!(dialog.title(), "int Settings");
        assert_eq!(dialog.data_type_name(), "int");
        assert!(!dialog.is_applied());
    }

    #[test]
    fn test_dt_dialog_set_value() {
        let mut dts = DataTypeSettings::new("int");
        dts.add(SettingsEntry::with_allowed("Format", "hex", vec!["hex".into(), "dec".into()]));

        let mut dialog = DataTypeSettingsDialogModel::new("int Settings", dts);
        assert!(dialog.set_value("Format", "dec"));
        assert_eq!(dialog.get_value("Format"), Some("dec"));
    }

    #[test]
    fn test_dt_dialog_set_value_unknown() {
        let mut dts = DataTypeSettings::new("int");
        dts.add(SettingsEntry::new("Format", "hex"));

        let mut dialog = DataTypeSettingsDialogModel::new("int Settings", dts);
        assert!(!dialog.set_value("Unknown", "value"));
    }

    #[test]
    fn test_dt_dialog_apply_cancel() {
        let mut dts = DataTypeSettings::new("int");
        dts.add(SettingsEntry::new("Format", "hex"));

        let mut dialog = DataTypeSettingsDialogModel::new("int Settings", dts);
        dialog.set_value("Format", "dec");
        dialog.apply();
        assert!(dialog.is_applied());

        let mut dts2 = DataTypeSettings::new("int");
        dts2.add(SettingsEntry::new("Format", "hex"));
        let mut dialog2 = DataTypeSettingsDialogModel::new("int Settings", dts2);
        dialog2.set_value("Format", "dec");
        dialog2.cancel();
        assert!(dialog2.is_cancelled());
    }

    #[test]
    fn test_dt_dialog_help() {
        let dts = DataTypeSettings::new("int");
        let mut dialog = DataTypeSettingsDialogModel::new("int Settings", dts);
        dialog.set_help("DataPlugin", "DataType_Settings");
        assert_eq!(dialog.help_category(), Some("DataPlugin"));
    }

    // -- MultiDataSettingsDialogModel --

    #[test]
    fn test_multi_dialog_new() {
        let dialog = MultiDataSettingsDialogModel::new("Settings", vec![make_settings(), make_settings()]);
        assert_eq!(dialog.title(), "Settings");
        assert_eq!(dialog.item_count(), 2);
    }

    #[test]
    fn test_multi_dialog_common_settings() {
        let mut ds1 = DataSettings::new();
        ds1.add(SettingsEntry::with_allowed("Format", "hex", vec!["hex".into(), "dec".into()]));
        ds1.add(SettingsEntry::new("Endian", "little"));

        let mut ds2 = DataSettings::new();
        ds2.add(SettingsEntry::with_allowed("Format", "hex", vec!["hex".into(), "dec".into()]));
        ds2.add(SettingsEntry::new("Endian", "big"));

        let dialog = MultiDataSettingsDialogModel::new("Settings", vec![ds1, ds2]);
        // Format is common, Endian differs
        assert_eq!(dialog.get_common_value("Format"), Some("hex"));
        assert_eq!(dialog.get_common_value("Endian"), None);
    }

    #[test]
    fn test_multi_dialog_set_value() {
        let mut dialog = MultiDataSettingsDialogModel::new("Settings", vec![make_settings(), make_settings()]);
        assert!(dialog.set_common_value("Format", "dec"));
        assert_eq!(dialog.get_common_value("Format"), Some("dec"));
        assert!(dialog.has_changes());
    }

    #[test]
    fn test_multi_dialog_set_value_missing() {
        let mut dialog = MultiDataSettingsDialogModel::new("Settings", vec![make_settings(), make_settings()]);
        assert!(!dialog.set_common_value("Missing", "value"));
    }

    #[test]
    fn test_multi_dialog_apply() {
        let mut dialog = MultiDataSettingsDialogModel::new("Settings", vec![make_settings(), make_settings()]);
        dialog.set_common_value("Format", "dec");
        dialog.apply();

        assert!(dialog.is_applied());
        let applied = dialog.applied_settings().unwrap();
        assert_eq!(applied.len(), 2);
        assert_eq!(applied[0].get("Format"), Some("dec"));
    }

    #[test]
    fn test_multi_dialog_cancel() {
        let mut dialog = MultiDataSettingsDialogModel::new("Settings", vec![make_settings(), make_settings()]);
        dialog.set_common_value("Format", "dec");
        dialog.cancel();

        assert!(dialog.is_cancelled());
        assert!(dialog.applied_settings().is_none());
    }

    #[test]
    fn test_multi_dialog_help() {
        let mut dialog = MultiDataSettingsDialogModel::new("Settings", vec![make_settings()]);
        dialog.set_help("DataPlugin", "Multi_Settings");
        assert_eq!(dialog.help_category(), Some("DataPlugin"));
        assert_eq!(dialog.help_topic(), Some("Multi_Settings"));
    }

    // -- SettingsValidation --

    #[test]
    fn test_validation() {
        assert!(SettingsValidation::Valid.is_valid());
        assert!(!SettingsValidation::Invalid("err".into()).is_valid());
        assert!(!SettingsValidation::RequiresConfirmation("confirm".into()).is_valid());
        assert!(SettingsValidation::RequiresConfirmation("".into()).requires_confirmation());
    }

    #[test]
    fn test_validation_message() {
        assert!(SettingsValidation::Valid.message().is_none());
        assert_eq!(
            SettingsValidation::Invalid("bad".into()).message(),
            Some("bad")
        );
    }

    // -- SettingsChangeRecord --

    #[test]
    fn test_change_record_summary() {
        let record = SettingsChangeRecord::new(
            "Format",
            SettingsChangeKind::Modified,
            "hex",
            "dec",
        );
        assert_eq!(record.summary(), "Format: hex -> dec");

        let reset = SettingsChangeRecord::new(
            "Format",
            SettingsChangeKind::Reset,
            "dec",
            "hex",
        );
        assert_eq!(reset.summary(), "Format: reset to hex");

        let reset_all = SettingsChangeRecord::new("", SettingsChangeKind::ResetAll, "", "");
        assert_eq!(reset_all.summary(), "All settings reset to defaults");
    }
}
