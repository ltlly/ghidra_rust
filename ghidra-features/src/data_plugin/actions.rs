//! Data plugin actions -- ported from Ghidra's `ghidra.app.plugin.core.data` package.
//!
//! Provides the action types for creating data in the listing:
//! [`DataActionDef`], [`CreateArrayActionDef`], [`CreateStructureActionDef`],
//! [`ChooseDataTypeActionDef`], [`CycleGroupActionDef`], [`PointerDataActionDef`],
//! and [`RecentlyUsedActionDef`].

use ghidra_core::Address;

/// A definition for a data-creation action in the listing context.
///
/// Ported from `ghidra.app.plugin.core.data.DataAction`.
#[derive(Debug, Clone)]
pub struct DataActionDef {
    /// Display name (e.g. "Define byte").
    pub name: String,
    /// Menu group (e.g. "Data").
    pub group: String,
    /// The data type name this action applies.
    pub data_type_name: String,
    /// The popup menu path (e.g. ["Data", "byte"]).
    pub popup_menu_path: Vec<String>,
    /// Optional key binding (e.g. "D").
    pub key_binding: Option<String>,
    /// Help location identifier.
    pub help_id: String,
    /// Whether the action is currently enabled.
    pub enabled: bool,
}

impl DataActionDef {
    /// Create a new data action definition for the given data type.
    pub fn new(data_type_name: impl Into<String>, group: impl Into<String>) -> Self {
        let dt = data_type_name.into();
        let grp = group.into();
        let help_id = classify_help_id(&dt);
        Self {
            name: format!("Define {}", dt),
            group: grp.clone(),
            data_type_name: dt.clone(),
            popup_menu_path: vec!["Data".into(), dt],
            key_binding: None,
            help_id,
            enabled: true,
        }
    }

    /// Set the key binding for this action.
    pub fn with_key_binding(mut self, key: impl Into<String>) -> Self {
        self.key_binding = Some(key.into());
        self
    }
}

/// Classify the help ID based on the data type name.
fn classify_help_id(dt_name: &str) -> String {
    match dt_name {
        n if n.contains("struct") || n.contains("Struct") => "Structure".into(),
        n if n.contains("union") || n.contains("Union") => "Union".into(),
        n if n.contains("pointer") || n.contains("Pointer") => "Define_Pointer".into(),
        _ => "Favorites".into(),
    }
}

// ---------------------------------------------------------------------------
// CreateArrayActionDef
// ---------------------------------------------------------------------------

/// Action definition for creating arrays in the listing.
///
/// Ported from `ghidra.app.plugin.core.data.CreateArrayAction`.
#[derive(Debug, Clone)]
pub struct CreateArrayActionDef {
    /// The display name.
    pub name: String,
    /// Popup menu path.
    pub popup_menu_path: Vec<String>,
    /// Key binding.
    pub key_binding: Option<String>,
    /// Maximum selection size for background processing.
    pub background_selection_threshold: usize,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl Default for CreateArrayActionDef {
    fn default() -> Self {
        Self {
            name: "Create Array...".into(),
            popup_menu_path: vec!["Data".into(), "Create Array...".into()],
            key_binding: Some("[".into()),
            background_selection_threshold: 2048,
            enabled: true,
        }
    }
}

impl CreateArrayActionDef {
    /// Create a new CreateArrayAction definition.
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether this action is valid for the given context.
    pub fn is_enabled_for(
        &self,
        selection_empty: bool,
        has_data_at_cursor: bool,
    ) -> bool {
        !selection_empty || has_data_at_cursor
    }
}

// ---------------------------------------------------------------------------
// CreateStructureActionDef
// ---------------------------------------------------------------------------

/// Action definition for creating structures from a selection.
///
/// Ported from `ghidra.app.plugin.core.data.CreateStructureAction`.
#[derive(Debug, Clone)]
pub struct CreateStructureActionDef {
    /// Display name.
    pub name: String,
    /// Popup menu path.
    pub popup_menu_path: Vec<String>,
    /// Key binding (Shift+[ in Ghidra).
    pub key_binding: Option<String>,
    /// Whether enabled.
    pub enabled: bool,
}

impl Default for CreateStructureActionDef {
    fn default() -> Self {
        Self {
            name: "Create Structure...".into(),
            popup_menu_path: vec!["Data".into(), "Create Structure...".into()],
            key_binding: Some("shift+]".into()),
            enabled: true,
        }
    }
}

impl CreateStructureActionDef {
    /// Create a new definition.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate whether a structure can be created from the given selection info.
    ///
    /// Returns `Ok(())` if valid, or an error message string.
    pub fn validate_selection(
        &self,
        num_ranges: usize,
        num_addresses: u64,
        has_data_at_min: bool,
    ) -> Result<(), String> {
        if num_ranges == 0 {
            return Err("No selection".into());
        }
        if num_ranges > 1 {
            return Err("Can only create structure on contiguous selection".into());
        }
        if num_addresses > u32::MAX as u64 {
            return Err("Can't create structures greater than 0x7fffffff bytes".into());
        }
        if !has_data_at_min {
            return Err("Create structure failed! No data at selection start".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ChooseDataTypeActionDef
// ---------------------------------------------------------------------------

/// Action for choosing a data type from a dialog.
///
/// Ported from `ghidra.app.plugin.core.data.ChooseDataTypeAction`.
#[derive(Debug, Clone)]
pub struct ChooseDataTypeActionDef {
    /// Display name.
    pub name: String,
    /// Popup menu path.
    pub popup_menu_path: Vec<String>,
    /// Key binding.
    pub key_binding: Option<String>,
    /// Whether enabled.
    pub enabled: bool,
}

impl Default for ChooseDataTypeActionDef {
    fn default() -> Self {
        Self {
            name: "Choose Data Type...".into(),
            popup_menu_path: vec!["Data".into(), "Choose Data Type...".into()],
            key_binding: None,
            enabled: true,
        }
    }
}

impl ChooseDataTypeActionDef {
    /// Create a new definition.
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// CycleGroupActionDef
// ---------------------------------------------------------------------------

/// A cycle group defines a set of related data types the user can cycle through
/// with a single key binding.
///
/// Ported from `ghidra.app.plugin.core.data.CycleGroupAction` and
/// `ghidra.program.model.data.CycleGroup`.
#[derive(Debug, Clone)]
pub struct CycleGroupActionDef {
    /// The cycle group name (e.g. "Byte/Word/Dword/Qword").
    pub name: String,
    /// The data types in the cycle, in order.
    pub data_types: Vec<String>,
    /// The default key binding.
    pub key_binding: Option<String>,
    /// Current index in the cycle.
    pub current_index: usize,
    /// Whether the action is enabled.
    pub enabled: bool,
}

impl CycleGroupActionDef {
    /// Create a new cycle group action definition.
    pub fn new(name: impl Into<String>, data_types: Vec<String>) -> Self {
        Self {
            name: name.into(),
            data_types,
            key_binding: None,
            current_index: 0,
            enabled: true,
        }
    }

    /// Get the current data type name in the cycle.
    pub fn current_data_type(&self) -> Option<&str> {
        self.data_types.get(self.current_index).map(|s| s.as_str())
    }

    /// Advance to the next data type in the cycle and return it.
    ///
    /// If `forward` is `true`, advances forward; otherwise backward.
    pub fn next_data_type(&mut self, forward: bool) -> Option<&str> {
        if self.data_types.is_empty() {
            return None;
        }
        if forward {
            self.current_index = (self.current_index + 1) % self.data_types.len();
        } else {
            self.current_index = if self.current_index == 0 {
                self.data_types.len() - 1
            } else {
                self.current_index - 1
            };
        }
        self.current_data_type()
    }

    /// Given a data type name, return the next type in the cycle.
    pub fn get_next_for(&self, current: &str, forward: bool) -> Option<&str> {
        if let Some(idx) = self.data_types.iter().position(|d| d == current) {
            let next = if forward {
                (idx + 1) % self.data_types.len()
            } else if idx == 0 {
                self.data_types.len() - 1
            } else {
                idx - 1
            };
            self.data_types.get(next).map(|s| s.as_str())
        } else {
            self.data_types.first().map(|s| s.as_str())
        }
    }

    /// The number of types in the cycle.
    pub fn len(&self) -> usize {
        self.data_types.len()
    }

    /// Whether the cycle group is empty.
    pub fn is_empty(&self) -> bool {
        self.data_types.is_empty()
    }
}

// ---------------------------------------------------------------------------
// PointerDataActionDef
// ---------------------------------------------------------------------------

/// Action for creating pointer data at the cursor.
///
/// Ported from `ghidra.app.plugin.core.data.PointerDataAction`.
#[derive(Debug, Clone)]
pub struct PointerDataActionDef {
    /// Display name.
    pub name: String,
    /// Popup menu path.
    pub popup_menu_path: Vec<String>,
    /// Key binding ('P' in Ghidra).
    pub key_binding: Option<String>,
    /// Whether enabled.
    pub enabled: bool,
}

impl Default for PointerDataActionDef {
    fn default() -> Self {
        Self {
            name: "Define Pointer".into(),
            popup_menu_path: vec!["Data".into(), "pointer".into()],
            key_binding: Some("P".into()),
            enabled: true,
        }
    }
}

impl PointerDataActionDef {
    /// Create a new definition.
    pub fn new() -> Self {
        Self::default()
    }
}

// ---------------------------------------------------------------------------
// RecentlyUsedActionDef
// ---------------------------------------------------------------------------

/// Action for applying the most recently used data type.
///
/// Ported from `ghidra.app.plugin.core.data.RecentlyUsedAction`.
#[derive(Debug, Clone)]
pub struct RecentlyUsedActionDef {
    /// Display name.
    pub name: String,
    /// The recently used data type name.
    pub data_type_name: Option<String>,
    /// Popup menu path.
    pub popup_menu_path: Vec<String>,
    /// Whether enabled.
    pub enabled: bool,
}

impl Default for RecentlyUsedActionDef {
    fn default() -> Self {
        Self {
            name: "Recently Used".into(),
            data_type_name: None,
            popup_menu_path: vec!["Data".into(), "Recently Used".into()],
            enabled: false,
        }
    }
}

impl RecentlyUsedActionDef {
    /// Create a new definition.
    pub fn new() -> Self {
        Self::default()
    }

    /// Update the recently used data type.
    pub fn update(&mut self, data_type_name: impl Into<String>) {
        self.data_type_name = Some(data_type_name.into());
        self.enabled = true;
        if let Some(ref dt) = self.data_type_name {
            self.name = format!("Recently Used: {}", dt);
        }
    }

    /// Clear the recently used data type.
    pub fn clear(&mut self) {
        self.data_type_name = None;
        self.enabled = false;
        self.name = "Recently Used".into();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_action_def_new() {
        let action = DataActionDef::new("byte", "BasicData");
        assert_eq!(action.name, "Define byte");
        assert_eq!(action.data_type_name, "byte");
        assert_eq!(action.help_id, "Favorites");
        assert!(action.enabled);
    }

    #[test]
    fn test_data_action_def_structure_help_id() {
        let action = DataActionDef::new("my_struct", "Data");
        assert_eq!(action.help_id, "Structure");
    }

    #[test]
    fn test_data_action_def_pointer_help_id() {
        let action = DataActionDef::new("pointer", "Data");
        assert_eq!(action.help_id, "Define_Pointer");
    }

    #[test]
    fn test_create_array_action_default() {
        let action = CreateArrayActionDef::new();
        assert_eq!(action.name, "Create Array...");
        assert_eq!(action.background_selection_threshold, 2048);
        assert!(action.enabled);
    }

    #[test]
    fn test_create_array_action_enabled() {
        let action = CreateArrayActionDef::new();
        // enabled when selection is not empty (has data)
        assert!(action.is_enabled_for(false, true));
        // enabled when selection not empty, even without data at cursor
        assert!(action.is_enabled_for(false, false));
        // disabled when selection empty AND no data at cursor
        assert!(!action.is_enabled_for(true, false));
    }

    #[test]
    fn test_create_structure_action_validate() {
        let action = CreateStructureActionDef::new();
        assert!(action.validate_selection(1, 100, true).is_ok());
        assert!(action.validate_selection(0, 0, false).is_err());
        assert!(action.validate_selection(2, 100, true).is_err());
        assert!(
            action
                .validate_selection(1, u32::MAX as u64 + 1, true)
                .is_err()
        );
    }

    #[test]
    fn test_choose_data_type_action_default() {
        let action = ChooseDataTypeActionDef::new();
        assert_eq!(action.name, "Choose Data Type...");
    }

    #[test]
    fn test_cycle_group_action() {
        let mut group = CycleGroupActionDef::new(
            "Byte/Word/Dword",
            vec!["byte".into(), "word".into(), "dword".into()],
        );
        assert_eq!(group.current_data_type(), Some("byte"));
        assert_eq!(group.next_data_type(true), Some("word"));
        assert_eq!(group.next_data_type(true), Some("dword"));
        assert_eq!(group.next_data_type(true), Some("byte"));
    }

    #[test]
    fn test_cycle_group_backward() {
        let mut group = CycleGroupActionDef::new(
            "Sizes",
            vec!["byte".into(), "word".into(), "dword".into()],
        );
        assert_eq!(group.next_data_type(false), Some("dword"));
    }

    #[test]
    fn test_cycle_group_get_next_for() {
        let group = CycleGroupActionDef::new(
            "Sizes",
            vec!["byte".into(), "word".into(), "dword".into()],
        );
        assert_eq!(group.get_next_for("byte", true), Some("word"));
        assert_eq!(group.get_next_for("dword", true), Some("byte"));
        assert_eq!(group.get_next_for("byte", false), Some("dword"));
        assert_eq!(group.get_next_for("unknown", true), Some("byte"));
    }

    #[test]
    fn test_cycle_group_empty() {
        let group = CycleGroupActionDef::new("Empty", vec![]);
        assert!(group.is_empty());
        assert_eq!(group.current_data_type(), None);
    }

    #[test]
    fn test_pointer_data_action_default() {
        let action = PointerDataActionDef::new();
        assert_eq!(action.name, "Define Pointer");
        assert_eq!(action.key_binding, Some("P".into()));
    }

    #[test]
    fn test_recently_used_action_update() {
        let mut action = RecentlyUsedActionDef::new();
        assert!(!action.enabled);
        action.update("float");
        assert!(action.enabled);
        assert_eq!(action.data_type_name, Some("float".into()));
        assert_eq!(action.name, "Recently Used: float");
    }

    #[test]
    fn test_recently_used_action_clear() {
        let mut action = RecentlyUsedActionDef::new();
        action.update("float");
        action.clear();
        assert!(!action.enabled);
        assert!(action.data_type_name.is_none());
    }

    #[test]
    fn test_data_action_def_with_key_binding() {
        let action = DataActionDef::new("byte", "BasicData").with_key_binding("B");
        assert_eq!(action.key_binding, Some("B".into()));
    }
}
