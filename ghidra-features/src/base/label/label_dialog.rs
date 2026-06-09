//! Add/edit label dialog for creating and modifying labels.
//!
//! Ported from Ghidra's `AddEditDialog` (`AddEditDialog.java`).
//!
//! This module provides the dialog model used when the user adds a new
//! label or edits an existing one. It handles:
//!
//! - Label name input with validation
//! - Namespace selection (global, local, function-local, recent)
//! - Checkbox options: primary, entry point, pinned
//! - Recent label name history
//! - Add vs. edit mode initialization
//! - OK/Cancel lifecycle with status reporting
//!
//! GUI-specific code (Swing components) is not ported; instead, the
//! module provides data structures and logic that can be driven by
//! any frontend.

use std::collections::VecDeque;

use ghidra_core::addr::Address;
use ghidra_core::symbol::{SourceType, SymbolType};

use super::operand_label::validate_label_name;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of recent label names to retain.
const MAX_RECENT_LABELS: usize = 10;

/// Maximum number of recent namespaces to retain.
const MAX_RECENT_NAMESPACES: usize = 10;

// ---------------------------------------------------------------------------
// NamespaceOption
// ---------------------------------------------------------------------------

/// A selectable namespace entry in the dialog's namespace combo box.
///
/// Mirrors Ghidra's `NamespaceWrapper` inner class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceOption {
    /// The namespace ID (0 for global).
    pub id: u64,
    /// The display name (fully qualified, e.g. "MyNamespace::SubNs").
    pub display_name: String,
    /// Whether this is the global namespace.
    pub is_global: bool,
    /// Whether this is a function namespace.
    pub is_function: bool,
}

impl NamespaceOption {
    /// Creates the global namespace option.
    pub fn global() -> Self {
        Self {
            id: 0,
            display_name: "Global".to_string(),
            is_global: true,
            is_function: false,
        }
    }

    /// Creates a namespace option.
    pub fn new(id: u64, display_name: impl Into<String>) -> Self {
        Self {
            id,
            display_name: display_name.into(),
            is_global: false,
            is_function: false,
        }
    }

    /// Creates a function namespace option.
    pub fn function(id: u64, display_name: impl Into<String>) -> Self {
        Self {
            id,
            display_name: display_name.into(),
            is_global: false,
            is_function: true,
        }
    }
}

// ---------------------------------------------------------------------------
// LabelDialogMode
// ---------------------------------------------------------------------------

/// The operating mode of the dialog.
///
/// In Ghidra, the dialog title, checkbox states, and namespace
/// selection behavior differ between add and edit modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LabelDialogMode {
    /// Adding a new label.
    Add,
    /// Editing an existing label.
    Edit,
    /// Renaming a function.
    RenameFunction,
    /// Renaming a variable (parameter or local).
    RenameVariable,
    /// Editing an external label.
    EditExternal,
}

impl LabelDialogMode {
    /// Returns whether this mode is an edit operation.
    pub fn is_edit(self) -> bool {
        !matches!(self, LabelDialogMode::Add)
    }
}

// ---------------------------------------------------------------------------
// AddEditDialog
// ---------------------------------------------------------------------------

/// Dialog for adding a new label or editing an existing one.
///
/// Ported from Ghidra's `AddEditDialog`. This models the dialog state
/// and logic without GUI dependencies:
///
/// - Label name text input with a combo box of recent names
/// - Namespace selection with a combo box of available namespaces
/// - Checkboxes for Primary, Entry Point, and Pinned properties
/// - OK/Cancel lifecycle with validation and status messages
///
/// # Example
///
/// ```
/// use ghidra_features::base::label::label_dialog::{AddEditDialog, LabelDialogMode};
/// use ghidra_core::addr::Address;
///
/// // Create a dialog for adding a label
/// let mut dialog = AddEditDialog::new_add(Address::new(0x1000));
/// assert_eq!(dialog.mode(), LabelDialogMode::Add);
/// assert_eq!(dialog.title(), "Add Label at 0x1000");
///
/// // Set a label name and confirm
/// dialog.set_label_name("main");
/// assert!(dialog.validate().is_ok());
/// ```
pub struct AddEditDialog {
    /// The dialog title.
    title: String,
    /// The operating mode.
    mode: LabelDialogMode,
    /// The address where the label is being added/edited.
    address: Address,
    /// The label name text input.
    label_name: String,
    /// Available namespaces (combo box items).
    namespaces: Vec<NamespaceOption>,
    /// Index of the selected namespace.
    selected_namespace_index: Option<usize>,
    /// Whether the namespace chooser is enabled.
    namespace_enabled: bool,
    /// Whether the "Primary" checkbox is checked.
    primary_checked: bool,
    /// Whether the "Primary" checkbox is enabled.
    primary_enabled: bool,
    /// Whether the "Entry Point" checkbox is checked.
    entry_point_checked: bool,
    /// Whether the "Entry Point" checkbox is enabled.
    entry_point_enabled: bool,
    /// Whether the "Pinned" checkbox is checked.
    pinned_checked: bool,
    /// Whether the "Pinned" checkbox is enabled.
    pinned_enabled: bool,
    /// Recent label names (most recent first).
    recent_labels: VecDeque<String>,
    /// Recent namespace selections (most recent first).
    recent_namespaces: VecDeque<u64>,
    /// The existing symbol name (when editing), if any.
    existing_name: Option<String>,
    /// The existing symbol type (when editing), if any.
    existing_symbol_type: Option<SymbolType>,
    /// The existing symbol source (when editing), if any.
    existing_source: Option<SourceType>,
    /// Whether the existing symbol is external.
    existing_is_external: bool,
    /// Whether the existing symbol is primary.
    existing_is_primary: bool,
    /// Whether the existing symbol is pinned.
    existing_is_pinned: bool,
    /// Whether the existing symbol is an external entry point.
    existing_is_entry_point: bool,
    /// Whether the dialog was confirmed (OK pressed).
    confirmed: bool,
    /// The status message (set on validation failure).
    status_message: Option<String>,
    /// Whether the dialog is reusable (does not dispose on close).
    reusable: bool,
    /// Help topic.
    help_topic: String,
    /// Help anchor.
    help_anchor: String,
}

impl AddEditDialog {
    /// Creates a dialog in Add mode for the given address.
    ///
    /// Mirrors `initDialogForAdd(Program p, Address address)` in Java.
    /// The dialog title is set to "Add Label at {address}".
    pub fn new_add(address: Address) -> Self {
        let title = format!("Add Label at 0x{:X}", address.offset);
        let namespaces = vec![NamespaceOption::global()];

        Self {
            title,
            mode: LabelDialogMode::Add,
            address,
            label_name: String::new(),
            namespaces,
            selected_namespace_index: Some(0),
            namespace_enabled: true,
            primary_checked: false,
            primary_enabled: true,
            entry_point_checked: false,
            entry_point_enabled: true,
            pinned_checked: false,
            pinned_enabled: true,
            recent_labels: VecDeque::new(),
            recent_namespaces: VecDeque::new(),
            existing_name: None,
            existing_symbol_type: None,
            existing_source: None,
            existing_is_external: false,
            existing_is_primary: false,
            existing_is_pinned: false,
            existing_is_entry_point: false,
            confirmed: false,
            status_message: None,
            reusable: false,
            help_topic: "Label".to_string(),
            help_anchor: "AddEditDialog".to_string(),
        }
    }

    /// Creates a dialog in Edit mode for the given symbol.
    ///
    /// Mirrors `initDialogForEdit(Program p, Symbol s)` in Java.
    /// The dialog title depends on the symbol type (label, function, variable).
    pub fn new_edit(
        address: Address,
        name: impl Into<String>,
        symbol_type: SymbolType,
        source: SourceType,
        is_external: bool,
    ) -> Self {
        let name = name.into();
        let mode = match symbol_type {
            SymbolType::Function => {
                if is_external {
                    LabelDialogMode::EditExternal
                } else {
                    LabelDialogMode::RenameFunction
                }
            }
            SymbolType::Parameter | SymbolType::LocalVar => LabelDialogMode::RenameVariable,
            _ => LabelDialogMode::Edit,
        };

        let title = match mode {
            LabelDialogMode::RenameFunction => {
                if is_external {
                    "Rename External Function".to_string()
                } else {
                    format!("Rename Function at 0x{:X}", address.offset)
                }
            }
            LabelDialogMode::RenameVariable => format!("Rename Variable: {}", name),
            LabelDialogMode::EditExternal => format!("Edit External Label at 0x{:X}", address.offset),
            _ => format!("Edit Label at 0x{:X}", address.offset),
        };

        let namespaces = vec![NamespaceOption::global()];

        // For variables, namespace and entry-point are not applicable.
        let is_variable = mode == LabelDialogMode::RenameVariable;

        Self {
            title,
            mode,
            address,
            label_name: name.clone(),
            namespaces,
            selected_namespace_index: Some(0),
            namespace_enabled: !is_variable,
            primary_checked: true, // editing existing symbol -> primary
            primary_enabled: false,
            entry_point_checked: false,
            entry_point_enabled: !is_variable,
            pinned_checked: false,
            pinned_enabled: !is_variable,
            recent_labels: VecDeque::new(),
            recent_namespaces: VecDeque::new(),
            existing_name: Some(name),
            existing_symbol_type: Some(symbol_type),
            existing_source: Some(source),
            existing_is_external: is_external,
            existing_is_primary: true, // will be set by caller if needed
            existing_is_pinned: false,
            existing_is_entry_point: false,
            confirmed: false,
            status_message: None,
            reusable: false,
            help_topic: "Label".to_string(),
            help_anchor: "AddEditDialog".to_string(),
        }
    }

    /// Sets the reusable flag.
    ///
    /// When reusable, closing the dialog does not dispose it.
    /// Mirrors `setReusable(boolean isReusable)` in Java.
    pub fn set_reusable(&mut self, reusable: bool) {
        self.reusable = reusable;
    }

    /// Returns whether the dialog is reusable.
    pub fn is_reusable(&self) -> bool {
        self.reusable
    }

    // -- Title -------------------------------------------------------------

    /// Returns the dialog title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the dialog mode.
    pub fn mode(&self) -> LabelDialogMode {
        self.mode
    }

    /// Returns the address.
    pub fn address(&self) -> Address {
        self.address
    }

    // -- Label name --------------------------------------------------------

    /// Returns the current label name text.
    pub fn label_name(&self) -> &str {
        &self.label_name
    }

    /// Sets the label name text.
    pub fn set_label_name(&mut self, name: impl Into<String>) {
        self.label_name = name.into();
    }

    // -- Namespace ---------------------------------------------------------

    /// Returns the available namespaces.
    pub fn namespaces(&self) -> &[NamespaceOption] {
        &self.namespaces
    }

    /// Sets the available namespaces.
    pub fn set_namespaces(&mut self, namespaces: Vec<NamespaceOption>) {
        self.namespaces = namespaces;
    }

    /// Adds a namespace option.
    pub fn add_namespace(&mut self, ns: NamespaceOption) {
        if !self.namespaces.iter().any(|n| n.id == ns.id) {
            self.namespaces.push(ns);
        }
    }

    /// Selects a namespace by index.
    pub fn select_namespace(&mut self, index: usize) {
        if index < self.namespaces.len() {
            self.selected_namespace_index = Some(index);
        }
    }

    /// Selects a namespace by ID.
    pub fn select_namespace_by_id(&mut self, id: u64) {
        self.selected_namespace_index = self
            .namespaces
            .iter()
            .position(|ns| ns.id == id);
    }

    /// Returns the selected namespace, if any.
    pub fn selected_namespace(&self) -> Option<&NamespaceOption> {
        self.selected_namespace_index
            .and_then(|i| self.namespaces.get(i))
    }

    /// Returns the selected namespace ID.
    pub fn selected_namespace_id(&self) -> u64 {
        self.selected_namespace()
            .map_or(0, |ns| ns.id)
    }

    /// Returns whether the namespace chooser is enabled.
    pub fn is_namespace_enabled(&self) -> bool {
        self.namespace_enabled
    }

    /// Sets whether the namespace chooser is enabled.
    pub fn set_namespace_enabled(&mut self, enabled: bool) {
        self.namespace_enabled = enabled;
    }

    // -- Checkboxes --------------------------------------------------------

    /// Returns whether the "Primary" checkbox is checked.
    pub fn is_primary_checked(&self) -> bool {
        self.primary_checked
    }

    /// Sets the "Primary" checkbox state.
    pub fn set_primary_checked(&mut self, checked: bool) {
        self.primary_checked = checked;
    }

    /// Returns whether the "Primary" checkbox is enabled.
    pub fn is_primary_enabled(&self) -> bool {
        self.primary_enabled
    }

    /// Sets whether the "Primary" checkbox is enabled.
    pub fn set_primary_enabled(&mut self, enabled: bool) {
        self.primary_enabled = enabled;
    }

    /// Returns whether the "Entry Point" checkbox is checked.
    pub fn is_entry_point_checked(&self) -> bool {
        self.entry_point_checked
    }

    /// Sets the "Entry Point" checkbox state.
    pub fn set_entry_point_checked(&mut self, checked: bool) {
        self.entry_point_checked = checked;
    }

    /// Returns whether the "Entry Point" checkbox is enabled.
    pub fn is_entry_point_enabled(&self) -> bool {
        self.entry_point_enabled
    }

    /// Sets whether the "Entry Point" checkbox is enabled.
    pub fn set_entry_point_enabled(&mut self, enabled: bool) {
        self.entry_point_enabled = enabled;
    }

    /// Returns whether the "Pinned" checkbox is checked.
    pub fn is_pinned_checked(&self) -> bool {
        self.pinned_checked
    }

    /// Sets the "Pinned" checkbox state.
    pub fn set_pinned_checked(&mut self, checked: bool) {
        self.pinned_checked = checked;
    }

    /// Returns whether the "Pinned" checkbox is enabled.
    pub fn is_pinned_enabled(&self) -> bool {
        self.pinned_enabled
    }

    /// Sets whether the "Pinned" checkbox is enabled.
    pub fn set_pinned_enabled(&mut self, enabled: bool) {
        self.pinned_enabled = enabled;
    }

    // -- Recent labels -----------------------------------------------------

    /// Returns the recent label names.
    pub fn recent_labels(&self) -> &VecDeque<String> {
        &self.recent_labels
    }

    /// Adds a label name to the recent list.
    ///
    /// If the name already exists, it is moved to the front.
    /// The list is capped at [`MAX_RECENT_LABELS`].
    pub fn add_recent_label(&mut self, label: impl Into<String>) {
        let label = label.into();
        self.recent_labels.retain(|l| l != &label);
        self.recent_labels.push_front(label);
        if self.recent_labels.len() > MAX_RECENT_LABELS {
            self.recent_labels.pop_back();
        }
    }

    /// Returns the recent namespace IDs.
    pub fn recent_namespaces(&self) -> &VecDeque<u64> {
        &self.recent_namespaces
    }

    /// Adds a namespace ID to the recent list.
    pub fn add_recent_namespace(&mut self, ns_id: u64) {
        self.recent_namespaces.retain(|&id| id != ns_id);
        self.recent_namespaces.push_front(ns_id);
        if self.recent_namespaces.len() > MAX_RECENT_NAMESPACES {
            self.recent_namespaces.pop_back();
        }
    }

    // -- Existing symbol properties ----------------------------------------

    /// Returns the existing symbol name (when editing).
    pub fn existing_name(&self) -> Option<&str> {
        self.existing_name.as_deref()
    }

    /// Returns the existing symbol type (when editing).
    pub fn existing_symbol_type(&self) -> Option<SymbolType> {
        self.existing_symbol_type
    }

    /// Returns whether the existing symbol is external.
    pub fn is_existing_external(&self) -> bool {
        self.existing_is_external
    }

    /// Sets the existing symbol's primary state.
    pub fn set_existing_primary(&mut self, primary: bool) {
        self.existing_is_primary = primary;
    }

    /// Sets the existing symbol's pinned state.
    pub fn set_existing_pinned(&mut self, pinned: bool) {
        self.existing_is_pinned = pinned;
    }

    /// Sets the existing symbol's entry point state.
    pub fn set_existing_entry_point(&mut self, entry_point: bool) {
        self.existing_is_entry_point = entry_point;
    }

    // -- Validation --------------------------------------------------------

    /// Validates the current dialog state.
    ///
    /// Mirrors the validation logic in `okCallback()` in Java.
    /// Returns `Ok(())` if valid, `Err(message)` if invalid.
    pub fn validate(&self) -> Result<(), String> {
        let name = self.label_name.trim();

        if name.is_empty() {
            return Err("Name cannot be blank".to_string());
        }

        // Check for namespace path notation (e.g., "Namespace::label")
        // In a full implementation, this would parse the SymbolPath.
        if name.ends_with("::") {
            return Err("Name cannot be blank while changing namespace".to_string());
        }

        // Validate the label name portion (after the last "::" if present).
        let label_part = name.rsplit("::").next().unwrap_or(name);
        validate_label_name(label_part)?;

        Ok(())
    }

    // -- OK callback -------------------------------------------------------

    /// Performs the OK action.
    ///
    /// Mirrors `okCallback()` in Java. Validates the input and
    /// produces a `LabelDialogResult` that describes the action to take.
    pub fn ok(&mut self) -> Result<LabelDialogResult, String> {
        self.validate()?;

        let label_name = self.label_name.trim().to_string();

        // Record in recent labels.
        self.add_recent_label(&label_name);

        // Record namespace in recent.
        if let Some(ns_id) = self.selected_namespace().map(|ns| ns.id) {
            self.add_recent_namespace(ns_id);
        }

        self.confirmed = true;
        self.status_message = None;

        let result = match self.mode {
            LabelDialogMode::Add => LabelDialogResult::Add {
                address: self.address,
                name: label_name,
                namespace_id: self.selected_namespace_id(),
                source: SourceType::UserDefined,
                primary: self.primary_checked,
                entry_point: self.entry_point_checked,
                pinned: self.pinned_checked,
            },
            LabelDialogMode::Edit
            | LabelDialogMode::RenameFunction
            | LabelDialogMode::RenameVariable
            | LabelDialogMode::EditExternal => LabelDialogResult::Edit {
                address: self.address,
                old_name: self.existing_name.clone().unwrap_or_default(),
                new_name: label_name,
                namespace_id: self.selected_namespace_id(),
                source: SourceType::UserDefined,
                primary: self.primary_checked && self.primary_enabled,
                entry_point: self.entry_point_checked && self.entry_point_enabled,
                pinned: self.pinned_checked && self.pinned_enabled,
            },
        };

        Ok(result)
    }

    /// Simulates pressing Cancel.
    pub fn cancel(&mut self) {
        self.confirmed = false;
        self.status_message = None;
    }

    /// Returns whether the dialog was confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    // -- Status ------------------------------------------------------------

    /// Returns the current status message, if any.
    pub fn status_message(&self) -> Option<&str> {
        self.status_message.as_deref()
    }

    /// Sets the status message.
    pub fn set_status_message(&mut self, msg: impl Into<String>) {
        self.status_message = Some(msg.into());
    }

    /// Clears the status message.
    pub fn clear_status_message(&mut self) {
        self.status_message = None;
    }

    // -- Help --------------------------------------------------------------

    /// Returns the help topic.
    pub fn help_topic(&self) -> &str {
        &self.help_topic
    }

    /// Returns the help anchor.
    pub fn help_anchor(&self) -> &str {
        &self.help_anchor
    }

    /// Sets the help location.
    pub fn set_help_location(&mut self, topic: impl Into<String>, anchor: impl Into<String>) {
        self.help_topic = topic.into();
        self.help_anchor = anchor.into();
    }

    // -- Dispose -----------------------------------------------------------

    /// Disposes of the dialog resources.
    ///
    /// Mirrors `dispose()` in Java which clears the recent labels list
    /// and resets the dialog state.
    pub fn dispose(&mut self) {
        self.label_name.clear();
        self.status_message = None;
        self.confirmed = false;
    }
}

// ---------------------------------------------------------------------------
// LabelDialogResult
// ---------------------------------------------------------------------------

/// The result of confirming the add/edit label dialog.
///
/// This describes the command(s) that should be executed in response
/// to the user's dialog input. In Ghidra, these correspond to
/// `AddLabelCmd`, `RenameLabelCmd`, `SetLabelPrimaryCmd`,
/// `ExternalEntryCmd`, and `PinSymbolCmd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelDialogResult {
    /// Add a new label.
    Add {
        /// The address to add the label at.
        address: Address,
        /// The label name.
        name: String,
        /// The namespace ID (0 for global).
        namespace_id: u64,
        /// The source type.
        source: SourceType,
        /// Whether to set as primary.
        primary: bool,
        /// Whether to mark as external entry point.
        entry_point: bool,
        /// Whether to pin the label.
        pinned: bool,
    },
    /// Edit an existing label.
    Edit {
        /// The address of the label.
        address: Address,
        /// The old label name.
        old_name: String,
        /// The new label name.
        new_name: String,
        /// The namespace ID (0 for global).
        namespace_id: u64,
        /// The source type.
        source: SourceType,
        /// Whether to set as primary.
        primary: bool,
        /// Whether to mark as external entry point.
        entry_point: bool,
        /// Whether to pin the label.
        pinned: bool,
    },
}

impl LabelDialogResult {
    /// Returns the address.
    pub fn address(&self) -> Address {
        match self {
            LabelDialogResult::Add { address, .. } => *address,
            LabelDialogResult::Edit { address, .. } => *address,
        }
    }

    /// Returns the label name (new name for edits).
    pub fn name(&self) -> &str {
        match self {
            LabelDialogResult::Add { name, .. } => name,
            LabelDialogResult::Edit { new_name, .. } => new_name,
        }
    }

    /// Returns whether this is an add operation.
    pub fn is_add(&self) -> bool {
        matches!(self, LabelDialogResult::Add { .. })
    }

    /// Returns whether this is an edit operation.
    pub fn is_edit(&self) -> bool {
        matches!(self, LabelDialogResult::Edit { .. })
    }

    /// Returns whether the primary flag is set.
    pub fn primary(&self) -> bool {
        match self {
            LabelDialogResult::Add { primary, .. } => *primary,
            LabelDialogResult::Edit { primary, .. } => *primary,
        }
    }

    /// Returns whether the entry point flag is set.
    pub fn entry_point(&self) -> bool {
        match self {
            LabelDialogResult::Add { entry_point, .. } => *entry_point,
            LabelDialogResult::Edit { entry_point, .. } => *entry_point,
        }
    }

    /// Returns whether the pinned flag is set.
    pub fn pinned(&self) -> bool {
        match self {
            LabelDialogResult::Add { pinned, .. } => *pinned,
            LabelDialogResult::Edit { pinned, .. } => *pinned,
        }
    }
}

// ---------------------------------------------------------------------------
// NamespaceCache
// ---------------------------------------------------------------------------

/// Cache of recently used namespaces.
///
/// Ported from Ghidra's `NamespaceCache` utility. Maintains a
/// per-program list of recently selected namespaces to populate
/// the namespace combo box.
#[derive(Debug, Clone, Default)]
pub struct NamespaceCache {
    /// Recent namespace IDs in order of most recent use.
    entries: VecDeque<u64>,
}

impl NamespaceCache {
    /// Creates a new empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a namespace ID to the cache.
    pub fn add(&mut self, ns_id: u64) {
        self.entries.retain(|&id| id != ns_id);
        self.entries.push_front(ns_id);
        if self.entries.len() > MAX_RECENT_NAMESPACES {
            self.entries.pop_back();
        }
    }

    /// Returns the cached namespace IDs.
    pub fn entries(&self) -> &VecDeque<u64> {
        &self.entries
    }

    /// Clears the cache.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Returns the number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(offset: u64) -> Address {
        Address::new(offset)
    }

    // -- Add mode ----------------------------------------------------------

    #[test]
    fn test_new_add_title() {
        let dialog = AddEditDialog::new_add(addr(0x1000));
        assert_eq!(dialog.title(), "Add Label at 0x1000");
    }

    #[test]
    fn test_new_add_mode() {
        let dialog = AddEditDialog::new_add(addr(0x1000));
        assert_eq!(dialog.mode(), LabelDialogMode::Add);
        assert!(!dialog.mode().is_edit());
    }

    #[test]
    fn test_new_add_defaults() {
        let dialog = AddEditDialog::new_add(addr(0x1000));
        assert_eq!(dialog.label_name(), "");
        assert!(dialog.is_namespace_enabled());
        assert!(!dialog.is_primary_checked());
        assert!(dialog.is_primary_enabled());
        assert!(!dialog.is_entry_point_checked());
        assert!(dialog.is_entry_point_enabled());
        assert!(!dialog.is_pinned_checked());
        assert!(dialog.is_pinned_enabled());
        assert!(!dialog.is_confirmed());
    }

    #[test]
    fn test_new_add_default_namespace_is_global() {
        let dialog = AddEditDialog::new_add(addr(0x1000));
        assert_eq!(dialog.namespaces().len(), 1);
        assert_eq!(dialog.namespaces()[0].id, 0);
        assert!(dialog.namespaces()[0].is_global);
        let selected = dialog.selected_namespace().unwrap();
        assert!(selected.is_global);
    }

    // -- Edit mode ---------------------------------------------------------

    #[test]
    fn test_new_edit_label_title() {
        let dialog = AddEditDialog::new_edit(
            addr(0x1000),
            "my_label",
            SymbolType::Label,
            SourceType::UserDefined,
            false,
        );
        assert_eq!(dialog.title(), "Edit Label at 0x1000");
        assert_eq!(dialog.mode(), LabelDialogMode::Edit);
        assert!(dialog.mode().is_edit());
    }

    #[test]
    fn test_new_edit_function_title() {
        let dialog = AddEditDialog::new_edit(
            addr(0x1000),
            "main",
            SymbolType::Function,
            SourceType::UserDefined,
            false,
        );
        assert_eq!(dialog.title(), "Rename Function at 0x1000");
        assert_eq!(dialog.mode(), LabelDialogMode::RenameFunction);
    }

    #[test]
    fn test_new_edit_external_function_title() {
        let dialog = AddEditDialog::new_edit(
            addr(0x1000),
            "printf",
            SymbolType::Function,
            SourceType::Imported,
            true,
        );
        assert_eq!(dialog.title(), "Rename External Function");
        assert_eq!(dialog.mode(), LabelDialogMode::EditExternal);
    }

    #[test]
    fn test_new_edit_variable_title() {
        let dialog = AddEditDialog::new_edit(
            addr(0x1000),
            "param_1",
            SymbolType::Parameter,
            SourceType::UserDefined,
            false,
        );
        assert_eq!(dialog.title(), "Rename Variable: param_1");
        assert_eq!(dialog.mode(), LabelDialogMode::RenameVariable);
    }

    #[test]
    fn test_new_edit_variable_disables_namespace() {
        let dialog = AddEditDialog::new_edit(
            addr(0x1000),
            "param_1",
            SymbolType::Parameter,
            SourceType::UserDefined,
            false,
        );
        assert!(!dialog.is_namespace_enabled());
        assert!(!dialog.is_entry_point_enabled());
        assert!(!dialog.is_pinned_enabled());
    }

    #[test]
    fn test_new_edit_preserves_name() {
        let dialog = AddEditDialog::new_edit(
            addr(0x1000),
            "existing_label",
            SymbolType::Label,
            SourceType::UserDefined,
            false,
        );
        assert_eq!(dialog.label_name(), "existing_label");
        assert_eq!(dialog.existing_name(), Some("existing_label"));
    }

    // -- Label name --------------------------------------------------------

    #[test]
    fn test_set_label_name() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_label_name("my_label");
        assert_eq!(dialog.label_name(), "my_label");
    }

    // -- Namespace ---------------------------------------------------------

    #[test]
    fn test_add_namespace() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.add_namespace(NamespaceOption::new(1, "MyNamespace"));
        assert_eq!(dialog.namespaces().len(), 2);
    }

    #[test]
    fn test_add_duplicate_namespace_ignored() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.add_namespace(NamespaceOption::new(1, "MyNamespace"));
        dialog.add_namespace(NamespaceOption::new(1, "MyNamespace"));
        assert_eq!(dialog.namespaces().len(), 2); // global + one custom
    }

    #[test]
    fn test_select_namespace_by_index() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.add_namespace(NamespaceOption::new(1, "MyNamespace"));
        dialog.select_namespace(1);
        assert_eq!(dialog.selected_namespace().unwrap().id, 1);
        assert_eq!(dialog.selected_namespace_id(), 1);
    }

    #[test]
    fn test_select_namespace_by_id() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.add_namespace(NamespaceOption::new(42, "Test"));
        dialog.select_namespace_by_id(42);
        assert_eq!(dialog.selected_namespace().unwrap().id, 42);
    }

    #[test]
    fn test_select_namespace_out_of_bounds() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.select_namespace(99);
        // Should not change the selection.
        assert_eq!(dialog.selected_namespace().unwrap().id, 0);
    }

    #[test]
    fn test_set_namespaces() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_namespaces(vec![
            NamespaceOption::global(),
            NamespaceOption::new(1, "A"),
            NamespaceOption::new(2, "B"),
        ]);
        assert_eq!(dialog.namespaces().len(), 3);
    }

    // -- Checkboxes --------------------------------------------------------

    #[test]
    fn test_checkbox_primary() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_primary_checked(true);
        assert!(dialog.is_primary_checked());
        dialog.set_primary_enabled(false);
        assert!(!dialog.is_primary_enabled());
    }

    #[test]
    fn test_checkbox_entry_point() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_entry_point_checked(true);
        assert!(dialog.is_entry_point_checked());
    }

    #[test]
    fn test_checkbox_pinned() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_pinned_checked(true);
        assert!(dialog.is_pinned_checked());
    }

    // -- Recent labels -----------------------------------------------------

    #[test]
    fn test_recent_labels() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.add_recent_label("main");
        dialog.add_recent_label("helper");
        assert_eq!(dialog.recent_labels().len(), 2);
        assert_eq!(dialog.recent_labels()[0], "helper");
        assert_eq!(dialog.recent_labels()[1], "main");
    }

    #[test]
    fn test_recent_labels_dedup() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.add_recent_label("main");
        dialog.add_recent_label("helper");
        dialog.add_recent_label("main"); // moved to front
        assert_eq!(dialog.recent_labels().len(), 2);
        assert_eq!(dialog.recent_labels()[0], "main");
    }

    #[test]
    fn test_recent_labels_max() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        for i in 0..15 {
            dialog.add_recent_label(format!("label_{}", i));
        }
        assert_eq!(dialog.recent_labels().len(), MAX_RECENT_LABELS);
        assert_eq!(dialog.recent_labels()[0], "label_14");
    }

    #[test]
    fn test_recent_namespaces() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.add_recent_namespace(1);
        dialog.add_recent_namespace(2);
        assert_eq!(dialog.recent_namespaces().len(), 2);
        assert_eq!(dialog.recent_namespaces()[0], 2);
    }

    // -- Validation --------------------------------------------------------

    #[test]
    fn test_validate_empty_name() {
        let dialog = AddEditDialog::new_add(addr(0x1000));
        assert!(dialog.validate().is_err());
        assert!(dialog.validate().unwrap_err().contains("blank"));
    }

    #[test]
    fn test_validate_whitespace_name() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_label_name("   ");
        assert!(dialog.validate().is_err());
    }

    #[test]
    fn test_validate_valid_name() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_label_name("main");
        assert!(dialog.validate().is_ok());
    }

    #[test]
    fn test_validate_invalid_chars() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_label_name("my-label");
        assert!(dialog.validate().is_err());
    }

    #[test]
    fn test_validate_reserved_keyword() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_label_name("if");
        assert!(dialog.validate().is_err());
    }

    #[test]
    fn test_validate_namespace_trailing_colons() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_label_name("Namespace::");
        assert!(dialog.validate().is_err());
        assert!(dialog.validate().unwrap_err().contains("blank"));
    }

    #[test]
    fn test_validate_namespace_path() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_label_name("MyNamespace::my_label");
        assert!(dialog.validate().is_ok());
    }

    // -- OK callback -------------------------------------------------------

    #[test]
    fn test_ok_add() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_label_name("main");

        let result = dialog.ok().unwrap();
        assert!(result.is_add());
        assert_eq!(result.address(), addr(0x1000));
        assert_eq!(result.name(), "main");
        assert!(dialog.is_confirmed());
    }

    #[test]
    fn test_ok_add_with_options() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_label_name("entry");
        dialog.set_primary_checked(true);
        dialog.set_entry_point_checked(true);
        dialog.set_pinned_checked(true);

        let result = dialog.ok().unwrap();
        assert!(result.primary());
        assert!(result.entry_point());
        assert!(result.pinned());
    }

    #[test]
    fn test_ok_edit() {
        let mut dialog = AddEditDialog::new_edit(
            addr(0x1000),
            "old_name",
            SymbolType::Label,
            SourceType::UserDefined,
            false,
        );
        dialog.set_label_name("new_name");

        let result = dialog.ok().unwrap();
        assert!(result.is_edit());
        assert_eq!(result.name(), "new_name");
        if let LabelDialogResult::Edit { old_name, .. } = &result {
            assert_eq!(old_name, "old_name");
        }
    }

    #[test]
    fn test_ok_failure_stays_open() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        // Empty name should fail validation.
        let result = dialog.ok();
        assert!(result.is_err());
        assert!(!dialog.is_confirmed());
    }

    #[test]
    fn test_ok_updates_recent_labels() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_label_name("my_func");
        dialog.ok().unwrap();
        assert_eq!(dialog.recent_labels().len(), 1);
        assert_eq!(dialog.recent_labels()[0], "my_func");
    }

    #[test]
    fn test_ok_updates_recent_namespaces() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.add_namespace(NamespaceOption::new(5, "TestNs"));
        dialog.select_namespace(1);
        dialog.set_label_name("test");
        dialog.ok().unwrap();
        assert!(dialog.recent_namespaces().contains(&5));
    }

    // -- Cancel ------------------------------------------------------------

    #[test]
    fn test_cancel() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.cancel();
        assert!(!dialog.is_confirmed());
    }

    // -- Status ------------------------------------------------------------

    #[test]
    fn test_status_message() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        assert!(dialog.status_message().is_none());

        dialog.set_status_message("Test error");
        assert_eq!(dialog.status_message(), Some("Test error"));

        dialog.clear_status_message();
        assert!(dialog.status_message().is_none());
    }

    // -- Help --------------------------------------------------------------

    #[test]
    fn test_help_location_defaults() {
        let dialog = AddEditDialog::new_add(addr(0x1000));
        assert_eq!(dialog.help_topic(), "Label");
        assert_eq!(dialog.help_anchor(), "AddEditDialog");
    }

    #[test]
    fn test_set_help_location() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_help_location("Custom", "Anchor");
        assert_eq!(dialog.help_topic(), "Custom");
        assert_eq!(dialog.help_anchor(), "Anchor");
    }

    // -- Reusable ----------------------------------------------------------

    #[test]
    fn test_reusable() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        assert!(!dialog.is_reusable());
        dialog.set_reusable(true);
        assert!(dialog.is_reusable());
    }

    // -- Dispose -----------------------------------------------------------

    #[test]
    fn test_dispose() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_label_name("test");
        dialog.dispose();
        assert_eq!(dialog.label_name(), "");
        assert!(!dialog.is_confirmed());
    }

    // -- NamespaceOption ---------------------------------------------------

    #[test]
    fn test_namespace_option_global() {
        let ns = NamespaceOption::global();
        assert!(ns.is_global);
        assert!(!ns.is_function);
        assert_eq!(ns.id, 0);
    }

    #[test]
    fn test_namespace_option_new() {
        let ns = NamespaceOption::new(42, "MyNamespace");
        assert_eq!(ns.id, 42);
        assert_eq!(ns.display_name, "MyNamespace");
        assert!(!ns.is_global);
        assert!(!ns.is_function);
    }

    #[test]
    fn test_namespace_option_function() {
        let ns = NamespaceOption::function(10, "my_func");
        assert!(ns.is_function);
        assert!(!ns.is_global);
    }

    // -- LabelDialogResult -------------------------------------------------

    #[test]
    fn test_result_add_properties() {
        let result = LabelDialogResult::Add {
            address: addr(0x1000),
            name: "test".to_string(),
            namespace_id: 0,
            source: SourceType::UserDefined,
            primary: true,
            entry_point: false,
            pinned: true,
        };
        assert!(result.is_add());
        assert!(!result.is_edit());
        assert_eq!(result.address(), addr(0x1000));
        assert_eq!(result.name(), "test");
        assert!(result.primary());
        assert!(!result.entry_point());
        assert!(result.pinned());
    }

    #[test]
    fn test_result_edit_properties() {
        let result = LabelDialogResult::Edit {
            address: addr(0x2000),
            old_name: "old".to_string(),
            new_name: "new".to_string(),
            namespace_id: 5,
            source: SourceType::UserDefined,
            primary: false,
            entry_point: true,
            pinned: false,
        };
        assert!(result.is_edit());
        assert!(!result.is_add());
        assert_eq!(result.name(), "new");
    }

    // -- NamespaceCache ----------------------------------------------------

    #[test]
    fn test_namespace_cache() {
        let mut cache = NamespaceCache::new();
        assert!(cache.is_empty());

        cache.add(1);
        cache.add(2);
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.entries()[0], 2); // most recent first
    }

    #[test]
    fn test_namespace_cache_dedup() {
        let mut cache = NamespaceCache::new();
        cache.add(1);
        cache.add(2);
        cache.add(1); // moved to front
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.entries()[0], 1);
    }

    #[test]
    fn test_namespace_cache_max() {
        let mut cache = NamespaceCache::new();
        for i in 0..15 {
            cache.add(i);
        }
        assert_eq!(cache.len(), MAX_RECENT_NAMESPACES);
    }

    #[test]
    fn test_namespace_cache_clear() {
        let mut cache = NamespaceCache::new();
        cache.add(1);
        cache.clear();
        assert!(cache.is_empty());
    }

    // -- LabelDialogMode ---------------------------------------------------

    #[test]
    fn test_mode_is_edit() {
        assert!(!LabelDialogMode::Add.is_edit());
        assert!(LabelDialogMode::Edit.is_edit());
        assert!(LabelDialogMode::RenameFunction.is_edit());
        assert!(LabelDialogMode::RenameVariable.is_edit());
        assert!(LabelDialogMode::EditExternal.is_edit());
    }

    // -- Full workflow -----------------------------------------------------

    #[test]
    fn test_add_label_workflow() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.add_namespace(NamespaceOption::new(1, "MyNamespace"));
        dialog.set_label_name("main");
        dialog.set_primary_checked(true);
        dialog.set_entry_point_checked(true);
        dialog.select_namespace(1);

        let result = dialog.ok().unwrap();
        assert!(result.is_add());
        assert_eq!(result.address(), addr(0x1000));
        assert_eq!(result.name(), "main");
        assert!(result.primary());
        assert!(result.entry_point());
        assert!(!result.pinned());
        assert_eq!(
            dialog.selected_namespace_id(),
            1
        );
    }

    #[test]
    fn test_edit_label_workflow() {
        let mut dialog = AddEditDialog::new_edit(
            addr(0x1000),
            "old_label",
            SymbolType::Label,
            SourceType::UserDefined,
            false,
        );
        dialog.set_label_name("new_label");
        dialog.set_pinned_checked(true);

        let result = dialog.ok().unwrap();
        assert!(result.is_edit());
        assert_eq!(result.name(), "new_label");
        assert!(result.pinned());

        if let LabelDialogResult::Edit { old_name, .. } = &result {
            assert_eq!(old_name, "old_label");
        }
    }

    #[test]
    fn test_cancel_then_ok() {
        let mut dialog = AddEditDialog::new_add(addr(0x1000));
        dialog.set_label_name("test");
        dialog.cancel();
        assert!(!dialog.is_confirmed());

        let result = dialog.ok().unwrap();
        assert!(dialog.is_confirmed());
        assert_eq!(result.name(), "test");
    }
}
