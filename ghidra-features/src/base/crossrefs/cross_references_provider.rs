//! Cross References Provider -- manages the cross-reference editor display.
//!
//! Ported from Ghidra's:
//! - `ghidra.app.plugin.core.references.EditReferencesProvider`
//! - `ghidra.app.plugin.core.references.ExternalReferencesProvider`
//!
//! Provides the component providers that display and edit cross-references
//! at a given code unit location, as well as the provider that manages
//! external program associations.
//!
//! # Key Types
//!
//! - [`CrossReferencesProvider`] -- Provider for viewing/editing xrefs at a location
//! - [`ExternalReferencesProvider`] -- Provider for external program references
//! - [`EditProviderState`] -- Location state tracked by the edit provider
//! - [`ExternalNamesRow`] -- A row in the external programs table

use ghidra_core::addr::Address;
use ghidra_core::symbol::{RefType, Reference, ReferenceManager, SourceType};

use super::{CrossReferenceManager, XRefEntry};

// ---------------------------------------------------------------------------
// EditProviderState -- location state tracked by an edit provider
// ---------------------------------------------------------------------------

/// The location state tracked by a cross-references edit provider.
///
/// Corresponds to the `currentCodeUnit`, `currentProgram`,
/// `currentLocation`, and `initLocation` fields of the Java
/// `EditReferencesProvider`.
#[derive(Debug, Clone, Default)]
pub struct EditProviderState {
    /// The address of the code unit whose references are being edited.
    pub address: Option<Address>,
    /// The initial location when the provider was opened.
    pub init_address: Option<Address>,
    /// The program name.
    pub program_name: Option<String>,
    /// Whether the location is locked (user has pinned it).
    pub location_locked: bool,
}

impl EditProviderState {
    /// Create a new empty provider state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all state.
    pub fn clear(&mut self) {
        self.address = None;
        self.init_address = None;
        self.program_name = None;
        self.location_locked = false;
    }
}

// ---------------------------------------------------------------------------
// CrossReferencesProvider -- edit references provider
// ---------------------------------------------------------------------------

/// Provider for viewing and editing cross-references at a given location.
///
/// Ported from `ghidra.app.plugin.core.references.EditReferencesProvider`.
///
/// Manages:
/// - The reference table model showing all xrefs to the current code unit
/// - Location tracking (current address, locked state)
/// - Actions for adding, editing, and deleting references
/// - The cross-reference manager that wraps the program's reference manager
#[derive(Debug)]
pub struct CrossReferencesProvider {
    /// Current location state.
    state: EditProviderState,
    /// Cross-reference manager wrapping the reference manager.
    xref_manager: CrossReferenceManager,
    /// Whether the provider is currently visible.
    visible: bool,
    /// Title prefix for the provider window.
    title: String,
    /// Whether to follow the cursor location.
    follow_location: bool,
    /// Whether to go to the reference target on selection.
    goto_reference_location: bool,
}

impl CrossReferencesProvider {
    /// Create a new cross-references provider.
    ///
    /// Ported from the `EditReferencesProvider` constructor.
    pub fn new() -> Self {
        Self {
            state: EditProviderState::new(),
            xref_manager: CrossReferenceManager::default(),
            visible: false,
            title: "References Editor".into(),
            follow_location: false,
            goto_reference_location: false,
        }
    }

    /// Show the provider for the given program and address.
    ///
    /// Ported from `EditReferencesProvider.show(Program, ProgramLocation)`.
    pub fn show(&mut self, program_name: &str, address: Address) {
        self.state.program_name = Some(program_name.to_string());
        self.state.address = Some(address);
        if self.state.init_address.is_none() {
            self.state.init_address = Some(address);
        }
        self.visible = true;
    }

    /// Update the provider for a new location.
    ///
    /// Ported from `EditReferencesProvider.updateForLocation(Program, ProgramLocation)`.
    /// Only updates if the provider is visible and the location is not locked.
    pub fn update_for_location(&mut self, address: Address) {
        if self.visible && !self.state.location_locked {
            self.state.address = Some(address);
        }
    }

    /// Hide the provider.
    pub fn hide(&mut self) {
        self.visible = false;
    }

    /// Dispose the provider, releasing all resources.
    ///
    /// Ported from `EditReferencesProvider.dispose()`.
    pub fn dispose(&mut self) {
        self.visible = false;
        self.state.clear();
        self.xref_manager = CrossReferenceManager::default();
    }

    // -------------------------------------------------------------------
    // State accessors
    // -------------------------------------------------------------------

    /// Whether the provider is currently visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set the visibility of the provider.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether the location is locked.
    pub fn is_location_locked(&self) -> bool {
        self.state.location_locked
    }

    /// Set whether the location is locked.
    pub fn set_location_locked(&mut self, locked: bool) {
        self.state.location_locked = locked;
    }

    /// Get the current address.
    pub fn current_address(&self) -> Option<Address> {
        self.state.address
    }

    /// Get the initial address when the provider was opened.
    pub fn init_location(&self) -> Option<Address> {
        self.state.init_address
    }

    /// Get the program name.
    pub fn program_name(&self) -> Option<&str> {
        self.state.program_name.as_deref()
    }

    /// Get a reference to the provider state.
    pub fn state(&self) -> &EditProviderState {
        &self.state
    }

    /// Get the title of the provider.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Whether to follow the cursor location.
    pub fn follow_location(&self) -> bool {
        self.follow_location
    }

    /// Set whether to follow the cursor location.
    pub fn set_follow_location(&mut self, follow: bool) {
        self.follow_location = follow;
    }

    /// Whether to go to the reference target on selection.
    pub fn goto_reference_location(&self) -> bool {
        self.goto_reference_location
    }

    /// Set whether to go to the reference target on selection.
    pub fn set_goto_reference_location(&mut self, goto: bool) {
        self.goto_reference_location = goto;
    }

    // -------------------------------------------------------------------
    // Cross-reference manager access
    // -------------------------------------------------------------------

    /// Get a reference to the cross-reference manager.
    pub fn xref_manager(&self) -> &CrossReferenceManager {
        &self.xref_manager
    }

    /// Get a mutable reference to the cross-reference manager.
    pub fn xref_manager_mut(&mut self) -> &mut CrossReferenceManager {
        &mut self.xref_manager
    }

    /// Get the references for the current address.
    ///
    /// Returns xrefs to the current location, or an empty vector if
    /// no address is set.
    pub fn get_current_references(&self) -> Vec<XRefEntry> {
        // This would be populated by the xref_manager in a full implementation.
        // For now, return empty -- the reference manager would be populated
        // from the program's reference manager when show() is called.
        Vec::new()
    }
}

impl Default for CrossReferencesProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ExternalNamesRow -- a row in the external programs table
// ---------------------------------------------------------------------------

/// A row in the external programs table.
///
/// Ported from `ExternalReferencesProvider.ExternalNamesRow`.
#[derive(Debug, Clone)]
pub struct ExternalNamesRow {
    /// The external program/library name.
    name: String,
    /// The associated Ghidra program path (if any).
    program_path: Option<String>,
}

impl ExternalNamesRow {
    /// Create a new external names row.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            program_path: None,
        }
    }

    /// Create a row with an associated program path.
    pub fn with_path(name: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            program_path: Some(path.into()),
        }
    }

    /// Get the external name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the associated program path, if any.
    pub fn program_path(&self) -> Option<&str> {
        self.program_path.as_deref()
    }

    /// Set the associated program path.
    pub fn set_program_path(&mut self, path: Option<String>) {
        self.program_path = path;
    }
}

// ---------------------------------------------------------------------------
// ExternalReferencesProvider -- external programs provider
// ---------------------------------------------------------------------------

/// Provider that displays a table of external programs.
///
/// Ported from `ghidra.app.plugin.core.references.ExternalReferencesProvider`.
///
/// Manages:
/// - The table of external library names and their associated programs
/// - Actions for adding, removing, and reordering external programs
/// - Setting and clearing external program associations
#[derive(Debug)]
pub struct ExternalReferencesProvider {
    /// The rows in the external programs table.
    rows: Vec<ExternalNamesRow>,
    /// The current program name (if any).
    program_name: Option<String>,
    /// Whether the provider is visible.
    visible: bool,
    /// Index of the row to highlight on next reload.
    highlight_row: Option<usize>,
}

impl ExternalReferencesProvider {
    /// Create a new external references provider.
    ///
    /// Ported from `ExternalReferencesProvider(ReferencesPlugin)`.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            program_name: None,
            visible: false,
            highlight_row: None,
        }
    }

    /// Set the current program.
    ///
    /// Ported from `ExternalReferencesProvider.setProgram(Program)`.
    pub fn set_program(&mut self, program_name: Option<String>) {
        self.highlight_row = None;
        self.program_name = program_name;
        self.reload();
    }

    /// Get the current program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Reload the table data.
    ///
    /// Ported from the domain object listener's `domainObjectChanged` callback.
    pub fn reload(&mut self) {
        // In a full implementation, this would query the program's
        // ExternalManager for external library names.
        // For now, the rows are managed explicitly.
        if let Some(idx) = self.highlight_row {
            // Reset highlight after reload.
            self.highlight_row = None;
            // The row at `idx` would be selected in the UI.
            let _ = idx;
        }
    }

    /// Add an external program name.
    ///
    /// Ported from `ExternalReferencesProvider.addExternalProgram()`.
    pub fn add_external_name(&mut self, name: &str) {
        if name.is_empty() {
            return;
        }
        // Check for duplicates.
        if self.rows.iter().any(|r| r.name() == name) {
            return;
        }
        self.rows.push(ExternalNamesRow::new(name));
    }

    /// Remove external program names by index.
    ///
    /// Ported from the "Delete External Program" action handler.
    pub fn remove_external_names(&mut self, indices: &[usize]) {
        // Sort indices in reverse so removal doesn't shift later indices.
        let mut sorted = indices.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        for &idx in sorted.iter().rev() {
            if idx < self.rows.len() {
                self.rows.remove(idx);
            }
        }
    }

    /// Clear the external association for the names at the given indices.
    ///
    /// Ported from `ExternalReferencesProvider.clearExternalAssociation()`.
    pub fn clear_external_association(&mut self, indices: &[usize]) {
        for &idx in indices {
            if let Some(row) = self.rows.get_mut(idx) {
                row.set_program_path(None);
            }
        }
    }

    /// Set the external program path for the name at the given index.
    ///
    /// Ported from `ExternalReferencesProvider.setExternalProgramAssociation()`.
    pub fn set_external_program_path(&mut self, index: usize, path: &str) {
        if let Some(row) = self.rows.get_mut(index) {
            row.set_program_path(Some(path.to_string()));
        }
    }

    /// Move a library up in ordinal position.
    ///
    /// Ported from `ExternalReferencesProvider.adjustLibraryOrdinal(true)`.
    pub fn move_up(&mut self, index: usize) -> bool {
        if index == 0 || index >= self.rows.len() {
            return false;
        }
        self.rows.swap(index, index - 1);
        true
    }

    /// Move a library down in ordinal position.
    ///
    /// Ported from `ExternalReferencesProvider.adjustLibraryOrdinal(false)`.
    pub fn move_down(&mut self, index: usize) -> bool {
        if index + 1 >= self.rows.len() {
            return false;
        }
        self.rows.swap(index, index + 1);
        true
    }

    // -------------------------------------------------------------------
    // State accessors
    // -------------------------------------------------------------------

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Set the visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Get the rows.
    pub fn rows(&self) -> &[ExternalNamesRow] {
        &self.rows
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a row by index.
    pub fn get_row(&self, index: usize) -> Option<&ExternalNamesRow> {
        self.rows.get(index)
    }

    /// Get the selected external names (by index).
    pub fn get_selected_external_names(&self, indices: &[usize]) -> Vec<String> {
        indices
            .iter()
            .filter_map(|&idx| self.rows.get(idx).map(|r| r.name().to_string()))
            .collect()
    }

    /// Whether a single row is selected.
    pub fn is_single_row_selected(&self, selected_count: usize) -> bool {
        selected_count == 1
    }

    /// Whether there are any selected rows.
    pub fn has_selected_rows(&self, selected_count: usize) -> bool {
        selected_count > 0
    }

    /// Dispose the provider.
    ///
    /// Ported from `ExternalReferencesProvider.dispose()`.
    pub fn dispose(&mut self) {
        self.rows.clear();
        self.program_name = None;
        self.visible = false;
        self.highlight_row = None;
    }
}

impl Default for ExternalReferencesProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ====================================================================
    // EditProviderState
    // ====================================================================

    #[test]
    fn test_edit_provider_state_new() {
        let state = EditProviderState::new();
        assert!(state.address.is_none());
        assert!(state.init_address.is_none());
        assert!(state.program_name.is_none());
        assert!(!state.location_locked);
    }

    #[test]
    fn test_edit_provider_state_clear() {
        let mut state = EditProviderState::new();
        state.address = Some(Address::new(0x1000));
        state.init_address = Some(Address::new(0x1000));
        state.program_name = Some("test.exe".into());
        state.location_locked = true;

        state.clear();
        assert!(state.address.is_none());
        assert!(state.init_address.is_none());
        assert!(state.program_name.is_none());
        assert!(!state.location_locked);
    }

    // ====================================================================
    // CrossReferencesProvider
    // ====================================================================

    #[test]
    fn test_provider_new() {
        let provider = CrossReferencesProvider::new();
        assert!(!provider.is_visible());
        assert!(!provider.is_location_locked());
        assert!(provider.current_address().is_none());
        assert!(provider.init_location().is_none());
        assert!(provider.program_name().is_none());
    }

    #[test]
    fn test_provider_show() {
        let mut provider = CrossReferencesProvider::new();
        provider.show("test.exe", Address::new(0x2000));
        assert!(provider.is_visible());
        assert_eq!(provider.current_address(), Some(Address::new(0x2000)));
        assert_eq!(provider.init_location(), Some(Address::new(0x2000)));
        assert_eq!(provider.program_name(), Some("test.exe"));
    }

    #[test]
    fn test_provider_update_for_location() {
        let mut provider = CrossReferencesProvider::new();
        provider.show("test.exe", Address::new(0x2000));
        provider.update_for_location(Address::new(0x3000));
        assert_eq!(provider.current_address(), Some(Address::new(0x3000)));
        // Init location should not change.
        assert_eq!(provider.init_location(), Some(Address::new(0x2000)));
    }

    #[test]
    fn test_provider_update_for_location_locked() {
        let mut provider = CrossReferencesProvider::new();
        provider.show("test.exe", Address::new(0x2000));
        provider.set_location_locked(true);
        provider.update_for_location(Address::new(0x3000));
        // Address should not change when locked.
        assert_eq!(provider.current_address(), Some(Address::new(0x2000)));
    }

    #[test]
    fn test_provider_hide() {
        let mut provider = CrossReferencesProvider::new();
        provider.show("test.exe", Address::new(0x2000));
        assert!(provider.is_visible());
        provider.hide();
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_provider_dispose() {
        let mut provider = CrossReferencesProvider::new();
        provider.show("test.exe", Address::new(0x2000));
        provider.set_visible(true);

        provider.dispose();
        assert!(!provider.is_visible());
        assert!(provider.current_address().is_none());
        assert!(provider.program_name().is_none());
    }

    #[test]
    fn test_provider_location_locked() {
        let mut provider = CrossReferencesProvider::new();
        assert!(!provider.is_location_locked());
        provider.set_location_locked(true);
        assert!(provider.is_location_locked());
    }

    #[test]
    fn test_provider_follow_location() {
        let mut provider = CrossReferencesProvider::new();
        assert!(!provider.follow_location());
        provider.set_follow_location(true);
        assert!(provider.follow_location());
    }

    #[test]
    fn test_provider_goto_reference_location() {
        let mut provider = CrossReferencesProvider::new();
        assert!(!provider.goto_reference_location());
        provider.set_goto_reference_location(true);
        assert!(provider.goto_reference_location());
    }

    #[test]
    fn test_provider_xref_manager() {
        let provider = CrossReferencesProvider::new();
        let _mgr = provider.xref_manager();
    }

    #[test]
    fn test_provider_title() {
        let provider = CrossReferencesProvider::new();
        assert_eq!(provider.title(), "References Editor");
    }

    // ====================================================================
    // ExternalNamesRow
    // ====================================================================

    #[test]
    fn test_external_names_row_new() {
        let row = ExternalNamesRow::new("kernel32.dll");
        assert_eq!(row.name(), "kernel32.dll");
        assert!(row.program_path().is_none());
    }

    #[test]
    fn test_external_names_row_with_path() {
        let row = ExternalNamesRow::with_path("kernel32.dll", "/path/to/kernel32.dll");
        assert_eq!(row.name(), "kernel32.dll");
        assert_eq!(row.program_path(), Some("/path/to/kernel32.dll"));
    }

    #[test]
    fn test_external_names_row_set_path() {
        let mut row = ExternalNamesRow::new("kernel32.dll");
        row.set_program_path(Some("/new/path".into()));
        assert_eq!(row.program_path(), Some("/new/path"));
        row.set_program_path(None);
        assert!(row.program_path().is_none());
    }

    // ====================================================================
    // ExternalReferencesProvider
    // ====================================================================

    #[test]
    fn test_external_provider_new() {
        let provider = ExternalReferencesProvider::new();
        assert!(!provider.is_visible());
        assert!(provider.program_name().is_none());
        assert_eq!(provider.row_count(), 0);
    }

    #[test]
    fn test_external_provider_set_program() {
        let mut provider = ExternalReferencesProvider::new();
        provider.set_program(Some("test.exe".into()));
        assert_eq!(provider.program_name(), Some("test.exe"));
        provider.set_program(None);
        assert!(provider.program_name().is_none());
    }

    #[test]
    fn test_external_provider_add_name() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_external_name("kernel32.dll");
        assert_eq!(provider.row_count(), 1);
        assert_eq!(provider.get_row(0).unwrap().name(), "kernel32.dll");
    }

    #[test]
    fn test_external_provider_add_empty_name() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_external_name("");
        assert_eq!(provider.row_count(), 0);
    }

    #[test]
    fn test_external_provider_add_duplicate() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_external_name("kernel32.dll");
        provider.add_external_name("kernel32.dll");
        assert_eq!(provider.row_count(), 1);
    }

    #[test]
    fn test_external_provider_remove_names() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_external_name("kernel32.dll");
        provider.add_external_name("ntdll.dll");
        provider.add_external_name("user32.dll");
        assert_eq!(provider.row_count(), 3);

        provider.remove_external_names(&[0, 2]);
        assert_eq!(provider.row_count(), 1);
        assert_eq!(provider.get_row(0).unwrap().name(), "ntdll.dll");
    }

    #[test]
    fn test_external_provider_clear_association() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_external_name("kernel32.dll");
        provider.set_external_program_path(0, "/path/to/kernel32.dll");
        assert_eq!(
            provider.get_row(0).unwrap().program_path(),
            Some("/path/to/kernel32.dll")
        );

        provider.clear_external_association(&[0]);
        assert!(provider.get_row(0).unwrap().program_path().is_none());
    }

    #[test]
    fn test_external_provider_move_up() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_external_name("kernel32.dll");
        provider.add_external_name("ntdll.dll");

        assert!(provider.move_up(1));
        assert_eq!(provider.get_row(0).unwrap().name(), "ntdll.dll");
        assert_eq!(provider.get_row(1).unwrap().name(), "kernel32.dll");
    }

    #[test]
    fn test_external_provider_move_up_first() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_external_name("kernel32.dll");
        assert!(!provider.move_up(0));
    }

    #[test]
    fn test_external_provider_move_down() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_external_name("kernel32.dll");
        provider.add_external_name("ntdll.dll");

        assert!(provider.move_down(0));
        assert_eq!(provider.get_row(0).unwrap().name(), "ntdll.dll");
        assert_eq!(provider.get_row(1).unwrap().name(), "kernel32.dll");
    }

    #[test]
    fn test_external_provider_move_down_last() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_external_name("kernel32.dll");
        provider.add_external_name("ntdll.dll");
        assert!(!provider.move_down(1));
    }

    #[test]
    fn test_external_provider_get_selected_names() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_external_name("kernel32.dll");
        provider.add_external_name("ntdll.dll");
        provider.add_external_name("user32.dll");

        let names = provider.get_selected_external_names(&[0, 2]);
        assert_eq!(names, vec!["kernel32.dll", "user32.dll"]);
    }

    #[test]
    fn test_external_provider_dispose() {
        let mut provider = ExternalReferencesProvider::new();
        provider.add_external_name("kernel32.dll");
        provider.set_program(Some("test.exe".into()));
        provider.set_visible(true);

        provider.dispose();
        assert_eq!(provider.row_count(), 0);
        assert!(provider.program_name().is_none());
        assert!(!provider.is_visible());
    }

    #[test]
    fn test_external_provider_is_single_row_selected() {
        let provider = ExternalReferencesProvider::new();
        assert!(provider.is_single_row_selected(1));
        assert!(!provider.is_single_row_selected(0));
        assert!(!provider.is_single_row_selected(2));
    }

    #[test]
    fn test_external_provider_has_selected_rows() {
        let provider = ExternalReferencesProvider::new();
        assert!(!provider.has_selected_rows(0));
        assert!(provider.has_selected_rows(1));
        assert!(provider.has_selected_rows(5));
    }
}
