//! Defined Strings Table Plugin -- displays all defined string data in a program.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.strings.DefinedStringsPlugin` Java class.
//!
//! This plugin provides the "Defined Strings" table view, which lists all
//! string data items that are already defined in the program listing.  It
//! listens for domain object changes (code added/removed, data type changes,
//! memory block changes) and can incrementally update the table without a
//! full reload.
//!
//! # Architecture
//!
//! ```text
//! DefinedStringTablePlugin
//!   ├── DefinedStringsProvider (table view)
//!   ├── DefinedStringsTableModel (data model with address index)
//!   ├── DefinedStringsContext (action context for selected rows)
//!   └── Refresh action + link navigation action
//! ```
//!
//! # Example
//!
//! ```
//! use ghidra_features::base::string::defined_string_table_plugin::DefinedStringTablePlugin;
//!
//! let mut plugin = DefinedStringTablePlugin::new("DefinedStrings");
//! plugin.init();
//! assert_eq!(plugin.name(), "DefinedStrings");
//! plugin.set_program(Some("test.exe".into()));
//! assert_eq!(plugin.program(), Some("test.exe"));
//! ```

use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// DefinedStringData -- a single defined string entry
// ---------------------------------------------------------------------------

/// A defined string data item from the program listing.
///
/// Represents one string that is already defined as a data item in the
/// program.  Ported from the row objects used by Ghidra's
/// `DefinedStringsTableModel`.
#[derive(Debug, Clone)]
pub struct DefinedStringData {
    /// Address of the string data.
    pub address: u64,
    /// The string value.
    pub value: String,
    /// Data type name (e.g., "string", "unicode").
    pub data_type_name: String,
    /// String representation (e.g., quoted form).
    pub representation: String,
    /// Character set name (e.g., "ASCII", "UTF-8").
    pub charset: String,
    /// Whether the string is pure ASCII.
    pub is_ascii: bool,
    /// Whether the string has encoding errors.
    pub has_encoding_error: bool,
    /// Unicode script name (e.g., "LATIN", "CYRILLIC").
    pub unicode_script: String,
    /// Translated value (empty if not translated).
    pub translated_value: String,
    /// String length in characters.
    pub length: usize,
}

impl DefinedStringData {
    /// Create a new defined string data entry.
    pub fn new(
        address: u64,
        value: impl Into<String>,
        data_type_name: impl Into<String>,
    ) -> Self {
        let val = value.into();
        let len = val.len();
        let is_ascii = val.is_ascii();
        Self {
            address,
            length: len,
            is_ascii,
            value: val,
            data_type_name: data_type_name.into(),
            representation: String::new(),
            charset: "ASCII".to_string(),
            has_encoding_error: false,
            unicode_script: "LATIN".to_string(),
            translated_value: String::new(),
        }
    }

    /// Set the string representation (quoted form).
    pub fn with_representation(mut self, rep: impl Into<String>) -> Self {
        self.representation = rep.into();
        self
    }

    /// Set the charset name.
    pub fn with_charset(mut self, charset: impl Into<String>) -> Self {
        self.charset = charset.into();
        self
    }

    /// Set the encoding error flag.
    pub fn with_encoding_error(mut self, has_error: bool) -> Self {
        self.has_encoding_error = has_error;
        self
    }

    /// Set the unicode script.
    pub fn with_unicode_script(mut self, script: impl Into<String>) -> Self {
        self.unicode_script = script.into();
        self
    }

    /// Set the translated value.
    pub fn with_translated_value(mut self, value: impl Into<String>) -> Self {
        self.translated_value = value.into();
        self
    }
}

impl fmt::Display for DefinedStringData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:08X} [{}]: \"{}\"",
            self.address, self.data_type_name, self.value
        )
    }
}

// ---------------------------------------------------------------------------
// DefinedStringsTableModel -- indexed table model
// ---------------------------------------------------------------------------

/// Table model for defined strings, with an address-based index for
/// efficient incremental updates.
///
/// Ported from Ghidra's `DefinedStringsTableModel` Java class.
#[derive(Debug)]
pub struct DefinedStringsTableModel {
    /// All defined string rows, keyed by address for fast lookup.
    rows: Vec<DefinedStringData>,
    /// Address-to-row-index map for incremental updates.
    address_index: HashMap<u64, usize>,
    /// Filtered view indices.
    filtered: Vec<usize>,
    /// Whether the model needs a filter rebuild.
    dirty: bool,
    /// Column to sort by (0 = address, 1 = value, etc.).
    sort_column: usize,
    /// Sort ascending.
    sort_ascending: bool,
}

impl DefinedStringsTableModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self {
            rows: Vec::new(),
            address_index: HashMap::new(),
            filtered: Vec::new(),
            dirty: true,
            sort_column: 0,
            sort_ascending: true,
        }
    }

    /// Reload the model with a new set of defined strings.
    pub fn reload(&mut self, strings: Vec<DefinedStringData>) {
        self.rows = strings;
        self.address_index.clear();
        for (i, row) in self.rows.iter().enumerate() {
            self.address_index.insert(row.address, i);
        }
        self.dirty = true;
    }

    /// Add a single defined string.
    pub fn add(&mut self, data: DefinedStringData) {
        let addr = data.address;
        let idx = self.rows.len();
        self.rows.push(data);
        self.address_index.insert(addr, idx);
        self.dirty = true;
    }

    /// Remove the string at the given address.
    pub fn remove_at(&mut self, address: u64) -> Option<DefinedStringData> {
        if let Some(&idx) = self.address_index.get(&address) {
            let removed = self.rows.remove(idx);
            // Rebuild the address index since indices shifted.
            self.address_index.clear();
            for (i, row) in self.rows.iter().enumerate() {
                self.address_index.insert(row.address, i);
            }
            self.dirty = true;
            Some(removed)
        } else {
            None
        }
    }

    /// Remove strings in the address range [start, end].
    pub fn remove_range(&mut self, start: u64, end: u64) {
        let before_len = self.rows.len();
        self.rows.retain(|r| r.address < start || r.address > end);
        if self.rows.len() != before_len {
            self.address_index.clear();
            for (i, row) in self.rows.iter().enumerate() {
                self.address_index.insert(row.address, i);
            }
            self.dirty = true;
        }
    }

    /// Find a row by address.
    pub fn find_by_address(&self, address: u64) -> Option<&DefinedStringData> {
        self.address_index
            .get(&address)
            .and_then(|&idx| self.rows.get(idx))
    }

    /// Total number of rows.
    pub fn total_count(&self) -> usize {
        self.rows.len()
    }

    /// Whether the model is empty.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Get a row by index.
    pub fn row(&self, index: usize) -> Option<&DefinedStringData> {
        self.rows.get(index)
    }

    /// Get all rows.
    pub fn rows(&self) -> &[DefinedStringData] {
        &self.rows
    }

    /// Rebuild the filtered view.
    fn rebuild(&mut self) {
        if !self.dirty {
            return;
        }
        self.filtered = (0..self.rows.len()).collect();

        // Sort.
        let ascending = self.sort_ascending;
        let col = self.sort_column;
        self.filtered.sort_by(|&a, &b| {
            let ra = &self.rows[a];
            let rb = &self.rows[b];
            let ord = match col {
                0 => ra.address.cmp(&rb.address),
                1 => ra.value.cmp(&rb.value),
                2 => ra.data_type_name.cmp(&rb.data_type_name),
                3 => ra.charset.cmp(&rb.charset),
                4 => ra.length.cmp(&rb.length),
                _ => ra.address.cmp(&rb.address),
            };
            if ascending {
                ord
            } else {
                ord.reverse()
            }
        });

        self.dirty = false;
    }

    /// Get the filtered count.
    pub fn filtered_count(&mut self) -> usize {
        self.rebuild();
        self.filtered.len()
    }

    /// Get a filtered row by index.
    pub fn get_filtered(&mut self, index: usize) -> Option<&DefinedStringData> {
        self.rebuild();
        self.filtered
            .get(index)
            .and_then(|&i| self.rows.get(i))
    }

    /// Set the sort column and direction.
    pub fn set_sort(&mut self, column: usize, ascending: bool) {
        self.sort_column = column;
        self.sort_ascending = ascending;
        self.dirty = true;
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
        self.address_index.clear();
        self.dirty = true;
    }
}

impl Default for DefinedStringsTableModel {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DefinedStringsContext -- action context for selected rows
// ---------------------------------------------------------------------------

/// Action context for the defined strings table.
///
/// Provides information about the currently selected rows for context menu
/// actions (e.g., "Settings...", "Default Settings...").
///
/// Ported from Ghidra's `DefinedStringsContext` Java class.
#[derive(Debug, Clone)]
pub struct DefinedStringsContext {
    /// Indices of selected rows.
    selected_rows: Vec<usize>,
    /// The program name.
    program: Option<String>,
}

impl DefinedStringsContext {
    /// Create a new context with the given selected rows.
    pub fn new(selected_rows: Vec<usize>, program: Option<String>) -> Self {
        Self {
            selected_rows,
            program,
        }
    }

    /// Number of selected rows.
    pub fn count(&self) -> usize {
        self.selected_rows.len()
    }

    /// Whether any rows are selected.
    pub fn has_selection(&self) -> bool {
        !self.selected_rows.is_empty()
    }

    /// The program name.
    pub fn program(&self) -> Option<&str> {
        self.program.as_deref()
    }

    /// The selected row indices.
    pub fn selected_rows(&self) -> &[usize] {
        &self.selected_rows
    }

    /// The first selected row index, if any.
    pub fn first_selected(&self) -> Option<usize> {
        self.selected_rows.first().copied()
    }
}

// ---------------------------------------------------------------------------
// DefinedStringsProvider -- the table view component
// ---------------------------------------------------------------------------

/// Provider component that displays the defined strings table.
///
/// Manages the table model, handles visibility changes, and provides
/// incremental updates when the program listing changes.
///
/// Ported from Ghidra's `DefinedStringsProvider` Java class.
#[derive(Debug)]
pub struct DefinedStringsProvider {
    /// Provider name.
    name: String,
    /// The table model.
    model: DefinedStringsTableModel,
    /// Current program name.
    program: Option<String>,
    /// Whether the provider is visible.
    visible: bool,
    /// Whether data is stale (needs refresh).
    stale: bool,
}

impl DefinedStringsProvider {
    /// Create a new provider.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            model: DefinedStringsTableModel::new(),
            program: None,
            visible: false,
            stale: false,
        }
    }

    /// Provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the current program.
    pub fn set_program(&mut self, program: Option<String>) {
        self.program = program;
        self.model.clear();
        self.stale = false;
    }

    /// Get the current program name.
    pub fn program(&self) -> Option<&str> {
        self.program.as_deref()
    }

    /// Reload the model from scratch.
    pub fn reload(&mut self, strings: Vec<DefinedStringData>) {
        self.model.reload(strings);
        self.stale = false;
    }

    /// Add a single string to the model.
    pub fn add(&mut self, data: DefinedStringData) {
        self.model.add(data);
    }

    /// Remove strings in an address range.
    pub fn remove_range(&mut self, start: u64, end: u64) {
        self.model.remove_range(start, end);
    }

    /// Mark the data as stale (needs refresh).
    pub fn mark_stale(&mut self) {
        self.stale = true;
    }

    /// Whether the data is stale.
    pub fn is_stale(&self) -> bool {
        self.stale
    }

    /// Get the table model.
    pub fn model(&self) -> &DefinedStringsTableModel {
        &self.model
    }

    /// Get a mutable reference to the table model.
    pub fn model_mut(&mut self) -> &mut DefinedStringsTableModel {
        &mut self.model
    }

    /// Set visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    /// Whether the provider is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Create an action context for the given selected rows.
    pub fn action_context(&self, selected_rows: Vec<usize>) -> DefinedStringsContext {
        DefinedStringsContext::new(selected_rows, self.program.clone())
    }

    /// Dispose the provider.
    pub fn dispose(&mut self) {
        self.model.clear();
        self.program = None;
        self.visible = false;
    }
}

// ---------------------------------------------------------------------------
// DomainChangeEvent -- events the plugin listens to
// ---------------------------------------------------------------------------

/// Domain object change events that affect the defined strings table.
///
/// Ported from the event types checked in
/// `DefinedStringsPlugin.domainObjectChanged()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainChangeEvent {
    /// The program was restored (full reload needed).
    Restored,
    /// A memory block was moved.
    MemoryBlockMoved,
    /// A memory block was removed.
    MemoryBlockRemoved,
    /// A data type changed.
    DataTypeChanged,
    /// Code was removed at an address range.
    CodeRemoved { start: u64, end: u64 },
    /// Code was added (new data item).
    CodeAdded { address: u64 },
    /// A data type setting changed.
    DataTypeSettingChanged,
}

// ---------------------------------------------------------------------------
// DefinedStringTablePlugin -- the main plugin
// ---------------------------------------------------------------------------

/// The Defined Strings Table plugin.
///
/// Displays all defined string data in the current program.  Listens for
/// domain object changes and incrementally updates the table.
///
/// Ported from Ghidra's `ghidra.app.plugin.core.strings.DefinedStringsPlugin`.
#[derive(Debug)]
pub struct DefinedStringTablePlugin {
    /// The plugin name.
    name: String,
    /// The provider (table view).
    provider: DefinedStringsProvider,
    /// Current program name.
    current_program: Option<String>,
    /// Whether the plugin is initialized.
    initialized: bool,
    /// Whether the plugin is disposed.
    disposed: bool,
    /// Whether the link navigation action is selected.
    link_navigation: bool,
    /// Coalesced reload pending flag.
    reload_pending: bool,
}

impl DefinedStringTablePlugin {
    /// Create a new defined strings plugin.
    pub fn new(name: impl Into<String>) -> Self {
        let n = name.into();
        Self {
            provider: DefinedStringsProvider::new(format!("{} Provider", n)),
            name: n,
            current_program: None,
            initialized: false,
            disposed: false,
            link_navigation: false,
            reload_pending: false,
        }
    }

    /// Returns the plugin name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Initializes the plugin.
    pub fn init(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
    }

    /// Disposes the plugin.
    pub fn dispose(&mut self) {
        if self.disposed {
            return;
        }
        self.disposed = true;
        self.provider.dispose();
    }

    /// Returns whether the plugin is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns whether the plugin is disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Set the current program (activates the program).
    pub fn set_program(&mut self, program: Option<String>) {
        self.current_program = program.clone();
        self.provider.set_program(program);
    }

    /// Get the current program name.
    pub fn program(&self) -> Option<&str> {
        self.current_program.as_deref()
    }

    /// Get a reference to the provider.
    pub fn provider(&self) -> &DefinedStringsProvider {
        &self.provider
    }

    /// Get a mutable reference to the provider.
    pub fn provider_mut(&mut self) -> &mut DefinedStringsProvider {
        &mut self.provider
    }

    /// Enable or disable link navigation.
    pub fn set_link_navigation(&mut self, enabled: bool) {
        self.link_navigation = enabled;
    }

    /// Whether link navigation is enabled.
    pub fn is_link_navigation(&self) -> bool {
        self.link_navigation
    }

    /// Handle a program location change (for linked navigation).
    pub fn location_changed(&mut self, address: u64) {
        if self.link_navigation {
            // In a full implementation this would scroll the table to the
            // row matching the address.  Here we just record the address.
            let _ = address;
        }
    }

    /// Request a reload of the defined strings table.
    ///
    /// In Ghidra this is coalesced via `SwingUpdateManager` with a 100ms
    /// delay and 60s max wait.  Here we simply mark it as pending.
    pub fn request_reload(&mut self) {
        self.reload_pending = true;
    }

    /// Perform the reload if pending.
    pub fn do_reload_if_pending(&mut self, strings: Vec<DefinedStringData>) {
        if self.reload_pending {
            self.provider.reload(strings);
            self.reload_pending = false;
        }
    }

    /// Whether a reload is pending.
    pub fn is_reload_pending(&self) -> bool {
        self.reload_pending
    }

    /// Handle a domain object change event.
    ///
    /// This is the Rust equivalent of `DefinedStringsPlugin.domainObjectChanged()`.
    pub fn handle_event(&mut self, event: DomainChangeEvent) {
        match event {
            DomainChangeEvent::Restored
            | DomainChangeEvent::MemoryBlockMoved
            | DomainChangeEvent::MemoryBlockRemoved
            | DomainChangeEvent::DataTypeChanged => {
                self.provider.mark_stale();
                self.request_reload();
            }
            DomainChangeEvent::CodeRemoved { start, end } => {
                self.provider.remove_range(start, end);
            }
            DomainChangeEvent::CodeAdded { .. } => {
                // In a full implementation we would add the new data item.
                // For now just request a reload.
                self.request_reload();
            }
            DomainChangeEvent::DataTypeSettingChanged => {
                // The table needs repaint but no structural change.
                self.provider.mark_stale();
            }
        }
    }
}

impl Default for DefinedStringTablePlugin {
    fn default() -> Self {
        Self::new("DefinedStringTablePlugin")
    }
}

impl fmt::Display for DefinedStringTablePlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DefinedStringTablePlugin({}, program={:?})",
            self.name, self.current_program
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- DefinedStringData --

    #[test]
    fn test_defined_string_data_new() {
        let d = DefinedStringData::new(0x1000, "hello", "string");
        assert_eq!(d.address, 0x1000);
        assert_eq!(d.value, "hello");
        assert_eq!(d.data_type_name, "string");
        assert_eq!(d.length, 5);
        assert!(d.is_ascii);
        assert!(!d.has_encoding_error);
    }

    #[test]
    fn test_defined_string_data_builders() {
        let d = DefinedStringData::new(0x1000, "test", "unicode")
            .with_representation("\"test\"")
            .with_charset("UTF-8")
            .with_encoding_error(true)
            .with_unicode_script("CYRILLIC")
            .with_translated_value("translated");
        assert_eq!(d.representation, "\"test\"");
        assert_eq!(d.charset, "UTF-8");
        assert!(d.has_encoding_error);
        assert_eq!(d.unicode_script, "CYRILLIC");
        assert_eq!(d.translated_value, "translated");
    }

    #[test]
    fn test_defined_string_data_display() {
        let d = DefinedStringData::new(0x401000, "hello world", "string");
        let s = format!("{}", d);
        assert!(s.contains("00401000"));
        assert!(s.contains("string"));
        assert!(s.contains("hello world"));
    }

    // -- DefinedStringsTableModel --

    #[test]
    fn test_table_model_empty() {
        let model = DefinedStringsTableModel::new();
        assert!(model.is_empty());
        assert_eq!(model.total_count(), 0);
    }

    #[test]
    fn test_table_model_reload() {
        let mut model = DefinedStringsTableModel::new();
        let strings = vec![
            DefinedStringData::new(0x100, "hello", "string"),
            DefinedStringData::new(0x200, "world", "string"),
        ];
        model.reload(strings);
        assert_eq!(model.total_count(), 2);
        assert!(!model.is_empty());
    }

    #[test]
    fn test_table_model_add() {
        let mut model = DefinedStringsTableModel::new();
        model.add(DefinedStringData::new(0x100, "first", "string"));
        model.add(DefinedStringData::new(0x200, "second", "string"));
        assert_eq!(model.total_count(), 2);
    }

    #[test]
    fn test_table_model_find_by_address() {
        let mut model = DefinedStringsTableModel::new();
        model.add(DefinedStringData::new(0x100, "hello", "string"));
        model.add(DefinedStringData::new(0x200, "world", "string"));

        let found = model.find_by_address(0x200);
        assert!(found.is_some());
        assert_eq!(found.unwrap().value, "world");

        assert!(model.find_by_address(0x999).is_none());
    }

    #[test]
    fn test_table_model_remove_at() {
        let mut model = DefinedStringsTableModel::new();
        model.add(DefinedStringData::new(0x100, "hello", "string"));
        model.add(DefinedStringData::new(0x200, "world", "string"));

        let removed = model.remove_at(0x100);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().value, "hello");
        assert_eq!(model.total_count(), 1);

        assert!(model.remove_at(0x999).is_none());
    }

    #[test]
    fn test_table_model_remove_range() {
        let mut model = DefinedStringsTableModel::new();
        model.add(DefinedStringData::new(0x100, "a", "string"));
        model.add(DefinedStringData::new(0x200, "b", "string"));
        model.add(DefinedStringData::new(0x300, "c", "string"));
        model.add(DefinedStringData::new(0x400, "d", "string"));

        model.remove_range(0x150, 0x350);
        assert_eq!(model.total_count(), 2);
        assert!(model.find_by_address(0x100).is_some());
        assert!(model.find_by_address(0x400).is_some());
        assert!(model.find_by_address(0x200).is_none());
        assert!(model.find_by_address(0x300).is_none());
    }

    #[test]
    fn test_table_model_sort() {
        let mut model = DefinedStringsTableModel::new();
        model.add(DefinedStringData::new(0x300, "charlie", "string"));
        model.add(DefinedStringData::new(0x100, "alpha", "string"));
        model.add(DefinedStringData::new(0x200, "bravo", "string"));

        // Sort by address ascending.
        model.set_sort(0, true);
        assert_eq!(model.filtered_count(), 3);
        assert_eq!(model.get_filtered(0).unwrap().address, 0x100);
        assert_eq!(model.get_filtered(1).unwrap().address, 0x200);
        assert_eq!(model.get_filtered(2).unwrap().address, 0x300);

        // Sort by address descending.
        model.set_sort(0, false);
        assert_eq!(model.get_filtered(0).unwrap().address, 0x300);

        // Sort by value ascending.
        model.set_sort(1, true);
        assert_eq!(model.get_filtered(0).unwrap().value, "alpha");
    }

    #[test]
    fn test_table_model_clear() {
        let mut model = DefinedStringsTableModel::new();
        model.add(DefinedStringData::new(0x100, "hello", "string"));
        assert_eq!(model.total_count(), 1);
        model.clear();
        assert_eq!(model.total_count(), 0);
        assert!(model.is_empty());
    }

    // -- DefinedStringsContext --

    #[test]
    fn test_context_empty() {
        let ctx = DefinedStringsContext::new(vec![], None);
        assert_eq!(ctx.count(), 0);
        assert!(!ctx.has_selection());
        assert!(ctx.first_selected().is_none());
    }

    #[test]
    fn test_context_with_selection() {
        let ctx = DefinedStringsContext::new(vec![0, 2, 4], Some("test.exe".into()));
        assert_eq!(ctx.count(), 3);
        assert!(ctx.has_selection());
        assert_eq!(ctx.first_selected(), Some(0));
        assert_eq!(ctx.program(), Some("test.exe"));
        assert_eq!(ctx.selected_rows(), &[0, 2, 4]);
    }

    // -- DefinedStringsProvider --

    #[test]
    fn test_provider_lifecycle() {
        let mut provider = DefinedStringsProvider::new("TestProvider");
        assert_eq!(provider.name(), "TestProvider");
        assert!(!provider.is_visible());
        assert!(provider.program().is_none());
        assert!(!provider.is_stale());

        provider.set_visible(true);
        assert!(provider.is_visible());

        provider.set_program(Some("test.exe".into()));
        assert_eq!(provider.program(), Some("test.exe"));
    }

    #[test]
    fn test_provider_reload() {
        let mut provider = DefinedStringsProvider::new("TestProvider");
        let strings = vec![
            DefinedStringData::new(0x100, "hello", "string"),
            DefinedStringData::new(0x200, "world", "string"),
        ];
        provider.reload(strings);
        assert_eq!(provider.model().total_count(), 2);
        assert!(!provider.is_stale());
    }

    #[test]
    fn test_provider_stale() {
        let mut provider = DefinedStringsProvider::new("TestProvider");
        assert!(!provider.is_stale());
        provider.mark_stale();
        assert!(provider.is_stale());
    }

    #[test]
    fn test_provider_add() {
        let mut provider = DefinedStringsProvider::new("TestProvider");
        provider.add(DefinedStringData::new(0x100, "hello", "string"));
        assert_eq!(provider.model().total_count(), 1);
    }

    #[test]
    fn test_provider_action_context() {
        let provider = DefinedStringsProvider::new("TestProvider");
        let ctx = provider.action_context(vec![0, 1]);
        assert_eq!(ctx.count(), 2);
    }

    #[test]
    fn test_provider_dispose() {
        let mut provider = DefinedStringsProvider::new("TestProvider");
        provider.set_program(Some("test.exe".into()));
        provider.add(DefinedStringData::new(0x100, "hello", "string"));
        provider.set_visible(true);

        provider.dispose();
        assert!(!provider.is_visible());
        assert!(provider.program().is_none());
        assert!(provider.model().is_empty());
    }

    // -- DomainChangeEvent --

    #[test]
    fn test_domain_event_equality() {
        assert_eq!(
            DomainChangeEvent::CodeRemoved {
                start: 0x100,
                end: 0x200
            },
            DomainChangeEvent::CodeRemoved {
                start: 0x100,
                end: 0x200
            }
        );
        assert_ne!(
            DomainChangeEvent::Restored,
            DomainChangeEvent::MemoryBlockMoved
        );
    }

    // -- DefinedStringTablePlugin --

    #[test]
    fn test_plugin_creation() {
        let plugin = DefinedStringTablePlugin::new("TestPlugin");
        assert_eq!(plugin.name(), "TestPlugin");
        assert!(!plugin.is_initialized());
        assert!(!plugin.is_disposed());
        assert!(!plugin.is_link_navigation());
        assert!(!plugin.is_reload_pending());
    }

    #[test]
    fn test_plugin_init_dispose() {
        let mut plugin = DefinedStringTablePlugin::new("TestPlugin");
        plugin.init();
        assert!(plugin.is_initialized());
        plugin.init(); // double-init ok

        plugin.dispose();
        assert!(plugin.is_disposed());
        plugin.dispose(); // double-dispose ok
    }

    #[test]
    fn test_plugin_program() {
        let mut plugin = DefinedStringTablePlugin::new("TestPlugin");
        assert!(plugin.program().is_none());

        plugin.set_program(Some("test.exe".into()));
        assert_eq!(plugin.program(), Some("test.exe"));

        plugin.set_program(None);
        assert!(plugin.program().is_none());
    }

    #[test]
    fn test_plugin_link_navigation() {
        let mut plugin = DefinedStringTablePlugin::new("TestPlugin");
        assert!(!plugin.is_link_navigation());

        plugin.set_link_navigation(true);
        assert!(plugin.is_link_navigation());

        plugin.set_link_navigation(false);
        assert!(!plugin.is_link_navigation());
    }

    #[test]
    fn test_plugin_location_changed() {
        let mut plugin = DefinedStringTablePlugin::new("TestPlugin");
        plugin.set_link_navigation(true);
        // Should not panic.
        plugin.location_changed(0x1000);
    }

    #[test]
    fn test_plugin_reload_request() {
        let mut plugin = DefinedStringTablePlugin::new("TestPlugin");
        assert!(!plugin.is_reload_pending());

        plugin.request_reload();
        assert!(plugin.is_reload_pending());

        // Reload with data.
        let strings = vec![DefinedStringData::new(0x100, "hello", "string")];
        plugin.do_reload_if_pending(strings);
        assert!(!plugin.is_reload_pending());
        assert_eq!(plugin.provider().model().total_count(), 1);
    }

    #[test]
    fn test_plugin_do_reload_not_pending() {
        let mut plugin = DefinedStringTablePlugin::new("TestPlugin");
        // No reload requested, so do_reload_if_pending is a no-op.
        let strings = vec![DefinedStringData::new(0x100, "hello", "string")];
        plugin.do_reload_if_pending(strings);
        assert_eq!(plugin.provider().model().total_count(), 0);
    }

    #[test]
    fn test_plugin_handle_event_restored() {
        let mut plugin = DefinedStringTablePlugin::new("TestPlugin");
        plugin.handle_event(DomainChangeEvent::Restored);
        assert!(plugin.provider().is_stale());
        assert!(plugin.is_reload_pending());
    }

    #[test]
    fn test_plugin_handle_event_memory_block_moved() {
        let mut plugin = DefinedStringTablePlugin::new("TestPlugin");
        plugin.handle_event(DomainChangeEvent::MemoryBlockMoved);
        assert!(plugin.provider().is_stale());
        assert!(plugin.is_reload_pending());
    }

    #[test]
    fn test_plugin_handle_event_memory_block_removed() {
        let mut plugin = DefinedStringTablePlugin::new("TestPlugin");
        plugin.handle_event(DomainChangeEvent::MemoryBlockRemoved);
        assert!(plugin.provider().is_stale());
        assert!(plugin.is_reload_pending());
    }

    #[test]
    fn test_plugin_handle_event_data_type_changed() {
        let mut plugin = DefinedStringTablePlugin::new("TestPlugin");
        plugin.handle_event(DomainChangeEvent::DataTypeChanged);
        assert!(plugin.provider().is_stale());
        assert!(plugin.is_reload_pending());
    }

    #[test]
    fn test_plugin_handle_event_code_removed() {
        let mut plugin = DefinedStringTablePlugin::new("TestPlugin");
        // Add some data first.
        plugin.provider_mut().add(DefinedStringData::new(0x100, "hello", "string"));
        plugin.provider_mut().add(DefinedStringData::new(0x200, "world", "string"));
        plugin.provider_mut().add(DefinedStringData::new(0x300, "test", "string"));

        plugin.handle_event(DomainChangeEvent::CodeRemoved {
            start: 0x150,
            end: 0x250,
        });
        // Should have removed the 0x200 entry.
        assert_eq!(plugin.provider().model().total_count(), 2);
        assert!(plugin.provider().model().find_by_address(0x100).is_some());
        assert!(plugin.provider().model().find_by_address(0x300).is_some());
        assert!(plugin.provider().model().find_by_address(0x200).is_none());
    }

    #[test]
    fn test_plugin_handle_event_code_added() {
        let mut plugin = DefinedStringTablePlugin::new("TestPlugin");
        plugin.handle_event(DomainChangeEvent::CodeAdded { address: 0x400 });
        assert!(plugin.is_reload_pending());
    }

    #[test]
    fn test_plugin_handle_event_data_type_setting_changed() {
        let mut plugin = DefinedStringTablePlugin::new("TestPlugin");
        plugin.handle_event(DomainChangeEvent::DataTypeSettingChanged);
        assert!(plugin.provider().is_stale());
        assert!(!plugin.is_reload_pending()); // only repaint, no structural change
    }

    #[test]
    fn test_plugin_display() {
        let plugin = DefinedStringTablePlugin::new("TestPlugin");
        let display = format!("{}", plugin);
        assert!(display.contains("TestPlugin"));
    }

    #[test]
    fn test_plugin_provider_access() {
        let plugin = DefinedStringTablePlugin::new("TestPlugin");
        assert_eq!(plugin.provider().name(), "TestPlugin Provider");
    }
}
