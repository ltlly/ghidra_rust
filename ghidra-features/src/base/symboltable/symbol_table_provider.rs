//! Symbol Table Provider -- ported from `SymbolProvider.java` and
//! `SymbolPanel.java`.
//!
//! The [`SymbolTableProvider`] manages the lifecycle of the symbol table
//! panel and its display configuration.  It coordinates with the plugin
//! to handle visibility, program changes, and configuration persistence.

use std::fmt;

use super::symbol_table_plugin::{SymbolFilter, SymbolTableModel};

// ---------------------------------------------------------------------------
// SymbolTableConfig -- display configuration
// ---------------------------------------------------------------------------

/// Display configuration for the symbol table panel.
///
/// Ported from `SymbolPanel` configuration.  Controls column
/// visibility, formatting, and layout options.
#[derive(Debug, Clone)]
pub struct SymbolTableConfig {
    /// Show addresses in hex format.
    pub show_address_hex: bool,
    /// Show the namespace column.
    pub show_namespace: bool,
    /// Show the source column.
    pub show_source: bool,
    /// Show the primary column.
    pub show_primary: bool,
    /// Auto-size columns to fit content.
    pub auto_size_columns: bool,
    /// Row height in pixels.
    pub row_height: i32,
    /// Whether to highlight external symbols.
    pub highlight_external: bool,
    /// Whether to show pinned symbols at the top.
    pub pin_to_top: bool,
}

impl Default for SymbolTableConfig {
    fn default() -> Self {
        Self {
            show_address_hex: true,
            show_namespace: true,
            show_source: true,
            show_primary: true,
            auto_size_columns: true,
            row_height: 20,
            highlight_external: true,
            pin_to_top: false,
        }
    }
}

impl SymbolTableConfig {
    /// Serializes the configuration to JSON for state persistence.
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"show_address_hex":{},"show_namespace":{},"show_source":{},"show_primary":{},"auto_size_columns":{},"row_height":{},"highlight_external":{},"pin_to_top":{}}}"#,
            self.show_address_hex,
            self.show_namespace,
            self.show_source,
            self.show_primary,
            self.auto_size_columns,
            self.row_height,
            self.highlight_external,
            self.pin_to_top,
        )
    }

    /// Deserializes a configuration from a JSON string.
    ///
    /// Returns `None` on parse failure.
    pub fn from_json(json: &str) -> Option<Self> {
        // Simple key-value parsing without a full JSON dependency.
        let get_bool = |key: &str| -> Option<bool> {
            let needle = format!("\"{}\":", key);
            let start = json.find(&needle)? + needle.len();
            let rest = &json[start..];
            if rest.starts_with("true") {
                Some(true)
            } else if rest.starts_with("false") {
                Some(false)
            } else {
                None
            }
        };
        let get_i32 = |key: &str| -> Option<i32> {
            let needle = format!("\"{}\":", key);
            let start = json.find(&needle)? + needle.len();
            let rest = &json[start..];
            let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-').unwrap_or(rest.len());
            rest[..end].parse().ok()
        };

        Some(Self {
            show_address_hex: get_bool("show_address_hex")?,
            show_namespace: get_bool("show_namespace")?,
            show_source: get_bool("show_source")?,
            show_primary: get_bool("show_primary")?,
            auto_size_columns: get_bool("auto_size_columns")?,
            row_height: get_i32("row_height")?,
            highlight_external: get_bool("highlight_external")?,
            pin_to_top: get_bool("pin_to_top")?,
        })
    }
}

// ---------------------------------------------------------------------------
// SortDirection
// ---------------------------------------------------------------------------

/// Sort direction for table columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDirection {
    /// Ascending order.
    Ascending,
    /// Descending order.
    Descending,
}

impl fmt::Display for SortDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ascending => write!(f, "Ascending"),
            Self::Descending => write!(f, "Descending"),
        }
    }
}

impl Default for SortDirection {
    fn default() -> Self {
        Self::Ascending
    }
}

// ---------------------------------------------------------------------------
// SortState
// ---------------------------------------------------------------------------

/// Tracks the current sort column and direction.
#[derive(Debug, Clone)]
pub struct SortState {
    /// The column index being sorted.
    pub column_index: usize,
    /// The sort direction.
    pub direction: SortDirection,
}

impl Default for SortState {
    fn default() -> Self {
        Self {
            column_index: 0, // Name
            direction: SortDirection::Ascending,
        }
    }
}

// ---------------------------------------------------------------------------
// SymbolTableProvider
// ---------------------------------------------------------------------------

/// The symbol table provider.
///
/// Manages the lifecycle of the symbol table panel: visibility, program
/// association, display configuration, and sort state.
///
/// Ported from Ghidra's `SymbolProvider` which extends
/// `ComponentProviderDocking`.
///
/// # Example
///
/// ```
/// use ghidra_features::base::symboltable::*;
///
/// let mut provider = SymbolTableProvider::new("Symbol Table");
/// provider.set_program_name(Some("test.exe".to_string()));
/// provider.set_visible(true);
/// assert!(provider.is_visible());
/// assert_eq!(provider.program_name(), Some("test.exe"));
/// ```
#[derive(Debug)]
pub struct SymbolTableProvider {
    /// Display name.
    name: String,
    /// Display configuration.
    config: SymbolTableConfig,
    /// Whether the panel is visible.
    visible: bool,
    /// Associated program name.
    program_name: Option<String>,
    /// Current sort state.
    sort_state: SortState,
    /// Whether the provider has been disposed.
    disposed: bool,
}

impl SymbolTableProvider {
    /// Creates a new symbol table provider.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            config: SymbolTableConfig::default(),
            visible: false,
            program_name: None,
            sort_state: SortState::default(),
            disposed: false,
        }
    }

    /// Returns the provider name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns whether the provider has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    // -- Configuration --

    /// Returns the current configuration.
    pub fn config(&self) -> &SymbolTableConfig {
        &self.config
    }

    /// Returns a mutable reference to the configuration.
    pub fn config_mut(&mut self) -> &mut SymbolTableConfig {
        &mut self.config
    }

    /// Updates the configuration.
    pub fn set_config(&mut self, config: SymbolTableConfig) {
        self.config = config;
    }

    // -- Visibility --

    /// Returns whether the panel is visible.
    pub fn is_visible(&self) -> bool {
        self.visible
    }

    /// Sets the panel visibility.
    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
    }

    // -- Program association --

    /// Sets the associated program name.
    pub fn set_program_name(&mut self, name: Option<String>) {
        self.program_name = name;
    }

    /// Returns the associated program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    // -- Sort state --

    /// Returns the current sort state.
    pub fn sort_state(&self) -> &SortState {
        &self.sort_state
    }

    /// Sets the sort state.
    pub fn set_sort_state(&mut self, state: SortState) {
        self.sort_state = state;
    }

    /// Toggles the sort direction for the given column.  If the column
    /// is already the sort column, the direction is flipped; otherwise
    /// the column is set to ascending.
    pub fn toggle_sort(&mut self, column_index: usize) {
        if self.sort_state.column_index == column_index {
            self.sort_state.direction = match self.sort_state.direction {
                SortDirection::Ascending => SortDirection::Descending,
                SortDirection::Descending => SortDirection::Ascending,
            };
        } else {
            self.sort_state.column_index = column_index;
            self.sort_state.direction = SortDirection::Ascending;
        }
    }

    // -- Lifecycle --

    /// Called when the associated program is activated.
    pub fn program_activated(&mut self, program_name: String) {
        self.program_name = Some(program_name);
        self.visible = true;
    }

    /// Called when the associated program is closed.
    pub fn program_closed(&mut self) {
        self.program_name = None;
        self.visible = false;
    }

    /// Disposes the provider.
    pub fn dispose(&mut self) {
        self.visible = false;
        self.program_name = None;
        self.disposed = true;
    }

    /// Saves provider state to a JSON string.
    pub fn save_state(&self) -> String {
        format!(
            r#"{{"name":"{}","visible":{},"config":{}}}"#,
            self.name,
            self.visible,
            self.config.to_json(),
        )
    }
}

impl Default for SymbolTableProvider {
    fn default() -> Self {
        Self::new("SymbolTable")
    }
}

impl fmt::Display for SymbolTableProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SymbolTableProvider({}, visible={})",
            self.name, self.visible
        )
    }
}

// ---------------------------------------------------------------------------
// SymbolTableService -- service interface for external consumers
// ---------------------------------------------------------------------------

/// Service interface provided by the symbol table plugin.
///
/// Ported from `SymbolTableService.java`.  Other plugins use this
/// interface to query the symbol table and trigger navigation.
pub trait SymbolTableService: fmt::Debug + Send + Sync {
    /// Returns the number of visible (filtered) symbols.
    fn visible_count(&self) -> usize;

    /// Navigates to a symbol by its address.
    fn go_to_symbol(&self, address: u64) -> bool;

    /// Refreshes the symbol table from the current program state.
    fn refresh(&mut self);

    /// Returns `true` if a program is loaded.
    fn has_program(&self) -> bool;
}

/// A no-op implementation of [`SymbolTableService`] for testing.
#[derive(Debug, Default)]
pub struct NullSymbolTableService;

impl SymbolTableService for NullSymbolTableService {
    fn visible_count(&self) -> usize {
        0
    }

    fn go_to_symbol(&self, _address: u64) -> bool {
        false
    }

    fn refresh(&mut self) {}

    fn has_program(&self) -> bool {
        false
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_creation() {
        let provider = SymbolTableProvider::new("TestProvider");
        assert_eq!(provider.name(), "TestProvider");
        assert!(!provider.is_visible());
        assert!(!provider.is_disposed());
        assert!(provider.program_name().is_none());
    }

    #[test]
    fn test_provider_visibility() {
        let mut provider = SymbolTableProvider::new("Test");
        provider.set_visible(true);
        assert!(provider.is_visible());
        provider.dispose();
        assert!(!provider.is_visible());
        assert!(provider.is_disposed());
    }

    #[test]
    fn test_provider_config() {
        let mut provider = SymbolTableProvider::new("Test");
        assert!(provider.config().show_address_hex);
        provider.config_mut().show_address_hex = false;
        assert!(!provider.config().show_address_hex);
    }

    #[test]
    fn test_provider_program() {
        let mut provider = SymbolTableProvider::new("Test");
        provider.set_program_name(Some("test.exe".to_string()));
        assert_eq!(provider.program_name(), Some("test.exe"));
    }

    #[test]
    fn test_provider_program_lifecycle() {
        let mut provider = SymbolTableProvider::new("Test");
        provider.program_activated("test.bin".to_string());
        assert!(provider.is_visible());
        assert_eq!(provider.program_name(), Some("test.bin"));

        provider.program_closed();
        assert!(!provider.is_visible());
        assert!(provider.program_name().is_none());
    }

    #[test]
    fn test_config_default() {
        let config = SymbolTableConfig::default();
        assert!(config.show_address_hex);
        assert!(config.show_namespace);
        assert!(config.show_source);
        assert!(config.show_primary);
        assert!(config.auto_size_columns);
        assert_eq!(config.row_height, 20);
        assert!(config.highlight_external);
        assert!(!config.pin_to_top);
    }

    #[test]
    fn test_config_json_roundtrip() {
        let config = SymbolTableConfig {
            show_address_hex: false,
            row_height: 30,
            pin_to_top: true,
            ..Default::default()
        };
        let json = config.to_json();
        let restored = SymbolTableConfig::from_json(&json).unwrap();
        assert!(!restored.show_address_hex);
        assert_eq!(restored.row_height, 30);
        assert!(restored.pin_to_top);
        assert!(restored.show_namespace);
    }

    #[test]
    fn test_sort_state_default() {
        let state = SortState::default();
        assert_eq!(state.column_index, 0);
        assert_eq!(state.direction, SortDirection::Ascending);
    }

    #[test]
    fn test_sort_direction_display() {
        assert_eq!(SortDirection::Ascending.to_string(), "Ascending");
        assert_eq!(SortDirection::Descending.to_string(), "Descending");
    }

    #[test]
    fn test_toggle_sort() {
        let mut provider = SymbolTableProvider::new("Test");

        // Same column toggles direction.
        provider.toggle_sort(0);
        assert_eq!(provider.sort_state().direction, SortDirection::Descending);

        provider.toggle_sort(0);
        assert_eq!(provider.sort_state().direction, SortDirection::Ascending);

        // Different column resets to ascending.
        provider.toggle_sort(2);
        assert_eq!(provider.sort_state().column_index, 2);
        assert_eq!(provider.sort_state().direction, SortDirection::Ascending);
    }

    #[test]
    fn test_save_state() {
        let provider = SymbolTableProvider::new("TestProvider");
        let state = provider.save_state();
        assert!(state.contains("TestProvider"));
        assert!(state.contains("visible"));
    }

    #[test]
    fn test_provider_display() {
        let provider = SymbolTableProvider::new("Test");
        let s = format!("{}", provider);
        assert!(s.contains("Test"));
        assert!(s.contains("visible=false"));
    }

    #[test]
    fn test_null_service() {
        let svc = NullSymbolTableService;
        assert_eq!(svc.visible_count(), 0);
        assert!(!svc.go_to_symbol(0x401000));
        assert!(!svc.has_program());
    }

    #[test]
    fn test_config_from_json_malformed() {
        assert!(SymbolTableConfig::from_json("not json").is_none());
    }
}
