//! GoTo query service -- ported from Ghidra's
//! `ghidra.app.plugin.core.gotoquery` Java package.
//!
//! Provides the "Go To Address" service that other plugins use to
//! navigate the listing to an address, symbol, or external location.
//! The core pieces are:
//!
//! - [`GoToHelper`] -- navigation logic (address resolution,
//!   external linkage)
//! - [`GoToServicePlugin`] -- plugin implementing the GoTo service
//! - [`GoToQueryResultsTableModel`] -- table model for multiple
//!   GoTo hits
//!
//! Swing UI code is omitted; only model and navigation logic are
//! ported.

pub mod go_to_helper;
pub mod go_to_service_plugin;

use ghidra_core::Address;

use go_to_helper::ProgramLocation;

// ---------------------------------------------------------------------------
// GoToQueryResultsTableModel
// ---------------------------------------------------------------------------

/// Table model for displaying multiple GoTo query results.
///
/// When a GoTo query matches multiple symbols or addresses, the
/// results are collected in this model for display in a results
/// table.
///
/// Ported from
/// `ghidra.app.plugin.core.gotoquery.GoToQueryResultsTableModel`.
#[derive(Debug)]
pub struct GoToQueryResultsTableModel {
    /// Title for the table.
    title: String,
    /// The program name.
    program_name: String,
    /// All result locations.
    results: Vec<ProgramLocation>,
    /// Whether loading is complete.
    loaded: bool,
}

impl GoToQueryResultsTableModel {
    /// Create a new table model with the given title and program
    /// name.
    pub fn new(
        title: impl Into<String>,
        program_name: impl Into<String>,
    ) -> Self {
        Self {
            title: title.into(),
            program_name: program_name.into(),
            results: Vec::new(),
            loaded: false,
        }
    }

    /// Add a result to the model.
    pub fn add_result(&mut self, location: ProgramLocation) {
        self.results.push(location);
    }

    /// Add multiple results.
    pub fn add_results(
        &mut self,
        locations: impl IntoIterator<Item = ProgramLocation>,
    ) {
        self.results.extend(locations);
    }

    /// Get the number of results.
    pub fn row_count(&self) -> usize {
        self.results.len()
    }

    /// Get a result by row index.
    pub fn get_result(&self, row: usize) -> Option<&ProgramLocation> {
        self.results.get(row)
    }

    /// Get the address for a row.
    pub fn get_address(&self, row: usize) -> Option<Address> {
        self.results.get(row).map(|r| r.address)
    }

    /// Get all results.
    pub fn results(&self) -> &[ProgramLocation] {
        &self.results
    }

    /// Mark the model as fully loaded.
    pub fn set_loaded(&mut self) {
        self.loaded = true;
    }

    /// Whether the model has finished loading.
    pub fn is_loaded(&self) -> bool {
        self.loaded
    }

    /// Get the title.
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Get the program name.
    pub fn program_name(&self) -> &str {
        &self.program_name
    }

    /// Clear all results.
    pub fn clear(&mut self) {
        self.results.clear();
        self.loaded = false;
    }
}

// ---------------------------------------------------------------------------
// DefaultNavigatableLocationMemento
// ---------------------------------------------------------------------------

/// Default memento for saving and restoring navigatable locations.
///
/// Ported from
/// `ghidra.app.plugin.core.gotoquery.DefaultNavigatableLocationMemento`.
///
/// Captures the location of all connected, visible navigatables
/// so they can be restored later (e.g., when navigating back).
#[derive(Debug, Clone)]
pub struct DefaultNavigatableLocationMemento {
    /// The program name.
    pub program_name: String,
    /// The address.
    pub address: u64,
    /// The component path (for composite data).
    pub component_path: Vec<u64>,
    /// Focused navigatable id (if any).
    pub focused_navigatable_id: Option<u64>,
}

impl DefaultNavigatableLocationMemento {
    /// Create a new memento.
    pub fn new(program_name: impl Into<String>, address: u64) -> Self {
        Self {
            program_name: program_name.into(),
            address,
            component_path: Vec::new(),
            focused_navigatable_id: None,
        }
    }

    /// Add a component path entry.
    pub fn add_component(&mut self, offset: u64) {
        self.component_path.push(offset);
    }

    /// Set the focused navigatable id.
    pub fn set_focused_navigatable(&mut self, id: u64) {
        self.focused_navigatable_id = Some(id);
    }

    /// Get the focused navigatable id.
    pub fn focused_navigatable_id(&self) -> Option<u64> {
        self.focused_navigatable_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_goto_query_results_table_model() {
        let mut model = GoToQueryResultsTableModel::new("Goto", "test.exe");
        assert_eq!(model.row_count(), 0);
        assert!(!model.is_loaded());
        assert_eq!(model.title(), "Goto");
        assert_eq!(model.program_name(), "test.exe");

        let addr1 = Address::new(0x401000);
        let addr2 = Address::new(0x402000);
        model.add_result(ProgramLocation::new("test.exe", addr1));
        model.add_result(ProgramLocation::with_symbol(
            "test.exe", addr2, "func",
        ));

        assert_eq!(model.row_count(), 2);
        assert_eq!(model.get_address(0), Some(addr1));
        assert_eq!(model.get_address(1), Some(addr2));
        assert_eq!(
            model.get_result(1).unwrap().symbol_name,
            Some("func".into())
        );

        model.set_loaded();
        assert!(model.is_loaded());

        model.clear();
        assert_eq!(model.row_count(), 0);
        assert!(!model.is_loaded());
    }

    #[test]
    fn test_goto_query_results_add_results() {
        let mut model = GoToQueryResultsTableModel::new("Goto", "test.exe");
        let locs = vec![
            ProgramLocation::new("test.exe", Address::new(0x1000)),
            ProgramLocation::new("test.exe", Address::new(0x2000)),
            ProgramLocation::new("test.exe", Address::new(0x3000)),
        ];
        model.add_results(locs);
        assert_eq!(model.row_count(), 3);
    }

    #[test]
    fn test_default_navigatable_location_memento() {
        let mut m = DefaultNavigatableLocationMemento::new("test.exe", 0x401000);
        assert_eq!(m.program_name, "test.exe");
        assert_eq!(m.address, 0x401000);
        assert!(m.component_path.is_empty());
        assert!(m.focused_navigatable_id().is_none());

        m.add_component(0x10);
        m.add_component(0x20);
        assert_eq!(m.component_path, vec![0x10, 0x20]);

        m.set_focused_navigatable(42);
        assert_eq!(m.focused_navigatable_id(), Some(42));
    }
}
