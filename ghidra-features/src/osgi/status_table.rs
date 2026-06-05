//! Bundle status table model for displaying bundle information.
//!
//! Ported from `ghidra.app.plugin.core.osgi.BundleStatusTableModel`.

use super::{BundleStatus, GhidraBundle};

/// Column indices for the bundle status table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleStatusColumns;

impl BundleStatusColumns {
    pub const SYMBOLIC_NAME: usize = 0;
    pub const DISPLAY_NAME: usize = 1;
    pub const VERSION: usize = 2;
    pub const STATUS: usize = 3;
    pub const SOURCE_PATH: usize = 4;

    pub const HEADERS: &'static [&'static str] = &[
        "Symbolic Name", "Display Name", "Version", "Status", "Source Path",
    ];
}

/// Table model for bundle status display.
///
/// Ported from `ghidra.app.plugin.core.osgi.BundleStatusTableModel`.
#[derive(Debug, Clone)]
pub struct BundleStatusTableModel {
    /// The bundles to display.
    entries: Vec<BundleStatusEntry>,
    /// The sort column.
    sort_column: usize,
    /// Sort ascending.
    sort_ascending: bool,
}

/// A row in the bundle status table.
#[derive(Debug, Clone)]
pub struct BundleStatusEntry {
    /// The symbolic name.
    pub symbolic_name: String,
    /// The display name.
    pub display_name: String,
    /// The version.
    pub version: String,
    /// The current status.
    pub status: BundleStatus,
    /// The source path.
    pub source_path: String,
}

impl BundleStatusEntry {
    /// Create an entry from a bundle.
    pub fn from_bundle(bundle: &GhidraBundle) -> Self {
        Self {
            symbolic_name: bundle.symbolic_name.clone(),
            display_name: bundle.display_name.clone(),
            version: bundle.version.clone(),
            status: bundle.status,
            source_path: bundle.source_path.display().to_string(),
        }
    }

    /// Get the cell value for a column.
    pub fn get_cell_value(&self, column: usize) -> String {
        match column {
            BundleStatusColumns::SYMBOLIC_NAME => self.symbolic_name.clone(),
            BundleStatusColumns::DISPLAY_NAME => self.display_name.clone(),
            BundleStatusColumns::VERSION => self.version.clone(),
            BundleStatusColumns::STATUS => format!("{:?}", self.status),
            BundleStatusColumns::SOURCE_PATH => self.source_path.clone(),
            _ => String::new(),
        }
    }
}

impl BundleStatusTableModel {
    /// Create a new table model.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            sort_column: BundleStatusColumns::SYMBOLIC_NAME,
            sort_ascending: true,
        }
    }

    /// Create a model from bundles.
    pub fn from_bundles(bundles: &[GhidraBundle]) -> Self {
        let entries = bundles.iter().map(BundleStatusEntry::from_bundle).collect();
        Self {
            entries,
            sort_column: BundleStatusColumns::SYMBOLIC_NAME,
            sort_ascending: true,
        }
    }

    /// Number of rows.
    pub fn row_count(&self) -> usize {
        self.entries.len()
    }

    /// Number of columns.
    pub fn column_count(&self) -> usize {
        BundleStatusColumns::HEADERS.len()
    }

    /// Get column header.
    pub fn column_name(&self, col: usize) -> &str {
        BundleStatusColumns::HEADERS.get(col).unwrap_or(&"")
    }

    /// Get cell value.
    pub fn get_cell_value(&self, row: usize, col: usize) -> Option<String> {
        self.entries.get(row).map(|e| e.get_cell_value(col))
    }

    /// Get the entry for a row.
    pub fn get_entry(&self, row: usize) -> Option<&BundleStatusEntry> {
        self.entries.get(row)
    }

    /// Set the sort column and direction.
    pub fn sort_by(&mut self, column: usize, ascending: bool) {
        self.sort_column = column;
        self.sort_ascending = ascending;

        let col = self.sort_column;
        let asc = self.sort_ascending;

        self.entries.sort_by(|a, b| {
            let va = a.get_cell_value(col);
            let vb = b.get_cell_value(col);
            if asc {
                va.cmp(&vb)
            } else {
                vb.cmp(&va)
            }
        });
    }

    /// Add an entry.
    pub fn add_entry(&mut self, entry: BundleStatusEntry) {
        self.entries.push(entry);
    }

    /// Remove all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Filter entries by status.
    pub fn filter_by_status(&self, status: BundleStatus) -> Vec<&BundleStatusEntry> {
        self.entries.iter().filter(|e| e.status == status).collect()
    }

    /// Search entries by name.
    pub fn search_by_name(&self, query: &str) -> Vec<&BundleStatusEntry> {
        let query_lower = query.to_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                e.display_name.to_lowercase().contains(&query_lower)
                    || e.symbolic_name.to_lowercase().contains(&query_lower)
            })
            .collect()
    }
}

impl Default for BundleStatusTableModel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bundle(name: &str) -> GhidraBundle {
        let mut b = GhidraBundle::new(name, name, "1.0.0", format!("/tmp/{}.jar", name));
        b.status = BundleStatus::Active;
        b
    }

    #[test]
    fn test_table_model_empty() {
        let model = BundleStatusTableModel::new();
        assert_eq!(model.row_count(), 0);
        assert_eq!(model.column_count(), 5);
    }

    #[test]
    fn test_table_model_from_bundles() {
        let bundles = vec![make_bundle("a"), make_bundle("b")];
        let model = BundleStatusTableModel::from_bundles(&bundles);
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_table_model_cell_values() {
        let bundles = vec![make_bundle("test")];
        let model = BundleStatusTableModel::from_bundles(&bundles);
        assert_eq!(model.get_cell_value(0, 0), Some("test".to_string()));
        assert_eq!(model.get_cell_value(0, 2), Some("1.0.0".to_string()));
    }

    #[test]
    fn test_table_model_sort() {
        let bundles = vec![make_bundle("z"), make_bundle("a"), make_bundle("m")];
        let mut model = BundleStatusTableModel::from_bundles(&bundles);
        model.sort_by(BundleStatusColumns::SYMBOLIC_NAME, true);
        assert_eq!(model.get_cell_value(0, 0), Some("a".to_string()));
        assert_eq!(model.get_cell_value(2, 0), Some("z".to_string()));
    }

    #[test]
    fn test_table_model_search() {
        let bundles = vec![make_bundle("alpha"), make_bundle("beta")];
        let model = BundleStatusTableModel::from_bundles(&bundles);
        let results = model.search_by_name("alp");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].display_name, "alpha");
    }

    #[test]
    fn test_bundle_status_entry_from_bundle() {
        let bundle = make_bundle("test");
        let entry = BundleStatusEntry::from_bundle(&bundle);
        assert_eq!(entry.symbolic_name, "test");
        assert_eq!(entry.status, BundleStatus::Active);
    }
}
