//! BSim overview panel types.
//!
//! Port of Ghidra's `ghidra.features.bsim.gui.overview` package.
//!
//! Provides data types for the BSim overview panel that shows a summary
//! of all executables in the database.

use super::BSimOverviewRow;

/// The overview model that holds the list of executables in the BSim database.
///
/// This model backs the overview table/grid that allows users to browse
/// the executables stored in a BSim database.
#[derive(Debug, Clone, Default)]
pub struct BSimOverviewModel {
    /// The list of executable overview rows.
    pub rows: Vec<BSimOverviewRow>,
    /// The currently selected row index.
    pub selected_index: Option<usize>,
    /// Filter string for the overview.
    pub filter: Option<String>,
}

impl BSimOverviewModel {
    /// Create a new empty overview model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an overview model from rows.
    pub fn from_rows(rows: Vec<BSimOverviewRow>) -> Self {
        Self {
            rows,
            selected_index: None,
            filter: None,
        }
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a row by index.
    pub fn get_row(&self, index: usize) -> Option<&BSimOverviewRow> {
        self.rows.get(index)
    }

    /// Add a row.
    pub fn add_row(&mut self, row: BSimOverviewRow) {
        self.rows.push(row);
    }

    /// Remove a row by index.
    pub fn remove_row(&mut self, index: usize) -> Option<BSimOverviewRow> {
        if index < self.rows.len() {
            Some(self.rows.remove(index))
        } else {
            None
        }
    }

    /// Select a row.
    pub fn select(&mut self, index: Option<usize>) {
        self.selected_index = index;
    }

    /// Get the currently selected row.
    pub fn selected_row(&self) -> Option<&BSimOverviewRow> {
        self.selected_index.and_then(|i| self.rows.get(i))
    }

    /// Set a filter on the model.
    pub fn set_filter(&mut self, filter: Option<String>) {
        self.filter = filter;
    }

    /// Get filtered rows.
    pub fn filtered_rows(&self) -> Vec<&BSimOverviewRow> {
        match &self.filter {
            Some(f) => {
                let lower = f.to_lowercase();
                self.rows
                    .iter()
                    .filter(|r| {
                        r.name.to_lowercase().contains(&lower)
                            || r.architecture.to_lowercase().contains(&lower)
                            || r.compiler.to_lowercase().contains(&lower)
                    })
                    .collect()
            }
            None => self.rows.iter().collect(),
        }
    }

    /// Sort rows by a column.
    pub fn sort_by(&mut self, column: OverviewColumn, ascending: bool) {
        match column {
            OverviewColumn::Name => {
                self.rows.sort_by(|a, b| {
                    let cmp = a.name.cmp(&b.name);
                    if ascending { cmp } else { cmp.reverse() }
                });
            }
            OverviewColumn::Architecture => {
                self.rows.sort_by(|a, b| {
                    let cmp = a.architecture.cmp(&b.architecture);
                    if ascending { cmp } else { cmp.reverse() }
                });
            }
            OverviewColumn::Compiler => {
                self.rows.sort_by(|a, b| {
                    let cmp = a.compiler.cmp(&b.compiler);
                    if ascending { cmp } else { cmp.reverse() }
                });
            }
            OverviewColumn::FunctionCount => {
                self.rows.sort_by(|a, b| {
                    let cmp = a.function_count.cmp(&b.function_count);
                    if ascending { cmp } else { cmp.reverse() }
                });
            }
            OverviewColumn::Md5 => {
                self.rows.sort_by(|a, b| {
                    let cmp = a.md5.cmp(&b.md5);
                    if ascending { cmp } else { cmp.reverse() }
                });
            }
            OverviewColumn::DateAdded => {
                self.rows.sort_by(|a, b| {
                    let cmp = a.date_added.cmp(&b.date_added);
                    if ascending { cmp } else { cmp.reverse() }
                });
            }
        }
    }
}

/// Columns in the BSim overview table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OverviewColumn {
    /// Executable name.
    Name,
    /// Architecture string.
    Architecture,
    /// Compiler name.
    Compiler,
    /// Number of functions.
    FunctionCount,
    /// MD5 hash.
    Md5,
    /// Date added.
    DateAdded,
}

/// A mapper that maps an overview row to an address table row.
///
/// Used to convert BSim overview data to the format needed by the
/// address table display.
#[derive(Debug, Clone)]
pub struct OverviewRowMapper {
    /// The column to use as the address source.
    pub address_column: OverviewColumn,
}

impl OverviewRowMapper {
    /// Create a new mapper.
    pub fn new(address_column: OverviewColumn) -> Self {
        Self { address_column }
    }

    /// Map a row to an address string.
    pub fn map_to_address<'a>(&self, row: &'a BSimOverviewRow) -> &'a str {
        match self.address_column {
            OverviewColumn::Name => &row.name,
            OverviewColumn::Architecture => &row.architecture,
            OverviewColumn::Compiler => &row.compiler,
            OverviewColumn::FunctionCount => "", // numeric, no address
            OverviewColumn::Md5 => &row.md5,
            OverviewColumn::DateAdded => &row.date_added,
        }
    }
}

/// Provider interface for the BSim overview panel.
///
/// Defines the operations available in the overview panel.
pub trait BSimOverviewProvider: std::fmt::Debug {
    /// Get the overview model.
    fn model(&self) -> &BSimOverviewModel;

    /// Get a mutable reference to the model.
    fn model_mut(&mut self) -> &mut BSimOverviewModel;

    /// Refresh the overview from the database.
    fn refresh(&mut self);

    /// Get the connection info.
    fn connection_info(&self) -> &str;

    /// Whether the provider is connected to a database.
    fn is_connected(&self) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_row(name: &str, arch: &str, compiler: &str, count: usize) -> BSimOverviewRow {
        BSimOverviewRow {
            name: name.to_string(),
            architecture: arch.to_string(),
            compiler: compiler.to_string(),
            function_count: count,
            md5: format!("md5_{}", name),
            date_added: "2024-01-01".to_string(),
        }
    }

    #[test]
    fn test_overview_model_new() {
        let model = BSimOverviewModel::new();
        assert_eq!(model.row_count(), 0);
        assert!(model.selected_index.is_none());
    }

    #[test]
    fn test_overview_model_from_rows() {
        let rows = vec![
            sample_row("libc", "x86:LE:64", "gcc", 1000),
            sample_row("libm", "x86:LE:64", "gcc", 500),
        ];
        let model = BSimOverviewModel::from_rows(rows);
        assert_eq!(model.row_count(), 2);
    }

    #[test]
    fn test_overview_model_select() {
        let rows = vec![
            sample_row("libc", "x86:LE:64", "gcc", 1000),
            sample_row("libm", "x86:LE:64", "gcc", 500),
        ];
        let mut model = BSimOverviewModel::from_rows(rows);
        model.select(Some(1));
        let selected = model.selected_row().unwrap();
        assert_eq!(selected.name, "libm");
    }

    #[test]
    fn test_overview_model_add_remove() {
        let mut model = BSimOverviewModel::new();
        model.add_row(sample_row("a", "x86", "gcc", 100));
        model.add_row(sample_row("b", "arm", "clang", 200));
        assert_eq!(model.row_count(), 2);
        let removed = model.remove_row(0).unwrap();
        assert_eq!(removed.name, "a");
        assert_eq!(model.row_count(), 1);
    }

    #[test]
    fn test_overview_model_remove_out_of_bounds() {
        let mut model = BSimOverviewModel::new();
        assert!(model.remove_row(0).is_none());
    }

    #[test]
    fn test_overview_model_filter() {
        let rows = vec![
            sample_row("libc.so", "x86:LE:64", "gcc", 1000),
            sample_row("libm.so", "x86:LE:64", "clang", 500),
            sample_row("libc.so", "arm:LE:32", "gcc", 800),
        ];
        let mut model = BSimOverviewModel::from_rows(rows);
        model.set_filter(Some("clang".to_string()));
        let filtered = model.filtered_rows();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].compiler, "clang");
    }

    #[test]
    fn test_overview_model_filter_case_insensitive() {
        let rows = vec![
            sample_row("LIBC", "x86", "GCC", 100),
        ];
        let mut model = BSimOverviewModel::from_rows(rows);
        model.set_filter(Some("libc".to_string()));
        assert_eq!(model.filtered_rows().len(), 1);
    }

    #[test]
    fn test_overview_model_sort_by_name() {
        let rows = vec![
            sample_row("zebra", "x86", "gcc", 100),
            sample_row("alpha", "x86", "gcc", 200),
            sample_row("middle", "x86", "gcc", 150),
        ];
        let mut model = BSimOverviewModel::from_rows(rows);
        model.sort_by(OverviewColumn::Name, true);
        assert_eq!(model.rows[0].name, "alpha");
        assert_eq!(model.rows[1].name, "middle");
        assert_eq!(model.rows[2].name, "zebra");
    }

    #[test]
    fn test_overview_model_sort_by_function_count_desc() {
        let rows = vec![
            sample_row("a", "x86", "gcc", 100),
            sample_row("b", "x86", "gcc", 300),
            sample_row("c", "x86", "gcc", 200),
        ];
        let mut model = BSimOverviewModel::from_rows(rows);
        model.sort_by(OverviewColumn::FunctionCount, false);
        assert_eq!(model.rows[0].function_count, 300);
        assert_eq!(model.rows[2].function_count, 100);
    }

    #[test]
    fn test_overview_row_mapper() {
        let row = sample_row("libc", "x86", "gcc", 1000);
        let mapper = OverviewRowMapper::new(OverviewColumn::Name);
        assert_eq!(mapper.map_to_address(&row), "libc");
    }

    #[test]
    fn test_overview_column_equality() {
        assert_eq!(OverviewColumn::Name, OverviewColumn::Name);
        assert_ne!(OverviewColumn::Name, OverviewColumn::Architecture);
    }
}
