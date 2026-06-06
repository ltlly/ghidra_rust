//! BSim overview panel types.
//!
//! Ports `ghidra.features.bsim.gui.overview` from Ghidra's Java source.

/// A row in the BSim overview table.
#[derive(Debug, Clone)]
pub struct BSimOverviewRowObject {
    /// Executable name.
    pub executable_name: String,
    /// Number of functions.
    pub function_count: usize,
    /// Architecture.
    pub architecture: String,
    /// Compiler.
    pub compiler: String,
    /// MD5 hash.
    pub md5: String,
    /// Whether the executable is in the current results.
    pub in_results: bool,
    /// Similarity score (if applicable).
    pub similarity: Option<f64>,
}

impl BSimOverviewRowObject {
    /// Create a new overview row.
    pub fn new(
        executable_name: impl Into<String>,
        function_count: usize,
        architecture: impl Into<String>,
    ) -> Self {
        Self {
            executable_name: executable_name.into(),
            function_count,
            architecture: architecture.into(),
            compiler: String::new(),
            md5: String::new(),
            in_results: false,
            similarity: None,
        }
    }
}

/// The overview model that holds the data for the overview table.
#[derive(Debug, Clone, Default)]
pub struct BSimOverviewModel {
    /// The rows in the overview.
    pub rows: Vec<BSimOverviewRowObject>,
}

impl BSimOverviewModel {
    /// Create a new empty overview model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the number of rows.
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Get a row by index.
    pub fn get_row(&self, index: usize) -> Option<&BSimOverviewRowObject> {
        self.rows.get(index)
    }

    /// Add a row.
    pub fn add_row(&mut self, row: BSimOverviewRowObject) {
        self.rows.push(row);
    }

    /// Clear all rows.
    pub fn clear(&mut self) {
        self.rows.clear();
    }

    /// Get total function count across all rows.
    pub fn total_function_count(&self) -> usize {
        self.rows.iter().map(|r| r.function_count).sum()
    }
}

/// Maps overview row objects to addresses for the address table.
#[derive(Debug, Clone, Default)]
pub struct BSimOverviewRowObjectToAddressTableRowMapper;

impl BSimOverviewRowObjectToAddressTableRowMapper {
    /// Map an overview row to an address (stub: returns 0).
    pub fn map(row: &BSimOverviewRowObject) -> u64 {
        // In a real implementation, this would map back to a program address.
        let _ = row;
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overview_row_new() {
        let row = BSimOverviewRowObject::new("test.exe", 100, "x86");
        assert_eq!(row.executable_name, "test.exe");
        assert_eq!(row.function_count, 100);
        assert_eq!(row.architecture, "x86");
    }

    #[test]
    fn test_overview_model() {
        let mut model = BSimOverviewModel::new();
        assert_eq!(model.row_count(), 0);

        model.add_row(BSimOverviewRowObject::new("exe1", 50, "x86"));
        model.add_row(BSimOverviewRowObject::new("exe2", 75, "ARM"));
        assert_eq!(model.row_count(), 2);
        assert_eq!(model.total_function_count(), 125);
    }

    #[test]
    fn test_overview_model_get_row() {
        let mut model = BSimOverviewModel::new();
        model.add_row(BSimOverviewRowObject::new("exe1", 50, "x86"));

        let row = model.get_row(0).unwrap();
        assert_eq!(row.executable_name, "exe1");

        assert!(model.get_row(1).is_none());
    }

    #[test]
    fn test_overview_model_clear() {
        let mut model = BSimOverviewModel::new();
        model.add_row(BSimOverviewRowObject::new("exe1", 50, "x86"));
        model.clear();
        assert_eq!(model.row_count(), 0);
    }
}
