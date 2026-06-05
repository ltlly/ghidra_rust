//! Row objects for the BSim overview table.
//!
//! Ports `ghidra.features.bsim.gui.overview.BSimOverviewRowObject`.

/// A row in the BSim overview table, representing a matched function.
#[derive(Debug, Clone)]
pub struct BSimOverviewRowObject {
    /// The function name in the current program.
    pub function_name: String,
    /// The function address (hex string).
    pub address: String,
    /// The name of the matching function in the BSim database.
    pub match_name: String,
    /// The similarity score.
    pub similarity: f64,
    /// The name of the matching executable.
    pub exe_name: String,
    /// The matching function's address in the remote executable.
    pub match_address: String,
    /// Whether this is a significant match.
    pub significant: bool,
}

impl BSimOverviewRowObject {
    /// Create a new overview row.
    pub fn new(
        function_name: impl Into<String>,
        address: impl Into<String>,
        match_name: impl Into<String>,
        similarity: f64,
    ) -> Self {
        Self {
            function_name: function_name.into(),
            address: address.into(),
            match_name: match_name.into(),
            similarity,
            exe_name: String::new(),
            match_address: String::new(),
            significant: similarity > 0.9,
        }
    }

    /// Get column value by index for table display.
    pub fn get_column_value(&self, column: usize) -> String {
        match column {
            0 => self.function_name.clone(),
            1 => self.address.clone(),
            2 => self.match_name.clone(),
            3 => format!("{:.4}", self.similarity),
            4 => self.exe_name.clone(),
            5 => self.match_address.clone(),
            _ => String::new(),
        }
    }
}

/// Mapper from BSimOverviewRowObject to program address for navigation.
pub struct BSimOverviewRowObjectToAddressTableRowMapper;

impl BSimOverviewRowObjectToAddressTableRowMapper {
    /// Get the address from a row object.
    pub fn get_address(row: &BSimOverviewRowObject) -> &str {
        &row.address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_overview_row() {
        let row = BSimOverviewRowObject::new("main", "0x1000", "main_clone", 0.95);
        assert_eq!(row.get_column_value(0), "main");
        assert_eq!(row.get_column_value(3), "0.9500");
        assert!(row.significant);
    }

    #[test]
    fn test_mapper() {
        let row = BSimOverviewRowObject::new("func", "0x2000", "other", 0.5);
        assert_eq!(BSimOverviewRowObjectToAddressTableRowMapper::get_address(&row), "0x2000");
    }
}
