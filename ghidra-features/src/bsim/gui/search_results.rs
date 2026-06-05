//! BSim search results display types.
//!
//! Ports `ghidra.features.bsim.gui.search.results` types.

/// Search settings for BSim results display.
#[derive(Debug, Clone)]
pub struct BSimSearchSettings {
    /// Minimum similarity threshold.
    pub min_similarity: f64,
    /// Maximum results to show.
    pub max_results: usize,
    /// Whether to show only significant matches.
    pub significant_only: bool,
    /// Active filter types.
    pub filters: Vec<String>,
}

impl Default for BSimSearchSettings {
    fn default() -> Self {
        Self {
            min_similarity: 0.7,
            max_results: 500,
            significant_only: false,
            filters: Vec::new(),
        }
    }
}

/// A row in the BSim search results table.
#[derive(Debug, Clone)]
pub struct BSimResultRowObject {
    /// The function name.
    pub function_name: String,
    /// The function address.
    pub address: String,
    /// Similarity score.
    pub similarity: f64,
    /// The matching executable name.
    pub match_exe: String,
    /// The matching function name in BSim.
    pub match_function: String,
    /// The matching address.
    pub match_address: String,
    /// Function signature.
    pub signature: Option<String>,
}

impl BSimResultRowObject {
    pub fn get_column_value(&self, col: usize) -> String {
        match col {
            0 => self.function_name.clone(),
            1 => self.address.clone(),
            2 => format!("{:.4}", self.similarity),
            3 => self.match_exe.clone(),
            4 => self.match_function.clone(),
            5 => self.match_address.clone(),
            _ => String::new(),
        }
    }
}

/// Apply results table model for BSim function comparisons.
#[derive(Debug, Clone, Default)]
pub struct BSimApplyResultsTableModel {
    /// Results to display.
    pub results: Vec<BSimResultRowObject>,
}

impl BSimApplyResultsTableModel {
    pub fn new() -> Self { Self::default() }
    pub fn add_result(&mut self, result: BSimResultRowObject) {
        self.results.push(result);
    }
    pub fn row_count(&self) -> usize { self.results.len() }
    pub fn get_row(&self, index: usize) -> Option<&BSimResultRowObject> {
        self.results.get(index)
    }
}

/// Exception for function comparison failures.
#[derive(Debug, Clone)]
pub struct FunctionComparisonException {
    pub message: String,
}

impl FunctionComparisonException {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { message: msg.into() }
    }
}

impl std::fmt::Display for FunctionComparisonException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Function comparison error: {}", self.message)
    }
}

impl std::error::Error for FunctionComparisonException {}

/// Search info display data.
#[derive(Debug, Clone)]
pub struct BSimSearchInfoDisplay {
    /// Server name.
    pub server_name: String,
    /// Database name.
    pub database_name: String,
    /// Number of functions searched.
    pub functions_searched: usize,
    /// Number of results found.
    pub results_found: usize,
    /// Search duration in milliseconds.
    pub duration_ms: u64,
}

impl BSimSearchInfoDisplay {
    pub fn summary(&self) -> String {
        format!(
            "Searched {} functions in {} on {} ({} results, {}ms)",
            self.functions_searched, self.database_name, self.server_name,
            self.results_found, self.duration_ms
        )
    }
}

/// Namespace display settings.
#[derive(Debug, Clone)]
pub struct ShowNamespaceSettings {
    /// Whether to show namespace prefixes.
    pub show_namespace: bool,
    /// The separator between namespace and function name.
    pub separator: String,
}

impl Default for ShowNamespaceSettings {
    fn default() -> Self {
        Self {
            show_namespace: false,
            separator: "::".to_string(),
        }
    }
}

/// Mapper from BSimResultRowObject to program address.
pub struct BSimResultRowObjectToAddressTableRowMapper;

impl BSimResultRowObjectToAddressTableRowMapper {
    pub fn get_address(row: &BSimResultRowObject) -> &str {
        &row.address
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_settings() {
        let settings = BSimSearchSettings::default();
        assert_eq!(settings.min_similarity, 0.7);
        assert_eq!(settings.max_results, 500);
    }

    #[test]
    fn test_result_row() {
        let row = BSimResultRowObject {
            function_name: "main".into(),
            address: "0x1000".into(),
            similarity: 0.95,
            match_exe: "other.exe".into(),
            match_function: "main".into(),
            match_address: "0x2000".into(),
            signature: None,
        };
        assert_eq!(row.get_column_value(0), "main");
        assert_eq!(row.get_column_value(2), "0.9500");
    }

    #[test]
    fn test_apply_model() {
        let mut model = BSimApplyResultsTableModel::new();
        assert_eq!(model.row_count(), 0);
        model.add_result(BSimResultRowObject {
            function_name: "f".into(),
            address: "0x0".into(),
            similarity: 0.8,
            match_exe: "e".into(),
            match_function: "f2".into(),
            match_address: "0x1".into(),
            signature: None,
        });
        assert_eq!(model.row_count(), 1);
    }

    #[test]
    fn test_search_info_display() {
        let info = BSimSearchInfoDisplay {
            server_name: "localhost".into(),
            database_name: "bsim_db".into(),
            functions_searched: 100,
            results_found: 25,
            duration_ms: 1500,
        };
        let s = info.summary();
        assert!(s.contains("100"));
        assert!(s.contains("25"));
    }

    #[test]
    fn test_comparison_exception() {
        let e = FunctionComparisonException::new("timeout");
        assert!(e.to_string().contains("timeout"));
    }
}
