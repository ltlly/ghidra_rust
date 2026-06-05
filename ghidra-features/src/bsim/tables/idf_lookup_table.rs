//! IDF (Inverse Document Frequency) lookup table.
//!
//! Ports `ghidra.features.bsim.query.client.tables.IdfLookupTable`.

/// A row in the IDF lookup table.
#[derive(Debug, Clone)]
pub struct IdfLookupRow {
    /// Token ID.
    pub token_id: i32,
    /// The token name/label.
    pub token_name: String,
    /// IDF score for this token.
    pub idf_score: f64,
    /// Document frequency (number of functions containing this token).
    pub doc_frequency: i64,
}

/// The IDF lookup table.
#[derive(Debug, Default)]
pub struct IdfLookupTable {
    rows: Vec<IdfLookupRow>,
}

impl IdfLookupTable {
    /// Create a new empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a row.
    pub fn insert(&mut self, row: IdfLookupRow) {
        self.rows.push(row);
    }

    /// Look up IDF score by token ID.
    pub fn get_score(&self, token_id: i32) -> Option<f64> {
        self.rows
            .iter()
            .find(|r| r.token_id == token_id)
            .map(|r| r.idf_score)
    }

    /// Look up by token name.
    pub fn get_by_name(&self, name: &str) -> Option<&IdfLookupRow> {
        self.rows.iter().find(|r| r.token_name == name)
    }

    /// All rows.
    pub fn all_rows(&self) -> &[IdfLookupRow] {
        &self.rows
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Generate CREATE TABLE SQL.
    pub fn create_table_sql() -> &'static str {
        "CREATE TABLE IF NOT EXISTS idflookuptable (token_id INTEGER PRIMARY KEY, token_name VARCHAR(256), idf_score DOUBLE PRECISION, doc_frequency BIGINT)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idf_insert_and_lookup() {
        let mut table = IdfLookupTable::new();
        table.insert(IdfLookupRow {
            token_id: 1,
            token_name: "mov".to_string(),
            idf_score: 2.5,
            doc_frequency: 1000,
        });
        assert_eq!(table.len(), 1);
        assert_eq!(table.get_score(1), Some(2.5));
        assert!(table.get_by_name("mov").is_some());
        assert!(table.get_by_name("jmp").is_none());
    }
}
