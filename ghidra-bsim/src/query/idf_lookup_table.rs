//! Port of `IdfLookupTable` from `ghidra.features.bsim.query.client.tables`.
//!
//! The `idftable` SQL table stores IDF lookup values for BSim signature
//! features. Provides fast lookup of inverse document frequency values
//! used in LSH vector computation.

use std::collections::HashMap;

/// A single IDF lookup entry.
#[derive(Debug, Clone, Default)]
pub struct IdfEntry {
    /// The feature/token identifier.
    pub token_id: i32,
    /// The IDF value (log(total_docs / docs_with_token)).
    pub idf_value: f64,
    /// Number of documents containing this token.
    pub document_count: i64,
    /// Total number of documents when this IDF was computed.
    pub total_documents: i64,
}

/// The IDF lookup table for BSim features.
///
/// Ports `ghidra.features.bsim.query.client.tables.IdfLookupTable`.
#[derive(Debug, Clone)]
pub struct IdfLookupTable {
    /// Table name.
    pub table_name: String,
    /// Cached IDF entries by token ID.
    entries: HashMap<i32, IdfEntry>,
    /// Total document count.
    total_docs: i64,
}

impl IdfLookupTable {
    /// Create a new IdfLookupTable.
    pub fn new() -> Self {
        Self::default()
    }

    /// CREATE TABLE SQL.
    pub fn create_table_sql() -> &'static str {
        "CREATE TABLE idftable (tokenid INTEGER PRIMARY KEY, idf DOUBLE PRECISION, doccount BIGINT, totaldocs BIGINT)"
    }

    /// Cache an IDF entry.
    pub fn cache_entry(&mut self, entry: IdfEntry) {
        if entry.total_documents > self.total_docs {
            self.total_docs = entry.total_documents;
        }
        self.entries.insert(entry.token_id, entry);
    }

    /// Get the IDF value for a token.
    pub fn get_idf(&self, token_id: i32) -> Option<f64> {
        self.entries.get(&token_id).map(|e| e.idf_value)
    }

    /// Get the full entry for a token.
    pub fn get_entry(&self, token_id: i32) -> Option<&IdfEntry> {
        self.entries.get(&token_id)
    }

    /// Get total document count.
    pub fn total_documents(&self) -> i64 {
        self.total_docs
    }

    /// Get number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all cached entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.total_docs = 0;
    }
}

impl Default for IdfLookupTable {
    fn default() -> Self {
        Self {
            table_name: "idftable".to_string(),
            entries: HashMap::new(),
            total_docs: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_idf_lookup_default() {
        let table = IdfLookupTable::new();
        assert!(table.is_empty());
        assert_eq!(table.total_documents(), 0);
    }

    #[test]
    fn test_idf_lookup_cache() {
        let mut table = IdfLookupTable::new();
        table.cache_entry(IdfEntry {
            token_id: 1,
            idf_value: 2.5,
            document_count: 10,
            total_documents: 1000,
        });
        table.cache_entry(IdfEntry {
            token_id: 2,
            idf_value: 1.0,
            document_count: 500,
            total_documents: 1000,
        });

        assert_eq!(table.len(), 2);
        assert_eq!(table.get_idf(1), Some(2.5));
        assert_eq!(table.total_documents(), 1000);
    }

    #[test]
    fn test_idf_lookup_sql() {
        let sql = IdfLookupTable::create_table_sql();
        assert!(sql.contains("idftable"));
        assert!(sql.contains("tokenid INTEGER PRIMARY KEY"));
    }
}
