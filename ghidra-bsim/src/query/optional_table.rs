//! Port of `OptionalTable` from `ghidra.features.bsim.query.client.tables`.
//!
//! The `optionaltable` SQL table stores optional metadata fields for functions
//! in the BSim database. These are additional attributes that can be queried
//! and filtered on but are not required for core similarity matching.

use std::collections::HashMap;

/// A single optional field value.
#[derive(Debug, Clone, Default)]
pub struct OptionalFieldEntry {
    /// The function description ID this entry belongs to.
    pub func_id: i64,
    /// The optional field name.
    pub field_name: String,
    /// The optional field value.
    pub field_value: String,
}

/// The `optionaltable` SQL table for optional function metadata.
///
/// Ports `ghidra.features.bsim.query.client.tables.OptionalTable`.
#[derive(Debug, Clone)]
pub struct OptionalTable {
    /// Table name.
    pub table_name: String,
    /// Cached entries indexed by function ID.
    by_func_id: HashMap<i64, Vec<OptionalFieldEntry>>,
    /// Cached entries indexed by field name.
    by_field_name: HashMap<String, Vec<OptionalFieldEntry>>,
}

impl OptionalTable {
    /// Create a new OptionalTable.
    pub fn new() -> Self {
        Self::default()
    }

    /// CREATE TABLE SQL.
    pub fn create_table_sql() -> &'static str {
        "CREATE TABLE optionaltable (id_func BIGINT, field_name TEXT, field_value TEXT, \
         PRIMARY KEY (id_func, field_name))"
    }

    /// INSERT SQL.
    pub fn insert_sql() -> &'static str {
        "INSERT INTO optionaltable (id_func, field_name, field_value) VALUES($1, $2, $3) \
         ON CONFLICT (id_func, field_name) DO UPDATE SET field_value = $3"
    }

    /// SELECT by function ID.
    pub fn select_by_func_sql() -> &'static str {
        "SELECT field_name, field_value FROM optionaltable WHERE id_func = $1"
    }

    /// SELECT functions by field name and value.
    pub fn select_by_field_sql() -> &'static str {
        "SELECT id_func FROM optionaltable WHERE field_name = $1 AND field_value = $2"
    }

    /// Cache an entry.
    pub fn cache_entry(&mut self, entry: OptionalFieldEntry) {
        self.by_func_id
            .entry(entry.func_id)
            .or_default()
            .push(entry.clone());
        self.by_field_name
            .entry(entry.field_name.clone())
            .or_default()
            .push(entry);
    }

    /// Get all optional fields for a function.
    pub fn get_fields_for_func(&self, func_id: i64) -> Option<&Vec<OptionalFieldEntry>> {
        self.by_func_id.get(&func_id)
    }

    /// Get all entries with a specific field name.
    pub fn get_entries_by_field(&self, field_name: &str) -> Option<&Vec<OptionalFieldEntry>> {
        self.by_field_name.get(field_name)
    }

    /// Get a specific optional field value for a function.
    pub fn get_value(&self, func_id: i64, field_name: &str) -> Option<&str> {
        self.by_func_id.get(&func_id)?.iter()
            .find(|e| e.field_name == field_name)
            .map(|e| e.field_value.as_str())
    }

    /// Get the number of cached entries.
    pub fn entry_count(&self) -> usize {
        self.by_func_id.values().map(|v| v.len()).sum()
    }

    /// Clear all cached entries.
    pub fn clear(&mut self) {
        self.by_func_id.clear();
        self.by_field_name.clear();
    }
}

impl Default for OptionalTable {
    fn default() -> Self {
        Self {
            table_name: "optionaltable".to_string(),
            by_func_id: HashMap::new(),
            by_field_name: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_optional_table_default() {
        let table = OptionalTable::new();
        assert_eq!(table.table_name, "optionaltable");
        assert_eq!(table.entry_count(), 0);
    }

    #[test]
    fn test_optional_table_cache() {
        let mut table = OptionalTable::new();

        table.cache_entry(OptionalFieldEntry {
            func_id: 1,
            field_name: "signature".to_string(),
            field_value: "int main(int, char**)".to_string(),
        });
        table.cache_entry(OptionalFieldEntry {
            func_id: 1,
            field_name: "library".to_string(),
            field_value: "libc".to_string(),
        });
        table.cache_entry(OptionalFieldEntry {
            func_id: 2,
            field_name: "signature".to_string(),
            field_value: "void init()".to_string(),
        });

        assert_eq!(table.entry_count(), 3);

        let fields = table.get_fields_for_func(1).unwrap();
        assert_eq!(fields.len(), 2);

        assert_eq!(table.get_value(1, "signature"), Some("int main(int, char**)"));
        assert_eq!(table.get_value(1, "library"), Some("libc"));
        assert_eq!(table.get_value(1, "missing"), None);

        let by_field = table.get_entries_by_field("signature").unwrap();
        assert_eq!(by_field.len(), 2);
    }

    #[test]
    fn test_optional_table_sql() {
        let sql = OptionalTable::create_table_sql();
        assert!(sql.contains("optionaltable"));
        assert!(sql.contains("id_func BIGINT"));
    }

    #[test]
    fn test_optional_table_clear() {
        let mut table = OptionalTable::new();
        table.cache_entry(OptionalFieldEntry {
            func_id: 1,
            field_name: "x".to_string(),
            field_value: "y".to_string(),
        });
        table.clear();
        assert_eq!(table.entry_count(), 0);
    }
}
