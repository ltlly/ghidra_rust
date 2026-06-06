//! Port of `ExeToCategoryTable` from `ghidra.features.bsim.query.client.tables`.
//!
//! The `exetocategorytable` SQL table maps executables to categories.
//! Each row associates an executable (by its exetable row ID) with a
//! category type and category value, enabling classification and filtering
//! of executables in BSim queries.

use std::collections::HashMap;

/// A single row from the `exetocategorytable`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExeCategoryRow {
    /// The executable's row ID in exetable.
    pub id_exe: i64,
    /// The category type ID.
    pub id_type: i64,
    /// The category value ID.
    pub id_category: i64,
}

impl ExeCategoryRow {
    /// Create a new category row.
    pub fn new(id_exe: i64, id_type: i64, id_category: i64) -> Self {
        Self {
            id_exe,
            id_type,
            id_category,
        }
    }
}

/// The `exetocategorytable` SQL table.
///
/// Ports `ghidra.features.bsim.query.client.tables.ExeToCategoryTable`.
#[derive(Debug, Clone)]
pub struct ExeToCategoryTable {
    /// Table name.
    pub table_name: String,
    /// Cached rows indexed by executable ID.
    by_exe: HashMap<i64, Vec<ExeCategoryRow>>,
    /// All cached rows.
    all_rows: Vec<ExeCategoryRow>,
}

impl ExeToCategoryTable {
    /// Create a new ExeToCategoryTable.
    pub fn new() -> Self {
        Self::default()
    }

    /// CREATE TABLE SQL.
    pub fn create_table_sql() -> &'static str {
        "CREATE TABLE exetocategorytable (id_exe INTEGER, id_type INTEGER, id_category INTEGER, \
         PRIMARY KEY (id_exe, id_type, id_category))"
    }

    /// INSERT SQL.
    pub fn insert_sql() -> &'static str {
        "INSERT INTO exetocategorytable (id_exe, id_type, id_category) VALUES($1, $2, $3)"
    }

    /// SELECT by executable ID.
    pub fn select_by_exe_sql() -> &'static str {
        "SELECT id_exe, id_type, id_category FROM exetocategorytable WHERE id_exe = $1"
    }

    /// Cache a row.
    pub fn cache_row(&mut self, row: ExeCategoryRow) {
        self.by_exe
            .entry(row.id_exe)
            .or_default()
            .push(row.clone());
        self.all_rows.push(row);
    }

    /// Get categories for an executable.
    pub fn get_categories(&self, exe_id: i64) -> Option<&Vec<ExeCategoryRow>> {
        self.by_exe.get(&exe_id)
    }

    /// Get all cached rows.
    pub fn all_rows(&self) -> &[ExeCategoryRow] {
        &self.all_rows
    }

    /// Get the number of cached rows.
    pub fn len(&self) -> usize {
        self.all_rows.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.all_rows.is_empty()
    }

    /// Clear all cached rows.
    pub fn clear(&mut self) {
        self.by_exe.clear();
        self.all_rows.clear();
    }
}

impl Default for ExeToCategoryTable {
    fn default() -> Self {
        Self {
            table_name: "exetocategorytable".to_string(),
            by_exe: HashMap::new(),
            all_rows: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exe_category_row() {
        let row = ExeCategoryRow::new(1, 2, 3);
        assert_eq!(row.id_exe, 1);
        assert_eq!(row.id_type, 2);
        assert_eq!(row.id_category, 3);
    }

    #[test]
    fn test_exe_to_category_table() {
        let mut table = ExeToCategoryTable::new();

        table.cache_row(ExeCategoryRow::new(1, 10, 100));
        table.cache_row(ExeCategoryRow::new(1, 20, 200));
        table.cache_row(ExeCategoryRow::new(2, 10, 100));

        assert_eq!(table.len(), 3);

        let cats = table.get_categories(1).unwrap();
        assert_eq!(cats.len(), 2);
        assert!(cats.iter().any(|r| r.id_type == 10));
        assert!(cats.iter().any(|r| r.id_type == 20));

        assert!(table.get_categories(99).is_none());
    }

    #[test]
    fn test_exe_to_category_sql() {
        let sql = ExeToCategoryTable::create_table_sql();
        assert!(sql.contains("exetocategorytable"));
        assert!(sql.contains("PRIMARY KEY (id_exe, id_type, id_category)"));
    }

    #[test]
    fn test_exe_to_category_clear() {
        let mut table = ExeToCategoryTable::new();
        table.cache_row(ExeCategoryRow::new(1, 1, 1));
        assert!(!table.is_empty());
        table.clear();
        assert!(table.is_empty());
    }
}
