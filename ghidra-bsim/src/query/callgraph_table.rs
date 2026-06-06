//! Port of `CallgraphTable` from `ghidra.features.bsim.query.client.tables`.
//!
//! The `callgraphtable` SQL table stores caller-callee relationships between
//! functions in the BSim database. Each row contains a source function ID
//! and a destination function ID, forming a directed edge in the call graph.

use std::collections::HashMap;

/// A single row from the `callgraphtable` SQL table.
///
/// Ports `CallgraphTable.CallgraphRow`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct CallgraphRow {
    /// The source function ID (caller).
    pub src: i64,
    /// The destination function ID (callee).
    pub dest: i64,
}

impl CallgraphRow {
    /// Create a new callgraph row.
    pub fn new(src: i64, dest: i64) -> Self {
        Self { src, dest }
    }
}

/// The `callgraphtable` SQL table in the BSim database.
///
/// Ports `ghidra.features.bsim.query.client.tables.CallgraphTable`.
/// Manages the storage and retrieval of function call graph edges.
#[derive(Debug, Clone)]
pub struct CallgraphTable {
    /// The SQL table name.
    pub table_name: String,
    /// Cached edges indexed by source function ID.
    edges_by_src: HashMap<i64, Vec<CallgraphRow>>,
    /// All cached edges.
    all_edges: Vec<CallgraphRow>,
    /// Number of insert operations.
    insert_count: u64,
}

impl CallgraphTable {
    /// Create a new CallgraphTable.
    pub fn new() -> Self {
        Self::default()
    }

    /// The CREATE TABLE SQL for callgraphtable.
    pub fn create_table_sql() -> &'static str {
        "CREATE TABLE callgraphtable (src BIGINT, dest BIGINT, PRIMARY KEY (src, dest))"
    }

    /// The SELECT SQL for edges by source.
    pub fn select_by_src_sql() -> &'static str {
        "SELECT src, dest FROM callgraphtable WHERE src = $1"
    }

    /// The INSERT SQL for a new edge.
    pub fn insert_sql() -> &'static str {
        "INSERT INTO callgraphtable (src, dest) VALUES($1, $2)"
    }

    /// Cache a callgraph edge.
    pub fn cache_edge(&mut self, row: CallgraphRow) {
        self.edges_by_src
            .entry(row.src)
            .or_default()
            .push(row.clone());
        self.all_edges.push(row);
    }

    /// Get all callees for a given source function ID.
    pub fn get_callees(&self, src: i64) -> Option<&Vec<CallgraphRow>> {
        self.edges_by_src.get(&src)
    }

    /// Get all cached edges.
    pub fn all_edges(&self) -> &[CallgraphRow] {
        &self.all_edges
    }

    /// Get total number of cached edges.
    pub fn edge_count(&self) -> usize {
        self.all_edges.len()
    }

    /// Record an insert operation.
    pub fn record_insert(&mut self) {
        self.insert_count += 1;
    }

    /// Get the number of inserts performed.
    pub fn insert_count(&self) -> u64 {
        self.insert_count
    }

    /// Extract a `CallgraphRow` from column values.
    pub fn extract_callgraph_row(values: &HashMap<String, String>) -> Option<CallgraphRow> {
        let src = values.get("src")?.parse().ok()?;
        let dest = values.get("dest")?.parse().ok()?;
        Some(CallgraphRow { src, dest })
    }

    /// Clear all cached edges.
    pub fn clear_cache(&mut self) {
        self.edges_by_src.clear();
        self.all_edges.clear();
    }
}

impl Default for CallgraphTable {
    fn default() -> Self {
        Self {
            table_name: "callgraphtable".to_string(),
            edges_by_src: HashMap::new(),
            all_edges: Vec::new(),
            insert_count: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_callgraph_row_new() {
        let row = CallgraphRow::new(1, 2);
        assert_eq!(row.src, 1);
        assert_eq!(row.dest, 2);
    }

    #[test]
    fn test_callgraph_table_sql() {
        let sql = CallgraphTable::create_table_sql();
        assert!(sql.contains("callgraphtable"));
        assert!(sql.contains("PRIMARY KEY (src, dest)"));

        let select = CallgraphTable::select_by_src_sql();
        assert!(select.contains("WHERE src = $1"));

        let insert = CallgraphTable::insert_sql();
        assert!(insert.contains("INSERT INTO callgraphtable"));
    }

    #[test]
    fn test_callgraph_table_cache() {
        let mut table = CallgraphTable::new();

        table.cache_edge(CallgraphRow::new(1, 2));
        table.cache_edge(CallgraphRow::new(1, 3));
        table.cache_edge(CallgraphRow::new(2, 4));

        assert_eq!(table.edge_count(), 3);

        let callees_of_1 = table.get_callees(1).unwrap();
        assert_eq!(callees_of_1.len(), 2);
        assert!(callees_of_1.iter().any(|e| e.dest == 2));
        assert!(callees_of_1.iter().any(|e| e.dest == 3));

        let callees_of_2 = table.get_callees(2).unwrap();
        assert_eq!(callees_of_2.len(), 1);
        assert_eq!(callees_of_2[0].dest, 4);

        assert!(table.get_callees(99).is_none());
    }

    #[test]
    fn test_callgraph_table_extract() {
        let mut values = HashMap::new();
        values.insert("src".to_string(), "10".to_string());
        values.insert("dest".to_string(), "20".to_string());

        let row = CallgraphTable::extract_callgraph_row(&values).unwrap();
        assert_eq!(row.src, 10);
        assert_eq!(row.dest, 20);
    }

    #[test]
    fn test_callgraph_table_clear() {
        let mut table = CallgraphTable::new();
        table.cache_edge(CallgraphRow::new(1, 2));
        assert_eq!(table.edge_count(), 1);
        table.clear_cache();
        assert_eq!(table.edge_count(), 0);
    }

    #[test]
    fn test_callgraph_row_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(CallgraphRow::new(1, 2));
        set.insert(CallgraphRow::new(1, 2)); // duplicate
        set.insert(CallgraphRow::new(1, 3));
        assert_eq!(set.len(), 2);
    }
}
