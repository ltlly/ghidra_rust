//! Panel components for data graph vertex display.
//!
//! Ported from Ghidra's `datagraph.data.graph.panel` Java package.

/// Display mode for data columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnDisplayMode {
    /// Compact mode: fewer columns, compressed display.
    Compact,
    /// Expanded mode: all columns visible.
    Expanded,
}

impl Default for ColumnDisplayMode {
    fn default() -> Self { Self::Compact }
}

/// A row in the data vertex table.
#[derive(Debug, Clone)]
pub struct DataRowObject {
    /// The offset within the data structure.
    pub offset: usize,
    /// The field name.
    pub field_name: String,
    /// The data type.
    pub data_type: String,
    /// The value (as string).
    pub value: String,
    /// Indentation level (for nested structures).
    pub indent_level: usize,
    /// Whether this row has children that can be expanded.
    pub has_children: bool,
}

impl DataRowObject {
    pub fn new(offset: usize, field_name: String, data_type: String, value: String) -> Self {
        Self {
            offset,
            field_name,
            data_type,
            value,
            indent_level: 0,
            has_children: false,
        }
    }
}

/// Cache for data row objects.
#[derive(Debug, Default)]
pub struct DataRowObjectCache {
    rows: Vec<DataRowObject>,
}

impl DataRowObjectCache {
    pub fn new() -> Self { Self::default() }
    pub fn add(&mut self, row: DataRowObject) { self.rows.push(row); }
    pub fn get(&self, index: usize) -> Option<&DataRowObject> { self.rows.get(index) }
    pub fn len(&self) -> usize { self.rows.len() }
    pub fn is_empty(&self) -> bool { self.rows.is_empty() }
    pub fn clear(&mut self) { self.rows.clear(); }
}

/// Sort comparator for data component paths.
pub fn compare_component_paths(a: &[usize], b: &[usize]) -> std::cmp::Ordering {
    a.cmp(b)
}

/// Exploring a data structure's children.
#[derive(Debug, Clone)]
pub struct OpenDataChildren {
    /// Parent row index.
    pub parent_index: usize,
    /// Child rows.
    pub children: Vec<DataRowObject>,
}

impl OpenDataChildren {
    pub fn new(parent_index: usize) -> Self {
        Self { parent_index, children: Vec::new() }
    }

    pub fn add_child(&mut self, child: DataRowObject) {
        self.children.push(child);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_row_object() {
        let r = DataRowObject::new(0, "field".into(), "int32".into(), "42".into());
        assert_eq!(r.offset, 0);
        assert_eq!(r.field_name, "field");
    }

    #[test]
    fn test_cache() {
        let mut cache = DataRowObjectCache::new();
        assert!(cache.is_empty());
        cache.add(DataRowObject::new(0, "a".into(), "int".into(), "1".into()));
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_compare_paths() {
        assert_eq!(compare_component_paths(&[1, 2], &[1, 3]), std::cmp::Ordering::Less);
        assert_eq!(compare_component_paths(&[1, 2], &[1, 2]), std::cmp::Ordering::Equal);
    }
}
