//! Extended GUI model types ported from Java.
//!
//! Ported from the Debugger module's `gui/model` package. Provides
//! the data model for the object tree and path table views in the
//! debugger GUI (non-GUI data structures only).

use std::collections::BTreeMap;

/// A row in the object tree model.
#[derive(Debug, Clone)]
pub struct ObjectTreeRow {
    /// The object path.
    pub path: Vec<String>,
    /// Display name for this row.
    pub display_name: String,
    /// The object type/schema name.
    pub type_name: String,
    /// Whether this row has children.
    pub has_children: bool,
    /// Whether this row is expanded in the tree.
    pub expanded: bool,
    /// The snap at which this object exists.
    pub snap: i64,
}

impl ObjectTreeRow {
    /// Create a new tree row.
    pub fn new(
        path: Vec<String>,
        display_name: impl Into<String>,
        type_name: impl Into<String>,
        snap: i64,
    ) -> Self {
        Self {
            path,
            display_name: display_name.into(),
            type_name: type_name.into(),
            has_children: false,
            expanded: false,
            snap,
        }
    }
}

/// A column in the model table.
#[derive(Debug, Clone)]
pub struct ModelColumn {
    /// Column name.
    pub name: String,
    /// Column type hint.
    pub column_type: ModelColumnType,
    /// Whether this column is editable.
    pub editable: bool,
    /// Column width hint in pixels.
    pub width_hint: i32,
}

/// Type of a model column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelColumnType {
    /// Text/string column.
    Text,
    /// Integer column.
    Integer,
    /// Boolean column.
    Boolean,
    /// Hexadecimal display.
    Hex,
    /// Custom format.
    Custom,
}

/// A value entry in the object model.
#[derive(Debug, Clone)]
pub struct ModelValueEntry {
    /// Key for this value.
    pub key: String,
    /// The value (as a display string).
    pub value: String,
    /// The value type.
    pub value_type: ModelValueType,
    /// Whether the value has been modified.
    pub modified: bool,
    /// The snap at which this value was recorded.
    pub snap: i64,
}

/// Type of a model value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelValueType {
    /// Primitive value (string, int, etc.).
    Primitive,
    /// Reference to another object.
    Reference,
    /// A collection (array, list).
    Collection,
    /// A map/struct.
    Map,
    /// Null/undefined.
    Null,
}

/// The complete data model for the object tree panel.
#[derive(Debug, Default)]
pub struct ObjectTreeModel {
    /// Root rows.
    pub roots: Vec<ObjectTreeRow>,
    /// Children of each path.
    children: BTreeMap<Vec<String>, Vec<ObjectTreeRow>>,
    /// Columns to display.
    pub columns: Vec<ModelColumn>,
}

impl ObjectTreeModel {
    /// Create a new empty model.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a root row.
    pub fn add_root(&mut self, row: ObjectTreeRow) {
        self.roots.push(row);
    }

    /// Set children for a given parent path.
    pub fn set_children(&mut self, parent_path: Vec<String>, children: Vec<ObjectTreeRow>) {
        self.children.insert(parent_path, children);
    }

    /// Get children for a given parent path.
    pub fn get_children(&self, parent_path: &[String]) -> &[ObjectTreeRow] {
        self.children
            .get(parent_path)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Get the total number of rows in the model.
    pub fn total_rows(&self) -> usize {
        let mut count = self.roots.len();
        for children in self.children.values() {
            count += children.len();
        }
        count
    }
}

/// The path model for displaying object value paths.
#[derive(Debug, Default)]
pub struct PathModel {
    /// Rows in the path model.
    pub rows: Vec<PathModelRow>,
}

/// A row in the path model.
#[derive(Debug, Clone)]
pub struct PathModelRow {
    /// The value entry.
    pub entry: ModelValueEntry,
    /// Indentation level.
    pub depth: u32,
    /// Whether this is a container that can be expanded.
    pub expandable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_tree_row() {
        let row = ObjectTreeRow::new(
            vec!["root".into(), "process1".into()],
            "process1",
            "Process",
            0,
        );
        assert_eq!(row.path.len(), 2);
        assert_eq!(row.display_name, "process1");
    }

    #[test]
    fn test_object_tree_model() {
        let mut model = ObjectTreeModel::new();
        model.add_root(ObjectTreeRow::new(vec!["root".into()], "Root", "Root", 0));

        let children = vec![
            ObjectTreeRow::new(vec!["root".into(), "proc1".into()], "proc1", "Process", 0),
        ];
        model.set_children(vec!["root".into()], children);

        assert_eq!(model.roots.len(), 1);
        assert_eq!(model.get_children(&["root".into()]).len(), 1);
        assert_eq!(model.total_rows(), 2);
    }

    #[test]
    fn test_model_value_entry() {
        let entry = ModelValueEntry {
            key: "RAX".into(),
            value: "0x12345678".into(),
            value_type: ModelValueType::Primitive,
            modified: false,
            snap: 0,
        };
        assert_eq!(entry.value_type, ModelValueType::Primitive);
    }
}
