//! Abstract base table model.
//!
//! Port of Ghidra's `AbstractGTableModel<T>`. Provides a concrete
//! implementation of common [`RowObjectTableModel`] logic so that
//! implementors only need to supply data and column-value extraction.

use std::any::Any;

use super::row_object_table_model::RowObjectTableModel;

/// A base table model that implements common [`RowObjectTableModel`] methods.
///
/// Subtypes should set `data` and implement the abstract column methods.
pub struct AbstractGTableModel<T: 'static> {
    /// The model name.
    name: String,
    /// Column names.
    column_names: Vec<String>,
    /// The backing data.
    data: Vec<T>,
    /// Last selected objects (for selection persistence).
    last_selected: Vec<T>,
    /// Whether the model has been disposed.
    disposed: bool,
}

impl<T: 'static> AbstractGTableModel<T> {
    pub const WIDTH_UNDEFINED: f32 = -1.0;

    /// Create a new model with the given name and column names.
    pub fn new(name: impl Into<String>, column_names: Vec<String>) -> Self {
        Self {
            name: name.into(),
            column_names,
            data: Vec::new(),
            last_selected: Vec::new(),
            disposed: false,
        }
    }

    /// Replace the model data and return the old data.
    pub fn set_data(&mut self, data: Vec<T>) -> Vec<T> {
        std::mem::replace(&mut self.data, data)
    }

    /// Append a single row object.
    pub fn add(&mut self, item: T) {
        self.data.push(item);
    }

    /// Remove all data.
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Returns the last selected objects (for selection restoration).
    pub fn last_selected_objects(&self) -> &[T] {
        &self.last_selected
    }

    /// Sets the last selected objects.
    pub fn set_last_selected_objects(&mut self, objects: Vec<T>) {
        self.last_selected = objects;
    }

    /// Mark the model as disposed and clear all data.
    pub fn dispose(&mut self) {
        self.last_selected.clear();
        self.data.clear();
        self.disposed = true;
    }

    /// Returns `true` if the model has been disposed.
    pub fn is_disposed(&self) -> bool {
        self.disposed
    }

    /// Returns a reference to the underlying data.
    pub fn data(&self) -> &[T] {
        &self.data
    }

    /// Returns a mutable reference to the underlying data.
    pub fn data_mut(&mut self) -> &mut Vec<T> {
        &mut self.data
    }
}

impl<T: 'static> RowObjectTableModel<T> for AbstractGTableModel<T>
where
    T: Clone,
{
    fn name(&self) -> &str {
        &self.name
    }

    fn column_count(&self) -> usize {
        self.column_names.len()
    }

    fn column_name(&self, index: usize) -> String {
        self.column_names
            .get(index)
            .cloned()
            .unwrap_or_default()
    }

    fn row_count(&self) -> usize {
        self.data.len()
    }

    fn get_row_object(&self, view_row: usize) -> Option<&T> {
        self.data.get(view_row)
    }

    fn get_row_index(&self, _row_object: &T) -> Option<usize> {
        // Default: linear scan by pointer equality (not available without
        // PartialEq). Subtypes should override.
        None
    }

    fn model_data(&self) -> Vec<&T> {
        self.data.iter().collect()
    }

    fn get_column_value_for_row(&self, _row: &T, _column: usize) -> Box<dyn Any> {
        // Default: return None. Subtypes should override.
        Box::new(None::<String>)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq)]
    struct TestRow {
        name: String,
        value: i32,
    }

    fn make_model(rows: Vec<TestRow>) -> AbstractGTableModel<TestRow> {
        let mut model = AbstractGTableModel::new(
            "TestModel",
            vec!["Name".to_string(), "Value".to_string()],
        );
        model.set_data(rows);
        model
    }

    #[test]
    fn test_basic_properties() {
        let model = make_model(vec![]);
        assert_eq!(model.name(), "TestModel");
        assert_eq!(model.column_count(), 2);
        assert_eq!(model.column_name(0), "Name");
        assert_eq!(model.column_name(1), "Value");
        assert_eq!(model.row_count(), 0);
        assert!(!model.is_disposed());
    }

    #[test]
    fn test_data_operations() {
        let rows = vec![
            TestRow { name: "a".into(), value: 1 },
            TestRow { name: "b".into(), value: 2 },
        ];
        let model = make_model(rows);
        assert_eq!(model.row_count(), 2);
        assert_eq!(model.get_row_object(0).unwrap().name, "a");
        assert_eq!(model.get_row_object(1).unwrap().value, 2);
        assert!(model.get_row_object(2).is_none());
    }

    #[test]
    fn test_get_row_index_default() {
        let rows = vec![
            TestRow { name: "x".into(), value: 10 },
            TestRow { name: "y".into(), value: 20 },
        ];
        let model = make_model(rows);
        // Default impl returns None (subtypes should override)
        assert_eq!(
            model.get_row_index(&TestRow { name: "x".into(), value: 10 }),
            None
        );
    }

    #[test]
    fn test_add_and_clear() {
        let mut model = make_model(vec![]);
        model.add(TestRow { name: "a".into(), value: 1 });
        assert_eq!(model.row_count(), 1);
        model.clear();
        assert_eq!(model.row_count(), 0);
    }

    #[test]
    fn test_dispose() {
        let mut model = make_model(vec![TestRow { name: "a".into(), value: 1 }]);
        model.set_last_selected_objects(vec![TestRow { name: "a".into(), value: 1 }]);
        model.dispose();
        assert!(model.is_disposed());
        assert_eq!(model.row_count(), 0);
        assert!(model.last_selected_objects().is_empty());
    }

    #[test]
    fn test_selection_storage() {
        let mut model = make_model(vec![]);
        let sel = vec![TestRow { name: "a".into(), value: 1 }];
        model.set_last_selected_objects(sel.clone());
        assert_eq!(model.last_selected_objects().len(), 1);
        assert_eq!(model.last_selected_objects()[0].name, "a");
    }

    #[test]
    fn test_out_of_bounds_name() {
        let model = make_model(vec![]);
        assert_eq!(model.column_name(99), "");
    }

    #[test]
    fn test_model_data() {
        let rows = vec![
            TestRow { name: "a".into(), value: 1 },
            TestRow { name: "b".into(), value: 2 },
        ];
        let model = make_model(rows);
        let data = model.model_data();
        assert_eq!(data.len(), 2);
        assert_eq!(data[0].name, "a");
    }
}
