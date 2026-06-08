//! Row-object table model trait.
//!
//! Port of Ghidra's `RowObjectTableModel<T>` interface. In the Java version
//! this extends `javax.swing.table.TableModel`. In Rust we define a trait that
//! provides the same row-object semantics without Swing dependencies.

use std::any::Any;

/// A table model where each row is backed by a typed row object.
///
/// Implementors supply column metadata, row data, and per-cell values.
/// The trait is generic over the row object type `T`.
pub trait RowObjectTableModel<T: 'static> {
    /// Returns the model name (for display/debugging).
    fn name(&self) -> &str;

    /// Returns the number of columns in the model.
    fn column_count(&self) -> usize;

    /// Returns the display name of the column at the given index.
    fn column_name(&self, index: usize) -> String;

    /// Returns the number of visible rows.
    fn row_count(&self) -> usize;

    /// Returns a reference to the row object at the given view row index.
    ///
    /// Returns `None` if the index is out of bounds.
    fn get_row_object(&self, view_row: usize) -> Option<&T>;

    /// Returns the view row index for the given row object, or `None` if not
    /// currently visible (e.g. filtered out).
    fn get_row_index(&self, row_object: &T) -> Option<usize>;

    /// Returns a snapshot of all currently-visible row objects.
    fn model_data(&self) -> Vec<&T>;

    /// Returns the cell value at the given view row and column as a
    /// type-erased `dyn Any`. Implementors may return `String`, `i64`, etc.
    fn get_column_value_for_row(&self, row: &T, column: usize) -> Box<dyn Any>;

    /// Returns the cell value at the given (row, column) position.
    ///
    /// The default implementation delegates to [`get_row_object`] and
    /// [`get_column_value_for_row`].
    fn get_value_at(&self, row: usize, column: usize) -> Option<Box<dyn Any>> {
        let row_obj = self.get_row_object(row)?;
        Some(self.get_column_value_for_row(row_obj, column))
    }

    /// Returns the preferred column width for the given column, or `None` for
    /// the default.
    fn preferred_column_width(&self, _column: usize) -> Option<f32> {
        None
    }

    /// Returns the minimum column width for the given column, or `None`.
    fn min_column_width(&self, _column: usize) -> Option<f32> {
        None
    }

    /// Returns the maximum column width for the given column, or `None`.
    fn max_column_width(&self, _column: usize) -> Option<f32> {
        None
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct SimpleModel {
        items: Vec<String>,
    }

    impl SimpleModel {
        fn new(items: Vec<String>) -> Self {
            Self { items }
        }
    }

    impl RowObjectTableModel<String> for SimpleModel {
        fn name(&self) -> &str {
            "SimpleModel"
        }
        fn column_count(&self) -> usize {
            1
        }
        fn column_name(&self, _index: usize) -> String {
            "Value".to_string()
        }
        fn row_count(&self) -> usize {
            self.items.len()
        }
        fn get_row_object(&self, view_row: usize) -> Option<&String> {
            self.items.get(view_row)
        }
        fn get_row_index(&self, row_object: &String) -> Option<usize> {
            self.items.iter().position(|s| s == row_object)
        }
        fn model_data(&self) -> Vec<&String> {
            self.items.iter().collect()
        }
        fn get_column_value_for_row(&self, row: &String, _column: usize) -> Box<dyn Any> {
            Box::new(row.clone())
        }
    }

    #[test]
    fn test_basic_model() {
        let model = SimpleModel::new(vec!["a".into(), "b".into(), "c".into()]);
        assert_eq!(model.row_count(), 3);
        assert_eq!(model.column_count(), 1);
        assert_eq!(model.name(), "SimpleModel");
    }

    #[test]
    fn test_get_row_object() {
        let model = SimpleModel::new(vec!["x".into(), "y".into()]);
        assert_eq!(model.get_row_object(0), Some(&"x".to_string()));
        assert_eq!(model.get_row_object(1), Some(&"y".to_string()));
        assert_eq!(model.get_row_object(2), None);
    }

    #[test]
    fn test_get_row_index() {
        let model = SimpleModel::new(vec!["a".into(), "b".into()]);
        assert_eq!(model.get_row_index(&"a".to_string()), Some(0));
        assert_eq!(model.get_row_index(&"b".to_string()), Some(1));
        assert_eq!(model.get_row_index(&"z".to_string()), None);
    }

    #[test]
    fn test_get_value_at() {
        let model = SimpleModel::new(vec!["hello".into()]);
        let val = model.get_value_at(0, 0).unwrap();
        assert_eq!(val.downcast_ref::<String>(), Some(&"hello".to_string()));
    }

    #[test]
    fn test_model_data() {
        let model = SimpleModel::new(vec!["a".into(), "b".into()]);
        let data = model.model_data();
        assert_eq!(data.len(), 2);
        assert_eq!(data[0], &"a".to_string());
    }

    #[test]
    fn test_column_width_defaults() {
        let model = SimpleModel::new(vec![]);
        assert_eq!(model.preferred_column_width(0), None);
        assert_eq!(model.min_column_width(0), None);
        assert_eq!(model.max_column_width(0), None);
    }
}
