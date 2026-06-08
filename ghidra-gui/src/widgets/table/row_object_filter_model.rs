//! Row-object filter model trait.
//!
//! Port of Ghidra's `RowObjectFilterModel<ROW_OBJECT>` interface. Extends
//! the base table model with filtering capabilities, mapping between model
//! indices (full data) and view indices (filtered data).

use super::table_filter::TableFilter;

/// Extension of [`RowObjectTableModel`](super::RowObjectTableModel) that
/// supports filtering rows via a [`TableFilter`].
///
/// Implementors maintain a mapping between "model rows" (the full, unfiltered
/// data set) and "view rows" (the rows currently visible after filtering).
pub trait RowObjectFilterModel<ROW_OBJECT: 'static>: super::RowObjectTableModel<ROW_OBJECT> {
    /// Sets the active table filter. Passing `None` clears the filter.
    fn set_table_filter(&mut self, filter: Option<Box<dyn TableFilter<ROW_OBJECT>>>);

    /// Returns a reference to the current filter, if any.
    fn table_filter(&self) -> Option<&dyn TableFilter<ROW_OBJECT>>;

    /// Returns `true` if a filter is currently active.
    fn is_filtered(&self) -> bool {
        self.table_filter().is_some()
    }

    /// Returns the total number of rows before filtering.
    fn unfiltered_row_count(&self) -> usize;

    /// Returns all row objects before filtering.
    fn unfiltered_data(&self) -> Vec<&ROW_OBJECT>;

    /// Translates a view row index to a model row index.
    fn get_model_row(&self, view_row: usize) -> usize;

    /// Translates a model row index to a view row index.
    /// Returns `None` if the model row is filtered out.
    fn get_view_row(&self, model_row: usize) -> Option<usize>;

    /// Returns the view index of the given row object.
    fn get_view_index(&self, row_object: &ROW_OBJECT) -> Option<usize>;

    /// Returns the model index of the given row object.
    fn get_model_index(&self, row_object: &ROW_OBJECT) -> Option<usize>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::widgets::table::row_object_table_model::RowObjectTableModel;
    use crate::widgets::table::table_filter::{AcceptAllFilter, TextContainsFilter};

    struct MockFilterModel {
        all_data: Vec<String>,
        filter: Option<Box<dyn TableFilter<String>>>,
        view_indices: Vec<usize>,
    }

    impl MockFilterModel {
        fn new(data: Vec<String>) -> Self {
            let view_indices = (0..data.len()).collect();
            Self {
                all_data: data,
                filter: None,
                view_indices,
            }
        }

        fn rebuild_view(&mut self) {
            if let Some(ref filter) = self.filter {
                self.view_indices = self
                    .all_data
                    .iter()
                    .enumerate()
                    .filter(|(_, item)| filter.accepts_row(item))
                    .map(|(i, _)| i)
                    .collect();
            } else {
                self.view_indices = (0..self.all_data.len()).collect();
            }
        }
    }

    impl super::super::RowObjectTableModel<String> for MockFilterModel {
        fn name(&self) -> &str {
            "MockFilterModel"
        }
        fn column_count(&self) -> usize {
            1
        }
        fn column_name(&self, _index: usize) -> String {
            "Name".to_string()
        }
        fn row_count(&self) -> usize {
            self.view_indices.len()
        }
        fn get_row_object(&self, view_row: usize) -> Option<&String> {
            self.view_indices
                .get(view_row)
                .and_then(|&idx| self.all_data.get(idx))
        }
        fn get_row_index(&self, row_object: &String) -> Option<usize> {
            let model_idx = self.all_data.iter().position(|s| s == row_object)?;
            self.view_indices.iter().position(|&i| i == model_idx)
        }
        fn model_data(&self) -> Vec<&String> {
            self.view_indices
                .iter()
                .filter_map(|&i| self.all_data.get(i))
                .collect()
        }
        fn get_column_value_for_row(&self, row: &String, _column: usize) -> Box<dyn std::any::Any> {
            Box::new(row.clone())
        }
    }

    impl RowObjectFilterModel<String> for MockFilterModel {
        fn set_table_filter(&mut self, filter: Option<Box<dyn TableFilter<String>>>) {
            self.filter = filter;
            self.rebuild_view();
        }
        fn table_filter(&self) -> Option<&dyn TableFilter<String>> {
            self.filter.as_deref()
        }
        fn unfiltered_row_count(&self) -> usize {
            self.all_data.len()
        }
        fn unfiltered_data(&self) -> Vec<&String> {
            self.all_data.iter().collect()
        }
        fn get_model_row(&self, view_row: usize) -> usize {
            self.view_indices[view_row]
        }
        fn get_view_row(&self, model_row: usize) -> Option<usize> {
            self.view_indices.iter().position(|&i| i == model_row)
        }
        fn get_view_index(&self, row_object: &String) -> Option<usize> {
            let model_idx = self.all_data.iter().position(|s| s == row_object)?;
            self.view_indices.iter().position(|&i| i == model_idx)
        }
        fn get_model_index(&self, row_object: &String) -> Option<usize> {
            self.all_data.iter().position(|s| s == row_object)
        }
    }

    #[test]
    fn test_unfiltered() {
        let model = MockFilterModel::new(vec!["a".into(), "b".into(), "c".into()]);
        assert_eq!(model.row_count(), 3);
        assert!(!model.is_filtered());
        assert_eq!(model.unfiltered_row_count(), 3);
    }

    #[test]
    fn test_filtered() {
        let mut model =
            MockFilterModel::new(vec!["apple".into(), "banana".into(), "avocado".into()]);
        model.set_table_filter(Some(Box::new(TextContainsFilter::new("a"))));
        assert!(model.is_filtered());
        assert_eq!(model.row_count(), 3); // all contain 'a'
        assert_eq!(model.unfiltered_row_count(), 3);
    }

    #[test]
    fn test_filtered_reduces_rows() {
        let mut model =
            MockFilterModel::new(vec!["apple".into(), "banana".into(), "cherry".into()]);
        model.set_table_filter(Some(Box::new(TextContainsFilter::new("b"))));
        assert_eq!(model.row_count(), 1); // only banana
        assert_eq!(model.get_model_row(0), 1); // model index of banana
    }

    #[test]
    fn test_clear_filter() {
        let mut model = MockFilterModel::new(vec!["x".into(), "y".into()]);
        model.set_table_filter(Some(Box::new(TextContainsFilter::new("x"))));
        assert_eq!(model.row_count(), 1);
        model.set_table_filter(None);
        assert_eq!(model.row_count(), 2);
        assert!(!model.is_filtered());
    }

    #[test]
    fn test_view_model_row_mapping() {
        let mut model =
            MockFilterModel::new(vec!["a".into(), "b".into(), "c".into(), "b2".into()]);
        model.set_table_filter(Some(Box::new(TextContainsFilter::new("b"))));
        // view 0 -> model 1 ("banana"), view 1 -> model 3 ("b2")
        assert_eq!(model.get_model_row(0), 1);
        assert_eq!(model.get_model_row(1), 3);
        assert_eq!(model.get_view_row(0), None); // "a" filtered out
        assert_eq!(model.get_view_row(1), Some(0));
    }

    #[test]
    fn test_accept_all_filter() {
        let mut model = MockFilterModel::new(vec!["a".into(), "b".into()]);
        model.set_table_filter(Some(Box::new(AcceptAllFilter)));
        assert!(model.is_filtered());
        assert_eq!(model.row_count(), 2);
    }
}
