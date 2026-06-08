//! Table sort state.
//!
//! Port of Ghidra's `TableSortState` class. Represents the full multi-column
//! sort state of a table.

use super::column_sort_state::{ColumnSortState, SortDirection};

/// Represents the complete sort state of a table: which columns are sorted,
/// in what direction, and in what priority order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TableSortState {
    column_sort_states: Vec<ColumnSortState>,
}

impl TableSortState {
    /// Create an unsorted state (no columns sorted).
    pub fn unsorted() -> Self {
        Self {
            column_sort_states: Vec::new(),
        }
    }

    /// Create a default ascending sort state for a single column.
    pub fn default_sort(column_model_index: usize) -> Self {
        Self {
            column_sort_states: vec![ColumnSortState::new(
                column_model_index,
                SortDirection::Ascending,
                1,
            )],
        }
    }

    /// Create a single-column sort state with the given direction.
    pub fn single_column(column_model_index: usize, ascending: bool) -> Self {
        let dir = if ascending {
            SortDirection::Ascending
        } else {
            SortDirection::Descending
        };
        Self {
            column_sort_states: vec![ColumnSortState::new(column_model_index, dir, 1)],
        }
    }

    /// Create a sort state from a list of column sort states.
    ///
    /// # Panics
    /// Panics if there are duplicate column indices or duplicate sort orders.
    pub fn from_states(states: Vec<ColumnSortState>) -> Self {
        let mut sort_orders = Vec::new();
        let mut column_indices = Vec::new();
        for state in &states {
            let order = state.sort_order();
            assert!(
                !sort_orders.contains(&order),
                "Duplicate sort order: {}",
                order
            );
            let col = state.column_model_index();
            assert!(
                !column_indices.contains(&col),
                "Duplicate column index: {}",
                col
            );
            sort_orders.push(order);
            column_indices.push(col);
        }
        Self {
            column_sort_states: states,
        }
    }

    /// Returns the number of sorted columns.
    pub fn sorted_column_count(&self) -> usize {
        self.column_sort_states.len()
    }

    /// Returns `true` if no columns are sorted.
    pub fn is_unsorted(&self) -> bool {
        self.column_sort_states.is_empty()
    }

    /// Returns the sort state for the given column, or `None` if unsorted.
    pub fn get_column_sort_state(&self, column_model_index: usize) -> Option<&ColumnSortState> {
        self.column_sort_states
            .iter()
            .find(|s| s.column_model_index() == column_model_index)
    }

    /// Returns all column sort states.
    pub fn all_sort_states(&self) -> &[ColumnSortState] {
        &self.column_sort_states
    }

    /// Iterate over the column sort states.
    pub fn iter(&self) -> impl Iterator<Item = &ColumnSortState> {
        self.column_sort_states.iter()
    }
}

impl Default for TableSortState {
    fn default() -> Self {
        Self::unsorted()
    }
}

impl<'a> IntoIterator for &'a TableSortState {
    type Item = &'a ColumnSortState;
    type IntoIter = std::slice::Iter<'a, ColumnSortState>;

    fn into_iter(self) -> Self::IntoIter {
        self.column_sort_states.iter()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unsorted() {
        let state = TableSortState::unsorted();
        assert!(state.is_unsorted());
        assert_eq!(state.sorted_column_count(), 0);
    }

    #[test]
    fn test_default_sort() {
        let state = TableSortState::default_sort(2);
        assert!(!state.is_unsorted());
        assert_eq!(state.sorted_column_count(), 1);
        let col = state.get_column_sort_state(2).unwrap();
        assert!(col.is_ascending());
        assert_eq!(col.sort_order(), 1);
    }

    #[test]
    fn test_single_column_descending() {
        let state = TableSortState::single_column(0, false);
        let col = state.get_column_sort_state(0).unwrap();
        assert!(!col.is_ascending());
    }

    #[test]
    fn test_multi_column() {
        let states = vec![
            ColumnSortState::new(0, SortDirection::Ascending, 1),
            ColumnSortState::new(2, SortDirection::Descending, 2),
        ];
        let ts = TableSortState::from_states(states);
        assert_eq!(ts.sorted_column_count(), 2);
        assert!(ts.get_column_sort_state(0).unwrap().is_ascending());
        assert!(!ts.get_column_sort_state(2).unwrap().is_ascending());
    }

    #[test]
    #[should_panic(expected = "Duplicate column index")]
    fn test_duplicate_column_panics() {
        let states = vec![
            ColumnSortState::new(0, SortDirection::Ascending, 1),
            ColumnSortState::new(0, SortDirection::Descending, 2),
        ];
        TableSortState::from_states(states);
    }

    #[test]
    #[should_panic(expected = "Duplicate sort order")]
    fn test_duplicate_order_panics() {
        let states = vec![
            ColumnSortState::new(0, SortDirection::Ascending, 1),
            ColumnSortState::new(1, SortDirection::Ascending, 1),
        ];
        TableSortState::from_states(states);
    }

    #[test]
    fn test_get_missing_column() {
        let state = TableSortState::default_sort(0);
        assert!(state.get_column_sort_state(5).is_none());
    }

    #[test]
    fn test_iterator() {
        let state = TableSortState::default_sort(3);
        let collected: Vec<_> = state.iter().collect();
        assert_eq!(collected.len(), 1);
        assert_eq!(collected[0].column_model_index(), 3);
    }

    #[test]
    fn test_into_iterator() {
        let state = TableSortState::default_sort(1);
        let mut count = 0;
        for _ in &state {
            count += 1;
        }
        assert_eq!(count, 1);
    }

    #[test]
    fn test_equality() {
        let a = TableSortState::default_sort(0);
        let b = TableSortState::default_sort(0);
        let c = TableSortState::default_sort(1);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_all_sort_states() {
        let state = TableSortState::unsorted();
        assert!(state.all_sort_states().is_empty());
    }
}
