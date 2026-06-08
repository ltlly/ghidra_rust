//! Column sort state.
//!
//! Port of Ghidra's `ColumnSortState` class. Represents the sort direction
//! and sort order for a single column in a multi-column sort.

use serde::{Deserialize, Serialize};

/// Sort direction for a column.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SortDirection {
    Ascending,
    Descending,
}

impl SortDirection {
    pub fn is_ascending(self) -> bool {
        self == SortDirection::Ascending
    }

    /// Flip the direction.
    pub fn flip(self) -> Self {
        match self {
            SortDirection::Ascending => SortDirection::Descending,
            SortDirection::Descending => SortDirection::Ascending,
        }
    }

    /// Parse from a string ("ascending" / "descending").
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ascending" => Some(SortDirection::Ascending),
            "descending" => Some(SortDirection::Descending),
            _ => None,
        }
    }
}

impl std::fmt::Display for SortDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SortDirection::Ascending => write!(f, "ascending"),
            SortDirection::Descending => write!(f, "descending"),
        }
    }
}

/// Sort state for a single column.
///
/// Contains the column model index, the sort direction, and the sort order
/// (1-based, for multi-column sorts).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ColumnSortState {
    column_model_index: usize,
    sort_direction: SortDirection,
    /// 1-based sort order within a multi-column sort.
    sort_order: usize,
}

impl ColumnSortState {
    pub fn new(column_model_index: usize, sort_direction: SortDirection, sort_order: usize) -> Self {
        Self {
            column_model_index,
            sort_direction,
            sort_order,
        }
    }

    pub fn column_model_index(&self) -> usize {
        self.column_model_index
    }

    pub fn sort_direction(&self) -> SortDirection {
        self.sort_direction
    }

    pub fn is_ascending(&self) -> bool {
        self.sort_direction.is_ascending()
    }

    pub fn sort_order(&self) -> usize {
        self.sort_order
    }

    pub fn set_sort_order(&mut self, order: usize) {
        self.sort_order = order;
    }

    /// Create a new state with the direction flipped.
    pub fn create_flip_state(&self) -> Self {
        Self {
            column_model_index: self.column_model_index,
            sort_direction: self.sort_direction.flip(),
            sort_order: self.sort_order,
        }
    }
}

impl std::fmt::Display for ColumnSortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ColumnSortState[column:{},direction:{},order:{}]",
            self.column_model_index, self.sort_direction, self.sort_order
        )
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let state = ColumnSortState::new(2, SortDirection::Ascending, 1);
        assert_eq!(state.column_model_index(), 2);
        assert!(state.is_ascending());
        assert_eq!(state.sort_order(), 1);
    }

    #[test]
    fn test_sort_direction_flip() {
        assert_eq!(
            SortDirection::Ascending.flip(),
            SortDirection::Descending
        );
        assert_eq!(
            SortDirection::Descending.flip(),
            SortDirection::Ascending
        );
    }

    #[test]
    fn test_create_flip_state() {
        let state = ColumnSortState::new(0, SortDirection::Ascending, 1);
        let flipped = state.create_flip_state();
        assert_eq!(flipped.column_model_index(), 0);
        assert!(!flipped.is_ascending());
        assert_eq!(flipped.sort_order(), 1);
    }

    #[test]
    fn test_sort_direction_from_str() {
        assert_eq!(SortDirection::from_str("ascending"), Some(SortDirection::Ascending));
        assert_eq!(SortDirection::from_str("DESCENDING"), Some(SortDirection::Descending));
        assert_eq!(SortDirection::from_str("unknown"), None);
    }

    #[test]
    fn test_display() {
        let state = ColumnSortState::new(3, SortDirection::Descending, 2);
        let s = format!("{}", state);
        assert!(s.contains("column:3"));
        assert!(s.contains("descending"));
        assert!(s.contains("order:2"));
    }

    #[test]
    fn test_set_sort_order() {
        let mut state = ColumnSortState::new(0, SortDirection::Ascending, 1);
        state.set_sort_order(3);
        assert_eq!(state.sort_order(), 3);
    }

    #[test]
    fn test_equality() {
        let a = ColumnSortState::new(1, SortDirection::Ascending, 1);
        let b = ColumnSortState::new(1, SortDirection::Ascending, 1);
        let c = ColumnSortState::new(1, SortDirection::Descending, 1);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn test_sort_direction_display() {
        assert_eq!(format!("{}", SortDirection::Ascending), "ascending");
        assert_eq!(format!("{}", SortDirection::Descending), "descending");
    }
}
