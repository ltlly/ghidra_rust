//! Port of `ExeToCategoryTable`.
use std::collections::HashMap;
/// Struct porting `ExeToCategoryTable`.
#[derive(Debug, Clone)]
pub struct ExeToCategoryTable {
    /// id_exe.
    pub id_exe: i64,
    /// id_type.
    pub id_type: i64,
    /// id_category.
    pub id_category: i64,
}

impl ExeToCategoryTable {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ExeToCategoryTable {
    fn default() -> Self {
        Self {
            id_exe: 0,
            id_type_: 0,
            id_category: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_exe_to_category_table_new() { let _ = ExeToCategoryTable::new(); }
}
