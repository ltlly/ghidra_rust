//! Port of `SQLStringTable`.
use std::collections::HashMap;
/// Struct porting `SQLStringTable`.
#[derive(Debug, Clone)]
pub struct SQLStringTable {
    /// id.
    pub id: i64,
    /// value.
    pub value: String,
    /// prev.
    pub prev: String,
    /// next.
    pub next: String,
}

impl SQLStringTable {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for SQLStringTable {
    fn default() -> Self {
        Self {
            id: 0,
            value: String::new(),
            prev: String::new(),
            next: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_sql_string_table_new() { let _ = SQLStringTable::new(); }
}
