//! Port of `ExeTable`.
use std::collections::HashMap;
/// Struct porting `ExeTable`.
#[derive(Debug, Clone)]
pub struct ExeTable {
    /// table_name.
    pub table_name: String,
    /// rowid.
    pub rowid: i64,
    /// md5.
    pub md5: String,
    /// exename.
    pub exename: String,
    /// arch_id.
    pub arch_id: i64,
    /// compiler_id.
    pub compiler_id: i64,
}

impl ExeTable {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ExeTable {
    fn default() -> Self {
        Self {
            table_name: String::new(),
            rowid: 0,
            md5: String::new(),
            exename: String::new(),
            arch_id: 0,
            compiler_id: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_exe_table_new() { let _ = ExeTable::new(); }
}
