//! Port of `DescriptionTable`.
use std::collections::HashMap;
/// Struct porting `DescriptionTable`.
#[derive(Debug, Clone)]
pub struct DescriptionTable {
    /// rowid.
    pub rowid: i64,
    /// func_name.
    pub func_name: String,
    /// id_exe.
    pub id_exe: i64,
    /// id_sig.
    pub id_sig: i64,
    /// addr.
    pub addr: i64,
    /// flags.
    pub flags: i32,
}

impl DescriptionTable {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for DescriptionTable {
    fn default() -> Self {
        Self {
            rowid: 0,
            func_name: String::new(),
            id_exe: 0,
            id_sig: 0,
            addr: 0,
            flags: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_description_table_new() { let _ = DescriptionTable::new(); }
}
