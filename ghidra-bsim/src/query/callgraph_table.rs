//! Port of `CallgraphTable`.
use std::collections::HashMap;
/// Struct porting `CallgraphTable`.
#[derive(Debug, Clone)]
pub struct CallgraphTable {
    /// src.
    pub src: i64,
    /// dest.
    pub dest: i64,
}

impl CallgraphTable {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for CallgraphTable {
    fn default() -> Self {
        Self {
            src: 0,
            dest: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_callgraph_table_new() { let _ = CallgraphTable::new(); }
}
