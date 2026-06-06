//! Port of `CallgraphEntry`.
use std::collections::HashMap;
/// Struct porting `CallgraphEntry`.
#[derive(Debug, Clone)]
pub struct CallgraphEntry {
    _phantom: std::marker::PhantomData<()>,
}
impl CallgraphEntry {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for CallgraphEntry {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_callgraph_entry_new() { let _ = CallgraphEntry::new(); }
}
