//! Port of `RelayoutFunctionGraphJob`.
use std::collections::HashMap;
/// Struct porting `RelayoutFunctionGraphJob`.
#[derive(Debug, Clone)]
pub struct RelayoutFunctionGraphJob {
    _phantom: std::marker::PhantomData<()>,
}
impl RelayoutFunctionGraphJob {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RelayoutFunctionGraphJob {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_relayout_function_graph_job_new() { let _ = RelayoutFunctionGraphJob::new(); }
}
