//! Port of `PCodeCombinedGraphTask`.
use std::collections::HashMap;
/// Struct porting `PCodeCombinedGraphTask`.
#[derive(Debug, Clone)]
pub struct PCodeCombinedGraphTask {
    _phantom: std::marker::PhantomData<()>,
}
impl PCodeCombinedGraphTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for PCodeCombinedGraphTask {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_p_code_combined_graph_task_new() { let _ = PCodeCombinedGraphTask::new(); }
}
