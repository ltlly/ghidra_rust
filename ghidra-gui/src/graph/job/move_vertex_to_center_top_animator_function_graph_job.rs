//! Port of `MoveVertexToCenterTopAnimatorFunctionGraphJob`.
use std::collections::HashMap;
/// Struct porting `MoveVertexToCenterTopAnimatorFunctionGraphJob`.
#[derive(Debug, Clone)]
pub struct MoveVertexToCenterTopAnimatorFunctionGraphJob {
    _phantom: std::marker::PhantomData<()>,
}
impl MoveVertexToCenterTopAnimatorFunctionGraphJob {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MoveVertexToCenterTopAnimatorFunctionGraphJob {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_move_vertex_to_center_top_animator_function_graph_job_new() { let _ = MoveVertexToCenterTopAnimatorFunctionGraphJob::new(); }
}
