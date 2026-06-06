//! Port of `MoveVertexToCenterAnimatorFunctionGraphJob`.
use std::collections::HashMap;
/// Struct porting `MoveVertexToCenterAnimatorFunctionGraphJob`.
#[derive(Debug, Clone)]
pub struct MoveVertexToCenterAnimatorFunctionGraphJob {
    _phantom: std::marker::PhantomData<()>,
}
impl MoveVertexToCenterAnimatorFunctionGraphJob {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MoveVertexToCenterAnimatorFunctionGraphJob {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_move_vertex_to_center_animator_function_graph_job_new() { let _ = MoveVertexToCenterAnimatorFunctionGraphJob::new(); }
}
