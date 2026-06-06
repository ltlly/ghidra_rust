//! Port of `MoveViewToLayoutSpacePointAnimatorFunctionGraphJob`.
use std::collections::HashMap;
/// Struct porting `MoveViewToLayoutSpacePointAnimatorFunctionGraphJob`.
#[derive(Debug, Clone)]
pub struct MoveViewToLayoutSpacePointAnimatorFunctionGraphJob {
    _phantom: std::marker::PhantomData<()>,
}
impl MoveViewToLayoutSpacePointAnimatorFunctionGraphJob {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MoveViewToLayoutSpacePointAnimatorFunctionGraphJob {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_move_view_to_layout_space_point_animator_function_graph_job_new() { let _ = MoveViewToLayoutSpacePointAnimatorFunctionGraphJob::new(); }
}
