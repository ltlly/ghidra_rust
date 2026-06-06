//! Port of `MoveViewToViewSpacePointAnimatorFunctionGraphJob`.
use std::collections::HashMap;
/// Struct porting `MoveViewToViewSpacePointAnimatorFunctionGraphJob`.
#[derive(Debug, Clone)]
pub struct MoveViewToViewSpacePointAnimatorFunctionGraphJob {
    _phantom: std::marker::PhantomData<()>,
}
impl MoveViewToViewSpacePointAnimatorFunctionGraphJob {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MoveViewToViewSpacePointAnimatorFunctionGraphJob {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_move_view_to_view_space_point_animator_function_graph_job_new() { let _ = MoveViewToViewSpacePointAnimatorFunctionGraphJob::new(); }
}
