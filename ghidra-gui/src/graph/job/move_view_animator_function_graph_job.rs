//! Port of `MoveViewAnimatorFunctionGraphJob`.
use std::collections::HashMap;
/// Struct porting `MoveViewAnimatorFunctionGraphJob`.
#[derive(Debug, Clone)]
pub struct MoveViewAnimatorFunctionGraphJob {
    _phantom: std::marker::PhantomData<()>,
}
impl MoveViewAnimatorFunctionGraphJob {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MoveViewAnimatorFunctionGraphJob {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_move_view_animator_function_graph_job_new() { let _ = MoveViewAnimatorFunctionGraphJob::new(); }
}
