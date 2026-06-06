//! Port of `EnsureAreaVisibleAnimatorFunctionGraphJob`.
use std::collections::HashMap;
/// Struct porting `EnsureAreaVisibleAnimatorFunctionGraphJob`.
#[derive(Debug, Clone)]
pub struct EnsureAreaVisibleAnimatorFunctionGraphJob {
    _phantom: std::marker::PhantomData<()>,
}
impl EnsureAreaVisibleAnimatorFunctionGraphJob {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for EnsureAreaVisibleAnimatorFunctionGraphJob {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ensure_area_visible_animator_function_graph_job_new() { let _ = EnsureAreaVisibleAnimatorFunctionGraphJob::new(); }
}
