//! Port of `FitGraphToViewJob`.
use std::collections::HashMap;
/// Struct porting `FitGraphToViewJob`.
#[derive(Debug, Clone)]
pub struct FitGraphToViewJob {
    _phantom: std::marker::PhantomData<()>,
}
impl FitGraphToViewJob {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FitGraphToViewJob {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_fit_graph_to_view_job_new() { let _ = FitGraphToViewJob::new(); }
}
