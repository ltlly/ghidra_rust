//! Port of `FilterVerticesJob`.
use std::collections::HashMap;
/// Struct porting `FilterVerticesJob`.
#[derive(Debug, Clone)]
pub struct FilterVerticesJob {
    _phantom: std::marker::PhantomData<()>,
}
impl FilterVerticesJob {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FilterVerticesJob {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_filter_vertices_job_new() { let _ = FilterVerticesJob::new(); }
}
