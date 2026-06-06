//! Port of `PCodeCfgGraphTask`.
use std::collections::HashMap;
/// Struct porting `PCodeCfgGraphTask`.
#[derive(Debug, Clone)]
pub struct PCodeCfgGraphTask {
    _phantom: std::marker::PhantomData<()>,
}
impl PCodeCfgGraphTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for PCodeCfgGraphTask {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_p_code_cfg_graph_task_new() { let _ = PCodeCfgGraphTask::new(); }
}
