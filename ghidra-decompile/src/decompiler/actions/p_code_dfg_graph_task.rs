//! Port of `PCodeDfgGraphTask`.
use std::collections::HashMap;
/// Struct porting `PCodeDfgGraphTask`.
#[derive(Debug, Clone)]
pub struct PCodeDfgGraphTask {
    /// hfunction
    pub hfunction: String,
    /// graph
    pub graph: String,
}
impl PCodeDfgGraphTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for PCodeDfgGraphTask {
    fn default() -> Self {
        Self {
            hfunction: String::new(),
            graph: String::new()
        }


}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_p_code_dfg_graph_task_new() { let _ = PCodeDfgGraphTask::new(); }
}
