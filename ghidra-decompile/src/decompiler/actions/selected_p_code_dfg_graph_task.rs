//! Port of `SelectedPCodeDfgGraphTask`.
use std::collections::HashMap;
/// Struct porting `SelectedPCodeDfgGraphTask`.
#[derive(Debug, Clone)]
pub struct SelectedPCodeDfgGraphTask {
    _phantom: std::marker::PhantomData<()>,
}
impl SelectedPCodeDfgGraphTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for SelectedPCodeDfgGraphTask {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_selected_p_code_dfg_graph_task_new() { let _ = SelectedPCodeDfgGraphTask::new(); }
}
