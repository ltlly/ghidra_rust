//! Port of `NameAndNamespaceBSimApplyTask`.
use std::collections::HashMap;
/// Struct porting `NameAndNamespaceBSimApplyTask`.
#[derive(Debug, Clone)]
pub struct NameAndNamespaceBSimApplyTask {
    _phantom: std::marker::PhantomData<()>,
}
impl NameAndNamespaceBSimApplyTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for NameAndNamespaceBSimApplyTask {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_name_and_namespace_b_sim_apply_task_new() { let _ = NameAndNamespaceBSimApplyTask::new(); }
}
