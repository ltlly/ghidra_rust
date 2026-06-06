//! Port of `AbstractBSimApplyTask`.
use std::collections::HashMap;
/// Struct porting `AbstractBSimApplyTask`.
#[derive(Debug, Clone)]
pub struct AbstractBSimApplyTask {
    _phantom: std::marker::PhantomData<()>,
}
impl AbstractBSimApplyTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for AbstractBSimApplyTask {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_abstract_b_sim_apply_task_new() { let _ = AbstractBSimApplyTask::new(); }
}
