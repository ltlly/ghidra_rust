//! Port of `SignatureBSimApplyTask`.
use std::collections::HashMap;
/// Struct porting `SignatureBSimApplyTask`.
#[derive(Debug, Clone)]
pub struct SignatureBSimApplyTask {
    _phantom: std::marker::PhantomData<()>,
}
impl SignatureBSimApplyTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for SignatureBSimApplyTask {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_signature_b_sim_apply_task_new() { let _ = SignatureBSimApplyTask::new(); }
}
