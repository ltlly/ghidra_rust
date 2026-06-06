//! Port of `ConvertConstantEquateTask`.
use std::collections::HashMap;
/// Struct porting `ConvertConstantEquateTask`.
#[derive(Debug, Clone)]
pub struct ConvertConstantEquateTask {
    _phantom: std::marker::PhantomData<()>,
}
impl ConvertConstantEquateTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ConvertConstantEquateTask {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_convert_constant_equate_task_new() { let _ = ConvertConstantEquateTask::new(); }
}
