//! Port of `IsolateVariableTask`.
use std::collections::HashMap;
/// Struct porting `IsolateVariableTask`.
#[derive(Debug, Clone)]
pub struct IsolateVariableTask {
    _phantom: std::marker::PhantomData<()>,
}
impl IsolateVariableTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for IsolateVariableTask {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_isolate_variable_task_new() { let _ = IsolateVariableTask::new(); }
}
