//! Port of `RenameVariableTask`.
use std::collections::HashMap;
/// Struct porting `RenameVariableTask`.
#[derive(Debug, Clone)]
pub struct RenameVariableTask {
    _phantom: std::marker::PhantomData<()>,
}
impl RenameVariableTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RenameVariableTask {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rename_variable_task_new() { let _ = RenameVariableTask::new(); }
}
