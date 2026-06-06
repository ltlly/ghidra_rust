//! Port of `RenameUnionFieldTask`.
use std::collections::HashMap;
/// Struct porting `RenameUnionFieldTask`.
#[derive(Debug, Clone)]
pub struct RenameUnionFieldTask {
    _phantom: std::marker::PhantomData<()>,
}
impl RenameUnionFieldTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RenameUnionFieldTask {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rename_union_field_task_new() { let _ = RenameUnionFieldTask::new(); }
}
