//! Port of `RenameStructFieldTask`.
use std::collections::HashMap;
/// Struct porting `RenameStructFieldTask`.
#[derive(Debug, Clone)]
pub struct RenameStructFieldTask {
    /// offset
    pub offset: i32,
}
impl RenameStructFieldTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RenameStructFieldTask {
    fn default() -> Self {
        Self {
            offset: 0
        }

}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rename_struct_field_task_new() { let _ = RenameStructFieldTask::new(); }
}
