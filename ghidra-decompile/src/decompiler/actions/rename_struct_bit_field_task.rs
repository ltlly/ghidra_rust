//! Port of `RenameStructBitFieldTask`.
use std::collections::HashMap;
/// Struct porting `RenameStructBitFieldTask`.
#[derive(Debug, Clone)]
pub struct RenameStructBitFieldTask {
    _phantom: std::marker::PhantomData<()>,
}
impl RenameStructBitFieldTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RenameStructBitFieldTask {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_rename_struct_bit_field_task_new() { let _ = RenameStructBitFieldTask::new(); }
}
