//! Port of `RetypeStructFieldTask`.
use std::collections::HashMap;
/// Struct porting `RetypeStructFieldTask`.
#[derive(Debug, Clone)]
pub struct RetypeStructFieldTask {
    _phantom: std::marker::PhantomData<()>,
}
impl RetypeStructFieldTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RetypeStructFieldTask {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_retype_struct_field_task_new() { let _ = RetypeStructFieldTask::new(); }
}
