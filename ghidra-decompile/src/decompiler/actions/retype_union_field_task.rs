//! Port of `RetypeUnionFieldTask`.
use std::collections::HashMap;
/// Struct porting `RetypeUnionFieldTask`.
#[derive(Debug, Clone)]
pub struct RetypeUnionFieldTask {
    _phantom: std::marker::PhantomData<()>,
}
impl RetypeUnionFieldTask {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RetypeUnionFieldTask {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_retype_union_field_task_new() { let _ = RetypeUnionFieldTask::new(); }
}
