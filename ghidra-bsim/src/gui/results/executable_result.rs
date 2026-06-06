//! Port of `ExecutableResult`.
use std::collections::HashMap;
/// Struct porting `ExecutableResult`.
#[derive(Debug, Clone)]
pub struct ExecutableResult {
    _phantom: std::marker::PhantomData<()>,
}
impl ExecutableResult {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ExecutableResult {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_executable_result_new() { let _ = ExecutableResult::new(); }
}
