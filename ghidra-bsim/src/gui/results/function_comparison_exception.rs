//! Port of `FunctionComparisonException`.
use std::collections::HashMap;
/// Struct porting `FunctionComparisonException`.
#[derive(Debug, Clone)]
pub struct FunctionComparisonException {
    _phantom: std::marker::PhantomData<()>,
}
impl FunctionComparisonException {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FunctionComparisonException {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_function_comparison_exception_new() { let _ = FunctionComparisonException::new(); }
}
