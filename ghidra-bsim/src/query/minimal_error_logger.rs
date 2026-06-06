//! Port of `MinimalErrorLogger`.
use std::collections::HashMap;
/// Struct porting `MinimalErrorLogger`.
#[derive(Debug, Clone)]
pub struct MinimalErrorLogger {
    _phantom: std::marker::PhantomData<()>,
}
impl MinimalErrorLogger {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MinimalErrorLogger {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_minimal_error_logger_new() { let _ = MinimalErrorLogger::new(); }
}
