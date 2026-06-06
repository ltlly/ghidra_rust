//! Port of `PreservingWhitespaceHandler`.
use std::collections::HashMap;
/// Struct porting `PreservingWhitespaceHandler`.
#[derive(Debug, Clone)]
pub struct PreservingWhitespaceHandler {
    _phantom: std::marker::PhantomData<()>,
}
impl PreservingWhitespaceHandler {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for PreservingWhitespaceHandler {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_preserving_whitespace_handler_new() { let _ = PreservingWhitespaceHandler::new(); }
}
