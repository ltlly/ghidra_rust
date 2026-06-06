//! Port of `WhitespaceHandler`.
use std::collections::HashMap;
/// Struct porting `WhitespaceHandler`.
#[derive(Debug, Clone)]
pub struct WhitespaceHandler {
    _phantom: std::marker::PhantomData<()>,
}
impl WhitespaceHandler {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for WhitespaceHandler {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_whitespace_handler_new() { let _ = WhitespaceHandler::new(); }
}
