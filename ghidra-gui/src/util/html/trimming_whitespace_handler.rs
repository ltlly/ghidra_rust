//! Port of `TrimmingWhitespaceHandler`.
use std::collections::HashMap;
/// Struct porting `TrimmingWhitespaceHandler`.
#[derive(Debug, Clone)]
pub struct TrimmingWhitespaceHandler {
    _phantom: std::marker::PhantomData<()>,
}
impl TrimmingWhitespaceHandler {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for TrimmingWhitespaceHandler {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_trimming_whitespace_handler_new() { let _ = TrimmingWhitespaceHandler::new(); }
}
