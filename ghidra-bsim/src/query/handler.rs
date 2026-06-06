//! Port of `Handler`.
use std::collections::HashMap;
/// Struct porting `Handler`.
#[derive(Debug, Clone)]
pub struct Handler {
    _phantom: std::marker::PhantomData<()>,
}
impl Handler {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for Handler {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_handler_new() { let _ = Handler::new(); }
}
