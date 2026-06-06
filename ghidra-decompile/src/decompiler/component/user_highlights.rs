//! Port of `UserHighlights`.
use std::collections::HashMap;
/// Struct porting `UserHighlights`.
#[derive(Debug, Clone)]
pub struct UserHighlights {
    _phantom: std::marker::PhantomData<()>,
}
impl UserHighlights {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for UserHighlights {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_user_highlights_new() { let _ = UserHighlights::new(); }
}
