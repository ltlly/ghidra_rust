//! Port of `NameTokenMatcher`.
use std::collections::HashMap;
/// Struct porting `NameTokenMatcher`.
#[derive(Debug, Clone)]
pub struct NameTokenMatcher {
    _phantom: std::marker::PhantomData<()>,
}
impl NameTokenMatcher {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for NameTokenMatcher {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_name_token_matcher_new() { let _ = NameTokenMatcher::new(); }
}
