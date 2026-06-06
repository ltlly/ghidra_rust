//! Port of `TokenKey`.
use std::collections::HashMap;
/// Struct porting `TokenKey`.
#[derive(Debug, Clone)]
pub struct TokenKey {
    _phantom: std::marker::PhantomData<()>,
}
impl TokenKey {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for TokenKey {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_token_key_new() { let _ = TokenKey::new(); }
}
