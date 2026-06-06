//! Port of `TemporaryScoreCaching`.
use std::collections::HashMap;
/// Struct porting `TemporaryScoreCaching`.
#[derive(Debug, Clone)]
pub struct TemporaryScoreCaching {
    _phantom: std::marker::PhantomData<()>,
}
impl TemporaryScoreCaching {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for TemporaryScoreCaching {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_temporary_score_caching_new() { let _ = TemporaryScoreCaching::new(); }
}
