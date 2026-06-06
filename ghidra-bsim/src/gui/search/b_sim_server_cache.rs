//! Port of `BSimServerCache`.
use std::collections::HashMap;
/// Struct porting `BSimServerCache`.
#[derive(Debug, Clone)]
pub struct BSimServerCache {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimServerCache {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimServerCache {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_server_cache_new() { let _ = BSimServerCache::new(); }
}
