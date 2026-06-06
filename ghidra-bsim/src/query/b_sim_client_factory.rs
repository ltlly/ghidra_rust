//! Port of `BSimClientFactory`.
use std::collections::HashMap;
/// Struct porting `BSimClientFactory`.
#[derive(Debug, Clone)]
pub struct BSimClientFactory {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimClientFactory {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimClientFactory {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_client_factory_new() { let _ = BSimClientFactory::new(); }
}
