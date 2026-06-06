//! Port of `BSimInitializer`.
use std::collections::HashMap;
/// Struct porting `BSimInitializer`.
#[derive(Debug, Clone)]
pub struct BSimInitializer {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimInitializer {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimInitializer {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_initializer_new() { let _ = BSimInitializer::new(); }
}
