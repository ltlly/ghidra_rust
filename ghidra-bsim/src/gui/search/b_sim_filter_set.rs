//! Port of `BSimFilterSet`.
use std::collections::HashMap;
/// Struct porting `BSimFilterSet`.
#[derive(Debug, Clone)]
pub struct BSimFilterSet {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimFilterSet {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimFilterSet {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_filter_set_new() { let _ = BSimFilterSet::new(); }
}
