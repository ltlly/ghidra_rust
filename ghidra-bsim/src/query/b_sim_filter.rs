//! Port of `BSimFilter`.
use std::collections::HashMap;
/// Struct porting `BSimFilter`.
#[derive(Debug, Clone)]
pub struct BSimFilter {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimFilter {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimFilter {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_filter_new() { let _ = BSimFilter::new(); }
}
