//! Port of `BSimLaunchable`.
use std::collections::HashMap;
/// Struct porting `BSimLaunchable`.
#[derive(Debug, Clone)]
pub struct BSimLaunchable {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimLaunchable {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimLaunchable {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_launchable_new() { let _ = BSimLaunchable::new(); }
}
