//! Port of `BSimServerManager`.
use std::collections::HashMap;
/// Struct porting `BSimServerManager`.
#[derive(Debug, Clone)]
pub struct BSimServerManager {
    _phantom: std::marker::PhantomData<()>,
}
impl BSimServerManager {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for BSimServerManager {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_b_sim_server_manager_new() { let _ = BSimServerManager::new(); }
}
