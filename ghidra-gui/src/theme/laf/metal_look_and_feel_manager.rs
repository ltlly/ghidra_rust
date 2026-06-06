//! Port of `MetalLookAndFeelManager`.
use std::collections::HashMap;
/// Struct porting `MetalLookAndFeelManager`.
#[derive(Debug, Clone)]
pub struct MetalLookAndFeelManager {
    _phantom: std::marker::PhantomData<()>,
}
impl MetalLookAndFeelManager {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MetalLookAndFeelManager {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_metal_look_and_feel_manager_new() { let _ = MetalLookAndFeelManager::new(); }
}
