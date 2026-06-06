//! Port of `FlatLookAndFeelManager`.
use std::collections::HashMap;
/// Struct porting `FlatLookAndFeelManager`.
#[derive(Debug, Clone)]
pub struct FlatLookAndFeelManager {
    _phantom: std::marker::PhantomData<()>,
}
impl FlatLookAndFeelManager {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FlatLookAndFeelManager {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_flat_look_and_feel_manager_new() { let _ = FlatLookAndFeelManager::new(); }
}
