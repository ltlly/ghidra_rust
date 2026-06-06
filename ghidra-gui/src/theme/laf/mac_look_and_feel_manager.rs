//! Port of `MacLookAndFeelManager`.
use std::collections::HashMap;
/// Struct porting `MacLookAndFeelManager`.
#[derive(Debug, Clone)]
pub struct MacLookAndFeelManager {
    _phantom: std::marker::PhantomData<()>,
}
impl MacLookAndFeelManager {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for MacLookAndFeelManager {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_mac_look_and_feel_manager_new() { let _ = MacLookAndFeelManager::new(); }
}
