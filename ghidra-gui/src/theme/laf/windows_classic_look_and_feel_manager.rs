//! Port of `WindowsClassicLookAndFeelManager`.
use std::collections::HashMap;
/// Struct porting `WindowsClassicLookAndFeelManager`.
#[derive(Debug, Clone)]
pub struct WindowsClassicLookAndFeelManager {
    _phantom: std::marker::PhantomData<()>,
}
impl WindowsClassicLookAndFeelManager {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for WindowsClassicLookAndFeelManager {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_windows_classic_look_and_feel_manager_new() { let _ = WindowsClassicLookAndFeelManager::new(); }
}
