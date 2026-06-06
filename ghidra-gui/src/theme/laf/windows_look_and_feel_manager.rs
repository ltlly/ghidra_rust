//! Port of `WindowsLookAndFeelManager`.
use std::collections::HashMap;
/// Struct porting `WindowsLookAndFeelManager`.
#[derive(Debug, Clone)]
pub struct WindowsLookAndFeelManager {
    _phantom: std::marker::PhantomData<()>,
}
impl WindowsLookAndFeelManager {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for WindowsLookAndFeelManager {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_windows_look_and_feel_manager_new() { let _ = WindowsLookAndFeelManager::new(); }
}
