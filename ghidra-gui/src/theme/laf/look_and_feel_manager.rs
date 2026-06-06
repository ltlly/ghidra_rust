//! Port of `LookAndFeelManager`.
use std::collections::HashMap;
/// Struct porting `LookAndFeelManager`.
#[derive(Debug, Clone)]
pub struct LookAndFeelManager {
    /// theme_manager.
    pub theme_manager: String,
}

impl LookAndFeelManager {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for LookAndFeelManager {
    fn default() -> Self {
        Self {
            theme_manager: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_look_and_feel_manager_new() { let _ = LookAndFeelManager::new(); }
}
