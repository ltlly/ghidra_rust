//! Port of `ResourceManager`.
use std::collections::HashMap;
/// Struct porting `ResourceManager`.
#[derive(Debug, Clone)]
pub struct ResourceManager {
    /// bomb.
    pub bomb: String,
    /// big_bomb.
    pub big_bomb: String,
    /// external_icon_prefix.
    pub external_icon_prefix: String,
}

impl ResourceManager {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for ResourceManager {
    fn default() -> Self {
        Self {
            bomb: String::new(),
            big_bomb: String::new(),
            external_icon_prefix: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_resource_manager_new() { let _ = ResourceManager::new(); }
}
