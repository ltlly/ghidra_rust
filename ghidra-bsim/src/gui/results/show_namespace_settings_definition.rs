//! Port of `ShowNamespaceSettingsDefinition`.
use std::collections::HashMap;
/// Struct porting `ShowNamespaceSettingsDefinition`.
#[derive(Debug, Clone)]
pub struct ShowNamespaceSettingsDefinition {
    /// DEF
    pub def: String,
}
impl ShowNamespaceSettingsDefinition {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ShowNamespaceSettingsDefinition {
    fn default() -> Self {
        Self {
            def: String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_show_namespace_settings_definition_new() { let _ = ShowNamespaceSettingsDefinition::new(); }
}
