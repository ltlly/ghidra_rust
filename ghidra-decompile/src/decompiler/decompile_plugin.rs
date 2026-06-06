//! Port of `DecompilePlugin`.
use std::collections::HashMap;
/// Struct porting `DecompilePlugin`.
#[derive(Debug, Clone)]
pub struct DecompilePlugin {
    /// OPTIONS_TITLE
    pub options_title: String,
}
impl DecompilePlugin {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilePlugin {
    fn default() -> Self {
        Self {
            options_title: String::new()
        }

}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompile_plugin_new() { let _ = DecompilePlugin::new(); }
}
