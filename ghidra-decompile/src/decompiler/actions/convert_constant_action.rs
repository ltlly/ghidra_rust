//! Port of `ConvertConstantAction`.
use std::collections::HashMap;
/// Struct porting `ConvertConstantAction`.
#[derive(Debug, Clone)]
pub struct ConvertConstantAction {
    /// plugin
    pub plugin: String,
    /// convertType
    pub convert_type: i32,
}
impl ConvertConstantAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ConvertConstantAction {
    fn default() -> Self {
        Self {
            plugin: String::new(),
            convert_type: 0
        }


}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_convert_constant_action_new() { let _ = ConvertConstantAction::new(); }
}
