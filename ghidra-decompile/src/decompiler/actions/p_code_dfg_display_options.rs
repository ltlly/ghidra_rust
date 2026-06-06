//! Port of `PCodeDfgDisplayOptions`.
use std::collections::HashMap;
/// Struct porting `PCodeDfgDisplayOptions`.
#[derive(Debug, Clone)]
pub struct PCodeDfgDisplayOptions {
    /// SHAPE_ATTRIBUTE
    pub shape_attribute: String,
}
impl PCodeDfgDisplayOptions {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for PCodeDfgDisplayOptions {
    fn default() -> Self {
        Self {
            shape_attribute: String::new()
        }

}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_p_code_dfg_display_options_new() { let _ = PCodeDfgDisplayOptions::new(); }
}
