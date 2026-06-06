//! Port of `DecompilerSwitchAnalyzer`.
use std::collections::HashMap;
/// Struct porting `DecompilerSwitchAnalyzer`.
#[derive(Debug, Clone)]
pub struct DecompilerSwitchAnalyzer {
    /// OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS
    pub option_default_decompiler_timeout_secs: i32,
}
impl DecompilerSwitchAnalyzer {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerSwitchAnalyzer {
    fn default() -> Self {
        Self {
            option_default_decompiler_timeout_secs: 0
        }

}}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_switch_analyzer_new() { let _ = DecompilerSwitchAnalyzer::new(); }
}
