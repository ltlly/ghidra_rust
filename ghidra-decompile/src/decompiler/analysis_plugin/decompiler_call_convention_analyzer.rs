//! Port of `DecompilerCallConventionAnalyzer`.
use std::collections::HashMap;
/// Struct porting `DecompilerCallConventionAnalyzer`.
#[derive(Debug, Clone)]
pub struct DecompilerCallConventionAnalyzer {
    /// OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS
    pub option_default_decompiler_timeout_secs: i32,
}
impl DecompilerCallConventionAnalyzer {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerCallConventionAnalyzer {
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
    fn test_decompiler_call_convention_analyzer_new() { let _ = DecompilerCallConventionAnalyzer::new(); }
}
