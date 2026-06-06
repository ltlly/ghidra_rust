//! Port of `DecompilerFunctionAnalyzer`.
use std::collections::HashMap;
/// Struct porting `DecompilerFunctionAnalyzer`.
#[derive(Debug, Clone)]
pub struct DecompilerFunctionAnalyzer {
    /// OPTION_DEFAULT_DECOMPILER_TIMEOUT_SECS
    pub option_default_decompiler_timeout_secs: i32,
}
impl DecompilerFunctionAnalyzer {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerFunctionAnalyzer {
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
    fn test_decompiler_function_analyzer_new() { let _ = DecompilerFunctionAnalyzer::new(); }
}
