//! Port of `DecompilerSwitchAnalysisCmd`.
use std::collections::HashMap;
/// Struct porting `DecompilerSwitchAnalysisCmd`.
#[derive(Debug, Clone)]
pub struct DecompilerSwitchAnalysisCmd {
    /// decompiler
    pub decompiler: String,
}
impl DecompilerSwitchAnalysisCmd {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerSwitchAnalysisCmd {
    fn default() -> Self {
        Self {
            decompiler: String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_switch_analysis_cmd_new() { let _ = DecompilerSwitchAnalysisCmd::new(); }
}
