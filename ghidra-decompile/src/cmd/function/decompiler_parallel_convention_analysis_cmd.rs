//! Port of `DecompilerParallelConventionAnalysisCmd`.
use std::collections::HashMap;
/// Struct porting `DecompilerParallelConventionAnalysisCmd`.
#[derive(Debug, Clone)]
pub struct DecompilerParallelConventionAnalysisCmd {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerParallelConventionAnalysisCmd {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerParallelConventionAnalysisCmd {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_parallel_convention_analysis_cmd_new() { let _ = DecompilerParallelConventionAnalysisCmd::new(); }
}
