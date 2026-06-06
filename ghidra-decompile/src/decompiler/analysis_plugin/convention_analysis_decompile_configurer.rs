//! Port of `ConventionAnalysisDecompileConfigurer`.
use std::collections::HashMap;
/// Struct porting `ConventionAnalysisDecompileConfigurer`.
#[derive(Debug, Clone)]
pub struct ConventionAnalysisDecompileConfigurer {
    _phantom: std::marker::PhantomData<()>,
}
impl ConventionAnalysisDecompileConfigurer {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ConventionAnalysisDecompileConfigurer {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_convention_analysis_decompile_configurer_new() { let _ = ConventionAnalysisDecompileConfigurer::new(); }
}
