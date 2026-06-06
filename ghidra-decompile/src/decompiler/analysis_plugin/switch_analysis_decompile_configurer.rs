//! Port of `SwitchAnalysisDecompileConfigurer`.
use std::collections::HashMap;
/// Struct porting `SwitchAnalysisDecompileConfigurer`.
#[derive(Debug, Clone)]
pub struct SwitchAnalysisDecompileConfigurer {
    _phantom: std::marker::PhantomData<()>,
}
impl SwitchAnalysisDecompileConfigurer {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for SwitchAnalysisDecompileConfigurer {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_switch_analysis_decompile_configurer_new() { let _ = SwitchAnalysisDecompileConfigurer::new(); }
}
