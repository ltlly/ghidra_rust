//! Port of `PCodeCfgGraphType`.
use std::collections::HashMap;
/// Struct porting `PCodeCfgGraphType`.
#[derive(Debug, Clone)]
pub struct PCodeCfgGraphType {
    _phantom: std::marker::PhantomData<()>,
}
impl PCodeCfgGraphType {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for PCodeCfgGraphType {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_p_code_cfg_graph_type_new() { let _ = PCodeCfgGraphType::new(); }
}
