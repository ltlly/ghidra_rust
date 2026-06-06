//! Port of `DebugDecompilerAction`.
use std::collections::HashMap;
/// Struct porting `DebugDecompilerAction`.
#[derive(Debug, Clone)]
pub struct DebugDecompilerAction {
    _phantom: std::marker::PhantomData<()>,
}
impl DebugDecompilerAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DebugDecompilerAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_debug_decompiler_action_new() { let _ = DebugDecompilerAction::new(); }
}
