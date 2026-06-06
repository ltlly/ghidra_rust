//! Port of `PCodeCfgDisplayListener`.
use std::collections::HashMap;
/// Struct porting `PCodeCfgDisplayListener`.
#[derive(Debug, Clone)]
pub struct PCodeCfgDisplayListener {
    _phantom: std::marker::PhantomData<()>,
}
impl PCodeCfgDisplayListener {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for PCodeCfgDisplayListener {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_p_code_cfg_display_listener_new() { let _ = PCodeCfgDisplayListener::new(); }
}
