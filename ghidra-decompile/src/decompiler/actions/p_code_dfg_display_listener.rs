//! Port of `PCodeDfgDisplayListener`.
use std::collections::HashMap;
/// Struct porting `PCodeDfgDisplayListener`.
#[derive(Debug, Clone)]
pub struct PCodeDfgDisplayListener {
    _phantom: std::marker::PhantomData<()>,
}
impl PCodeDfgDisplayListener {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for PCodeDfgDisplayListener {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_p_code_dfg_display_listener_new() { let _ = PCodeDfgDisplayListener::new(); }
}
