//! Port of `VgActionContext`.
use std::collections::HashMap;
/// Struct porting `VgActionContext`.
#[derive(Debug, Clone)]
pub struct VgActionContext {
    _phantom: std::marker::PhantomData<()>,
}
impl VgActionContext {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for VgActionContext {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_vg_action_context_new() { let _ = VgActionContext::new(); }
}
