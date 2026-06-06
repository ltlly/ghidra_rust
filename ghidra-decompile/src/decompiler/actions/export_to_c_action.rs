//! Port of `ExportToCAction`.
use std::collections::HashMap;
/// Struct porting `ExportToCAction`.
#[derive(Debug, Clone)]
pub struct ExportToCAction {
    _phantom: std::marker::PhantomData<()>,
}
impl ExportToCAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ExportToCAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_export_to_c_action_new() { let _ = ExportToCAction::new(); }
}
