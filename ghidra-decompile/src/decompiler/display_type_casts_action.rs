//! Port of `DisplayTypeCastsAction`.
use std::collections::HashMap;
/// Struct porting `DisplayTypeCastsAction`.
#[derive(Debug, Clone)]
pub struct DisplayTypeCastsAction {
    _phantom: std::marker::PhantomData<()>,
}
impl DisplayTypeCastsAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DisplayTypeCastsAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_display_type_casts_action_new() { let _ = DisplayTypeCastsAction::new(); }
}
