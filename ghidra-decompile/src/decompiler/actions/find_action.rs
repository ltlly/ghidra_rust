//! Port of `FindAction`.
use std::collections::HashMap;
/// Struct porting `FindAction`.
#[derive(Debug, Clone)]
pub struct FindAction {
    _phantom: std::marker::PhantomData<()>,
}
impl FindAction {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for FindAction {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_find_action_new() { let _ = FindAction::new(); }
}
