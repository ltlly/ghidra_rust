//! Port of `LocationClangHighlightController`.
use std::collections::HashMap;
/// Struct porting `LocationClangHighlightController`.
#[derive(Debug, Clone)]
pub struct LocationClangHighlightController {
    _phantom: std::marker::PhantomData<()>,
}
impl LocationClangHighlightController {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for LocationClangHighlightController {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_location_clang_highlight_controller_new() { let _ = LocationClangHighlightController::new(); }
}
