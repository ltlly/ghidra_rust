//! Port of `RightSidedSquishyBuddyLayout`.
use std::collections::HashMap;
/// Struct porting `RightSidedSquishyBuddyLayout`.
#[derive(Debug, Clone)]
pub struct RightSidedSquishyBuddyLayout {
    _phantom: std::marker::PhantomData<()>,
}
impl RightSidedSquishyBuddyLayout {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for RightSidedSquishyBuddyLayout {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_right_sided_squishy_buddy_layout_new() { let _ = RightSidedSquishyBuddyLayout::new(); }
}
