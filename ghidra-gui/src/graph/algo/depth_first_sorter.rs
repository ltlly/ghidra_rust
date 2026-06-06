//! Port of `DepthFirstSorter`.
use std::collections::HashMap;
/// Struct porting `DepthFirstSorter`.
#[derive(Debug, Clone)]
pub struct DepthFirstSorter {
    _phantom: std::marker::PhantomData<()>,
}
impl DepthFirstSorter {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DepthFirstSorter {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_depth_first_sorter_new() { let _ = DepthFirstSorter::new(); }
}
