//! Port of `LayoutLocationMap`.
use std::collections::HashMap;
/// Struct porting `LayoutLocationMap`.
#[derive(Debug, Clone)]
pub struct LayoutLocationMap {
    _phantom: std::marker::PhantomData<()>,
}
impl LayoutLocationMap {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for LayoutLocationMap {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_layout_location_map_new() { let _ = LayoutLocationMap::new(); }
}
