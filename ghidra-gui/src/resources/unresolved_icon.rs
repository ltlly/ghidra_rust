//! Port of `UnresolvedIcon`.
use std::collections::HashMap;
/// Struct porting `UnresolvedIcon`.
#[derive(Debug, Clone)]
pub struct UnresolvedIcon {
    _phantom: std::marker::PhantomData<()>,
}
impl UnresolvedIcon {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for UnresolvedIcon {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_unresolved_icon_new() { let _ = UnresolvedIcon::new(); }
}
