//! Port of `EmptyIcon`.
use std::collections::HashMap;
/// Struct porting `EmptyIcon`.
#[derive(Debug, Clone)]
pub struct EmptyIcon {
    _phantom: std::marker::PhantomData<()>,
}
impl EmptyIcon {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for EmptyIcon {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_empty_icon_new() { let _ = EmptyIcon::new(); }
}
