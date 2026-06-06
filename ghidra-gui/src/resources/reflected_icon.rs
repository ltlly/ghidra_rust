//! Port of `ReflectedIcon`.
use std::collections::HashMap;
/// Struct porting `ReflectedIcon`.
#[derive(Debug, Clone)]
pub struct ReflectedIcon {
    _phantom: std::marker::PhantomData<()>,
}
impl ReflectedIcon {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for ReflectedIcon {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_reflected_icon_new() { let _ = ReflectedIcon::new(); }
}
