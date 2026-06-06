//! Port of `Attributed`.
use std::collections::HashMap;
/// Struct porting `Attributed`.
#[derive(Debug, Clone)]
pub struct Attributed {
    _phantom: std::marker::PhantomData<()>,
}
impl Attributed {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for Attributed {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_attributed_new() { let _ = Attributed::new(); }
}
