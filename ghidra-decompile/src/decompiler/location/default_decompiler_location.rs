//! Port of `DefaultDecompilerLocation`.
use std::collections::HashMap;
/// Struct porting `DefaultDecompilerLocation`.
#[derive(Debug, Clone)]
pub struct DefaultDecompilerLocation {
    _phantom: std::marker::PhantomData<()>,
}
impl DefaultDecompilerLocation {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DefaultDecompilerLocation {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_default_decompiler_location_new() { let _ = DefaultDecompilerLocation::new(); }
}
