//! Port of `DecompilerCallback`.
use std::collections::HashMap;
/// Struct porting `DecompilerCallback`.
#[derive(Debug, Clone)]
pub struct DecompilerCallback {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerCallback {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerCallback {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_callback_new() { let _ = DecompilerCallback::new(); }
}
