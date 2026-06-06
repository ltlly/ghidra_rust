//! Port of `DecompilerConcurrentQ`.
use std::collections::HashMap;
/// Struct porting `DecompilerConcurrentQ`.
#[derive(Debug, Clone)]
pub struct DecompilerConcurrentQ {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerConcurrentQ {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerConcurrentQ {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_concurrent_q_new() { let _ = DecompilerConcurrentQ::new(); }
}
