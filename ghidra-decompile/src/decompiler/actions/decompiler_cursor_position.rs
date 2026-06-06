//! Port of `DecompilerCursorPosition`.
use std::collections::HashMap;
/// Struct porting `DecompilerCursorPosition`.
#[derive(Debug, Clone)]
pub struct DecompilerCursorPosition {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerCursorPosition {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerCursorPosition {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_cursor_position_new() { let _ = DecompilerCursorPosition::new(); }
}
