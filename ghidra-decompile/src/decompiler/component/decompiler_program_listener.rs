//! Port of `DecompilerProgramListener`.
use std::collections::HashMap;
/// Struct porting `DecompilerProgramListener`.
#[derive(Debug, Clone)]
pub struct DecompilerProgramListener {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerProgramListener {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerProgramListener {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_program_listener_new() { let _ = DecompilerProgramListener::new(); }
}
