//! Port of `DecompilerParameterIdCmd`.
use std::collections::HashMap;
/// Struct porting `DecompilerParameterIdCmd`.
#[derive(Debug, Clone)]
pub struct DecompilerParameterIdCmd {
    _phantom: std::marker::PhantomData<()>,
}
impl DecompilerParameterIdCmd {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}
impl Default for DecompilerParameterIdCmd {
    fn default() -> Self { Self { _phantom: std::marker::PhantomData } }
}
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_decompiler_parameter_id_cmd_new() { let _ = DecompilerParameterIdCmd::new(); }
}
