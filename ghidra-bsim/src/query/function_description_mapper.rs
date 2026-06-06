//! Port of `FunctionDescriptionMapper`.
use std::collections::HashMap;
/// Struct porting `FunctionDescriptionMapper`.
#[derive(Debug, Clone)]
pub struct FunctionDescriptionMapper {
    /// recnum.
    pub recnum: i32,
}

impl FunctionDescriptionMapper {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for FunctionDescriptionMapper {
    fn default() -> Self {
        Self {
            recnum: 0,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_function_description_mapper_new() { let _ = FunctionDescriptionMapper::new(); }
}
