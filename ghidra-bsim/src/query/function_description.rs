//! Port of `FunctionDescription`.
use std::collections::HashMap;
/// Struct porting `FunctionDescription`.
#[derive(Debug, Clone)]
pub struct FunctionDescription {
    /// update.
    pub update: String,
    /// function_name.
    pub function_name: bool,
    /// flags.
    pub flags: bool,
}

impl FunctionDescription {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for FunctionDescription {
    fn default() -> Self {
        Self {
            update: String::new(),
            function_name: false,
            flags: false,
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_function_description_new() { let _ = FunctionDescription::new(); }
}
