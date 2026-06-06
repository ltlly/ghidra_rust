//! Port of `AbstractThemeReader`.
use std::collections::HashMap;
/// Struct porting `AbstractThemeReader`.
#[derive(Debug, Clone)]
pub struct AbstractThemeReader {
    /// source.
    pub source: String,
}

impl AbstractThemeReader {
    /// Create a new instance.
    pub fn new() -> Self { Self::default() }
}

impl Default for AbstractThemeReader {
    fn default() -> Self {
        Self {
            source: String::new(),
}
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_abstract_theme_reader_new() { let _ = AbstractThemeReader::new(); }
}
