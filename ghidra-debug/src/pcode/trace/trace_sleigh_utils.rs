//! Sleigh language utilities for traces.

/// Sleigh language utilities for traces.
#[derive(Debug, Clone)]
pub struct TraceSleighUtils {
    /// language_id
    pub language_id: String,
    /// compiler_spec_id
    pub compiler_spec_id: String,
}

impl TraceSleighUtils {
    /// Create a new TraceSleighUtils.
    pub fn new(language_id: String, compiler_spec_id: String) -> Self {
        Self { language_id, compiler_spec_id }
    }

    /// language_id
    pub fn language_id(&self) -> &String {
        &self.language_id
    }

    /// compiler_spec_id
    pub fn compiler_spec_id(&self) -> &String {
        &self.compiler_spec_id
    }
}

impl Default for TraceSleighUtils {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = TraceSleighUtils::new("test".to_string(), "test".to_string());
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = TraceSleighUtils::default();
    }
}
