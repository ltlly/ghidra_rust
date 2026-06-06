//! Arithmetic tracking memory state.

/// Arithmetic tracking memory state.
#[derive(Debug, Clone)]
pub struct TraceMemoryStatePcodeArithmetic {
    /// propagate_unknown
    pub propagate_unknown: bool,
    /// word_size
    pub word_size: usize,
}

impl TraceMemoryStatePcodeArithmetic {
    /// Create a new TraceMemoryStatePcodeArithmetic.
    pub fn new(propagate_unknown: bool, word_size: usize) -> Self {
        Self { propagate_unknown, word_size }
    }

    /// propagate_unknown
    pub fn propagate_unknown(&self) -> &bool {
        &self.propagate_unknown
    }

    /// word_size
    pub fn word_size(&self) -> &usize {
        &self.word_size
    }
}

impl Default for TraceMemoryStatePcodeArithmetic {
    fn default() -> Self {
        Self::new(Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = TraceMemoryStatePcodeArithmetic::new(true, 4);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = TraceMemoryStatePcodeArithmetic::default();
    }
}
