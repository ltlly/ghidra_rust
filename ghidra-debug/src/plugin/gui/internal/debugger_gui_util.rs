//! GUI utility.

/// GUI utility.
#[derive(Debug, Clone)]
pub struct DebuggerGuiUtil {
    /// initialized
    pub initialized: bool,
}

impl DebuggerGuiUtil {
    /// Create a new DebuggerGuiUtil.
    pub fn new(initialized: bool) -> Self {
        Self { initialized }
    }

    /// initialized
    pub fn initialized(&self) -> &bool {
        &self.initialized
    }
}

impl Default for DebuggerGuiUtil {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = DebuggerGuiUtil::new(true);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = DebuggerGuiUtil::default();
    }
}
