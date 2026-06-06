//! Watch expression.

/// Watch expression.
#[derive(Debug, Clone)]
pub struct WatchExpression {
    /// expression
    pub expression: String,
    /// value
    pub value: Option<String>,
    /// error
    pub error: Option<String>,
}

impl WatchExpression {
    /// Create a new WatchExpression.
    pub fn new(expression: String, value: Option<String>, error: Option<String>) -> Self {
        Self { expression, value, error }
    }

    /// expression
    pub fn expression(&self) -> &String {
        &self.expression
    }

    /// value
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }

    /// error
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}

impl Default for WatchExpression {
    fn default() -> Self {
        Self::new(Default::default(), Default::default(), Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let obj = WatchExpression::new("test".to_string(), None, None);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = WatchExpression::default();
    }
}
