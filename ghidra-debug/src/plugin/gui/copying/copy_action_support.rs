//! Copy support.

/// Copy support.
#[derive(Debug, Clone)]
pub struct CopyActionSupport {
    /// supported_formats
    pub supported_formats: Vec<String>,
}

impl CopyActionSupport {
    /// Create a new CopyActionSupport.
    pub fn new(supported_formats: Vec<String>) -> Self {
        Self { supported_formats }
    }

    /// supported_formats
    pub fn supported_formats(&self) -> &Vec<String> {
        &self.supported_formats
    }
}

impl Default for CopyActionSupport {
    fn default() -> Self {
        Self::new(Default::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_creation() {
        let _obj = CopyActionSupport::new(vec![]);
        assert!(true);
    }

    #[test]
    fn test_default() {
        let _obj = CopyActionSupport::default();
    }
}
