//! ResponsePrewarm -- response to a prewarm request.
//!
//! Ports `ghidra.features.bsim.query.protocol.ResponsePrewarm`.

use serde::{Deserialize, Serialize};

/// Response to a prewarm request.
///
/// Port of `ResponsePrewarm.java`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsePrewarm {
    /// Whether prewarming was successful.
    pub success: bool,
    /// Number of pages warmed.
    pub pages_loaded: usize,
}

impl ResponsePrewarm {
    /// Create a successful prewarm response.
    pub fn success(pages_loaded: usize) -> Self {
        Self {
            success: true,
            pages_loaded,
        }
    }

    /// Create a failed prewarm response.
    pub fn failure() -> Self {
        Self {
            success: false,
            pages_loaded: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_response_prewarm_success() {
        let rp = ResponsePrewarm::success(1024);
        assert!(rp.success);
        assert_eq!(rp.pages_loaded, 1024);
    }

    #[test]
    fn test_response_prewarm_failure() {
        let rp = ResponsePrewarm::failure();
        assert!(!rp.success);
        assert_eq!(rp.pages_loaded, 0);
    }

    #[test]
    fn test_response_prewarm_serialization() {
        let rp = ResponsePrewarm::success(512);
        let json = serde_json::to_string(&rp).unwrap();
        assert!(json.contains("512"));
        let back: ResponsePrewarm = serde_json::from_str(&json).unwrap();
        assert!(back.success);
        assert_eq!(back.pages_loaded, 512);
    }

    #[test]
    fn test_response_prewarm_clone() {
        let rp = ResponsePrewarm::success(256);
        let cloned = rp.clone();
        assert_eq!(cloned.pages_loaded, 256);
    }

    #[test]
    fn test_response_prewarm_debug() {
        let rp = ResponsePrewarm::success(128);
        let debug = format!("{:?}", rp);
        assert!(debug.contains("128"));
    }
}
