//! Contains information regarding the result of a BSim 'apply function name' operation.
//!
//! Ports Ghidra's `ghidra.features.bsim.gui.search.results.BSimApplyResult`.

use super::b_sim_match_result::BSimMatchResult;
use super::b_sim_result_status::BSimResultStatus;

/// Contains information regarding the result of a BSim 'apply function name' operation.
/// It indicates the function name being changed, the new name to use, the address,
/// and any pertinent error/informational text.
#[derive(Debug, Clone)]
pub struct BSimApplyResult {
    /// The target function name (the function being renamed).
    pub target: String,
    /// The source function name (the new name to apply).
    pub source: String,
    /// The status of the apply operation.
    pub status: BSimResultStatus,
    /// The address of the target function.
    pub address: u64,
    /// An informational or error message.
    pub message: String,
}

impl BSimApplyResult {
    /// Create a new apply result.
    pub fn new(
        target: String,
        source: String,
        status: BSimResultStatus,
        address: u64,
        message: String,
    ) -> Self {
        Self {
            target,
            source,
            status,
            address,
            message,
        }
    }

    /// Create from a BSim match result.
    pub fn from_match_result(
        match_result: &BSimMatchResult,
        status: BSimResultStatus,
        message: String,
    ) -> Self {
        Self::new(
            match_result.original_function_name.clone(),
            match_result.similar_function_name.clone(),
            status,
            match_result.address,
            message,
        )
    }

    /// Get the target function name.
    pub fn target_function_name(&self) -> &str {
        &self.target
    }

    /// Get the similar function name.
    pub fn source_function_name(&self) -> &str {
        &self.source
    }

    /// Get the status.
    pub fn status(&self) -> BSimResultStatus {
        self.status
    }

    /// Get the address.
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Get the message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether this result represents an error.
    pub fn is_error(&self) -> bool {
        self.status.is_error()
    }

    /// Whether this result was ignored.
    pub fn is_ignored(&self) -> bool {
        self.status.is_ignored()
    }
}

impl Default for BSimApplyResult {
    fn default() -> Self {
        Self {
            target: String::new(),
            source: String::new(),
            status: BSimResultStatus::NotApplied,
            address: 0,
            message: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let r = BSimApplyResult::new(
            "old_name".to_string(),
            "new_name".to_string(),
            BSimResultStatus::NameApplied,
            0x1000,
            "Applied successfully".to_string(),
        );
        assert_eq!(r.target_function_name(), "old_name");
        assert_eq!(r.source_function_name(), "new_name");
        assert!(r.status().is_applied());
    }

    #[test]
    fn test_from_match_result() {
        let match_result = BSimMatchResult::new(
            "func_a".to_string(),
            0x1000,
            "func_b".to_string(),
            0x2000,
            "test.exe".to_string(),
            "http://example.com".to_string(),
            "x86".to_string(),
            "gcc".to_string(),
            "md5".to_string(),
            0.95,
            10.0,
            0x1000,
        );
        let r = BSimApplyResult::from_match_result(
            &match_result,
            BSimResultStatus::SignatureApplied,
            "OK".to_string(),
        );
        assert_eq!(r.target, "func_a");
        assert_eq!(r.source, "func_b");
    }

    #[test]
    fn test_is_error() {
        let r = BSimApplyResult::new(
            "f".to_string(),
            "g".to_string(),
            BSimResultStatus::Error,
            0,
            "fail".to_string(),
        );
        assert!(r.is_error());
        assert!(!r.is_ignored());
    }

    #[test]
    fn test_is_ignored() {
        let r = BSimApplyResult::new(
            "f".to_string(),
            "g".to_string(),
            BSimResultStatus::Ignored,
            0,
            "ignored".to_string(),
        );
        assert!(r.is_ignored());
    }
}
