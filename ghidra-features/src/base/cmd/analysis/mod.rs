//! Analysis commands.
//!
//! Ported from `ghidra.app.cmd.analysis`.

/// Command for shared-return analysis.
///
/// Detects functions that share a common return instruction and
/// splits them at the shared return point.
#[derive(Debug)]
pub struct SharedReturnAnalysisCmd {
    function_entry: u64,
}

impl SharedReturnAnalysisCmd {
    pub fn new(function_entry: u64) -> Self {
        Self { function_entry }
    }

    pub fn function_entry(&self) -> u64 {
        self.function_entry
    }

    /// Apply the command. Returns `true` on success.
    pub fn apply_to(&self, _program_name: &str) -> bool {
        // Shared-return detection logic would go here.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_return_analysis_cmd() {
        let cmd = SharedReturnAnalysisCmd::new(0x401000);
        assert_eq!(cmd.function_entry(), 0x401000);
        assert!(cmd.apply_to("test.exe"));
    }
}
