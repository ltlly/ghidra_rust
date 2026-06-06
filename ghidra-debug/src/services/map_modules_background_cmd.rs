//! Background command for module mapping.
//!
//! Ported from Ghidra's `MapModulesBackgroundCommand`.

use serde::{Deserialize, Serialize};

use super::mapping_proposals_impl::ModuleMapProposal;

/// Background command that applies module mapping proposals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapModulesBackgroundCommand {
    proposals: Vec<ModuleMapProposal>,
    overwrite: bool,
}

impl MapModulesBackgroundCommand {
    /// Create a new command with the given proposals.
    pub fn new(proposals: Vec<ModuleMapProposal>) -> Self {
        Self { proposals, overwrite: false }
    }
    /// Enable or disable overwrite mode.
    pub fn with_overwrite(mut self, v: bool) -> Self { self.overwrite = v; self }
    /// Get the number of proposals.
    pub fn proposal_count(&self) -> usize { self.proposals.len() }
    /// Check if overwrite mode is enabled.
    pub fn is_overwrite(&self) -> bool { self.overwrite }
    /// Get a reference to the proposals.
    pub fn proposals(&self) -> &[ModuleMapProposal] { &self.proposals }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmd_empty() {
        let cmd = MapModulesBackgroundCommand::new(vec![]);
        assert_eq!(cmd.proposal_count(), 0);
        assert!(!cmd.is_overwrite());
    }

    #[test]
    fn test_cmd_overwrite() {
        let cmd = MapModulesBackgroundCommand::new(vec![]).with_overwrite(true);
        assert!(cmd.is_overwrite());
    }

    #[test]
    fn test_cmd_proposals() {
        let proposals = vec![
            ModuleMapProposal::new("libc", "libc"),
            ModuleMapProposal::new("main", "main"),
        ];
        let cmd = MapModulesBackgroundCommand::new(proposals);
        assert_eq!(cmd.proposal_count(), 2);
        assert_eq!(cmd.proposals()[0].module_name, "libc");
    }
}
