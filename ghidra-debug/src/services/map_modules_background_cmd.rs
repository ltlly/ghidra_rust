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
    pub fn new(proposals: Vec<ModuleMapProposal>) -> Self {
        Self { proposals, overwrite: false }
    }
    pub fn with_overwrite(mut self, v: bool) -> Self { self.overwrite = v; self }
    pub fn proposal_count(&self) -> usize { self.proposals.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_cmd() {
        let cmd = MapModulesBackgroundCommand::new(vec![]);
        assert_eq!(cmd.proposal_count(), 0);
    }
}
