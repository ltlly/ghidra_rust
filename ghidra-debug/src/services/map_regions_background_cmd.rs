//! Background command for region mapping.
//!
//! Ported from Ghidra's `MapRegionsBackgroundCommand`.

use serde::{Deserialize, Serialize};

use super::mapping_proposals_impl::RegionMapProposal;

/// Background command that applies region mapping proposals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapRegionsBackgroundCommand {
    proposals: Vec<RegionMapProposal>,
}

impl MapRegionsBackgroundCommand {
    /// Create a new command with the given proposals.
    pub fn new(proposals: Vec<RegionMapProposal>) -> Self { Self { proposals } }
    /// Get the number of proposals.
    pub fn proposal_count(&self) -> usize { self.proposals.len() }
    /// Get a reference to the proposals.
    pub fn proposals(&self) -> &[RegionMapProposal] { &self.proposals }
    /// Check if the command has any proposals.
    pub fn is_empty(&self) -> bool { self.proposals.is_empty() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmd_empty() {
        let cmd = MapRegionsBackgroundCommand::new(vec![]);
        assert_eq!(cmd.proposal_count(), 0);
        assert!(cmd.is_empty());
    }

    #[test]
    fn test_cmd_with_proposals() {
        let proposals = vec![
            RegionMapProposal::new("stack"),
            RegionMapProposal::new("heap"),
        ];
        let cmd = MapRegionsBackgroundCommand::new(proposals);
        assert_eq!(cmd.proposal_count(), 2);
        assert!(!cmd.is_empty());
        assert_eq!(cmd.proposals()[0].region_name, "stack");
        assert_eq!(cmd.proposals()[1].region_name, "heap");
    }
}
