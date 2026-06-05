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
    pub fn new(proposals: Vec<RegionMapProposal>) -> Self {
        Self { proposals }
    }
    pub fn proposal_count(&self) -> usize { self.proposals.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_cmd() {
        let cmd = MapRegionsBackgroundCommand::new(vec![]);
        assert_eq!(cmd.proposal_count(), 0);
    }
}
