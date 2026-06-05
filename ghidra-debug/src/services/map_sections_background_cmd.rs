//! Background command for section mapping.
//!
//! Ported from Ghidra's `MapSectionsBackgroundCommand`.

use serde::{Deserialize, Serialize};

use super::mapping_proposals_impl::SectionMapProposal;

/// Background command that applies section mapping proposals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapSectionsBackgroundCommand {
    proposals: Vec<SectionMapProposal>,
}

impl MapSectionsBackgroundCommand {
    pub fn new(proposals: Vec<SectionMapProposal>) -> Self {
        Self { proposals }
    }
    pub fn proposal_count(&self) -> usize { self.proposals.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_cmd() {
        let cmd = MapSectionsBackgroundCommand::new(vec![]);
        assert_eq!(cmd.proposal_count(), 0);
    }
}
