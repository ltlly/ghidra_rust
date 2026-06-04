//! Related match implementation.

use std::fmt;

use ghidra_core::addr::Address;

use crate::versiontracking::match_set::VtMatch;
use crate::versiontracking::types::{VtAssociationType, VtScore};

/// Represents a match that is related to another match through
/// a shared source or destination address.
///
/// Corresponds to Ghidra's `VTRelatedMatchImpl` Java class.
#[derive(Debug, Clone)]
pub struct VTRelatedMatchImpl {
    /// The related match data
    match_data: VtMatch,
    /// The correlation type
    correlation_type: VTRelatedMatchCorrelationType,
    /// Description of the relationship
    description: String,
}

/// How two matches are related.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VTRelatedMatchCorrelationType {
    /// Same source address
    SameSource,
    /// Same destination address
    SameDestination,
    /// Both source and destination addresses match
    SameSourceAndDestination,
    /// Implied through call reference
    Implied,
    /// Duplicate function
    Duplicate,
}

impl VTRelatedMatchCorrelationType {
    /// Returns a display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            VTRelatedMatchCorrelationType::SameSource => "Same Source",
            VTRelatedMatchCorrelationType::SameDestination => "Same Destination",
            VTRelatedMatchCorrelationType::SameSourceAndDestination => "Same Source and Destination",
            VTRelatedMatchCorrelationType::Implied => "Implied",
            VTRelatedMatchCorrelationType::Duplicate => "Duplicate",
        }
    }
}

impl fmt::Display for VTRelatedMatchCorrelationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// The type of relationship.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VTRelatedMatchType {
    /// Related by source address
    Source,
    /// Related by destination address
    Destination,
}

impl VTRelatedMatchType {
    /// Returns a display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            VTRelatedMatchType::Source => "Source",
            VTRelatedMatchType::Destination => "Destination",
        }
    }
}

impl VTRelatedMatchImpl {
    /// Create a new related match.
    pub fn new(
        match_data: VtMatch,
        correlation_type: VTRelatedMatchCorrelationType,
        description: impl Into<String>,
    ) -> Self {
        Self {
            match_data,
            correlation_type,
            description: description.into(),
        }
    }

    /// Returns the match data.
    pub fn match_data(&self) -> &VtMatch {
        &self.match_data
    }

    /// Returns the correlation type.
    pub fn correlation_type(&self) -> VTRelatedMatchCorrelationType {
        self.correlation_type
    }

    /// Returns the description.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Returns the source address.
    pub fn source_address(&self) -> Address {
        self.match_data.source_address
    }

    /// Returns the destination address.
    pub fn destination_address(&self) -> Address {
        self.match_data.destination_address
    }

    /// Returns the similarity score.
    pub fn similarity_score(&self) -> &VtScore {
        &self.match_data.similarity_score
    }

    /// Returns the association type.
    pub fn association_type(&self) -> VtAssociationType {
        self.match_data.association_type
    }
}

impl fmt::Display for VTRelatedMatchImpl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RelatedMatch({}, {}, src=0x{:x}, dst=0x{:x})",
            self.correlation_type,
            self.match_data.association_type,
            self.match_data.source_address.offset(),
            self.match_data.destination_address.offset()
        )
    }
}

/// Selection listener for related match events.
pub trait VTRelatedMatchSelectionListener: Send + Sync {
    /// Called when a related match is selected.
    fn related_match_selected(&self, related_match: &VTRelatedMatchImpl);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_related_match() -> VTRelatedMatchImpl {
        let vt_match = VtMatch {
            association_id: 1,
            match_set_id: 1,
            source_address: Address::new(0x1000),
            destination_address: Address::new(0x2000),
            association_type: VtAssociationType::Function,
            similarity_score: VtScore::new(0.95),
            confidence_score: VtScore::new(0.85),
            source_length: 100,
            destination_length: 100,
            length_type: "bytes".to_string(),
            tag: crate::versiontracking::types::VtMatchTag::untagged(),
        };
        VTRelatedMatchImpl::new(vt_match, VTRelatedMatchCorrelationType::SameSource, "shares source address")
    }

    #[test]
    fn test_related_match_create() {
        let rm = make_related_match();
        assert_eq!(rm.correlation_type(), VTRelatedMatchCorrelationType::SameSource);
        assert_eq!(rm.description(), "shares source address");
        assert_eq!(rm.source_address().offset(), 0x1000);
        assert_eq!(rm.destination_address().offset(), 0x2000);
    }

    #[test]
    fn test_correlation_type_display() {
        assert_eq!(VTRelatedMatchCorrelationType::SameSource.display_name(), "Same Source");
        assert_eq!(VTRelatedMatchCorrelationType::Implied.display_name(), "Implied");
    }

    #[test]
    fn test_related_match_type_display() {
        assert_eq!(VTRelatedMatchType::Source.display_name(), "Source");
        assert_eq!(VTRelatedMatchType::Destination.display_name(), "Destination");
    }

    #[test]
    fn test_related_match_display() {
        let rm = make_related_match();
        let display = format!("{}", rm);
        assert!(display.contains("RelatedMatch"));
        assert!(display.contains("Same Source"));
    }
}
