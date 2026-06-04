//! Core enums and types for Version Tracking.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VtAssociationType { Function, Data }

impl fmt::Display for VtAssociationType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { VtAssociationType::Function => write!(f, "Function"), VtAssociationType::Data => write!(f, "Data") }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VtAssociationStatus { Available, Accepted, Blocked, Rejected }

impl VtAssociationStatus {
    pub fn can_apply(&self) -> bool { matches!(self, VtAssociationStatus::Accepted | VtAssociationStatus::Available) }
    pub fn is_blocked(&self) -> bool { matches!(self, VtAssociationStatus::Blocked | VtAssociationStatus::Rejected) }
    pub fn display_name(&self) -> &str {
        match self { VtAssociationStatus::Available => "Available", VtAssociationStatus::Accepted => "Accepted",
            VtAssociationStatus::Blocked => "Blocked", VtAssociationStatus::Rejected => "Rejected" }
    }
}

impl fmt::Display for VtAssociationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.display_name()) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VtAssociationMarkupStatus { HasNone, HasAppliedMarkup, HasExaminedMarkup, HasErrors, HasDontCareMarkup, HasDontKnowMarkup, HasUnexaminedMarkup }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VtMarkupItemStatus { Unapplied, Added, Replaced, FailedApply, DontCare, DontKnow, Rejected, Same, Conflict }

impl VtMarkupItemStatus {
    pub fn is_appliable(&self) -> bool { matches!(self, VtMarkupItemStatus::Unapplied | VtMarkupItemStatus::DontCare | VtMarkupItemStatus::DontKnow) }
    pub fn is_unappliable(&self) -> bool { matches!(self, VtMarkupItemStatus::Added | VtMarkupItemStatus::Replaced) }
    pub fn is_default(&self) -> bool { matches!(self, VtMarkupItemStatus::Same | VtMarkupItemStatus::Conflict | VtMarkupItemStatus::Unapplied) }
    pub fn description(&self) -> &str {
        match self { VtMarkupItemStatus::Unapplied => "Unapplied", VtMarkupItemStatus::Added => "Applied (Added)",
            VtMarkupItemStatus::Replaced => "Applied (Replaced)", VtMarkupItemStatus::FailedApply => "Apply Failed",
            VtMarkupItemStatus::DontCare => "Don't Care", VtMarkupItemStatus::DontKnow => "Don't Know",
            VtMarkupItemStatus::Rejected => "Rejected", VtMarkupItemStatus::Same => "Destination has same value",
            VtMarkupItemStatus::Conflict => "Conflicting item is applied" }
    }
}

impl fmt::Display for VtMarkupItemStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.description()) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VtMarkupItemApplyActionType { Add, AddAsPrimary, ReplaceDefaultOnly, Replace, ReplaceFirstOnly }

impl VtMarkupItemApplyActionType {
    pub fn apply_status(&self) -> VtMarkupItemStatus {
        match self { VtMarkupItemApplyActionType::Add | VtMarkupItemApplyActionType::AddAsPrimary => VtMarkupItemStatus::Added,
            _ => VtMarkupItemStatus::Replaced }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VtMarkupItemConsideredStatus { Unconsidered, IgnoreDontKnow, IgnoreDontCare, Reject }

impl VtMarkupItemConsideredStatus {
    pub fn markup_item_status(&self) -> VtMarkupItemStatus {
        match self { VtMarkupItemConsideredStatus::Unconsidered => VtMarkupItemStatus::Unapplied,
            VtMarkupItemConsideredStatus::IgnoreDontKnow => VtMarkupItemStatus::DontKnow,
            VtMarkupItemConsideredStatus::IgnoreDontCare => VtMarkupItemStatus::DontCare,
            VtMarkupItemConsideredStatus::Reject => VtMarkupItemStatus::Rejected }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VtMarkupItemDestinationAddressEditStatus { NotSupported, Editable, Applied }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VtProgramCorrelatorAddressRestrictionPreference { NoPreference, RestrictionNotAllowed, PreferRestrictingAcceptedMatches }

#[derive(Debug, Clone, Copy)]
pub struct VtScore { score: f64 }

impl VtScore {
    pub fn new(score: f64) -> Self { Self { score: (score * 1000.0).round() / 1000.0 } }
    pub fn from_str(s: &str) -> Result<Self, std::num::ParseFloatError> { Ok(Self { score: s.parse()? }) }
    pub fn score(&self) -> f64 { self.score }
    pub fn log10_score(&self) -> f64 { self.score.log10() }
    pub fn formatted_score(&self) -> String { format!("{:.3}", self.score) }
    pub fn to_storage_string(&self) -> String { self.score.to_string() }
}

impl PartialEq for VtScore { fn eq(&self, other: &Self) -> bool { self.score == other.score } }
impl Eq for VtScore {}
impl PartialOrd for VtScore { fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) } }
impl Ord for VtScore { fn cmp(&self, other: &Self) -> std::cmp::Ordering { self.score.partial_cmp(&other.score).unwrap_or(std::cmp::Ordering::Equal) } }
impl fmt::Display for VtScore { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.formatted_score()) } }

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VtMatchTag { name: String }

impl VtMatchTag {
    pub fn new(name: impl Into<String>) -> Self { Self { name: name.into() } }
    pub fn name(&self) -> &str { &self.name }
    pub fn untagged() -> Self { Self { name: String::new() } }
    pub fn is_untagged(&self) -> bool { self.name.is_empty() }
}

impl PartialOrd for VtMatchTag { fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) } }
impl Ord for VtMatchTag { fn cmp(&self, other: &Self) -> std::cmp::Ordering { self.name.cmp(&other.name) } }
impl fmt::Display for VtMatchTag { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { if self.is_untagged() { write!(f, "<Not Tagged>") } else { write!(f, "{}", self.name) } } }

#[derive(Debug, Clone)]
pub struct VtMatchInfo {
    pub association_type: VtAssociationType,
    pub similarity_score: VtScore,
    pub confidence_score: VtScore,
    pub source_length: u64,
    pub destination_length: u64,
    pub length_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_association_status() {
        assert!(VtAssociationStatus::Available.can_apply());
        assert!(!VtAssociationStatus::Blocked.can_apply());
        assert!(VtAssociationStatus::Blocked.is_blocked());
    }

    #[test]
    fn test_markup_item_status() {
        assert!(VtMarkupItemStatus::Unapplied.is_appliable());
        assert!(!VtMarkupItemStatus::Added.is_appliable());
        assert!(VtMarkupItemStatus::Added.is_unappliable());
    }

    #[test]
    fn test_apply_action_types() {
        assert_eq!(VtMarkupItemApplyActionType::Add.apply_status(), VtMarkupItemStatus::Added);
        assert_eq!(VtMarkupItemApplyActionType::Replace.apply_status(), VtMarkupItemStatus::Replaced);
    }

    #[test]
    fn test_considered_status() {
        assert_eq!(VtMarkupItemConsideredStatus::Reject.markup_item_status(), VtMarkupItemStatus::Rejected);
    }

    #[test]
    fn test_vt_score() {
        let s = VtScore::new(0.123456);
        assert!((s.score() - 0.123).abs() < 0.001);
        assert!(VtScore::new(1.0) > VtScore::new(0.5));
    }

    #[test]
    fn test_match_tag() {
        let tag = VtMatchTag::new("verified");
        assert_eq!(tag.name(), "verified");
        assert!(!tag.is_untagged());
        let untagged = VtMatchTag::untagged();
        assert!(untagged.is_untagged());
    }
}
