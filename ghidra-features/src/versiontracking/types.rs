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

/// Bitfield-based association markup status.
///
/// Tracks the aggregate status of all markup items within an association.
/// Each bit represents a different status condition.
///
/// Corresponds to Ghidra's `VTAssociationMarkupStatus` Java class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VtAssociationMarkupStatus {
    status: i32,
}

const INITIALIZED: i32 = 0x1;
const HAS_UNEXAMINED: i32 = 0x2;
const HAS_APPLIED: i32 = 0x4;
const HAS_REJECTED: i32 = 0x8;
const HAS_DONT_CARE: i32 = 0x10;
const HAS_DONT_KNOW: i32 = 0x20;
const HAS_ERRORS: i32 = 0x40;

impl VtAssociationMarkupStatus {
    /// Create a new uninitialized status.
    pub fn new_none() -> Self { Self { status: 0 } }

    /// Create a status from individual flags.
    pub fn new(has_unexamined: bool, has_applied: bool, has_rejected: bool,
               has_dont_care: bool, has_dont_know: bool, has_errors: bool) -> Self {
        let mut status = INITIALIZED;
        if has_unexamined { status |= HAS_UNEXAMINED; }
        if has_applied { status |= HAS_APPLIED; }
        if has_rejected { status |= HAS_REJECTED; }
        if has_dont_care { status |= HAS_DONT_CARE; }
        if has_dont_know { status |= HAS_DONT_KNOW; }
        if has_errors { status |= HAS_ERRORS; }
        Self { status }
    }

    /// Create from raw status value.
    pub fn from_value(status: i32) -> Self { Self { status } }

    /// Returns the raw status value.
    pub fn status_value(&self) -> i32 { self.status }

    /// Whether the status has been initialized (set on an accepted association).
    pub fn is_initialized(&self) -> bool { (self.status & INITIALIZED) != 0 }

    /// Whether there are markup items that have not been examined.
    pub fn has_unexamined_markups(&self) -> bool { (self.status & HAS_UNEXAMINED) != 0 }

    /// Whether there are applied markup items.
    pub fn has_applied_markup(&self) -> bool { (self.status & HAS_APPLIED) != 0 }

    /// Whether there are rejected markup items.
    pub fn has_rejected_markup(&self) -> bool { (self.status & HAS_REJECTED) != 0 }

    /// Whether there are "Don't Care" markup items.
    pub fn has_dont_care_markup(&self) -> bool { (self.status & HAS_DONT_CARE) != 0 }

    /// Whether there are "Don't Know" markup items.
    pub fn has_dont_know_markup(&self) -> bool { (self.status & HAS_DONT_KNOW) != 0 }

    /// Whether there are markup items that failed to apply.
    pub fn has_errors(&self) -> bool { (self.status & HAS_ERRORS) != 0 }

    /// Whether all markup items have been applied.
    pub fn is_fully_applied(&self) -> bool {
        self.status == INITIALIZED || self.status == (INITIALIZED | HAS_APPLIED)
    }

    /// Returns a human-readable description.
    pub fn description(&self) -> String {
        let mut parts = Vec::new();
        if self.has_unexamined_markups() { parts.push("Has one or more unexamined markup items."); }
        if self.has_applied_markup() { parts.push("Has one or more applied markup items."); }
        if self.has_errors() { parts.push("Has one or more markup items that failed to apply."); }
        if self.has_dont_care_markup() { parts.push("Has one or more \"Don't Care\" markup items."); }
        if self.has_dont_know_markup() { parts.push("Has one or more \"Don't Know\" markup items."); }
        if self.has_rejected_markup() { parts.push("Has one or more rejected markup items."); }
        parts.join("\n")
    }
}

impl PartialOrd for VtAssociationMarkupStatus {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) }
}

impl Ord for VtAssociationMarkupStatus {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering { self.status.cmp(&other.status) }
}

impl fmt::Display for VtAssociationMarkupStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Markup Status: {}", self.description())
    }
}

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
