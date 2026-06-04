//! Merge and conflict resolution constants.
//!
//! Ports Ghidra's `MergeConstants` and `ListingMergeConstants` interfaces.

/// Version indices used throughout the merge system.
///
/// These identify the four program copies participating in a three-way merge:
/// RESULT (the target where changes are applied), LATEST (the checked-in
/// version), MY (the user's working copy), and ORIGINAL (the common ancestor).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MergeVersion {
    /// The target program where merged results are written.
    Result = 0,
    /// The latest version from version control.
    Latest = 1,
    /// The user's checked-out (modified) version.
    My = 2,
    /// The original common ancestor.
    Original = 3,
}

impl MergeVersion {
    /// Convert from integer constant (matching Ghidra's `MergeConstants.RESULT`, etc.).
    pub fn from_int(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::Result),
            1 => Some(Self::Latest),
            2 => Some(Self::My),
            3 => Some(Self::Original),
            _ => None,
        }
    }

    /// The display title for this version.
    pub fn title(&self) -> &'static str {
        match self {
            Self::Result => "Result",
            Self::Latest => "Latest",
            Self::My => "Checked Out",
            Self::Original => "Original",
        }
    }
}

impl std::fmt::Display for MergeVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.title())
    }
}

// --- Standardized resolve-information keys ---

/// Resolved latest data types.
pub const RESOLVED_LATEST_DTS: &str = "ResolvedLatestDataTypes";
/// Resolved my (checked-out) data types.
pub const RESOLVED_MY_DTS: &str = "ResolvedMyDataTypes";
/// Resolved original data types.
pub const RESOLVED_ORIGINAL_DTS: &str = "ResolvedOriginalDataTypes";
/// Resolved code units.
pub const RESOLVED_CODE_UNITS: &str = "ResolvedCodeUnits";
/// Picked latest code units.
pub const PICKED_LATEST_CODE_UNITS: &str = "PickedLatestCodeUnits";
/// Picked my code units.
pub const PICKED_MY_CODE_UNITS: &str = "PickedMyCodeUnits";
/// Picked original code units.
pub const PICKED_ORIGINAL_CODE_UNITS: &str = "PickedOriginalCodeUnits";
/// Resolved latest symbols.
pub const RESOLVED_LATEST_SYMBOLS: &str = "ResolvedLatestSymbols";
/// Resolved my symbols.
pub const RESOLVED_MY_SYMBOLS: &str = "ResolvedMySymbols";
/// Resolved original symbols.
pub const RESOLVED_ORIGINAL_SYMBOLS: &str = "ResolvedOriginalSymbols";

// ---------------------------------------------------------------------------
// ListingMergeConstants
// ---------------------------------------------------------------------------

/// Conflict option: the user canceled the merge.
pub const CANCELED: i32 = -1;
/// Conflict option: prompt the user for a response.
pub const ASK_USER: i32 = 0;
/// A row on the conflicts panel is strictly informational (no choice).
pub const INFO_ROW: i32 = 0;
/// Keep the Original program's information.
pub const KEEP_ORIGINAL: i32 = 1;
/// Keep the Latest program's information.
pub const KEEP_LATEST: i32 = 2;
/// Keep My (checked-out) program's information.
pub const KEEP_MY: i32 = 4;
/// Keep the Result program's existing information.
pub const KEEP_RESULT: i32 = 8;
/// Keep both the Latest and My program's information.
pub const KEEP_BOTH: i32 = KEEP_LATEST | KEEP_MY;
/// Keep the Original, Latest, and My program's information.
pub const KEEP_ALL: i32 = KEEP_LATEST | KEEP_MY | KEEP_ORIGINAL;
/// Remove the Latest program's conflict item.
pub const REMOVE_LATEST: i32 = 8;
/// Rename the conflict item as in Latest.
pub const RENAME_LATEST: i32 = 16;
/// Remove the My program's conflict item.
pub const REMOVE_MY: i32 = 32;
/// Rename the conflict item as in My.
pub const RENAME_MY: i32 = 64;

/// Maximum length before truncation in conflict panel display.
pub const TRUNCATE_LENGTH: usize = 160;

// --- GUI component name constants ---

/// Button name for the Latest list.
pub const LATEST_LIST_BUTTON_NAME: &str = "LatestListRB";
/// Button name for the Checked-Out list.
pub const CHECKED_OUT_LIST_BUTTON_NAME: &str = "CheckedOutListRB";
/// Radio button name for Latest version.
pub const LATEST_BUTTON_NAME: &str = "LatestVersionRB";
/// Radio button name for Checked-Out version.
pub const CHECKED_OUT_BUTTON_NAME: &str = "CheckedOutVersionRB";
/// Radio button name for Original version.
pub const ORIGINAL_BUTTON_NAME: &str = "OriginalVersionRB";
/// Radio button name for Result version.
pub const RESULT_BUTTON_NAME: &str = "ResultVersionRB";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_version_from_int() {
        assert_eq!(MergeVersion::from_int(0), Some(MergeVersion::Result));
        assert_eq!(MergeVersion::from_int(1), Some(MergeVersion::Latest));
        assert_eq!(MergeVersion::from_int(2), Some(MergeVersion::My));
        assert_eq!(MergeVersion::from_int(3), Some(MergeVersion::Original));
        assert_eq!(MergeVersion::from_int(4), None);
        assert_eq!(MergeVersion::from_int(-1), None);
    }

    #[test]
    fn test_merge_version_titles() {
        assert_eq!(MergeVersion::Result.title(), "Result");
        assert_eq!(MergeVersion::Latest.title(), "Latest");
        assert_eq!(MergeVersion::My.title(), "Checked Out");
        assert_eq!(MergeVersion::Original.title(), "Original");
    }

    #[test]
    fn test_merge_version_display() {
        assert_eq!(format!("{}", MergeVersion::Result), "Result");
        assert_eq!(format!("{}", MergeVersion::My), "Checked Out");
    }

    #[test]
    fn test_keep_both_is_latest_or_my() {
        assert_eq!(KEEP_BOTH, KEEP_LATEST | KEEP_MY);
    }

    #[test]
    fn test_keep_all() {
        assert_eq!(KEEP_ALL, KEEP_LATEST | KEEP_MY | KEEP_ORIGINAL);
    }
}
