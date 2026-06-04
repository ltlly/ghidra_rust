//! Conflict formatting and merge utilities.
//!
//! Ports Ghidra's `ConflictUtility` and `MergeUtilities` classes.

use crate::base::merge::constants::TRUNCATE_LENGTH;

// ============================================================================
// ConflictUtility
// ============================================================================

// --- HTML color constants ---

/// Maroon color (`#990000`).
pub const MAROON: &str = "#990000";
/// Green color (`#009900`).
pub const GREEN: &str = "#009900";
/// Blue color (`#000099`).
pub const BLUE: &str = "#000099";
/// Purple color (`#990099`).
pub const PURPLE: &str = "#990099";
/// Dark cyan color (`#009999`).
pub const DARK_CYAN: &str = "#009999";
/// Olive color (`#999900`).
pub const OLIVE: &str = "#999900";
/// Orange color (`#FF9900`).
pub const ORANGE: &str = "#FF9900";
/// Pink color (`#FF9999`).
pub const PINK: &str = "#FF9999";
/// Yellow color (`#FFFF00`).
pub const YELLOW: &str = "#FFFF00";
/// Gray color (`#888888`).
pub const GRAY: &str = "#888888";

/// Color for displaying addresses.
pub const ADDRESS_COLOR: &str = MAROON;
/// Color for displaying numeric values.
pub const NUMBER_COLOR: &str = MAROON;
/// Color for displaying emphasized text (e.g., symbols).
pub const EMPHASIZE_COLOR: &str = MAROON;
/// Color for displaying offsets.
pub const OFFSET_COLOR: &str = MAROON;

/// Text displayed when a version doesn't have a value for an element.
pub const NO_VALUE: &str = "-- No Value --";

/// Wrap text in HTML and BODY tags.
pub fn wrap_as_html(text: &str) -> String {
    format!("<html><body>{}</body></html>", text)
}

/// Color a text string using an HTML font tag.
pub fn color_string(rgb_color: &str, text: &str) -> String {
    format!("<font color=\"{}\">{}</font>", rgb_color, text)
}

/// Color an integer using an HTML font tag.
pub fn color_string_int(rgb_color: &str, value: i32) -> String {
    format!("<font color=\"{}\">{}</font>", rgb_color, value)
}

/// Create a string of `n` non-breaking spaces for HTML.
pub fn html_spaces(num: usize) -> String {
    "&nbsp;".repeat(num)
}

/// Create a colored number string (as HTML).
pub fn get_number_string(count: i32) -> String {
    color_string_int(NUMBER_COLOR, count)
}

/// Create a colored address string (as HTML).
pub fn get_address_string(address: &str) -> String {
    color_string(ADDRESS_COLOR, address)
}

/// Create a colored offset string displayed in hexadecimal.
pub fn get_offset_string(offset: i32) -> String {
    let hex = if offset >= 0 {
        format!("0x{:x}", offset)
    } else {
        format!("-0x{:x}", -offset)
    };
    color_string(OFFSET_COLOR, &hex)
}

/// Create a colored hash string displayed as unsigned hex.
pub fn get_hash_string(hash: u64) -> String {
    color_string(NUMBER_COLOR, &format!("0x{:x}", hash))
}

/// Create a colored emphasized string (as HTML).
pub fn get_emphasize_string(text: &str) -> String {
    color_string(EMPHASIZE_COLOR, text)
}

/// Generate a conflict count message: `"Conflict #1 of 5"`.
pub fn get_conflict_count(conflict_num: i32, total_conflicts: i32) -> String {
    format!(
        "Conflict #{} of {}",
        get_number_string(conflict_num),
        get_number_string(total_conflicts)
    )
}

/// Generate a conflict count message with an address: `"Conflict #1 of 5 @ address: 0x1000"`.
pub fn get_conflict_count_with_address(
    conflict_num: i32,
    total_conflicts: i32,
    address: &str,
) -> String {
    format!(
        "{} @ address: {}",
        get_conflict_count(conflict_num, total_conflicts),
        get_address_string(address)
    )
}

/// Generate a conflict count message for an address range.
pub fn get_conflict_count_with_range(
    conflict_num: i32,
    total_conflicts: i32,
    min_addr: &str,
    max_addr: &str,
) -> String {
    format!(
        "{} for address range: {}-{}",
        get_conflict_count(conflict_num, total_conflicts),
        get_address_string(min_addr),
        get_address_string(max_addr)
    )
}

/// Generate an address conflict count message.
pub fn get_address_conflict_count(
    address_num: i32,
    total_addresses: i32,
    is_range: bool,
) -> String {
    let prefix = if is_range {
        "Address range #"
    } else {
        "Address #"
    };
    format!(
        "{}{} of {} with conflicts",
        prefix,
        get_number_string(address_num),
        get_number_string(total_addresses)
    )
}

/// Replace newlines with HTML `<br>` tags.
pub fn replace_newlines(text: &str) -> String {
    text.replace('\n', "<br>")
}

/// Truncate a string and wrap it in HTML, replacing newlines.
pub fn get_truncated_html_string(original: &str, trunc_length: usize) -> String {
    let truncated = if original.len() > trunc_length {
        let end = trunc_length.saturating_sub(3);
        format!("{}...", &original[..end])
    } else {
        original.to_string()
    };
    wrap_as_html(&replace_newlines(&truncated))
}

/// Convenience overload using the default [`TRUNCATE_LENGTH`].
pub fn get_truncated_html_string_default(original: &str) -> String {
    get_truncated_html_string(original, TRUNCATE_LENGTH)
}

// ============================================================================
// MergeUtilities
// ============================================================================

/// Partition `my_diffs` into auto-changes and conflict-changes by comparing
/// against `latest_diffs`.
///
/// This is the direct port of Ghidra's `MergeUtilities.adjustSets()`:
///
/// - `auto_changes` receives addresses present in `my_diffs` but NOT in `latest_diffs`.
/// - `conflict_changes` receives addresses present in both `my_diffs` AND `latest_diffs`.
///
/// Both output sets are additive (existing entries are preserved).
pub fn adjust_address_sets(
    latest_diffs: &[(u64, u64)],
    my_diffs: &[(u64, u64)],
    auto_changes: &mut Vec<(u64, u64)>,
    conflict_changes: &mut Vec<(u64, u64)>,
) {
    // Collect auto-changes: ranges in my_diffs that do not overlap any range in latest_diffs.
    let mut auto_ranges = Vec::new();
    let mut conflict_ranges = Vec::new();

    for &(my_start, my_end) in my_diffs {
        let mut overlaps = false;
        for &(late_start, late_end) in latest_diffs {
            if ranges_overlap(my_start, my_end, late_start, late_end) {
                overlaps = true;
                break;
            }
        }
        if overlaps {
            conflict_ranges.push((my_start, my_end));
        } else {
            auto_ranges.push((my_start, my_end));
        }
    }

    auto_changes.extend(auto_ranges);
    conflict_changes.extend(conflict_ranges);
}

/// Check if two inclusive address ranges `[start1, end1]` and `[start2, end2]` overlap.
fn ranges_overlap(start1: u64, end1: u64, start2: u64, end2: u64) -> bool {
    start1 <= end2 && start2 <= end1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_string() {
        let colored = color_string("#FF0000", "hello");
        assert_eq!(colored, "<font color=\"#FF0000\">hello</font>");
    }

    #[test]
    fn test_color_string_int() {
        let colored = color_string_int(MAROON, 42);
        assert_eq!(colored, "<font color=\"#990000\">42</font>");
    }

    #[test]
    fn test_wrap_as_html() {
        let html = wrap_as_html("test");
        assert_eq!(html, "<html><body>test</body></html>");
    }

    #[test]
    fn test_html_spaces() {
        assert_eq!(html_spaces(0), "");
        assert_eq!(html_spaces(1), "&nbsp;");
        assert_eq!(html_spaces(3), "&nbsp;&nbsp;&nbsp;");
    }

    #[test]
    fn test_get_conflict_count() {
        let msg = get_conflict_count(1, 5);
        assert!(msg.contains("Conflict #"));
        assert!(msg.contains("of"));
    }

    #[test]
    fn test_get_conflict_count_with_address() {
        let msg = get_conflict_count_with_address(2, 10, "0x401000");
        assert!(msg.contains("@ address:"));
    }

    #[test]
    fn test_get_truncated_html_string_short() {
        let result = get_truncated_html_string("short", 100);
        assert!(result.contains("short"));
        assert!(result.contains("<html>"));
    }

    #[test]
    fn test_get_truncated_html_string_long() {
        let long_text = "a".repeat(200);
        let result = get_truncated_html_string(&long_text, 50);
        assert!(result.contains("..."));
    }

    #[test]
    fn test_replace_newlines() {
        assert_eq!(replace_newlines("a\nb\nc"), "a<br>b<br>c");
    }

    #[test]
    fn test_get_offset_string_positive() {
        let s = get_offset_string(255);
        assert!(s.contains("0xff"));
    }

    #[test]
    fn test_get_offset_string_negative() {
        let s = get_offset_string(-16);
        assert!(s.contains("-0x10"));
    }

    #[test]
    fn test_get_hash_string() {
        let s = get_hash_string(0xDEADBEEF);
        assert!(s.contains("0xdeadbeef"));
    }

    #[test]
    fn test_ranges_overlap() {
        assert!(ranges_overlap(0, 10, 5, 15));
        assert!(ranges_overlap(5, 15, 0, 10));
        assert!(ranges_overlap(0, 10, 0, 10));
        assert!(!ranges_overlap(0, 5, 6, 10));
        assert!(!ranges_overlap(6, 10, 0, 5));
        // Adjacent but not overlapping (since both are inclusive).
        assert!(!ranges_overlap(0, 5, 6, 10));
    }

    #[test]
    fn test_adjust_address_sets_no_overlap() {
        let latest = vec![(0, 10)];
        let mine = vec![(20, 30)];
        let mut auto = Vec::new();
        let mut conflict = Vec::new();
        adjust_address_sets(&latest, &mine, &mut auto, &mut conflict);
        assert_eq!(auto, vec![(20, 30)]);
        assert!(conflict.is_empty());
    }

    #[test]
    fn test_adjust_address_sets_with_overlap() {
        let latest = vec![(0, 10)];
        let mine = vec![(5, 15), (30, 40)];
        let mut auto = Vec::new();
        let mut conflict = Vec::new();
        adjust_address_sets(&latest, &mine, &mut auto, &mut conflict);
        assert_eq!(auto, vec![(30, 40)]);
        assert_eq!(conflict, vec![(5, 15)]);
    }

    #[test]
    fn test_adjust_address_sets_empty() {
        let latest: Vec<(u64, u64)> = vec![];
        let mine: Vec<(u64, u64)> = vec![];
        let mut auto = Vec::new();
        let mut conflict = Vec::new();
        adjust_address_sets(&latest, &mine, &mut auto, &mut conflict);
        assert!(auto.is_empty());
        assert!(conflict.is_empty());
    }
}
