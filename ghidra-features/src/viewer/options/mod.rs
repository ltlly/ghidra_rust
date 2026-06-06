//! Viewer options -- ported from `ghidra.app.util.viewer.options`.
//!
//! Display options for the listing viewer.

/// Options for controlling listing display behavior.
///
/// Ported from `OptionsGui.java` and related option classes.
#[derive(Debug, Clone)]
pub struct ListingOptions {
    /// Whether to show address fields.
    pub show_addresses: bool,
    /// Whether to show bytes fields.
    pub show_bytes: bool,
    /// Whether to show EOL comments.
    pub show_eol_comments: bool,
    /// Whether to show plate comments.
    pub show_plate_comments: bool,
    /// Whether to show pre-comments.
    pub show_pre_comments: bool,
    /// Whether to show post-comments.
    pub show_post_comments: bool,
    /// Whether to show repeating labels.
    pub show_repeating_labels: bool,
    /// Whether to show instruction signatures.
    pub show_signatures: bool,
    /// The maximum number of comment lines per code unit.
    pub max_comment_lines: usize,
    /// Whether to display in condensed mode.
    pub condensed: bool,
}

impl Default for ListingOptions {
    fn default() -> Self {
        Self {
            show_addresses: true,
            show_bytes: false,
            show_eol_comments: true,
            show_plate_comments: true,
            show_pre_comments: true,
            show_post_comments: true,
            show_repeating_labels: true,
            show_signatures: false,
            max_comment_lines: 5,
            condensed: false,
        }
    }
}

impl ListingOptions {
    /// Create new default options.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create options for a minimal display (only addresses and mnemonics).
    pub fn minimal() -> Self {
        Self {
            show_addresses: true,
            show_bytes: false,
            show_eol_comments: false,
            show_plate_comments: false,
            show_pre_comments: false,
            show_post_comments: false,
            show_repeating_labels: false,
            show_signatures: false,
            max_comment_lines: 1,
            condensed: true,
        }
    }

    /// Create options for a verbose display.
    pub fn verbose() -> Self {
        Self {
            show_bytes: true,
            show_signatures: true,
            max_comment_lines: 10,
            ..Self::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_options() {
        let opts = ListingOptions::default();
        assert!(opts.show_addresses);
        assert!(!opts.show_bytes);
        assert!(opts.show_eol_comments);
        assert_eq!(opts.max_comment_lines, 5);
    }

    #[test]
    fn test_minimal_options() {
        let opts = ListingOptions::minimal();
        assert!(opts.condensed);
        assert!(!opts.show_eol_comments);
    }

    #[test]
    fn test_verbose_options() {
        let opts = ListingOptions::verbose();
        assert!(opts.show_bytes);
        assert!(opts.show_signatures);
        assert_eq!(opts.max_comment_lines, 10);
    }
}
