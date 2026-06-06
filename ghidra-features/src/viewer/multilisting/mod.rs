//! Multi-listing support -- ported from `ghidra.app.util.viewer.multilisting`.
//!
//! Supports synchronized side-by-side listings.

/// A multi-listing panel that displays two synchronized listing views.
///
/// Ported from `MultiListingPanel.java`.
#[derive(Debug)]
pub struct MultiListingPanel {
    /// The name of the primary listing.
    primary_name: String,
    /// The name of the secondary listing.
    secondary_name: String,
    /// Whether the listings are synchronized.
    synchronized: bool,
}

impl MultiListingPanel {
    /// Create a new multi-listing panel.
    pub fn new(primary_name: &str, secondary_name: &str) -> Self {
        Self {
            primary_name: primary_name.to_string(),
            secondary_name: secondary_name.to_string(),
            synchronized: true,
        }
    }

    /// Get the primary listing name.
    pub fn primary_name(&self) -> &str {
        &self.primary_name
    }

    /// Get the secondary listing name.
    pub fn secondary_name(&self) -> &str {
        &self.secondary_name
    }

    /// Returns true if the listings are synchronized.
    pub fn is_synchronized(&self) -> bool {
        self.synchronized
    }

    /// Set whether the listings are synchronized.
    pub fn set_synchronized(&mut self, synchronized: bool) {
        self.synchronized = synchronized;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_listing() {
        let mut panel = MultiListingPanel::new("Original", "Modified");
        assert_eq!(panel.primary_name(), "Original");
        assert_eq!(panel.secondary_name(), "Modified");
        assert!(panel.is_synchronized());

        panel.set_synchronized(false);
        assert!(!panel.is_synchronized());
    }
}
