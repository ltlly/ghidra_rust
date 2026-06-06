//! Listing panel -- the main code browser display panel.
//!
//! Ported from `ghidra.app.util.viewer.listingpanel`.
//!
//! - [`ListingPanel`] -- the main panel for displaying program listings
//! - [`AddressBasedPanelView`] -- trait for panels that display address-based content

/// Trait for panels that display content based on program addresses.
pub trait AddressBasedPanelView {
    /// Go to the given address.
    fn go_to(&mut self, address: u64);

    /// Get the current address being displayed.
    fn current_address(&self) -> Option<u64>;

    /// Set the program to display.
    fn set_program(&mut self, program_name: &str);

    /// Get the current program name.
    fn program_name(&self) -> Option<&str>;
}

/// The main listing panel for displaying program code and data.
///
/// Ported from `ListingPanel.java`.
#[derive(Debug)]
pub struct ListingPanel {
    /// The name of the current program.
    program_name: Option<String>,
    /// The current address being viewed.
    current_address: Option<u64>,
    /// Whether the panel is in overview mode.
    overview_mode: bool,
    /// The listing font size in points.
    font_size: f32,
    /// Line height in pixels.
    line_height: f32,
}

impl ListingPanel {
    /// Create a new listing panel.
    pub fn new() -> Self {
        Self {
            program_name: None,
            current_address: None,
            overview_mode: false,
            font_size: 12.0,
            line_height: 16.0,
        }
    }

    /// Get the current program name.
    pub fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }

    /// Get the current address.
    pub fn current_address(&self) -> Option<u64> {
        self.current_address
    }

    /// Get the font size.
    pub fn font_size(&self) -> f32 {
        self.font_size
    }

    /// Set the font size.
    pub fn set_font_size(&mut self, size: f32) {
        self.font_size = size.max(1.0);
        self.line_height = self.font_size * 1.4;
    }

    /// Get the line height.
    pub fn line_height(&self) -> f32 {
        self.line_height
    }

    /// Returns true if in overview mode.
    pub fn is_overview_mode(&self) -> bool {
        self.overview_mode
    }

    /// Set overview mode.
    pub fn set_overview_mode(&mut self, overview: bool) {
        self.overview_mode = overview;
    }
}

impl Default for ListingPanel {
    fn default() -> Self {
        Self::new()
    }
}

impl AddressBasedPanelView for ListingPanel {
    fn go_to(&mut self, address: u64) {
        self.current_address = Some(address);
    }

    fn current_address(&self) -> Option<u64> {
        self.current_address
    }

    fn set_program(&mut self, program_name: &str) {
        self.program_name = Some(program_name.to_string());
        self.current_address = None;
    }

    fn program_name(&self) -> Option<&str> {
        self.program_name.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_listing_panel() {
        let mut panel = ListingPanel::new();
        assert!(panel.program_name().is_none());
        assert!(panel.current_address().is_none());

        panel.set_program("test.exe");
        assert_eq!(panel.program_name(), Some("test.exe"));

        panel.go_to(0x401000);
        assert_eq!(panel.current_address(), Some(0x401000));
    }

    #[test]
    fn test_font_size() {
        let mut panel = ListingPanel::new();
        panel.set_font_size(14.0);
        assert_eq!(panel.font_size(), 14.0);
        assert!((panel.line_height() - 19.6).abs() < 0.1);
    }

    #[test]
    fn test_overview_mode() {
        let mut panel = ListingPanel::new();
        assert!(!panel.is_overview_mode());
        panel.set_overview_mode(true);
        assert!(panel.is_overview_mode());
    }

    #[test]
    fn test_program_change_resets_address() {
        let mut panel = ListingPanel::new();
        panel.set_program("test.exe");
        panel.go_to(0x401000);
        panel.set_program("other.exe");
        assert!(panel.current_address().is_none());
    }
}
