//! Shared configuration options for the Data Graph plugin.
//!
//! Ported from Ghidra's `datagraph.DegSharedConfig` Java class.
//!
//! Provides simple storage of shared data-graph configuration states. If any
//! provider changes any of these values, that becomes the value going forward
//! (last-write-wins).

/// Persistence keys used when reading / writing option state.
mod keys {
    pub const NAVIGATE_IN: &str = "Navigate In";
    pub const NAVIGATE_OUT: &str = "Navigate Out";
    pub const COMPACT_FORMAT: &str = "Compact Format";
    pub const SHOW_POPUPS: &str = "Show Popups";
}

/// Shared display options for the Data Graph.
///
/// Ported from `datagraph.DegSharedConfig`.
///
/// Each field mirrors a user-togglable setting.  The struct is cheap to clone
/// so that providers can snapshot the current options at creation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataGraphOptions {
    /// Navigate to the vertex matching an incoming tool location change.
    navigate_in: bool,
    /// Send outgoing navigation events when the user selects a vertex.
    navigate_out: bool,
    /// Show popups / tooltips on graph vertices.
    show_popups: bool,
    /// Use compact (true) or expanded (false) format inside data vertices.
    use_compact_format: bool,
}

impl DataGraphOptions {
    /// Create options with the Ghidra default values.
    pub fn new() -> Self {
        Self {
            navigate_in: false,
            navigate_out: true,
            show_popups: true,
            use_compact_format: true,
        }
    }

    // -- navigate_in -------------------------------------------------------

    /// Whether incoming location changes should navigate the graph.
    pub fn is_navigate_in(&self) -> bool {
        self.navigate_in
    }

    /// Set whether incoming location changes should navigate the graph.
    pub fn set_navigate_in(&mut self, value: bool) {
        self.navigate_in = value;
    }

    // -- navigate_out ------------------------------------------------------

    /// Whether selecting a vertex should navigate the tool.
    pub fn is_navigate_out(&self) -> bool {
        self.navigate_out
    }

    /// Set whether selecting a vertex should navigate the tool.
    pub fn set_navigate_out(&mut self, value: bool) {
        self.navigate_out = value;
    }

    // -- show_popups -------------------------------------------------------

    /// Whether popups / tooltips are visible.
    pub fn is_show_popups(&self) -> bool {
        self.show_popups
    }

    /// Set whether popups / tooltips are visible.
    pub fn set_show_popups(&mut self, value: bool) {
        self.show_popups = value;
    }

    // -- compact_format ----------------------------------------------------

    /// Whether data vertices use compact format.
    pub fn use_compact_format(&self) -> bool {
        self.use_compact_format
    }

    /// Set whether data vertices use compact format.
    pub fn set_compact_format(&mut self, value: bool) {
        self.use_compact_format = value;
    }

    // -- serialisation helpers --------------------------------------------

    /// Serialize the options into a flat list of `(key, value_bool)` pairs,
    /// suitable for persisting via a `SaveState`-like mechanism.
    pub fn to_pairs(&self) -> Vec<(&'static str, bool)> {
        vec![
            (keys::NAVIGATE_IN, self.navigate_in),
            (keys::NAVIGATE_OUT, self.navigate_out),
            (keys::COMPACT_FORMAT, self.use_compact_format),
            (keys::SHOW_POPUPS, self.show_popups),
        ]
    }

    /// Deserialize options from a flat list of `(key, value_bool)` pairs.
    /// Missing keys retain their defaults.
    pub fn from_pairs(pairs: &[(&str, bool)]) -> Self {
        let mut opts = Self::new();
        for &(k, v) in pairs {
            match k {
                keys::NAVIGATE_IN => opts.navigate_in = v,
                keys::NAVIGATE_OUT => opts.navigate_out = v,
                keys::COMPACT_FORMAT => opts.use_compact_format = v,
                keys::SHOW_POPUPS => opts.show_popups = v,
                _ => {}
            }
        }
        opts
    }
}

impl Default for DataGraphOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let opts = DataGraphOptions::new();
        assert!(!opts.is_navigate_in());
        assert!(opts.is_navigate_out());
        assert!(opts.is_show_popups());
        assert!(opts.use_compact_format());
    }

    #[test]
    fn test_setters() {
        let mut opts = DataGraphOptions::new();
        opts.set_navigate_in(true);
        assert!(opts.is_navigate_in());

        opts.set_navigate_out(false);
        assert!(!opts.is_navigate_out());

        opts.set_show_popups(false);
        assert!(!opts.is_show_popups());

        opts.set_compact_format(false);
        assert!(!opts.use_compact_format());
    }

    #[test]
    fn test_to_pairs_round_trip() {
        let mut opts = DataGraphOptions::new();
        opts.set_navigate_in(true);
        opts.set_compact_format(false);
        opts.set_show_popups(false);

        let pairs = opts.to_pairs();
        let restored = DataGraphOptions::from_pairs(&pairs);
        assert_eq!(opts, restored);
    }

    #[test]
    fn test_from_pairs_partial() {
        // Only set navigate_in; everything else should remain default.
        let pairs = vec![("Navigate In", true)];
        let opts = DataGraphOptions::from_pairs(&pairs);
        assert!(opts.is_navigate_in());
        assert!(opts.is_navigate_out()); // default
        assert!(opts.use_compact_format()); // default
    }

    #[test]
    fn test_from_pairs_unknown_key_ignored() {
        let pairs = vec![("Bogus Key", true)];
        let opts = DataGraphOptions::from_pairs(&pairs);
        // All defaults unchanged.
        assert_eq!(opts, DataGraphOptions::default());
    }

    #[test]
    fn test_clone_eq() {
        let a = DataGraphOptions::new();
        let b = a.clone();
        assert_eq!(a, b);
    }
}
