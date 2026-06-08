//! Address correlator factory for cross-architecture comparison.
//!
//! Ported from Ghidra's `CodeCompareAddressCorrelator` Java class in
//! `ghidra.features.codecompare.correlator`.
//!
//! The `CodeCompareAddressCorrelator` is a factory that creates
//! `AddressCorrelation` instances for comparing functions from two
//! different programs. It is designed for cross-architecture comparison
//! and returns `None` when both functions come from programs with the
//! same language (architecture), since simpler correlators should be
//! used in that case.
//!
//! # Key types
//!
//! - [`CorrelatorPriority`] -- priority levels for correlator ordering
//! - [`CorrelatorOptions`] -- configuration for the correlator
//! - [`CodeCompareAddressCorrelator`] -- the main correlator factory

use super::address_correlation::CodeCompareAddressCorrelation;

/// Priority levels for address correlators.
///
/// Ghidra uses priority to determine the order in which correlators are
/// tried. Lower numeric values mean higher priority (tried first).
///
/// Ported from the priority constants in Ghidra's `AddressCorrelator` interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CorrelatorPriority {
    /// Highest priority -- tried first.
    Highest,
    /// High priority.
    High,
    /// Normal priority (default).
    Normal,
    /// Low priority.
    Low,
    /// Late chance priority -- tried just before the last resort.
    LateChance,
    /// Lowest priority -- last resort.
    Lowest,
}

impl CorrelatorPriority {
    /// Get the numeric priority value.
    ///
    /// Lower values mean higher priority.
    pub fn value(&self) -> i32 {
        match self {
            Self::Highest => 0,
            Self::High => 100,
            Self::Normal => 200,
            Self::Low => 300,
            Self::LateChance => 400,
            Self::Lowest => 500,
        }
    }

    /// The priority offset used by Ghidra's priority system.
    pub const PRIORITY_OFFSET: i32 = 10;

    /// Late chance priority value (from Ghidra's `AddressCorrelator` interface).
    pub const LATE_CHANCE_PRIORITY: i32 = 400;
}

/// Configuration for the code compare address correlator.
///
/// Ported from the options handling in Ghidra's `CodeCompareAddressCorrelator`.
#[derive(Debug, Clone)]
pub struct CorrelatorOptions {
    /// Timeout in seconds for decompilation.
    pub timeout_seconds: u32,
    /// Whether to match constants exactly.
    pub match_constants_exactly: bool,
    /// Whether to collapse sizes when architectures differ.
    pub size_collapse: bool,
    /// Whether to enable debug output.
    pub debug_enabled: bool,
}

impl CorrelatorOptions {
    /// Create new options with default values.
    pub fn new() -> Self {
        Self {
            timeout_seconds: 60,
            match_constants_exactly: false,
            size_collapse: true,
            debug_enabled: false,
        }
    }

    /// Set the timeout in seconds.
    pub fn with_timeout(mut self, seconds: u32) -> Self {
        self.timeout_seconds = seconds;
        self
    }

    /// Set whether to match constants exactly.
    pub fn with_match_constants_exactly(mut self, exact: bool) -> Self {
        self.match_constants_exactly = exact;
        self
    }

    /// Set whether to collapse sizes.
    pub fn with_size_collapse(mut self, collapse: bool) -> Self {
        self.size_collapse = collapse;
        self
    }

    /// Enable debug output.
    pub fn with_debug(mut self, enabled: bool) -> Self {
        self.debug_enabled = enabled;
        self
    }
}

impl Default for CorrelatorOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// The code compare address correlator factory.
///
/// Creates `CodeCompareAddressCorrelation` instances for comparing
/// functions from two different programs. This correlator is designed
/// for cross-architecture comparison and will return `None` when both
/// functions come from programs with the same language (architecture),
/// since simpler and faster correlators should be used in that case.
///
/// Ported from Ghidra's `CodeCompareAddressCorrelator` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::correlator::address_correlator::*;
///
/// let correlator = CodeCompareAddressCorrelator::new();
/// assert_eq!(correlator.name(), "CodeCompareAddressCorrelator");
/// assert_eq!(correlator.priority(), CorrelatorPriority::LateChance);
/// ```
#[derive(Debug)]
pub struct CodeCompareAddressCorrelator {
    /// Correlator name.
    name: String,
    /// Configuration options.
    options: CorrelatorOptions,
}

impl CodeCompareAddressCorrelator {
    /// Create a new code compare address correlator.
    pub fn new() -> Self {
        Self {
            name: "CodeCompareAddressCorrelator".to_string(),
            options: CorrelatorOptions::default(),
        }
    }

    /// Create a new correlator with custom options.
    pub fn with_options(options: CorrelatorOptions) -> Self {
        Self {
            name: "CodeCompareAddressCorrelator".to_string(),
            options,
        }
    }

    /// Get the correlator name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the correlator priority.
    ///
    /// This correlator runs just above the last chance priority,
    /// allowing it to serve as a fallback general-purpose correlator.
    pub fn priority(&self) -> CorrelatorPriority {
        CorrelatorPriority::LateChance
    }

    /// Get the numeric priority value.
    pub fn priority_value(&self) -> i32 {
        CorrelatorPriority::LATE_CHANCE_PRIORITY - CorrelatorPriority::PRIORITY_OFFSET
    }

    /// Get the options.
    pub fn options(&self) -> &CorrelatorOptions {
        &self.options
    }

    /// Get a mutable reference to the options.
    pub fn options_mut(&mut self) -> &mut CorrelatorOptions {
        &mut self.options
    }

    /// Check if this correlator is applicable for the given pair of architectures.
    ///
    /// Returns `true` only when the source and destination architectures differ.
    /// When both programs have the same language, simpler correlators should be used.
    pub fn is_applicable(&self, source_arch: &str, dest_arch: &str) -> bool {
        source_arch != dest_arch
    }

    /// Create a correlation for the given pair of functions.
    ///
    /// Returns `None` if the architectures are the same (simpler correlators
    /// should be used in that case).
    ///
    /// # Arguments
    ///
    /// * `source_name` - Name of the source function
    /// * `dest_name` - Name of the destination function
    /// * `source_arch` - Architecture ID of the source program
    /// * `dest_arch` - Architecture ID of the destination program
    pub fn correlate(
        &self,
        source_name: &str,
        dest_name: &str,
        source_arch: &str,
        dest_arch: &str,
    ) -> Option<CodeCompareAddressCorrelation> {
        if !self.is_applicable(source_arch, dest_arch) {
            return None;
        }

        Some(CodeCompareAddressCorrelation::new(
            source_name,
            dest_name,
            self.options.clone(),
        ))
    }
}

impl Default for CodeCompareAddressCorrelator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- CorrelatorPriority tests ---

    #[test]
    fn test_priority_ordering() {
        assert!(CorrelatorPriority::Highest < CorrelatorPriority::High);
        assert!(CorrelatorPriority::High < CorrelatorPriority::Normal);
        assert!(CorrelatorPriority::Normal < CorrelatorPriority::Low);
        assert!(CorrelatorPriority::Low < CorrelatorPriority::LateChance);
        assert!(CorrelatorPriority::LateChance < CorrelatorPriority::Lowest);
    }

    #[test]
    fn test_priority_values() {
        assert_eq!(CorrelatorPriority::Highest.value(), 0);
        assert_eq!(CorrelatorPriority::High.value(), 100);
        assert_eq!(CorrelatorPriority::Normal.value(), 200);
        assert_eq!(CorrelatorPriority::Low.value(), 300);
        assert_eq!(CorrelatorPriority::LateChance.value(), 400);
        assert_eq!(CorrelatorPriority::Lowest.value(), 500);
    }

    #[test]
    fn test_priority_constants() {
        assert_eq!(CorrelatorPriority::PRIORITY_OFFSET, 10);
        assert_eq!(CorrelatorPriority::LATE_CHANCE_PRIORITY, 400);
    }

    // --- CorrelatorOptions tests ---

    #[test]
    fn test_options_default() {
        let opts = CorrelatorOptions::default();
        assert_eq!(opts.timeout_seconds, 60);
        assert!(!opts.match_constants_exactly);
        assert!(opts.size_collapse);
        assert!(!opts.debug_enabled);
    }

    #[test]
    fn test_options_builder() {
        let opts = CorrelatorOptions::new()
            .with_timeout(120)
            .with_match_constants_exactly(true)
            .with_size_collapse(false)
            .with_debug(true);

        assert_eq!(opts.timeout_seconds, 120);
        assert!(opts.match_constants_exactly);
        assert!(!opts.size_collapse);
        assert!(opts.debug_enabled);
    }

    // --- CodeCompareAddressCorrelator tests ---

    #[test]
    fn test_correlator_new() {
        let correlator = CodeCompareAddressCorrelator::new();
        assert_eq!(correlator.name(), "CodeCompareAddressCorrelator");
    }

    #[test]
    fn test_correlator_priority() {
        let correlator = CodeCompareAddressCorrelator::new();
        assert_eq!(correlator.priority(), CorrelatorPriority::LateChance);
        assert_eq!(correlator.priority_value(), 390);
    }

    #[test]
    fn test_correlator_is_applicable_different_arch() {
        let correlator = CodeCompareAddressCorrelator::new();
        assert!(correlator.is_applicable("x86", "ARM"));
        assert!(correlator.is_applicable("x86:LE:64:default", "ARM:LE:32:v8"));
    }

    #[test]
    fn test_correlator_is_applicable_same_arch() {
        let correlator = CodeCompareAddressCorrelator::new();
        assert!(!correlator.is_applicable("x86", "x86"));
        assert!(!correlator.is_applicable("ARM:LE:32:v8", "ARM:LE:32:v8"));
    }

    #[test]
    fn test_correlator_correlate_different_arch() {
        let correlator = CodeCompareAddressCorrelator::new();
        let result = correlator.correlate("main", "main_recompiled", "x86", "ARM");
        assert!(result.is_some());

        let correlation = result.unwrap();
        assert_eq!(correlation.source_name(), "main");
        assert_eq!(correlation.dest_name(), "main_recompiled");
    }

    #[test]
    fn test_correlator_correlate_same_arch() {
        let correlator = CodeCompareAddressCorrelator::new();
        let result = correlator.correlate("main", "main_v2", "x86", "x86");
        assert!(result.is_none());
    }

    #[test]
    fn test_correlator_with_options() {
        let opts = CorrelatorOptions::new()
            .with_timeout(30)
            .with_debug(true);

        let correlator = CodeCompareAddressCorrelator::with_options(opts);
        assert_eq!(correlator.options().timeout_seconds, 30);
        assert!(correlator.options().debug_enabled);
    }

    #[test]
    fn test_correlator_options_mut() {
        let mut correlator = CodeCompareAddressCorrelator::new();
        correlator.options_mut().timeout_seconds = 120;
        assert_eq!(correlator.options().timeout_seconds, 120);
    }

    #[test]
    fn test_correlator_default() {
        let correlator = CodeCompareAddressCorrelator::default();
        assert_eq!(correlator.name(), "CodeCompareAddressCorrelator");
    }
}
