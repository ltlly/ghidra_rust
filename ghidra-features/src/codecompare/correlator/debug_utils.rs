//! Debug utilities for the code comparison correlator.
//!
//! Ported from Ghidra's `DebugUtils` Java class in
//! `ghidra.features.codecompare.correlator`.
//!
//! Provides optional debugging and visualization support for
//! address correlation results. When enabled, records end-of-line
//! comments and colorizes code units to show correlation mappings.
//!
//! # Key types
//!
//! - [`DebugConfig`] -- configuration for debug output
//! - [`DebugCorrelationEntry`] -- a single debug correlation record
//! - [`DebugColor`] -- HSB-based color for correlation visualization
//! - [`DebugCorrelationLog`] -- a log of correlation events

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use super::{CorrelationKind, CorrelationRange};

/// Whether debug output is globally enabled.
static DEBUG_ENABLED: Mutex<bool> = Mutex::new(false);

/// Enable or disable debug output globally.
pub fn enable_debug(enabled: bool) {
    *DEBUG_ENABLED.lock().unwrap() = enabled;
}

/// Check if debug output is globally enabled.
pub fn is_debug_enabled() -> bool {
    *DEBUG_ENABLED.lock().unwrap()
}

/// A single debug correlation record.
///
/// Records how a source address range was correlated to a destination
/// address range, including the kind of correlation and the program
/// names involved.
#[derive(Debug, Clone)]
pub struct DebugCorrelationEntry {
    /// Source program name.
    pub source_program: String,
    /// Destination program name.
    pub dest_program: String,
    /// Source address range (start, end inclusive).
    pub source_range: (u64, u64),
    /// Destination address range (start, end inclusive).
    pub dest_range: (u64, u64),
    /// The kind of correlation.
    pub kind: CorrelationKind,
    /// Timestamp (Unix epoch millis) when this entry was recorded.
    pub timestamp: u64,
}

impl DebugCorrelationEntry {
    /// Create a new debug correlation entry.
    pub fn new(
        source_program: impl Into<String>,
        dest_program: impl Into<String>,
        source_range: (u64, u64),
        dest_range: (u64, u64),
        kind: CorrelationKind,
    ) -> Self {
        Self {
            source_program: source_program.into(),
            dest_program: dest_program.into(),
            source_range,
            dest_range,
            kind,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        }
    }

    /// Get the source address range size.
    pub fn source_size(&self) -> u64 {
        self.source_range.1 - self.source_range.0 + 1
    }

    /// Get the destination address range size.
    pub fn dest_size(&self) -> u64 {
        self.dest_range.1 - self.dest_range.0 + 1
    }
}

/// An HSB-based color for correlation visualization.
///
/// Maps correlation kinds to distinct hues and applies slight
/// randomization for visual distinction.
#[derive(Debug, Clone, Copy)]
pub struct DebugColor {
    /// Hue (0.0-1.0).
    pub hue: f32,
    /// Saturation (0.0-1.0).
    pub saturation: f32,
    /// Brightness (0.0-1.0).
    pub brightness: f32,
}

impl DebugColor {
    /// Create a new debug color.
    pub fn new(hue: f32, saturation: f32, brightness: f32) -> Self {
        Self {
            hue,
            saturation,
            brightness,
        }
    }

    /// Get the color for a given correlation kind.
    ///
    /// Uses the same hue mapping as Ghidra's `DebugUtils.pickColor`:
    /// - `CodeCompare` -> green (0.33)
    /// - `LCS` -> pink (0.9)
    /// - `Parameters` -> yellow-green (0.2)
    /// - Other -> red (0.1)
    pub fn for_kind(kind: CorrelationKind) -> Self {
        match kind {
            CorrelationKind::CodeCompare => Self::new(0.33, 0.4, 0.9),
            CorrelationKind::Lcs => Self::new(0.9, 0.4, 0.9),
            CorrelationKind::Parameters => Self::new(0.2, 0.8, 0.8),
            _ => Self::new(0.1, 1.0, 1.0),
        }
    }

    /// Convert to an ARGB integer (alpha = 0xFF).
    pub fn to_argb(&self) -> u32 {
        let (r, g, b) = hsb_to_rgb(self.hue, self.saturation, self.brightness);
        0xFF000000
            | ((r as u32) << 16)
            | ((g as u32) << 8)
            | (b as u32)
    }

    /// Convert to a CSS hex color string.
    pub fn to_hex(&self) -> String {
        let (r, g, b) = hsb_to_rgb(self.hue, self.saturation, self.brightness);
        format!("#{:02x}{:02x}{:02x}", r, g, b)
    }

    /// Apply slight randomization for visual distinction.
    pub fn randomized(&self, seed: u64) -> Self {
        // Simple LCG-based pseudo-random
        let r1 = lcg(seed);
        let r2 = lcg(r1);
        let sat_offset = (r1 as f32 / u64::MAX as f32 - 0.5) / 3.0;
        let bri_offset = (r2 as f32 / u64::MAX as f32 - 0.5) / 5.0;

        Self {
            hue: self.hue,
            saturation: (self.saturation + sat_offset).clamp(0.0, 1.0),
            brightness: (self.brightness + bri_offset).clamp(0.0, 1.0),
        }
    }
}

/// Simple LCG pseudo-random number generator.
fn lcg(seed: u64) -> u64 {
    seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407)
}

/// Convert HSB to RGB.
fn hsb_to_rgb(hue: f32, saturation: f32, brightness: f32) -> (u8, u8, u8) {
    let hue = hue % 1.0;
    let hue_degrees = hue * 360.0;

    let c = brightness * saturation;
    let x = c * (1.0 - ((hue_degrees / 60.0) % 2.0 - 1.0).abs());
    let m = brightness - c;

    let (r1, g1, b1) = if hue_degrees < 60.0 {
        (c, x, 0.0)
    } else if hue_degrees < 120.0 {
        (x, c, 0.0)
    } else if hue_degrees < 180.0 {
        (0.0, c, x)
    } else if hue_degrees < 240.0 {
        (0.0, x, c)
    } else if hue_degrees < 300.0 {
        (x, 0.0, c)
    } else {
        (c, 0.0, x)
    };

    (
        ((r1 + m) * 255.0).round() as u8,
        ((g1 + m) * 255.0).round() as u8,
        ((b1 + m) * 255.0).round() as u8,
    )
}

/// Configuration for debug output.
#[derive(Debug, Clone)]
pub struct DebugConfig {
    /// Whether debug is enabled.
    pub enabled: bool,
    /// Whether to use random colors for CodeCompare correlations.
    pub use_random_colors: bool,
    /// Whether to record EOL comments.
    pub record_comments: bool,
    /// Whether to colorize code units.
    pub colorize: bool,
}

impl DebugConfig {
    /// Create a new debug config with defaults (all disabled).
    pub fn new() -> Self {
        Self {
            enabled: false,
            use_random_colors: false,
            record_comments: false,
            colorize: false,
        }
    }

    /// Create a config with everything enabled.
    pub fn full() -> Self {
        Self {
            enabled: true,
            use_random_colors: false,
            record_comments: true,
            colorize: true,
        }
    }

    /// Enable or disable random colors for CodeCompare correlations.
    pub fn with_random_colors(mut self, random: bool) -> Self {
        self.use_random_colors = random;
        self
    }
}

impl Default for DebugConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// A colorization record: an address range to be colored.
#[derive(Debug, Clone)]
pub struct ColorizationRecord {
    /// The address range (start, end inclusive).
    pub range: (u64, u64),
    /// The ARGB color to apply.
    pub color: u32,
    /// The correlation kind that produced this record.
    pub kind: CorrelationKind,
}

/// A log of correlation events for debugging.
///
/// Records all correlation mappings and can produce colorization
/// records for visualization.
///
/// Ported from Ghidra's `DebugUtils` Java class.
///
/// # Example
///
/// ```rust
/// use ghidra_features::codecompare::correlator::debug_utils::*;
/// use ghidra_features::codecompare::correlator::CorrelationKind;
///
/// let mut log = DebugCorrelationLog::new(DebugConfig::full());
///
/// log.record_correlation(
///     "source_prog",
///     "dest_prog",
///     (0x1000, 0x1010),
///     (0x2000, 0x2010),
///     CorrelationKind::CodeCompare,
/// );
///
/// assert_eq!(log.entry_count(), 1);
/// let entries = log.entries_for_source("source_prog");
/// assert_eq!(entries.len(), 1);
/// ```
pub struct DebugCorrelationLog {
    /// Configuration.
    config: DebugConfig,
    /// Recorded correlation entries.
    entries: Vec<DebugCorrelationEntry>,
    /// Colorization records for the source program.
    source_colorizations: Vec<ColorizationRecord>,
    /// Colorization records for the destination program.
    dest_colorizations: Vec<ColorizationRecord>,
    /// Seed for pseudo-random color generation.
    color_seed: u64,
}

impl DebugCorrelationLog {
    /// Create a new debug correlation log.
    pub fn new(config: DebugConfig) -> Self {
        Self {
            config,
            entries: Vec::new(),
            source_colorizations: Vec::new(),
            dest_colorizations: Vec::new(),
            color_seed: 42,
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &DebugConfig {
        &self.config
    }

    /// Set the configuration.
    pub fn set_config(&mut self, config: DebugConfig) {
        self.config = config;
    }

    /// Whether debug logging is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Record a correlation mapping.
    ///
    /// If debug is enabled, creates an entry and (if configured)
    /// generates colorization records.
    pub fn record_correlation(
        &mut self,
        source_program: &str,
        dest_program: &str,
        source_range: (u64, u64),
        dest_range: (u64, u64),
        kind: CorrelationKind,
    ) {
        if !self.config.enabled {
            return;
        }

        let entry = DebugCorrelationEntry::new(
            source_program,
            dest_program,
            source_range,
            dest_range,
            kind,
        );

        if self.config.colorize {
            let mut color = DebugColor::for_kind(kind);
            if self.config.use_random_colors && kind == CorrelationKind::CodeCompare {
                self.color_seed = lcg(self.color_seed);
                color = color.randomized(self.color_seed);
            }
            let argb = color.to_argb();

            self.source_colorizations.push(ColorizationRecord {
                range: source_range,
                color: argb,
                kind,
            });
            self.dest_colorizations.push(ColorizationRecord {
                range: dest_range,
                color: argb,
                kind,
            });
        }

        self.entries.push(entry);
    }

    /// Get the total number of recorded entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Get all entries.
    pub fn entries(&self) -> &[DebugCorrelationEntry] {
        &self.entries
    }

    /// Get entries for a specific source program.
    pub fn entries_for_source(&self, program: &str) -> Vec<&DebugCorrelationEntry> {
        self.entries
            .iter()
            .filter(|e| e.source_program == program)
            .collect()
    }

    /// Get entries for a specific destination program.
    pub fn entries_for_dest(&self, program: &str) -> Vec<&DebugCorrelationEntry> {
        self.entries
            .iter()
            .filter(|e| e.dest_program == program)
            .collect()
    }

    /// Get entries of a specific correlation kind.
    pub fn entries_of_kind(&self, kind: CorrelationKind) -> Vec<&DebugCorrelationEntry> {
        self.entries.iter().filter(|e| e.kind == kind).collect()
    }

    /// Get the colorization records for the source program.
    pub fn source_colorizations(&self) -> &[ColorizationRecord] {
        &self.source_colorizations
    }

    /// Get the colorization records for the destination program.
    pub fn dest_colorizations(&self) -> &[ColorizationRecord] {
        &self.dest_colorizations
    }

    /// Get the color for a source address, if any.
    pub fn color_for_source_address(&self, address: u64) -> Option<u32> {
        self.source_colorizations
            .iter()
            .find(|r| address >= r.range.0 && address <= r.range.1)
            .map(|r| r.color)
    }

    /// Get the color for a destination address, if any.
    pub fn color_for_dest_address(&self, address: u64) -> Option<u32> {
        self.dest_colorizations
            .iter()
            .find(|r| address >= r.range.0 && address <= r.range.1)
            .map(|r| r.color)
    }

    /// Get summary statistics.
    pub fn statistics(&self) -> DebugStatistics {
        let mut code_compare_count = 0;
        let mut lcs_count = 0;
        let mut parameters_count = 0;
        let mut other_count = 0;

        for entry in &self.entries {
            match entry.kind {
                CorrelationKind::CodeCompare => code_compare_count += 1,
                CorrelationKind::Lcs => lcs_count += 1,
                CorrelationKind::Parameters => parameters_count += 1,
                _ => other_count += 1,
            }
        }

        DebugStatistics {
            total_entries: self.entries.len(),
            code_compare_count,
            lcs_count,
            parameters_count,
            other_count,
        }
    }

    /// Clear all entries and colorizations.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.source_colorizations.clear();
        self.dest_colorizations.clear();
    }
}

/// Summary statistics for a debug correlation log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DebugStatistics {
    /// Total number of entries.
    pub total_entries: usize,
    /// Number of CodeCompare correlations.
    pub code_compare_count: usize,
    /// Number of LCS correlations.
    pub lcs_count: usize,
    /// Number of Parameters correlations.
    pub parameters_count: usize,
    /// Number of other correlations.
    pub other_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- DebugColor tests ---

    #[test]
    fn test_debug_color_for_kind() {
        let cc = DebugColor::for_kind(CorrelationKind::CodeCompare);
        assert!((cc.hue - 0.33).abs() < 0.01);

        let lcs = DebugColor::for_kind(CorrelationKind::Lcs);
        assert!((lcs.hue - 0.9).abs() < 0.01);

        let params = DebugColor::for_kind(CorrelationKind::Parameters);
        assert!((params.hue - 0.2).abs() < 0.01);
    }

    #[test]
    fn test_debug_color_to_argb() {
        let color = DebugColor::new(0.0, 0.0, 1.0); // White
        let argb = color.to_argb();
        assert_eq!(argb & 0xFF000000, 0xFF000000); // Alpha should be 0xFF
    }

    #[test]
    fn test_debug_color_to_hex() {
        let color = DebugColor::new(0.0, 0.0, 1.0); // White
        let hex = color.to_hex();
        assert!(hex.starts_with('#'));
        assert_eq!(hex.len(), 7);
    }

    #[test]
    fn test_debug_color_randomized() {
        let color = DebugColor::new(0.33, 0.5, 0.9);
        let randomized = color.randomized(12345);
        assert!((randomized.hue - 0.33).abs() < 0.01); // Hue unchanged
        // Saturation and brightness should be close but may differ
        assert!(randomized.saturation >= 0.0 && randomized.saturation <= 1.0);
        assert!(randomized.brightness >= 0.0 && randomized.brightness <= 1.0);
    }

    #[test]
    fn test_hsb_to_rgb_red() {
        let (r, g, b) = hsb_to_rgb(0.0, 1.0, 1.0);
        assert_eq!(r, 255);
        assert_eq!(g, 0);
        assert_eq!(b, 0);
    }

    #[test]
    fn test_hsb_to_rgb_green() {
        let (r, g, b) = hsb_to_rgb(1.0 / 3.0, 1.0, 1.0);
        assert_eq!(r, 0);
        assert_eq!(g, 255);
        assert_eq!(b, 0);
    }

    #[test]
    fn test_hsb_to_rgb_white() {
        let (r, g, b) = hsb_to_rgb(0.0, 0.0, 1.0);
        assert_eq!(r, 255);
        assert_eq!(g, 255);
        assert_eq!(b, 255);
    }

    #[test]
    fn test_hsb_to_rgb_black() {
        let (r, g, b) = hsb_to_rgb(0.0, 0.0, 0.0);
        assert_eq!(r, 0);
        assert_eq!(g, 0);
        assert_eq!(b, 0);
    }

    // --- DebugConfig tests ---

    #[test]
    fn test_debug_config_default() {
        let config = DebugConfig::new();
        assert!(!config.enabled);
        assert!(!config.use_random_colors);
        assert!(!config.record_comments);
        assert!(!config.colorize);
    }

    #[test]
    fn test_debug_config_full() {
        let config = DebugConfig::full();
        assert!(config.enabled);
        assert!(config.record_comments);
        assert!(config.colorize);
    }

    #[test]
    fn test_debug_config_builder() {
        let config = DebugConfig::new().with_random_colors(true);
        assert!(config.use_random_colors);
    }

    // --- DebugCorrelationEntry tests ---

    #[test]
    fn test_entry_creation() {
        let entry = DebugCorrelationEntry::new(
            "src",
            "dst",
            (0x1000, 0x1010),
            (0x2000, 0x2010),
            CorrelationKind::CodeCompare,
        );
        assert_eq!(entry.source_program, "src");
        assert_eq!(entry.dest_program, "dst");
        assert_eq!(entry.source_size(), 0x11);
        assert_eq!(entry.dest_size(), 0x11);
        assert_eq!(entry.kind, CorrelationKind::CodeCompare);
    }

    // --- DebugCorrelationLog tests ---

    #[test]
    fn test_log_disabled() {
        let mut log = DebugCorrelationLog::new(DebugConfig::new());
        log.record_correlation(
            "src",
            "dst",
            (0x1000, 0x1010),
            (0x2000, 0x2010),
            CorrelationKind::CodeCompare,
        );
        assert_eq!(log.entry_count(), 0);
    }

    #[test]
    fn test_log_enabled() {
        let mut log = DebugCorrelationLog::new(DebugConfig::full());
        log.record_correlation(
            "src",
            "dst",
            (0x1000, 0x1010),
            (0x2000, 0x2010),
            CorrelationKind::CodeCompare,
        );
        assert_eq!(log.entry_count(), 1);
    }

    #[test]
    fn test_log_entries_for_source() {
        let mut log = DebugCorrelationLog::new(DebugConfig::full());
        log.record_correlation(
            "prog1",
            "prog2",
            (0x1000, 0x1010),
            (0x2000, 0x2010),
            CorrelationKind::CodeCompare,
        );
        log.record_correlation(
            "prog3",
            "prog2",
            (0x3000, 0x3010),
            (0x2000, 0x2010),
            CorrelationKind::Lcs,
        );

        assert_eq!(log.entries_for_source("prog1").len(), 1);
        assert_eq!(log.entries_for_source("prog3").len(), 1);
        assert_eq!(log.entries_for_source("nonexistent").len(), 0);
    }

    #[test]
    fn test_log_entries_for_dest() {
        let mut log = DebugCorrelationLog::new(DebugConfig::full());
        log.record_correlation(
            "prog1",
            "prog2",
            (0x1000, 0x1010),
            (0x2000, 0x2010),
            CorrelationKind::CodeCompare,
        );

        assert_eq!(log.entries_for_dest("prog2").len(), 1);
        assert_eq!(log.entries_for_dest("prog1").len(), 0);
    }

    #[test]
    fn test_log_entries_of_kind() {
        let mut log = DebugCorrelationLog::new(DebugConfig::full());
        log.record_correlation(
            "p1",
            "p2",
            (0x1000, 0x1010),
            (0x2000, 0x2010),
            CorrelationKind::CodeCompare,
        );
        log.record_correlation(
            "p1",
            "p2",
            (0x3000, 0x3010),
            (0x4000, 0x4010),
            CorrelationKind::Lcs,
        );
        log.record_correlation(
            "p1",
            "p2",
            (0x5000, 0x5010),
            (0x6000, 0x6010),
            CorrelationKind::CodeCompare,
        );

        assert_eq!(log.entries_of_kind(CorrelationKind::CodeCompare).len(), 2);
        assert_eq!(log.entries_of_kind(CorrelationKind::Lcs).len(), 1);
        assert_eq!(log.entries_of_kind(CorrelationKind::Parameters).len(), 0);
    }

    #[test]
    fn test_log_colorizations() {
        let config = DebugConfig {
            enabled: true,
            colorize: true,
            ..DebugConfig::new()
        };
        let mut log = DebugCorrelationLog::new(config);
        log.record_correlation(
            "p1",
            "p2",
            (0x1000, 0x1010),
            (0x2000, 0x2010),
            CorrelationKind::CodeCompare,
        );

        assert_eq!(log.source_colorizations().len(), 1);
        assert_eq!(log.dest_colorizations().len(), 1);
    }

    #[test]
    fn test_log_color_for_address() {
        let config = DebugConfig {
            enabled: true,
            colorize: true,
            ..DebugConfig::new()
        };
        let mut log = DebugCorrelationLog::new(config);
        log.record_correlation(
            "p1",
            "p2",
            (0x1000, 0x1010),
            (0x2000, 0x2010),
            CorrelationKind::CodeCompare,
        );

        assert!(log.color_for_source_address(0x1000).is_some());
        assert!(log.color_for_source_address(0x1005).is_some());
        assert!(log.color_for_source_address(0x1011).is_none());
        assert!(log.color_for_dest_address(0x2000).is_some());
    }

    #[test]
    fn test_log_statistics() {
        let mut log = DebugCorrelationLog::new(DebugConfig::full());
        log.record_correlation(
            "p1",
            "p2",
            (0x1000, 0x1010),
            (0x2000, 0x2010),
            CorrelationKind::CodeCompare,
        );
        log.record_correlation(
            "p1",
            "p2",
            (0x3000, 0x3010),
            (0x4000, 0x4010),
            CorrelationKind::Lcs,
        );
        log.record_correlation(
            "p1",
            "p2",
            (0x5000, 0x5010),
            (0x6000, 0x6010),
            CorrelationKind::Parameters,
        );

        let stats = log.statistics();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.code_compare_count, 1);
        assert_eq!(stats.lcs_count, 1);
        assert_eq!(stats.parameters_count, 1);
        assert_eq!(stats.other_count, 0);
    }

    #[test]
    fn test_log_clear() {
        let mut log = DebugCorrelationLog::new(DebugConfig::full());
        log.record_correlation(
            "p1",
            "p2",
            (0x1000, 0x1010),
            (0x2000, 0x2010),
            CorrelationKind::CodeCompare,
        );
        assert_eq!(log.entry_count(), 1);

        log.clear();
        assert_eq!(log.entry_count(), 0);
    }

    // --- Global debug enable/disable ---

    #[test]
    fn test_global_enable_disable() {
        enable_debug(true);
        assert!(is_debug_enabled());
        enable_debug(false);
        assert!(!is_debug_enabled());
    }
}
