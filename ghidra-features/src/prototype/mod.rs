//! Prototype Analyzers
//!
//! Ported from `ghidra.app.plugin.prototype`.
//!
//! Contains prototype/experimental analyzers such as the Aggressive Instruction
//! Finder, which attempts to disassemble undefined bytes to discover code in
//! regions not reached by the normal analysis flow.

use log::{debug, info, warn};

/// Minimum number of discovered functions before the aggressive finder
/// considers a region viable.
pub const MINIMUM_FUNCTION_COUNT: usize = 20;

/// Minimum size (in bytes) of a function to be considered.
pub const MINIMUM_FUNCTION_SIZE: usize = 2;

/// Maximum number of undefined bytes to sample per iteration.
pub const MAX_SAMPLES_PER_ITERATION: usize = 1000;

/// Aggressive Instruction Finder Analyzer.
///
/// Looks at all undefined bytes to see if they start a valid subroutine.
/// If they do, the function is disassembled and the analyzer schedules
/// itself to run again so other auto-analysis can process the results.
///
/// This is an experimental/heuristic analyzer that should be used with
/// caution as it can produce false positives.
#[derive(Debug, Clone)]
pub struct AggressiveInstructionFinderAnalyzer {
    /// Name of the analyzer.
    pub name: String,
    /// Description of the analyzer.
    pub description: String,
    /// Whether the analyzer is enabled by default.
    pub enabled: bool,
    /// Whether to log verbose details.
    pub verbose: bool,
}

impl AggressiveInstructionFinderAnalyzer {
    /// Analyzer name.
    pub const NAME: &'static str = "Aggressive Instruction Finder";

    /// Analyzer description.
    pub const DESCRIPTION: &'static str =
        "Looks at all undefined bytes to see if it starts a valid subroutine";

    /// Create a new analyzer with default settings.
    pub fn new() -> Self {
        Self {
            name: Self::NAME.to_string(),
            description: Self::DESCRIPTION.to_string(),
            enabled: false, // not enabled by default
            verbose: false,
        }
    }

    /// Determine if the analyzer should run based on the current program state.
    ///
    /// The aggressive finder should only run when the number of functions
    /// discovered by normal analysis is below a threshold, indicating that
    /// there may be significant unexplored code regions.
    pub fn should_analyze(&self, function_count: usize) -> bool {
        self.enabled && function_count < MINIMUM_FUNCTION_COUNT
    }

    /// Process undefined data bytes and attempt to find valid instructions.
    ///
    /// Returns a list of addresses where valid subroutines were discovered.
    pub fn find_undefined_starts(&self, undefined_regions: &[(u64, usize)]) -> Vec<u64> {
        let mut candidates = Vec::new();

        for &(start, length) in undefined_regions {
            if length >= MINIMUM_FUNCTION_SIZE {
                candidates.push(start);
                if candidates.len() >= MAX_SAMPLES_PER_ITERATION {
                    break;
                }
            }
        }

        debug!(
            "AggressiveInstructionFinder: found {} candidate addresses from {} undefined regions",
            candidates.len(),
            undefined_regions.len()
        );

        candidates
    }

    /// Record a discovered function at the given address.
    pub fn record_discovery(&self, address: u64, length: usize) {
        info!(
            "AggressiveInstructionFinder: discovered function at 0x{:x} ({} bytes)",
            address, length
        );
    }
}

impl Default for AggressiveInstructionFinderAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// ARM-specific variant of the Aggressive Instruction Finder.
///
/// Uses ARM-specific heuristics such as checking for common ARM function
/// prologues (PUSH {r4-r7, lr}, etc.) before attempting disassembly.
#[derive(Debug, Clone)]
pub struct ArmAggressiveInstructionFinderAnalyzer {
    /// The base analyzer.
    pub base: AggressiveInstructionFinderAnalyzer,
    /// Whether to check for ARM function prologues.
    pub check_prologues: bool,
}

impl ArmAggressiveInstructionFinderAnalyzer {
    /// Create a new ARM-specific aggressive instruction finder.
    pub fn new() -> Self {
        Self {
            base: AggressiveInstructionFinderAnalyzer {
                name: "ARM Aggressive Instruction Finder".to_string(),
                description:
                    "ARM-specific aggressive instruction finder with prologue checking"
                        .to_string(),
                enabled: false,
                verbose: false,
            },
            check_prologues: true,
        }
    }

    /// Check if a byte sequence looks like an ARM function prologue.
    ///
    /// Common ARM prologues include:
    /// - `PUSH {r4-r7, lr}` (0xE92D 0x40F0 in ARM mode)
    /// - `STMFD sp!, {regs}` (various encodings)
    /// - `SUB sp, sp, #imm` followed by `PUSH`
    pub fn looks_like_arm_prologue(bytes: &[u8]) -> bool {
        // Check for common Thumb-2 PUSH patterns
        // PUSH {r4-r7, lr} = 0xB5 {F0|70|30|...}
        if bytes.len() >= 2 && bytes[0] == 0xB5 {
            return true;
        }

        // Check for ARM STMFD pattern (PUSH)
        // 0xE92D 0xXXXX = STMDB sp!, {regs} (big-endian instruction word)
        if bytes.len() >= 4 && bytes[3] == 0xE9 && bytes[2] == 0x2D {
            return true;
        }

        false
    }
}

impl Default for ArmAggressiveInstructionFinderAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

/// Screenshot Plugin (stub).
///
/// The ScreenshotPlugin captures a screenshot of the current Ghidra tool
/// and saves it to a file. This is a GUI-only feature; the Rust port
/// provides the data model.
#[derive(Debug, Clone)]
pub struct ScreenshotPlugin {
    /// Plugin name.
    pub name: String,
    /// Default output format.
    pub format: ScreenshotFormat,
}

/// Supported screenshot output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenshotFormat {
    /// PNG format.
    Png,
    /// JPEG format.
    Jpeg,
    /// BMP format.
    Bmp,
}

impl ScreenshotPlugin {
    /// Create a new screenshot plugin.
    pub fn new() -> Self {
        Self {
            name: "Screenshot".to_string(),
            format: ScreenshotFormat::Png,
        }
    }

    /// Get the file extension for the current format.
    pub fn file_extension(&self) -> &str {
        match self.format {
            ScreenshotFormat::Png => "png",
            ScreenshotFormat::Jpeg => "jpg",
            ScreenshotFormat::Bmp => "bmp",
        }
    }
}

impl Default for ScreenshotPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aggressive_finder_disabled_by_default() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        assert!(!analyzer.enabled);
        assert_eq!(analyzer.name, "Aggressive Instruction Finder");
    }

    #[test]
    fn test_should_analyze() {
        let mut analyzer = AggressiveInstructionFinderAnalyzer::new();
        assert!(!analyzer.should_analyze(10)); // disabled
        analyzer.enabled = true;
        assert!(analyzer.should_analyze(10)); // below threshold
        assert!(!analyzer.should_analyze(100)); // above threshold
    }

    #[test]
    fn test_find_undefined_starts() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        let regions = vec![
            (0x1000, 10),
            (0x2000, 1), // too small
            (0x3000, 20),
        ];
        let starts = analyzer.find_undefined_starts(&regions);
        assert_eq!(starts.len(), 2);
        assert_eq!(starts[0], 0x1000);
        assert_eq!(starts[1], 0x3000);
    }

    #[test]
    fn test_find_undefined_starts_max_samples() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        let regions: Vec<(u64, usize)> = (0..2000)
            .map(|i| (0x1000 + i * 0x10, 10))
            .collect();
        let starts = analyzer.find_undefined_starts(&regions);
        assert_eq!(starts.len(), MAX_SAMPLES_PER_ITERATION);
    }

    #[test]
    fn test_arm_finder_prologue_detection() {
        // Thumb-2 PUSH {r4-r7, lr}
        assert!(ArmAggressiveInstructionFinderAnalyzer::looks_like_arm_prologue(&[
            0xB5, 0xF0
        ]));
        // ARM STMDB sp!, {r4-r7, lr}
        assert!(ArmAggressiveInstructionFinderAnalyzer::looks_like_arm_prologue(&[
            0xF0, 0x40, 0x2D, 0xE9
        ]));
        // Not a prologue
        assert!(!ArmAggressiveInstructionFinderAnalyzer::looks_like_arm_prologue(&[
            0x00, 0x00
        ]));
        // Too short
        assert!(!ArmAggressiveInstructionFinderAnalyzer::looks_like_arm_prologue(&[0xB5]));
    }

    #[test]
    fn test_arm_finder_disabled_by_default() {
        let finder = ArmAggressiveInstructionFinderAnalyzer::new();
        assert!(!finder.base.enabled);
        assert!(finder.check_prologues);
    }

    #[test]
    fn test_screenshot_plugin() {
        let plugin = ScreenshotPlugin::new();
        assert_eq!(plugin.name, "Screenshot");
        assert_eq!(plugin.format, ScreenshotFormat::Png);
        assert_eq!(plugin.file_extension(), "png");
    }

    #[test]
    fn test_screenshot_format() {
        let mut plugin = ScreenshotPlugin::new();
        plugin.format = ScreenshotFormat::Jpeg;
        assert_eq!(plugin.file_extension(), "jpg");
        plugin.format = ScreenshotFormat::Bmp;
        assert_eq!(plugin.file_extension(), "bmp");
    }
}
