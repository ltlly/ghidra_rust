//! Prototype / Experimental Analyzers
//!
//! Ported from `ghidra.app.plugin.prototype`.
//!
//! Contains prototype/experimental analyzers and plugins:
//!
//! - [`AggressiveInstructionFinderAnalyzer`] -- discovers code in undefined
//!   byte regions by hashing function-start patterns and validating
//!   candidates with pseudo-disassembly.
//! - [`ArmAggressiveInstructionFinderAnalyzer`] -- ARM/Thumb-specific
//!   variant with TMode tracking, dual-mode validation, and prologue
//!   detection.
//! - [`ScreenshotPlugin`] -- captures screenshots of the active tool
//!   component or frame and exports to PNG (data model only; actual
//!   rendering requires a GUI layer).

pub mod aggressive_instruction_finder;
pub mod arm_aggressive_instruction_finder;
pub mod screenshot_plugin;

// Re-export primary types for convenience.
pub use aggressive_instruction_finder::{
    AggressiveFinderOptions, AggressiveInstructionFinderAnalyzer, StartPattern, SubFlowResult,
};
pub use arm_aggressive_instruction_finder::{
    ArmAggressiveInstructionFinderAnalyzer, ArmPseudoInstruction, ArmSubFlowResult, TModeValue,
};
pub use screenshot_plugin::{
    CaptureResult, CaptureTarget, ScreenshotFormat, ScreenshotPlugin, ScreenshotResult,
    ScreenshotStatus,
};

// ---------------------------------------------------------------------------
// Module-level constants (shared across sub-modules)
// ---------------------------------------------------------------------------

/// Minimum number of discovered functions before the aggressive finder
/// considers a region viable.
pub const MINIMUM_FUNCTION_COUNT: usize = 20;

/// Minimum size (in bytes) of a function to be considered.
pub const MINIMUM_FUNCTION_SIZE: usize = 2;

/// Maximum number of undefined bytes to sample per iteration.
pub const MAX_SAMPLES_PER_ITERATION: usize = 1000;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::analyzer::Analyzer;

    // --- AggressiveInstructionFinderAnalyzer ---

    #[test]
    fn test_aggressive_finder_disabled_by_default() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        assert!(!analyzer.default_enablement(&Default::default()));
        assert_eq!(analyzer.name(), "Aggressive Instruction Finder");
    }

    #[test]
    fn test_aggressive_finder_prototype() {
        let analyzer = AggressiveInstructionFinderAnalyzer::new();
        assert!(analyzer.is_prototype());
        assert!(analyzer.supports_one_time_analysis());
    }

    #[test]
    fn test_aggressive_finder_options_default() {
        let opts = AggressiveFinderOptions::default();
        assert!(opts.create_bookmarks);
    }

    #[test]
    fn test_start_pattern_key() {
        let a = StartPattern(vec![0x55, 0x48, 0x89]);
        let b = StartPattern(vec![0x55, 0x48, 0x89]);
        assert_eq!(a, b);
    }

    #[test]
    fn test_sub_flow_result_default() {
        let r = SubFlowResult::default();
        assert_eq!(r.num_instructions, 0);
        assert!(!r.adds_info);
    }

    // --- ArmAggressiveInstructionFinderAnalyzer ---

    #[test]
    fn test_arm_finder_creation() {
        let finder = ArmAggressiveInstructionFinderAnalyzer::new();
        assert_eq!(finder.name(), "ARM Aggressive Instruction Finder");
        assert!(finder.is_prototype());
    }

    #[test]
    fn test_arm_finder_prologue_detection_thumb() {
        assert!(ArmAggressiveInstructionFinderAnalyzer::looks_like_arm_prologue(&[
            0xB5, 0xF0
        ]));
    }

    #[test]
    fn test_arm_finder_prologue_detection_arm() {
        assert!(ArmAggressiveInstructionFinderAnalyzer::looks_like_arm_prologue(&[
            0xF0, 0x40, 0x2D, 0xE9
        ]));
    }

    #[test]
    fn test_arm_finder_prologue_not_a_prologue() {
        assert!(!ArmAggressiveInstructionFinderAnalyzer::looks_like_arm_prologue(&[
            0x00, 0x00
        ]));
    }

    #[test]
    fn test_arm_finder_prologue_too_short() {
        assert!(!ArmAggressiveInstructionFinderAnalyzer::looks_like_arm_prologue(&[0xB5]));
    }

    #[test]
    fn test_tmode_values() {
        assert_eq!(TModeValue::ARM, TModeValue(0));
        assert_eq!(TModeValue::THUMB, TModeValue(1));
        assert!(!TModeValue::ARM.is_thumb());
        assert!(TModeValue::THUMB.is_thumb());
        assert_eq!(TModeValue::ARM.flip(), TModeValue::THUMB);
        assert_eq!(TModeValue::THUMB.flip(), TModeValue::ARM);
    }

    #[test]
    fn test_arm_pseudo_filler() {
        let nop = ArmPseudoInstruction {
            address: crate::base::analyzer::Address::new(0),
            length: 2,
            mnemonic: "nop".into(),
            flow_type: crate::base::analyzer::FlowType::Fallthrough,
            flows: vec![],
            has_fallthrough: true,
            result_registers: vec![],
            input_registers: vec![],
        };
        assert!(nop.is_filler());
    }

    #[test]
    fn test_arm_sub_flow_default() {
        let r = ArmSubFlowResult::default();
        assert_eq!(r.num_instructions, 0);
    }

    // --- ScreenshotPlugin ---

    #[test]
    fn test_screenshot_plugin_creation() {
        let plugin = ScreenshotPlugin::new();
        assert_eq!(plugin.name, "ScreenshotPlugin");
        assert_eq!(plugin.format, ScreenshotFormat::Png);
        assert_eq!(plugin.actions.len(), 2);
    }

    #[test]
    fn test_screenshot_plugin_dispose() {
        let mut plugin = ScreenshotPlugin::new();
        assert!(!plugin.is_disposed());
        plugin.dispose();
        assert!(plugin.is_disposed());
    }

    #[test]
    fn test_screenshot_format() {
        assert_eq!(ScreenshotFormat::Png.extension(), "png");
        assert_eq!(ScreenshotFormat::Jpeg.extension(), "jpg");
        assert_eq!(ScreenshotFormat::Bmp.extension(), "bmp");
    }

    #[test]
    fn test_screenshot_format_display() {
        assert_eq!(
            ScreenshotFormat::Png.display_name(),
            "Portable Network Graphics"
        );
    }

    #[test]
    fn test_capture_target_stem() {
        let target = CaptureTarget::ActiveComponent {
            component_name: "Listing".to_string(),
        };
        assert_eq!(target.filename_stem(), "Listing");
    }

    #[test]
    fn test_capture_active_component() {
        let mut plugin = ScreenshotPlugin::new();
        let result = plugin.capture_active_component("Test", 800, 600);
        assert!(result.is_ok());
    }

    #[test]
    fn test_capture_tool_frame() {
        let mut plugin = ScreenshotPlugin::new();
        let result = plugin.capture_tool_frame("CodeBrowser", 1024, 768);
        assert!(result.is_ok());
    }

    #[test]
    fn test_capture_result_summary() {
        let result = CaptureResult {
            file_path: std::path::PathBuf::from("/tmp/test.png"),
            width: 1920,
            height: 1080,
            format: ScreenshotFormat::Png,
            file_size: 50000,
        };
        assert!(result.summary().contains("1920x1080"));
    }

    #[test]
    fn test_screenshot_status() {
        assert_eq!(ScreenshotStatus::default(), ScreenshotStatus::Idle);
        assert_eq!(ScreenshotStatus::Idle.to_string(), "Idle");
    }
}
