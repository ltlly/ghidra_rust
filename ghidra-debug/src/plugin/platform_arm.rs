//! ARM platform support for debugger disassembly.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.platform.arm` package.
//! Provides ARM-specific disassembly injection to handle Thumb/ARM mode
//! switching via the CPSR register.

use serde::{Deserialize, Serialize};

use super::platform_opinion::{OpinionContext, PlatformOpinion, PlatformOpinionProvider};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The Thumb bit in the CPSR register.
pub const THUMB_BIT: u64 = 0x20;

/// Supported ARM language IDs for disassembly injection.
pub const ARM_LANG_IDS: &[&str] = &[
    "ARM:LE:32:v8",
    "ARM:LE:32:v8T",
    "ARM:LEBE:32:v8LEInstruction",
    "ARM:BE:32:v8",
    "ARM:BE:32:v8T",
    "ARM:LE:32:v7",
    "ARM:LEBE:32:v7LEInstruction",
    "ARM:BE:32:v7",
    "ARM:LE:32:Cortex",
    "ARM:BE:32:Cortex",
    "ARM:LE:32:v6",
    "ARM:BE:32:v6",
    "ARM:LE:32:v5t",
    "ARM:BE:32:v5t",
    "ARM:LE:32:v5",
    "ARM:BE:32:v5",
    "ARM:LE:32:v4t",
    "ARM:BE:32:v4t",
    "ARM:LE:32:v4",
    "ARM:BE:32:v4",
];

// ---------------------------------------------------------------------------
// ARM disassembly inject
// ---------------------------------------------------------------------------

/// ARM-specific disassembly injection.
///
/// Ported from Ghidra's `ArmDisassemblyInject`. Handles Thumb mode
/// detection via the CPSR register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArmDisassemblyInject {
    /// The current Thumb mode state.
    pub thumb_mode: bool,
    /// The CPSR register value (if available).
    pub cpsr_value: Option<u64>,
    /// The TMode register value (if available).
    pub tmode_value: Option<bool>,
}

impl ArmDisassemblyInject {
    /// Create a new ARM disassembly inject.
    pub fn new() -> Self {
        Self {
            thumb_mode: false,
            cpsr_value: None,
            tmode_value: None,
        }
    }

    /// Check if Thumb mode is indicated by the CPSR value.
    pub fn is_thumb_mode_from_cpsr(cpsr: u64) -> bool {
        (cpsr & THUMB_BIT) != 0
    }

    /// Update the Thumb mode from the CPSR register value.
    pub fn update_from_cpsr(&mut self, cpsr: u64) {
        self.cpsr_value = Some(cpsr);
        self.thumb_mode = Self::is_thumb_mode_from_cpsr(cpsr);
    }

    /// Update the Thumb mode from the TMode register.
    pub fn update_from_tmode(&mut self, tmode: bool) {
        self.tmode_value = Some(tmode);
        self.thumb_mode = tmode;
    }

    /// Determine the Thumb mode. Prefers TMode register over CPSR.
    pub fn compute_thumb_mode(&self) -> bool {
        if let Some(tmode) = self.tmode_value {
            tmode
        } else if let Some(cpsr) = self.cpsr_value {
            Self::is_thumb_mode_from_cpsr(cpsr)
        } else {
            false
        }
    }

    /// Check if a language ID is an ARM language that this inject handles.
    pub fn is_arm_language(lang_id: &str) -> bool {
        ARM_LANG_IDS.contains(&lang_id)
    }

    /// Apply pre-disassembly setup for ARM.
    ///
    /// Sets the TMode register based on CPSR before disassembly.
    pub fn pre_disassemble(&mut self, cpsr: Option<u64>, tmode: Option<bool>) {
        if let Some(t) = tmode {
            self.update_from_tmode(t);
        } else if let Some(c) = cpsr {
            self.update_from_cpsr(c);
        }
    }
}

impl Default for ArmDisassemblyInject {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ARM platform opinion
// ---------------------------------------------------------------------------

/// ARM platform opinion provider.
///
/// Maps ARM architecture information to Ghidra language/compiler spec IDs.
#[derive(Debug, Clone)]
pub struct ArmPlatformOpinion;

impl PlatformOpinionProvider for ArmPlatformOpinion {
    fn name(&self) -> &str {
        "ARM"
    }

    fn debugger_types(&self) -> &[&str] {
        &["gdb", "gdbserver", "lldb", "dbgeng"]
    }

    fn get_opinions(&self, context: &OpinionContext) -> Vec<PlatformOpinion> {
        let arch = context.architecture.to_lowercase();
        if !arch.contains("arm") && !arch.starts_with("armv") {
            return Vec::new();
        }

        let endian = if context.big_endian { "BE" } else { "LE" };
        let mut opinions = Vec::new();

        if context.pointer_size >= 8 {
            // AArch64
            let variant = if arch.contains("v8") { "v8A" } else { "v8A" };
            opinions.push(PlatformOpinion::new(
                "arm",
                &format!("AARCH64:{}:64:{}", endian, variant),
                "default",
                "AARCH64",
                0.9,
            ));
        } else {
            // 32-bit ARM
            let variant = if arch.contains("v8") {
                "v8"
            } else if arch.contains("v7") || arch.contains("v7l") {
                "v7"
            } else if arch.contains("v6") {
                "v6"
            } else if arch.contains("v5t") {
                "v5t"
            } else if arch.contains("v5") {
                "v5"
            } else if arch.contains("v4t") {
                "v4t"
            } else if arch.contains("v4") {
                "v4"
            } else {
                "v8" // Default
            };
            opinions.push(PlatformOpinion::new(
                "arm",
                &format!("ARM:{}:32:{}", endian, variant),
                "default",
                "ARM",
                0.9,
            ));
        }

        opinions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thumb_bit_detection() {
        assert!(ArmDisassemblyInject::is_thumb_mode_from_cpsr(0x20));
        assert!(ArmDisassemblyInject::is_thumb_mode_from_cpsr(0x3F));
        assert!(!ArmDisassemblyInject::is_thumb_mode_from_cpsr(0x00));
        assert!(!ArmDisassemblyInject::is_thumb_mode_from_cpsr(0x1F));
    }

    #[test]
    fn test_arm_disassembly_inject_update() {
        let mut inject = ArmDisassemblyInject::new();
        assert!(!inject.thumb_mode);

        inject.update_from_cpsr(0x20);
        assert!(inject.thumb_mode);
        assert_eq!(inject.cpsr_value, Some(0x20));

        inject.update_from_cpsr(0x00);
        assert!(!inject.thumb_mode);
    }

    #[test]
    fn test_arm_disassembly_inject_tmode_priority() {
        let mut inject = ArmDisassemblyInject::new();
        inject.update_from_cpsr(0x00); // Not thumb
        inject.update_from_tmode(true); // Override to thumb
        assert!(inject.compute_thumb_mode());
        assert!(inject.thumb_mode);
    }

    #[test]
    fn test_compute_thumb_mode_defaults() {
        let inject = ArmDisassemblyInject::new();
        assert!(!inject.compute_thumb_mode()); // Default: ARM mode
    }

    #[test]
    fn test_is_arm_language() {
        assert!(ArmDisassemblyInject::is_arm_language("ARM:LE:32:v8"));
        assert!(ArmDisassemblyInject::is_arm_language("ARM:BE:32:v7"));
        assert!(!ArmDisassemblyInject::is_arm_language("x86:LE:64:default"));
    }

    #[test]
    fn test_arm_platform_opinion_32bit() {
        let opinion = ArmPlatformOpinion;
        let context = OpinionContext {
            debugger_type: "gdb".into(),
            architecture: "armv7l".into(),
            os: "linux".into(),
            big_endian: false,
            pointer_size: 4,
            ..Default::default()
        };
        let results = opinion.get_opinions(&context);
        assert!(!results.is_empty());
        assert!(results[0].language_id.contains("ARM:LE:32:v7"));
    }

    #[test]
    fn test_arm_platform_opinion_64bit() {
        let opinion = ArmPlatformOpinion;
        let context = OpinionContext {
            debugger_type: "gdb".into(),
            architecture: "armv8".into(),
            os: "linux".into(),
            big_endian: false,
            pointer_size: 8,
            ..Default::default()
        };
        let results = opinion.get_opinions(&context);
        assert!(!results.is_empty());
        assert!(results[0].language_id.contains("AARCH64"));
    }

    #[test]
    fn test_arm_platform_opinion_no_match() {
        let opinion = ArmPlatformOpinion;
        let context = OpinionContext {
            debugger_type: "gdb".into(),
            architecture: "x86_64".into(),
            os: "linux".into(),
            big_endian: false,
            pointer_size: 8,
            ..Default::default()
        };
        let results = opinion.get_opinions(&context);
        assert!(results.is_empty());
    }

    #[test]
    fn test_arm_lang_ids_count() {
        assert_eq!(ARM_LANG_IDS.len(), 20);
    }
}
