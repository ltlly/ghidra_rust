//! Test processor constants.
//!
//! Ported from `ghidra.test.TestProcessorConstants`.
//!
//! Provides static processor identifiers commonly used in Ghidra tests.

use crate::base::analyzer::core::Language;

/// Processor identifier for Intel 8051.
pub const PROCESSOR_8051: &str = "8051";

/// Processor identifier for Zilog Z80.
pub const PROCESSOR_Z80: &str = "Z80";

/// Processor identifier for PowerPC (Motorola).
pub const PROCESSOR_POWERPC: &str = "PowerPC";

/// Processor identifier for SPARC.
pub const PROCESSOR_SPARC: &str = "Sparc";

/// Processor identifier for Intel x86.
pub const PROCESSOR_X86: &str = "x86";

/// Processor identifier for TMS320C3x.
pub const PROCESSOR_TMS320C3X: &str = "TMS320C3x";

/// Processor identifier for ARM.
pub const PROCESSOR_ARM: &str = "ARM";

/// Processor identifier for DATA (raw data).
pub const PROCESSOR_DATA: &str = "DATA";

/// Create a [`Language`] for the given processor constant.
///
/// Uses little-endian and the platform's default address size (64-bit).
pub fn language_for(processor: &str) -> Language {
    Language {
        processor: processor.to_string(),
        variant: "LE".to_string(),
        size: 64,
    }
}

/// Convenience: get all well-known test processor identifiers.
pub fn all_test_processors() -> Vec<&'static str> {
    vec![
        PROCESSOR_8051,
        PROCESSOR_Z80,
        PROCESSOR_POWERPC,
        PROCESSOR_SPARC,
        PROCESSOR_X86,
        PROCESSOR_TMS320C3X,
        PROCESSOR_ARM,
        PROCESSOR_DATA,
    ]
}

/// Create the default x86:LE:64 language used by most tests.
pub fn x86_language() -> Language {
    Language {
        processor: PROCESSOR_X86.to_string(),
        variant: "LE".to_string(),
        size: 64,
    }
}

/// Create a 32-bit x86:LE:32 language.
pub fn x86_32_language() -> Language {
    Language {
        processor: PROCESSOR_X86.to_string(),
        variant: "LE".to_string(),
        size: 32,
    }
}

/// Create an ARM:LE:32 language.
pub fn arm_language() -> Language {
    Language {
        processor: PROCESSOR_ARM.to_string(),
        variant: "LE".to_string(),
        size: 32,
    }
}

/// Create an AARCH64:LE:64 language.
pub fn aarch64_language() -> Language {
    Language {
        processor: "AARCH64".to_string(),
        variant: "LE".to_string(),
        size: 64,
    }
}

/// Create a MIPS:LE:32 language.
pub fn mips_language() -> Language {
    Language {
        processor: "MIPS".to_string(),
        variant: "LE".to_string(),
        size: 32,
    }
}

/// Create a PowerPC:BE:32 language.
pub fn powerpc_language() -> Language {
    Language {
        processor: PROCESSOR_POWERPC.to_string(),
        variant: "BE".to_string(),
        size: 32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_constants_are_unique() {
        let processors = all_test_processors();
        for i in 0..processors.len() {
            for j in (i + 1)..processors.len() {
                assert_ne!(processors[i], processors[j]);
            }
        }
    }

    #[test]
    fn test_x86_language() {
        let lang = x86_language();
        assert_eq!(lang.processor, "x86");
        assert_eq!(lang.variant, "LE");
        assert_eq!(lang.size, 64);
    }

    #[test]
    fn test_arm_language() {
        let lang = arm_language();
        assert_eq!(lang.processor, "ARM");
        assert_eq!(lang.variant, "LE");
        assert_eq!(lang.size, 32);
    }

    #[test]
    fn test_powerpc_language() {
        let lang = powerpc_language();
        assert_eq!(lang.processor, "PowerPC");
        assert_eq!(lang.variant, "BE");
        assert_eq!(lang.size, 32);
    }

    #[test]
    fn test_language_for() {
        let lang = language_for(PROCESSOR_Z80);
        assert_eq!(lang.processor, "Z80");
        assert_eq!(lang.variant, "LE");
        assert_eq!(lang.size, 64);
    }

    #[test]
    fn test_all_test_processors_count() {
        assert_eq!(all_test_processors().len(), 8);
    }
}
