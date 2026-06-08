//! Processor family definitions.
//!
//! This module re-exports the [`Processor`] struct from the parent `lang`
//! module, providing a dedicated access path for processor family
//! functionality.
//!
//! # Correspondence to Ghidra
//!
//! This is a direct translation of `ghidra.program.model.lang.Processor`.
//! The Java version uses a static registry pattern (`findOrPossiblyCreateProcessor`,
//! `toProcessor`). This Rust version is a plain struct. Registry-like behavior
//! can be built separately using a `HashMap<String, Processor>`.

// Re-export from the parent lang module.
pub use super::lang::Processor;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processor_new() {
        let proc = Processor::new("x86");
        assert_eq!(proc.name, "x86");
    }

    #[test]
    fn test_processor_convenience() {
        let x86 = Processor::x86();
        assert_eq!(x86.name, "x86");

        let arm = Processor::arm();
        assert_eq!(arm.name, "ARM");

        let mips = Processor::mips();
        assert_eq!(mips.name, "MIPS");

        let ppc = Processor::powerpc();
        assert_eq!(ppc.name, "PowerPC");
    }

    #[test]
    fn test_processor_display() {
        let proc = Processor::new("test");
        assert_eq!(format!("{}", proc), "test (0 languages)");
    }

    #[test]
    fn test_processor_to_string() {
        let proc = Processor::x86();
        // The display includes language count
        assert!(proc.to_string().starts_with("x86"));
    }

}
