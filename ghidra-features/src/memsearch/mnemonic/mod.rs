//! Mnemonic-based instruction search -- ported from
//! `ghidra.features.base.memsearch.mnemonic`.
//!
//! Builds mask/value pairs from selected instructions to search for
//! matching instruction patterns in memory.

mod mask_value;
mod mask_generator;
mod mask_control;

pub use mask_value::MaskValue;
pub use mask_generator::MaskGenerator;
pub use mask_control::SLMaskControl;
