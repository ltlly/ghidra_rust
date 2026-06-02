//! MIPS32/MIPS64 Register Definitions
//!
//! Re-exports from the parent module.

pub use super::{
    MipsRegisterBank, StatusField, CauseField, Cp0Register, ExceptionCode, ConfigField,
    MIPS_GPR_ABI_NAMES,
};

/// Register offset constants.
pub const GPR_OFFSET_BASE: u64 = 0x0000;
pub const SPECIAL_OFFSET_BASE: u64 = 0x0100;
pub const CP0_OFFSET_BASE: u64 = 0x0200;
pub const FPU_OFFSET_BASE: u64 = 0x0400;
pub const FPU_CTRL_OFFSET_BASE: u64 = 0x0500;
pub const MSA_OFFSET_BASE: u64 = 0x0600;
pub const DSP_ACC_OFFSET_BASE: u64 = 0x0700;
