//! SPARC V8/V9 Register Definitions
//!
//! Defines the complete register set for SPARC V8 (32-bit) and V9 (64-bit)
//! processors including:
//! - Register windows: global, in, local, out (with CWP window pointer)
//! - FPU registers: f0-f63 (single/double/quad precision views)
//! - State/control registers: PSR, WIM, TBR, FSR, Y, ASI, etc.
//! - V9-specific: ASR, PSTATE, CCR, GL, TL, TICK, etc.
//! - VIS: GSR, TICK, STICK, SYS_TICK, SYS_STICK, SOFTINT
//!
//! Register space layout (offsets):
//! - Global %g0-%g7:        0x0000 - 0x0038
//! - Out %o0-%o7:           0x0040 - 0x0078
//! - Local %l0-%l7:         0x0080 - 0x00B8
//! - In %i0-%i7:            0x00C0 - 0x00F8
//! - Control/Status:        0x0100 - 0x017F
//! - ASR (%y, %asr0-31):    0x0180 - 0x027F
//! - Privileged:            0x0280 - 0x02FF
//! - FPU (%f0-63):          0x0300 - 0x04FF
//! - VIS extended:          0x0500 - 0x057F

// Re-export the register bank and related types from the parent module.
pub use super::SparcRegisterBank;

/// Register offset constants.
pub const GREG_BASE: u64 = 0x0000;
pub const OREG_BASE: u64 = 0x0040;
pub const LREG_BASE: u64 = 0x0080;
pub const IREG_BASE: u64 = 0x00C0;
pub const CONTROL_BASE: u64 = 0x0100;
pub const ASR_BASE: u64 = 0x0180;
pub const PRIV_BASE: u64 = 0x0280;
pub const FPU_BASE: u64 = 0x0300;
pub const VIS_BASE: u64 = 0x0500;

/// Window constants.
pub const NWINDOWS_MIN: u32 = 2;
pub const NWINDOWS_MAX: u32 = 32;
pub const NWINDOWS_DEFAULT: u32 = 8;
