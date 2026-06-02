//! PowerPC Register Definitions
//!
//! Defines the complete register set for PowerPC 32/64-bit processors:
//! - 32 general-purpose registers GPR0-GPR31 (64-bit, with 32-bit R0-R31 aliases)
//! - 32 floating-point registers FPR0-FPR31 (64-bit, with F0-F31 aliases)
//! - CR (Condition Register, 32-bit, 8 x 4-bit fields CR0-CR7)
//! - LR (Link Register, 64-bit)
//! - CTR (Count Register, 64-bit)
//! - XER (Fixed-Point Exception Register, 64-bit)
//! - MSR (Machine State Register, 64-bit)
//! - SRR0, SRR1 (Save/Restore Registers)
//! - SPRG0-SPRG3 (SPR General-purpose registers)
//! - DSISR, DAR (Data storage interrupt / Data address)
//! - DEC, TB, TBU (Decrementer, Time Base)
//! - PVR (Processor Version Register)
//! - VR0-VR31 (AltiVec/VMX vector registers, 128-bit)
//! - VSCR, VRSAVE (Vector status/save control)
//! - VSR0-VSR63 (VSX vector-scalar registers, 128-bit)
//!
//! Register space layout:
//! - GPR0-GPR31:     0x0000 - 0x00F8
//! - FPR0-FPR31:     0x0100 - 0x01F8
//! - CR:             0x0200
//! - LR:             0x0204
//! - CTR:            0x020C
//! - XER:            0x0214
//! - MSR:            0x021C
//! - SRR0:           0x0224
//! - SRR1:           0x022C
//! - SPRG0-3:        0x0230 - 0x0248
//! - VR0-VR31:       0x0300 - 0x04F8
//! - VSR0-VSR63:     0x0500 - 0x06F8

pub use super::{
    PowerPcRegisterBank, MsrBit, CrField, XerBit,
};

/// Register offset constants.
pub const GPR_OFFSET_BASE: u64 = 0x0000;
pub const FPR_OFFSET_BASE: u64 = 0x0100;
pub const CR_OFFSET: u64 = 0x0200;
pub const LR_OFFSET: u64 = 0x0204;
pub const CTR_OFFSET: u64 = 0x020C;
pub const XER_OFFSET: u64 = 0x0214;
pub const MSR_OFFSET: u64 = 0x021C;
pub const SRR0_OFFSET: u64 = 0x0224;
pub const SRR1_OFFSET: u64 = 0x022C;
pub const SPRG_OFFSET_BASE: u64 = 0x0230;
pub const DSISR_OFFSET: u64 = 0x0250;
pub const DAR_OFFSET: u64 = 0x0258;
pub const DEC_OFFSET: u64 = 0x0260;
pub const TB_OFFSET: u64 = 0x0268;
pub const TBU_OFFSET: u64 = 0x0270;
pub const PVR_OFFSET: u64 = 0x0278;
pub const VR_OFFSET_BASE: u64 = 0x0300;
pub const VSCR_OFFSET: u64 = 0x0400;
pub const VRSAVE_OFFSET: u64 = 0x0404;
pub const VSR_OFFSET_BASE: u64 = 0x0500;
