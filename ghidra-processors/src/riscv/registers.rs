//! RISC-V Register Definitions
//!
//! Defines the complete register set for RISC-V 32/64-bit processors:
//! - 32 general-purpose integer registers x0-x31 (64-bit in RV64)
//! - ABI aliases: zero, ra, sp, gp, tp, t0-t6, s0-s11/fp, a0-a7
//! - 32 floating-point registers f0-f31 (64-bit, with 32-bit single-precision aliases)
//! - PC (Program Counter)
//! - Machine-level CSRs: mstatus, misa, mie, mtvec, mepc, mcause, mtval, mip, mscratch, etc.
//! - Supervisor CSRs: sstatus, sie, stvec, sepc, scause, stval, sip, satp, etc.
//! - Hypervisor CSRs: hstatus, hie, htval, hip, hvip, hgatp, etc.
//! - Virtual Supervisor CSRs: vsstatus, vsie, vstvec, vsepc, etc.
//! - User CSRs: ustatus, uie, utvec, uscratch, uepc, ucause, utval, uip
//! - FPU CSRs: fflags, frm, fcsr
//! - Shadow read-only CSRs: cycle, time, instret
//!
//! Register space layout:
//! - x0-x31 (GPR):     0x0000 - 0x00F8
//! - f0-f31 (FPR):     0x0100 - 0x01F8
//! - PC:               0x0200
//! - CSR space:        0x0300 - 0x0FFF (mapped by CSR address)

pub use super::{
    ExceptionCode, InterruptBit, McauseBit, MstatusBit, RiscVRegisterBank, SatpMode,
};

/// GPR/FPR offset constants.
pub const GPR_OFFSET_BASE: u64 = 0x0000;
pub const FPR_OFFSET_BASE: u64 = 0x0100;
pub const PC_OFFSET: u64 = 0x0200;
pub const CSR_OFFSET_BASE: u64 = 0x0300;

/// Standard CSR addresses (12-bit CSR address space).
pub const CSR_USTATUS: u16 = 0x000;
pub const CSR_UIE: u16 = 0x004;
pub const CSR_UTVEC: u16 = 0x005;
pub const CSR_USCRATCH: u16 = 0x040;
pub const CSR_UEPC: u16 = 0x041;
pub const CSR_UCAUSE: u16 = 0x042;
pub const CSR_UTVAL: u16 = 0x043;
pub const CSR_UIP: u16 = 0x044;
pub const CSR_FFLAGS: u16 = 0x001;
pub const CSR_FRM: u16 = 0x002;
pub const CSR_FCSR: u16 = 0x003;
pub const CSR_CYCLE: u16 = 0xC00;
pub const CSR_TIME: u16 = 0xC01;
pub const CSR_INSTRET: u16 = 0xC02;
pub const CSR_CYCLEH: u16 = 0xC80;
pub const CSR_TIMEH: u16 = 0xC81;
pub const CSR_INSTRETH: u16 = 0xC82;

pub const CSR_SSTATUS: u16 = 0x100;
pub const CSR_SEDELEG: u16 = 0x102;
pub const CSR_SIDELEG: u16 = 0x103;
pub const CSR_SIE: u16 = 0x104;
pub const CSR_STVEC: u16 = 0x105;
pub const CSR_SCOUNTEREN: u16 = 0x106;
pub const CSR_SSCRATCH: u16 = 0x140;
pub const CSR_SEPC: u16 = 0x141;
pub const CSR_SCAUSE: u16 = 0x142;
pub const CSR_STVAL: u16 = 0x143;
pub const CSR_SIP: u16 = 0x144;
pub const CSR_SATP: u16 = 0x180;

pub const CSR_VSSTATUS: u16 = 0x200;
pub const CSR_VSIE: u16 = 0x204;
pub const CSR_VSTVEC: u16 = 0x205;
pub const CSR_VSSCRATCH: u16 = 0x240;
pub const CSR_VSEPC: u16 = 0x241;
pub const CSR_VSCAUSE: u16 = 0x242;
pub const CSR_VSTVAL: u16 = 0x243;
pub const CSR_VSIP: u16 = 0x244;
pub const CSR_VSATP: u16 = 0x280;

pub const CSR_MSTATUS: u16 = 0x300;
pub const CSR_MISA: u16 = 0x301;
pub const CSR_MEDELEG: u16 = 0x302;
pub const CSR_MIDELEG: u16 = 0x303;
pub const CSR_MIE: u16 = 0x304;
pub const CSR_MTVEC: u16 = 0x305;
pub const CSR_MCOUNTEREN: u16 = 0x306;
pub const CSR_MSCRATCH: u16 = 0x340;
pub const CSR_MEPC: u16 = 0x341;
pub const CSR_MCAUSE: u16 = 0x342;
pub const CSR_MTVAL: u16 = 0x343;
pub const CSR_MIP: u16 = 0x344;
pub const CSR_MTINST: u16 = 0x34A;
pub const CSR_MTVAL2: u16 = 0x34B;
pub const CSR_MENVCFG: u16 = 0x30A;
pub const CSR_MSECCFG: u16 = 0x747;
pub const CSR_MCYCLE: u16 = 0xB00;
pub const CSR_MINSTRET: u16 = 0xB02;
pub const CSR_MCOUNTINHIBIT: u16 = 0x320;
pub const CSR_MHARTID: u16 = 0xF14;
pub const CSR_MARCHID: u16 = 0xF12;
pub const CSR_MIMPID: u16 = 0xF13;
pub const CSR_MVENDORID: u16 = 0xF11;

pub const CSR_HSTATUS: u16 = 0x600;
pub const CSR_HEDELEG: u16 = 0x602;
pub const CSR_HIDELEG: u16 = 0x603;
pub const CSR_HIE: u16 = 0x604;
pub const CSR_HCOUNTEREN: u16 = 0x606;
pub const CSR_HGEIE: u16 = 0x607;
pub const CSR_HTVAL: u16 = 0x643;
pub const CSR_HIP: u16 = 0x644;
pub const CSR_HVIP: u16 = 0x645;
pub const CSR_HTINST: u16 = 0x64A;
pub const CSR_HGATP: u16 = 0x680;
pub const CSR_HENVCFG: u16 = 0x60A;
