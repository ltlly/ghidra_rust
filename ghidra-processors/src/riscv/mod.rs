//! RISC-V Processor Module
//!
//! Complete RISC-V processor support for the Ghidra Rust implementation.
//!
//! ## Supported Extensions
//!
//! | Extension   | Description                                     |
//! |-------------|-------------------------------------------------|
//! | RV32I       | Base 32-bit Integer ISA, 40 instructions        |
//! | RV64I       | Base 64-bit Integer ISA, 15 additional          |
//! | M           | Integer Multiply/Divide                         |
//! | A           | Atomic Instructions                             |
//! | F           | Single-Precision Floating-Point                 |
//! | D           | Double-Precision Floating-Point                 |
//! | C           | Compressed Instructions (16-bit encoding)       |
//! | Zicsr       | Control and Status Register Instructions         |
//! | Zifencei    | Instruction-Fetch Fence                         |
//! | Zba         | Address Generation (Bitmanip)                    |
//! | Zbb         | Basic Bit Manipulation                           |
//! | Zbc         | Carry-less Multiplication                        |
//! | Zbs         | Single-Bit Manipulation                          |
//! | Zfh         | Half-Precision Floating-Point                    |
//! | Zbkb        | Bitmanip crypto (pack, packh, etc.)             |
//! | V           | Vector Extension (RVV)                           |
//! | H           | Hypervisor Extension                             |
//! | S           | Supervisor-level CSRs                            |
//! | U           | User-level CSRs                                  |
//! | Zk/Zkn/Zks  | Scalar Cryptography                              |
//!
//! ## Register Model
//!
//! - x0-x31: 32 general-purpose registers (64-bit in RV64, 32-bit in RV32)
//!   ABI names: zero, ra, sp, gp, tp, t0-t6, s0-s11, a0-a7
//!   fp is an alias for s0
//! - f0-f31: 32 floating-point registers (32-bit for F, 64-bit for D)
//!   with 32-bit single-precision sub-register aliases fN_s
//! - pc: Program Counter
//! - Full CSR coverage across Machine, Supervisor, Hypervisor, and User privilege levels
//!
//! ## Module Structure
//!
//! - Register definitions with full CSR and sub-register coverage
//! - Complete instruction mnemonic enumeration (200+ mnemonics)
//! - mstatus/mcause/mie/mip bit field definitions
//! - ProcessorModule trait implementation

pub mod registers;

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

// ============================================================================
// Processor Name Constants
// ============================================================================

pub const PROCESSOR_NAME: &str = "RISC-V";

pub const PROCESSOR_DESCRIPTION: &str =
    "RISC-V 32/64-bit processor family including extensions RV32I, RV64I, M, A, F, D, C, Zicsr, V";

// ============================================================================
// RISC-V Extension Set
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiscVExtension {
    RV32I,
    RV64I,
    M,
    A,
    F,
    D,
    C,
    Zicsr,
    Zifencei,
    Zba,
    Zbb,
    Zbc,
    Zbs,
    Zfh,
    V,
    H,
    Sstc,
    Svinval,
    Svnapot,
    Svpbmt,
    Zk,
    Zkn,
    Zks,
    Zkr,
    Zihintpause,
    Zihintntl,
}

impl RiscVExtension {
    pub fn name(&self) -> &'static str {
        match self {
            RiscVExtension::RV32I => "RV32I",
            RiscVExtension::RV64I => "RV64I",
            RiscVExtension::M => "M",
            RiscVExtension::A => "A",
            RiscVExtension::F => "F",
            RiscVExtension::D => "D",
            RiscVExtension::C => "C",
            RiscVExtension::Zicsr => "Zicsr",
            RiscVExtension::Zifencei => "Zifencei",
            RiscVExtension::Zba => "Zba",
            RiscVExtension::Zbb => "Zbb",
            RiscVExtension::Zbc => "Zbc",
            RiscVExtension::Zbs => "Zbs",
            RiscVExtension::Zfh => "Zfh",
            RiscVExtension::V => "V",
            RiscVExtension::H => "H",
            RiscVExtension::Sstc => "Sstc",
            RiscVExtension::Svinval => "Svinval",
            RiscVExtension::Svnapot => "Svnapot",
            RiscVExtension::Svpbmt => "Svpbmt",
            RiscVExtension::Zk => "Zk",
            RiscVExtension::Zkn => "Zkn",
            RiscVExtension::Zks => "Zks",
            RiscVExtension::Zkr => "Zkr",
            RiscVExtension::Zihintpause => "Zihintpause",
            RiscVExtension::Zihintntl => "Zihintntl",
        }
    }
}

impl std::fmt::Display for RiscVExtension {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// RISC-V XLEN variants
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiscVXlen {
    RV32,
    RV64,
    RV128,
}

impl RiscVXlen {
    pub fn bits(&self) -> u32 {
        match self {
            RiscVXlen::RV32 => 32,
            RiscVXlen::RV64 => 64,
            RiscVXlen::RV128 => 128,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            RiscVXlen::RV32 => "RV32",
            RiscVXlen::RV64 => "RV64",
            RiscVXlen::RV128 => "RV128",
        }
    }

    pub fn is_32bit(&self) -> bool {
        matches!(self, RiscVXlen::RV32)
    }

    pub fn is_64bit(&self) -> bool {
        matches!(self, RiscVXlen::RV64)
    }
}

// ============================================================================
// Privilege Levels
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrivilegeLevel {
    User,
    Supervisor,
    Hypervisor,
    Machine,
}

impl PrivilegeLevel {
    pub fn name(&self) -> &'static str {
        match self {
            PrivilegeLevel::User => "U",
            PrivilegeLevel::Supervisor => "S",
            PrivilegeLevel::Hypervisor => "H",
            PrivilegeLevel::Machine => "M",
        }
    }
}

// ============================================================================
// mstatus Bit Fields (Machine Status Register)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MstatusBit {
    UIE = 0,
    SIE = 1,
    MIE = 3,
    UPIE = 4,
    SPIE = 5,
    UBE = 6,
    MPIE = 7,
    SPP = 8,
    VS0 = 9,
    VS1 = 10,
    MPP0 = 11,
    MPP1 = 12,
    FS0 = 13,
    FS1 = 14,
    XS0 = 15,
    XS1 = 16,
    MPRV = 17,
    SUM = 18,
    MXR = 19,
    TVM = 20,
    TW = 21,
    TSR = 22,
    UXL0 = 32,
    UXL1 = 33,
    SXL0 = 34,
    SXL1 = 35,
    SBE = 36,
    MBE = 37,
    GVA = 38,
    MPV = 39,
    SD = 63,
}

impl MstatusBit {
    pub fn mask(&self) -> u64 {
        1u64 << (*self as u32)
    }

    pub fn bit(&self) -> u32 {
        *self as u32
    }

    pub fn name(&self) -> &'static str {
        match self {
            MstatusBit::UIE => "UIE",
            MstatusBit::SIE => "SIE",
            MstatusBit::MIE => "MIE",
            MstatusBit::UPIE => "UPIE",
            MstatusBit::SPIE => "SPIE",
            MstatusBit::UBE => "UBE",
            MstatusBit::MPIE => "MPIE",
            MstatusBit::SPP => "SPP",
            MstatusBit::VS0 => "VS0",
            MstatusBit::VS1 => "VS1",
            MstatusBit::MPP0 => "MPP0",
            MstatusBit::MPP1 => "MPP1",
            MstatusBit::FS0 => "FS0",
            MstatusBit::FS1 => "FS1",
            MstatusBit::XS0 => "XS0",
            MstatusBit::XS1 => "XS1",
            MstatusBit::MPRV => "MPRV",
            MstatusBit::SUM => "SUM",
            MstatusBit::MXR => "MXR",
            MstatusBit::TVM => "TVM",
            MstatusBit::TW => "TW",
            MstatusBit::TSR => "TSR",
            MstatusBit::UXL0 => "UXL0",
            MstatusBit::UXL1 => "UXL1",
            MstatusBit::SXL0 => "SXL0",
            MstatusBit::SXL1 => "SXL1",
            MstatusBit::SBE => "SBE",
            MstatusBit::MBE => "MBE",
            MstatusBit::GVA => "GVA",
            MstatusBit::MPV => "MPV",
            MstatusBit::SD => "SD",
        }
    }
}

/// FS field values for mstatus.FS
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsState {
    Off = 0,
    Initial = 1,
    Clean = 2,
    Dirty = 3,
}

/// VS field values for mstatus.VS (vector context state)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VsState {
    Off = 0,
    Initial = 1,
    Clean = 2,
    Dirty = 3,
}

/// XS field values for mstatus.XS (user extension context state)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XsState {
    AllOff = 0,
    NoneDirtyOrClean = 1,
    SomeDirty = 2,
    SomeClean = 3,
}

/// MPP field values for mstatus.MPP (machine previous privilege)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MppMode {
    User = 0,
    Supervisor = 1,
    Machine = 3,
}

// ============================================================================
// mcause Bit Fields and Exception Codes
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum McauseBit {
    Interrupt = 63,
}

impl McauseBit {
    pub fn mask(&self) -> u64 {
        1u64 << (*self as u32)
    }

    pub fn bit(&self) -> u32 {
        *self as u32
    }
}

/// Machine cause exception/interrupt codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExceptionCode {
    InstructionAddressMisaligned = 0,
    InstructionAccessFault = 1,
    IllegalInstruction = 2,
    Breakpoint = 3,
    LoadAddressMisaligned = 4,
    LoadAccessFault = 5,
    StoreAMOAddressMisaligned = 6,
    StoreAMOAccessFault = 7,
    EnvironmentCallFromUMode = 8,
    EnvironmentCallFromSMode = 9,
    EnvironmentCallFromMMode = 11,
    InstructionPageFault = 12,
    LoadPageFault = 13,
    StoreAMOPageFault = 15,
    SoftwareCheck = 18,
    HardwareError = 19,
    InstructionGuestPageFault = 20,
    LoadGuestPageFault = 21,
    VirtualInstruction = 22,
    StoreGuestPageFault = 23,
    // Interrupt codes share the same numeric values as exceptions;
    // they're distinguished by the top bit of mcause.
    SupervisorSoftwareInterrupt,
    MachineSoftwareInterrupt,
    SupervisorTimerInterrupt,
    MachineTimerInterrupt,
    SupervisorExternalInterrupt,
    MachineExternalInterrupt,
    CounterOverflowInterrupt,
    GuestExternalInterrupt,
}

impl ExceptionCode {
    pub fn code(&self) -> u32 {
        *self as u32
    }

    pub fn is_interrupt(&self) -> bool {
        matches!(
            self,
            ExceptionCode::SupervisorSoftwareInterrupt
                | ExceptionCode::MachineSoftwareInterrupt
                | ExceptionCode::SupervisorTimerInterrupt
                | ExceptionCode::MachineTimerInterrupt
                | ExceptionCode::SupervisorExternalInterrupt
                | ExceptionCode::MachineExternalInterrupt
                | ExceptionCode::CounterOverflowInterrupt
                | ExceptionCode::GuestExternalInterrupt
        )
    }

    pub fn name(&self) -> &'static str {
        match self {
            ExceptionCode::InstructionAddressMisaligned => "InstructionAddressMisaligned",
            ExceptionCode::InstructionAccessFault => "InstructionAccessFault",
            ExceptionCode::IllegalInstruction => "IllegalInstruction",
            ExceptionCode::Breakpoint => "Breakpoint",
            ExceptionCode::LoadAddressMisaligned => "LoadAddressMisaligned",
            ExceptionCode::LoadAccessFault => "LoadAccessFault",
            ExceptionCode::StoreAMOAddressMisaligned => "StoreAMOAddressMisaligned",
            ExceptionCode::StoreAMOAccessFault => "StoreAMOAccessFault",
            ExceptionCode::EnvironmentCallFromUMode => "EnvironmentCallFromUMode",
            ExceptionCode::EnvironmentCallFromSMode => "EnvironmentCallFromSMode",
            ExceptionCode::EnvironmentCallFromMMode => "EnvironmentCallFromMMode",
            ExceptionCode::InstructionPageFault => "InstructionPageFault",
            ExceptionCode::LoadPageFault => "LoadPageFault",
            ExceptionCode::StoreAMOPageFault => "StoreAMOPageFault",
            ExceptionCode::SoftwareCheck => "SoftwareCheck",
            ExceptionCode::HardwareError => "HardwareError",
            ExceptionCode::InstructionGuestPageFault => "InstructionGuestPageFault",
            ExceptionCode::LoadGuestPageFault => "LoadGuestPageFault",
            ExceptionCode::VirtualInstruction => "VirtualInstruction",
            ExceptionCode::StoreGuestPageFault => "StoreGuestPageFault",
            ExceptionCode::SupervisorSoftwareInterrupt => "SupervisorSoftwareInterrupt",
            ExceptionCode::MachineSoftwareInterrupt => "MachineSoftwareInterrupt",
            ExceptionCode::SupervisorTimerInterrupt => "SupervisorTimerInterrupt",
            ExceptionCode::MachineTimerInterrupt => "MachineTimerInterrupt",
            ExceptionCode::SupervisorExternalInterrupt => "SupervisorExternalInterrupt",
            ExceptionCode::MachineExternalInterrupt => "MachineExternalInterrupt",
            ExceptionCode::CounterOverflowInterrupt => "CounterOverflowInterrupt",
            ExceptionCode::GuestExternalInterrupt => "GuestExternalInterrupt",
        }
    }
}

// ============================================================================
// MIE / MIP Bit Fields (Machine Interrupt Enable / Pending)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterruptBit {
    USIE = 0,
    SSIE = 1,
    VSIE = 2,
    MSIE = 3,
    UTIE = 4,
    STIE = 5,
    VTIE = 6,
    MTIE = 7,
    UEIE = 8,
    SEIE = 9,
    VEIE = 10,
    MEIE = 11,
    SGEIE = 12,
    LCOFIE = 13,
}

impl InterruptBit {
    pub fn mask(&self) -> u64 {
        1u64 << (*self as u32)
    }

    pub fn bit(&self) -> u32 {
        *self as u32
    }

    pub fn name(&self) -> &'static str {
        match self {
            InterruptBit::USIE => "USIE",
            InterruptBit::SSIE => "SSIE",
            InterruptBit::VSIE => "VSIE",
            InterruptBit::MSIE => "MSIE",
            InterruptBit::UTIE => "UTIE",
            InterruptBit::STIE => "STIE",
            InterruptBit::VTIE => "VTIE",
            InterruptBit::MTIE => "MTIE",
            InterruptBit::UEIE => "UEIE",
            InterruptBit::SEIE => "SEIE",
            InterruptBit::VEIE => "VEIE",
            InterruptBit::MEIE => "MEIE",
            InterruptBit::SGEIE => "SGEIE",
            InterruptBit::LCOFIE => "LCOFIE",
        }
    }
}

// ============================================================================
// satp Mode
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SatpMode {
    Bare = 0,
    Sv32 = 1,
    Sv39 = 8,
    Sv48 = 9,
    Sv57 = 10,
    Sv64 = 11,
}

impl SatpMode {
    pub fn from_bits(bits: u64) -> Option<Self> {
        match bits {
            0 => Some(SatpMode::Bare),
            1 => Some(SatpMode::Sv32),
            8 => Some(SatpMode::Sv39),
            9 => Some(SatpMode::Sv48),
            10 => Some(SatpMode::Sv57),
            11 => Some(SatpMode::Sv64),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            SatpMode::Bare => "Bare",
            SatpMode::Sv32 => "Sv32",
            SatpMode::Sv39 => "Sv39",
            SatpMode::Sv48 => "Sv48",
            SatpMode::Sv57 => "Sv57",
            SatpMode::Sv64 => "Sv64",
        }
    }
}

// ============================================================================
// Register Offset Layout
// ============================================================================

/// Register space layout (offsets):
/// - x0-x31 (GPR):        0x0000 - 0x00F8 (64-bit = 8 bytes each)
/// - f0-f31 (FPR):        0x0100 - 0x01F8
/// - PC:                  0x0200 - 0x0207
/// - CSR space:           0x0300 - 0x0FFF

const GPR_OFFSET_BASE: u64 = 0x0000;
const FPR_OFFSET_BASE: u64 = 0x0100;
const PC_OFFSET: u64 = 0x0200;
const CSR_OFFSET_BASE: u64 = 0x0300;

/// Standard CSR addresses (12-bit CSR address space)
const CSR_USTATUS: u16 = 0x000;
const CSR_UIE: u16 = 0x004;
const CSR_UTVEC: u16 = 0x005;
const CSR_USCRATCH: u16 = 0x040;
const CSR_UEPC: u16 = 0x041;
const CSR_UCAUSE: u16 = 0x042;
const CSR_UTVAL: u16 = 0x043;
const CSR_UIP: u16 = 0x044;
const CSR_FFLAGS: u16 = 0x001;
const CSR_FRM: u16 = 0x002;
const CSR_FCSR: u16 = 0x003;
const CSR_CYCLE: u16 = 0xC00;
const CSR_TIME: u16 = 0xC01;
const CSR_INSTRET: u16 = 0xC02;
const CSR_HPMCOUNTER3: u16 = 0xC03;
const CSR_HPMCOUNTER31: u16 = 0xC1F;
const CSR_CYCLEH: u16 = 0xC80;
const CSR_TIMEH: u16 = 0xC81;
const CSR_INSTRETH: u16 = 0xC82;

const CSR_SSTATUS: u16 = 0x100;
const CSR_SEDELEG: u16 = 0x102;
const CSR_SIDELEG: u16 = 0x103;
const CSR_SIE: u16 = 0x104;
const CSR_STVEC: u16 = 0x105;
const CSR_SCOUNTEREN: u16 = 0x106;
const CSR_SENVCFG: u16 = 0x10A;
const CSR_SSCRATCH: u16 = 0x140;
const CSR_SEPC: u16 = 0x141;
const CSR_SCAUSE: u16 = 0x142;
const CSR_STVAL: u16 = 0x143;
const CSR_SIP: u16 = 0x144;
const CSR_SATP: u16 = 0x180;
const CSR_SCONTEXT: u16 = 0x5A8;

const CSR_VSSTATUS: u16 = 0x200;
const CSR_VSIE: u16 = 0x204;
const CSR_VSTVEC: u16 = 0x205;
const CSR_VSSCRATCH: u16 = 0x240;
const CSR_VSEPC: u16 = 0x241;
const CSR_VSCAUSE: u16 = 0x242;
const CSR_VSTVAL: u16 = 0x243;
const CSR_VSIP: u16 = 0x244;
const CSR_VSATP: u16 = 0x280;

const CSR_MSTATUS: u16 = 0x300;
const CSR_MISA: u16 = 0x301;
const CSR_MEDELEG: u16 = 0x302;
const CSR_MIDELEG: u16 = 0x303;
const CSR_MIE: u16 = 0x304;
const CSR_MTVEC: u16 = 0x305;
const CSR_MCOUNTEREN: u16 = 0x306;
const CSR_MSTATUSH: u16 = 0x310;
const CSR_MSCRATCH: u16 = 0x340;
const CSR_MEPC: u16 = 0x341;
const CSR_MCAUSE: u16 = 0x342;
const CSR_MTVAL: u16 = 0x343;
const CSR_MIP: u16 = 0x344;
const CSR_MTINST: u16 = 0x34A;
const CSR_MTVAL2: u16 = 0x34B;
const CSR_MENVCFG: u16 = 0x30A;
const CSR_MENVCFGH: u16 = 0x31A;
const CSR_MSECCFG: u16 = 0x747;
const CSR_MSECCFGH: u16 = 0x757;
const CSR_MCYCLE: u16 = 0xB00;
const CSR_MINSTRET: u16 = 0xB02;
const CSR_MCYCLEH: u16 = 0xB80;
const CSR_MINSTRETH: u16 = 0xB82;
const CSR_MCOUNTINHIBIT: u16 = 0x320;
const CSR_MHARTID: u16 = 0xF14;
const CSR_MCONFIGPTR: u16 = 0xF15;
const CSR_MARCHID: u16 = 0xF12;
const CSR_MIMPID: u16 = 0xF13;
const CSR_MVENDORID: u16 = 0xF11;

const CSR_HSTATUS: u16 = 0x600;
const CSR_HEDELEG: u16 = 0x602;
const CSR_HIDELEG: u16 = 0x603;
const CSR_HIE: u16 = 0x604;
const CSR_HCOUNTEREN: u16 = 0x606;
const CSR_HGEIE: u16 = 0x607;
const CSR_HTVAL: u16 = 0x643;
const CSR_HIP: u16 = 0x644;
const CSR_HVIP: u16 = 0x645;
const CSR_HTINST: u16 = 0x64A;
const CSR_HGATP: u16 = 0x680;
const CSR_HCONTEXT: u16 = 0x6A8;
const CSR_HENVCFG: u16 = 0x60A;
const CSR_HENVCFGH: u16 = 0x61A;

// ============================================================================
// RISC-V Register Bank
// ============================================================================

#[derive(Debug, Clone)]
pub struct RiscVRegisterBank {
    pub x: [Register; 32],
    pub f: [Register; 32],
    pub pc: Register,
    // Machine CSRs
    pub mstatus: Register,
    pub misa: Register,
    pub medeleg: Register,
    pub mideleg: Register,
    pub mie: Register,
    pub mtvec: Register,
    pub mcounteren: Register,
    pub mscratch: Register,
    pub mepc: Register,
    pub mcause: Register,
    pub mtval: Register,
    pub mip: Register,
    pub mtinst: Register,
    pub mtval2: Register,
    pub menvcfg: Register,
    pub mseccfg: Register,
    pub mcycle: Register,
    pub minstret: Register,
    pub mcountinhibit: Register,
    pub mhartid: Register,
    pub marchid: Register,
    pub mimpid: Register,
    pub mvendorid: Register,
    // Supervisor CSRs
    pub sstatus: Register,
    pub sedeleg: Register,
    pub sideleg: Register,
    pub sie: Register,
    pub stvec: Register,
    pub scounteren: Register,
    pub sscratch: Register,
    pub sepc: Register,
    pub scause: Register,
    pub stval: Register,
    pub sip: Register,
    pub satp: Register,
    // Hypervisor CSRs
    pub hstatus: Register,
    pub hedeleg: Register,
    pub hideleg: Register,
    pub hie: Register,
    pub hcounteren: Register,
    pub hgeie: Register,
    pub htval: Register,
    pub hip: Register,
    pub hvip: Register,
    pub htinst: Register,
    pub hgatp: Register,
    pub henvcfg: Register,
    // Virtual Supervisor CSRs
    pub vsstatus: Register,
    pub vsie: Register,
    pub vstvec: Register,
    pub vsscratch: Register,
    pub vsepc: Register,
    pub vscause: Register,
    pub vstval: Register,
    pub vsip: Register,
    pub vsatp: Register,
    // User CSRs
    pub ustatus: Register,
    pub uie: Register,
    pub utvec: Register,
    pub uscratch: Register,
    pub uepc: Register,
    pub ucause: Register,
    pub utval: Register,
    pub uip: Register,
    // FPU CSRs
    pub fflags: Register,
    pub frm: Register,
    pub fcsr: Register,
    // Shadow read-only CSRs
    pub cycle: Register,
    pub time: Register,
    pub instret: Register,
    register_by_name: std::collections::HashMap<String, Register>,
}

impl RiscVRegisterBank {
    pub fn new_rv64() -> Self {
        let x: [Register; 32] = std::array::from_fn(|i| {
            Register::new(&format!("x{}", i), 64, GPR_OFFSET_BASE + (i as u64) * 8)
        });

        let abi_names: [(&str, u64); 33] = [
            ("zero", 0x00),
            ("ra", 0x08),
            ("sp", 0x10),
            ("gp", 0x18),
            ("tp", 0x20),
            ("t0", 0x28),
            ("t1", 0x30),
            ("t2", 0x38),
            ("s0", 0x40),
            ("fp", 0x40),
            ("s1", 0x48),
            ("a0", 0x50),
            ("a1", 0x58),
            ("a2", 0x60),
            ("a3", 0x68),
            ("a4", 0x70),
            ("a5", 0x78),
            ("a6", 0x80),
            ("a7", 0x88),
            ("s2", 0x90),
            ("s3", 0x98),
            ("s4", 0xA0),
            ("s5", 0xA8),
            ("s6", 0xB0),
            ("s7", 0xB8),
            ("s8", 0xC0),
            ("s9", 0xC8),
            ("s10", 0xD0),
            ("s11", 0xD8),
            ("t3", 0xE0),
            ("t4", 0xE8),
            ("t5", 0xF0),
            ("t6", 0xF8),
        ];

        let f: [Register; 32] = std::array::from_fn(|i| {
            Register::new(&format!("f{}", i), 64, FPR_OFFSET_BASE + (i as u64) * 8)
        });

        let pc = Register::new("pc", 64, PC_OFFSET);

        let csr_offset = |addr: u16| -> u64 { CSR_OFFSET_BASE + addr as u64 };

        // Machine CSRs
        let mstatus = Register::new("mstatus", 64, csr_offset(CSR_MSTATUS));
        let misa = Register::new("misa", 64, csr_offset(CSR_MISA));
        let medeleg = Register::new("medeleg", 64, csr_offset(CSR_MEDELEG));
        let mideleg = Register::new("mideleg", 64, csr_offset(CSR_MIDELEG));
        let mie = Register::new("mie", 64, csr_offset(CSR_MIE));
        let mtvec = Register::new("mtvec", 64, csr_offset(CSR_MTVEC));
        let mcounteren = Register::new("mcounteren", 32, csr_offset(CSR_MCOUNTEREN));
        let mscratch = Register::new("mscratch", 64, csr_offset(CSR_MSCRATCH));
        let mepc = Register::new("mepc", 64, csr_offset(CSR_MEPC));
        let mcause = Register::new("mcause", 64, csr_offset(CSR_MCAUSE));
        let mtval = Register::new("mtval", 64, csr_offset(CSR_MTVAL));
        let mip = Register::new("mip", 64, csr_offset(CSR_MIP));
        let mtinst = Register::new("mtinst", 64, csr_offset(CSR_MTINST));
        let mtval2 = Register::new("mtval2", 64, csr_offset(CSR_MTVAL2));
        let menvcfg = Register::new("menvcfg", 64, csr_offset(CSR_MENVCFG));
        let mseccfg = Register::new("mseccfg", 64, csr_offset(CSR_MSECCFG));
        let mcycle = Register::new("mcycle", 64, csr_offset(CSR_MCYCLE));
        let minstret = Register::new("minstret", 64, csr_offset(CSR_MINSTRET));
        let mcountinhibit = Register::new("mcountinhibit", 32, csr_offset(CSR_MCOUNTINHIBIT));
        let mhartid = Register::new("mhartid", 64, csr_offset(CSR_MHARTID));
        let marchid = Register::new("marchid", 64, csr_offset(CSR_MARCHID));
        let mimpid = Register::new("mimpid", 64, csr_offset(CSR_MIMPID));
        let mvendorid = Register::new("mvendorid", 32, csr_offset(CSR_MVENDORID));

        // Supervisor CSRs
        let sstatus = Register::new("sstatus", 64, csr_offset(CSR_SSTATUS));
        let sedeleg = Register::new("sedeleg", 64, csr_offset(CSR_SEDELEG));
        let sideleg = Register::new("sideleg", 64, csr_offset(CSR_SIDELEG));
        let sie = Register::new("sie", 64, csr_offset(CSR_SIE));
        let stvec = Register::new("stvec", 64, csr_offset(CSR_STVEC));
        let scounteren = Register::new("scounteren", 32, csr_offset(CSR_SCOUNTEREN));
        let sscratch = Register::new("sscratch", 64, csr_offset(CSR_SSCRATCH));
        let sepc = Register::new("sepc", 64, csr_offset(CSR_SEPC));
        let scause = Register::new("scause", 64, csr_offset(CSR_SCAUSE));
        let stval = Register::new("stval", 64, csr_offset(CSR_STVAL));
        let sip = Register::new("sip", 64, csr_offset(CSR_SIP));
        let satp = Register::new("satp", 64, csr_offset(CSR_SATP));

        // Hypervisor CSRs
        let hstatus = Register::new("hstatus", 64, csr_offset(CSR_HSTATUS));
        let hedeleg = Register::new("hedeleg", 64, csr_offset(CSR_HEDELEG));
        let hideleg = Register::new("hideleg", 64, csr_offset(CSR_HIDELEG));
        let hie = Register::new("hie", 64, csr_offset(CSR_HIE));
        let hcounteren = Register::new("hcounteren", 32, csr_offset(CSR_HCOUNTEREN));
        let hgeie = Register::new("hgeie", 64, csr_offset(CSR_HGEIE));
        let htval = Register::new("htval", 64, csr_offset(CSR_HTVAL));
        let hip = Register::new("hip", 64, csr_offset(CSR_HIP));
        let hvip = Register::new("hvip", 64, csr_offset(CSR_HVIP));
        let htinst = Register::new("htinst", 64, csr_offset(CSR_HTINST));
        let hgatp = Register::new("hgatp", 64, csr_offset(CSR_HGATP));
        let henvcfg = Register::new("henvcfg", 64, csr_offset(CSR_HENVCFG));

        // Virtual Supervisor CSRs
        let vsstatus = Register::new("vsstatus", 64, csr_offset(CSR_VSSTATUS));
        let vsie = Register::new("vsie", 64, csr_offset(CSR_VSIE));
        let vstvec = Register::new("vstvec", 64, csr_offset(CSR_VSTVEC));
        let vsscratch = Register::new("vsscratch", 64, csr_offset(CSR_VSSCRATCH));
        let vsepc = Register::new("vsepc", 64, csr_offset(CSR_VSEPC));
        let vscause = Register::new("vscause", 64, csr_offset(CSR_VSCAUSE));
        let vstval = Register::new("vstval", 64, csr_offset(CSR_VSTVAL));
        let vsip = Register::new("vsip", 64, csr_offset(CSR_VSIP));
        let vsatp = Register::new("vsatp", 64, csr_offset(CSR_VSATP));

        // User CSRs
        let ustatus = Register::new("ustatus", 64, csr_offset(CSR_USTATUS));
        let uie = Register::new("uie", 64, csr_offset(CSR_UIE));
        let utvec = Register::new("utvec", 64, csr_offset(CSR_UTVEC));
        let uscratch = Register::new("uscratch", 64, csr_offset(CSR_USCRATCH));
        let uepc = Register::new("uepc", 64, csr_offset(CSR_UEPC));
        let ucause = Register::new("ucause", 64, csr_offset(CSR_UCAUSE));
        let utval = Register::new("utval", 64, csr_offset(CSR_UTVAL));
        let uip = Register::new("uip", 64, csr_offset(CSR_UIP));

        // FPU CSRs
        let fflags = Register::new("fflags", 32, csr_offset(CSR_FFLAGS));
        let frm = Register::new("frm", 32, csr_offset(CSR_FRM));
        let fcsr = Register::new("fcsr", 32, csr_offset(CSR_FCSR));

        // Shadow read-only CSRs
        let cycle = Register::new("cycle", 64, csr_offset(CSR_CYCLE));
        let time = Register::new("time", 64, csr_offset(CSR_TIME));
        let instret = Register::new("instret", 64, csr_offset(CSR_INSTRET));

        // Build lookup table
        let mut register_by_name = std::collections::HashMap::new();

        for (i, reg) in x.iter().enumerate() {
            register_by_name.insert(format!("x{}", i), reg.clone());
        }
        for (name, offset) in &abi_names {
            let r = Register::new(name, 64, GPR_OFFSET_BASE + offset);
            register_by_name.insert(name.to_string(), r);
        }

        for (i, reg) in f.iter().enumerate() {
            register_by_name.insert(format!("f{}", i), reg.clone());
            register_by_name.insert(
                format!("f{}_s", i),
                Register::sub_register(
                    &format!("f{}_s", i),
                    32,
                    FPR_OFFSET_BASE + (i as u64) * 8,
                    &format!("f{}", i),
                    0,
                ),
            );
        }

        register_by_name.insert("pc".to_string(), pc.clone());

        // Machine CSRs
        let machine_csrs: [(&str, &Register); 23] = [
            ("mstatus", &mstatus),
            ("misa", &misa),
            ("medeleg", &medeleg),
            ("mideleg", &mideleg),
            ("mie", &mie),
            ("mtvec", &mtvec),
            ("mcounteren", &mcounteren),
            ("mscratch", &mscratch),
            ("mepc", &mepc),
            ("mcause", &mcause),
            ("mtval", &mtval),
            ("mip", &mip),
            ("mtinst", &mtinst),
            ("mtval2", &mtval2),
            ("menvcfg", &menvcfg),
            ("mseccfg", &mseccfg),
            ("mcycle", &mcycle),
            ("minstret", &minstret),
            ("mcountinhibit", &mcountinhibit),
            ("mhartid", &mhartid),
            ("marchid", &marchid),
            ("mimpid", &mimpid),
            ("mvendorid", &mvendorid),
        ];
        for (name, reg) in &machine_csrs {
            register_by_name.insert(name.to_string(), (*reg).clone());
        }

        // mstatus sub-fields
        for bit in &[
            MstatusBit::UIE,
            MstatusBit::SIE,
            MstatusBit::MIE,
            MstatusBit::UPIE,
            MstatusBit::SPIE,
            MstatusBit::MPIE,
            MstatusBit::SPP,
            MstatusBit::MPRV,
            MstatusBit::SUM,
            MstatusBit::MXR,
            MstatusBit::TVM,
            MstatusBit::TW,
            MstatusBit::TSR,
            MstatusBit::SD,
        ] {
            let field_name = format!("mstatus_{}", bit.name());
            register_by_name.insert(
                field_name.clone(),
                Register::sub_register(
                    &field_name,
                    1,
                    csr_offset(CSR_MSTATUS),
                    "mstatus",
                    bit.bit(),
                ),
            );
        }

        // Shadow CSRs
        register_by_name.insert("cycle".to_string(), cycle.clone());
        register_by_name.insert("time".to_string(), time.clone());
        register_by_name.insert("instret".to_string(), instret.clone());

        // Supervisor CSRs
        let supervisor_csrs: [(&str, &Register); 12] = [
            ("sstatus", &sstatus),
            ("sedeleg", &sedeleg),
            ("sideleg", &sideleg),
            ("sie", &sie),
            ("stvec", &stvec),
            ("scounteren", &scounteren),
            ("sscratch", &sscratch),
            ("sepc", &sepc),
            ("scause", &scause),
            ("stval", &stval),
            ("sip", &sip),
            ("satp", &satp),
        ];
        for (name, reg) in &supervisor_csrs {
            register_by_name.insert(name.to_string(), (*reg).clone());
        }

        // Hypervisor CSRs
        let hypervisor_csrs: [(&str, &Register); 12] = [
            ("hstatus", &hstatus),
            ("hedeleg", &hedeleg),
            ("hideleg", &hideleg),
            ("hie", &hie),
            ("hcounteren", &hcounteren),
            ("hgeie", &hgeie),
            ("htval", &htval),
            ("hip", &hip),
            ("hvip", &hvip),
            ("htinst", &htinst),
            ("hgatp", &hgatp),
            ("henvcfg", &henvcfg),
        ];
        for (name, reg) in &hypervisor_csrs {
            register_by_name.insert(name.to_string(), (*reg).clone());
        }

        // Virtual Supervisor CSRs
        let vs_csrs: [(&str, &Register); 9] = [
            ("vsstatus", &vsstatus),
            ("vsie", &vsie),
            ("vstvec", &vstvec),
            ("vsscratch", &vsscratch),
            ("vsepc", &vsepc),
            ("vscause", &vscause),
            ("vstval", &vstval),
            ("vsip", &vsip),
            ("vsatp", &vsatp),
        ];
        for (name, reg) in &vs_csrs {
            register_by_name.insert(name.to_string(), (*reg).clone());
        }

        // User CSRs
        let user_csrs: [(&str, &Register); 8] = [
            ("ustatus", &ustatus),
            ("uie", &uie),
            ("utvec", &utvec),
            ("uscratch", &uscratch),
            ("uepc", &uepc),
            ("ucause", &ucause),
            ("utval", &utval),
            ("uip", &uip),
        ];
        for (name, reg) in &user_csrs {
            register_by_name.insert(name.to_string(), (*reg).clone());
        }

        // FPU CSRs
        register_by_name.insert("fflags".to_string(), fflags.clone());
        register_by_name.insert("frm".to_string(), frm.clone());
        register_by_name.insert("fcsr".to_string(), fcsr.clone());

        // fcsr sub-fields: fflags and frm are sub-registers of fcsr
        register_by_name.insert(
            "fcsr_fflags".to_string(),
            Register::sub_register("fcsr_fflags", 5, csr_offset(CSR_FCSR), "fcsr", 0),
        );
        register_by_name.insert(
            "fcsr_frm".to_string(),
            Register::sub_register("fcsr_frm", 3, csr_offset(CSR_FCSR), "fcsr", 5),
        );

        RiscVRegisterBank {
            x,
            f,
            pc,
            mstatus,
            misa,
            medeleg,
            mideleg,
            mie,
            mtvec,
            mcounteren,
            mscratch,
            mepc,
            mcause,
            mtval,
            mip,
            mtinst,
            mtval2,
            menvcfg,
            mseccfg,
            mcycle,
            minstret,
            mcountinhibit,
            mhartid,
            marchid,
            mimpid,
            mvendorid,
            sstatus,
            sedeleg,
            sideleg,
            sie,
            stvec,
            scounteren,
            sscratch,
            sepc,
            scause,
            stval,
            sip,
            satp,
            hstatus,
            hedeleg,
            hideleg,
            hie,
            hcounteren,
            hgeie,
            htval,
            hip,
            hvip,
            htinst,
            hgatp,
            henvcfg,
            vsstatus,
            vsie,
            vstvec,
            vsscratch,
            vsepc,
            vscause,
            vstval,
            vsip,
            vsatp,
            ustatus,
            uie,
            utvec,
            uscratch,
            uepc,
            ucause,
            utval,
            uip,
            fflags,
            frm,
            fcsr,
            cycle,
            time,
            instret,
            register_by_name,
        }
    }

    pub fn get(&self, name: &str) -> Option<&Register> {
        self.register_by_name.get(name)
    }

    pub fn sub_registers_of(&self, parent_name: &str) -> Vec<&Register> {
        self.register_by_name
            .values()
            .filter(|r| r.parent.as_deref() == Some(parent_name))
            .collect()
    }

    pub fn top_level_registers(&self) -> Vec<&Register> {
        self.register_by_name
            .values()
            .filter(|r| r.parent.is_none())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.register_by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.register_by_name.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Register> {
        self.register_by_name.values()
    }
}

impl Default for RiscVRegisterBank {
    fn default() -> Self {
        Self::new_rv64()
    }
}

// ============================================================================
// RISC-V Instruction Mnemonics (200+)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiscVMnemonic {
    // ======================================================================
    // RV32I / RV64I Base Integer (49 unique mnemonics)
    // ======================================================================
    LUI,
    AUIPC,
    JAL,
    JALR,
    BEQ,
    BNE,
    BLT,
    BGE,
    BLTU,
    BGEU,
    LB,
    LH,
    LW,
    LBU,
    LHU,
    LD,
    LWU,
    SB,
    SH,
    SW,
    SD,
    ADDI,
    SLTI,
    SLTIU,
    XORI,
    ORI,
    ANDI,
    SLLI,
    SRLI,
    SRAI,
    ADD,
    SUB,
    SLL,
    SLT,
    SLTU,
    XOR,
    SRL,
    SRA,
    OR,
    AND,
    FENCE,
    FENCE_I,
    FENCE_TSO,
    ECALL,
    EBREAK,
    ADDIW,
    SLLIW,
    SRLIW,
    SRAIW,
    ADDW,
    SUBW,
    SLLW,
    SRLW,
    SRAW,

    // ======================================================================
    // M Extension - Multiply/Divide (13 mnemonics)
    // ======================================================================
    MUL,
    MULH,
    MULHSU,
    MULHU,
    DIV,
    DIVU,
    REM,
    REMU,
    MULW,
    DIVW,
    DIVUW,
    REMW,
    REMUW,

    // ======================================================================
    // A Extension - Atomic (22 mnemonics)
    // ======================================================================
    LR_W,
    SC_W,
    AMOSWAP_W,
    AMOADD_W,
    AMOXOR_W,
    AMOAND_W,
    AMOOR_W,
    AMOMIN_W,
    AMOMAX_W,
    AMOMINU_W,
    AMOMAXU_W,
    LR_D,
    SC_D,
    AMOSWAP_D,
    AMOADD_D,
    AMOXOR_D,
    AMOAND_D,
    AMOOR_D,
    AMOMIN_D,
    AMOMAX_D,
    AMOMINU_D,
    AMOMAXU_D,

    // ======================================================================
    // F Extension - Single-Precision FP (26 mnemonics)
    // ======================================================================
    FLW,
    FSW,
    FMADD_S,
    FMSUB_S,
    FNMSUB_S,
    FNMADD_S,
    FADD_S,
    FSUB_S,
    FMUL_S,
    FDIV_S,
    FSQRT_S,
    FSGNJ_S,
    FSGNJN_S,
    FSGNJX_S,
    FMIN_S,
    FMAX_S,
    FCVT_W_S,
    FCVT_WU_S,
    FMV_X_W,
    FEQ_S,
    FLT_S,
    FLE_S,
    FCLASS_S,
    FCVT_S_W,
    FCVT_S_WU,
    FMV_W_X,

    // ======================================================================
    // D Extension - Double-Precision FP (26 mnemonics)
    // ======================================================================
    FLD,
    FSD,
    FMADD_D,
    FMSUB_D,
    FNMSUB_D,
    FNMADD_D,
    FADD_D,
    FSUB_D,
    FMUL_D,
    FDIV_D,
    FSQRT_D,
    FSGNJ_D,
    FSGNJN_D,
    FSGNJX_D,
    FMIN_D,
    FMAX_D,
    FCVT_S_D,
    FCVT_D_S,
    FEQ_D,
    FLT_D,
    FLE_D,
    FCLASS_D,
    FCVT_W_D,
    FCVT_WU_D,
    FCVT_D_W,
    FCVT_D_WU,

    // ======================================================================
    // D Extension - 64-bit FP <-> Integer Conversions (10 mnemonics)
    // ======================================================================
    FCVT_L_S,
    FCVT_LU_S,
    FCVT_S_L,
    FCVT_S_LU,
    FCVT_L_D,
    FCVT_LU_D,
    FCVT_D_L,
    FCVT_D_LU,
    FMV_X_D,
    FMV_D_X,

    // ======================================================================
    // C Extension - Compressed Instructions (34 mnemonics)
    // ======================================================================
    C_ADDI4SPN,
    C_FLD,
    C_LW,
    C_FLW,
    C_LD,
    C_FSD,
    C_SW,
    C_FSW,
    C_SD,
    C_NOP,
    C_ADDI,
    C_JAL,
    C_ADDIW,
    C_LI,
    C_ADDI16SP,
    C_LUI,
    C_SRLI,
    C_SRAI,
    C_ANDI,
    C_SUB,
    C_XOR,
    C_OR,
    C_AND,
    C_SUBW,
    C_ADDW,
    C_J,
    C_BEQZ,
    C_BNEZ,
    C_SLLI,
    C_FLDSP,
    C_LWSP,
    C_FLWSP,
    C_LDSP,
    C_JR,
    C_MV,
    C_EBREAK,
    C_JALR,
    C_ADD,
    C_FSDSP,
    C_SWSP,
    C_FSWSP,
    C_SDSP,

    // ======================================================================
    // Zicsr Extension - CSR Instructions (6 mnemonics)
    // ======================================================================
    CSRRW,
    CSRRS,
    CSRRC,
    CSRRWI,
    CSRRSI,
    CSRRCI,

    // ======================================================================
    // Zba Extension - Address Generation (7 mnemonics)
    // ======================================================================
    SH1ADD,
    SH2ADD,
    SH3ADD,
    SH1ADD_UW,
    SH2ADD_UW,
    SH3ADD_UW,
    SLLI_UW,
    ADD_UW,

    // ======================================================================
    // Zbb Extension - Basic Bit Manipulation (20 mnemonics)
    // ======================================================================
    ANDN,
    ORN,
    XNOR,
    CLZ,
    CTZ,
    CPOP,
    CLZW,
    CTZW,
    CPOPW,
    MAX,
    MAXU,
    MIN,
    MINU,
    SEXT_B,
    SEXT_H,
    ZEXT_H,
    ROL,
    ROR,
    RORI,
    ROLW,
    RORW,
    RORIW,
    ORC_B,
    REV8,

    // ======================================================================
    // Zbs Extension - Single-Bit (8 mnemonics)
    // ======================================================================
    BCLR,
    BCLRI,
    BSET,
    BSETI,
    BINV,
    BINVI,
    BEXT,
    BEXTI,

    // ======================================================================
    // Zbc Extension - Carry-less Multiply (3 mnemonics)
    // ======================================================================
    CLMUL,
    CLMULR,
    CLMULH,

    // ======================================================================
    // Zfh Extension - Half-Precision Float (26 mnemonics)
    // ======================================================================
    FLH,
    FSH,
    FMADD_H,
    FMSUB_H,
    FNMSUB_H,
    FNMADD_H,
    FADD_H,
    FSUB_H,
    FMUL_H,
    FDIV_H,
    FSQRT_H,
    FSGNJ_H,
    FSGNJN_H,
    FSGNJX_H,
    FMIN_H,
    FMAX_H,
    FCVT_S_H,
    FCVT_H_S,
    FCVT_D_H,
    FCVT_H_D,
    FCVT_W_H,
    FCVT_WU_H,
    FCVT_H_W,
    FCVT_H_WU,
    FCVT_L_H,
    FCVT_LU_H,
    FCVT_H_L,
    FCVT_H_LU,
    FEQ_H,
    FLT_H,
    FLE_H,
    FCLASS_H,
    FMV_X_H,
    FMV_H_X,

    // ======================================================================
    // Zbkb Extension - Crypto Bitmanip (5 mnemonics)
    // ======================================================================
    PACK,
    PACKH,
    PACKW,
    BREV8,
    ZIP,
    UNZIP,

    // ======================================================================
    // Zk Scalar Cryptography (24 mnemonics)
    // ======================================================================
    AES32ESMI,
    AES32ESI,
    AES32DSMI,
    AES32DSI,
    AES64ESM,
    AES64ES,
    AES64DSM,
    AES64DS,
    AES64KS1I,
    AES64KS2,
    SHA256SIG0,
    SHA256SIG1,
    SHA256SUM0,
    SHA256SUM1,
    SHA512SIG0H,
    SHA512SIG0L,
    SHA512SIG1H,
    SHA512SIG1L,
    SHA512SUM0R,
    SHA512SUM1R,
    SHA512SIG0,
    SHA512SIG1,
    SM3P0,
    SM3P1,
    SM4ED0,
    SM4ED1,
    SM4ED2,
    SM4ED3,
    SM4KS,
    POLLENTROPY,

    // ======================================================================
    // V Extension - Vector Instructions (40 mnemonics)
    // ======================================================================
    VLE8_V,
    VLE16_V,
    VLE32_V,
    VLE64_V,
    VSE8_V,
    VSE16_V,
    VSE32_V,
    VSE64_V,
    VLM_V,
    VSM_V,
    VLSE8_V,
    VLSE16_V,
    VLSE32_V,
    VLSE64_V,
    VSSE8_V,
    VSSE16_V,
    VSSE32_V,
    VSSE64_V,
    VLUXEI8_V,
    VLUXEI16_V,
    VLUXEI32_V,
    VLUXEI64_V,
    VSUXEI8_V,
    VSUXEI16_V,
    VSUXEI32_V,
    VSUXEI64_V,
    VADD_VV,
    VADD_VX,
    VADD_VI,
    VSUB_VV,
    VSUB_VX,
    VMUL_VV,
    VMUL_VX,
    VMULH_VV,
    VMULH_VX,
    VMULHU_VV,
    VMULHU_VX,
    VDIV_VV,
    VDIV_VX,
    VDIVU_VV,
    VDIVU_VX,
    VAND_VV,
    VAND_VX,
    VAND_VI,
    VOR_VV,
    VOR_VX,
    VOR_VI,
    VXOR_VV,
    VXOR_VX,
    VXOR_VI,
    VSLL_VV,
    VSLL_VX,
    VSLL_VI,
    VSRL_VV,
    VSRL_VX,
    VSRL_VI,
    VSRA_VV,
    VSRA_VX,
    VSRA_VI,
    VMFEQ_VV,
    VMFEQ_VF,
    VMFNE_VV,
    VMFNE_VF,
    VMFLT_VV,
    VMFLT_VF,
    VMFLE_VV,
    VMFLE_VF,
    VMFGT_VV,
    VMFGT_VF,
    VMFGE_VV,
    VMFGE_VF,
    VMERGE_VVM,
    VMERGE_VXM,
    VMV_V_V,
    VMV_V_X,
    VMV_V_I,
    VMV_X_S,
    VMV_S_X,
    VSLIDEUP_VX,
    VSLIDEUP_VI,
    VSLIDEDOWN_VX,
    VSLIDEDOWN_VI,
    VREDSUM_VS,
    VREDMAX_VS,
    VREDMIN_VS,
    VREDAND_VS,
    VREDOR_VS,
    VREDXOR_VS,
    VSETVLI,
    VSETVL,
    VSETIVLI,
    VFADD_VV,
    VFADD_VF,
    VFSUB_VV,
    VFSUB_VF,
    VFMUL_VV,
    VFMUL_VF,
    VFDIV_VV,
    VFDIV_VF,
    VFMADD_VV,
    VFMADD_VF,
    VFNMADD_VV,
    VFNMADD_VF,
    VFMSUB_VV,
    VFMSUB_VF,
    VFNMSUB_VV,
    VFNMSUB_VF,
    VFMERGE_VFM,
    VFMV_V_F,
    VFMV_F_S,
    VFSQRT_V,
    VFCLASS_V,
    VFCVT_XU_F_V,
    VFCVT_X_F_V,
    VFCVT_F_XU_V,
    VFCVT_F_X_V,
    VFWCVT_F_F_V,
    VFWCVT_XU_F_V,
    VFWCVT_X_F_V,
    VFNCVT_F_F_W,
    VFNCVT_XU_F_W,
    VFNCVT_X_F_W,
    VFRSQRT7_V,
    VFREC7_V,
    VFMIN_VV,
    VFMIN_VF,
    VFMAX_VV,
    VFMAX_VF,
    VFSGNJ_VV,
    VFSGNJ_VF,
    VFSGNJN_VV,
    VFSGNJN_VF,
    VFSGNJX_VV,
    VFSGNJX_VF,
    VWADDU_VV,
    VWADDU_VX,
    VWADD_VV,
    VWADD_VX,
    VWSUBU_VV,
    VWSUBU_VX,
    VWSUB_VV,
    VWSUB_VX,
    VWMULU_VV,
    VWMULU_VX,
    VWMUL_VV,
    VWMUL_VX,
    VWMULSU_VV,
    VWMULSU_VX,
    VSEXT_VF2,
    VSEXT_VF4,
    VSEXT_VF8,
    VZEXT_VF2,
    VZEXT_VF4,
    VZEXT_VF8,
    VNSRL_WV,
    VNSRL_WX,
    VNSRL_WI,
    VNSRA_WV,
    VNSRA_WX,
    VNSRA_WI,
    VNCVT_X_X_W,
    VCOMPRESS_VM,
    VMAND_MM,
    VMNAND_MM,
    VMANDN_MM,
    VMXOR_MM,
    VMOR_MM,
    VMNOR_MM,
    VMORN_MM,
    VMXNOR_MM,
    VPOPC_M,
    VFIRST_M,
    VMSBF_M,
    VMSIF_M,
    VMSOF_M,
    VIOTA_M,
    VID_V,

    // ======================================================================
    // Privileged / System (14 mnemonics)
    // ======================================================================
    WFI,
    MRET,
    SRET,
    MNRET,
    SFENCE_VMA,
    SINVAL_VMA,
    SFENCE_W_INVAL,
    SFENCE_INVAL_IR,
    HFENCE_VVMA,
    HFENCE_GVMA,
    HLV_B,
    HLV_H,
    HLV_W,
    HLV_D,
    HLV_BU,
    HLV_HU,
    HLV_WU,
    HSV_B,
    HSV_H,
    HSV_W,
    HSV_D,
    PAUSE,
}

impl RiscVMnemonic {
    pub fn as_str(&self) -> &'static str {
        match self {
            // RV32I / RV64I
            RiscVMnemonic::LUI => "LUI",
            RiscVMnemonic::AUIPC => "AUIPC",
            RiscVMnemonic::JAL => "JAL",
            RiscVMnemonic::JALR => "JALR",
            RiscVMnemonic::BEQ => "BEQ",
            RiscVMnemonic::BNE => "BNE",
            RiscVMnemonic::BLT => "BLT",
            RiscVMnemonic::BGE => "BGE",
            RiscVMnemonic::BLTU => "BLTU",
            RiscVMnemonic::BGEU => "BGEU",
            RiscVMnemonic::LB => "LB",
            RiscVMnemonic::LH => "LH",
            RiscVMnemonic::LW => "LW",
            RiscVMnemonic::LBU => "LBU",
            RiscVMnemonic::LHU => "LHU",
            RiscVMnemonic::LD => "LD",
            RiscVMnemonic::LWU => "LWU",
            RiscVMnemonic::SB => "SB",
            RiscVMnemonic::SH => "SH",
            RiscVMnemonic::SW => "SW",
            RiscVMnemonic::SD => "SD",
            RiscVMnemonic::ADDI => "ADDI",
            RiscVMnemonic::SLTI => "SLTI",
            RiscVMnemonic::SLTIU => "SLTIU",
            RiscVMnemonic::XORI => "XORI",
            RiscVMnemonic::ORI => "ORI",
            RiscVMnemonic::ANDI => "ANDI",
            RiscVMnemonic::SLLI => "SLLI",
            RiscVMnemonic::SRLI => "SRLI",
            RiscVMnemonic::SRAI => "SRAI",
            RiscVMnemonic::ADD => "ADD",
            RiscVMnemonic::SUB => "SUB",
            RiscVMnemonic::SLL => "SLL",
            RiscVMnemonic::SLT => "SLT",
            RiscVMnemonic::SLTU => "SLTU",
            RiscVMnemonic::XOR => "XOR",
            RiscVMnemonic::SRL => "SRL",
            RiscVMnemonic::SRA => "SRA",
            RiscVMnemonic::OR => "OR",
            RiscVMnemonic::AND => "AND",
            RiscVMnemonic::FENCE => "FENCE",
            RiscVMnemonic::FENCE_I => "FENCE.I",
            RiscVMnemonic::FENCE_TSO => "FENCE.TSO",
            RiscVMnemonic::ECALL => "ECALL",
            RiscVMnemonic::EBREAK => "EBREAK",
            RiscVMnemonic::ADDIW => "ADDIW",
            RiscVMnemonic::SLLIW => "SLLIW",
            RiscVMnemonic::SRLIW => "SRLIW",
            RiscVMnemonic::SRAIW => "SRAIW",
            RiscVMnemonic::ADDW => "ADDW",
            RiscVMnemonic::SUBW => "SUBW",
            RiscVMnemonic::SLLW => "SLLW",
            RiscVMnemonic::SRLW => "SRLW",
            RiscVMnemonic::SRAW => "SRAW",
            // M Extension
            RiscVMnemonic::MUL => "MUL",
            RiscVMnemonic::MULH => "MULH",
            RiscVMnemonic::MULHSU => "MULHSU",
            RiscVMnemonic::MULHU => "MULHU",
            RiscVMnemonic::DIV => "DIV",
            RiscVMnemonic::DIVU => "DIVU",
            RiscVMnemonic::REM => "REM",
            RiscVMnemonic::REMU => "REMU",
            RiscVMnemonic::MULW => "MULW",
            RiscVMnemonic::DIVW => "DIVW",
            RiscVMnemonic::DIVUW => "DIVUW",
            RiscVMnemonic::REMW => "REMW",
            RiscVMnemonic::REMUW => "REMUW",
            // A Extension
            RiscVMnemonic::LR_W => "LR.W",
            RiscVMnemonic::SC_W => "SC.W",
            RiscVMnemonic::AMOSWAP_W => "AMOSWAP.W",
            RiscVMnemonic::AMOADD_W => "AMOADD.W",
            RiscVMnemonic::AMOXOR_W => "AMOXOR.W",
            RiscVMnemonic::AMOAND_W => "AMOAND.W",
            RiscVMnemonic::AMOOR_W => "AMOOR.W",
            RiscVMnemonic::AMOMIN_W => "AMOMIN.W",
            RiscVMnemonic::AMOMAX_W => "AMOMAX.W",
            RiscVMnemonic::AMOMINU_W => "AMOMINU.W",
            RiscVMnemonic::AMOMAXU_W => "AMOMAXU.W",
            RiscVMnemonic::LR_D => "LR.D",
            RiscVMnemonic::SC_D => "SC.D",
            RiscVMnemonic::AMOSWAP_D => "AMOSWAP.D",
            RiscVMnemonic::AMOADD_D => "AMOADD.D",
            RiscVMnemonic::AMOXOR_D => "AMOXOR.D",
            RiscVMnemonic::AMOAND_D => "AMOAND.D",
            RiscVMnemonic::AMOOR_D => "AMOOR.D",
            RiscVMnemonic::AMOMIN_D => "AMOMIN.D",
            RiscVMnemonic::AMOMAX_D => "AMOMAX.D",
            RiscVMnemonic::AMOMINU_D => "AMOMINU.D",
            RiscVMnemonic::AMOMAXU_D => "AMOMAXU.D",
            // F Extension
            RiscVMnemonic::FLW => "FLW",
            RiscVMnemonic::FSW => "FSW",
            RiscVMnemonic::FMADD_S => "FMADD.S",
            RiscVMnemonic::FMSUB_S => "FMSUB.S",
            RiscVMnemonic::FNMSUB_S => "FNMSUB.S",
            RiscVMnemonic::FNMADD_S => "FNMADD.S",
            RiscVMnemonic::FADD_S => "FADD.S",
            RiscVMnemonic::FSUB_S => "FSUB.S",
            RiscVMnemonic::FMUL_S => "FMUL.S",
            RiscVMnemonic::FDIV_S => "FDIV.S",
            RiscVMnemonic::FSQRT_S => "FSQRT.S",
            RiscVMnemonic::FSGNJ_S => "FSGNJ.S",
            RiscVMnemonic::FSGNJN_S => "FSGNJN.S",
            RiscVMnemonic::FSGNJX_S => "FSGNJX.S",
            RiscVMnemonic::FMIN_S => "FMIN.S",
            RiscVMnemonic::FMAX_S => "FMAX.S",
            RiscVMnemonic::FCVT_W_S => "FCVT.W.S",
            RiscVMnemonic::FCVT_WU_S => "FCVT.WU.S",
            RiscVMnemonic::FMV_X_W => "FMV.X.W",
            RiscVMnemonic::FEQ_S => "FEQ.S",
            RiscVMnemonic::FLT_S => "FLT.S",
            RiscVMnemonic::FLE_S => "FLE.S",
            RiscVMnemonic::FCLASS_S => "FCLASS.S",
            RiscVMnemonic::FCVT_S_W => "FCVT.S.W",
            RiscVMnemonic::FCVT_S_WU => "FCVT.S.WU",
            RiscVMnemonic::FMV_W_X => "FMV.W.X",
            // D Extension
            RiscVMnemonic::FLD => "FLD",
            RiscVMnemonic::FSD => "FSD",
            RiscVMnemonic::FMADD_D => "FMADD.D",
            RiscVMnemonic::FMSUB_D => "FMSUB.D",
            RiscVMnemonic::FNMSUB_D => "FNMSUB.D",
            RiscVMnemonic::FNMADD_D => "FNMADD.D",
            RiscVMnemonic::FADD_D => "FADD.D",
            RiscVMnemonic::FSUB_D => "FSUB.D",
            RiscVMnemonic::FMUL_D => "FMUL.D",
            RiscVMnemonic::FDIV_D => "FDIV.D",
            RiscVMnemonic::FSQRT_D => "FSQRT.D",
            RiscVMnemonic::FSGNJ_D => "FSGNJ.D",
            RiscVMnemonic::FSGNJN_D => "FSGNJN.D",
            RiscVMnemonic::FSGNJX_D => "FSGNJX.D",
            RiscVMnemonic::FMIN_D => "FMIN.D",
            RiscVMnemonic::FMAX_D => "FMAX.D",
            RiscVMnemonic::FCVT_S_D => "FCVT.S.D",
            RiscVMnemonic::FCVT_D_S => "FCVT.D.S",
            RiscVMnemonic::FEQ_D => "FEQ.D",
            RiscVMnemonic::FLT_D => "FLT.D",
            RiscVMnemonic::FLE_D => "FLE.D",
            RiscVMnemonic::FCLASS_D => "FCLASS.D",
            RiscVMnemonic::FCVT_W_D => "FCVT.W.D",
            RiscVMnemonic::FCVT_WU_D => "FCVT.WU.D",
            RiscVMnemonic::FCVT_D_W => "FCVT.D.W",
            RiscVMnemonic::FCVT_D_WU => "FCVT.D.WU",
            // D Extension 64-bit FP <-> Integer
            RiscVMnemonic::FCVT_L_S => "FCVT.L.S",
            RiscVMnemonic::FCVT_LU_S => "FCVT.LU.S",
            RiscVMnemonic::FCVT_S_L => "FCVT.S.L",
            RiscVMnemonic::FCVT_S_LU => "FCVT.S.LU",
            RiscVMnemonic::FCVT_L_D => "FCVT.L.D",
            RiscVMnemonic::FCVT_LU_D => "FCVT.LU.D",
            RiscVMnemonic::FCVT_D_L => "FCVT.D.L",
            RiscVMnemonic::FCVT_D_LU => "FCVT.D.LU",
            RiscVMnemonic::FMV_X_D => "FMV.X.D",
            RiscVMnemonic::FMV_D_X => "FMV.D.X",
            // C Extension
            RiscVMnemonic::C_ADDI4SPN => "C.ADDI4SPN",
            RiscVMnemonic::C_FLD => "C.FLD",
            RiscVMnemonic::C_LW => "C.LW",
            RiscVMnemonic::C_FLW => "C.FLW",
            RiscVMnemonic::C_LD => "C.LD",
            RiscVMnemonic::C_FSD => "C.FSD",
            RiscVMnemonic::C_SW => "C.SW",
            RiscVMnemonic::C_FSW => "C.FSW",
            RiscVMnemonic::C_SD => "C.SD",
            RiscVMnemonic::C_NOP => "C.NOP",
            RiscVMnemonic::C_ADDI => "C.ADDI",
            RiscVMnemonic::C_JAL => "C.JAL",
            RiscVMnemonic::C_ADDIW => "C.ADDIW",
            RiscVMnemonic::C_LI => "C.LI",
            RiscVMnemonic::C_ADDI16SP => "C.ADDI16SP",
            RiscVMnemonic::C_LUI => "C.LUI",
            RiscVMnemonic::C_SRLI => "C.SRLI",
            RiscVMnemonic::C_SRAI => "C.SRAI",
            RiscVMnemonic::C_ANDI => "C.ANDI",
            RiscVMnemonic::C_SUB => "C.SUB",
            RiscVMnemonic::C_XOR => "C.XOR",
            RiscVMnemonic::C_OR => "C.OR",
            RiscVMnemonic::C_AND => "C.AND",
            RiscVMnemonic::C_SUBW => "C.SUBW",
            RiscVMnemonic::C_ADDW => "C.ADDW",
            RiscVMnemonic::C_J => "C.J",
            RiscVMnemonic::C_BEQZ => "C.BEQZ",
            RiscVMnemonic::C_BNEZ => "C.BNEZ",
            RiscVMnemonic::C_SLLI => "C.SLLI",
            RiscVMnemonic::C_FLDSP => "C.FLDSP",
            RiscVMnemonic::C_LWSP => "C.LWSP",
            RiscVMnemonic::C_FLWSP => "C.FLWSP",
            RiscVMnemonic::C_LDSP => "C.LDSP",
            RiscVMnemonic::C_JR => "C.JR",
            RiscVMnemonic::C_MV => "C.MV",
            RiscVMnemonic::C_EBREAK => "C.EBREAK",
            RiscVMnemonic::C_JALR => "C.JALR",
            RiscVMnemonic::C_ADD => "C.ADD",
            RiscVMnemonic::C_FSDSP => "C.FSDSP",
            RiscVMnemonic::C_SWSP => "C.SWSP",
            RiscVMnemonic::C_FSWSP => "C.FSWSP",
            RiscVMnemonic::C_SDSP => "C.SDSP",
            // Zicsr
            RiscVMnemonic::CSRRW => "CSRRW",
            RiscVMnemonic::CSRRS => "CSRRS",
            RiscVMnemonic::CSRRC => "CSRRC",
            RiscVMnemonic::CSRRWI => "CSRRWI",
            RiscVMnemonic::CSRRSI => "CSRRSI",
            RiscVMnemonic::CSRRCI => "CSRRCI",
            // Zba
            RiscVMnemonic::SH1ADD => "SH1ADD",
            RiscVMnemonic::SH2ADD => "SH2ADD",
            RiscVMnemonic::SH3ADD => "SH3ADD",
            RiscVMnemonic::SH1ADD_UW => "SH1ADD.UW",
            RiscVMnemonic::SH2ADD_UW => "SH2ADD.UW",
            RiscVMnemonic::SH3ADD_UW => "SH3ADD.UW",
            RiscVMnemonic::SLLI_UW => "SLLI.UW",
            RiscVMnemonic::ADD_UW => "ADD.UW",
            // Zbb
            RiscVMnemonic::ANDN => "ANDN",
            RiscVMnemonic::ORN => "ORN",
            RiscVMnemonic::XNOR => "XNOR",
            RiscVMnemonic::CLZ => "CLZ",
            RiscVMnemonic::CTZ => "CTZ",
            RiscVMnemonic::CPOP => "CPOP",
            RiscVMnemonic::CLZW => "CLZW",
            RiscVMnemonic::CTZW => "CTZW",
            RiscVMnemonic::CPOPW => "CPOPW",
            RiscVMnemonic::MAX => "MAX",
            RiscVMnemonic::MAXU => "MAXU",
            RiscVMnemonic::MIN => "MIN",
            RiscVMnemonic::MINU => "MINU",
            RiscVMnemonic::SEXT_B => "SEXT.B",
            RiscVMnemonic::SEXT_H => "SEXT.H",
            RiscVMnemonic::ZEXT_H => "ZEXT.H",
            RiscVMnemonic::ROL => "ROL",
            RiscVMnemonic::ROR => "ROR",
            RiscVMnemonic::RORI => "RORI",
            RiscVMnemonic::ROLW => "ROLW",
            RiscVMnemonic::RORW => "RORW",
            RiscVMnemonic::RORIW => "RORIW",
            RiscVMnemonic::ORC_B => "ORC.B",
            RiscVMnemonic::REV8 => "REV8",
            // Zbs
            RiscVMnemonic::BCLR => "BCLR",
            RiscVMnemonic::BCLRI => "BCLRI",
            RiscVMnemonic::BSET => "BSET",
            RiscVMnemonic::BSETI => "BSETI",
            RiscVMnemonic::BINV => "BINV",
            RiscVMnemonic::BINVI => "BINVI",
            RiscVMnemonic::BEXT => "BEXT",
            RiscVMnemonic::BEXTI => "BEXTI",
            // Zbc
            RiscVMnemonic::CLMUL => "CLMUL",
            RiscVMnemonic::CLMULR => "CLMULR",
            RiscVMnemonic::CLMULH => "CLMULH",
            // Zfh
            RiscVMnemonic::FLH => "FLH",
            RiscVMnemonic::FSH => "FSH",
            RiscVMnemonic::FMADD_H => "FMADD.H",
            RiscVMnemonic::FMSUB_H => "FMSUB.H",
            RiscVMnemonic::FNMSUB_H => "FNMSUB.H",
            RiscVMnemonic::FNMADD_H => "FNMADD.H",
            RiscVMnemonic::FADD_H => "FADD.H",
            RiscVMnemonic::FSUB_H => "FSUB.H",
            RiscVMnemonic::FMUL_H => "FMUL.H",
            RiscVMnemonic::FDIV_H => "FDIV.H",
            RiscVMnemonic::FSQRT_H => "FSQRT.H",
            RiscVMnemonic::FSGNJ_H => "FSGNJ.H",
            RiscVMnemonic::FSGNJN_H => "FSGNJN.H",
            RiscVMnemonic::FSGNJX_H => "FSGNJX.H",
            RiscVMnemonic::FMIN_H => "FMIN.H",
            RiscVMnemonic::FMAX_H => "FMAX.H",
            RiscVMnemonic::FCVT_S_H => "FCVT.S.H",
            RiscVMnemonic::FCVT_H_S => "FCVT.H.S",
            RiscVMnemonic::FCVT_D_H => "FCVT.D.H",
            RiscVMnemonic::FCVT_H_D => "FCVT.H.D",
            RiscVMnemonic::FCVT_W_H => "FCVT.W.H",
            RiscVMnemonic::FCVT_WU_H => "FCVT.WU.H",
            RiscVMnemonic::FCVT_H_W => "FCVT.H.W",
            RiscVMnemonic::FCVT_H_WU => "FCVT.H.WU",
            RiscVMnemonic::FCVT_L_H => "FCVT.L.H",
            RiscVMnemonic::FCVT_LU_H => "FCVT.LU.H",
            RiscVMnemonic::FCVT_H_L => "FCVT.H.L",
            RiscVMnemonic::FCVT_H_LU => "FCVT.H.LU",
            RiscVMnemonic::FEQ_H => "FEQ.H",
            RiscVMnemonic::FLT_H => "FLT.H",
            RiscVMnemonic::FLE_H => "FLE.H",
            RiscVMnemonic::FCLASS_H => "FCLASS.H",
            RiscVMnemonic::FMV_X_H => "FMV.X.H",
            RiscVMnemonic::FMV_H_X => "FMV.H.X",
            // Zbkb
            RiscVMnemonic::PACK => "PACK",
            RiscVMnemonic::PACKH => "PACKH",
            RiscVMnemonic::PACKW => "PACKW",
            RiscVMnemonic::BREV8 => "BREV8",
            RiscVMnemonic::ZIP => "ZIP",
            RiscVMnemonic::UNZIP => "UNZIP",
            // Zk Crypto
            RiscVMnemonic::AES32ESMI => "AES32ESMI",
            RiscVMnemonic::AES32ESI => "AES32ESI",
            RiscVMnemonic::AES32DSMI => "AES32DSMI",
            RiscVMnemonic::AES32DSI => "AES32DSI",
            RiscVMnemonic::AES64ESM => "AES64ESM",
            RiscVMnemonic::AES64ES => "AES64ES",
            RiscVMnemonic::AES64DSM => "AES64DSM",
            RiscVMnemonic::AES64DS => "AES64DS",
            RiscVMnemonic::AES64KS1I => "AES64KS1I",
            RiscVMnemonic::AES64KS2 => "AES64KS2",
            RiscVMnemonic::SHA256SIG0 => "SHA256SIG0",
            RiscVMnemonic::SHA256SIG1 => "SHA256SIG1",
            RiscVMnemonic::SHA256SUM0 => "SHA256SUM0",
            RiscVMnemonic::SHA256SUM1 => "SHA256SUM1",
            RiscVMnemonic::SHA512SIG0H => "SHA512SIG0H",
            RiscVMnemonic::SHA512SIG0L => "SHA512SIG0L",
            RiscVMnemonic::SHA512SIG1H => "SHA512SIG1H",
            RiscVMnemonic::SHA512SIG1L => "SHA512SIG1L",
            RiscVMnemonic::SHA512SUM0R => "SHA512SUM0R",
            RiscVMnemonic::SHA512SUM1R => "SHA512SUM1R",
            RiscVMnemonic::SHA512SIG0 => "SHA512SIG0",
            RiscVMnemonic::SHA512SIG1 => "SHA512SIG1",
            RiscVMnemonic::SM3P0 => "SM3P0",
            RiscVMnemonic::SM3P1 => "SM3P1",
            RiscVMnemonic::SM4ED0 => "SM4ED0",
            RiscVMnemonic::SM4ED1 => "SM4ED1",
            RiscVMnemonic::SM4ED2 => "SM4ED2",
            RiscVMnemonic::SM4ED3 => "SM4ED3",
            RiscVMnemonic::SM4KS => "SM4KS",
            RiscVMnemonic::POLLENTROPY => "POLLENTROPY",
            // V Extension - Vector Load/Store
            RiscVMnemonic::VLE8_V => "VLE8.V",
            RiscVMnemonic::VLE16_V => "VLE16.V",
            RiscVMnemonic::VLE32_V => "VLE32.V",
            RiscVMnemonic::VLE64_V => "VLE64.V",
            RiscVMnemonic::VSE8_V => "VSE8.V",
            RiscVMnemonic::VSE16_V => "VSE16.V",
            RiscVMnemonic::VSE32_V => "VSE32.V",
            RiscVMnemonic::VSE64_V => "VSE64.V",
            RiscVMnemonic::VLM_V => "VLM.V",
            RiscVMnemonic::VSM_V => "VSM.V",
            RiscVMnemonic::VLSE8_V => "VLSE8.V",
            RiscVMnemonic::VLSE16_V => "VLSE16.V",
            RiscVMnemonic::VLSE32_V => "VLSE32.V",
            RiscVMnemonic::VLSE64_V => "VLSE64.V",
            RiscVMnemonic::VSSE8_V => "VSSE8.V",
            RiscVMnemonic::VSSE16_V => "VSSE16.V",
            RiscVMnemonic::VSSE32_V => "VSSE32.V",
            RiscVMnemonic::VSSE64_V => "VSSE64.V",
            // V Extension - Indexed Load/Store
            RiscVMnemonic::VLUXEI8_V => "VLUXEI8.V",
            RiscVMnemonic::VLUXEI16_V => "VLUXEI16.V",
            RiscVMnemonic::VLUXEI32_V => "VLUXEI32.V",
            RiscVMnemonic::VLUXEI64_V => "VLUXEI64.V",
            RiscVMnemonic::VSUXEI8_V => "VSUXEI8.V",
            RiscVMnemonic::VSUXEI16_V => "VSUXEI16.V",
            RiscVMnemonic::VSUXEI32_V => "VSUXEI32.V",
            RiscVMnemonic::VSUXEI64_V => "VSUXEI64.V",
            // V Extension - Integer Arithmetic
            RiscVMnemonic::VADD_VV => "VADD.VV",
            RiscVMnemonic::VADD_VX => "VADD.VX",
            RiscVMnemonic::VADD_VI => "VADD.VI",
            RiscVMnemonic::VSUB_VV => "VSUB.VV",
            RiscVMnemonic::VSUB_VX => "VSUB.VX",
            RiscVMnemonic::VMUL_VV => "VMUL.VV",
            RiscVMnemonic::VMUL_VX => "VMUL.VX",
            RiscVMnemonic::VMULH_VV => "VMULH.VV",
            RiscVMnemonic::VMULH_VX => "VMULH.VX",
            RiscVMnemonic::VMULHU_VV => "VMULHU.VV",
            RiscVMnemonic::VMULHU_VX => "VMULHU.VX",
            RiscVMnemonic::VDIV_VV => "VDIV.VV",
            RiscVMnemonic::VDIV_VX => "VDIV.VX",
            RiscVMnemonic::VDIVU_VV => "VDIVU.VV",
            RiscVMnemonic::VDIVU_VX => "VDIVU.VX",
            // V Extension - Bitwise
            RiscVMnemonic::VAND_VV => "VAND.VV",
            RiscVMnemonic::VAND_VX => "VAND.VX",
            RiscVMnemonic::VAND_VI => "VAND.VI",
            RiscVMnemonic::VOR_VV => "VOR.VV",
            RiscVMnemonic::VOR_VX => "VOR.VX",
            RiscVMnemonic::VOR_VI => "VOR.VI",
            RiscVMnemonic::VXOR_VV => "VXOR.VV",
            RiscVMnemonic::VXOR_VX => "VXOR.VX",
            RiscVMnemonic::VXOR_VI => "VXOR.VI",
            RiscVMnemonic::VSLL_VV => "VSLL.VV",
            RiscVMnemonic::VSLL_VX => "VSLL.VX",
            RiscVMnemonic::VSLL_VI => "VSLL.VI",
            RiscVMnemonic::VSRL_VV => "VSRL.VV",
            RiscVMnemonic::VSRL_VX => "VSRL.VX",
            RiscVMnemonic::VSRL_VI => "VSRL.VI",
            RiscVMnemonic::VSRA_VV => "VSRA.VV",
            RiscVMnemonic::VSRA_VX => "VSRA.VX",
            RiscVMnemonic::VSRA_VI => "VSRA.VI",
            // V Extension - Comparison
            RiscVMnemonic::VMFEQ_VV => "VMFEQ.VV",
            RiscVMnemonic::VMFEQ_VF => "VMFEQ.VF",
            RiscVMnemonic::VMFNE_VV => "VMFNE.VV",
            RiscVMnemonic::VMFNE_VF => "VMFNE.VF",
            RiscVMnemonic::VMFLT_VV => "VMFLT.VV",
            RiscVMnemonic::VMFLT_VF => "VMFLT.VF",
            RiscVMnemonic::VMFLE_VV => "VMFLE.VV",
            RiscVMnemonic::VMFLE_VF => "VMFLE.VF",
            RiscVMnemonic::VMFGT_VV => "VMFGT.VV",
            RiscVMnemonic::VMFGT_VF => "VMFGT.VF",
            RiscVMnemonic::VMFGE_VV => "VMFGE.VV",
            RiscVMnemonic::VMFGE_VF => "VMFGE.VF",
            // V Extension - Merge/Move
            RiscVMnemonic::VMERGE_VVM => "VMERGE.VVM",
            RiscVMnemonic::VMERGE_VXM => "VMERGE.VXM",
            RiscVMnemonic::VMV_V_V => "VMV.V.V",
            RiscVMnemonic::VMV_V_X => "VMV.V.X",
            RiscVMnemonic::VMV_V_I => "VMV.V.I",
            RiscVMnemonic::VMV_X_S => "VMV.X.S",
            RiscVMnemonic::VMV_S_X => "VMV.S.X",
            // V Extension - Slide
            RiscVMnemonic::VSLIDEUP_VX => "VSLIDEUP.VX",
            RiscVMnemonic::VSLIDEUP_VI => "VSLIDEUP.VI",
            RiscVMnemonic::VSLIDEDOWN_VX => "VSLIDEDOWN.VX",
            RiscVMnemonic::VSLIDEDOWN_VI => "VSLIDEDOWN.VI",
            // V Extension - Reduction
            RiscVMnemonic::VREDSUM_VS => "VREDSUM.VS",
            RiscVMnemonic::VREDMAX_VS => "VREDMAX.VS",
            RiscVMnemonic::VREDMIN_VS => "VREDMIN.VS",
            RiscVMnemonic::VREDAND_VS => "VREDAND.VS",
            RiscVMnemonic::VREDOR_VS => "VREDOR.VS",
            RiscVMnemonic::VREDXOR_VS => "VREDXOR.VS",
            // V Extension - Configuration
            RiscVMnemonic::VSETVLI => "VSETVLI",
            RiscVMnemonic::VSETVL => "VSETVL",
            RiscVMnemonic::VSETIVLI => "VSETIVLI",
            // V Extension - Floating-Point
            RiscVMnemonic::VFADD_VV => "VFADD.VV",
            RiscVMnemonic::VFADD_VF => "VFADD.VF",
            RiscVMnemonic::VFSUB_VV => "VFSUB.VV",
            RiscVMnemonic::VFSUB_VF => "VFSUB.VF",
            RiscVMnemonic::VFMUL_VV => "VFMUL.VV",
            RiscVMnemonic::VFMUL_VF => "VFMUL.VF",
            RiscVMnemonic::VFDIV_VV => "VFDIV.VV",
            RiscVMnemonic::VFDIV_VF => "VFDIV.VF",
            RiscVMnemonic::VFMADD_VV => "VFMADD.VV",
            RiscVMnemonic::VFMADD_VF => "VFMADD.VF",
            RiscVMnemonic::VFNMADD_VV => "VFNMADD.VV",
            RiscVMnemonic::VFNMADD_VF => "VFNMADD.VF",
            RiscVMnemonic::VFMSUB_VV => "VFMSUB.VV",
            RiscVMnemonic::VFMSUB_VF => "VFMSUB.VF",
            RiscVMnemonic::VFNMSUB_VV => "VFNMSUB.VV",
            RiscVMnemonic::VFNMSUB_VF => "VFNMSUB.VF",
            RiscVMnemonic::VFMERGE_VFM => "VFMERGE.VFM",
            RiscVMnemonic::VFMV_V_F => "VFMV.V.F",
            RiscVMnemonic::VFMV_F_S => "VFMV.F.S",
            RiscVMnemonic::VFSQRT_V => "VFSQRT.V",
            RiscVMnemonic::VFCLASS_V => "VFCLASS.V",
            // V Extension - FP Conversions
            RiscVMnemonic::VFCVT_XU_F_V => "VFCVT.XU.F.V",
            RiscVMnemonic::VFCVT_X_F_V => "VFCVT.X.F.V",
            RiscVMnemonic::VFCVT_F_XU_V => "VFCVT.F.XU.V",
            RiscVMnemonic::VFCVT_F_X_V => "VFCVT.F.X.V",
            RiscVMnemonic::VFWCVT_F_F_V => "VFWCVT.F.F.V",
            RiscVMnemonic::VFWCVT_XU_F_V => "VFWCVT.XU.F.V",
            RiscVMnemonic::VFWCVT_X_F_V => "VFWCVT.X.F.V",
            RiscVMnemonic::VFNCVT_F_F_W => "VFNCVT.F.F.W",
            RiscVMnemonic::VFNCVT_XU_F_W => "VFNCVT.XU.F.W",
            RiscVMnemonic::VFNCVT_X_F_W => "VFNCVT.X.F.W",
            RiscVMnemonic::VFRSQRT7_V => "VFRSQRT7.V",
            RiscVMnemonic::VFREC7_V => "VFREC7.V",
            // V Extension - FP Min/Max/Sign
            RiscVMnemonic::VFMIN_VV => "VFMIN.VV",
            RiscVMnemonic::VFMIN_VF => "VFMIN.VF",
            RiscVMnemonic::VFMAX_VV => "VFMAX.VV",
            RiscVMnemonic::VFMAX_VF => "VFMAX.VF",
            RiscVMnemonic::VFSGNJ_VV => "VFSGNJ.VV",
            RiscVMnemonic::VFSGNJ_VF => "VFSGNJ.VF",
            RiscVMnemonic::VFSGNJN_VV => "VFSGNJN.VV",
            RiscVMnemonic::VFSGNJN_VF => "VFSGNJN.VF",
            RiscVMnemonic::VFSGNJX_VV => "VFSGNJX.VV",
            RiscVMnemonic::VFSGNJX_VF => "VFSGNJX.VF",
            // V Extension - Widening Integer
            RiscVMnemonic::VWADDU_VV => "VWADDU.VV",
            RiscVMnemonic::VWADDU_VX => "VWADDU.VX",
            RiscVMnemonic::VWADD_VV => "VWADD.VV",
            RiscVMnemonic::VWADD_VX => "VWADD.VX",
            RiscVMnemonic::VWSUBU_VV => "VWSUBU.VV",
            RiscVMnemonic::VWSUBU_VX => "VWSUBU.VX",
            RiscVMnemonic::VWSUB_VV => "VWSUB.VV",
            RiscVMnemonic::VWSUB_VX => "VWSUB.VX",
            RiscVMnemonic::VWMULU_VV => "VWMULU.VV",
            RiscVMnemonic::VWMULU_VX => "VWMULU.VX",
            RiscVMnemonic::VWMUL_VV => "VWMUL.VV",
            RiscVMnemonic::VWMUL_VX => "VWMUL.VX",
            RiscVMnemonic::VWMULSU_VV => "VWMULSU.VV",
            RiscVMnemonic::VWMULSU_VX => "VWMULSU.VX",
            // V Extension - Extension/Narrowing
            RiscVMnemonic::VSEXT_VF2 => "VSEXT.VF2",
            RiscVMnemonic::VSEXT_VF4 => "VSEXT.VF4",
            RiscVMnemonic::VSEXT_VF8 => "VSEXT.VF8",
            RiscVMnemonic::VZEXT_VF2 => "VZEXT.VF2",
            RiscVMnemonic::VZEXT_VF4 => "VZEXT.VF4",
            RiscVMnemonic::VZEXT_VF8 => "VZEXT.VF8",
            RiscVMnemonic::VNSRL_WV => "VNSRL.WV",
            RiscVMnemonic::VNSRL_WX => "VNSRL.WX",
            RiscVMnemonic::VNSRL_WI => "VNSRL.WI",
            RiscVMnemonic::VNSRA_WV => "VNSRA.WV",
            RiscVMnemonic::VNSRA_WX => "VNSRA.WX",
            RiscVMnemonic::VNSRA_WI => "VNSRA.WI",
            RiscVMnemonic::VNCVT_X_X_W => "VNCVT.X.X.W",
            // V Extension - Mask/Permutation
            RiscVMnemonic::VCOMPRESS_VM => "VCOMPRESS.VM",
            RiscVMnemonic::VMAND_MM => "VMAND.MM",
            RiscVMnemonic::VMNAND_MM => "VMNAND.MM",
            RiscVMnemonic::VMANDN_MM => "VMANDN.MM",
            RiscVMnemonic::VMXOR_MM => "VMXOR.MM",
            RiscVMnemonic::VMOR_MM => "VMOR.MM",
            RiscVMnemonic::VMNOR_MM => "VMNOR.MM",
            RiscVMnemonic::VMORN_MM => "VMORN.MM",
            RiscVMnemonic::VMXNOR_MM => "VMXNOR.MM",
            RiscVMnemonic::VPOPC_M => "VPOPC.M",
            RiscVMnemonic::VFIRST_M => "VFIRST.M",
            RiscVMnemonic::VMSBF_M => "VMSBF.M",
            RiscVMnemonic::VMSIF_M => "VMSIF.M",
            RiscVMnemonic::VMSOF_M => "VMSOF.M",
            RiscVMnemonic::VIOTA_M => "VIOTA.M",
            RiscVMnemonic::VID_V => "VID.V",
            // Privileged / System
            RiscVMnemonic::WFI => "WFI",
            RiscVMnemonic::MRET => "MRET",
            RiscVMnemonic::SRET => "SRET",
            RiscVMnemonic::MNRET => "MNRET",
            RiscVMnemonic::SFENCE_VMA => "SFENCE.VMA",
            RiscVMnemonic::SINVAL_VMA => "SINVAL.VMA",
            RiscVMnemonic::SFENCE_W_INVAL => "SFENCE.W.INVAL",
            RiscVMnemonic::SFENCE_INVAL_IR => "SFENCE.INVAL.IR",
            RiscVMnemonic::HFENCE_VVMA => "HFENCE.VVMA",
            RiscVMnemonic::HFENCE_GVMA => "HFENCE.GVMA",
            RiscVMnemonic::HLV_B => "HLV.B",
            RiscVMnemonic::HLV_H => "HLV.H",
            RiscVMnemonic::HLV_W => "HLV.W",
            RiscVMnemonic::HLV_D => "HLV.D",
            RiscVMnemonic::HLV_BU => "HLV.BU",
            RiscVMnemonic::HLV_HU => "HLV.HU",
            RiscVMnemonic::HLV_WU => "HLV.WU",
            RiscVMnemonic::HSV_B => "HSV.B",
            RiscVMnemonic::HSV_H => "HSV.H",
            RiscVMnemonic::HSV_W => "HSV.W",
            RiscVMnemonic::HSV_D => "HSV.D",
            RiscVMnemonic::PAUSE => "PAUSE",
        }
    }

    pub fn category(&self) -> InstructionCategory {
        match self {
            RiscVMnemonic::LUI
            | RiscVMnemonic::AUIPC
            | RiscVMnemonic::ADD
            | RiscVMnemonic::ADDI
            | RiscVMnemonic::SUB
            | RiscVMnemonic::SLL
            | RiscVMnemonic::SLT
            | RiscVMnemonic::SLTI
            | RiscVMnemonic::SLTU
            | RiscVMnemonic::SLTIU
            | RiscVMnemonic::XOR
            | RiscVMnemonic::XORI
            | RiscVMnemonic::OR
            | RiscVMnemonic::ORI
            | RiscVMnemonic::AND
            | RiscVMnemonic::ANDI
            | RiscVMnemonic::SRL
            | RiscVMnemonic::SRA
            | RiscVMnemonic::SLLI
            | RiscVMnemonic::SRLI
            | RiscVMnemonic::SRAI
            | RiscVMnemonic::ADDIW
            | RiscVMnemonic::ADDW
            | RiscVMnemonic::SUBW
            | RiscVMnemonic::SLLW
            | RiscVMnemonic::SRLW
            | RiscVMnemonic::SRAW
            | RiscVMnemonic::SLLIW
            | RiscVMnemonic::SRLIW
            | RiscVMnemonic::SRAIW => InstructionCategory::Integer,
            RiscVMnemonic::BEQ
            | RiscVMnemonic::BNE
            | RiscVMnemonic::BLT
            | RiscVMnemonic::BGE
            | RiscVMnemonic::BLTU
            | RiscVMnemonic::BGEU
            | RiscVMnemonic::JAL
            | RiscVMnemonic::JALR => InstructionCategory::Branch,
            RiscVMnemonic::LB
            | RiscVMnemonic::LH
            | RiscVMnemonic::LW
            | RiscVMnemonic::LBU
            | RiscVMnemonic::LHU
            | RiscVMnemonic::LD
            | RiscVMnemonic::LWU
            | RiscVMnemonic::SB
            | RiscVMnemonic::SH
            | RiscVMnemonic::SW
            | RiscVMnemonic::SD => InstructionCategory::LoadStore,
            RiscVMnemonic::MUL
            | RiscVMnemonic::MULH
            | RiscVMnemonic::MULHSU
            | RiscVMnemonic::MULHU
            | RiscVMnemonic::DIV
            | RiscVMnemonic::DIVU
            | RiscVMnemonic::REM
            | RiscVMnemonic::REMU
            | RiscVMnemonic::MULW
            | RiscVMnemonic::DIVW
            | RiscVMnemonic::DIVUW
            | RiscVMnemonic::REMW
            | RiscVMnemonic::REMUW => InstructionCategory::Multiply,
            RiscVMnemonic::LR_W
            | RiscVMnemonic::SC_W
            | RiscVMnemonic::LR_D
            | RiscVMnemonic::SC_D
            | RiscVMnemonic::AMOSWAP_W
            | RiscVMnemonic::AMOADD_W
            | RiscVMnemonic::AMOXOR_W
            | RiscVMnemonic::AMOAND_W
            | RiscVMnemonic::AMOOR_W
            | RiscVMnemonic::AMOMIN_W
            | RiscVMnemonic::AMOMAX_W
            | RiscVMnemonic::AMOMINU_W
            | RiscVMnemonic::AMOMAXU_W
            | RiscVMnemonic::AMOSWAP_D
            | RiscVMnemonic::AMOADD_D
            | RiscVMnemonic::AMOXOR_D
            | RiscVMnemonic::AMOAND_D
            | RiscVMnemonic::AMOOR_D
            | RiscVMnemonic::AMOMIN_D
            | RiscVMnemonic::AMOMAX_D
            | RiscVMnemonic::AMOMINU_D
            | RiscVMnemonic::AMOMAXU_D => InstructionCategory::Atomic,
            RiscVMnemonic::FLW
            | RiscVMnemonic::FSW
            | RiscVMnemonic::FLD
            | RiscVMnemonic::FSD
            | RiscVMnemonic::FLH
            | RiscVMnemonic::FSH
            | RiscVMnemonic::FADD_S
            | RiscVMnemonic::FSUB_S
            | RiscVMnemonic::FMUL_S
            | RiscVMnemonic::FDIV_S
            | RiscVMnemonic::FADD_D
            | RiscVMnemonic::FSUB_D
            | RiscVMnemonic::FMUL_D
            | RiscVMnemonic::FDIV_D
            | RiscVMnemonic::FADD_H
            | RiscVMnemonic::FSUB_H
            | RiscVMnemonic::FMUL_H
            | RiscVMnemonic::FDIV_H
            | RiscVMnemonic::FSQRT_S
            | RiscVMnemonic::FSQRT_D
            | RiscVMnemonic::FSQRT_H
            | RiscVMnemonic::FMADD_S
            | RiscVMnemonic::FMSUB_S
            | RiscVMnemonic::FNMSUB_S
            | RiscVMnemonic::FNMADD_S
            | RiscVMnemonic::FMADD_D
            | RiscVMnemonic::FMSUB_D
            | RiscVMnemonic::FNMSUB_D
            | RiscVMnemonic::FNMADD_D
            | RiscVMnemonic::FCVT_W_S
            | RiscVMnemonic::FCVT_S_W
            | RiscVMnemonic::FCVT_W_D
            | RiscVMnemonic::FCVT_D_W
            | RiscVMnemonic::FCVT_S_D
            | RiscVMnemonic::FCVT_D_S => InstructionCategory::FloatingPoint,
            _ => InstructionCategory::Miscellaneous,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InstructionCategory {
    Integer,
    Branch,
    LoadStore,
    Multiply,
    Atomic,
    FloatingPoint,
    Compressed,
    Csr,
    Vector,
    Bitmanip,
    Crypto,
    System,
    Miscellaneous,
}

// ============================================================================
// Conversion to common InstructionMnemonic
// ============================================================================

pub fn all_riscv_mnemonics() -> Vec<InstructionMnemonic> {
    use RiscVMnemonic::*;
    let variants = [
        // RV32I / RV64I
        LUI, AUIPC, JAL, JALR,
        BEQ, BNE, BLT, BGE, BLTU, BGEU,
        LB, LH, LW, LBU, LHU, LD, LWU,
        SB, SH, SW, SD,
        ADDI, SLTI, SLTIU, XORI, ORI, ANDI,
        SLLI, SRLI, SRAI,
        ADD, SUB, SLL, SLT, SLTU, XOR, SRL, SRA, OR, AND,
        FENCE, FENCE_I, FENCE_TSO,
        ECALL, EBREAK,
        ADDIW, SLLIW, SRLIW, SRAIW,
        ADDW, SUBW, SLLW, SRLW, SRAW,
        // M
        MUL, MULH, MULHSU, MULHU,
        DIV, DIVU, REM, REMU,
        MULW, DIVW, DIVUW, REMW, REMUW,
        // A
        LR_W, SC_W,
        AMOSWAP_W, AMOADD_W, AMOXOR_W, AMOAND_W, AMOOR_W,
        AMOMIN_W, AMOMAX_W, AMOMINU_W, AMOMAXU_W,
        LR_D, SC_D,
        AMOSWAP_D, AMOADD_D, AMOXOR_D, AMOAND_D, AMOOR_D,
        AMOMIN_D, AMOMAX_D, AMOMINU_D, AMOMAXU_D,
        // F
        FLW, FSW,
        FMADD_S, FMSUB_S, FNMSUB_S, FNMADD_S,
        FADD_S, FSUB_S, FMUL_S, FDIV_S, FSQRT_S,
        FSGNJ_S, FSGNJN_S, FSGNJX_S, FMIN_S, FMAX_S,
        FCVT_W_S, FCVT_WU_S, FMV_X_W,
        FEQ_S, FLT_S, FLE_S, FCLASS_S,
        FCVT_S_W, FCVT_S_WU, FMV_W_X,
        // D
        FLD, FSD,
        FMADD_D, FMSUB_D, FNMSUB_D, FNMADD_D,
        FADD_D, FSUB_D, FMUL_D, FDIV_D, FSQRT_D,
        FSGNJ_D, FSGNJN_D, FSGNJX_D, FMIN_D, FMAX_D,
        FCVT_S_D, FCVT_D_S,
        FEQ_D, FLT_D, FLE_D, FCLASS_D,
        FCVT_W_D, FCVT_WU_D, FCVT_D_W, FCVT_D_WU,
        FCVT_L_S, FCVT_LU_S, FCVT_S_L, FCVT_S_LU,
        FCVT_L_D, FCVT_LU_D, FCVT_D_L, FCVT_D_LU,
        FMV_X_D, FMV_D_X,
        // C
        C_ADDI4SPN, C_LW, C_LD, C_SW, C_SD,
        C_NOP, C_ADDI, C_LI, C_ADDI16SP, C_LUI,
        C_SRLI, C_SRAI, C_ANDI,
        C_SUB, C_XOR, C_OR, C_AND, C_SUBW, C_ADDW,
        C_J, C_BEQZ, C_BNEZ,
        C_SLLI, C_LWSP, C_LDSP,
        C_JR, C_MV, C_EBREAK, C_JALR, C_ADD,
        C_SWSP, C_SDSP,
        C_FLD, C_FLW, C_FSD, C_FSW, C_FLDSP, C_FLWSP, C_FSDSP, C_FSWSP,
        C_JAL, C_ADDIW,
        // Zicsr
        CSRRW, CSRRS, CSRRC, CSRRWI, CSRRSI, CSRRCI,
        // Zba
        SH1ADD, SH2ADD, SH3ADD,
        SH1ADD_UW, SH2ADD_UW, SH3ADD_UW,
        SLLI_UW, ADD_UW,
        // Zbb
        ANDN, ORN, XNOR,
        CLZ, CTZ, CPOP, CLZW, CTZW, CPOPW,
        MAX, MAXU, MIN, MINU,
        SEXT_B, SEXT_H, ZEXT_H,
        ROL, ROR, RORI, ROLW, RORW, RORIW,
        ORC_B, REV8,
        // Zbs
        BCLR, BCLRI, BSET, BSETI, BINV, BINVI, BEXT, BEXTI,
        // Zbc
        CLMUL, CLMULR, CLMULH,
        // Zfh
        FLH, FSH,
        FMADD_H, FMSUB_H, FNMSUB_H, FNMADD_H,
        FADD_H, FSUB_H, FMUL_H, FDIV_H, FSQRT_H,
        FSGNJ_H, FSGNJN_H, FSGNJX_H, FMIN_H, FMAX_H,
        FCVT_S_H, FCVT_H_S, FCVT_D_H, FCVT_H_D,
        FCVT_W_H, FCVT_WU_H, FCVT_H_W, FCVT_H_WU,
        FCVT_L_H, FCVT_LU_H, FCVT_H_L, FCVT_H_LU,
        FEQ_H, FLT_H, FLE_H, FCLASS_H,
        FMV_X_H, FMV_H_X,
        // Zbkb
        PACK, PACKH, PACKW, BREV8, ZIP, UNZIP,
        // Zk
        AES32ESMI, AES32ESI, AES32DSMI, AES32DSI,
        AES64ESM, AES64ES, AES64DSM, AES64DS,
        AES64KS1I, AES64KS2,
        SHA256SIG0, SHA256SIG1, SHA256SUM0, SHA256SUM1,
        SHA512SIG0H, SHA512SIG0L, SHA512SIG1H, SHA512SIG1L,
        SHA512SUM0R, SHA512SUM1R, SHA512SIG0, SHA512SIG1,
        SM3P0, SM3P1,
        SM4ED0, SM4ED1, SM4ED2, SM4ED3, SM4KS,
        POLLENTROPY,
        // V Extension
        VLE8_V, VLE16_V, VLE32_V, VLE64_V,
        VSE8_V, VSE16_V, VSE32_V, VSE64_V,
        VLM_V, VSM_V,
        VLSE8_V, VLSE16_V, VLSE32_V, VLSE64_V,
        VSSE8_V, VSSE16_V, VSSE32_V, VSSE64_V,
        VLUXEI8_V, VLUXEI16_V, VLUXEI32_V, VLUXEI64_V,
        VSUXEI8_V, VSUXEI16_V, VSUXEI32_V, VSUXEI64_V,
        VADD_VV, VADD_VX, VADD_VI,
        VSUB_VV, VSUB_VX,
        VMUL_VV, VMUL_VX,
        VMULH_VV, VMULH_VX, VMULHU_VV, VMULHU_VX,
        VDIV_VV, VDIV_VX, VDIVU_VV, VDIVU_VX,
        VAND_VV, VAND_VX, VAND_VI,
        VOR_VV, VOR_VX, VOR_VI,
        VXOR_VV, VXOR_VX, VXOR_VI,
        VSLL_VV, VSLL_VX, VSLL_VI,
        VSRL_VV, VSRL_VX, VSRL_VI,
        VSRA_VV, VSRA_VX, VSRA_VI,
        VMFEQ_VV, VMFEQ_VF, VMFNE_VV, VMFNE_VF,
        VMFLT_VV, VMFLT_VF, VMFLE_VV, VMFLE_VF,
        VMFGT_VV, VMFGT_VF, VMFGE_VV, VMFGE_VF,
        VMERGE_VVM, VMERGE_VXM,
        VMV_V_V, VMV_V_X, VMV_V_I,
        VMV_X_S, VMV_S_X,
        VSLIDEUP_VX, VSLIDEUP_VI,
        VSLIDEDOWN_VX, VSLIDEDOWN_VI,
        VREDSUM_VS, VREDMAX_VS, VREDMIN_VS,
        VREDAND_VS, VREDOR_VS, VREDXOR_VS,
        VSETVLI, VSETVL, VSETIVLI,
        VFADD_VV, VFADD_VF, VFSUB_VV, VFSUB_VF,
        VFMUL_VV, VFMUL_VF, VFDIV_VV, VFDIV_VF,
        VFMADD_VV, VFMADD_VF,
        VFNMADD_VV, VFNMADD_VF,
        VFMSUB_VV, VFMSUB_VF,
        VFNMSUB_VV, VFNMSUB_VF,
        VFMERGE_VFM, VFMV_V_F, VFMV_F_S,
        VFSQRT_V, VFCLASS_V,
        VFCVT_XU_F_V, VFCVT_X_F_V,
        VFCVT_F_XU_V, VFCVT_F_X_V,
        VFWCVT_F_F_V, VFWCVT_XU_F_V, VFWCVT_X_F_V,
        VFNCVT_F_F_W, VFNCVT_XU_F_W, VFNCVT_X_F_W,
        VFRSQRT7_V, VFREC7_V,
        VFMIN_VV, VFMIN_VF, VFMAX_VV, VFMAX_VF,
        VFSGNJ_VV, VFSGNJ_VF, VFSGNJN_VV, VFSGNJN_VF,
        VFSGNJX_VV, VFSGNJX_VF,
        VWADDU_VV, VWADDU_VX, VWADD_VV, VWADD_VX,
        VWSUBU_VV, VWSUBU_VX, VWSUB_VV, VWSUB_VX,
        VWMULU_VV, VWMULU_VX, VWMUL_VV, VWMUL_VX,
        VWMULSU_VV, VWMULSU_VX,
        VSEXT_VF2, VSEXT_VF4, VSEXT_VF8,
        VZEXT_VF2, VZEXT_VF4, VZEXT_VF8,
        VNSRL_WV, VNSRL_WX, VNSRL_WI,
        VNSRA_WV, VNSRA_WX, VNSRA_WI,
        VNCVT_X_X_W,
        VCOMPRESS_VM,
        VMAND_MM, VMNAND_MM, VMANDN_MM, VMXOR_MM,
        VMOR_MM, VMNOR_MM, VMORN_MM, VMXNOR_MM,
        VPOPC_M, VFIRST_M,
        VMSBF_M, VMSIF_M, VMSOF_M,
        VIOTA_M, VID_V,
        // Privileged
        WFI, MRET, SRET, MNRET,
        SFENCE_VMA, SINVAL_VMA,
        SFENCE_W_INVAL, SFENCE_INVAL_IR,
        HFENCE_VVMA, HFENCE_GVMA,
        HLV_B, HLV_H, HLV_W, HLV_D,
        HLV_BU, HLV_HU, HLV_WU,
        HSV_B, HSV_H, HSV_W, HSV_D,
        PAUSE,
    ];

    let mut mnemonics: Vec<InstructionMnemonic> = variants
        .iter()
        .map(|m| InstructionMnemonic::new(m.as_str()))
        .collect();
    mnemonics.sort_by(|a, b| a.text.cmp(&b.text));
    mnemonics.dedup_by(|a, b| a.text == b.text);
    mnemonics
}

// ============================================================================
// ProcessorModule Implementation
// ============================================================================

pub struct RiscVModule;

impl ProcessorModule for RiscVModule {
    fn name() -> &'static str {
        PROCESSOR_NAME
    }

    fn registers() -> RegisterBank {
        let rv_bank = RiscVRegisterBank::new_rv64();
        let mut bank = RegisterBank::new();
        for reg in rv_bank.iter() {
            bank.add(reg.clone());
        }
        bank
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "RISCV:LE:32:RV32I",
                "RISC-V 32-bit RV32I (Little Endian)",
                "RV32I",
                Endian::Little,
                32,
            ),
            Language::new(
                "RISCV:LE:32:RV32IMAC",
                "RISC-V 32-bit RV32IMAC (Little Endian)",
                "RV32IMAC",
                Endian::Little,
                32,
            ),
            Language::new(
                "RISCV:LE:32:RV32G",
                "RISC-V 32-bit RV32G (Little Endian)",
                "RV32G",
                Endian::Little,
                32,
            ),
            Language::new(
                "RISCV:LE:32:RV32GC",
                "RISC-V 32-bit RV32GC (Little Endian)",
                "RV32GC",
                Endian::Little,
                32,
            ),
            Language::new(
                "RISCV:LE:64:RV64I",
                "RISC-V 64-bit RV64I (Little Endian)",
                "RV64I",
                Endian::Little,
                64,
            ),
            Language::new(
                "RISCV:LE:64:RV64IMAC",
                "RISC-V 64-bit RV64IMAC (Little Endian)",
                "RV64IMAC",
                Endian::Little,
                64,
            ),
            Language::new(
                "RISCV:LE:64:RV64G",
                "RISC-V 64-bit RV64G (Little Endian)",
                "RV64G",
                Endian::Little,
                64,
            ),
            Language::new(
                "RISCV:LE:64:RV64GC",
                "RISC-V 64-bit RV64GC (Little Endian)",
                "RV64GC",
                Endian::Little,
                64,
            ),
            Language::new(
                "RISCV:LE:64:RV64GC_Zba_Zbb",
                "RISC-V 64-bit RV64GC+Zba+Zbb (Little Endian)",
                "RV64GCB",
                Endian::Little,
                64,
            ),
            Language::new(
                "RISCV:LE:64:RV64GCV",
                "RISC-V 64-bit RV64GC+V (Little Endian)",
                "RV64GCV",
                Endian::Little,
                64,
            ),
        ]
    }

    fn instructions() -> Vec<InstructionMnemonic> {
        all_riscv_mnemonics()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_count() {
        let bank = RiscVRegisterBank::new_rv64();
        assert!(
            bank.len() > 100,
            "RISC-V bank should have >100 registers, got {}",
            bank.len()
        );
    }

    #[test]
    fn test_integer_registers() {
        let bank = RiscVRegisterBank::new_rv64();
        for i in 0..32 {
            assert!(bank.get(&format!("x{}", i)).is_some(), "Missing x{}", i);
        }
    }

    #[test]
    fn test_abi_names() {
        let bank = RiscVRegisterBank::new_rv64();
        let abi = [
            "zero", "ra", "sp", "gp", "tp",
            "t0", "t1", "t2",
            "s0", "s1", "fp",
            "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
            "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
            "t3", "t4", "t5", "t6",
        ];
        for name in &abi {
            assert!(bank.get(name).is_some(), "Missing ABI register {}", name);
        }
    }

    #[test]
    fn test_fp_registers() {
        let bank = RiscVRegisterBank::new_rv64();
        for i in 0..32 {
            assert!(bank.get(&format!("f{}", i)).is_some(), "Missing f{}", i);
        }
    }

    #[test]
    fn test_machine_csrs() {
        let bank = RiscVRegisterBank::new_rv64();
        let csrs = [
            "mstatus", "misa", "mie", "mtvec", "mepc", "mcause",
            "mtval", "mip", "mscratch", "medeleg", "mideleg",
            "mcycle", "minstret", "mhartid", "marchid", "mimpid",
            "mvendorid", "mcountinhibit",
        ];
        for csr in &csrs {
            assert!(bank.get(csr).is_some(), "Missing machine CSR {}", csr);
        }
    }

    #[test]
    fn test_supervisor_csrs() {
        let bank = RiscVRegisterBank::new_rv64();
        let csrs = [
            "sstatus", "sie", "stvec", "sepc", "scause",
            "stval", "sip", "sscratch", "satp", "sedeleg", "sideleg",
        ];
        for csr in &csrs {
            assert!(bank.get(csr).is_some(), "Missing supervisor CSR {}", csr);
        }
    }

    #[test]
    fn test_hypervisor_csrs() {
        let bank = RiscVRegisterBank::new_rv64();
        let csrs = [
            "hstatus", "hie", "htval", "hip", "hvip",
            "htinst", "hgatp", "hedeleg", "hideleg",
        ];
        for csr in &csrs {
            assert!(bank.get(csr).is_some(), "Missing hypervisor CSR {}", csr);
        }
    }

    #[test]
    fn test_user_csrs() {
        let bank = RiscVRegisterBank::new_rv64();
        let csrs = [
            "ustatus", "uie", "utvec", "uscratch",
            "uepc", "ucause", "utval", "uip",
        ];
        for csr in &csrs {
            assert!(bank.get(csr).is_some(), "Missing user CSR {}", csr);
        }
    }

    #[test]
    fn test_fpu_csrs() {
        let bank = RiscVRegisterBank::new_rv64();
        assert!(bank.get("fflags").is_some());
        assert!(bank.get("frm").is_some());
        assert!(bank.get("fcsr").is_some());
        assert!(bank.get("fcsr_fflags").is_some());
        assert!(bank.get("fcsr_frm").is_some());
    }

    #[test]
    fn test_shadow_csrs() {
        let bank = RiscVRegisterBank::new_rv64();
        assert!(bank.get("cycle").is_some());
        assert!(bank.get("time").is_some());
        assert!(bank.get("instret").is_some());
    }

    #[test]
    fn test_pc_register() {
        let bank = RiscVRegisterBank::new_rv64();
        assert!(bank.get("pc").is_some());
    }

    #[test]
    fn test_fp_sub_register_aliasing() {
        let bank = RiscVRegisterBank::new_rv64();
        for i in 0..32 {
            let s_reg = bank.get(&format!("f{}_s", i)).unwrap();
            assert_eq!(s_reg.parent.as_deref(), Some(&format!("f{}", i)));
            assert_eq!(s_reg.bit_size, 32);
            assert_eq!(s_reg.lsb, 0);
        }
    }

    #[test]
    fn test_mstatus_bit_fields_exist() {
        let bank = RiscVRegisterBank::new_rv64();
        for bit in [MstatusBit::UIE, MstatusBit::SIE, MstatusBit::MIE,
                    MstatusBit::MPIE, MstatusBit::SPIE, MstatusBit::SPP,
                    MstatusBit::MPRV, MstatusBit::SUM, MstatusBit::MXR,
                    MstatusBit::TVM, MstatusBit::TW, MstatusBit::TSR,
                    MstatusBit::SD] {
            let field_name = format!("mstatus_{}", bit.name());
            let reg = bank.get(&field_name);
            assert!(reg.is_some(), "Missing mstatus bit field {}", field_name);
            let r = reg.unwrap();
            assert_eq!(r.bit_size, 1);
            assert_eq!(r.lsb, bit.bit());
        }
    }

    #[test]
    fn test_mstatus_bit_masks() {
        assert_eq!(MstatusBit::MIE.mask(), 1u64 << 3);
        assert_eq!(MstatusBit::SIE.mask(), 1u64 << 1);
        assert_eq!(MstatusBit::UIE.mask(), 1);
        assert_eq!(MstatusBit::MPP0.mask(), 1u64 << 11);
        assert_eq!(MstatusBit::MPP1.mask(), 1u64 << 12);
        assert_eq!(MstatusBit::MPIE.mask(), 1u64 << 7);
        assert_eq!(MstatusBit::SD.mask(), 1u64 << 63);
    }

    #[test]
    fn test_interrupt_bits() {
        assert_eq!(InterruptBit::MSIE.mask(), 1u64 << 3);
        assert_eq!(InterruptBit::MTIE.mask(), 1u64 << 7);
        assert_eq!(InterruptBit::MEIE.mask(), 1u64 << 11);
        assert_eq!(InterruptBit::SSIE.mask(), 1u64 << 1);
        assert_eq!(InterruptBit::USIE.mask(), 1);
    }

    #[test]
    fn test_exception_codes() {
        assert_eq!(ExceptionCode::IllegalInstruction as u32, 2);
        assert_eq!(ExceptionCode::Breakpoint as u32, 3);
        assert_eq!(ExceptionCode::EnvironmentCallFromMMode as u32, 11);
        assert_eq!(ExceptionCode::MachineTimerInterrupt as u32, 7);
        assert!(ExceptionCode::MachineTimerInterrupt.is_interrupt());
        assert!(!ExceptionCode::IllegalInstruction.is_interrupt());
    }

    #[test]
    fn test_mnemonic_count() {
        let mnemonics = all_riscv_mnemonics();
        assert!(
            mnemonics.len() >= 200,
            "Expected >=200 unique mnemonics, got {}",
            mnemonics.len()
        );
    }

    #[test]
    fn test_extension_names() {
        assert_eq!(RiscVExtension::RV32I.name(), "RV32I");
        assert_eq!(RiscVExtension::Zba.name(), "Zba");
        assert_eq!(RiscVExtension::Zicsr.name(), "Zicsr");
        assert_eq!(RiscVExtension::V.name(), "V");
        assert_eq!(RiscVExtension::H.name(), "H");
    }

    #[test]
    fn test_xlen_bits() {
        assert_eq!(RiscVXlen::RV32.bits(), 32);
        assert_eq!(RiscVXlen::RV64.bits(), 64);
        assert_eq!(RiscVXlen::RV128.bits(), 128);
        assert!(RiscVXlen::RV32.is_32bit());
        assert!(RiscVXlen::RV64.is_64bit());
    }

    #[test]
    fn test_satp_modes() {
        assert_eq!(SatpMode::from_bits(0), Some(SatpMode::Bare));
        assert_eq!(SatpMode::from_bits(8), Some(SatpMode::Sv39));
        assert_eq!(SatpMode::from_bits(99), None);
    }

    #[test]
    fn test_vs_csrs() {
        let bank = RiscVRegisterBank::new_rv64();
        let csrs = [
            "vsstatus", "vsie", "vstvec", "vsscratch",
            "vsepc", "vscause", "vstval", "vsip", "vsatp",
        ];
        for csr in &csrs {
            assert!(bank.get(csr).is_some(), "Missing VS CSR {}", csr);
        }
    }

    #[test]
    fn test_processor_module_interface() {
        let regs = RiscVModule::registers();
        assert!(!regs.is_empty());
        let langs = RiscVModule::languages();
        assert!(langs.len() >= 6);
        let insts = RiscVModule::instructions();
        assert!(insts.len() >= 200);
    }

    #[test]
    fn test_vector_mnemonics_present() {
        let mnemonics = all_riscv_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["VADD.VV", "VLE32.V", "VSETVLI", "VFMADD.VV", "VMFEQ.VV"] {
            assert!(texts.contains(&m), "Missing V extension mnemonic: {}", m);
        }
    }

    #[test]
    fn test_priviledged_mnemonics_present() {
        let mnemonics = all_riscv_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["WFI", "MRET", "SRET", "SFENCE.VMA", "HFENCE.VVMA"] {
            assert!(texts.contains(&m), "Missing privileged mnemonic: {}", m);
        }
    }
}
