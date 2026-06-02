//! x86/x86-64 Register Definitions
//!
//! Defines the complete register set for all x86 processor variants,
//! from the 8086 through AVX-512 capable x86-64 processors.
//!
//! Register space layout (offsets):
//! - General purpose:  0x000 - 0x07F  (RAX..R15, plus sub-register aliases)
//! - Segment:          0x080 - 0x0BF  (ES, CS, SS, DS, FS, GS)
//! - Control:          0x100 - 0x13F  (CR0..CR15)
//! - Debug:            0x180 - 0x1BF  (DR0..DR15)
//! - MMX:              0x200 - 0x23F  (MM0..MM7)
//! - SSE (XMM):        0x240 - 0x2FF  (XMM0..XMM31)
//! - AVX (YMM):        0x300 - 0x3FF  (YMM0..YMM31, aliased with XMM)
//! - AVX-512 (ZMM):    0x400 - 0x5FF  (ZMM0..ZMM31, aliased with YMM/XMM)
//! - OpMask:           0x600 - 0x63F  (K0..K7)
//! - BND:              0x680 - 0x6BF  (BND0..BND3)
//! - x87:              0x700 - 0x77F  (ST0..ST7)
//! - Flags:            0x800 - 0x803  (EFLAGS/RFLAGS)
//! - IP:               0x810 - 0x817  (RIP/EIP/IP)
//! - MXCSR:            0x820 - 0x823
//! - XCR0:             0x830 - 0x837

use std::collections::HashMap;

/// A single processor register definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Register {
    /// Human-readable name (e.g., "RAX", "XMM0", "CR3")
    pub name: String,
    /// Width of the register in bits
    pub bit_size: u32,
    /// Offset into the register space (unique address for this register)
    pub offset: u64,
    /// For sub-registers, the name of the parent register (e.g., AL -> RAX, AX -> RAX)
    pub parent: Option<String>,
    /// Least significant bit offset within the parent register (0 for full-width)
    pub lsb: u32,
}

impl Register {
    /// Create a new top-level (non-sub-register) register.
    pub fn new(name: &str, bit_size: u32, offset: u64) -> Self {
        Register {
            name: name.to_string(),
            bit_size,
            offset,
            parent: None,
            lsb: 0,
        }
    }

    /// Create a new sub-register that aliases a portion of a parent register.
    pub fn sub_register(name: &str, bit_size: u32, offset: u64, parent: &str, lsb: u32) -> Self {
        Register {
            name: name.to_string(),
            bit_size,
            offset,
            parent: Some(parent.to_string()),
            lsb,
        }
    }

    /// Size of this register in bytes.
    pub fn byte_size(&self) -> u32 {
        (self.bit_size + 7) / 8
    }
}

// ---------------------------------------------------------------------------
// Flag bit definitions for EFLAGS / RFLAGS
// ---------------------------------------------------------------------------

/// Bit positions in the EFLAGS/RFLAGS register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlagBit {
    /// Carry flag (bit 0)
    CF = 0,
    /// Parity flag (bit 2) - always 1 in 64-bit mode
    PF = 2,
    /// Auxiliary carry flag (bit 4)
    AF = 4,
    /// Zero flag (bit 6)
    ZF = 6,
    /// Sign flag (bit 7)
    SF = 7,
    /// Trap flag (bit 8) - single-step
    TF = 8,
    /// Interrupt enable flag (bit 9)
    IF = 9,
    /// Direction flag (bit 10)
    DF = 10,
    /// Overflow flag (bit 11)
    OF = 11,
    /// I/O privilege level (bits 12-13)
    IOPL = 12,
    /// Nested task flag (bit 14)
    NT = 14,
    /// Resume flag (bit 16)
    RF = 16,
    /// Virtual-8086 mode flag (bit 17)
    VM = 17,
    /// Alignment check flag (bit 18)
    AC = 18,
    /// Virtual interrupt flag (bit 19)
    VIF = 19,
    /// Virtual interrupt pending flag (bit 20)
    VIP = 20,
    /// ID flag (bit 21) - CPUID availability
    ID = 21,
}

impl FlagBit {
    /// Return the bit mask for this flag.
    pub fn mask(&self) -> u64 {
        1u64 << (*self as u32)
    }

    /// Return the bit position (0-63) of this flag.
    pub fn bit(&self) -> u32 {
        *self as u32
    }

    /// Human-readable name of the flag.
    pub fn name(&self) -> &'static str {
        match self {
            FlagBit::CF => "CF",
            FlagBit::PF => "PF",
            FlagBit::AF => "AF",
            FlagBit::ZF => "ZF",
            FlagBit::SF => "SF",
            FlagBit::TF => "TF",
            FlagBit::IF => "IF",
            FlagBit::DF => "DF",
            FlagBit::OF => "OF",
            FlagBit::IOPL => "IOPL",
            FlagBit::NT => "NT",
            FlagBit::RF => "RF",
            FlagBit::VM => "VM",
            FlagBit::AC => "AC",
            FlagBit::VIF => "VIF",
            FlagBit::VIP => "VIP",
            FlagBit::ID => "ID",
        }
    }
}

// ---------------------------------------------------------------------------
// x86 register bank
// ---------------------------------------------------------------------------

/// The complete register bank for an x86/x86-64 processor.
///
/// Organises all registers into logical groups. Sub-register aliases
/// (e.g., AL, AX, EAX all reference RAX) are tracked via `Register::parent`.
#[derive(Debug, Clone)]
pub struct X86RegisterBank {
    /// General-purpose registers (index 0 = RAX, 15 = R15)
    pub general: [Register; 16],
    /// Segment registers: [ES, CS, SS, DS, FS, GS]
    pub segments: [Register; 6],
    /// Control registers (CR0..CR15 when present)
    pub control: Vec<Register>,
    /// Debug registers (DR0..DR15 when present)
    pub debug: Vec<Register>,
    /// x87 FPU stack registers (ST0..ST7)
    pub x87: [Register; 8],
    /// MMX registers (MM0..MM7), aliased with x87 mantissa
    pub mmx: [Register; 8],
    /// SSE XMM registers (XMM0..XMM31)
    pub sse: Vec<Register>,
    /// AVX YMM registers (YMM0..YMM31), aliased with XMM low 128 bits
    pub avx: Vec<Register>,
    /// AVX-512 ZMM registers (ZMM0..ZMM31), aliased with YMM low 256 bits
    pub avx512: Vec<Register>,
    /// OpMask registers (K0..K7)
    pub opmask: Vec<Register>,
    /// Bound registers (BND0..BND3) for Intel MPX
    pub bnd: Vec<Register>,
    /// x87/SSE control/status: MXCSR, x87 control word, status word, tag word
    pub fpu_control: Vec<Register>,
    /// Flags register (EFLAGS / RFLAGS)
    pub flags: Register,
    /// Instruction pointer (RIP / EIP / IP)
    pub instruction_pointer: Register,
    /// Stack pointer is RSP (index 4 in general), but kept as named reference
    pub stack_pointer: Register,
    /// Extended control register (XCR0)
    pub xcr0: Register,
    /// All registers indexed by name for fast lookup.
    register_by_name: HashMap<String, Register>,
}

impl X86RegisterBank {
    /// Create the full x86-64 register bank with all extensions enabled.
    pub fn new_x86_64() -> Self {
        // ---------------------------------------------------------------
        // General-purpose registers and sub-register aliases
        // ---------------------------------------------------------------
        let rax = Register::new("RAX", 64, 0x0000);
        let rcx = Register::new("RCX", 64, 0x0008);
        let rdx = Register::new("RDX", 64, 0x0010);
        let rbx = Register::new("RBX", 64, 0x0018);
        let rsp = Register::new("RSP", 64, 0x0020);
        let rbp = Register::new("RBP", 64, 0x0028);
        let rsi = Register::new("RSI", 64, 0x0030);
        let rdi = Register::new("RDI", 64, 0x0038);
        let r8 = Register::new("R8", 64, 0x0040);
        let r9 = Register::new("R9", 64, 0x0048);
        let r10 = Register::new("R10", 64, 0x0050);
        let r11 = Register::new("R11", 64, 0x0058);
        let r12 = Register::new("R12", 64, 0x0060);
        let r13 = Register::new("R13", 64, 0x0068);
        let r14 = Register::new("R14", 64, 0x0070);
        let r15 = Register::new("R15", 64, 0x0078);

        // 32-bit sub-registers (low 32 bits of the 64-bit regs)
        let eax = Register::sub_register("EAX", 32, 0x0000, "RAX", 0);
        let ecx = Register::sub_register("ECX", 32, 0x0008, "RCX", 0);
        let edx = Register::sub_register("EDX", 32, 0x0010, "RDX", 0);
        let ebx = Register::sub_register("EBX", 32, 0x0018, "RBX", 0);
        let esp = Register::sub_register("ESP", 32, 0x0020, "RSP", 0);
        let ebp = Register::sub_register("EBP", 32, 0x0028, "RBP", 0);
        let esi = Register::sub_register("ESI", 32, 0x0030, "RSI", 0);
        let edi = Register::sub_register("EDI", 32, 0x0038, "RDI", 0);
        let r8d = Register::sub_register("R8D", 32, 0x0040, "R8", 0);
        let r9d = Register::sub_register("R9D", 32, 0x0048, "R9", 0);
        let r10d = Register::sub_register("R10D", 32, 0x0050, "R10", 0);
        let r11d = Register::sub_register("R11D", 32, 0x0058, "R11", 0);
        let r12d = Register::sub_register("R12D", 32, 0x0060, "R12", 0);
        let r13d = Register::sub_register("R13D", 32, 0x0068, "R13", 0);
        let r14d = Register::sub_register("R14D", 32, 0x0070, "R14", 0);
        let r15d = Register::sub_register("R15D", 32, 0x0078, "R15", 0);

        // 16-bit sub-registers (low 16 bits of the 32-bit regs)
        let ax = Register::sub_register("AX", 16, 0x0000, "RAX", 0);
        let cx = Register::sub_register("CX", 16, 0x0008, "RCX", 0);
        let dx = Register::sub_register("DX", 16, 0x0010, "RDX", 0);
        let bx = Register::sub_register("BX", 16, 0x0018, "RBX", 0);
        let sp = Register::sub_register("SP", 16, 0x0020, "RSP", 0);
        let bp = Register::sub_register("BP", 16, 0x0028, "RBP", 0);
        let si = Register::sub_register("SI", 16, 0x0030, "RSI", 0);
        let di = Register::sub_register("DI", 16, 0x0038, "RDI", 0);
        let r8w = Register::sub_register("R8W", 16, 0x0040, "R8", 0);
        let r9w = Register::sub_register("R9W", 16, 0x0048, "R9", 0);
        let r10w = Register::sub_register("R10W", 16, 0x0050, "R10", 0);
        let r11w = Register::sub_register("R11W", 16, 0x0058, "R11", 0);
        let r12w = Register::sub_register("R12W", 16, 0x0060, "R12", 0);
        let r13w = Register::sub_register("R13W", 16, 0x0068, "R13", 0);
        let r14w = Register::sub_register("R14W", 16, 0x0070, "R14", 0);
        let r15w = Register::sub_register("R15W", 16, 0x0078, "R15", 0);

        // 8-bit sub-registers (low 8 bits)
        let al = Register::sub_register("AL", 8, 0x0000, "RAX", 0);
        let cl = Register::sub_register("CL", 8, 0x0008, "RCX", 0);
        let dl = Register::sub_register("DL", 8, 0x0010, "RDX", 0);
        let bl = Register::sub_register("BL", 8, 0x0018, "RBX", 0);
        let spl_ = Register::sub_register("SPL", 8, 0x0020, "RSP", 0);
        let bpl_ = Register::sub_register("BPL", 8, 0x0028, "RBP", 0);
        let sil_ = Register::sub_register("SIL", 8, 0x0030, "RSI", 0);
        let dil_ = Register::sub_register("DIL", 8, 0x0038, "RDI", 0);
        let r8b = Register::sub_register("R8B", 8, 0x0040, "R8", 0);
        let r9b = Register::sub_register("R9B", 8, 0x0048, "R9", 0);
        let r10b = Register::sub_register("R10B", 8, 0x0050, "R10", 0);
        let r11b = Register::sub_register("R11B", 8, 0x0058, "R11", 0);
        let r12b = Register::sub_register("R12B", 8, 0x0060, "R12", 0);
        let r13b = Register::sub_register("R13B", 8, 0x0068, "R13", 0);
        let r14b = Register::sub_register("R14B", 8, 0x0070, "R14", 0);
        let r15b = Register::sub_register("R15B", 8, 0x0078, "R15", 0);

        // High 8-bit sub-registers (bits 8-15 of AX..DX)
        let ah = Register::sub_register("AH", 8, 0x0001, "RAX", 8);
        let ch = Register::sub_register("CH", 8, 0x0009, "RCX", 8);
        let dh = Register::sub_register("DH", 8, 0x0011, "RDX", 8);
        let bh = Register::sub_register("BH", 8, 0x0019, "RBX", 8);

        // ---------------------------------------------------------------
        // Segment registers
        // ---------------------------------------------------------------
        let es = Register::new("ES", 16, 0x0080);
        let cs = Register::new("CS", 16, 0x0088);
        let ss = Register::new("SS", 16, 0x0090);
        let ds = Register::new("DS", 16, 0x0098);
        let fs = Register::new("FS", 16, 0x00A0);
        let gs = Register::new("GS", 16, 0x00A8);

        // ---------------------------------------------------------------
        // Control registers
        // ---------------------------------------------------------------
        let cr0 = Register::new("CR0", 64, 0x0100);
        let cr2 = Register::new("CR2", 64, 0x0108);
        let cr3 = Register::new("CR3", 64, 0x0110);
        let cr4 = Register::new("CR4", 64, 0x0118);
        let cr8 = Register::new("CR8", 64, 0x0120);

        // ---------------------------------------------------------------
        // Debug registers
        // ---------------------------------------------------------------
        let dr0 = Register::new("DR0", 64, 0x0180);
        let dr1 = Register::new("DR1", 64, 0x0188);
        let dr2 = Register::new("DR2", 64, 0x0190);
        let dr3 = Register::new("DR3", 64, 0x0198);
        let dr6 = Register::new("DR6", 64, 0x01A0);
        let dr7 = Register::new("DR7", 64, 0x01A8);

        // ---------------------------------------------------------------
        // MMX registers (aliased with x87 ST0..ST7 mantissa bits)
        // ---------------------------------------------------------------
        let mmx_regs: [Register; 8] = std::array::from_fn(|i| {
            Register::new(&format!("MM{}", i), 64, 0x0200 + (i as u64) * 8)
        });

        // ---------------------------------------------------------------
        // SSE XMM registers
        // ---------------------------------------------------------------
        let num_xmm = 32; // XMM0..XMM31 for AVX-512 capable
        let mut xmm_regs = Vec::with_capacity(num_xmm);
        for i in 0..num_xmm {
            xmm_regs.push(Register::new(
                &format!("XMM{}", i),
                128,
                0x0240 + (i as u64) * 16,
            ));
        }

        // ---------------------------------------------------------------
        // AVX YMM registers (aliased with XMM low 128 bits)
        // ---------------------------------------------------------------
        let num_ymm = 32;
        let mut ymm_regs = Vec::with_capacity(num_ymm);
        for i in 0..num_ymm {
            let parent = format!("XMM{}", i);
            ymm_regs.push(Register::sub_register(
                &format!("YMM{}", i),
                256,
                0x0300 + (i as u64) * 32,
                &parent,
                0,
            ));
        }

        // ---------------------------------------------------------------
        // AVX-512 ZMM registers (aliased with YMM low 256 bits)
        // ---------------------------------------------------------------
        let num_zmm = 32;
        let mut zmm_regs = Vec::with_capacity(num_zmm);
        for i in 0..num_zmm {
            let parent = format!("YMM{}", i);
            zmm_regs.push(Register::sub_register(
                &format!("ZMM{}", i),
                512,
                0x0400 + (i as u64) * 64,
                &parent,
                0,
            ));
        }

        // ---------------------------------------------------------------
        // OpMask registers (K0..K7)
        // ---------------------------------------------------------------
        let mut opmask_regs = Vec::with_capacity(8);
        for i in 0..8 {
            opmask_regs.push(Register::new(
                &format!("K{}", i),
                64,
                0x0600 + (i as u64) * 8,
            ));
        }

        // ---------------------------------------------------------------
        // BND registers (MPX)
        // ---------------------------------------------------------------
        let mut bnd_regs = Vec::with_capacity(4);
        for i in 0..4 {
            bnd_regs.push(Register::new(
                &format!("BND{}", i),
                128,
                0x0680 + (i as u64) * 16,
            ));
        }

        // ---------------------------------------------------------------
        // x87 FPU stack registers
        // ---------------------------------------------------------------
        let x87_regs: [Register; 8] = std::array::from_fn(|i| {
            Register::new(&format!("ST{}", i), 80, 0x0700 + (i as u64) * 16)
        });

        // ---------------------------------------------------------------
        // FPU control/status registers
        // ---------------------------------------------------------------
        let fcw = Register::new("FCW", 16, 0x0780); // x87 control word
        let fsw = Register::new("FSW", 16, 0x0782); // x87 status word
        let ftw = Register::new("FTW", 16, 0x0784); // x87 tag word
        let fop = Register::new("FOP", 16, 0x0786); // x87 last opcode
        let fip = Register::new("FIP", 64, 0x0788); // x87 last instruction pointer
        let fdp = Register::new("FDP", 64, 0x0790); // x87 last data pointer
        let mxcsr = Register::new("MXCSR", 32, 0x0820);

        // ---------------------------------------------------------------
        // Flags, instruction pointer, stack pointer, XCR0
        // ---------------------------------------------------------------
        let eflags = Register::new("EFLAGS", 32, 0x0800);
        let rflags = Register::new("RFLAGS", 64, 0x0800);
        let eip = Register::new("EIP", 32, 0x0810);
        let rip = Register::new("RIP", 64, 0x0810);
        let ip = Register::sub_register("IP", 16, 0x0810, "RIP", 0);
        let xcr0 = Register::new("XCR0", 64, 0x0830);

        // Build the lookup table
        let mut register_by_name = HashMap::new();

        // General + sub-registers
        let gp_names = [
            ("RAX", &rax),
            ("RCX", &rcx),
            ("RDX", &rdx),
            ("RBX", &rbx),
            ("RSP", &rsp),
            ("RBP", &rbp),
            ("RSI", &rsi),
            ("RDI", &rdi),
            ("R8", &r8),
            ("R9", &r9),
            ("R10", &r10),
            ("R11", &r11),
            ("R12", &r12),
            ("R13", &r13),
            ("R14", &r14),
            ("R15", &r15),
        ];
        for (name, reg) in &gp_names {
            register_by_name.insert((*name).to_string(), (*reg).clone());
        }

        let sub32_names = [
            ("EAX", &eax),
            ("ECX", &ecx),
            ("EDX", &edx),
            ("EBX", &ebx),
            ("ESP", &esp),
            ("EBP", &ebp),
            ("ESI", &esi),
            ("EDI", &edi),
            ("R8D", &r8d),
            ("R9D", &r9d),
            ("R10D", &r10d),
            ("R11D", &r11d),
            ("R12D", &r12d),
            ("R13D", &r13d),
            ("R14D", &r14d),
            ("R15D", &r15d),
        ];
        for (name, reg) in &sub32_names {
            register_by_name.insert((*name).to_string(), (*reg).clone());
        }

        let sub16_names = [
            ("AX", &ax),
            ("CX", &cx),
            ("DX", &dx),
            ("BX", &bx),
            ("SP", &sp),
            ("BP", &bp),
            ("SI", &si),
            ("DI", &di),
            ("R8W", &r8w),
            ("R9W", &r9w),
            ("R10W", &r10w),
            ("R11W", &r11w),
            ("R12W", &r12w),
            ("R13W", &r13w),
            ("R14W", &r14w),
            ("R15W", &r15w),
        ];
        for (name, reg) in &sub16_names {
            register_by_name.insert((*name).to_string(), (*reg).clone());
        }

        let sub8_names = [
            ("AL", &al),
            ("CL", &cl),
            ("DL", &dl),
            ("BL", &bl),
            ("AH", &ah),
            ("CH", &ch),
            ("DH", &dh),
            ("BH", &bh),
            ("SPL", &spl_),
            ("BPL", &bpl_),
            ("SIL", &sil_),
            ("DIL", &dil_),
            ("R8B", &r8b),
            ("R9B", &r9b),
            ("R10B", &r10b),
            ("R11B", &r11b),
            ("R12B", &r12b),
            ("R13B", &r13b),
            ("R14B", &r14b),
            ("R15B", &r15b),
        ];
        for (name, reg) in &sub8_names {
            register_by_name.insert((*name).to_string(), (*reg).clone());
        }

        // Segment
        let seg_names = [
            ("ES", &es),
            ("CS", &cs),
            ("SS", &ss),
            ("DS", &ds),
            ("FS", &fs),
            ("GS", &gs),
        ];
        for (name, reg) in &seg_names {
            register_by_name.insert((*name).to_string(), (*reg).clone());
        }

        // Control
        let cr_names = [
            ("CR0", &cr0),
            ("CR2", &cr2),
            ("CR3", &cr3),
            ("CR4", &cr4),
            ("CR8", &cr8),
        ];
        for (name, reg) in &cr_names {
            register_by_name.insert((*name).to_string(), (*reg).clone());
        }

        // Debug
        let dr_names = [
            ("DR0", &dr0),
            ("DR1", &dr1),
            ("DR2", &dr2),
            ("DR3", &dr3),
            ("DR6", &dr6),
            ("DR7", &dr7),
        ];
        for (name, reg) in &dr_names {
            register_by_name.insert((*name).to_string(), (*reg).clone());
        }

        // MMX
        for (i, reg) in mmx_regs.iter().enumerate() {
            register_by_name.insert(format!("MM{}", i), reg.clone());
        }

        // XMM
        for (i, reg) in xmm_regs.iter().enumerate() {
            register_by_name.insert(format!("XMM{}", i), reg.clone());
        }

        // YMM
        for (i, reg) in ymm_regs.iter().enumerate() {
            register_by_name.insert(format!("YMM{}", i), reg.clone());
        }

        // ZMM
        for (i, reg) in zmm_regs.iter().enumerate() {
            register_by_name.insert(format!("ZMM{}", i), reg.clone());
        }

        // OpMask
        for (i, reg) in opmask_regs.iter().enumerate() {
            register_by_name.insert(format!("K{}", i), reg.clone());
        }

        // BND
        for (i, reg) in bnd_regs.iter().enumerate() {
            register_by_name.insert(format!("BND{}", i), reg.clone());
        }

        // x87
        for (i, reg) in x87_regs.iter().enumerate() {
            register_by_name.insert(format!("ST{}", i), reg.clone());
        }

        // FPU control
        register_by_name.insert("FCW".to_string(), fcw.clone());
        register_by_name.insert("FSW".to_string(), fsw.clone());
        register_by_name.insert("FTW".to_string(), ftw.clone());
        register_by_name.insert("FOP".to_string(), fop.clone());
        register_by_name.insert("FIP".to_string(), fip.clone());
        register_by_name.insert("FDP".to_string(), fdp.clone());
        register_by_name.insert("MXCSR".to_string(), mxcsr.clone());

        // Flags, IP
        register_by_name.insert("EFLAGS".to_string(), eflags.clone());
        register_by_name.insert("RFLAGS".to_string(), rflags);
        register_by_name.insert("EIP".to_string(), eip);
        register_by_name.insert("RIP".to_string(), rip.clone());
        register_by_name.insert("IP".to_string(), ip);
        register_by_name.insert("XCR0".to_string(), xcr0.clone());

        X86RegisterBank {
            general: [
                rax, rcx, rdx, rbx, rsp.clone(), rbp, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15,
            ],
            segments: [es, cs, ss, ds, fs, gs],
            control: vec![cr0, cr2, cr3, cr4, cr8],
            debug: vec![dr0, dr1, dr2, dr3, dr6, dr7],
            x87: x87_regs,
            mmx: mmx_regs,
            sse: xmm_regs,
            avx: ymm_regs,
            avx512: zmm_regs,
            opmask: opmask_regs,
            bnd: bnd_regs,
            fpu_control: vec![fcw, fsw, ftw, fop, fip, fdp, mxcsr],
            flags: eflags,
            instruction_pointer: rip,
            stack_pointer: rsp.clone(),
            xcr0,
            register_by_name,
        }
    }

    /// Look up a register by its name (case-sensitive, e.g., "RAX", "XMM0").
    pub fn get(&self, name: &str) -> Option<&Register> {
        self.register_by_name.get(name)
    }

    /// Return all registers that alias (are sub-registers of) the given parent.
    pub fn sub_registers_of(&self, parent_name: &str) -> Vec<&Register> {
        self.register_by_name
            .values()
            .filter(|r| r.parent.as_deref() == Some(parent_name))
            .collect()
    }

    /// Return all top-level registers (those without a parent).
    pub fn top_level_registers(&self) -> Vec<&Register> {
        self.register_by_name
            .values()
            .filter(|r| r.parent.is_none())
            .collect()
    }

    /// Return the total number of defined registers (including sub-registers).
    pub fn len(&self) -> usize {
        self.register_by_name.len()
    }

    /// Returns true if the register bank is empty.
    pub fn is_empty(&self) -> bool {
        self.register_by_name.is_empty()
    }

    /// Iterate over all registered registers.
    pub fn iter(&self) -> impl Iterator<Item = &Register> {
        self.register_by_name.values()
    }
}

impl Default for X86RegisterBank {
    fn default() -> Self {
        Self::new_x86_64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_bank_creation() {
        let bank = X86RegisterBank::new_x86_64();
        assert!(bank.len() > 100, "Expected many register definitions");
        assert!(bank.get("RAX").is_some());
        assert!(bank.get("R15").is_some());
        assert!(bank.get("ZMM31").is_some());
        assert!(bank.get("XMM0").is_some());
        assert!(bank.get("CR3").is_some());
        assert!(bank.get("EFLAGS").is_some());
    }

    #[test]
    fn test_sub_register_aliasing() {
        let bank = X86RegisterBank::new_x86_64();
        let rax = bank.get("RAX").unwrap();
        assert_eq!(rax.bit_size, 64);

        let eax = bank.get("EAX").unwrap();
        assert_eq!(eax.parent.as_deref(), Some("RAX"));
        assert_eq!(eax.bit_size, 32);

        let ax = bank.get("AX").unwrap();
        assert_eq!(ax.parent.as_deref(), Some("RAX"));
        assert_eq!(ax.bit_size, 16);

        let al = bank.get("AL").unwrap();
        assert_eq!(al.parent.as_deref(), Some("RAX"));
        assert_eq!(al.bit_size, 8);

        let ah = bank.get("AH").unwrap();
        assert_eq!(ah.parent.as_deref(), Some("RAX"));
        assert_eq!(ah.bit_size, 8);
        assert_eq!(ah.lsb, 8);
    }

    #[test]
    fn test_flag_bits() {
        assert_eq!(FlagBit::CF.mask(), 1);
        assert_eq!(FlagBit::ZF.mask(), 1 << 6);
        assert_eq!(FlagBit::OF.mask(), 1 << 11);
        assert_eq!(FlagBit::ID.mask(), 1 << 21);
    }

    #[test]
    fn test_sub_registers_of() {
        let bank = X86RegisterBank::new_x86_64();
        let subs = bank.sub_registers_of("RAX");
        assert!(subs.iter().any(|r| r.name == "EAX"));
        assert!(subs.iter().any(|r| r.name == "AX"));
        assert!(subs.iter().any(|r| r.name == "AL"));
        assert!(subs.iter().any(|r| r.name == "AH"));
    }

    #[test]
    fn test_xmm_ymm_zmm_chain() {
        let bank = X86RegisterBank::new_x86_64();
        let xmm0 = bank.get("XMM0").unwrap();
        assert_eq!(xmm0.bit_size, 128);

        let ymm0 = bank.get("YMM0").unwrap();
        assert_eq!(ymm0.bit_size, 256);
        assert_eq!(ymm0.parent.as_deref(), Some("XMM0"));

        let zmm0 = bank.get("ZMM0").unwrap();
        assert_eq!(zmm0.bit_size, 512);
        assert_eq!(zmm0.parent.as_deref(), Some("YMM0"));
    }

    #[test]
    fn test_segment_registers() {
        let bank = X86RegisterBank::new_x86_64();
        for seg in &["ES", "CS", "SS", "DS", "FS", "GS"] {
            let reg = bank.get(seg).expect(seg);
            assert_eq!(reg.bit_size, 16, "Segment {} should be 16-bit", seg);
        }
    }

    #[test]
    fn test_control_debug_registers() {
        let bank = X86RegisterBank::new_x86_64();
        for cr in &["CR0", "CR2", "CR3", "CR4", "CR8"] {
            assert!(bank.get(cr).is_some(), "Missing {}", cr);
        }
        for dr in &["DR0", "DR1", "DR2", "DR3", "DR6", "DR7"] {
            assert!(bank.get(dr).is_some(), "Missing {}", dr);
        }
    }
}
