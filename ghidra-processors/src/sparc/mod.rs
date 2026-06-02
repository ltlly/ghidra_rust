//! SPARC Processor Module
//!
//! Complete SPARC V8/V9 processor support including register windows, privileged
//! registers, FPU (%f0-63), VIS extensions, and 200+ instruction mnemonics.
//!
//! ## Supported Variants
//!
//! | Variant | Features                                                     |
//! |---------|--------------------------------------------------------------|
//! | V7      | 32-bit, register windows, no multiply/divide                 |
//! | V8      | 32-bit, integer mul/div, SWAP, LDSTUB                        |
//! | V8+     | 32-bit with V9 instruction subset in 32-bit mode              |
//! | V9      | 64-bit, extended ASRs, alternate space, VIS, prefetch         |
//! | V9+VIS1 | V9 + Visual Instruction Set 1                                 |
//! | V9+VIS2 | V9 + VIS 2 (BF, FP min/max, FP subs/adds)                    |
//! | V9+VIS3 | V9 + VIS 3 (movdtox, lzcnt, fp half-prec, etc.)              |
//!
//! ## Register Model
//!
//! SPARC uses overlapping register windows:
//! - %g0-7: Global registers (shared across all windows; %g0 = zero)
//! - %o0-7: Out registers (%o6 = %sp, %o7 = return address)
//! - %l0-7: Local registers
//! - %i0-7: In registers (%i6 = %fp, %i7 = return address)
//!
//! ABI flat aliases: %r0-%r31 map to %g0-7, %o0-7, %l0-7, %i0-7
//!
//! ## Register Space Layout
//! - Global registers (%g0-7):      0x0000 - 0x0038 (64-bit)
//! - Out registers (%o0-7):         0x0040 - 0x0078
//! - Local registers (%l0-7):       0x0080 - 0x00B8
//! - In registers (%i0-7):          0x00C0 - 0x00F8
//! - Control/Status:                0x0100 - 0x017F
//! - ASR (%y, %asr0-31):           0x0180 - 0x027F
//! - Privileged:                    0x0280 - 0x02FF
//! - FPU (%f0-63):                 0x0300 - 0x04FF
//! - VIS extended:                  0x0500 - 0x057F

pub mod registers;

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

// ============================================================================
// Processor Name Constants
// ============================================================================

pub const PROCESSOR_NAME: &str = "SPARC";

pub const PROCESSOR_DESCRIPTION: &str =
    "SPARC V8/V9 processor family with register windows, FPU, and VIS SIMD extensions";

// ============================================================================
// SPARC ISA Variants
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SparcVariant {
    V7,
    V8,
    V8Plus,
    V9,
    V9VIS1,
    V9VIS2,
    V9VIS3,
}

impl SparcVariant {
    pub fn name(&self) -> &'static str {
        match self {
            SparcVariant::V7 => "V7",
            SparcVariant::V8 => "V8",
            SparcVariant::V8Plus => "V8+",
            SparcVariant::V9 => "V9",
            SparcVariant::V9VIS1 => "V9+VIS1",
            SparcVariant::V9VIS2 => "V9+VIS2",
            SparcVariant::V9VIS3 => "V9+VIS3",
        }
    }

    pub fn is_64bit(&self) -> bool {
        matches!(
            self,
            SparcVariant::V9
                | SparcVariant::V9VIS1
                | SparcVariant::V9VIS2
                | SparcVariant::V9VIS3
        )
    }

    pub fn pointer_size(&self) -> u32 {
        if self.is_64bit() {
            64
        } else {
            32
        }
    }

    pub fn has_vis(&self) -> bool {
        matches!(
            self,
            SparcVariant::V9VIS1
                | SparcVariant::V9VIS2
                | SparcVariant::V9VIS3
        )
    }
}

impl std::fmt::Display for SparcVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

// ============================================================================
// Register Window Constants
// ============================================================================

/// Number of register windows (implementation-dependent, 2 to 32).
pub const NWINDOWS_MIN: u32 = 2;
pub const NWINDOWS_MAX: u32 = 32;
/// Default number of windows for V9.
pub const NWINDOWS_DEFAULT: u32 = 8;

// ============================================================================
// Register Offset Layout
// ============================================================================

const GREG_BASE: u64 = 0x0000;
const OREG_BASE: u64 = 0x0040;
const LREG_BASE: u64 = 0x0080;
const IREG_BASE: u64 = 0x00C0;
const CONTROL_BASE: u64 = 0x0100;
const ASR_BASE: u64 = 0x0180;
const PRIV_BASE: u64 = 0x0280;
const FPU_BASE: u64 = 0x0300;
const VIS_BASE: u64 = 0x0500;

// ============================================================================
// SPARC Register Bank
// ============================================================================

#[derive(Debug, Clone)]
pub struct SparcRegisterBank {
    pub g: [Register; 8],
    pub o: [Register; 8],
    pub l: [Register; 8],
    pub i: [Register; 8],
    pub pc: Register,
    pub npc: Register,
    pub cwp: Register,
    pub wim: Register,
    pub cansaved: Register,
    pub canrestore: Register,
    pub cleanwin: Register,
    pub otherwin: Register,
    pub wstate: Register,
    pub y: Register,
    pub asr: [Option<Register>; 32],
    pub ccr: Register,
    pub psr: Register,
    pub tbr: Register,
    pub pstate: Register,
    pub tba: Register,
    pub tstate: Register,
    pub tpc: Register,
    pub tnpc: Register,
    pub tt: Register,
    pub tl: Register,
    pub gl: Register,
    pub ver: Register,
    pub pil: Register,
    pub asi: Register,
    pub fsr: Register,
    pub fprs: Register,
    pub f: [Register; 64],
    pub gsr: Register,
    pub tick: Register,
    pub stick: Register,
    pub sys_tick: Register,
    pub sys_stick: Register,
    pub softint: Register,
    register_by_name: std::collections::HashMap<String, Register>,
}

impl SparcRegisterBank {
    pub fn new_v9() -> Self {
        let b64 = |name: &str, off: u64| Register::new(name, 64, off);
        let b32 = |name: &str, off: u64| Register::new(name, 32, off);

        let g: [Register; 8] = std::array::from_fn(|i| {
            b64(&format!("%g{}", i), GREG_BASE + (i as u64) * 8)
        });
        let o: [Register; 8] = std::array::from_fn(|i| {
            b64(&format!("%o{}", i), OREG_BASE + (i as u64) * 8)
        });
        let l: [Register; 8] = std::array::from_fn(|i| {
            b64(&format!("%l{}", i), LREG_BASE + (i as u64) * 8)
        });
        let i_regs: [Register; 8] = std::array::from_fn(|i| {
            b64(&format!("%i{}", i), IREG_BASE + (i as u64) * 8)
        });

        let pc = b64("%pc", CONTROL_BASE + 0x00);
        let npc = b64("%npc", CONTROL_BASE + 0x08);
        let cwp = b32("%cwp", CONTROL_BASE + 0x10);
        let wim = b32("%wim", CONTROL_BASE + 0x14);
        let cansaved = b32("%cansaved", CONTROL_BASE + 0x18);
        let canrestore = b32("%canrestore", CONTROL_BASE + 0x1C);
        let cleanwin = b32("%cleanwin", CONTROL_BASE + 0x20);
        let otherwin = b32("%otherwin", CONTROL_BASE + 0x24);
        let wstate = b32("%wstate", CONTROL_BASE + 0x28);
        let ccr = b32("%ccr", CONTROL_BASE + 0x2C);

        let y = b64("%y", ASR_BASE + 0x00);
        let asr: [Option<Register>; 32] = std::array::from_fn(|i| {
            Some(b64(
                &format!("%asr{}", i),
                ASR_BASE + 0x08 + (i as u64) * 8,
            ))
        });

        let psr = b32("%psr", PRIV_BASE + 0x00);
        let tbr = b64("%tbr", PRIV_BASE + 0x08);
        let pstate = b64("%pstate", PRIV_BASE + 0x10);
        let tba = b64("%tba", PRIV_BASE + 0x18);
        let tstate = b64("%tstate", PRIV_BASE + 0x20);
        let tpc = b64("%tpc", PRIV_BASE + 0x28);
        let tnpc = b64("%tnpc", PRIV_BASE + 0x30);
        let tt = b32("%tt", PRIV_BASE + 0x38);
        let tl = b32("%tl", PRIV_BASE + 0x3C);
        let gl = b32("%gl", PRIV_BASE + 0x40);
        let ver = b32("%ver", PRIV_BASE + 0x44);
        let pil = b32("%pil", PRIV_BASE + 0x48);
        let asi = b32("%asi", PRIV_BASE + 0x4C);
        let fsr = b64("%fsr", PRIV_BASE + 0x50);
        let fprs = b32("%fprs", PRIV_BASE + 0x58);

        let f: [Register; 64] = std::array::from_fn(|i| {
            b32(&format!("%f{}", i), FPU_BASE + (i as u64) * 4)
        });

        let gsr = b64("%gsr", VIS_BASE + 0x00);
        let tick = b64("%tick", VIS_BASE + 0x08);
        let stick = b64("%stick", VIS_BASE + 0x10);
        let sys_tick = b64("%sys_tick", VIS_BASE + 0x18);
        let sys_stick = b64("%sys_stick", VIS_BASE + 0x20);
        let softint = b64("%softint", VIS_BASE + 0x28);

        let mut register_by_name = std::collections::HashMap::new();

        // Global registers
        for i in 0u32..8 {
            register_by_name.insert(format!("%g{}", i), g[i as usize].clone());
            register_by_name.insert(format!("g{}", i), g[i as usize].clone());
        }
        register_by_name.insert("%zero".to_string(), g[0].clone());
        register_by_name.insert("g0".to_string(), g[0].clone());

        // Out registers
        for i in 0u32..8 {
            register_by_name.insert(format!("%o{}", i), o[i as usize].clone());
            register_by_name.insert(format!("o{}", i), o[i as usize].clone());
        }
        register_by_name.insert("%sp".to_string(), o[6].clone());

        // Local registers
        for i in 0u32..8 {
            register_by_name.insert(format!("%l{}", i), l[i as usize].clone());
            register_by_name.insert(format!("l{}", i), l[i as usize].clone());
        }

        // In registers
        for i in 0u32..8 {
            register_by_name.insert(format!("%i{}", i), i_regs[i as usize].clone());
            register_by_name.insert(format!("i{}", i), i_regs[i as usize].clone());
        }
        register_by_name.insert("%fp".to_string(), i_regs[6].clone());

        // ABI r0-r31 aliases (flat view)
        for i in 0u32..8 {
            register_by_name.insert(format!("%r{}", i), g[i as usize].clone());
            register_by_name.insert(format!("r{}", i), g[i as usize].clone());
        }
        for i in 0u32..8 {
            register_by_name.insert(format!("%r{}", 8 + i), o[i as usize].clone());
            register_by_name.insert(format!("r{}", 8 + i), o[i as usize].clone());
        }
        for i in 0u32..8 {
            register_by_name.insert(format!("%r{}", 16 + i), l[i as usize].clone());
            register_by_name.insert(format!("r{}", 16 + i), l[i as usize].clone());
        }
        for i in 0u32..8 {
            register_by_name.insert(format!("%r{}", 24 + i), i_regs[i as usize].clone());
            register_by_name.insert(format!("r{}", 24 + i), i_regs[i as usize].clone());
        }

        // Control/Status registers
        register_by_name.insert("%pc".to_string(), pc.clone());
        register_by_name.insert("%npc".to_string(), npc.clone());
        register_by_name.insert("%cwp".to_string(), cwp.clone());
        register_by_name.insert("%wim".to_string(), wim.clone());
        register_by_name.insert("%cansaved".to_string(), cansaved.clone());
        register_by_name.insert("%canrestore".to_string(), canrestore.clone());
        register_by_name.insert("%cleanwin".to_string(), cleanwin.clone());
        register_by_name.insert("%otherwin".to_string(), otherwin.clone());
        register_by_name.insert("%wstate".to_string(), wstate.clone());
        register_by_name.insert("%ccr".to_string(), ccr.clone());
        register_by_name.insert(
            "%icc".to_string(),
            Register::sub_register("%icc", 8, CONTROL_BASE + 0x2C, "%ccr", 0),
        );
        register_by_name.insert(
            "%xcc".to_string(),
            Register::sub_register("%xcc", 8, CONTROL_BASE + 0x2C, "%ccr", 4),
        );

        // ASR registers
        register_by_name.insert("%y".to_string(), y.clone());
        for i in 0u32..32 {
            if let Some(ref a) = asr[i as usize] {
                register_by_name.insert(format!("%asr{}", i), a.clone());
                register_by_name.insert(format!("asr{}", i), a.clone());
            }
        }

        // Privileged registers
        let priv_names: [&str; 15] = [
            "%psr", "%tbr", "%pstate", "%tba", "%tstate", "%tpc", "%tnpc",
            "%tt", "%tl", "%gl", "%ver", "%pil", "%asi", "%fsr", "%fprs",
        ];
        let priv_regs: [&Register; 15] = [
            &psr, &tbr, &pstate, &tba, &tstate, &tpc, &tnpc,
            &tt, &tl, &gl, &ver, &pil, &asi, &fsr, &fprs,
        ];
        for (name, reg) in priv_names.iter().zip(priv_regs.iter()) {
            register_by_name.insert(name.to_string(), (*reg).clone());
        }

        // PSR bit fields (32-bit layout for V8)
        let psr_fields: [(&str, u32); 8] = [
            ("%psr_N", 23),
            ("%psr_Z", 22),
            ("%psr_V", 21),
            ("%psr_C", 20),
            ("%psr_EF", 12),
            ("%psr_PIL0", 8),
            ("%psr_S", 7),
            ("%psr_ET", 5),
        ];
        for (name, bit) in psr_fields {
            register_by_name.insert(
                name.to_string(),
                Register::sub_register(name, 1, PRIV_BASE + 0x00, "%psr", bit),
            );
        }

        // PSTATE bit fields (64-bit for V9)
        let pstate_fields: [(&str, u32); 12] = [
            ("%pstate_IE", 1),
            ("%pstate_PRIV", 2),
            ("%pstate_AM", 3),
            ("%pstate_PEF", 4),
            ("%pstate_RED", 5),
            ("%pstate_TLE", 6),
            ("%pstate_CLE", 7),
            ("%pstate_MM0", 8),
            ("%pstate_MM1", 9),
            ("%pstate_TCT", 10),
            ("%pstate_IG", 11),
            ("%pstate_MG", 12),
        ];
        for (name, bit) in pstate_fields {
            register_by_name.insert(
                name.to_string(),
                Register::sub_register(name, 1, PRIV_BASE + 0x10, "%pstate", bit),
            );
        }

        // FSR bit fields
        let fsr_fields: [(&str, u32); 8] = [
            ("%fsr_N", 31),
            ("%fsr_Z", 30),
            ("%fsr_V", 29),
            ("%fsr_C", 28),
            ("%fsr_AEXC", 22),
            ("%fsr_CEXC0", 0),
            ("%fsr_TEM0", 23),
            ("%fsr_RD0", 30),
        ];
        for (name, bit) in fsr_fields {
            register_by_name.insert(
                name.to_string(),
                Register::sub_register(name, 1, PRIV_BASE + 0x50, "%fsr", bit),
            );
        }

        // FPU %f0-63 (32-bit single precision)
        for (i, reg) in f.iter().enumerate() {
            register_by_name.insert(format!("%f{}", i), reg.clone());
            register_by_name.insert(format!("f{}", i), reg.clone());
        }

        // Double-precision aliases %d0-%d62 (pairs of %f registers)
        for i in (0u32..64).step_by(2) {
            let dname = format!("%d{}", i);
            register_by_name.insert(
                dname.clone(),
                Register::sub_register(&dname, 64, FPU_BASE + (i as u64) * 4, &format!("%f{}", i), 0),
            );
            register_by_name.insert(format!("d{}", i), Register::sub_register(
                &format!("d{}", i), 64, FPU_BASE + (i as u64) * 4, &format!("%f{}", i), 0,
            ));
        }

        // Quad-precision aliases %q0-%q48 (groups of 4 %f registers)
        for i in (0u32..64).step_by(4) {
            let qname = format!("%q{}", i);
            register_by_name.insert(
                qname.clone(),
                Register::sub_register(&qname, 128, FPU_BASE + (i as u64) * 4, &format!("%f{}", i), 0),
            );
            register_by_name.insert(format!("q{}", i), Register::sub_register(
                &format!("q{}", i), 128, FPU_BASE + (i as u64) * 4, &format!("%f{}", i), 0,
            ));
        }

        // VIS registers
        register_by_name.insert("%gsr".to_string(), gsr.clone());
        register_by_name.insert("%tick".to_string(), tick.clone());
        register_by_name.insert("%stick".to_string(), stick.clone());
        register_by_name.insert("%sys_tick".to_string(), sys_tick.clone());
        register_by_name.insert("%sys_stick".to_string(), sys_stick.clone());
        register_by_name.insert("%softint".to_string(), softint.clone());

        // GSR sub-fields
        register_by_name.insert(
            "%gsr_IMASK".to_string(),
            Register::sub_register("%gsr_IMASK", 4, VIS_BASE + 0x00, "%gsr", 0),
        );
        register_by_name.insert(
            "%gsr_ALIGN".to_string(),
            Register::sub_register("%gsr_ALIGN", 3, VIS_BASE + 0x00, "%gsr", 4),
        );
        register_by_name.insert(
            "%gsr_SCALE".to_string(),
            Register::sub_register("%gsr_SCALE", 3, VIS_BASE + 0x00, "%gsr", 32),
        );

        SparcRegisterBank {
            g,
            o,
            l,
            i: i_regs,
            pc,
            npc,
            cwp,
            wim,
            cansaved,
            canrestore,
            cleanwin,
            otherwin,
            wstate,
            y,
            asr,
            ccr,
            psr,
            tbr,
            pstate,
            tba,
            tstate,
            tpc,
            tnpc,
            tt,
            tl,
            gl,
            ver,
            pil,
            asi,
            fsr,
            fprs,
            f,
            gsr,
            tick,
            stick,
            sys_tick,
            sys_stick,
            softint,
            register_by_name,
        }
    }

    pub fn get(&self, name: &str) -> Option<&Register> {
        self.register_by_name.get(name)
    }

    pub fn sub_registers_of(&self, parent: &str) -> Vec<&Register> {
        self.register_by_name
            .values()
            .filter(|r| r.parent.as_deref() == Some(parent))
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

impl Default for SparcRegisterBank {
    fn default() -> Self {
        Self::new_v9()
    }
}

// ============================================================================
// SPARC Instruction Mnemonics (200+)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SparcMnemonic {
    // ----- Load / Store Integer (20) -----
    Ldsb,
    Ldsh,
    Ldub,
    Lduh,
    Ld,
    Ldd,
    Ldx,
    Stb,
    Sth,
    St,
    Std,
    Stx,
    Lduw,
    Ldsw,
    Ldstub,
    Swap,
    Ldstuba,
    Swapa,
    CasxaLoad,
    CasxaStore,

    // ----- Load / Store Floating-Point (8) -----
    Ldf,
    Lddf,
    Ldsr,
    Stf,
    Stdf,
    Stfsr,
    Ldqf,
    Stqf,

    // ----- Load / Store Alternate Space (15) -----
    Lda,
    Ldda,
    Ldsba,
    Ldsha,
    Lduba,
    Lduha,
    Ldxa,
    Stba,
    Stha,
    Sta,
    Stda,
    Stxa,
    Ldfa,
    Stfa,
    Stdfa,

    // ----- Prefetch (2) -----
    Prefetch,
    Prefetcha,

    // ----- Arithmetic (18) -----
    Add,
    Addcc,
    Addx,
    Addxcc,
    Sub,
    Subcc,
    Subx,
    Subxcc,
    Taddcc,
    Taddcctv,
    Tsubcc,
    Tsubcctv,
    Mulscc,
    Umul,
    Smul,
    Udiv,
    Sdiv,
    Cmp,

    // ----- Arithmetic 64-bit (V9) (6) -----
    Umulx,
    Smulx,
    Udivx,
    Sdivx,
    Mulx,
    Addxc,
    Addxccc,

    // ----- Logical (12) -----
    And,
    Andcc,
    Andn,
    Andncc,
    Or,
    Orcc,
    Orn,
    Orncc,
    Xor,
    Xorcc,
    Xnor,
    Xnorcc,

    // ----- Shift (6) -----
    Sll,
    Srl,
    Sra,
    Sllx,
    Srlx,
    Srax,

    // ----- SETHI / NOP / Save / Restore (4) -----
    Sethi,
    Nop,
    Save,
    Restore,

    // ----- Branch on Integer Condition Codes (16) -----
    Bn,
    Be,
    Ble,
    Bl,
    Bleu,
    Bcs,
    Bneg,
    Bvs,
    Ba,
    Bne,
    Bg,
    Bge,
    Bgu,
    Bcc,
    Bpos,
    Bvc,

    // ----- Branch with Prediction (V9) (16) -----
    Bpa,
    Bpn,
    Bpne,
    Bpe,
    Bpg,
    Bple,
    Bpge,
    Bpl,
    Bpgu,
    Bpleu,
    Bpcc,
    Bpcs,
    Bppos,
    Bpneg,
    Bpvc,
    Bpvs,

    // ----- Floating-Point Branch (16) -----
    Fbnv,
    Fbne,
    Fbg,
    Fbuge,
    Fbl,
    Fbule,
    Fbge,
    Fbug,
    Fble,
    Fbul,
    Fbue,
    Fblg,
    Fbo,
    Fbu,
    Fba,
    Fbe,

    // ----- Branch on Register (6) -----
    Brz,
    Brlez,
    Brlz,
    Brnz,
    Brgz,
    Brgez,

    // ----- Call / Jump (4) -----
    Call,
    Jmpl,
    Ret,
    Retl,

    // ----- Trap (16) -----
    Ta,
    Tn,
    Tne,
    Te,
    Tg,
    Tle,
    Tge,
    Tl,
    Tgu,
    Tleu,
    Tcc,
    Tcs,
    Tpos,
    Tneg,
    Tvc,
    Tvs,

    // ----- Read / Write State Registers (8) -----
    Rdy,
    Wry,
    Rdasr,
    Wrasr,
    Rdpr,
    Wrpr,
    Rdhpr,
    Wrhpr,

    // ----- System / Misc (12) -----
    Unimp,
    Iflush,
    Flushw,
    Impdep1,
    Impdep2,
    Membar,
    Stbar,
    Sir,
    Done,
    Retry,
    Illtrap,
    FmovsFpu,
    FmovdFpu,

    // ----- Atomic (4) -----
    Cas,
    Casx,
    Casa,
    Casxa,

    // ----- FPU Single-Precision (18) -----
    Fadds,
    Fsubs,
    Fmuls,
    Fdivs,
    Fsqrts,
    Fabss,
    Fnegs,
    Fmovs,
    Fcmps,
    Fcmpes,
    Fsmtos,
    Fdtos,
    Fqtos,
    Fitos,
    Fstoi,
    Fstod,
    Fstoq,
    Fstox,

    // ----- FPU Double-Precision (16) -----
    Faddd,
    Fsubd,
    Fmuld,
    Fdivd,
    Fsqrtd,
    Fabsd,
    Fnegd,
    Fmovd,
    Fcmpd,
    Fcmped,
    Fdtod,
    Fqtod,
    Fitod,
    Fdtoi,
    Fdtoq,

    // ----- FPU Quad-Precision (12) -----
    Faddq,
    Fsubq,
    Fmulq,
    Fdivq,
    Fsqrtq,
    Fabsq,
    Fnegq,
    Fmovq,
    Fcmpq,
    Fcmpeq,
    Fqtoi,

    // ----- FPU Miscellaneous (12) -----
    Fsmuld,
    Fdtox,
    Fxtos,
    Fxtod,
    Fxtoq,
    Fdix,
    Fqtox,
    Fitoq,
    Fmovrse,
    Fmovrde,
    Fmovrlez,
    Fmovrnez,
    Fmovrgz,
    Fmovrlz,
    Fmovrgez,

    // ----- VIS 1 (42) -----
    Array8,
    Array16,
    Array32,
    Alignaddr,
    AlignaddrLittle,
    Bmask,
    Bshuffle,
    Cmask8,
    Cmask16,
    Cmask32,
    Edge8,
    Edge8l,
    Edge16,
    Edge16l,
    Edge32,
    Edge32l,
    Fpack8,
    Fpack16,
    Fpack32,
    Fpackfix,
    Fpmerge,
    Fmul8x16,
    Fmul8x16al,
    Fmul8x16au,
    Fmul8sux16,
    Fmul8ulx16,
    Fmuld8sux16,
    Fmuld8ulx16,
    Pst8,
    Pst16,
    Pst32,
    Fexpand,
    Fandvis,
    Fnandvis,
    Forvis,
    Fnorvis,
    Fxorvis,
    Fxnorvis,
    Fandnot1vis,
    Fandnot2vis,
    Fornot1vis,
    Fornot2vis,
    Fzerovis,
    Fonevis,
    Fsrc1vis,
    Fsrc2vis,
    Fnot1vis,
    Fnot2vis,

    // ----- VIS 2 (12) -----
    Bfset,
    Bfclr,
    Bfxtr,
    Bfins,
    Flcmps,
    Fpmin32,
    Fpmax32,
    Fpmaxu32,
    Fpminu32,
    Fpsub16,
    Fpsub32,
    Fpadd16,
    Fpadd32,

    // ----- VIS 3 (22) -----
    Movdtox,
    Movstouw,
    Movstosw,
    Movxtod,
    Flcmpd,
    Xmulx,
    Xmulxhi,
    Lzcnt,
    Fchksm16,
    Pdist,
    Fhadd,
    Fhadds,
    Fnadd,
    Fnadds,
    Fnmul,
    Fnmuls,
    Fpsubs16,
    Fpsubs32,
    Fpadds16,
    Fpadds32,
    Fmean16,
    Fmeas16,

    // ----- VIS 4 / M8 Crypto (38) -----
    Sha256,
    Sha512,
    Md5,
    Desip,
    Desii,
    Deskp,
    Kasumi,
    KasumiFi,
    KasumiFl,
    Crc32c,
    AeseRnd00,
    AeseRnd01,
    AeseRnd10,
    AeseRnd11,
    AeseRndLast00,
    AeseRndLast01,
    AeseRndLast10,
    AeseRndLast11,
    AesdRnd00,
    AesdRnd01,
    AesdRnd10,
    AesdRnd11,
    AesdRndLast00,
    AesdRndLast01,
    AesdRndLast10,
    AesdRndLast11,
    AeskRnd00,
    AeskRnd01,
    AeskRnd10,
    AeskRnd11,
    Mpfill,
    Mpsll,
    Mpsrl,
    Mpsra,
    Xmpmul,
    Xmontmul,
    Xmontsqr,
    CamelliaF,
    CamelliaFl,
    Pmulxhi,
    Pmulxlo,

    // ----- Hyperprivileged (2) -----
    Hvret,
    Hvcleanwin,

    // ----- Additional V9 (4) -----
    Fmovccs,
    Fmovccd,
    FmovrSne,
    FmovrSnz,
}

impl SparcMnemonic {
    pub fn as_str(&self) -> &'static str {
        match self {
            // Load / Store Integer
            SparcMnemonic::Ldsb => "ldsb",
            SparcMnemonic::Ldsh => "ldsh",
            SparcMnemonic::Ldub => "ldub",
            SparcMnemonic::Lduh => "lduh",
            SparcMnemonic::Ld => "ld",
            SparcMnemonic::Ldd => "ldd",
            SparcMnemonic::Ldx => "ldx",
            SparcMnemonic::Stb => "stb",
            SparcMnemonic::Sth => "sth",
            SparcMnemonic::St => "st",
            SparcMnemonic::Std => "std",
            SparcMnemonic::Stx => "stx",
            SparcMnemonic::Lduw => "lduw",
            SparcMnemonic::Ldsw => "ldsw",
            SparcMnemonic::Ldstub => "ldstub",
            SparcMnemonic::Swap => "swap",
            SparcMnemonic::Ldstuba => "ldstuba",
            SparcMnemonic::Swapa => "swapa",
            SparcMnemonic::CasxaLoad => "casxa",
            SparcMnemonic::CasxaStore => "casxa",

            // Load / Store FP
            SparcMnemonic::Ldf => "ldf",
            SparcMnemonic::Lddf => "lddf",
            SparcMnemonic::Ldsr => "ldsr",
            SparcMnemonic::Stf => "stf",
            SparcMnemonic::Stdf => "stdf",
            SparcMnemonic::Stfsr => "stfsr",
            SparcMnemonic::Ldqf => "ldqf",
            SparcMnemonic::Stqf => "stqf",

            // Load / Store Alternate
            SparcMnemonic::Lda => "lda",
            SparcMnemonic::Ldda => "ldda",
            SparcMnemonic::Ldsba => "ldsba",
            SparcMnemonic::Ldsha => "ldsha",
            SparcMnemonic::Lduba => "lduba",
            SparcMnemonic::Lduha => "lduha",
            SparcMnemonic::Ldxa => "ldxa",
            SparcMnemonic::Stba => "stba",
            SparcMnemonic::Stha => "stha",
            SparcMnemonic::Sta => "sta",
            SparcMnemonic::Stda => "stda",
            SparcMnemonic::Stxa => "stxa",
            SparcMnemonic::Ldfa => "ldfa",
            SparcMnemonic::Stfa => "stfa",
            SparcMnemonic::Stdfa => "stdfa",

            // Prefetch
            SparcMnemonic::Prefetch => "prefetch",
            SparcMnemonic::Prefetcha => "prefetcha",

            // Arithmetic
            SparcMnemonic::Add => "add",
            SparcMnemonic::Addcc => "addcc",
            SparcMnemonic::Addx => "addx",
            SparcMnemonic::Addxcc => "addxcc",
            SparcMnemonic::Sub => "sub",
            SparcMnemonic::Subcc => "subcc",
            SparcMnemonic::Subx => "subx",
            SparcMnemonic::Subxcc => "subxcc",
            SparcMnemonic::Taddcc => "taddcc",
            SparcMnemonic::Taddcctv => "taddcctv",
            SparcMnemonic::Tsubcc => "tsubcc",
            SparcMnemonic::Tsubcctv => "tsubcctv",
            SparcMnemonic::Mulscc => "mulscc",
            SparcMnemonic::Umul => "umul",
            SparcMnemonic::Smul => "smul",
            SparcMnemonic::Udiv => "udiv",
            SparcMnemonic::Sdiv => "sdiv",
            SparcMnemonic::Cmp => "cmp",

            // Arithmetic 64-bit
            SparcMnemonic::Umulx => "umulx",
            SparcMnemonic::Smulx => "smulx",
            SparcMnemonic::Udivx => "udivx",
            SparcMnemonic::Sdivx => "sdivx",
            SparcMnemonic::Mulx => "mulx",
            SparcMnemonic::Addxc => "addxc",
            SparcMnemonic::Addxccc => "addxccc",

            // Logical
            SparcMnemonic::And => "and",
            SparcMnemonic::Andcc => "andcc",
            SparcMnemonic::Andn => "andn",
            SparcMnemonic::Andncc => "andncc",
            SparcMnemonic::Or => "or",
            SparcMnemonic::Orcc => "orcc",
            SparcMnemonic::Orn => "orn",
            SparcMnemonic::Orncc => "orncc",
            SparcMnemonic::Xor => "xor",
            SparcMnemonic::Xorcc => "xorcc",
            SparcMnemonic::Xnor => "xnor",
            SparcMnemonic::Xnorcc => "xnorcc",

            // Shift
            SparcMnemonic::Sll => "sll",
            SparcMnemonic::Srl => "srl",
            SparcMnemonic::Sra => "sra",
            SparcMnemonic::Sllx => "sllx",
            SparcMnemonic::Srlx => "srlx",
            SparcMnemonic::Srax => "srax",

            // SETHI / NOP / Save / Restore
            SparcMnemonic::Sethi => "sethi",
            SparcMnemonic::Nop => "nop",
            SparcMnemonic::Save => "save",
            SparcMnemonic::Restore => "restore",

            // Branch ICC
            SparcMnemonic::Bn => "bn",
            SparcMnemonic::Be => "be",
            SparcMnemonic::Ble => "ble",
            SparcMnemonic::Bl => "bl",
            SparcMnemonic::Bleu => "bleu",
            SparcMnemonic::Bcs => "bcs",
            SparcMnemonic::Bneg => "bneg",
            SparcMnemonic::Bvs => "bvs",
            SparcMnemonic::Ba => "ba",
            SparcMnemonic::Bne => "bne",
            SparcMnemonic::Bg => "bg",
            SparcMnemonic::Bge => "bge",
            SparcMnemonic::Bgu => "bgu",
            SparcMnemonic::Bcc => "bcc",
            SparcMnemonic::Bpos => "bpos",
            SparcMnemonic::Bvc => "bvc",

            // Branch with Prediction
            SparcMnemonic::Bpa => "bpa",
            SparcMnemonic::Bpn => "bpn",
            SparcMnemonic::Bpne => "bpne",
            SparcMnemonic::Bpe => "bpe",
            SparcMnemonic::Bpg => "bpg",
            SparcMnemonic::Bple => "bple",
            SparcMnemonic::Bpge => "bpge",
            SparcMnemonic::Bpl => "bpl",
            SparcMnemonic::Bpgu => "bpgu",
            SparcMnemonic::Bpleu => "bpleu",
            SparcMnemonic::Bpcc => "bpcc",
            SparcMnemonic::Bpcs => "bpcs",
            SparcMnemonic::Bppos => "bppos",
            SparcMnemonic::Bpneg => "bpneg",
            SparcMnemonic::Bpvc => "bpvc",
            SparcMnemonic::Bpvs => "bpvs",

            // FP Branch
            SparcMnemonic::Fbnv => "fbn",
            SparcMnemonic::Fbne => "fbne",
            SparcMnemonic::Fbg => "fbg",
            SparcMnemonic::Fbuge => "fbuge",
            SparcMnemonic::Fbl => "fbl",
            SparcMnemonic::Fbule => "fbule",
            SparcMnemonic::Fbge => "fbge",
            SparcMnemonic::Fbug => "fbug",
            SparcMnemonic::Fble => "fble",
            SparcMnemonic::Fbul => "fbul",
            SparcMnemonic::Fbue => "fbue",
            SparcMnemonic::Fblg => "fblg",
            SparcMnemonic::Fbo => "fbo",
            SparcMnemonic::Fbu => "fbu",
            SparcMnemonic::Fba => "fba",
            SparcMnemonic::Fbe => "fbe",

            // Branch on Register
            SparcMnemonic::Brz => "brz",
            SparcMnemonic::Brlez => "brlez",
            SparcMnemonic::Brlz => "brlz",
            SparcMnemonic::Brnz => "brnz",
            SparcMnemonic::Brgz => "brgz",
            SparcMnemonic::Brgez => "brgez",

            // Call / Jump
            SparcMnemonic::Call => "call",
            SparcMnemonic::Jmpl => "jmpl",
            SparcMnemonic::Ret => "ret",
            SparcMnemonic::Retl => "retl",

            // Trap
            SparcMnemonic::Ta => "ta",
            SparcMnemonic::Tn => "tn",
            SparcMnemonic::Tne => "tne",
            SparcMnemonic::Te => "te",
            SparcMnemonic::Tg => "tg",
            SparcMnemonic::Tle => "tle",
            SparcMnemonic::Tge => "tge",
            SparcMnemonic::Tl => "tl",
            SparcMnemonic::Tgu => "tgu",
            SparcMnemonic::Tleu => "tleu",
            SparcMnemonic::Tcc => "tcc",
            SparcMnemonic::Tcs => "tcs",
            SparcMnemonic::Tpos => "tpos",
            SparcMnemonic::Tneg => "tneg",
            SparcMnemonic::Tvc => "tvc",
            SparcMnemonic::Tvs => "tvs",

            // Read / Write State
            SparcMnemonic::Rdy => "rdy",
            SparcMnemonic::Wry => "wry",
            SparcMnemonic::Rdasr => "rdasr",
            SparcMnemonic::Wrasr => "wrasr",
            SparcMnemonic::Rdpr => "rdpr",
            SparcMnemonic::Wrpr => "wrpr",
            SparcMnemonic::Rdhpr => "rdhpr",
            SparcMnemonic::Wrhpr => "wrhpr",

            // System
            SparcMnemonic::Unimp => "unimp",
            SparcMnemonic::Iflush => "iflush",
            SparcMnemonic::Flushw => "flushw",
            SparcMnemonic::Impdep1 => "impdep1",
            SparcMnemonic::Impdep2 => "impdep2",
            SparcMnemonic::Membar => "membar",
            SparcMnemonic::Stbar => "stbar",
            SparcMnemonic::Sir => "sir",
            SparcMnemonic::Done => "done",
            SparcMnemonic::Retry => "retry",
            SparcMnemonic::Illtrap => "illtrap",
            SparcMnemonic::FmovsFpu => "fmovs",
            SparcMnemonic::FmovdFpu => "fmovd",

            // Atomic
            SparcMnemonic::Cas => "cas",
            SparcMnemonic::Casx => "casx",
            SparcMnemonic::Casa => "casa",
            SparcMnemonic::Casxa => "casxa",

            // FPU Single
            SparcMnemonic::Fadds => "fadds",
            SparcMnemonic::Fsubs => "fsubs",
            SparcMnemonic::Fmuls => "fmuls",
            SparcMnemonic::Fdivs => "fdivs",
            SparcMnemonic::Fsqrts => "fsqrts",
            SparcMnemonic::Fabss => "fabss",
            SparcMnemonic::Fnegs => "fnegs",
            SparcMnemonic::Fmovs => "fmovs",
            SparcMnemonic::Fcmps => "fcmps",
            SparcMnemonic::Fcmpes => "fcmpes",
            SparcMnemonic::Fsmtos => "fsmtos",
            SparcMnemonic::Fdtos => "fdtos",
            SparcMnemonic::Fqtos => "fqtos",
            SparcMnemonic::Fitos => "fitos",
            SparcMnemonic::Fstoi => "fstoi",
            SparcMnemonic::Fstod => "fstod",
            SparcMnemonic::Fstoq => "fstoq",
            SparcMnemonic::Fstox => "fstox",

            // FPU Double
            SparcMnemonic::Faddd => "faddd",
            SparcMnemonic::Fsubd => "fsubd",
            SparcMnemonic::Fmuld => "fmuld",
            SparcMnemonic::Fdivd => "fdivd",
            SparcMnemonic::Fsqrtd => "fsqrtd",
            SparcMnemonic::Fabsd => "fabsd",
            SparcMnemonic::Fnegd => "fnegd",
            SparcMnemonic::Fmovd => "fmovd",
            SparcMnemonic::Fcmpd => "fcmpd",
            SparcMnemonic::Fcmped => "fcmped",
            SparcMnemonic::Fdtod => "fdtod",
            SparcMnemonic::Fqtod => "fqtod",
            SparcMnemonic::Fitod => "fitod",
            SparcMnemonic::Fdtoi => "fdtoi",
            SparcMnemonic::Fdtoq => "fdtoq",

            // FPU Quad
            SparcMnemonic::Faddq => "faddq",
            SparcMnemonic::Fsubq => "fsubq",
            SparcMnemonic::Fmulq => "fmulq",
            SparcMnemonic::Fdivq => "fdivq",
            SparcMnemonic::Fsqrtq => "fsqrtq",
            SparcMnemonic::Fabsq => "fabsq",
            SparcMnemonic::Fnegq => "fnegq",
            SparcMnemonic::Fmovq => "fmovq",
            SparcMnemonic::Fcmpq => "fcmpq",
            SparcMnemonic::Fcmpeq => "fcmpeq",
            SparcMnemonic::Fqtoi => "fqtoi",

            // FPU Misc
            SparcMnemonic::Fsmuld => "fsmuld",
            SparcMnemonic::Fdtox => "fdtox",
            SparcMnemonic::Fxtos => "fxtos",
            SparcMnemonic::Fxtod => "fxtod",
            SparcMnemonic::Fxtoq => "fxtoq",
            SparcMnemonic::Fdix => "fdix",
            SparcMnemonic::Fqtox => "fqtox",
            SparcMnemonic::Fitoq => "fitoq",
            SparcMnemonic::Fmovrse => "fmovrse",
            SparcMnemonic::Fmovrde => "fmovrde",
            SparcMnemonic::Fmovrlez => "fmovrlez",
            SparcMnemonic::Fmovrnez => "fmovrnez",
            SparcMnemonic::Fmovrgz => "fmovrgz",
            SparcMnemonic::Fmovrlz => "fmovrlz",
            SparcMnemonic::Fmovrgez => "fmovrgez",

            // VIS 1
            SparcMnemonic::Array8 => "array8",
            SparcMnemonic::Array16 => "array16",
            SparcMnemonic::Array32 => "array32",
            SparcMnemonic::Alignaddr => "alignaddr",
            SparcMnemonic::AlignaddrLittle => "alignaddr_little",
            SparcMnemonic::Bmask => "bmask",
            SparcMnemonic::Bshuffle => "bshuffle",
            SparcMnemonic::Cmask8 => "cmask8",
            SparcMnemonic::Cmask16 => "cmask16",
            SparcMnemonic::Cmask32 => "cmask32",
            SparcMnemonic::Edge8 => "edge8",
            SparcMnemonic::Edge8l => "edge8l",
            SparcMnemonic::Edge16 => "edge16",
            SparcMnemonic::Edge16l => "edge16l",
            SparcMnemonic::Edge32 => "edge32",
            SparcMnemonic::Edge32l => "edge32l",
            SparcMnemonic::Fpack8 => "fpack8",
            SparcMnemonic::Fpack16 => "fpack16",
            SparcMnemonic::Fpack32 => "fpack32",
            SparcMnemonic::Fpackfix => "fpackfix",
            SparcMnemonic::Fpmerge => "fpmerge",
            SparcMnemonic::Fmul8x16 => "fmul8x16",
            SparcMnemonic::Fmul8x16al => "fmul8x16al",
            SparcMnemonic::Fmul8x16au => "fmul8x16au",
            SparcMnemonic::Fmul8sux16 => "fmul8sux16",
            SparcMnemonic::Fmul8ulx16 => "fmul8ulx16",
            SparcMnemonic::Fmuld8sux16 => "fmuld8sux16",
            SparcMnemonic::Fmuld8ulx16 => "fmuld8ulx16",
            SparcMnemonic::Pst8 => "pst8",
            SparcMnemonic::Pst16 => "pst16",
            SparcMnemonic::Pst32 => "pst32",
            SparcMnemonic::Fexpand => "fexpand",
            SparcMnemonic::Fandvis => "fand",
            SparcMnemonic::Fnandvis => "fnand",
            SparcMnemonic::Forvis => "for",
            SparcMnemonic::Fnorvis => "fnor",
            SparcMnemonic::Fxorvis => "fxor",
            SparcMnemonic::Fxnorvis => "fxnor",
            SparcMnemonic::Fandnot1vis => "fandnot1",
            SparcMnemonic::Fandnot2vis => "fandnot2",
            SparcMnemonic::Fornot1vis => "fornot1",
            SparcMnemonic::Fornot2vis => "fornot2",
            SparcMnemonic::Fzerovis => "fzero",
            SparcMnemonic::Fonevis => "fone",
            SparcMnemonic::Fsrc1vis => "fsrc1",
            SparcMnemonic::Fsrc2vis => "fsrc2",
            SparcMnemonic::Fnot1vis => "fnot1",
            SparcMnemonic::Fnot2vis => "fnot2",

            // VIS 2
            SparcMnemonic::Bfset => "bfset",
            SparcMnemonic::Bfclr => "bfclr",
            SparcMnemonic::Bfxtr => "bfxtr",
            SparcMnemonic::Bfins => "bfins",
            SparcMnemonic::Flcmps => "flcmps",
            SparcMnemonic::Fpmin32 => "fpmin32",
            SparcMnemonic::Fpmax32 => "fpmax32",
            SparcMnemonic::Fpmaxu32 => "fpmaxu32",
            SparcMnemonic::Fpminu32 => "fpminu32",
            SparcMnemonic::Fpsub16 => "fpsub16",
            SparcMnemonic::Fpsub32 => "fpsub32",
            SparcMnemonic::Fpadd16 => "fpadd16",
            SparcMnemonic::Fpadd32 => "fpadd32",

            // VIS 3
            SparcMnemonic::Movdtox => "movdtox",
            SparcMnemonic::Movstouw => "movstouw",
            SparcMnemonic::Movstosw => "movstosw",
            SparcMnemonic::Movxtod => "movxtod",
            SparcMnemonic::Flcmpd => "flcmpd",
            SparcMnemonic::Xmulx => "xmulx",
            SparcMnemonic::Xmulxhi => "xmulxhi",
            SparcMnemonic::Lzcnt => "lzcnt",
            SparcMnemonic::Fchksm16 => "fchksm16",
            SparcMnemonic::Pdist => "pdist",
            SparcMnemonic::Fhadd => "fhadd",
            SparcMnemonic::Fhadds => "fhadds",
            SparcMnemonic::Fnadd => "fnadd",
            SparcMnemonic::Fnadds => "fnadds",
            SparcMnemonic::Fnmul => "fnmul",
            SparcMnemonic::Fnmuls => "fnmuls",
            SparcMnemonic::Fpsubs16 => "fpsubs16",
            SparcMnemonic::Fpsubs32 => "fpsubs32",
            SparcMnemonic::Fpadds16 => "fpadds16",
            SparcMnemonic::Fpadds32 => "fpadds32",
            SparcMnemonic::Fmean16 => "fmean16",
            SparcMnemonic::Fmeas16 => "fmeas16",

            // VIS 4 Crypto
            SparcMnemonic::Sha256 => "sha256",
            SparcMnemonic::Sha512 => "sha512",
            SparcMnemonic::Md5 => "md5",
            SparcMnemonic::Desip => "des_ip",
            SparcMnemonic::Desii => "des_ii",
            SparcMnemonic::Deskp => "des_kp",
            SparcMnemonic::Kasumi => "kasumi",
            SparcMnemonic::KasumiFi => "kasumi_fi",
            SparcMnemonic::KasumiFl => "kasumi_fl",
            SparcMnemonic::Crc32c => "crc32c",
            SparcMnemonic::AeseRnd00 => "aese_round00",
            SparcMnemonic::AeseRnd01 => "aese_round01",
            SparcMnemonic::AeseRnd10 => "aese_round10",
            SparcMnemonic::AeseRnd11 => "aese_round11",
            SparcMnemonic::AeseRndLast00 => "aese_round_last00",
            SparcMnemonic::AeseRndLast01 => "aese_round_last01",
            SparcMnemonic::AeseRndLast10 => "aese_round_last10",
            SparcMnemonic::AeseRndLast11 => "aese_round_last11",
            SparcMnemonic::AesdRnd00 => "aesd_round00",
            SparcMnemonic::AesdRnd01 => "aesd_round01",
            SparcMnemonic::AesdRnd10 => "aesd_round10",
            SparcMnemonic::AesdRnd11 => "aesd_round11",
            SparcMnemonic::AesdRndLast00 => "aesd_round_last00",
            SparcMnemonic::AesdRndLast01 => "aesd_round_last01",
            SparcMnemonic::AesdRndLast10 => "aesd_round_last10",
            SparcMnemonic::AesdRndLast11 => "aesd_round_last11",
            SparcMnemonic::AeskRnd00 => "aesk_round00",
            SparcMnemonic::AeskRnd01 => "aesk_round01",
            SparcMnemonic::AeskRnd10 => "aesk_round10",
            SparcMnemonic::AeskRnd11 => "aesk_round11",
            SparcMnemonic::Mpfill => "mpfill",
            SparcMnemonic::Mpsll => "mpsll",
            SparcMnemonic::Mpsrl => "mpsrl",
            SparcMnemonic::Mpsra => "mpsra",
            SparcMnemonic::Xmpmul => "xmpmul",
            SparcMnemonic::Xmontmul => "xmontmul",
            SparcMnemonic::Xmontsqr => "xmontsqr",
            SparcMnemonic::CamelliaF => "camellia_f",
            SparcMnemonic::CamelliaFl => "camellia_fl",
            SparcMnemonic::Pmulxhi => "pmulxhi",
            SparcMnemonic::Pmulxlo => "pmulxlo",

            // Hyperprivileged
            SparcMnemonic::Hvret => "hvret",
            SparcMnemonic::Hvcleanwin => "hvcleanwin",

            // Additional V9
            SparcMnemonic::Fmovccs => "fmovccs",
            SparcMnemonic::Fmovccd => "fmovccd",
            SparcMnemonic::FmovrSne => "fmovrsne",
            SparcMnemonic::FmovrSnz => "fmovrsnz",
        }
    }
}

// ============================================================================
// Convert all SPARC mnemonics to the common InstructionMnemonic type
// ============================================================================

pub fn all_sparc_mnemonics() -> Vec<InstructionMnemonic> {
    use SparcMnemonic::*;
    let variants = [
        // Load / Store Integer
        Ldsb, Ldsh, Ldub, Lduh, Ld, Ldd, Ldx,
        Stb, Sth, St, Std, Stx, Lduw, Ldsw,
        Ldstub, Swap, Ldstuba, Swapa,
        CasxaLoad, CasxaStore,
        // Load / Store FP
        Ldf, Lddf, Ldsr, Stf, Stdf, Stfsr, Ldqf, Stqf,
        // Load / Store Alternate
        Lda, Ldda, Ldsba, Ldsha, Lduba, Lduha, Ldxa,
        Stba, Stha, Sta, Stda, Stxa, Ldfa, Stfa, Stdfa,
        // Prefetch
        Prefetch, Prefetcha,
        // Arithmetic
        Add, Addcc, Addx, Addxcc,
        Sub, Subcc, Subx, Subxcc,
        Taddcc, Taddcctv, Tsubcc, Tsubcctv, Mulscc,
        Umul, Smul, Udiv, Sdiv, Cmp,
        // Arithmetic 64-bit
        Umulx, Smulx, Udivx, Sdivx, Mulx,
        Addxc, Addxccc,
        // Logical
        And, Andcc, Andn, Andncc,
        Or, Orcc, Orn, Orncc,
        Xor, Xorcc, Xnor, Xnorcc,
        // Shift
        Sll, Srl, Sra, Sllx, Srlx, Srax,
        // SETHI / NOP / Save / Restore
        Sethi, Nop, Save, Restore,
        // Branch ICC
        Bn, Be, Ble, Bl, Bleu, Bcs, Bneg, Bvs, Ba,
        Bne, Bg, Bge, Bgu, Bcc, Bpos, Bvc,
        // Branch with Prediction
        Bpa, Bpn, Bpne, Bpe, Bpg, Bple, Bpge, Bpl,
        Bpgu, Bpleu, Bpcc, Bpcs, Bppos, Bpneg, Bpvc, Bpvs,
        // FP Branch
        Fbnv, Fbne, Fbg, Fbuge, Fbl, Fbule, Fbge, Fbug, Fble, Fbul,
        Fbue, Fblg, Fbo, Fbu, Fba, Fbe,
        // Branch on Register
        Brz, Brlez, Brlz, Brnz, Brgz, Brgez,
        // Call / Jump
        Call, Jmpl, Ret, Retl,
        // Trap
        Ta, Tn, Tne, Te, Tg, Tle, Tge, Tl, Tgu, Tleu, Tcc, Tcs,
        Tpos, Tneg, Tvc, Tvs,
        // Read / Write
        Rdy, Wry, Rdasr, Wrasr, Rdpr, Wrpr, Rdhpr, Wrhpr,
        // System
        Unimp, Iflush, Flushw, Impdep1, Impdep2,
        Membar, Stbar, Sir,
        Done, Retry,
        Illtrap, FmovsFpu, FmovdFpu,
        // Atomic
        Cas, Casx, Casa, Casxa,
        // FPU Single
        Fadds, Fsubs, Fmuls, Fdivs, Fsqrts,
        Fabss, Fnegs, Fmovs, Fcmps, Fcmpes,
        Fsmtos, Fdtos, Fqtos, Fitos, Fstoi, Fstod, Fstoq, Fstox,
        // FPU Double
        Faddd, Fsubd, Fmuld, Fdivd, Fsqrtd,
        Fabsd, Fnegd, Fmovd, Fcmpd, Fcmped,
        Fdtod, Fqtod, Fitod, Fdtoi, Fdtoq,
        // FPU Quad
        Faddq, Fsubq, Fmulq, Fdivq, Fsqrtq,
        Fabsq, Fnegq, Fmovq, Fcmpq, Fcmpeq,
        Fqtoi,
        // FPU Misc
        Fsmuld, Fdtox, Fxtos, Fxtod, Fxtoq,
        Fdix, Fqtox, Fitoq,
        Fmovrse, Fmovrde,
        Fmovrlez, Fmovrnez, Fmovrgz, Fmovrlz, Fmovrgez,
        // VIS 1
        Array8, Array16, Array32,
        Alignaddr, AlignaddrLittle,
        Bmask, Bshuffle,
        Cmask8, Cmask16, Cmask32,
        Edge8, Edge8l, Edge16, Edge16l, Edge32, Edge32l,
        Fpack8, Fpack16, Fpack32, Fpackfix,
        Fpmerge,
        Fmul8x16, Fmul8x16al, Fmul8x16au,
        Fmul8sux16, Fmul8ulx16,
        Fmuld8sux16, Fmuld8ulx16,
        Pst8, Pst16, Pst32, Fexpand,
        Fandvis, Fnandvis, Forvis, Fnorvis, Fxorvis, Fxnorvis,
        Fandnot1vis, Fandnot2vis, Fornot1vis, Fornot2vis,
        Fzerovis, Fonevis, Fsrc1vis, Fsrc2vis, Fnot1vis, Fnot2vis,
        // VIS 2
        Bfset, Bfclr, Bfxtr, Bfins, Flcmps,
        Fpmin32, Fpmax32, Fpmaxu32, Fpminu32,
        Fpsub16, Fpsub32, Fpadd16, Fpadd32,
        // VIS 3
        Movdtox, Movstouw, Movstosw, Movxtod,
        Flcmpd, Xmulx, Xmulxhi,
        Lzcnt, Fchksm16, Pdist,
        Fhadd, Fhadds, Fnadd, Fnadds, Fnmul, Fnmuls,
        Fpsubs16, Fpsubs32, Fpadds16, Fpadds32,
        Fmean16, Fmeas16,
        // VIS 4 Crypto
        Sha256, Sha512, Md5,
        Desip, Desii, Deskp, Kasumi, KasumiFi, KasumiFl,
        Crc32c,
        AeseRnd00, AeseRnd01, AeseRnd10, AeseRnd11,
        AeseRndLast00, AeseRndLast01, AeseRndLast10, AeseRndLast11,
        AesdRnd00, AesdRnd01, AesdRnd10, AesdRnd11,
        AesdRndLast00, AesdRndLast01, AesdRndLast10, AesdRndLast11,
        AeskRnd00, AeskRnd01, AeskRnd10, AeskRnd11,
        Mpfill, Mpsll, Mpsrl, Mpsra,
        Xmpmul, Xmontmul, Xmontsqr,
        CamelliaF, CamelliaFl,
        Pmulxhi, Pmulxlo,
        // Hyperprivileged
        Hvret, Hvcleanwin,
        // Additional V9
        Fmovccs, Fmovccd, FmovrSne, FmovrSnz,
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

pub struct SparcModule;

impl ProcessorModule for SparcModule {
    fn name() -> &'static str {
        PROCESSOR_NAME
    }

    fn registers() -> RegisterBank {
        let sparc_bank = SparcRegisterBank::new_v9();
        let mut bank = RegisterBank::new();
        for reg in sparc_bank.iter() {
            bank.add(reg.clone());
        }
        bank
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "sparc:BE:32:V7",
                "SPARC V7 32-bit Big Endian",
                "V7",
                Endian::Big,
                32,
            ),
            Language::new(
                "sparc:BE:32:V8",
                "SPARC V8 32-bit Big Endian",
                "V8",
                Endian::Big,
                32,
            ),
            Language::new(
                "sparc:BE:32:V8+",
                "SPARC V8+ 32-bit Big Endian",
                "V8+",
                Endian::Big,
                32,
            ),
            Language::new(
                "sparc:BE:64:V9",
                "SPARC V9 64-bit Big Endian",
                "V9",
                Endian::Big,
                64,
            ),
            Language::new(
                "sparc:BE:64:V9_VIS1",
                "SPARC V9 64-bit Big Endian with VIS 1",
                "V9+VIS1",
                Endian::Big,
                64,
            ),
            Language::new(
                "sparc:BE:64:V9_VIS2",
                "SPARC V9 64-bit Big Endian with VIS 2",
                "V9+VIS2",
                Endian::Big,
                64,
            ),
            Language::new(
                "sparc:BE:64:V9_VIS3",
                "SPARC V9 64-bit Big Endian with VIS 3",
                "V9+VIS3",
                Endian::Big,
                64,
            ),
        ]
    }

    fn instructions() -> Vec<InstructionMnemonic> {
        all_sparc_mnemonics()
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
        let bank = SparcRegisterBank::new_v9();
        assert!(
            bank.len() > 120,
            "SPARC bank should have >120 registers, got {}",
            bank.len()
        );
    }

    #[test]
    fn test_global_registers() {
        let bank = SparcRegisterBank::new_v9();
        for i in 0u32..8 {
            assert!(bank.get(&format!("%g{}", i)).is_some(), "Missing %g{}", i);
        }
        assert_eq!(bank.get("%g0").unwrap().bit_size, 64);
    }

    #[test]
    fn test_zero_register_alias() {
        let bank = SparcRegisterBank::new_v9();
        assert!(bank.get("%zero").is_some());
    }

    #[test]
    fn test_window_registers() {
        let bank = SparcRegisterBank::new_v9();
        for i in 0u32..8 {
            assert!(bank.get(&format!("%o{}", i)).is_some());
            assert!(bank.get(&format!("%l{}", i)).is_some());
            assert!(bank.get(&format!("%i{}", i)).is_some());
        }
    }

    #[test]
    fn test_sp_fp_aliases() {
        let bank = SparcRegisterBank::new_v9();
        assert!(bank.get("%sp").is_some());
        assert!(bank.get("%fp").is_some());
    }

    #[test]
    fn test_control_registers() {
        let bank = SparcRegisterBank::new_v9();
        for name in ["%pc", "%npc", "%cwp", "%wim", "%cansaved", "%canrestore"] {
            assert!(bank.get(name).is_some(), "Missing {}", name);
        }
    }

    #[test]
    fn test_window_registers_extended() {
        let bank = SparcRegisterBank::new_v9();
        for name in ["%cleanwin", "%otherwin", "%wstate"] {
            assert!(bank.get(name).is_some(), "Missing {}", name);
        }
    }

    #[test]
    fn test_asr_registers() {
        let bank = SparcRegisterBank::new_v9();
        assert!(bank.get("%y").is_some());
        for i in 0u32..16 {
            assert!(
                bank.get(&format!("%asr{}", i)).is_some(),
                "Missing %asr{}",
                i
            );
        }
    }

    #[test]
    fn test_privileged_registers() {
        let bank = SparcRegisterBank::new_v9();
        let priv_regs = [
            "%psr", "%tbr", "%pstate", "%tba", "%tstate", "%tpc",
            "%tnpc", "%tt", "%tl", "%gl", "%ver", "%pil", "%asi", "%fsr", "%fprs",
        ];
        for r in &priv_regs {
            assert!(bank.get(r).is_some(), "Missing privileged register {}", r);
        }
    }

    #[test]
    fn test_psr_bit_fields() {
        let bank = SparcRegisterBank::new_v9();
        for f in ["%psr_N", "%psr_Z", "%psr_V", "%psr_C", "%psr_EF", "%psr_S"] {
            assert!(bank.get(f).is_some(), "Missing PSR field {}", f);
        }
    }

    #[test]
    fn test_pstate_bit_fields() {
        let bank = SparcRegisterBank::new_v9();
        for f in ["%pstate_IE", "%pstate_PRIV", "%pstate_AM", "%pstate_PEF"] {
            assert!(bank.get(f).is_some(), "Missing PSTATE field {}", f);
        }
    }

    #[test]
    fn test_fsr_bit_fields() {
        let bank = SparcRegisterBank::new_v9();
        for f in ["%fsr_N", "%fsr_Z", "%fsr_V", "%fsr_C", "%fsr_AEXC"] {
            assert!(bank.get(f).is_some(), "Missing FSR field {}", f);
        }
    }

    #[test]
    fn test_fpu_64_registers() {
        let bank = SparcRegisterBank::new_v9();
        for i in 0u32..64 {
            assert!(bank.get(&format!("%f{}", i)).is_some(), "Missing %f{}", i);
        }
    }

    #[test]
    fn test_fpu_double_aliases() {
        let bank = SparcRegisterBank::new_v9();
        for i in (0u32..64).step_by(2) {
            let d = bank.get(&format!("%d{}", i)).unwrap();
            assert_eq!(d.bit_size, 64);
        }
    }

    #[test]
    fn test_fpu_quad_aliases() {
        let bank = SparcRegisterBank::new_v9();
        for i in (0u32..64).step_by(4) {
            let q = bank.get(&format!("%q{}", i)).unwrap();
            assert_eq!(q.bit_size, 128);
        }
    }

    #[test]
    fn test_vis_registers() {
        let bank = SparcRegisterBank::new_v9();
        for r in ["%gsr", "%tick", "%stick", "%sys_tick", "%sys_stick", "%softint"] {
            assert!(bank.get(r).is_some(), "Missing VIS register {}", r);
        }
    }

    #[test]
    fn test_gsr_sub_fields() {
        let bank = SparcRegisterBank::new_v9();
        for f in ["%gsr_IMASK", "%gsr_ALIGN", "%gsr_SCALE"] {
            assert!(bank.get(f).is_some(), "Missing GSR field {}", f);
        }
    }

    #[test]
    fn test_numeric_r_aliases() {
        let bank = SparcRegisterBank::new_v9();
        for i in 0u32..32 {
            assert!(bank.get(&format!("%r{}", i)).is_some(), "Missing %r{}", i);
        }
    }

    #[test]
    fn test_numeric_aliases_no_pct() {
        let bank = SparcRegisterBank::new_v9();
        for i in 0u32..8 {
            assert!(bank.get(&format!("g{}", i)).is_some());
            assert!(bank.get(&format!("o{}", i)).is_some());
            assert!(bank.get(&format!("l{}", i)).is_some());
            assert!(bank.get(&format!("i{}", i)).is_some());
        }
    }

    #[test]
    fn test_mnemonic_count() {
        let mnemonics = all_sparc_mnemonics();
        assert!(
            mnemonics.len() >= 200,
            "Expected >=200 unique mnemonics, got {}",
            mnemonics.len()
        );
    }

    #[test]
    fn test_key_mnemonics_exist() {
        let mnemonics = all_sparc_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in [
            "ld", "st", "add", "sub", "call", "jmpl", "save", "restore",
            "ba", "bne", "be", "nop", "sethi",
            "fadds", "fmuls", "fdivs",
            "ldx", "stx", "flushw", "membar", "done", "retry",
            "array8", "fand", "fxor", "pdist",
            "sha256", "aese_round00", "kasumi",
            "cas", "casx", "casa", "casxa",
            "fmuld", "fmovd", "fcmps", "fmovs",
        ] {
            assert!(texts.contains(&m), "Missing key mnemonic: {}", m);
        }
    }

    #[test]
    fn test_processor_module_interface() {
        assert_eq!(SparcModule::name(), "SPARC");
        let regs = SparcModule::registers();
        assert!(!regs.is_empty());
        let langs = SparcModule::languages();
        assert!(langs.len() >= 5);
        let insts = SparcModule::instructions();
        assert!(insts.len() >= 200);
    }

    #[test]
    fn test_variant_is_64bit() {
        assert!(!SparcVariant::V7.is_64bit());
        assert!(!SparcVariant::V8.is_64bit());
        assert!(!SparcVariant::V8Plus.is_64bit());
        assert!(SparcVariant::V9.is_64bit());
        assert!(SparcVariant::V9VIS3.is_64bit());
    }

    #[test]
    fn test_variant_has_vis() {
        assert!(!SparcVariant::V7.has_vis());
        assert!(!SparcVariant::V9.has_vis());
        assert!(SparcVariant::V9VIS1.has_vis());
        assert!(SparcVariant::V9VIS2.has_vis());
        assert!(SparcVariant::V9VIS3.has_vis());
    }

    #[test]
    fn test_variant_pointer_sizes() {
        assert_eq!(SparcVariant::V7.pointer_size(), 32);
        assert_eq!(SparcVariant::V8.pointer_size(), 32);
        assert_eq!(SparcVariant::V8Plus.pointer_size(), 32);
        assert_eq!(SparcVariant::V9.pointer_size(), 64);
        assert_eq!(SparcVariant::V9VIS3.pointer_size(), 64);
    }

    #[test]
    fn test_condition_codes() {
        let bank = SparcRegisterBank::new_v9();
        assert!(bank.get("%ccr").is_some());
        assert!(bank.get("%icc").is_some());
        assert!(bank.get("%xcc").is_some());
    }

    #[test]
    fn test_vis_mnemonics() {
        let mnemonics = all_sparc_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["edge8", "edge8l", "fpmerge", "fpack16", "pst8",
                   "bfset", "flcmps", "fpmin32",
                   "lzcnt", "fhadd", "fnmuls", "fmean16"] {
            assert!(texts.contains(&m), "Missing VIS mnemonic: {}", m);
        }
    }

    #[test]
    fn test_crypto_mnemonics() {
        let mnemonics = all_sparc_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["aese_round00", "aesd_round_last11", "sha256", "sha512",
                   "camellia_f", "camellia_fl", "xmpmul", "xmontmul"] {
            assert!(texts.contains(&m), "Missing crypto mnemonic: {}", m);
        }
    }
}
