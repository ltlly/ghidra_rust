//! Tests for multi-architecture processor register banks and instruction mnemonics.
//!
//! Covers ARM32, AArch64, MIPS, and RISC-V processor modules.
//! Ports register aliasing, flag bit, and mnemonic classification tests
//! from Ghidra's Java processor test suites.

use ghidra_processors::arm::registers::{ArmRegisterBank, CpsrFlagBit, ProcessorMode};
use ghidra_processors::aarch64::registers::{Aarch64RegisterBank, PstateField};
use ghidra_processors::mips::{
    MipsRegisterBank, MipsVariant, MipsMnemonic, MipsInstructionCategory,
    StatusField, CauseField, ExceptionCode, Cp0Register, MIPS_GPR_ABI_NAMES,
};

// ============================================================================
// ARM32 Register Bank
// ============================================================================

#[test]
fn test_arm_gp_register_aliases() {
    let bank = ArmRegisterBank::new_armv7a();
    // SP, LR, PC are aliases
    assert_eq!(bank.get("SP").unwrap().bit_size, 32);
    assert_eq!(bank.get("LR").unwrap().bit_size, 32);
    assert_eq!(bank.get("PC").unwrap().bit_size, 32);
    // R13 = SP, R14 = LR, R15 = PC
    assert_eq!(bank.get("R13").unwrap().offset, bank.get("SP").unwrap().offset);
    assert_eq!(bank.get("R14").unwrap().offset, bank.get("LR").unwrap().offset);
    assert_eq!(bank.get("R15").unwrap().offset, bank.get("PC").unwrap().offset);
}

#[test]
fn test_arm_banked_sp_per_mode() {
    let bank = ArmRegisterBank::new_armv7a();
    let modes = ["USR", "FIQ", "IRQ", "SVC", "ABT", "UND", "MON", "HYP"];
    for mode in &modes {
        let name = format!("SP_{}", mode);
        let reg = bank.get(&name).expect(&name);
        assert_eq!(reg.bit_size, 32);
    }
    // Each banked SP should have a distinct offset
    let offsets: std::collections::HashSet<u64> = modes.iter()
        .map(|m| bank.get(&format!("SP_{}", m)).unwrap().offset)
        .collect();
    assert_eq!(offsets.len(), modes.len());
}

#[test]
fn test_arm_neon_q_to_d_aliasing() {
    let bank = ArmRegisterBank::new_armv7a();
    for i in 0..16 {
        let q = bank.get(&format!("Q{}", i)).unwrap();
        assert_eq!(q.bit_size, 128);
        assert_eq!(q.parent.as_deref(), Some(format!("D{}", i * 2).as_str()));
    }
}

#[test]
fn test_arm_s_to_d_aliasing_all() {
    let bank = ArmRegisterBank::new_armv7a();
    for i in 0..32 {
        let s = bank.get(&format!("S{}", i)).unwrap();
        let expected_d = i / 2;
        assert_eq!(s.parent.as_deref(), Some(format!("D{}", expected_d).as_str()));
        let expected_lsb = if i % 2 == 0 { 0 } else { 32 };
        assert_eq!(s.lsb, expected_lsb);
    }
}

#[test]
fn test_arm_cpsr_flag_semantics() {
    // NZCV are the condition flags (top 4 bits of CPSR)
    assert_eq!(CpsrFlagBit::N.bit(), 31);
    assert_eq!(CpsrFlagBit::Z.bit(), 30);
    assert_eq!(CpsrFlagBit::C.bit(), 29);
    assert_eq!(CpsrFlagBit::V.bit(), 28);

    // Mode bits are the bottom 5 bits
    assert_eq!(CpsrFlagBit::MODE.bit(), 0);

    // Thumb state bit
    assert_eq!(CpsrFlagBit::T.bit(), 5);
}

#[test]
fn test_arm_processor_mode_encodings() {
    assert_eq!(ProcessorMode::USR.encoding(), 0b10000);
    assert_eq!(ProcessorMode::FIQ.encoding(), 0b10001);
    assert_eq!(ProcessorMode::IRQ.encoding(), 0b10010);
    assert_eq!(ProcessorMode::SVC.encoding(), 0b10011);
    assert_eq!(ProcessorMode::ABT.encoding(), 0b10111);
    assert_eq!(ProcessorMode::UND.encoding(), 0b11011);
    assert_eq!(ProcessorMode::SYS.encoding(), 0b11111);
    assert_eq!(ProcessorMode::HYP.encoding(), 0b11010);
}

#[test]
fn test_arm_mode_banked_suffix() {
    assert_eq!(ProcessorMode::USR.banked_suffix(), "usr");
    assert_eq!(ProcessorMode::FIQ.banked_suffix(), "fiq");
    assert_eq!(ProcessorMode::SVC.banked_suffix(), "svc");
    assert_eq!(ProcessorMode::HYP.banked_suffix(), "hyp");
}

#[test]
fn test_arm_mode_display() {
    assert_eq!(format!("{}", ProcessorMode::USR), "User");
    assert_eq!(format!("{}", ProcessorMode::FIQ), "FIQ");
    assert_eq!(format!("{}", ProcessorMode::SVC), "Supervisor");
    assert_eq!(format!("{}", ProcessorMode::SYS), "System");
}

// ============================================================================
// AArch64 Register Bank
// ============================================================================

#[test]
fn test_aarch64_x_register_count() {
    let bank = Aarch64RegisterBank::new_armv8a();
    // X0-X30 = 31 registers
    for i in 0..=30 {
        let name = format!("X{}", i);
        let reg = bank.get(&name).expect(&name);
        assert_eq!(reg.bit_size, 64);
        assert!(reg.parent.is_none());
    }
}

#[test]
fn test_aarch64_w_to_x_aliasing() {
    let bank = Aarch64RegisterBank::new_armv8a();
    for i in 0..=30 {
        let w = bank.get(&format!("W{}", i)).unwrap();
        assert_eq!(w.bit_size, 32);
        assert_eq!(w.parent.as_deref(), Some(format!("X{}", i).as_str()));
    }
    let wzr = bank.get("WZR").unwrap();
    assert_eq!(wzr.parent.as_deref(), Some("XZR"));
}

#[test]
fn test_aarch64_simd_all_views() {
    let bank = Aarch64RegisterBank::new_armv8a();
    for i in 0..32 {
        let v = bank.get(&format!("V{}", i)).unwrap();
        assert_eq!(v.bit_size, 128);
        assert!(v.parent.is_none()); // V is top-level

        let b = bank.get(&format!("B{}", i)).unwrap();
        assert_eq!(b.bit_size, 8);
        assert_eq!(b.parent.as_deref(), Some(format!("V{}", i).as_str()));

        let h = bank.get(&format!("H{}", i)).unwrap();
        assert_eq!(h.bit_size, 16);
        assert_eq!(h.parent.as_deref(), Some(format!("V{}", i).as_str()));

        let s = bank.get(&format!("S{}", i)).unwrap();
        assert_eq!(s.bit_size, 32);
        assert_eq!(s.parent.as_deref(), Some(format!("V{}", i).as_str()));

        let d = bank.get(&format!("D{}", i)).unwrap();
        assert_eq!(d.bit_size, 64);
        assert_eq!(d.parent.as_deref(), Some(format!("V{}", i).as_str()));

        let q = bank.get(&format!("Q{}", i)).unwrap();
        assert_eq!(q.bit_size, 128);
        assert_eq!(q.parent.as_deref(), Some(format!("V{}", i).as_str()));
    }
}

#[test]
fn test_aarch64_special_registers() {
    let bank = Aarch64RegisterBank::new_armv8a();
    assert_eq!(bank.get("SP").unwrap().bit_size, 64);
    assert_eq!(bank.get("WSP").unwrap().bit_size, 32);
    assert_eq!(bank.get("WSP").unwrap().parent.as_deref(), Some("SP"));
    assert_eq!(bank.get("PC").unwrap().bit_size, 64);
    assert_eq!(bank.get("FP").unwrap().bit_size, 64);
    assert_eq!(bank.get("LR").unwrap().bit_size, 64);
}

#[test]
fn test_aarch64_pstate_flags() {
    // NZCV condition flags
    assert_eq!(PstateField::N.nzcv_bit(), Some(31));
    assert_eq!(PstateField::Z.nzcv_bit(), Some(30));
    assert_eq!(PstateField::C.nzcv_bit(), Some(29));
    assert_eq!(PstateField::V.nzcv_bit(), Some(28));

    // DAIF exception masks
    assert_eq!(PstateField::D.daif_bit(), Some(9));
    assert_eq!(PstateField::A.daif_bit(), Some(8));
    assert_eq!(PstateField::I.daif_bit(), Some(7));
    assert_eq!(PstateField::F.daif_bit(), Some(6));

    // Non-DAIF fields return None
    assert_eq!(PstateField::SS.daif_bit(), None);
    assert_eq!(PstateField::SPSEL.daif_bit(), None);
}

#[test]
fn test_aarch64_pstate_display() {
    assert_eq!(PstateField::N.name(), "N");
    assert_eq!(PstateField::SPSEL.name(), "SPSel");
    assert_eq!(PstateField::NRW.name(), "nRW");
    assert_eq!(PstateField::BTI.name(), "BTI");
}

#[test]
fn test_aarch64_system_registers_present() {
    let bank = Aarch64RegisterBank::new_armv8a();
    let required = [
        "CurrentEL", "SPSel", "DAIF", "TPIDR_EL0", "TPIDR_EL1",
        "TTBR0_EL1", "TTBR1_EL1", "SCTLR_EL1", "VBAR_EL1",
        "ESR_EL1", "FAR_EL1", "ELR_EL1", "SP_EL0", "SP_EL1",
        "SPSR_EL1", "MIDR_EL1", "CPACR_EL1",
    ];
    for name in &required {
        assert!(bank.get(name).is_some(), "Missing system register: {}", name);
    }
}

// ============================================================================
// MIPS Register Bank
// ============================================================================

#[test]
fn test_mips_gpr_numbered_and_dollar() {
    let bank = MipsRegisterBank::new_mips64();
    for i in 0..32 {
        assert!(bank.get(&format!("R{}", i)).is_some(), "Missing R{}", i);
        assert!(bank.get(&format!("${}", i)).is_some(), "Missing ${}", i);
    }
}

#[test]
fn test_mips_abi_name_mapping() {
    let bank = MipsRegisterBank::new_mips64();
    let expected = [
        ("zero", 0), ("at", 1), ("v0", 2), ("v1", 3),
        ("a0", 4), ("a1", 5), ("a2", 6), ("a3", 7),
        ("t0", 8), ("t1", 9), ("t2", 10), ("t3", 11),
        ("t4", 12), ("t5", 13), ("t6", 14), ("t7", 15),
        ("s0", 16), ("s1", 17), ("s2", 18), ("s3", 19),
        ("s4", 20), ("s5", 21), ("s6", 22), ("s7", 23),
        ("t8", 24), ("t9", 25), ("k0", 26), ("k1", 27),
        ("gp", 28), ("sp", 29), ("fp", 30), ("ra", 31),
    ];
    for (abi, idx) in &expected {
        assert_eq!(bank.gpr_index_by_abi(abi), Some(*idx));
        let reg = bank.get(abi).expect(abi);
        assert_eq!(reg.bit_size, 64);
    }
}

#[test]
fn test_mips_special_registers() {
    let bank = MipsRegisterBank::new_mips64();
    assert_eq!(bank.get("HI").unwrap().bit_size, 64);
    assert_eq!(bank.get("LO").unwrap().bit_size, 64);
    assert_eq!(bank.get("PC").unwrap().bit_size, 64);
}

#[test]
fn test_mips_cp0_select_numbers() {
    assert_eq!(Cp0Register::Index.select_number(), 0);
    assert_eq!(Cp0Register::EntryLo0.select_number(), 2);
    assert_eq!(Cp0Register::Status.select_number(), 12);
    assert_eq!(Cp0Register::Cause.select_number(), 13);
    assert_eq!(Cp0Register::EPC.select_number(), 14);
    assert_eq!(Cp0Register::Config.select_number(), 16);
    assert_eq!(Cp0Register::DESAVE.select_number(), 31);
}

#[test]
fn test_mips_status_field_masks() {
    assert_eq!(StatusField::IE.mask(), 1 << 0);
    assert_eq!(StatusField::EXL.mask(), 1 << 1);
    assert_eq!(StatusField::ERL.mask(), 1 << 2);
    assert_eq!(StatusField::BEV.mask(), 1 << 22);
    assert_eq!(StatusField::CU0.mask(), 1 << 28);
    assert_eq!(StatusField::CU1.mask(), 1 << 29);
    assert_eq!(StatusField::CU2.mask(), 1 << 30);
    assert_eq!(StatusField::CU3.mask(), 1u32 << 31);
}

#[test]
fn test_mips_cause_field_semantics() {
    assert_eq!(CauseField::ExcCode.bit(), 2);
    assert_eq!(CauseField::BD.mask(), 1u32 << 31);
    assert_eq!(CauseField::TI.mask(), 1u32 << 30);
    assert_eq!(CauseField::IP0.mask(), 1 << 8);
    assert_eq!(CauseField::IP7.mask(), 1 << 15);
}

#[test]
fn test_mips_exception_codes() {
    assert_eq!(ExceptionCode::Int.code(), 0);
    assert_eq!(ExceptionCode::Mod.code(), 1);
    assert_eq!(ExceptionCode::AdEL.code(), 4);
    assert_eq!(ExceptionCode::Syscall.code(), 8);
    assert_eq!(ExceptionCode::Bp.code(), 9);
    assert_eq!(ExceptionCode::RI.code(), 10);
    assert_eq!(ExceptionCode::CpU.code(), 11);
    assert_eq!(ExceptionCode::Ov.code(), 12);
    assert_eq!(ExceptionCode::FPE.code(), 15);
}

#[test]
fn test_mips_variant_properties() {
    // 32-bit variants
    assert!(!MipsVariant::Mips32.is_64bit());
    assert!(!MipsVariant::Mips32R2.is_64bit());

    // 64-bit variants
    assert!(MipsVariant::Mips64.is_64bit());
    assert!(MipsVariant::Mips64R2.is_64bit());
    assert!(MipsVariant::Mips64R6.is_64bit());
    assert!(MipsVariant::MipsIII.is_64bit());
    assert!(MipsVariant::MipsIV.is_64bit());

    // MSA support
    assert!(MipsVariant::Mips64R5.has_msa());
    assert!(MipsVariant::Mips64R6.has_msa());
    assert!(!MipsVariant::Mips32.has_msa());
    assert!(!MipsVariant::Mips64.has_msa());

    // DSP support
    assert!(MipsVariant::Mips32R2.has_dsp());
    assert!(MipsVariant::Mips64R2.has_dsp());
    assert!(!MipsVariant::Mips32.has_dsp());
    assert!(!MipsVariant::Mips64R6.has_dsp());

    // VZ support
    assert!(MipsVariant::Mips64R5.has_vz());
    assert!(MipsVariant::Mips64R6.has_vz());
    assert!(!MipsVariant::Mips64R2.has_vz());
}

#[test]
fn test_mips_variant_display() {
    assert_eq!(format!("{}", MipsVariant::Mips32), "MIPS32");
    assert_eq!(format!("{}", MipsVariant::Mips64R6), "MIPS64 R6");
    assert_eq!(format!("{}", MipsVariant::MicroMips), "microMIPS");
}

#[test]
fn test_mips_mnemonic_categories() {
    // Arithmetic / Logical
    assert!(matches!(MipsMnemonic::ADD.category(), MipsInstructionCategory::ArithmeticLogical));
    assert!(matches!(MipsMnemonic::ANDI.category(), MipsInstructionCategory::ArithmeticLogical));
    assert!(matches!(MipsMnemonic::LUI.category(), MipsInstructionCategory::ArithmeticLogical));
    assert!(matches!(MipsMnemonic::SLL.category(), MipsInstructionCategory::ArithmeticLogical));
    assert!(matches!(MipsMnemonic::DSUB.category(), MipsInstructionCategory::ArithmeticLogical));

    // Branch
    assert!(matches!(MipsMnemonic::BEQ.category(), MipsInstructionCategory::Branch));
    assert!(matches!(MipsMnemonic::JAL.category(), MipsInstructionCategory::Branch));
    assert!(matches!(MipsMnemonic::JR.category(), MipsInstructionCategory::Branch));
    assert!(matches!(MipsMnemonic::BALC.category(), MipsInstructionCategory::Branch));

    // Load/Store
    assert!(matches!(MipsMnemonic::LW.category(), MipsInstructionCategory::LoadStore));
    assert!(matches!(MipsMnemonic::SW.category(), MipsInstructionCategory::LoadStore));
    assert!(matches!(MipsMnemonic::LD.category(), MipsInstructionCategory::LoadStore));
    assert!(matches!(MipsMnemonic::LDC1.category(), MipsInstructionCategory::LoadStore));

    // Trap
    assert!(matches!(MipsMnemonic::TEQ.category(), MipsInstructionCategory::Trap));
    assert!(matches!(MipsMnemonic::TGE.category(), MipsInstructionCategory::Trap));

    // System
    assert!(matches!(MipsMnemonic::SYSCALL.category(), MipsInstructionCategory::System));
    assert!(matches!(MipsMnemonic::BREAK.category(), MipsInstructionCategory::System));
    assert!(matches!(MipsMnemonic::ERET.category(), MipsInstructionCategory::System));
    assert!(matches!(MipsMnemonic::NOP.category(), MipsInstructionCategory::System));
    assert!(matches!(MipsMnemonic::TLBWI.category(), MipsInstructionCategory::System));

    // FPU
    assert!(matches!(MipsMnemonic::ADD_S.category(), MipsInstructionCategory::Fpu));
    assert!(matches!(MipsMnemonic::MOV_D.category(), MipsInstructionCategory::Fpu));
    assert!(matches!(MipsMnemonic::CVT_S_W.category(), MipsInstructionCategory::Fpu));

    // SIMD (MSA)
    assert!(matches!(MipsMnemonic::ADDV_B.category(), MipsInstructionCategory::Simd));
    assert!(matches!(MipsMnemonic::LD_B.category(), MipsInstructionCategory::Simd));

    // DSP
    assert!(matches!(MipsMnemonic::ABSQ_S_PH.category(), MipsInstructionCategory::Dsp));

    // Virtualization
    assert!(matches!(MipsMnemonic::HYPCALL.category(), MipsInstructionCategory::Virtualization));
}

#[test]
fn test_mips_mnemonic_display_names() {
    assert_eq!(MipsMnemonic::ADD.as_str(), "ADD");
    assert_eq!(MipsMnemonic::ADD_S.as_str(), "ADD.S");
    assert_eq!(MipsMnemonic::LW.as_str(), "LW");
    assert_eq!(MipsMnemonic::JR_HB.as_str(), "JR.HB");
    assert_eq!(MipsMnemonic::SYSCALL.as_str(), "SYSCALL");
    assert_eq!(MipsMnemonic::LD_B.as_str(), "LD.B");
}

#[test]
fn test_mips_register_sizes() {
    let bank = MipsRegisterBank::new_mips64();
    // GPR: 64-bit
    assert_eq!(bank.get("R0").unwrap().bit_size, 64);
    assert_eq!(bank.get("R31").unwrap().bit_size, 64);
    // FPU: 64-bit
    assert_eq!(bank.get("F0").unwrap().bit_size, 64);
    // MSA: 128-bit
    assert_eq!(bank.get("W0").unwrap().bit_size, 128);
    // FPU control: 32-bit
    assert_eq!(bank.get("FCSR").unwrap().bit_size, 32);
    // CP0: 64-bit
    assert_eq!(bank.get("Status").unwrap().bit_size, 64);
}

// ============================================================================
// Cross-architecture comparison tests
// ============================================================================

#[test]
fn test_all_architectures_have_pc() {
    let arm = ArmRegisterBank::new_armv7a();
    let aarch64 = Aarch64RegisterBank::new_armv8a();
    let mips = MipsRegisterBank::new_mips64();

    assert!(arm.get("PC").is_some());
    assert!(aarch64.get("PC").is_some());
    assert!(mips.get("PC").is_some());
}

#[test]
fn test_all_architectures_have_sp() {
    let arm = ArmRegisterBank::new_armv7a();
    let aarch64 = Aarch64RegisterBank::new_armv8a();
    let mips = MipsRegisterBank::new_mips64();

    assert!(arm.get("SP").is_some());
    assert!(aarch64.get("SP").is_some());
    assert!(mips.get("sp").is_some());
}

#[test]
fn test_register_bank_nonempty_counts() {
    let arm = ArmRegisterBank::new_armv7a();
    let aarch64 = Aarch64RegisterBank::new_armv8a();
    let mips = MipsRegisterBank::new_mips64();

    // ARM: >50 (13 GP + banked SP/LR + VFP/NEON + CPSR/SPSR)
    assert!(arm.len() > 50, "ARM registers: {}", arm.len());
    // AArch64: >100 (31 X + 31 W + 32x6 SIMD views + system regs)
    assert!(aarch64.len() > 100, "AArch64 registers: {}", aarch64.len());
    // MIPS: >100 (32 GPR + CP0 + FPU + MSA + DSP)
    assert!(mips.len() > 100, "MIPS registers: {}", mips.len());
}
