//! Tests for x86 register definitions and instruction mnemonic enum values.
//!
//! Covers the `ghidra_processors::x86` module:
//! - Register bank creation and lookup
//! - Sub-register aliasing (RAX -> EAX -> AX -> AL/AH)
//! - Flag bit definitions and masks
//! - XMM/YMM/ZMM register aliasing chain
//! - Instruction mnemonic classification and categories

use ghidra_processors::x86::{
    registers::{FlagBit, Register, X86RegisterBank},
    instructions::{
        ConditionCode, DecodedInstruction, EVEX, InstructionCategory, MemoryOperand,
        ModRM, Operand, PrefixInfo, REX, SIB, SegmentRegister, VEX, X86Mnemonic,
    },
};

// ---------------------------------------------------------------------------
// Register tests
// ---------------------------------------------------------------------------

#[test]
fn test_register_creation() {
    let reg = Register::new("RAX", 64, 0x0000);
    assert_eq!(reg.name, "RAX");
    assert_eq!(reg.bit_size, 64);
    assert_eq!(reg.offset, 0);
    assert_eq!(reg.byte_size(), 8);
    assert!(reg.parent.is_none());
    assert_eq!(reg.lsb, 0);
}

#[test]
fn test_sub_register_creation() {
    let eax = Register::sub_register("EAX", 32, 0x0000, "RAX", 0);
    assert_eq!(eax.name, "EAX");
    assert_eq!(eax.bit_size, 32);
    assert_eq!(eax.byte_size(), 4);
    assert_eq!(eax.parent.as_deref(), Some("RAX"));
    assert_eq!(eax.lsb, 0);
}

#[test]
fn test_register_bank_creation() {
    let bank = X86RegisterBank::new_x86_64();
    assert!(bank.len() > 100, "Expected >100 register definitions, got {}", bank.len());
    assert!(!bank.is_empty());
}

#[test]
fn test_general_purpose_registers() {
    let bank = X86RegisterBank::new_x86_64();

    for reg_name in &["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"] {
        let reg = bank.get(reg_name).expect(reg_name);
        assert_eq!(reg.bit_size, 64, "{} should be 64-bit", reg_name);
        assert!(reg.parent.is_none(), "{} should be a top-level register", reg_name);
    }

    for reg_name in &["R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"] {
        assert!(bank.get(reg_name).is_some(), "Missing register {}", reg_name);
    }
}

#[test]
fn test_sub_register_aliasing_rax() {
    let bank = X86RegisterBank::new_x86_64();

    let rax = bank.get("RAX").unwrap();
    assert_eq!(rax.bit_size, 64);

    let eax = bank.get("EAX").unwrap();
    assert_eq!(eax.parent.as_deref(), Some("RAX"));
    assert_eq!(eax.bit_size, 32);
    assert_eq!(eax.lsb, 0);

    let ax = bank.get("AX").unwrap();
    assert_eq!(ax.parent.as_deref(), Some("RAX"));
    assert_eq!(ax.bit_size, 16);

    let al = bank.get("AL").unwrap();
    assert_eq!(al.parent.as_deref(), Some("RAX"));
    assert_eq!(al.bit_size, 8);
    assert_eq!(al.lsb, 0);

    let ah = bank.get("AH").unwrap();
    assert_eq!(ah.parent.as_deref(), Some("RAX"));
    assert_eq!(ah.bit_size, 8);
    assert_eq!(ah.lsb, 8);
}

#[test]
fn test_sub_registers_of() {
    let bank = X86RegisterBank::new_x86_64();
    let subs = bank.sub_registers_of("RAX");

    let sub_names: Vec<&str> = subs.iter().map(|r| r.name.as_str()).collect();
    assert!(sub_names.contains(&"EAX"));
    assert!(sub_names.contains(&"AX"));
    assert!(sub_names.contains(&"AL"));
    assert!(sub_names.contains(&"AH"));
}

#[test]
fn test_top_level_registers() {
    let bank = X86RegisterBank::new_x86_64();
    let tops = bank.top_level_registers();

    // All top-level registers should have no parent
    for reg in &tops {
        assert!(reg.parent.is_none(), "{} should not have a parent", reg.name);
    }

    // RAX, RCX, etc. and segments, control regs are top-level
    let top_names: Vec<&str> = tops.iter().map(|r| r.name.as_str()).collect();
    assert!(top_names.contains(&"RAX"));
    assert!(top_names.contains(&"R15"));
    assert!(top_names.contains(&"CR0"));
    assert!(top_names.contains(&"DR0"));
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
fn test_control_registers() {
    let bank = X86RegisterBank::new_x86_64();
    for cr in &["CR0", "CR2", "CR3", "CR4", "CR8"] {
        assert!(bank.get(cr).is_some(), "Missing control register {}", cr);
    }
}

#[test]
fn test_debug_registers() {
    let bank = X86RegisterBank::new_x86_64();
    for dr in &["DR0", "DR1", "DR2", "DR3", "DR6", "DR7"] {
        assert!(bank.get(dr).is_some(), "Missing debug register {}", dr);
    }
}

#[test]
fn test_xmm_ymm_zmm_chain() {
    let bank = X86RegisterBank::new_x86_64();

    let xmm0 = bank.get("XMM0").unwrap();
    assert_eq!(xmm0.bit_size, 128);
    assert!(xmm0.parent.is_none());

    let ymm0 = bank.get("YMM0").unwrap();
    assert_eq!(ymm0.bit_size, 256);
    assert_eq!(ymm0.parent.as_deref(), Some("XMM0"));

    let zmm0 = bank.get("ZMM0").unwrap();
    assert_eq!(zmm0.bit_size, 512);
    assert_eq!(zmm0.parent.as_deref(), Some("YMM0"));
}

#[test]
fn test_floating_point_registers() {
    let bank = X86RegisterBank::new_x86_64();
    for i in 0..8 {
        assert!(bank.get(&format!("ST{}", i)).is_some());
        assert!(bank.get(&format!("MM{}", i)).is_some());
    }
}

#[test]
fn test_special_registers() {
    let bank = X86RegisterBank::new_x86_64();
    assert!(bank.get("EFLAGS").is_some());
    assert!(bank.get("RFLAGS").is_some());
    assert!(bank.get("RIP").is_some());
    assert!(bank.get("EIP").is_some());
    assert!(bank.get("IP").is_some());
    assert!(bank.get("MXCSR").is_some());
    assert!(bank.get("XCR0").is_some());
}

#[test]
fn test_iter_registers() {
    let bank = X86RegisterBank::new_x86_64();
    let all: Vec<&Register> = bank.iter().collect();
    assert!(!all.is_empty());
    assert_eq!(all.len(), bank.len());
}

// ---------------------------------------------------------------------------
// Flag bit tests
// ---------------------------------------------------------------------------

#[test]
fn test_flag_bit_masks() {
    assert_eq!(FlagBit::CF.mask(), 1 << 0);
    assert_eq!(FlagBit::PF.mask(), 1 << 2);
    assert_eq!(FlagBit::AF.mask(), 1 << 4);
    assert_eq!(FlagBit::ZF.mask(), 1 << 6);
    assert_eq!(FlagBit::SF.mask(), 1 << 7);
    assert_eq!(FlagBit::TF.mask(), 1 << 8);
    assert_eq!(FlagBit::IF.mask(), 1 << 9);
    assert_eq!(FlagBit::DF.mask(), 1 << 10);
    assert_eq!(FlagBit::OF.mask(), 1 << 11);
    assert_eq!(FlagBit::ID.mask(), 1 << 21);
}

#[test]
fn test_flag_bit_positions() {
    assert_eq!(FlagBit::CF.bit(), 0);
    assert_eq!(FlagBit::ZF.bit(), 6);
    assert_eq!(FlagBit::OF.bit(), 11);
    assert_eq!(FlagBit::ID.bit(), 21);
}

#[test]
fn test_flag_bit_names() {
    assert_eq!(FlagBit::CF.name(), "CF");
    assert_eq!(FlagBit::ZF.name(), "ZF");
    assert_eq!(FlagBit::SF.name(), "SF");
    assert_eq!(FlagBit::OF.name(), "OF");
    assert_eq!(FlagBit::IF.name(), "IF");
    assert_eq!(FlagBit::DF.name(), "DF");
    assert_eq!(FlagBit::AC.name(), "AC");
    assert_eq!(FlagBit::ID.name(), "ID");
}

// ---------------------------------------------------------------------------
// Instruction mnemonic tests
// ---------------------------------------------------------------------------

#[test]
fn test_mnemonic_base_instructions() {
    // Data movement
    assert_eq!(X86Mnemonic::MOV.category(), InstructionCategory::DataMovement);
    assert_eq!(X86Mnemonic::PUSH.category(), InstructionCategory::DataMovement);
    assert_eq!(X86Mnemonic::POP.category(), InstructionCategory::DataMovement);

    // Arithmetic
    assert_eq!(X86Mnemonic::ADD.category(), InstructionCategory::Arithmetic);
    assert_eq!(X86Mnemonic::SUB.category(), InstructionCategory::Arithmetic);
    assert_eq!(X86Mnemonic::IMUL.category(), InstructionCategory::Arithmetic);

    // Control flow
    assert_eq!(X86Mnemonic::JMP.category(), InstructionCategory::ControlFlow);
    assert_eq!(X86Mnemonic::CALL.category(), InstructionCategory::ControlFlow);
    assert_eq!(X86Mnemonic::RET.category(), InstructionCategory::ControlFlow);

    // Logical
    assert_eq!(X86Mnemonic::AND.category(), InstructionCategory::Logical);
    assert_eq!(X86Mnemonic::OR.category(), InstructionCategory::Logical);
    assert_eq!(X86Mnemonic::XOR.category(), InstructionCategory::Logical);
}

#[test]
fn test_mnemonic_fpu_instructions() {
    assert_eq!(X86Mnemonic::FADD.category(), InstructionCategory::X87);
    assert_eq!(X86Mnemonic::FMUL.category(), InstructionCategory::X87);
    assert_eq!(X86Mnemonic::FLD.category(), InstructionCategory::X87);
}

#[test]
fn test_mnemonic_sse_instructions() {
    assert_eq!(X86Mnemonic::ADDPS.category(), InstructionCategory::SSE);
    assert_eq!(X86Mnemonic::MOVAPS.category(), InstructionCategory::SSE);
}

#[test]
fn test_mnemonic_avx_instructions() {
    assert_eq!(X86Mnemonic::VADDPS.category(), InstructionCategory::AVX);
    assert_eq!(X86Mnemonic::VMOVAPS.category(), InstructionCategory::AVX);
}

#[test]
fn test_mnemonic_fma_instructions() {
    assert_eq!(X86Mnemonic::VFMADD132PS.category(), InstructionCategory::FMA);
}

#[test]
fn test_mnemonic_system_instructions() {
    assert_eq!(X86Mnemonic::SYSCALL.category(), InstructionCategory::System);
    assert_eq!(X86Mnemonic::CPUID.category(), InstructionCategory::System);
}

#[test]
fn test_mnemonic_virtualization() {
    assert_eq!(X86Mnemonic::VMXON.category(), InstructionCategory::Virtualization);
    assert_eq!(X86Mnemonic::VMRUN.category(), InstructionCategory::Virtualization);
}

#[test]
fn test_mnemonic_crypto() {
    assert_eq!(X86Mnemonic::AESENC.category(), InstructionCategory::Crypto);
    assert_eq!(X86Mnemonic::SHA1RNDS4.category(), InstructionCategory::Crypto);
}

#[test]
fn test_mnemonic_security() {
    assert_eq!(X86Mnemonic::ENCLS.category(), InstructionCategory::Security);
    assert_eq!(X86Mnemonic::ENDBR64.category(), InstructionCategory::Security);
}

#[test]
fn test_mnemonic_transactional() {
    assert_eq!(X86Mnemonic::XBEGIN.category(), InstructionCategory::Transactional);
    assert_eq!(X86Mnemonic::XEND.category(), InstructionCategory::Transactional);
}

#[test]
fn test_mnemonic_conditional_branches() {
    // Jcc and SETcc with condition codes
    let jnz = X86Mnemonic::Jcc(ConditionCode::NZ);
    assert_eq!(jnz.category(), InstructionCategory::ControlFlow);

    let jle = X86Mnemonic::Jcc(ConditionCode::LE);
    assert_eq!(jle.category(), InstructionCategory::ControlFlow);

    let setz = X86Mnemonic::SETcc(ConditionCode::Z);
    assert_eq!(setz.category(), InstructionCategory::Conditional);
}

#[test]
fn test_mnemonic_string_instructions() {
    assert_eq!(X86Mnemonic::MOVS.category(), InstructionCategory::String);
    assert_eq!(X86Mnemonic::SCASB.category(), InstructionCategory::String);
    assert_eq!(X86Mnemonic::REP.category(), InstructionCategory::String);
}

// ---------------------------------------------------------------------------
// Condition code tests
// ---------------------------------------------------------------------------

#[test]
fn test_condition_code_names() {
    let conditions = [
        (ConditionCode::O, "O"),
        (ConditionCode::NO, "NO"),
        (ConditionCode::E, "E"),
        (ConditionCode::NE, "NE"),
        (ConditionCode::L, "L"),
        (ConditionCode::GE, "GE"),
    ];

    for (cc, name) in &conditions {
        assert_eq!(cc.name(), *name);
    }
}

#[test]
fn test_condition_code_aliases() {
    // B, C, NAE are aliases
    assert_eq!(ConditionCode::B.name(), ConditionCode::C.name());
    assert_eq!(ConditionCode::B.name(), ConditionCode::NAE.name());

    // E and Z are aliases
    assert_eq!(ConditionCode::E.name(), ConditionCode::Z.name());
}

// ---------------------------------------------------------------------------
// ModR/M tests
// ---------------------------------------------------------------------------

#[test]
fn test_modrm_register_mode() {
    // mod=11, reg=000, rm=000 => 0b11000000 = 0xC0
    let m = ModRM::new(0xC0);
    assert_eq!(m.mod_bits(), 0b11);
    assert_eq!(m.reg(), 0);
    assert_eq!(m.rm(), 0);
    assert!(m.is_register());
    assert!(!m.has_sib());
    assert_eq!(m.displacement_size(), 0);
}

#[test]
fn test_modrm_sib_required() {
    // mod=00, reg=100, rm=100 => [--][--] with SIB
    let m = ModRM::new(0x24);
    assert_eq!(m.mod_bits(), 0);
    assert_eq!(m.reg(), 4);
    assert_eq!(m.rm(), 4);
    assert!(m.has_sib());
}

#[test]
fn test_modrm_disp8() {
    // mod=01, reg=010, rm=101 => [EBP + disp8]
    let m = ModRM::new(0x55);
    assert_eq!(m.displacement_size(), 1);
}

#[test]
fn test_modrm_disp32() {
    // mod=10, reg=000, rm=001 => [ECX + disp32]
    let m = ModRM::new(0x81);
    assert_eq!(m.displacement_size(), 4);
}

#[test]
fn test_modrm_from_u8() {
    let m: ModRM = 0xC0.into();
    assert_eq!(m.mod_bits(), 3);
    assert_eq!(m.reg(), 0);
    assert_eq!(m.rm(), 0);
}

// ---------------------------------------------------------------------------
// SIB tests
// ---------------------------------------------------------------------------

#[test]
fn test_sib_fields() {
    // scale=10 (4x), index=100 (none), base=101 (EBP)
    let s = SIB::new(0x95);
    assert_eq!(s.scale(), 2);
    assert_eq!(s.scale_multiplier(), 4);
    assert_eq!(s.index(), 4);
    assert!(s.no_index());
    assert_eq!(s.base(), 5);
}

#[test]
fn test_sib_scale_values() {
    for scale in 0..=3u8 {
        let raw = scale << 6;
        let s = SIB::new(raw);
        assert_eq!(s.scale(), scale);
        assert_eq!(s.scale_multiplier(), 1 << scale);
    }
}

// ---------------------------------------------------------------------------
// REX tests
// ---------------------------------------------------------------------------

#[test]
fn test_rex_flags() {
    let rex_w = REX::new(0x48); // REX.W
    assert!(rex_w.w());
    assert!(!rex_w.r());
    assert!(!rex_w.x());
    assert!(!rex_w.b());

    let rex_r = REX::new(0x44); // REX.R
    assert!(!rex_r.w());
    assert!(rex_r.r());
    assert!(!rex_r.x());
    assert!(!rex_r.b());
}

#[test]
fn test_rex_is_rex() {
    assert!(REX::is_rex(0x40));
    assert!(REX::is_rex(0x4F));
    assert!(!REX::is_rex(0x50));
    assert!(!REX::is_rex(0x3F));
}

// ---------------------------------------------------------------------------
// Memory operand tests
// ---------------------------------------------------------------------------

#[test]
fn test_memory_operand_indirect() {
    let m = MemoryOperand::indirect("RAX", 8);
    assert_eq!(m.base.as_deref(), Some("RAX"));
    assert_eq!(m.index, None);
    assert_eq!(m.scale, 1);
    assert_eq!(m.displacement, 0);
    assert_eq!(m.size, 8);
    assert_eq!(m.segment, None);
}

#[test]
fn test_memory_operand_full() {
    let m = MemoryOperand::full(
        Some("FS"),
        Some("RAX"),
        Some("RSI"),
        4,
        0x10,
        8,
    );

    assert_eq!(m.base.as_deref(), Some("RAX"));
    assert_eq!(m.index.as_deref(), Some("RSI"));
    assert_eq!(m.scale, 4);
    assert_eq!(m.displacement, 0x10);
    assert_eq!(m.segment.as_deref(), Some("FS"));
    assert_eq!(m.size, 8);
}

#[test]
fn test_memory_operand_display() {
    let m = MemoryOperand::full(
        Some("FS"),
        Some("RAX"),
        Some("RSI"),
        4,
        0x10,
        8,
    );
    assert_eq!(m.display(), "FS:[RAX+RSI*4+0x10]");
}

#[test]
fn test_memory_operand_base_disp() {
    let m = MemoryOperand::base_disp("RBP", -8, 8);
    assert_eq!(m.base.as_deref(), Some("RBP"));
    assert_eq!(m.displacement, -8);
    assert!(m.display().contains("RBP"));
    assert!(m.display().contains("-0x8") || m.display().contains("8"));
}

// ---------------------------------------------------------------------------
// Condition codes - more tests
// ---------------------------------------------------------------------------

#[test]
fn test_condition_code_arithmetic_semantics() {
    // Verify standard x86 condition groupings
    // Unsigned comparison (after SUB/CMP)
    let unsigned_below = [ConditionCode::B, ConditionCode::C, ConditionCode::NAE];
    for cc in &unsigned_below {
        // All should have the same primary name
        assert!(cc.name() == "B", "Expected B, got {}", cc.name());
    }

    // Signed comparison (after SUB/CMP)
    let signed_less = [ConditionCode::L, ConditionCode::NGE];
    for cc in &signed_less {
        assert!(cc.name() == "L", "Expected L, got {}", cc.name());
    }

    // Equality
    let equal = [ConditionCode::E, ConditionCode::Z];
    for cc in &equal {
        assert!(cc.name() == "E", "Expected E, got {}", cc.name());
    }
}
