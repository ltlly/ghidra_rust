//! Dalvik Virtual Machine Processor Module
//!
//! Supports the Dalvik VM used in Android (DEX format).
//!
//! ## Architecture overview
//! - Register-based VM (not stack-based like JVM)
//! - Up to 65536 virtual registers (v0-v65535)
//! - 32-bit register width (64-bit values occupy register pairs)
//! - 32-bit program counter
//! - Special registers: sp (stack pointer), fp (frame pointer), resultreg
//! - 64-bit wide result register (resultregw)
//! - Little-endian byte order
//!
//! ## Register space layout
//! - Special registers:           0x00-0x0B  (sp, fp, resultreg)
//! - Wide result register:        0x08-0x0F  (64-bit)
//! - Input registers (v0-v15):   0x100-0x13C  (32-bit each)
//! - Wide input registers:        0x100-0x13C  (64-bit pairs)
//! - Virtual registers (v0-vN):  0x1000+  (32-bit each)

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

/// Dalvik VM processor struct.
pub struct DalvikProcessor;

/// Build the complete Dalvik register bank.
fn build_registers() -> RegisterBank {
    let mut bank = RegisterBank::new();

    // ---- Special registers ----
    bank.add(Register::new("sp", 32, 0x0000)
        .with_type(crate::common::RegisterType::SP)
        .with_description("Stack pointer")
        .with_group("Special"));
    bank.add(Register::new("fp", 32, 0x0004)
        .with_type(crate::common::RegisterType::FP)
        .with_description("Frame pointer")
        .with_group("Special"));
    bank.add(Register::new("resultreg", 32, 0x0008)
        .with_description("Return value register (32-bit)")
        .with_group("Special"));
    bank.add(Register::new("resultregw", 64, 0x0008)
        .with_description("Return value register (64-bit wide)")
        .with_group("Special"));

    // ---- Input parameter registers (v0-v5) ----
    for i in 0..6u64 {
        let name = format!("v{}", i);
        bank.add(Register::new(&name, 32, 0x100 + i * 4)
            .with_description(format!("Parameter/variable register v{}", i))
            .with_group("Virtual Registers"));
    }

    // ---- Wide input register pairs ----
    for i in (0..6).step_by(2) {
        let name = format!("v{}_w", i);
        bank.add(Register::new(&name, 64, 0x100 + i * 4)
            .with_description(format!("Wide register pair v{}:v{}", i, i + 1))
            .with_group("Wide Registers"));
    }

    bank
}

/// Build the Dalvik instruction mnemonics.
fn build_instructions() -> Vec<InstructionMnemonic> {
    vec![
        // === Move ===
        InstructionMnemonic::new("move"),           // Move register
        InstructionMnemonic::new("move_from16"),    // Move register (from16)
        InstructionMnemonic::new("move_16"),        // Move register (16-bit)
        InstructionMnemonic::new("move_wide"),      // Move wide register
        InstructionMnemonic::new("move_object"),    // Move object register
        InstructionMnemonic::new("move_result"),    // Move result
        InstructionMnemonic::new("move_result_wide"), // Move wide result
        InstructionMnemonic::new("move_result_object"), // Move object result
        InstructionMnemonic::new("move_exception"), // Move exception
        // === Return ===
        InstructionMnemonic::new("return_void"),    // Return void
        InstructionMnemonic::new("return"),         // Return
        InstructionMnemonic::new("return_wide"),    // Return wide
        InstructionMnemonic::new("return_object"),  // Return object
        // === Const ===
        InstructionMnemonic::new("const_4"),        // Const 4-bit
        InstructionMnemonic::new("const_16"),       // Const 16-bit
        InstructionMnemonic::new("const"),          // Const 32-bit
        InstructionMnemonic::new("const_high16"),   // Const high 16-bit
        InstructionMnemonic::new("const_wide_16"),  // Const wide 16-bit
        InstructionMnemonic::new("const_wide_32"),  // Const wide 32-bit
        InstructionMnemonic::new("const_wide"),     // Const wide 64-bit
        InstructionMnemonic::new("const_string"),   // Const string
        InstructionMnemonic::new("const_class"),    // Const class
        // === Monitor ===
        InstructionMnemonic::new("monitor_enter"),  // Monitor enter
        InstructionMnemonic::new("monitor_exit"),   // Monitor exit
        // === Check cast ===
        InstructionMnemonic::new("check_cast"),     // Check cast
        InstructionMnemonic::new("instance_of"),    // Instance of
        // === Array ===
        InstructionMnemonic::new("new_array"),      // New array
        InstructionMnemonic::new("filled_new_array"), // Filled new array
        InstructionMnemonic::new("array_length"),   // Array length
        InstructionMnemonic::new("aget"),           // Array get
        InstructionMnemonic::new("aget_wide"),      // Array get wide
        InstructionMnemonic::new("aget_object"),    // Array get object
        InstructionMnemonic::new("aget_boolean"),   // Array get boolean
        InstructionMnemonic::new("aget_byte"),      // Array get byte
        InstructionMnemonic::new("aget_char"),      // Array get char
        InstructionMnemonic::new("aget_short"),     // Array get short
        InstructionMnemonic::new("aput"),           // Array put
        InstructionMnemonic::new("aput_wide"),      // Array put wide
        InstructionMnemonic::new("aput_object"),    // Array put object
        InstructionMnemonic::new("aput_boolean"),   // Array put boolean
        InstructionMnemonic::new("aput_byte"),      // Array put byte
        InstructionMnemonic::new("aput_char"),      // Array put char
        InstructionMnemonic::new("aput_short"),     // Array put short
        // === Instance ===
        InstructionMnemonic::new("iget"),           // Instance get
        InstructionMnemonic::new("iget_wide"),      // Instance get wide
        InstructionMnemonic::new("iget_object"),    // Instance get object
        InstructionMnemonic::new("iget_boolean"),   // Instance get boolean
        InstructionMnemonic::new("iget_byte"),      // Instance get byte
        InstructionMnemonic::new("iget_char"),      // Instance get char
        InstructionMnemonic::new("iget_short"),     // Instance get short
        InstructionMnemonic::new("iput"),           // Instance put
        InstructionMnemonic::new("iput_wide"),      // Instance put wide
        InstructionMnemonic::new("iput_object"),    // Instance put object
        InstructionMnemonic::new("iput_boolean"),   // Instance put boolean
        InstructionMnemonic::new("iput_byte"),      // Instance put byte
        InstructionMnemonic::new("iput_char"),      // Instance put char
        InstructionMnemonic::new("iput_short"),     // Instance put short
        // === Static ===
        InstructionMnemonic::new("sget"),           // Static get
        InstructionMnemonic::new("sget_wide"),      // Static get wide
        InstructionMnemonic::new("sget_object"),    // Static get object
        InstructionMnemonic::new("sget_boolean"),   // Static get boolean
        InstructionMnemonic::new("sget_byte"),      // Static get byte
        InstructionMnemonic::new("sget_char"),      // Static get char
        InstructionMnemonic::new("sget_short"),     // Static get short
        InstructionMnemonic::new("sput"),           // Static put
        InstructionMnemonic::new("sput_wide"),      // Static put wide
        InstructionMnemonic::new("sput_object"),    // Static put object
        InstructionMnemonic::new("sput_boolean"),   // Static put boolean
        InstructionMnemonic::new("sput_byte"),      // Static put byte
        InstructionMnemonic::new("sput_char"),      // Static put char
        InstructionMnemonic::new("sput_short"),     // Static put short
        // === Arithmetic ===
        InstructionMnemonic::new("neg_int"),        // Negate int
        InstructionMnemonic::new("neg_long"),       // Negate long
        InstructionMnemonic::new("neg_float"),      // Negate float
        InstructionMnemonic::new("neg_double"),     // Negate double
        InstructionMnemonic::new("not_int"),        // Bitwise NOT int
        InstructionMnemonic::new("not_long"),       // Bitwise NOT long
        InstructionMnemonic::new("add_int"),        // Add int
        InstructionMnemonic::new("sub_int"),        // Subtract int
        InstructionMnemonic::new("mul_int"),        // Multiply int
        InstructionMnemonic::new("div_int"),        // Divide int
        InstructionMnemonic::new("rem_int"),        // Remainder int
        InstructionMnemonic::new("and_int"),        // AND int
        InstructionMnemonic::new("or_int"),         // OR int
        InstructionMnemonic::new("xor_int"),        // XOR int
        InstructionMnemonic::new("shl_int"),        // Shift left int
        InstructionMnemonic::new("shr_int"),        // Shift right int
        InstructionMnemonic::new("ushr_int"),       // Unsigned shift right int
        InstructionMnemonic::new("add_long"),       // Add long
        InstructionMnemonic::new("sub_long"),       // Subtract long
        InstructionMnemonic::new("mul_long"),       // Multiply long
        InstructionMnemonic::new("div_long"),       // Divide long
        InstructionMnemonic::new("rem_long"),       // Remainder long
        InstructionMnemonic::new("and_long"),       // AND long
        InstructionMnemonic::new("or_long"),        // OR long
        InstructionMnemonic::new("xor_long"),       // XOR long
        InstructionMnemonic::new("shl_long"),       // Shift left long
        InstructionMnemonic::new("shr_long"),       // Shift right long
        InstructionMnemonic::new("ushr_long"),      // Unsigned shift right long
        InstructionMnemonic::new("add_float"),      // Add float
        InstructionMnemonic::new("sub_float"),      // Subtract float
        InstructionMnemonic::new("mul_float"),      // Multiply float
        InstructionMnemonic::new("div_float"),      // Divide float
        InstructionMnemonic::new("rem_float"),      // Remainder float
        InstructionMnemonic::new("add_double"),     // Add double
        InstructionMnemonic::new("sub_double"),     // Subtract double
        InstructionMnemonic::new("mul_double"),     // Multiply double
        InstructionMnemonic::new("div_double"),     // Divide double
        InstructionMnemonic::new("rem_double"),     // Remainder double
        // === Compare ===
        InstructionMnemonic::new("cmpl_float"),     // Compare less float
        InstructionMnemonic::new("cmpg_float"),     // Compare greater float
        InstructionMnemonic::new("cmpl_double"),    // Compare less double
        InstructionMnemonic::new("cmpg_double"),    // Compare greater double
        InstructionMnemonic::new("cmp_long"),       // Compare long
        // === Branch ===
        InstructionMnemonic::new("if_eq"),          // If equal
        InstructionMnemonic::new("if_ne"),          // If not equal
        InstructionMnemonic::new("if_lt"),          // If less than
        InstructionMnemonic::new("if_ge"),          // If greater or equal
        InstructionMnemonic::new("if_gt"),          // If greater than
        InstructionMnemonic::new("if_le"),          // If less or equal
        InstructionMnemonic::new("if_eqz"),         // If equal to zero
        InstructionMnemonic::new("if_nez"),         // If not equal to zero
        InstructionMnemonic::new("if_ltz"),         // If less than zero
        InstructionMnemonic::new("if_gez"),         // If greater or equal to zero
        InstructionMnemonic::new("if_gtz"),         // If greater than zero
        InstructionMnemonic::new("if_lez"),         // If less or equal to zero
        // === Jump ===
        InstructionMnemonic::new("goto"),           // Goto
        InstructionMnemonic::new("goto_16"),        // Goto 16-bit
        InstructionMnemonic::new("goto_32"),        // Goto 32-bit
        InstructionMnemonic::new("packed_switch"),  // Packed switch
        InstructionMnemonic::new("sparse_switch"),  // Sparse switch
        // === Invoke ===
        InstructionMnemonic::new("invoke_virtual"),     // Invoke virtual
        InstructionMnemonic::new("invoke_super"),       // Invoke super
        InstructionMnemonic::new("invoke_direct"),      // Invoke direct
        InstructionMnemonic::new("invoke_static"),      // Invoke static
        InstructionMnemonic::new("invoke_interface"),   // Invoke interface
        // === New ===
        InstructionMnemonic::new("new_instance"),   // New instance
        // === Throw ===
        InstructionMnemonic::new("throw"),          // Throw exception
        // === Type conversion ===
        InstructionMnemonic::new("int_to_long"),    // Int to long
        InstructionMnemonic::new("int_to_float"),   // Int to float
        InstructionMnemonic::new("int_to_double"),  // Int to double
        InstructionMnemonic::new("long_to_int"),    // Long to int
        InstructionMnemonic::new("long_to_float"),  // Long to float
        InstructionMnemonic::new("long_to_double"), // Long to double
        InstructionMnemonic::new("float_to_int"),   // Float to int
        InstructionMnemonic::new("float_to_long"),  // Float to long
        InstructionMnemonic::new("float_to_double"), // Float to double
        InstructionMnemonic::new("double_to_int"),  // Double to int
        InstructionMnemonic::new("double_to_long"), // Double to long
        InstructionMnemonic::new("double_to_float"), // Double to float
        InstructionMnemonic::new("int_to_byte"),    // Int to byte
        InstructionMnemonic::new("int_to_char"),    // Int to char
        InstructionMnemonic::new("int_to_short"),   // Int to short
        // === Fill array data ===
        InstructionMnemonic::new("fill_array_data"), // Fill array data
        // === Nop ===
        InstructionMnemonic::new("nop"),            // No operation
    ]
}

impl ProcessorModule for DalvikProcessor {
    fn name() -> &'static str {
        "Dalvik"
    }

    fn registers() -> RegisterBank {
        build_registers()
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "Dalvik:LE:32:default",
                "Dalvik Base",
                "default",
                Endian::Little,
                32,
            )
            .with_instruction_alignment(1)
            .with_pc_register("PC"),
            Language::new(
                "Dalvik:LE:32:DEX_Base",
                "Dalvik Base (DEX)",
                "DEX-Base",
                Endian::Little,
                32,
            )
            .with_instruction_alignment(1),
            Language::new(
                "Dalvik:LE:32:DEX_KitKat",
                "Dalvik DEX KitKat",
                "DEX KitKat",
                Endian::Little,
                32,
            )
            .with_instruction_alignment(1),
            Language::new(
                "Dalvik:LE:32:DEX_Lollipop",
                "Dalvik DEX Lollipop",
                "DEX Lollipop",
                Endian::Little,
                32,
            )
            .with_instruction_alignment(1),
            Language::new(
                "Dalvik:LE:32:Marshmallow",
                "Dalvik DEX Marshmallow",
                "DEX Marshmallow",
                Endian::Little,
                32,
            )
            .with_instruction_alignment(1),
        ]
    }

    fn instructions() -> Vec<InstructionMnemonic> {
        build_instructions()
    }

    fn description() -> &'static str {
        "Dalvik Virtual Machine (Android DEX)"
    }

    fn family() -> &'static str {
        "Dalvik"
    }

    fn default_pointer_size() -> u32 {
        32
    }

    fn default_endian() -> Endian {
        Endian::Little
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dalvik_name() {
        assert_eq!(DalvikProcessor::name(), "Dalvik");
    }

    #[test]
    fn test_dalvik_registers() {
        let bank = DalvikProcessor::registers();
        assert!(bank.len() >= 10, "Expected at least 10 registers, got {}", bank.len());
        // Special registers
        assert!(bank.get("sp").is_some());
        assert!(bank.get("fp").is_some());
        assert!(bank.get("resultreg").is_some());
        assert!(bank.get("resultregw").is_some());
        // Virtual registers
        assert!(bank.get("v0").is_some());
        assert!(bank.get("v1").is_some());
        assert!(bank.get("v5").is_some());
        // Wide register pairs
        assert!(bank.get("v0_w").is_some());
        assert!(bank.get("v2_w").is_some());
        assert!(bank.get("v4_w").is_some());
    }

    #[test]
    fn test_dalvik_register_bits() {
        let bank = DalvikProcessor::registers();
        assert_eq!(bank.get("sp").unwrap().bit_size, 32);
        assert_eq!(bank.get("fp").unwrap().bit_size, 32);
        assert_eq!(bank.get("resultreg").unwrap().bit_size, 32);
        assert_eq!(bank.get("resultregw").unwrap().bit_size, 64);
        assert_eq!(bank.get("v0").unwrap().bit_size, 32);
        assert_eq!(bank.get("v0_w").unwrap().bit_size, 64);
    }

    #[test]
    fn test_dalvik_languages() {
        let langs = DalvikProcessor::languages();
        assert!(langs.len() >= 5);
        assert!(langs.iter().any(|l| l.id == "Dalvik:LE:32:default"));
        assert!(langs.iter().any(|l| l.id == "Dalvik:LE:32:DEX_Base"));
        assert!(langs.iter().any(|l| l.id == "Dalvik:LE:32:DEX_KitKat"));
        assert!(langs.iter().all(|l| l.endian == Endian::Little));
    }

    #[test]
    fn test_dalvik_instructions() {
        let insts = DalvikProcessor::instructions();
        assert!(insts.len() > 100);
        let texts: Vec<&str> = insts.iter().map(|i| i.text.as_str()).collect();
        // Move
        assert!(texts.contains(&"move"));
        assert!(texts.contains(&"move_wide"));
        assert!(texts.contains(&"move_result"));
        // Return
        assert!(texts.contains(&"return_void"));
        assert!(texts.contains(&"return"));
        assert!(texts.contains(&"return_wide"));
        // Const
        assert!(texts.contains(&"const_4"));
        assert!(texts.contains(&"const_16"));
        assert!(texts.contains(&"const"));
        assert!(texts.contains(&"const_string"));
        assert!(texts.contains(&"const_class"));
        // Arithmetic
        assert!(texts.contains(&"add_int"));
        assert!(texts.contains(&"sub_int"));
        assert!(texts.contains(&"mul_int"));
        assert!(texts.contains(&"div_int"));
        assert!(texts.contains(&"rem_int"));
        assert!(texts.contains(&"and_int"));
        assert!(texts.contains(&"or_int"));
        assert!(texts.contains(&"xor_int"));
        // Compare
        assert!(texts.contains(&"cmpl_float"));
        assert!(texts.contains(&"cmp_long"));
        // Branch
        assert!(texts.contains(&"if_eq"));
        assert!(texts.contains(&"if_ne"));
        assert!(texts.contains(&"if_lt"));
        assert!(texts.contains(&"if_eqz"));
        // Jump
        assert!(texts.contains(&"goto"));
        assert!(texts.contains(&"packed_switch"));
        assert!(texts.contains(&"sparse_switch"));
        // Invoke
        assert!(texts.contains(&"invoke_virtual"));
        assert!(texts.contains(&"invoke_static"));
        assert!(texts.contains(&"invoke_direct"));
        // Array
        assert!(texts.contains(&"aget"));
        assert!(texts.contains(&"aput"));
        assert!(texts.contains(&"new_array"));
        assert!(texts.contains(&"array_length"));
        // Instance
        assert!(texts.contains(&"iget"));
        assert!(texts.contains(&"iput"));
        // Static
        assert!(texts.contains(&"sget"));
        assert!(texts.contains(&"sput"));
        // Type conversion
        assert!(texts.contains(&"int_to_long"));
        assert!(texts.contains(&"float_to_int"));
        // System
        assert!(texts.contains(&"nop"));
        assert!(texts.contains(&"throw"));
        assert!(texts.contains(&"monitor_enter"));
        assert!(texts.contains(&"monitor_exit"));
    }

    #[test]
    fn test_dalvik_metadata() {
        assert_eq!(DalvikProcessor::family(), "Dalvik");
        assert_eq!(DalvikProcessor::default_pointer_size(), 32);
        assert_eq!(DalvikProcessor::default_endian(), Endian::Little);
    }
}
