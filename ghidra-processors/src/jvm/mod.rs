//! JVM (Java Virtual Machine) Processor Module
//!
//! Complete JVM bytecode processor support with ALL 200+ bytecode opcodes,
//! constant pool tag descriptions, method descriptor format, and class access flags.
//!
//! ## Architecture Overview
//!
//! The JVM is a stack-based virtual machine:
//! - Stack-based computation (no general-purpose registers)
//! - Operand stack with depth tracking per frame
//! - Local variable array indexed from 0
//! - Constant pool for symbolic references
//! - Object references and arrays with GC
//!
//! ## Register Space Layout
//! - PC (program counter):        0x0000  (32-bit, bytecode offset)
//! - SP (stack pointer):           0x0004  (32-bit, operand stack depth)
//! - FP (frame pointer):           0x0008  (32-bit, current frame base)
//! - Local variable slots lv0-15:  0x0100+ (32-bit each, 16 conceptual slots)
//! - Constant pool base:           0x0200  (32-bit)
//! - Constant pool size:           0x0204  (32-bit)
//! - Max stack depth:               0x0208  (16-bit)
//! - Max locals:                    0x020A  (16-bit)
//! - Code length:                   0x020C  (32-bit)
//!
//! ## Constant Pool Tags
//!
//! | Tag | Name                      | Description                          |
//! |-----|---------------------------|--------------------------------------|
//! | 1   | CONSTANT_Utf8             | UTF-8 encoded string                 |
//! | 3   | CONSTANT_Integer          | 4-byte signed integer                |
//! | 4   | CONSTANT_Float            | 4-byte IEEE 754 float                |
//! | 5   | CONSTANT_Long             | 8-byte signed long (takes 2 slots)   |
//! | 6   | CONSTANT_Double           | 8-byte IEEE 754 double (takes 2 slots)|
//! | 7   | CONSTANT_Class            | Class or interface reference         |
//! | 8   | CONSTANT_String           | String constant reference            |
//! | 9   | CONSTANT_Fieldref         | Field reference                      |
//! | 10  | CONSTANT_Methodref        | Method reference                     |
//! | 11  | CONSTANT_InterfaceMethodref | Interface method reference         |
//! | 12  | CONSTANT_NameAndType      | Name and type descriptor             |
//! | 15  | CONSTANT_MethodHandle     | Method handle (Java 7+)              |
//! | 16  | CONSTANT_MethodType       | Method type (Java 7+)                |
//! | 17  | CONSTANT_Dynamic          | Dynamically computed constant (11+)  |
//! | 18  | CONSTANT_InvokeDynamic    | Invoke dynamic bootstrap (Java 7+)   |
//! | 19  | CONSTANT_Module           | Module reference (Java 9+)           |
//! | 20  | CONSTANT_Package          | Package reference (Java 9+)          |
//!
//! ## Method Descriptor Format
//!
//! Method descriptors encode parameter and return types:
//! - Syntax: `(ParameterDescriptor*)ReturnDescriptor`
//! - Base types: B=byte, C=char, D=double, F=float, I=int, J=long,
//!   S=short, Z=boolean, V=void
//! - Object types: L<class-name>;
//! - Array types: [<component-type>
//! - Example: `(ILjava/lang/String;[D)V`
//!   == void method(int, String, double[])
//!
//! ## Class Access Flags
//!
//! | Flag            | Value  | Description            |
//! |-----------------|--------|------------------------|
//! | ACC_PUBLIC      | 0x0001 | Public access          |
//! | ACC_FINAL       | 0x0010 | Final class            |
//! | ACC_SUPER       | 0x0020 | Invokespecial semantics|
//! | ACC_INTERFACE   | 0x0200 | Interface type         |
//! | ACC_ABSTRACT    | 0x0400 | Abstract class         |
//! | ACC_SYNTHETIC   | 0x1000 | Compiler-generated     |
//! | ACC_ANNOTATION  | 0x2000 | Annotation type        |
//! | ACC_ENUM        | 0x4000 | Enum type              |
//! | ACC_MODULE      | 0x8000 | Module info (Java 9+)  |

pub mod instructions;

use crate::common::{Endian, Language, ProcessorModule, Register, RegisterBank};
use ghidra_core::listing::InstructionMnemonic;

// ============================================================================
// Processor Name Constants
// ============================================================================

pub const PROCESSOR_NAME: &str = "JVM";
pub const PROCESSOR_DESCRIPTION: &str =
    "Java Virtual Machine bytecode processor with 200+ opcodes";

// ============================================================================
// Constant Pool Tags
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConstantPoolTag {
    Utf8 = 1,
    Integer = 3,
    Float = 4,
    Long = 5,
    Double = 6,
    Class = 7,
    String = 8,
    Fieldref = 9,
    Methodref = 10,
    InterfaceMethodref = 11,
    NameAndType = 12,
    MethodHandle = 15,
    MethodType = 16,
    Dynamic = 17,
    InvokeDynamic = 18,
    Module = 19,
    Package = 20,
}

impl ConstantPoolTag {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(ConstantPoolTag::Utf8),
            3 => Some(ConstantPoolTag::Integer),
            4 => Some(ConstantPoolTag::Float),
            5 => Some(ConstantPoolTag::Long),
            6 => Some(ConstantPoolTag::Double),
            7 => Some(ConstantPoolTag::Class),
            8 => Some(ConstantPoolTag::String),
            9 => Some(ConstantPoolTag::Fieldref),
            10 => Some(ConstantPoolTag::Methodref),
            11 => Some(ConstantPoolTag::InterfaceMethodref),
            12 => Some(ConstantPoolTag::NameAndType),
            15 => Some(ConstantPoolTag::MethodHandle),
            16 => Some(ConstantPoolTag::MethodType),
            17 => Some(ConstantPoolTag::Dynamic),
            18 => Some(ConstantPoolTag::InvokeDynamic),
            19 => Some(ConstantPoolTag::Module),
            20 => Some(ConstantPoolTag::Package),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ConstantPoolTag::Utf8 => "CONSTANT_Utf8",
            ConstantPoolTag::Integer => "CONSTANT_Integer",
            ConstantPoolTag::Float => "CONSTANT_Float",
            ConstantPoolTag::Long => "CONSTANT_Long",
            ConstantPoolTag::Double => "CONSTANT_Double",
            ConstantPoolTag::Class => "CONSTANT_Class",
            ConstantPoolTag::String => "CONSTANT_String",
            ConstantPoolTag::Fieldref => "CONSTANT_Fieldref",
            ConstantPoolTag::Methodref => "CONSTANT_Methodref",
            ConstantPoolTag::InterfaceMethodref => "CONSTANT_InterfaceMethodref",
            ConstantPoolTag::NameAndType => "CONSTANT_NameAndType",
            ConstantPoolTag::MethodHandle => "CONSTANT_MethodHandle",
            ConstantPoolTag::MethodType => "CONSTANT_MethodType",
            ConstantPoolTag::Dynamic => "CONSTANT_Dynamic",
            ConstantPoolTag::InvokeDynamic => "CONSTANT_InvokeDynamic",
            ConstantPoolTag::Module => "CONSTANT_Module",
            ConstantPoolTag::Package => "CONSTANT_Package",
        }
    }

    pub fn slot_count(&self) -> u32 {
        match self {
            ConstantPoolTag::Long | ConstantPoolTag::Double => 2,
            _ => 1,
        }
    }
}

// ============================================================================
// Class Access Flags
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClassAccessFlag {
    Public = 0x0001,
    Final = 0x0010,
    Super = 0x0020,
    Interface = 0x0200,
    Abstract = 0x0400,
    Synthetic = 0x1000,
    Annotation = 0x2000,
    Enum = 0x4000,
    Module = 0x8000,
}

impl ClassAccessFlag {
    pub fn name(&self) -> &'static str {
        match self {
            ClassAccessFlag::Public => "ACC_PUBLIC",
            ClassAccessFlag::Final => "ACC_FINAL",
            ClassAccessFlag::Super => "ACC_SUPER",
            ClassAccessFlag::Interface => "ACC_INTERFACE",
            ClassAccessFlag::Abstract => "ACC_ABSTRACT",
            ClassAccessFlag::Synthetic => "ACC_SYNTHETIC",
            ClassAccessFlag::Annotation => "ACC_ANNOTATION",
            ClassAccessFlag::Enum => "ACC_ENUM",
            ClassAccessFlag::Module => "ACC_MODULE",
        }
    }

    pub fn value(&self) -> u16 {
        *self as u16
    }
}

// ============================================================================
// JVM Register Bank
// ============================================================================

#[derive(Debug, Clone)]
pub struct JvmRegisterBank {
    pub pc: Register,
    pub sp: Register,
    pub fp: Register,
    pub locals: [Register; 16],
    pub cpool: Register,
    pub cpool_size: Register,
    pub max_stack: Register,
    pub max_locals: Register,
    pub code_length: Register,
    register_by_name: std::collections::HashMap<String, Register>,
}

impl JvmRegisterBank {
    pub fn new() -> Self {
        let pc = Register::new("pc", 32, 0x0000);
        let sp = Register::new("sp", 32, 0x0004);
        let fp = Register::new("fp", 32, 0x0008);

        let locals: [Register; 16] = std::array::from_fn(|i| {
            Register::new(&format!("lv{}", i), 32, 0x0100 + (i as u64) * 4)
        });

        let cpool = Register::new("cpool", 32, 0x0200);
        let cpool_size = Register::new("cpool_size", 32, 0x0204);
        let max_stack = Register::new("max_stack", 16, 0x0208);
        let max_locals = Register::new("max_locals", 16, 0x020A);
        let code_length = Register::new("code_length", 32, 0x020C);

        let mut register_by_name = std::collections::HashMap::new();
        register_by_name.insert("pc".to_string(), pc.clone());
        register_by_name.insert("sp".to_string(), sp.clone());
        register_by_name.insert("fp".to_string(), fp.clone());
        for (i, reg) in locals.iter().enumerate() {
            register_by_name.insert(format!("lv{}", i), reg.clone());
        }
        register_by_name.insert("cpool".to_string(), cpool.clone());
        register_by_name.insert("cpool_size".to_string(), cpool_size.clone());
        register_by_name.insert("max_stack".to_string(), max_stack.clone());
        register_by_name.insert("max_locals".to_string(), max_locals.clone());
        register_by_name.insert("code_length".to_string(), code_length.clone());

        JvmRegisterBank {
            pc, sp, fp, locals,
            cpool, cpool_size, max_stack, max_locals, code_length,
            register_by_name,
        }
    }

    pub fn get(&self, name: &str) -> Option<&Register> {
        self.register_by_name.get(name)
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

impl Default for JvmRegisterBank {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// JVM Instruction Mnemonics (ALL 200+ bytecode opcodes)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JvmMnemonic {
    // ======================================================================
    // Constants (0x00 - 0x14)
    // ======================================================================
    Nop,           // 0x00
    AconstNull,    // 0x01
    IconstM1,      // 0x02
    Iconst0,       // 0x03
    Iconst1,       // 0x04
    Iconst2,       // 0x05
    Iconst3,       // 0x06
    Iconst4,       // 0x07
    Iconst5,       // 0x08
    Lconst0,       // 0x09
    Lconst1,       // 0x0A
    Fconst0,       // 0x0B
    Fconst1,       // 0x0C
    Fconst2,       // 0x0D
    Dconst0,       // 0x0E
    Dconst1,       // 0x0F
    Bipush,        // 0x10
    Sipush,        // 0x11
    Ldc,           // 0x12
    LdcW,          // 0x13
    Ldc2W,         // 0x14

    // ======================================================================
    // Loads (0x15 - 0x35)
    // ======================================================================
    Iload,         // 0x15
    Lload,         // 0x16
    Fload,         // 0x17
    Dload,         // 0x18
    Aload,         // 0x19
    Iload0,        // 0x1A
    Iload1,        // 0x1B
    Iload2,        // 0x1C
    Iload3,        // 0x1D
    Lload0,        // 0x1E
    Lload1,        // 0x1F
    Lload2,        // 0x20
    Lload3,        // 0x21
    Fload0,        // 0x22
    Fload1,        // 0x23
    Fload2,        // 0x24
    Fload3,        // 0x25
    Dload0,        // 0x26
    Dload1,        // 0x27
    Dload2,        // 0x28
    Dload3,        // 0x29
    Aload0,        // 0x2A
    Aload1,        // 0x2B
    Aload2,        // 0x2C
    Aload3,        // 0x2D
    Iaload,        // 0x2E
    Laload,        // 0x2F
    Faload,        // 0x30
    Daload,        // 0x31
    Aaload,        // 0x32
    Baload,        // 0x33
    Caload,        // 0x34
    Saload,        // 0x35

    // ======================================================================
    // Stores (0x36 - 0x56)
    // ======================================================================
    Istore,        // 0x36
    Lstore,        // 0x37
    Fstore,        // 0x38
    Dstore,        // 0x39
    Astore,        // 0x3A
    Istore0,       // 0x3B
    Istore1,       // 0x3C
    Istore2,       // 0x3D
    Istore3,       // 0x3E
    Lstore0,       // 0x3F
    Lstore1,       // 0x40
    Lstore2,       // 0x41
    Lstore3,       // 0x42
    Fstore0,       // 0x43
    Fstore1,       // 0x44
    Fstore2,       // 0x45
    Fstore3,       // 0x46
    Dstore0,       // 0x47
    Dstore1,       // 0x48
    Dstore2,       // 0x49
    Dstore3,       // 0x4A
    Astore0,       // 0x4B
    Astore1,       // 0x4C
    Astore2,       // 0x4D
    Astore3,       // 0x4E
    Iastore,       // 0x4F
    Lastore,       // 0x50
    Fastore,       // 0x51
    Dastore,       // 0x52
    Aastore,       // 0x53
    Bastore,       // 0x54
    Castore,       // 0x55
    Sastore,       // 0x56

    // ======================================================================
    // Stack (0x57 - 0x5F)
    // ======================================================================
    Pop,           // 0x57
    Pop2,          // 0x58
    Dup,           // 0x59
    DupX1,         // 0x5A
    DupX2,         // 0x5B
    Dup2,          // 0x5C
    Dup2X1,        // 0x5D
    Dup2X2,        // 0x5E
    Swap,          // 0x5F

    // ======================================================================
    // Math (0x60 - 0x84)
    // ======================================================================
    Iadd,          // 0x60
    Ladd,          // 0x61
    Fadd,          // 0x62
    Dadd,          // 0x63
    Isub,          // 0x64
    Lsub,          // 0x65
    Fsub,          // 0x66
    Dsub,          // 0x67
    Imul,          // 0x68
    Lmul,          // 0x69
    Fmul,          // 0x6A
    Dmul,          // 0x6B
    Idiv,          // 0x6C
    Ldiv,          // 0x6D
    Fdiv,          // 0x6E
    Ddiv,          // 0x6F
    Irem,          // 0x70
    Lrem,          // 0x71
    Frem,          // 0x72
    Drem,          // 0x73
    Ineg,          // 0x74
    Lneg,          // 0x75
    Fneg,          // 0x76
    Dneg,          // 0x77
    Ishl,          // 0x78
    Lshl,          // 0x79
    Ishr,          // 0x7A
    Lshr,          // 0x7B
    Iushr,         // 0x7C
    Lushr,         // 0x7D
    Iand,          // 0x7E
    Land,          // 0x7F
    Ior,           // 0x80
    Lor,           // 0x81
    Ixor,          // 0x82
    Lxor,          // 0x83
    Iinc,          // 0x84

    // ======================================================================
    // Conversions (0x85 - 0x93)
    // ======================================================================
    I2l,           // 0x85
    I2f,           // 0x86
    I2d,           // 0x87
    L2i,           // 0x88
    L2f,           // 0x89
    L2d,           // 0x8A
    F2i,           // 0x8B
    F2l,           // 0x8C
    F2d,           // 0x8D
    D2i,           // 0x8E
    D2l,           // 0x8F
    D2f,           // 0x90
    I2b,           // 0x91
    I2c,           // 0x92
    I2s,           // 0x93

    // ======================================================================
    // Comparisons (0x94 - 0xA6)
    // ======================================================================
    Lcmp,          // 0x94
    Fcmpl,         // 0x95
    Fcmpg,         // 0x96
    Dcmpl,         // 0x97
    Dcmpg,         // 0x98
    Ifeq,          // 0x99
    Ifne,          // 0x9A
    Iflt,          // 0x9B
    Ifge,          // 0x9C
    Ifgt,          // 0x9D
    Ifle,          // 0x9E
    IfIcmpeq,      // 0x9F
    IfIcmpne,      // 0xA0
    IfIcmplt,      // 0xA1
    IfIcmpge,      // 0xA2
    IfIcmpgt,      // 0xA3
    IfIcmple,      // 0xA4
    IfAcmpeq,      // 0xA5
    IfAcmpne,      // 0xA6

    // ======================================================================
    // Control (0xA7 - 0xB1)
    // ======================================================================
    Goto,          // 0xA7
    Jsr,           // 0xA8
    Ret,           // 0xA9
    Tableswitch,   // 0xAA
    Lookupswitch,  // 0xAB
    Ireturn,       // 0xAC
    Lreturn,       // 0xAD
    Freturn,       // 0xAE
    Dreturn,       // 0xAF
    Areturn,       // 0xB0
    Return,        // 0xB1

    // ======================================================================
    // References (0xB2 - 0xC3)
    // ======================================================================
    Getstatic,     // 0xB2
    Putstatic,     // 0xB3
    Getfield,      // 0xB4
    Putfield,      // 0xB5
    Invokevirtual, // 0xB6
    Invokespecial, // 0xB7
    Invokestatic,  // 0xB8
    Invokeinterface, // 0xB9
    Invokedynamic, // 0xBA
    New,           // 0xBB
    Newarray,      // 0xBC
    Anewarray,     // 0xBD
    Arraylength,   // 0xBE
    Athrow,        // 0xBF
    Checkcast,     // 0xC0
    Instanceof,    // 0xC1
    Monitorenter,  // 0xC2
    Monitorexit,   // 0xC3

    // ======================================================================
    // Extended (0xC4 - 0xC9)
    // ======================================================================
    Wide,          // 0xC4
    Multianewarray,// 0xC5
    Ifnull,        // 0xC6
    Ifnonnull,     // 0xC7
    GotoW,         // 0xC8
    JsrW,          // 0xC9

    // ======================================================================
    // Reserved (0xCA - 0xFF)
    // ======================================================================
    Breakpoint,    // 0xCA
    Impdep1,       // 0xFE
    Impdep2,       // 0xFF

    // ======================================================================
    // Quick Pseudo-Opcodes (HotSpot JVM internal, used for optimization)
    // ======================================================================
    LdcQuick,
    LdcWQuick,
    Ldc2WQuick,
    GetfieldQuick,
    PutfieldQuick,
    Getfield2Quick,
    Putfield2Quick,
    GetstaticQuick,
    PutstaticQuick,
    Getstatic2Quick,
    Putstatic2Quick,
    InvokevirtualQuick,
    InvokenonvirtualQuick,
    InvokesuperQuick,
    NewQuick,
    AnewarrayQuick,
    MultianewarrayQuick,
    CheckcastQuick,
    InstanceofQuick,
}

impl JvmMnemonic {
    pub fn opcode(&self) -> Option<u8> {
        match self {
            JvmMnemonic::Nop => Some(0x00),
            JvmMnemonic::AconstNull => Some(0x01),
            JvmMnemonic::IconstM1 => Some(0x02),
            JvmMnemonic::Iconst0 => Some(0x03),
            JvmMnemonic::Iconst1 => Some(0x04),
            JvmMnemonic::Iconst2 => Some(0x05),
            JvmMnemonic::Iconst3 => Some(0x06),
            JvmMnemonic::Iconst4 => Some(0x07),
            JvmMnemonic::Iconst5 => Some(0x08),
            JvmMnemonic::Lconst0 => Some(0x09),
            JvmMnemonic::Lconst1 => Some(0x0A),
            JvmMnemonic::Fconst0 => Some(0x0B),
            JvmMnemonic::Fconst1 => Some(0x0C),
            JvmMnemonic::Fconst2 => Some(0x0D),
            JvmMnemonic::Dconst0 => Some(0x0E),
            JvmMnemonic::Dconst1 => Some(0x0F),
            JvmMnemonic::Bipush => Some(0x10),
            JvmMnemonic::Sipush => Some(0x11),
            JvmMnemonic::Ldc => Some(0x12),
            JvmMnemonic::LdcW => Some(0x13),
            JvmMnemonic::Ldc2W => Some(0x14),
            JvmMnemonic::Iload => Some(0x15),
            JvmMnemonic::Lload => Some(0x16),
            JvmMnemonic::Fload => Some(0x17),
            JvmMnemonic::Dload => Some(0x18),
            JvmMnemonic::Aload => Some(0x19),
            JvmMnemonic::Iload0 => Some(0x1A),
            JvmMnemonic::Iload1 => Some(0x1B),
            JvmMnemonic::Iload2 => Some(0x1C),
            JvmMnemonic::Iload3 => Some(0x1D),
            JvmMnemonic::Lload0 => Some(0x1E),
            JvmMnemonic::Lload1 => Some(0x1F),
            JvmMnemonic::Lload2 => Some(0x20),
            JvmMnemonic::Lload3 => Some(0x21),
            JvmMnemonic::Fload0 => Some(0x22),
            JvmMnemonic::Fload1 => Some(0x23),
            JvmMnemonic::Fload2 => Some(0x24),
            JvmMnemonic::Fload3 => Some(0x25),
            JvmMnemonic::Dload0 => Some(0x26),
            JvmMnemonic::Dload1 => Some(0x27),
            JvmMnemonic::Dload2 => Some(0x28),
            JvmMnemonic::Dload3 => Some(0x29),
            JvmMnemonic::Aload0 => Some(0x2A),
            JvmMnemonic::Aload1 => Some(0x2B),
            JvmMnemonic::Aload2 => Some(0x2C),
            JvmMnemonic::Aload3 => Some(0x2D),
            JvmMnemonic::Iaload => Some(0x2E),
            JvmMnemonic::Laload => Some(0x2F),
            JvmMnemonic::Faload => Some(0x30),
            JvmMnemonic::Daload => Some(0x31),
            JvmMnemonic::Aaload => Some(0x32),
            JvmMnemonic::Baload => Some(0x33),
            JvmMnemonic::Caload => Some(0x34),
            JvmMnemonic::Saload => Some(0x35),
            JvmMnemonic::Istore => Some(0x36),
            JvmMnemonic::Lstore => Some(0x37),
            JvmMnemonic::Fstore => Some(0x38),
            JvmMnemonic::Dstore => Some(0x39),
            JvmMnemonic::Astore => Some(0x3A),
            JvmMnemonic::Istore0 => Some(0x3B),
            JvmMnemonic::Istore1 => Some(0x3C),
            JvmMnemonic::Istore2 => Some(0x3D),
            JvmMnemonic::Istore3 => Some(0x3E),
            JvmMnemonic::Lstore0 => Some(0x3F),
            JvmMnemonic::Lstore1 => Some(0x40),
            JvmMnemonic::Lstore2 => Some(0x41),
            JvmMnemonic::Lstore3 => Some(0x42),
            JvmMnemonic::Fstore0 => Some(0x43),
            JvmMnemonic::Fstore1 => Some(0x44),
            JvmMnemonic::Fstore2 => Some(0x45),
            JvmMnemonic::Fstore3 => Some(0x46),
            JvmMnemonic::Dstore0 => Some(0x47),
            JvmMnemonic::Dstore1 => Some(0x48),
            JvmMnemonic::Dstore2 => Some(0x49),
            JvmMnemonic::Dstore3 => Some(0x4A),
            JvmMnemonic::Astore0 => Some(0x4B),
            JvmMnemonic::Astore1 => Some(0x4C),
            JvmMnemonic::Astore2 => Some(0x4D),
            JvmMnemonic::Astore3 => Some(0x4E),
            JvmMnemonic::Iastore => Some(0x4F),
            JvmMnemonic::Lastore => Some(0x50),
            JvmMnemonic::Fastore => Some(0x51),
            JvmMnemonic::Dastore => Some(0x52),
            JvmMnemonic::Aastore => Some(0x53),
            JvmMnemonic::Bastore => Some(0x54),
            JvmMnemonic::Castore => Some(0x55),
            JvmMnemonic::Sastore => Some(0x56),
            JvmMnemonic::Pop => Some(0x57),
            JvmMnemonic::Pop2 => Some(0x58),
            JvmMnemonic::Dup => Some(0x59),
            JvmMnemonic::DupX1 => Some(0x5A),
            JvmMnemonic::DupX2 => Some(0x5B),
            JvmMnemonic::Dup2 => Some(0x5C),
            JvmMnemonic::Dup2X1 => Some(0x5D),
            JvmMnemonic::Dup2X2 => Some(0x5E),
            JvmMnemonic::Swap => Some(0x5F),
            JvmMnemonic::Iadd => Some(0x60),
            JvmMnemonic::Ladd => Some(0x61),
            JvmMnemonic::Fadd => Some(0x62),
            JvmMnemonic::Dadd => Some(0x63),
            JvmMnemonic::Isub => Some(0x64),
            JvmMnemonic::Lsub => Some(0x65),
            JvmMnemonic::Fsub => Some(0x66),
            JvmMnemonic::Dsub => Some(0x67),
            JvmMnemonic::Imul => Some(0x68),
            JvmMnemonic::Lmul => Some(0x69),
            JvmMnemonic::Fmul => Some(0x6A),
            JvmMnemonic::Dmul => Some(0x6B),
            JvmMnemonic::Idiv => Some(0x6C),
            JvmMnemonic::Ldiv => Some(0x6D),
            JvmMnemonic::Fdiv => Some(0x6E),
            JvmMnemonic::Ddiv => Some(0x6F),
            JvmMnemonic::Irem => Some(0x70),
            JvmMnemonic::Lrem => Some(0x71),
            JvmMnemonic::Frem => Some(0x72),
            JvmMnemonic::Drem => Some(0x73),
            JvmMnemonic::Ineg => Some(0x74),
            JvmMnemonic::Lneg => Some(0x75),
            JvmMnemonic::Fneg => Some(0x76),
            JvmMnemonic::Dneg => Some(0x77),
            JvmMnemonic::Ishl => Some(0x78),
            JvmMnemonic::Lshl => Some(0x79),
            JvmMnemonic::Ishr => Some(0x7A),
            JvmMnemonic::Lshr => Some(0x7B),
            JvmMnemonic::Iushr => Some(0x7C),
            JvmMnemonic::Lushr => Some(0x7D),
            JvmMnemonic::Iand => Some(0x7E),
            JvmMnemonic::Land => Some(0x7F),
            JvmMnemonic::Ior => Some(0x80),
            JvmMnemonic::Lor => Some(0x81),
            JvmMnemonic::Ixor => Some(0x82),
            JvmMnemonic::Lxor => Some(0x83),
            JvmMnemonic::Iinc => Some(0x84),
            JvmMnemonic::I2l => Some(0x85),
            JvmMnemonic::I2f => Some(0x86),
            JvmMnemonic::I2d => Some(0x87),
            JvmMnemonic::L2i => Some(0x88),
            JvmMnemonic::L2f => Some(0x89),
            JvmMnemonic::L2d => Some(0x8A),
            JvmMnemonic::F2i => Some(0x8B),
            JvmMnemonic::F2l => Some(0x8C),
            JvmMnemonic::F2d => Some(0x8D),
            JvmMnemonic::D2i => Some(0x8E),
            JvmMnemonic::D2l => Some(0x8F),
            JvmMnemonic::D2f => Some(0x90),
            JvmMnemonic::I2b => Some(0x91),
            JvmMnemonic::I2c => Some(0x92),
            JvmMnemonic::I2s => Some(0x93),
            JvmMnemonic::Lcmp => Some(0x94),
            JvmMnemonic::Fcmpl => Some(0x95),
            JvmMnemonic::Fcmpg => Some(0x96),
            JvmMnemonic::Dcmpl => Some(0x97),
            JvmMnemonic::Dcmpg => Some(0x98),
            JvmMnemonic::Ifeq => Some(0x99),
            JvmMnemonic::Ifne => Some(0x9A),
            JvmMnemonic::Iflt => Some(0x9B),
            JvmMnemonic::Ifge => Some(0x9C),
            JvmMnemonic::Ifgt => Some(0x9D),
            JvmMnemonic::Ifle => Some(0x9E),
            JvmMnemonic::IfIcmpeq => Some(0x9F),
            JvmMnemonic::IfIcmpne => Some(0xA0),
            JvmMnemonic::IfIcmplt => Some(0xA1),
            JvmMnemonic::IfIcmpge => Some(0xA2),
            JvmMnemonic::IfIcmpgt => Some(0xA3),
            JvmMnemonic::IfIcmple => Some(0xA4),
            JvmMnemonic::IfAcmpeq => Some(0xA5),
            JvmMnemonic::IfAcmpne => Some(0xA6),
            JvmMnemonic::Goto => Some(0xA7),
            JvmMnemonic::Jsr => Some(0xA8),
            JvmMnemonic::Ret => Some(0xA9),
            JvmMnemonic::Tableswitch => Some(0xAA),
            JvmMnemonic::Lookupswitch => Some(0xAB),
            JvmMnemonic::Ireturn => Some(0xAC),
            JvmMnemonic::Lreturn => Some(0xAD),
            JvmMnemonic::Freturn => Some(0xAE),
            JvmMnemonic::Dreturn => Some(0xAF),
            JvmMnemonic::Areturn => Some(0xB0),
            JvmMnemonic::Return => Some(0xB1),
            JvmMnemonic::Getstatic => Some(0xB2),
            JvmMnemonic::Putstatic => Some(0xB3),
            JvmMnemonic::Getfield => Some(0xB4),
            JvmMnemonic::Putfield => Some(0xB5),
            JvmMnemonic::Invokevirtual => Some(0xB6),
            JvmMnemonic::Invokespecial => Some(0xB7),
            JvmMnemonic::Invokestatic => Some(0xB8),
            JvmMnemonic::Invokeinterface => Some(0xB9),
            JvmMnemonic::Invokedynamic => Some(0xBA),
            JvmMnemonic::New => Some(0xBB),
            JvmMnemonic::Newarray => Some(0xBC),
            JvmMnemonic::Anewarray => Some(0xBD),
            JvmMnemonic::Arraylength => Some(0xBE),
            JvmMnemonic::Athrow => Some(0xBF),
            JvmMnemonic::Checkcast => Some(0xC0),
            JvmMnemonic::Instanceof => Some(0xC1),
            JvmMnemonic::Monitorenter => Some(0xC2),
            JvmMnemonic::Monitorexit => Some(0xC3),
            JvmMnemonic::Wide => Some(0xC4),
            JvmMnemonic::Multianewarray => Some(0xC5),
            JvmMnemonic::Ifnull => Some(0xC6),
            JvmMnemonic::Ifnonnull => Some(0xC7),
            JvmMnemonic::GotoW => Some(0xC8),
            JvmMnemonic::JsrW => Some(0xC9),
            JvmMnemonic::Breakpoint => Some(0xCA),
            JvmMnemonic::Impdep1 => Some(0xFE),
            JvmMnemonic::Impdep2 => Some(0xFF),
            _ => None, // Quick pseudo-opcodes have no real opcode
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            JvmMnemonic::Nop => "nop",
            JvmMnemonic::AconstNull => "aconst_null",
            JvmMnemonic::IconstM1 => "iconst_m1",
            JvmMnemonic::Iconst0 => "iconst_0",
            JvmMnemonic::Iconst1 => "iconst_1",
            JvmMnemonic::Iconst2 => "iconst_2",
            JvmMnemonic::Iconst3 => "iconst_3",
            JvmMnemonic::Iconst4 => "iconst_4",
            JvmMnemonic::Iconst5 => "iconst_5",
            JvmMnemonic::Lconst0 => "lconst_0",
            JvmMnemonic::Lconst1 => "lconst_1",
            JvmMnemonic::Fconst0 => "fconst_0",
            JvmMnemonic::Fconst1 => "fconst_1",
            JvmMnemonic::Fconst2 => "fconst_2",
            JvmMnemonic::Dconst0 => "dconst_0",
            JvmMnemonic::Dconst1 => "dconst_1",
            JvmMnemonic::Bipush => "bipush",
            JvmMnemonic::Sipush => "sipush",
            JvmMnemonic::Ldc => "ldc",
            JvmMnemonic::LdcW => "ldc_w",
            JvmMnemonic::Ldc2W => "ldc2_w",
            JvmMnemonic::Iload => "iload",
            JvmMnemonic::Lload => "lload",
            JvmMnemonic::Fload => "fload",
            JvmMnemonic::Dload => "dload",
            JvmMnemonic::Aload => "aload",
            JvmMnemonic::Iload0 => "iload_0",
            JvmMnemonic::Iload1 => "iload_1",
            JvmMnemonic::Iload2 => "iload_2",
            JvmMnemonic::Iload3 => "iload_3",
            JvmMnemonic::Lload0 => "lload_0",
            JvmMnemonic::Lload1 => "lload_1",
            JvmMnemonic::Lload2 => "lload_2",
            JvmMnemonic::Lload3 => "lload_3",
            JvmMnemonic::Fload0 => "fload_0",
            JvmMnemonic::Fload1 => "fload_1",
            JvmMnemonic::Fload2 => "fload_2",
            JvmMnemonic::Fload3 => "fload_3",
            JvmMnemonic::Dload0 => "dload_0",
            JvmMnemonic::Dload1 => "dload_1",
            JvmMnemonic::Dload2 => "dload_2",
            JvmMnemonic::Dload3 => "dload_3",
            JvmMnemonic::Aload0 => "aload_0",
            JvmMnemonic::Aload1 => "aload_1",
            JvmMnemonic::Aload2 => "aload_2",
            JvmMnemonic::Aload3 => "aload_3",
            JvmMnemonic::Iaload => "iaload",
            JvmMnemonic::Laload => "laload",
            JvmMnemonic::Faload => "faload",
            JvmMnemonic::Daload => "daload",
            JvmMnemonic::Aaload => "aaload",
            JvmMnemonic::Baload => "baload",
            JvmMnemonic::Caload => "caload",
            JvmMnemonic::Saload => "saload",
            JvmMnemonic::Istore => "istore",
            JvmMnemonic::Lstore => "lstore",
            JvmMnemonic::Fstore => "fstore",
            JvmMnemonic::Dstore => "dstore",
            JvmMnemonic::Astore => "astore",
            JvmMnemonic::Istore0 => "istore_0",
            JvmMnemonic::Istore1 => "istore_1",
            JvmMnemonic::Istore2 => "istore_2",
            JvmMnemonic::Istore3 => "istore_3",
            JvmMnemonic::Lstore0 => "lstore_0",
            JvmMnemonic::Lstore1 => "lstore_1",
            JvmMnemonic::Lstore2 => "lstore_2",
            JvmMnemonic::Lstore3 => "lstore_3",
            JvmMnemonic::Fstore0 => "fstore_0",
            JvmMnemonic::Fstore1 => "fstore_1",
            JvmMnemonic::Fstore2 => "fstore_2",
            JvmMnemonic::Fstore3 => "fstore_3",
            JvmMnemonic::Dstore0 => "dstore_0",
            JvmMnemonic::Dstore1 => "dstore_1",
            JvmMnemonic::Dstore2 => "dstore_2",
            JvmMnemonic::Dstore3 => "dstore_3",
            JvmMnemonic::Astore0 => "astore_0",
            JvmMnemonic::Astore1 => "astore_1",
            JvmMnemonic::Astore2 => "astore_2",
            JvmMnemonic::Astore3 => "astore_3",
            JvmMnemonic::Iastore => "iastore",
            JvmMnemonic::Lastore => "lastore",
            JvmMnemonic::Fastore => "fastore",
            JvmMnemonic::Dastore => "dastore",
            JvmMnemonic::Aastore => "aastore",
            JvmMnemonic::Bastore => "bastore",
            JvmMnemonic::Castore => "castore",
            JvmMnemonic::Sastore => "sastore",
            JvmMnemonic::Pop => "pop",
            JvmMnemonic::Pop2 => "pop2",
            JvmMnemonic::Dup => "dup",
            JvmMnemonic::DupX1 => "dup_x1",
            JvmMnemonic::DupX2 => "dup_x2",
            JvmMnemonic::Dup2 => "dup2",
            JvmMnemonic::Dup2X1 => "dup2_x1",
            JvmMnemonic::Dup2X2 => "dup2_x2",
            JvmMnemonic::Swap => "swap",
            JvmMnemonic::Iadd => "iadd",
            JvmMnemonic::Ladd => "ladd",
            JvmMnemonic::Fadd => "fadd",
            JvmMnemonic::Dadd => "dadd",
            JvmMnemonic::Isub => "isub",
            JvmMnemonic::Lsub => "lsub",
            JvmMnemonic::Fsub => "fsub",
            JvmMnemonic::Dsub => "dsub",
            JvmMnemonic::Imul => "imul",
            JvmMnemonic::Lmul => "lmul",
            JvmMnemonic::Fmul => "fmul",
            JvmMnemonic::Dmul => "dmul",
            JvmMnemonic::Idiv => "idiv",
            JvmMnemonic::Ldiv => "ldiv",
            JvmMnemonic::Fdiv => "fdiv",
            JvmMnemonic::Ddiv => "ddiv",
            JvmMnemonic::Irem => "irem",
            JvmMnemonic::Lrem => "lrem",
            JvmMnemonic::Frem => "frem",
            JvmMnemonic::Drem => "drem",
            JvmMnemonic::Ineg => "ineg",
            JvmMnemonic::Lneg => "lneg",
            JvmMnemonic::Fneg => "fneg",
            JvmMnemonic::Dneg => "dneg",
            JvmMnemonic::Ishl => "ishl",
            JvmMnemonic::Lshl => "lshl",
            JvmMnemonic::Ishr => "ishr",
            JvmMnemonic::Lshr => "lshr",
            JvmMnemonic::Iushr => "iushr",
            JvmMnemonic::Lushr => "lushr",
            JvmMnemonic::Iand => "iand",
            JvmMnemonic::Land => "land",
            JvmMnemonic::Ior => "ior",
            JvmMnemonic::Lor => "lor",
            JvmMnemonic::Ixor => "ixor",
            JvmMnemonic::Lxor => "lxor",
            JvmMnemonic::Iinc => "iinc",
            JvmMnemonic::I2l => "i2l",
            JvmMnemonic::I2f => "i2f",
            JvmMnemonic::I2d => "i2d",
            JvmMnemonic::L2i => "l2i",
            JvmMnemonic::L2f => "l2f",
            JvmMnemonic::L2d => "l2d",
            JvmMnemonic::F2i => "f2i",
            JvmMnemonic::F2l => "f2l",
            JvmMnemonic::F2d => "f2d",
            JvmMnemonic::D2i => "d2i",
            JvmMnemonic::D2l => "d2l",
            JvmMnemonic::D2f => "d2f",
            JvmMnemonic::I2b => "i2b",
            JvmMnemonic::I2c => "i2c",
            JvmMnemonic::I2s => "i2s",
            JvmMnemonic::Lcmp => "lcmp",
            JvmMnemonic::Fcmpl => "fcmpl",
            JvmMnemonic::Fcmpg => "fcmpg",
            JvmMnemonic::Dcmpl => "dcmpl",
            JvmMnemonic::Dcmpg => "dcmpg",
            JvmMnemonic::Ifeq => "ifeq",
            JvmMnemonic::Ifne => "ifne",
            JvmMnemonic::Iflt => "iflt",
            JvmMnemonic::Ifge => "ifge",
            JvmMnemonic::Ifgt => "ifgt",
            JvmMnemonic::Ifle => "ifle",
            JvmMnemonic::IfIcmpeq => "if_icmpeq",
            JvmMnemonic::IfIcmpne => "if_icmpne",
            JvmMnemonic::IfIcmplt => "if_icmplt",
            JvmMnemonic::IfIcmpge => "if_icmpge",
            JvmMnemonic::IfIcmpgt => "if_icmpgt",
            JvmMnemonic::IfIcmple => "if_icmple",
            JvmMnemonic::IfAcmpeq => "if_acmpeq",
            JvmMnemonic::IfAcmpne => "if_acmpne",
            JvmMnemonic::Goto => "goto",
            JvmMnemonic::Jsr => "jsr",
            JvmMnemonic::Ret => "ret",
            JvmMnemonic::Tableswitch => "tableswitch",
            JvmMnemonic::Lookupswitch => "lookupswitch",
            JvmMnemonic::Ireturn => "ireturn",
            JvmMnemonic::Lreturn => "lreturn",
            JvmMnemonic::Freturn => "freturn",
            JvmMnemonic::Dreturn => "dreturn",
            JvmMnemonic::Areturn => "areturn",
            JvmMnemonic::Return => "return",
            JvmMnemonic::Getstatic => "getstatic",
            JvmMnemonic::Putstatic => "putstatic",
            JvmMnemonic::Getfield => "getfield",
            JvmMnemonic::Putfield => "putfield",
            JvmMnemonic::Invokevirtual => "invokevirtual",
            JvmMnemonic::Invokespecial => "invokespecial",
            JvmMnemonic::Invokestatic => "invokestatic",
            JvmMnemonic::Invokeinterface => "invokeinterface",
            JvmMnemonic::Invokedynamic => "invokedynamic",
            JvmMnemonic::New => "new",
            JvmMnemonic::Newarray => "newarray",
            JvmMnemonic::Anewarray => "anewarray",
            JvmMnemonic::Arraylength => "arraylength",
            JvmMnemonic::Athrow => "athrow",
            JvmMnemonic::Checkcast => "checkcast",
            JvmMnemonic::Instanceof => "instanceof",
            JvmMnemonic::Monitorenter => "monitorenter",
            JvmMnemonic::Monitorexit => "monitorexit",
            JvmMnemonic::Wide => "wide",
            JvmMnemonic::Multianewarray => "multianewarray",
            JvmMnemonic::Ifnull => "ifnull",
            JvmMnemonic::Ifnonnull => "ifnonnull",
            JvmMnemonic::GotoW => "goto_w",
            JvmMnemonic::JsrW => "jsr_w",
            JvmMnemonic::Breakpoint => "breakpoint",
            JvmMnemonic::Impdep1 => "impdep1",
            JvmMnemonic::Impdep2 => "impdep2",
            // Quick pseudo-opcodes
            JvmMnemonic::LdcQuick => "ldc_quick",
            JvmMnemonic::LdcWQuick => "ldc_w_quick",
            JvmMnemonic::Ldc2WQuick => "ldc2_w_quick",
            JvmMnemonic::GetfieldQuick => "getfield_quick",
            JvmMnemonic::PutfieldQuick => "putfield_quick",
            JvmMnemonic::Getfield2Quick => "getfield2_quick",
            JvmMnemonic::Putfield2Quick => "putfield2_quick",
            JvmMnemonic::GetstaticQuick => "getstatic_quick",
            JvmMnemonic::PutstaticQuick => "putstatic_quick",
            JvmMnemonic::Getstatic2Quick => "getstatic2_quick",
            JvmMnemonic::Putstatic2Quick => "putstatic2_quick",
            JvmMnemonic::InvokevirtualQuick => "invokevirtual_quick",
            JvmMnemonic::InvokenonvirtualQuick => "invokenonvirtual_quick",
            JvmMnemonic::InvokesuperQuick => "invokesuper_quick",
            JvmMnemonic::NewQuick => "new_quick",
            JvmMnemonic::AnewarrayQuick => "anewarray_quick",
            JvmMnemonic::MultianewarrayQuick => "multianewarray_quick",
            JvmMnemonic::CheckcastQuick => "checkcast_quick",
            JvmMnemonic::InstanceofQuick => "instanceof_quick",
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            JvmMnemonic::Nop | JvmMnemonic::AconstNull | JvmMnemonic::IconstM1
            | JvmMnemonic::Iconst0 | JvmMnemonic::Iconst1 | JvmMnemonic::Iconst2
            | JvmMnemonic::Iconst3 | JvmMnemonic::Iconst4 | JvmMnemonic::Iconst5
            | JvmMnemonic::Lconst0 | JvmMnemonic::Lconst1
            | JvmMnemonic::Fconst0 | JvmMnemonic::Fconst1 | JvmMnemonic::Fconst2
            | JvmMnemonic::Dconst0 | JvmMnemonic::Dconst1
            | JvmMnemonic::Bipush | JvmMnemonic::Sipush
            | JvmMnemonic::Ldc | JvmMnemonic::LdcW | JvmMnemonic::Ldc2W => "Constants",
            JvmMnemonic::Iload | JvmMnemonic::Lload | JvmMnemonic::Fload
            | JvmMnemonic::Dload | JvmMnemonic::Aload
            | JvmMnemonic::Iload0 | JvmMnemonic::Iload1 | JvmMnemonic::Iload2 | JvmMnemonic::Iload3
            | JvmMnemonic::Lload0 | JvmMnemonic::Lload1 | JvmMnemonic::Lload2 | JvmMnemonic::Lload3
            | JvmMnemonic::Fload0 | JvmMnemonic::Fload1 | JvmMnemonic::Fload2 | JvmMnemonic::Fload3
            | JvmMnemonic::Dload0 | JvmMnemonic::Dload1 | JvmMnemonic::Dload2 | JvmMnemonic::Dload3
            | JvmMnemonic::Aload0 | JvmMnemonic::Aload1 | JvmMnemonic::Aload2 | JvmMnemonic::Aload3
            | JvmMnemonic::Iaload | JvmMnemonic::Laload | JvmMnemonic::Faload
            | JvmMnemonic::Daload | JvmMnemonic::Aaload | JvmMnemonic::Baload
            | JvmMnemonic::Caload | JvmMnemonic::Saload => "Loads",
            JvmMnemonic::Istore | JvmMnemonic::Lstore | JvmMnemonic::Fstore
            | JvmMnemonic::Dstore | JvmMnemonic::Astore
            | JvmMnemonic::Istore0 | JvmMnemonic::Istore1 | JvmMnemonic::Istore2 | JvmMnemonic::Istore3
            | JvmMnemonic::Lstore0 | JvmMnemonic::Lstore1 | JvmMnemonic::Lstore2 | JvmMnemonic::Lstore3
            | JvmMnemonic::Fstore0 | JvmMnemonic::Fstore1 | JvmMnemonic::Fstore2 | JvmMnemonic::Fstore3
            | JvmMnemonic::Dstore0 | JvmMnemonic::Dstore1 | JvmMnemonic::Dstore2 | JvmMnemonic::Dstore3
            | JvmMnemonic::Astore0 | JvmMnemonic::Astore1 | JvmMnemonic::Astore2 | JvmMnemonic::Astore3
            | JvmMnemonic::Iastore | JvmMnemonic::Lastore | JvmMnemonic::Fastore
            | JvmMnemonic::Dastore | JvmMnemonic::Aastore | JvmMnemonic::Bastore
            | JvmMnemonic::Castore | JvmMnemonic::Sastore => "Stores",
            JvmMnemonic::Pop | JvmMnemonic::Pop2 | JvmMnemonic::Dup
            | JvmMnemonic::DupX1 | JvmMnemonic::DupX2 | JvmMnemonic::Dup2
            | JvmMnemonic::Dup2X1 | JvmMnemonic::Dup2X2 | JvmMnemonic::Swap => "Stack",
            JvmMnemonic::Iadd | JvmMnemonic::Ladd | JvmMnemonic::Fadd | JvmMnemonic::Dadd
            | JvmMnemonic::Isub | JvmMnemonic::Lsub | JvmMnemonic::Fsub | JvmMnemonic::Dsub
            | JvmMnemonic::Imul | JvmMnemonic::Lmul | JvmMnemonic::Fmul | JvmMnemonic::Dmul
            | JvmMnemonic::Idiv | JvmMnemonic::Ldiv | JvmMnemonic::Fdiv | JvmMnemonic::Ddiv
            | JvmMnemonic::Irem | JvmMnemonic::Lrem | JvmMnemonic::Frem | JvmMnemonic::Drem
            | JvmMnemonic::Ineg | JvmMnemonic::Lneg | JvmMnemonic::Fneg | JvmMnemonic::Dneg
            | JvmMnemonic::Ishl | JvmMnemonic::Lshl | JvmMnemonic::Ishr | JvmMnemonic::Lshr
            | JvmMnemonic::Iushr | JvmMnemonic::Lushr | JvmMnemonic::Iand | JvmMnemonic::Land
            | JvmMnemonic::Ior | JvmMnemonic::Lor | JvmMnemonic::Ixor | JvmMnemonic::Lxor
            | JvmMnemonic::Iinc => "Math",
            JvmMnemonic::I2l | JvmMnemonic::I2f | JvmMnemonic::I2d
            | JvmMnemonic::L2i | JvmMnemonic::L2f | JvmMnemonic::L2d
            | JvmMnemonic::F2i | JvmMnemonic::F2l | JvmMnemonic::F2d
            | JvmMnemonic::D2i | JvmMnemonic::D2l | JvmMnemonic::D2f
            | JvmMnemonic::I2b | JvmMnemonic::I2c | JvmMnemonic::I2s => "Conversions",
            JvmMnemonic::Lcmp | JvmMnemonic::Fcmpl | JvmMnemonic::Fcmpg
            | JvmMnemonic::Dcmpl | JvmMnemonic::Dcmpg
            | JvmMnemonic::Ifeq | JvmMnemonic::Ifne | JvmMnemonic::Iflt
            | JvmMnemonic::Ifge | JvmMnemonic::Ifgt | JvmMnemonic::Ifle
            | JvmMnemonic::IfIcmpeq | JvmMnemonic::IfIcmpne
            | JvmMnemonic::IfIcmplt | JvmMnemonic::IfIcmpge
            | JvmMnemonic::IfIcmpgt | JvmMnemonic::IfIcmple
            | JvmMnemonic::IfAcmpeq | JvmMnemonic::IfAcmpne => "Comparisons",
            JvmMnemonic::Goto | JvmMnemonic::Jsr | JvmMnemonic::Ret
            | JvmMnemonic::Tableswitch | JvmMnemonic::Lookupswitch
            | JvmMnemonic::Ireturn | JvmMnemonic::Lreturn | JvmMnemonic::Freturn
            | JvmMnemonic::Dreturn | JvmMnemonic::Areturn | JvmMnemonic::Return => "Control",
            JvmMnemonic::Getstatic | JvmMnemonic::Putstatic | JvmMnemonic::Getfield
            | JvmMnemonic::Putfield | JvmMnemonic::Invokevirtual | JvmMnemonic::Invokespecial
            | JvmMnemonic::Invokestatic | JvmMnemonic::Invokeinterface
            | JvmMnemonic::Invokedynamic | JvmMnemonic::New | JvmMnemonic::Newarray
            | JvmMnemonic::Anewarray | JvmMnemonic::Arraylength | JvmMnemonic::Athrow
            | JvmMnemonic::Checkcast | JvmMnemonic::Instanceof
            | JvmMnemonic::Monitorenter | JvmMnemonic::Monitorexit => "References",
            JvmMnemonic::Wide | JvmMnemonic::Multianewarray | JvmMnemonic::Ifnull
            | JvmMnemonic::Ifnonnull | JvmMnemonic::GotoW | JvmMnemonic::JsrW => "Extended",
            JvmMnemonic::Breakpoint | JvmMnemonic::Impdep1 | JvmMnemonic::Impdep2 => "Reserved",
            _ => "Quick",
        }
    }
}

// ============================================================================
// Conversion to common InstructionMnemonic
// ============================================================================

pub fn all_jvm_mnemonics() -> Vec<InstructionMnemonic> {
    use JvmMnemonic::*;
    let variants = [
        Nop, AconstNull, IconstM1,
        Iconst0, Iconst1, Iconst2, Iconst3, Iconst4, Iconst5,
        Lconst0, Lconst1,
        Fconst0, Fconst1, Fconst2,
        Dconst0, Dconst1,
        Bipush, Sipush, Ldc, LdcW, Ldc2W,
        Iload, Lload, Fload, Dload, Aload,
        Iload0, Iload1, Iload2, Iload3,
        Lload0, Lload1, Lload2, Lload3,
        Fload0, Fload1, Fload2, Fload3,
        Dload0, Dload1, Dload2, Dload3,
        Aload0, Aload1, Aload2, Aload3,
        Iaload, Laload, Faload, Daload, Aaload, Baload, Caload, Saload,
        Istore, Lstore, Fstore, Dstore, Astore,
        Istore0, Istore1, Istore2, Istore3,
        Lstore0, Lstore1, Lstore2, Lstore3,
        Fstore0, Fstore1, Fstore2, Fstore3,
        Dstore0, Dstore1, Dstore2, Dstore3,
        Astore0, Astore1, Astore2, Astore3,
        Iastore, Lastore, Fastore, Dastore, Aastore, Bastore, Castore, Sastore,
        Pop, Pop2, Dup, DupX1, DupX2, Dup2, Dup2X1, Dup2X2, Swap,
        Iadd, Ladd, Fadd, Dadd,
        Isub, Lsub, Fsub, Dsub,
        Imul, Lmul, Fmul, Dmul,
        Idiv, Ldiv, Fdiv, Ddiv,
        Irem, Lrem, Frem, Drem,
        Ineg, Lneg, Fneg, Dneg,
        Ishl, Lshl, Ishr, Lshr, Iushr, Lushr,
        Iand, Land, Ior, Lor, Ixor, Lxor, Iinc,
        I2l, I2f, I2d, L2i, L2f, L2d, F2i, F2l, F2d, D2i, D2l, D2f,
        I2b, I2c, I2s,
        Lcmp, Fcmpl, Fcmpg, Dcmpl, Dcmpg,
        Ifeq, Ifne, Iflt, Ifge, Ifgt, Ifle,
        IfIcmpeq, IfIcmpne, IfIcmplt, IfIcmpge, IfIcmpgt, IfIcmple,
        IfAcmpeq, IfAcmpne,
        Goto, Jsr, Ret, Tableswitch, Lookupswitch,
        Ireturn, Lreturn, Freturn, Dreturn, Areturn, Return,
        Getstatic, Putstatic, Getfield, Putfield,
        Invokevirtual, Invokespecial, Invokestatic, Invokeinterface, Invokedynamic,
        New, Newarray, Anewarray, Arraylength, Athrow,
        Checkcast, Instanceof, Monitorenter, Monitorexit,
        Wide, Multianewarray, Ifnull, Ifnonnull, GotoW, JsrW,
        Breakpoint, Impdep1, Impdep2,
        LdcQuick, LdcWQuick, Ldc2WQuick,
        GetfieldQuick, PutfieldQuick,
        Getfield2Quick, Putfield2Quick,
        GetstaticQuick, PutstaticQuick,
        Getstatic2Quick, Putstatic2Quick,
        InvokevirtualQuick, InvokenonvirtualQuick, InvokesuperQuick,
        NewQuick, AnewarrayQuick, MultianewarrayQuick,
        CheckcastQuick, InstanceofQuick,
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

pub struct JvmModule;

impl ProcessorModule for JvmModule {
    fn name() -> &'static str {
        PROCESSOR_NAME
    }

    fn registers() -> RegisterBank {
        let jvm_bank = JvmRegisterBank::new();
        let mut bank = RegisterBank::new();
        for reg in jvm_bank.iter() {
            bank.add(reg.clone());
        }
        bank
    }

    fn languages() -> Vec<Language> {
        vec![
            Language::new(
                "JVM:BE:32:default",
                "Generic JVM",
                "1.1",
                Endian::Big,
                32,
            ),
        ]
    }

    fn instructions() -> Vec<InstructionMnemonic> {
        all_jvm_mnemonics()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name() {
        assert_eq!(JvmModule::name(), "JVM");
    }

    #[test]
    fn test_register_count() {
        let bank = JvmRegisterBank::new();
        assert!(bank.len() >= 20, "JVM bank should have >=20 registers, got {}", bank.len());
    }

    #[test]
    fn test_registers_exist() {
        let bank = JvmRegisterBank::new();
        for name in ["pc", "sp", "fp", "cpool", "cpool_size", "max_stack", "max_locals", "code_length"] {
            assert!(bank.get(name).is_some(), "Missing register {}", name);
        }
        for i in 0..16 {
            assert!(bank.get(&format!("lv{}", i)).is_some(), "Missing lv{}", i);
        }
    }

    #[test]
    fn test_mnemonic_count() {
        let mnemonics = all_jvm_mnemonics();
        assert!(mnemonics.len() >= 200, "Expected >=200 JVM mnemonics, got {}", mnemonics.len());
    }

    #[test]
    fn test_constant_opcodes() {
        let mnemonics = all_jvm_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["nop", "aconst_null", "iconst_0", "iconst_5", "lconst_0",
                  "fconst_1", "dconst_0", "bipush", "sipush", "ldc", "ldc_w", "ldc2_w"] {
            assert!(texts.contains(&m), "Missing constant mnemonic: {}", m);
        }
    }

    #[test]
    fn test_load_opcodes() {
        let mnemonics = all_jvm_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["iload", "lload", "fload", "dload", "aload",
                  "iload_0", "aload_3", "iaload", "laload", "faload",
                  "daload", "aaload", "baload", "caload", "saload"] {
            assert!(texts.contains(&m), "Missing load mnemonic: {}", m);
        }
    }

    #[test]
    fn test_store_opcodes() {
        let mnemonics = all_jvm_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["istore", "lstore", "fstore", "dstore", "astore",
                  "istore_0", "astore_3", "iastore", "lastore", "fastore",
                  "dastore", "aastore", "bastore", "castore", "sastore"] {
            assert!(texts.contains(&m), "Missing store mnemonic: {}", m);
        }
    }

    #[test]
    fn test_stack_opcodes() {
        let mnemonics = all_jvm_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["pop", "pop2", "dup", "dup_x1", "dup_x2",
                  "dup2", "dup2_x1", "dup2_x2", "swap"] {
            assert!(texts.contains(&m), "Missing stack mnemonic: {}", m);
        }
    }

    #[test]
    fn test_math_opcodes() {
        let mnemonics = all_jvm_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["iadd", "ladd", "fadd", "dadd", "isub", "lsub", "fsub", "dsub",
                  "imul", "lmul", "fmul", "dmul", "idiv", "ldiv", "fdiv", "ddiv",
                  "irem", "lrem", "frem", "drem", "ineg", "lneg", "fneg", "dneg",
                  "ishl", "lshl", "ishr", "lshr", "iushr", "lushr",
                  "iand", "land", "ior", "lor", "ixor", "lxor", "iinc"] {
            assert!(texts.contains(&m), "Missing math mnemonic: {}", m);
        }
    }

    #[test]
    fn test_conversion_opcodes() {
        let mnemonics = all_jvm_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["i2l", "i2f", "i2d", "l2i", "l2f", "l2d",
                  "f2i", "f2l", "f2d", "d2i", "d2l", "d2f",
                  "i2b", "i2c", "i2s"] {
            assert!(texts.contains(&m), "Missing conversion mnemonic: {}", m);
        }
    }

    #[test]
    fn test_comparison_opcodes() {
        let mnemonics = all_jvm_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["lcmp", "fcmpl", "fcmpg", "dcmpl", "dcmpg",
                  "ifeq", "ifne", "iflt", "ifge", "ifgt", "ifle",
                  "if_icmpeq", "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt", "if_icmple",
                  "if_acmpeq", "if_acmpne"] {
            assert!(texts.contains(&m), "Missing comparison mnemonic: {}", m);
        }
    }

    #[test]
    fn test_control_opcodes() {
        let mnemonics = all_jvm_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["goto", "jsr", "ret", "tableswitch", "lookupswitch",
                  "ireturn", "lreturn", "freturn", "dreturn", "areturn", "return"] {
            assert!(texts.contains(&m), "Missing control mnemonic: {}", m);
        }
    }

    #[test]
    fn test_reference_opcodes() {
        let mnemonics = all_jvm_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["getstatic", "putstatic", "getfield", "putfield",
                  "invokevirtual", "invokespecial", "invokestatic",
                  "invokeinterface", "invokedynamic",
                  "new", "newarray", "anewarray", "arraylength", "athrow",
                  "checkcast", "instanceof", "monitorenter", "monitorexit"] {
            assert!(texts.contains(&m), "Missing reference mnemonic: {}", m);
        }
    }

    #[test]
    fn test_extended_opcodes() {
        let mnemonics = all_jvm_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["wide", "multianewarray", "ifnull", "ifnonnull", "goto_w", "jsr_w"] {
            assert!(texts.contains(&m), "Missing extended mnemonic: {}", m);
        }
    }

    #[test]
    fn test_reserved_opcodes() {
        let mnemonics = all_jvm_mnemonics();
        let texts: Vec<&str> = mnemonics.iter().map(|m| m.text.as_str()).collect();
        for m in ["breakpoint", "impdep1", "impdep2"] {
            assert!(texts.contains(&m), "Missing reserved mnemonic: {}", m);
        }
    }

    #[test]
    fn test_constant_pool_tags() {
        assert_eq!(ConstantPoolTag::Utf8 as u8, 1);
        assert_eq!(ConstantPoolTag::Methodref as u8, 10);
        assert_eq!(ConstantPoolTag::InvokeDynamic as u8, 18);
        assert_eq!(ConstantPoolTag::Module as u8, 19);
        assert_eq!(ConstantPoolTag::Package as u8, 20);
        assert!(ConstantPoolTag::from_u8(2).is_none());
        assert_eq!(ConstantPoolTag::from_u8(1), Some(ConstantPoolTag::Utf8));
        assert_eq!(ConstantPoolTag::Long.slot_count(), 2);
        assert_eq!(ConstantPoolTag::Double.slot_count(), 2);
        assert_eq!(ConstantPoolTag::Utf8.slot_count(), 1);
    }

    #[test]
    fn test_class_access_flags() {
        assert_eq!(ClassAccessFlag::Public.value(), 0x0001);
        assert_eq!(ClassAccessFlag::Interface.value(), 0x0200);
        assert_eq!(ClassAccessFlag::Module.value(), 0x8000);
        assert_eq!(ClassAccessFlag::Public.name(), "ACC_PUBLIC");
        assert_eq!(ClassAccessFlag::Enum.name(), "ACC_ENUM");
    }

    #[test]
    fn test_opcode_map() {
        assert_eq!(JvmMnemonic::Nop.opcode(), Some(0x00));
        assert_eq!(JvmMnemonic::Bipush.opcode(), Some(0x10));
        assert_eq!(JvmMnemonic::Iadd.opcode(), Some(0x60));
        assert_eq!(JvmMnemonic::Goto.opcode(), Some(0xA7));
        assert_eq!(JvmMnemonic::Invokevirtual.opcode(), Some(0xB6));
        assert_eq!(JvmMnemonic::Return.opcode(), Some(0xB1));
        assert_eq!(JvmMnemonic::Breakpoint.opcode(), Some(0xCA));
        assert_eq!(JvmMnemonic::Impdep1.opcode(), Some(0xFE));
        assert_eq!(JvmMnemonic::Impdep2.opcode(), Some(0xFF));
        assert_eq!(JvmMnemonic::LdcQuick.opcode(), None); // pseudo-opcode
    }

    #[test]
    fn test_processor_module_interface() {
        assert_eq!(JvmModule::name(), "JVM");
        let regs = JvmModule::registers();
        assert!(!regs.is_empty());
        let langs = JvmModule::languages();
        assert!(langs.len() >= 1);
        let insts = JvmModule::instructions();
        assert!(insts.len() >= 200);
    }
}
