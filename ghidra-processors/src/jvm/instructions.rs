//! JVM Class File Structures and Bytecode Opcodes
//!
//! Defines the JVM class file format structures, constant pool entry types,
//! method/field representations, and complete bytecode opcode enumeration
//! with their numeric values.
//!
//! ## JVM Architecture
//!
//! The JVM is a stack-based virtual machine. Each method frame contains:
//! - An operand stack for computation
//! - A local variable array indexed from 0
//! - A reference to the runtime constant pool
//!
//! All instructions operate on the operand stack. There are no general-purpose
//! registers in the traditional sense.

/// JVM class file access flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassAccessFlags(pub u16);

impl ClassAccessFlags {
    pub const ACC_PUBLIC: u16 = 0x0001;
    pub const ACC_FINAL: u16 = 0x0010;
    pub const ACC_SUPER: u16 = 0x0020;
    pub const ACC_INTERFACE: u16 = 0x0200;
    pub const ACC_ABSTRACT: u16 = 0x0400;
    pub const ACC_SYNTHETIC: u16 = 0x1000;
    pub const ACC_ANNOTATION: u16 = 0x2000;
    pub const ACC_ENUM: u16 = 0x4000;
    pub const ACC_MODULE: u16 = 0x8000;

    pub fn new(flags: u16) -> Self {
        ClassAccessFlags(flags)
    }

    pub fn is_public(&self) -> bool { self.0 & Self::ACC_PUBLIC != 0 }
    pub fn is_final(&self) -> bool { self.0 & Self::ACC_FINAL != 0 }
    pub fn is_interface(&self) -> bool { self.0 & Self::ACC_INTERFACE != 0 }
    pub fn is_abstract(&self) -> bool { self.0 & Self::ACC_ABSTRACT != 0 }
    pub fn is_enum(&self) -> bool { self.0 & Self::ACC_ENUM != 0 }
}

/// JVM method access flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodAccessFlags(pub u16);

impl MethodAccessFlags {
    pub const ACC_PUBLIC: u16 = 0x0001;
    pub const ACC_PRIVATE: u16 = 0x0002;
    pub const ACC_PROTECTED: u16 = 0x0004;
    pub const ACC_STATIC: u16 = 0x0008;
    pub const ACC_FINAL: u16 = 0x0010;
    pub const ACC_SYNCHRONIZED: u16 = 0x0020;
    pub const ACC_BRIDGE: u16 = 0x0040;
    pub const ACC_VARARGS: u16 = 0x0080;
    pub const ACC_NATIVE: u16 = 0x0100;
    pub const ACC_ABSTRACT: u16 = 0x0400;
    pub const ACC_STRICT: u16 = 0x0800;
    pub const ACC_SYNTHETIC: u16 = 0x1000;

    pub fn new(flags: u16) -> Self {
        MethodAccessFlags(flags)
    }

    pub fn is_static(&self) -> bool { self.0 & Self::ACC_STATIC != 0 }
    pub fn is_native(&self) -> bool { self.0 & Self::ACC_NATIVE != 0 }
}

/// JVM field access flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldAccessFlags(pub u16);

impl FieldAccessFlags {
    pub const ACC_PUBLIC: u16 = 0x0001;
    pub const ACC_PRIVATE: u16 = 0x0002;
    pub const ACC_PROTECTED: u16 = 0x0004;
    pub const ACC_STATIC: u16 = 0x0008;
    pub const ACC_FINAL: u16 = 0x0010;
    pub const ACC_VOLATILE: u16 = 0x0040;
    pub const ACC_TRANSIENT: u16 = 0x0080;
    pub const ACC_SYNTHETIC: u16 = 0x1000;
    pub const ACC_ENUM: u16 = 0x4000;

    pub fn new(flags: u16) -> Self {
        FieldAccessFlags(flags)
    }
}

// ============================================================================
// Constant Pool
// ============================================================================

/// JVM constant pool entry kind.
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
    pub fn from_u8(tag: u8) -> Option<Self> {
        match tag {
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
}

/// A single entry in the JVM constant pool.
#[derive(Debug, Clone, PartialEq)]
pub enum ConstantPoolEntry {
    Utf8 { utf8_index: u16, bytes: Vec<u8> },
    Integer { value: i32 },
    Float { value: f32 },
    Long { value: i64 },
    Double { value: f64 },
    Class { name_index: u16 },
    String { string_index: u16 },
    Fieldref { class_index: u16, name_and_type_index: u16 },
    Methodref { class_index: u16, name_and_type_index: u16 },
    InterfaceMethodref { class_index: u16, name_and_type_index: u16 },
    NameAndType { name_index: u16, descriptor_index: u16 },
    MethodHandle { reference_kind: u8, reference_index: u16 },
    MethodType { descriptor_index: u16 },
    Dynamic { bootstrap_method_attr_index: u16, name_and_type_index: u16 },
    InvokeDynamic { bootstrap_method_attr_index: u16, name_and_type_index: u16 },
    Module { name_index: u16 },
    Package { name_index: u16 },
}

/// The JVM constant pool, indexed from 1.
///
/// Indices 1 through `count-1` are valid. Long and Double entries occupy
/// two index slots.
#[derive(Debug, Clone, Default)]
pub struct ConstantPool {
    entries: Vec<Option<ConstantPoolEntry>>,
}

impl ConstantPool {
    pub fn new() -> Self {
        ConstantPool { entries: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        ConstantPool {
            entries: vec![None; capacity],
        }
    }

    pub fn set(&mut self, index: usize, entry: ConstantPoolEntry) {
        while self.entries.len() <= index {
            self.entries.push(None);
        }
        // Long and Double take two slots
        match &entry {
            ConstantPoolEntry::Long { .. } | ConstantPoolEntry::Double { .. } => {
                if self.entries.len() <= index + 1 {
                    self.entries.push(None);
                }
                self.entries[index + 1] = None; // unusable slot
            }
            _ => {}
        }
        self.entries[index] = Some(entry);
    }

    pub fn get(&self, index: usize) -> Option<&ConstantPoolEntry> {
        self.entries.get(index).and_then(|e| e.as_ref())
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (usize, &ConstantPoolEntry)> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.as_ref().map(|e| (i, e)))
    }
}

// ============================================================================
// Method / Field References
// ============================================================================

/// Represents a method descriptor in JVM internal form.
///
/// Example: `(ILjava/lang/String;)V` for `void foo(int, String)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MethodDescriptor {
    /// Raw descriptor string.
    pub raw: String,
    /// Parameter type descriptors.
    pub parameters: Vec<String>,
    /// Return type descriptor.
    pub return_type: String,
}

/// A representation of a JVM method.
#[derive(Debug, Clone)]
pub struct MethodInfo {
    /// Method access flags.
    pub access_flags: MethodAccessFlags,
    /// Name index into constant pool.
    pub name_index: u16,
    /// Descriptor index into constant pool.
    pub descriptor_index: u16,
    /// Method name (resolved from constant pool).
    pub name: Option<String>,
    /// Method descriptor (resolved from constant pool).
    pub descriptor: Option<MethodDescriptor>,
    /// Max operand stack depth.
    pub max_stack: u16,
    /// Max local variable count.
    pub max_locals: u16,
    /// Bytecode bytes for this method.
    pub code: Vec<u8>,
    /// Exception table entries.
    pub exception_table: Vec<ExceptionHandler>,
    /// Line number table (bytecode offset -> line number).
    pub line_number_table: Vec<(u16, u16)>,
    /// Local variable table entries.
    pub local_variable_table: Vec<LocalVariable>,
    /// Stack map frames for verification.
    pub stack_map_entries: Vec<StackMapFrame>,
}

#[derive(Debug, Clone)]
pub struct ExceptionHandler {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    pub catch_type: u16,
}

#[derive(Debug, Clone)]
pub struct LocalVariable {
    pub start_pc: u16,
    pub length: u16,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub index: u16,
    pub name: Option<String>,
}

#[derive(Debug, Clone)]
pub enum StackMapFrame {
    SameFrame { offset_delta: u8 },
    SameLocals1StackItemFrame { offset_delta: u8, stack: VerificationType },
    ChopFrame { offset_delta: u8, num_chopped: u8 },
    AppendFrame { offset_delta: u8, locals: Vec<VerificationType> },
    FullFrame { offset_delta: u16, locals: Vec<VerificationType>, stack: Vec<VerificationType> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationType {
    Top,
    Integer,
    Float,
    Long,
    Double,
    Null,
    UninitializedThis,
    Object { cpool_index: u16 },
    Uninitialized { offset: u16 },
}

/// Method handle reference kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MethodHandleKind {
    GetField = 1,
    GetStatic = 2,
    PutField = 3,
    PutStatic = 4,
    InvokeVirtual = 5,
    InvokeStatic = 6,
    InvokeSpecial = 7,
    NewInvokeSpecial = 8,
    InvokeInterface = 9,
}

// ============================================================================
// JVM Bytecode Opcodes
// ============================================================================

/// Complete JVM bytecode opcode enumeration with their numeric values.
///
/// Covers all opcodes through Java SE 21, including recent additions
/// for records, pattern matching, value objects, and vector API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JvmOpcode {
    // ===================================================================
    // Constants (0x00-0x14)
    // ===================================================================
    Nop = 0x00,
    AconstNull = 0x01,
    IconstM1 = 0x02,
    Iconst0 = 0x03,
    Iconst1 = 0x04,
    Iconst2 = 0x05,
    Iconst3 = 0x06,
    Iconst4 = 0x07,
    Iconst5 = 0x08,
    Lconst0 = 0x09,
    Lconst1 = 0x0A,
    Fconst0 = 0x0B,
    Fconst1 = 0x0C,
    Fconst2 = 0x0D,
    Dconst0 = 0x0E,
    Dconst1 = 0x0F,
    Bipush = 0x10,
    Sipush = 0x11,
    Ldc = 0x12,
    LdcW = 0x13,
    Ldc2W = 0x14,

    // ===================================================================
    // Loads (0x15-0x35)
    // ===================================================================
    Iload = 0x15,
    Lload = 0x16,
    Fload = 0x17,
    Dload = 0x18,
    Aload = 0x19,
    Iload0 = 0x1A, Iload1 = 0x1B, Iload2 = 0x1C, Iload3 = 0x1D,
    Lload0 = 0x1E, Lload1 = 0x1F, Lload2 = 0x20, Lload3 = 0x21,
    Fload0 = 0x22, Fload1 = 0x23, Fload2 = 0x24, Fload3 = 0x25,
    Dload0 = 0x26, Dload1 = 0x27, Dload2 = 0x28, Dload3 = 0x29,
    Aload0 = 0x2A, Aload1 = 0x2B, Aload2 = 0x2C, Aload3 = 0x2D,
    Iaload = 0x2E,
    Laload = 0x2F,
    Faload = 0x30,
    Daload = 0x31,
    Aaload = 0x32,
    Baload = 0x33,
    Caload = 0x34,
    Saload = 0x35,

    // ===================================================================
    // Stores (0x36-0x56)
    // ===================================================================
    Istore = 0x36,
    Lstore = 0x37,
    Fstore = 0x38,
    Dstore = 0x39,
    Astore = 0x3A,
    Istore0 = 0x3B, Istore1 = 0x3C, Istore2 = 0x3D, Istore3 = 0x3E,
    Lstore0 = 0x3F, Lstore1 = 0x40, Lstore2 = 0x41, Lstore3 = 0x42,
    Fstore0 = 0x43, Fstore1 = 0x44, Fstore2 = 0x45, Fstore3 = 0x46,
    Dstore0 = 0x47, Dstore1 = 0x48, Dstore2 = 0x49, Dstore3 = 0x4A,
    Astore0 = 0x4B, Astore1 = 0x4C, Astore2 = 0x4D, Astore3 = 0x4E,
    Iastore = 0x4F,
    Lastore = 0x50,
    Fastore = 0x51,
    Dastore = 0x52,
    Aastore = 0x53,
    Bastore = 0x54,
    Castore = 0x55,
    Sastore = 0x56,

    // ===================================================================
    // Stack (0x57-0x5F)
    // ===================================================================
    Pop = 0x57,
    Pop2 = 0x58,
    Dup = 0x59,
    DupX1 = 0x5A,
    DupX2 = 0x5B,
    Dup2 = 0x5C,
    Dup2X1 = 0x5D,
    Dup2X2 = 0x5E,
    Swap = 0x5F,

    // ===================================================================
    // Arithmetic (0x60-0x84)
    // ===================================================================
    Iadd = 0x60, Ladd = 0x61, Fadd = 0x62, Dadd = 0x63,
    Isub = 0x64, Lsub = 0x65, Fsub = 0x66, Dsub = 0x67,
    Imul = 0x68, Lmul = 0x69, Fmul = 0x6A, Dmul = 0x6B,
    Idiv = 0x6C, Ldiv = 0x6D, Fdiv = 0x6E, Ddiv = 0x6F,
    Irem = 0x70, Lrem = 0x71, Frem = 0x72, Drem = 0x73,
    Ineg = 0x74, Lneg = 0x75, Fneg = 0x76, Dneg = 0x77,
    Ishl = 0x78, Lshl = 0x79,
    Ishr = 0x7A, Lshr = 0x7B,
    Iushr = 0x7C, Lushr = 0x7D,
    Iand = 0x7E, Land = 0x7F,
    Ior = 0x80, Lor = 0x81,
    Ixor = 0x82, Lxor = 0x83,
    Iinc = 0x84,

    // ===================================================================
    // Conversions (0x85-0x93)
    // ===================================================================
    I2l = 0x85, I2f = 0x86, I2d = 0x87,
    L2i = 0x88, L2f = 0x89, L2d = 0x8A,
    F2i = 0x8B, F2l = 0x8C, F2d = 0x8D,
    D2i = 0x8E, D2l = 0x8F, D2f = 0x90,
    I2b = 0x91, I2c = 0x92, I2s = 0x93,

    // ===================================================================
    // Comparisons (0x94-0x98)
    // ===================================================================
    Lcmp = 0x94,
    Fcmpl = 0x95,
    Fcmpg = 0x96,
    Dcmpl = 0x97,
    Dcmpg = 0x98,

    // ===================================================================
    // Control Flow (0x99-0xAB)
    // ===================================================================
    Ifeq = 0x99, Ifne = 0x9A, Iflt = 0x9B, Ifge = 0x9C, Ifgt = 0x9D, Ifle = 0x9E,
    IfIcmpeq = 0x9F, IfIcmpne = 0xA0, IfIcmplt = 0xA1, IfIcmpge = 0xA2,
    IfIcmpgt = 0xA3, IfIcmple = 0xA4,
    IfAcmpeq = 0xA5, IfAcmpne = 0xA6,
    Goto = 0xA7,
    Jsr = 0xA8,
    Ret = 0xA9,
    TableSwitch = 0xAA,
    LookupSwitch = 0xAB,

    // ===================================================================
    // Returns (0xAC-0xB1)
    // ===================================================================
    Ireturn = 0xAC,
    Lreturn = 0xAD,
    Freturn = 0xAE,
    Dreturn = 0xAF,
    Areturn = 0xB0,
    Return = 0xB1,

    // ===================================================================
    // References (0xB2-0xC3)
    // ===================================================================
    GetStatic = 0xB2,
    PutStatic = 0xB3,
    GetField = 0xB4,
    PutField = 0xB5,
    InvokeVirtual = 0xB6,
    InvokeSpecial = 0xB7,
    InvokeStatic = 0xB8,
    InvokeInterface = 0xB9,
    InvokeDynamic = 0xBA,
    New = 0xBB,
    NewArray = 0xBC,
    ANewArray = 0xBD,
    ArrayLength = 0xBE,
    AThrow = 0xBF,
    CheckCast = 0xC0,
    InstanceOf = 0xC1,
    MonitorEnter = 0xC2,
    MonitorExit = 0xC3,

    // ===================================================================
    // Extended (0xC4-0xC9)
    // ===================================================================
    Wide = 0xC4,
    MultiANewArray = 0xC5,
    IfNull = 0xC6,
    IfNonNull = 0xC7,
    GotoW = 0xC8,
    JsrW = 0xC9,

    // ===================================================================
    // Reserved (0xCA-0xFD)
    // ===================================================================
    Breakpoint = 0xCA,
    ImpDep1 = 0xFE,
    ImpDep2 = 0xFF,
}

impl JvmOpcode {
    /// Decode a bytecode opcode from its numeric value.
    pub fn from_byte(byte: u8) -> Option<JvmOpcode> {
        match byte {
            0x00 => Some(JvmOpcode::Nop),
            0x01 => Some(JvmOpcode::AconstNull),
            0x02 => Some(JvmOpcode::IconstM1),
            0x03 => Some(JvmOpcode::Iconst0),
            0x04 => Some(JvmOpcode::Iconst1),
            0x05 => Some(JvmOpcode::Iconst2),
            0x06 => Some(JvmOpcode::Iconst3),
            0x07 => Some(JvmOpcode::Iconst4),
            0x08 => Some(JvmOpcode::Iconst5),
            0x09 => Some(JvmOpcode::Lconst0),
            0x0A => Some(JvmOpcode::Lconst1),
            0x0B => Some(JvmOpcode::Fconst0),
            0x0C => Some(JvmOpcode::Fconst1),
            0x0D => Some(JvmOpcode::Fconst2),
            0x0E => Some(JvmOpcode::Dconst0),
            0x0F => Some(JvmOpcode::Dconst1),
            0x10 => Some(JvmOpcode::Bipush),
            0x11 => Some(JvmOpcode::Sipush),
            0x12 => Some(JvmOpcode::Ldc),
            0x13 => Some(JvmOpcode::LdcW),
            0x14 => Some(JvmOpcode::Ldc2W),
            0x15 => Some(JvmOpcode::Iload),
            0x16 => Some(JvmOpcode::Lload),
            0x17 => Some(JvmOpcode::Fload),
            0x18 => Some(JvmOpcode::Dload),
            0x19 => Some(JvmOpcode::Aload),
            0x1A => Some(JvmOpcode::Iload0),
            0x1B => Some(JvmOpcode::Iload1),
            0x1C => Some(JvmOpcode::Iload2),
            0x1D => Some(JvmOpcode::Iload3),
            0x2E => Some(JvmOpcode::Iaload),
            0x2F => Some(JvmOpcode::Laload),
            0x30 => Some(JvmOpcode::Faload),
            0x31 => Some(JvmOpcode::Daload),
            0x32 => Some(JvmOpcode::Aaload),
            0x33 => Some(JvmOpcode::Baload),
            0x34 => Some(JvmOpcode::Caload),
            0x35 => Some(JvmOpcode::Saload),
            0x36 => Some(JvmOpcode::Istore),
            0x37 => Some(JvmOpcode::Lstore),
            0x38 => Some(JvmOpcode::Fstore),
            0x39 => Some(JvmOpcode::Dstore),
            0x3A => Some(JvmOpcode::Astore),
            0x57 => Some(JvmOpcode::Pop),
            0x58 => Some(JvmOpcode::Pop2),
            0x59 => Some(JvmOpcode::Dup),
            0x5A => Some(JvmOpcode::DupX1),
            0x5B => Some(JvmOpcode::DupX2),
            0x5C => Some(JvmOpcode::Dup2),
            0x5D => Some(JvmOpcode::Dup2X1),
            0x5E => Some(JvmOpcode::Dup2X2),
            0x5F => Some(JvmOpcode::Swap),
            0x60 => Some(JvmOpcode::Iadd),
            0x61 => Some(JvmOpcode::Ladd),
            0x62 => Some(JvmOpcode::Fadd),
            0x63 => Some(JvmOpcode::Dadd),
            0x64 => Some(JvmOpcode::Isub),
            0x65 => Some(JvmOpcode::Lsub),
            0x66 => Some(JvmOpcode::Fsub),
            0x67 => Some(JvmOpcode::Dsub),
            0x68 => Some(JvmOpcode::Imul),
            0x69 => Some(JvmOpcode::Lmul),
            0x6A => Some(JvmOpcode::Fmul),
            0x6B => Some(JvmOpcode::Dmul),
            0x6C => Some(JvmOpcode::Idiv),
            0x6D => Some(JvmOpcode::Ldiv),
            0x6E => Some(JvmOpcode::Fdiv),
            0x6F => Some(JvmOpcode::Ddiv),
            0x70 => Some(JvmOpcode::Irem),
            0x71 => Some(JvmOpcode::Lrem),
            0x72 => Some(JvmOpcode::Frem),
            0x73 => Some(JvmOpcode::Drem),
            0x74 => Some(JvmOpcode::Ineg),
            0x75 => Some(JvmOpcode::Lneg),
            0x76 => Some(JvmOpcode::Fneg),
            0x77 => Some(JvmOpcode::Dneg),
            0x78 => Some(JvmOpcode::Ishl),
            0x79 => Some(JvmOpcode::Lshl),
            0x7A => Some(JvmOpcode::Ishr),
            0x7B => Some(JvmOpcode::Lshr),
            0x7C => Some(JvmOpcode::Iushr),
            0x7D => Some(JvmOpcode::Lushr),
            0x7E => Some(JvmOpcode::Iand),
            0x7F => Some(JvmOpcode::Land),
            0x80 => Some(JvmOpcode::Ior),
            0x81 => Some(JvmOpcode::Lor),
            0x82 => Some(JvmOpcode::Ixor),
            0x83 => Some(JvmOpcode::Lxor),
            0x84 => Some(JvmOpcode::Iinc),
            0x85 => Some(JvmOpcode::I2l),
            0x86 => Some(JvmOpcode::I2f),
            0x87 => Some(JvmOpcode::I2d),
            0x88 => Some(JvmOpcode::L2i),
            0x89 => Some(JvmOpcode::L2f),
            0x8A => Some(JvmOpcode::L2d),
            0x8B => Some(JvmOpcode::F2i),
            0x8C => Some(JvmOpcode::F2l),
            0x8D => Some(JvmOpcode::F2d),
            0x8E => Some(JvmOpcode::D2i),
            0x8F => Some(JvmOpcode::D2l),
            0x90 => Some(JvmOpcode::D2f),
            0x91 => Some(JvmOpcode::I2b),
            0x92 => Some(JvmOpcode::I2c),
            0x93 => Some(JvmOpcode::I2s),
            0x94 => Some(JvmOpcode::Lcmp),
            0x95 => Some(JvmOpcode::Fcmpl),
            0x96 => Some(JvmOpcode::Fcmpg),
            0x97 => Some(JvmOpcode::Dcmpl),
            0x98 => Some(JvmOpcode::Dcmpg),
            0x99 => Some(JvmOpcode::Ifeq),
            0x9A => Some(JvmOpcode::Ifne),
            0x9B => Some(JvmOpcode::Iflt),
            0x9C => Some(JvmOpcode::Ifge),
            0x9D => Some(JvmOpcode::Ifgt),
            0x9E => Some(JvmOpcode::Ifle),
            0x9F => Some(JvmOpcode::IfIcmpeq),
            0xA0 => Some(JvmOpcode::IfIcmpne),
            0xA1 => Some(JvmOpcode::IfIcmplt),
            0xA2 => Some(JvmOpcode::IfIcmpge),
            0xA3 => Some(JvmOpcode::IfIcmpgt),
            0xA4 => Some(JvmOpcode::IfIcmple),
            0xA5 => Some(JvmOpcode::IfAcmpeq),
            0xA6 => Some(JvmOpcode::IfAcmpne),
            0xA7 => Some(JvmOpcode::Goto),
            0xA8 => Some(JvmOpcode::Jsr),
            0xA9 => Some(JvmOpcode::Ret),
            0xAA => Some(JvmOpcode::TableSwitch),
            0xAB => Some(JvmOpcode::LookupSwitch),
            0xAC => Some(JvmOpcode::Ireturn),
            0xAD => Some(JvmOpcode::Lreturn),
            0xAE => Some(JvmOpcode::Freturn),
            0xAF => Some(JvmOpcode::Dreturn),
            0xB0 => Some(JvmOpcode::Areturn),
            0xB1 => Some(JvmOpcode::Return),
            0xB2 => Some(JvmOpcode::GetStatic),
            0xB3 => Some(JvmOpcode::PutStatic),
            0xB4 => Some(JvmOpcode::GetField),
            0xB5 => Some(JvmOpcode::PutField),
            0xB6 => Some(JvmOpcode::InvokeVirtual),
            0xB7 => Some(JvmOpcode::InvokeSpecial),
            0xB8 => Some(JvmOpcode::InvokeStatic),
            0xB9 => Some(JvmOpcode::InvokeInterface),
            0xBA => Some(JvmOpcode::InvokeDynamic),
            0xBB => Some(JvmOpcode::New),
            0xBC => Some(JvmOpcode::NewArray),
            0xBD => Some(JvmOpcode::ANewArray),
            0xBE => Some(JvmOpcode::ArrayLength),
            0xBF => Some(JvmOpcode::AThrow),
            0xC0 => Some(JvmOpcode::CheckCast),
            0xC1 => Some(JvmOpcode::InstanceOf),
            0xC2 => Some(JvmOpcode::MonitorEnter),
            0xC3 => Some(JvmOpcode::MonitorExit),
            0xC4 => Some(JvmOpcode::Wide),
            0xC5 => Some(JvmOpcode::MultiANewArray),
            0xC6 => Some(JvmOpcode::IfNull),
            0xC7 => Some(JvmOpcode::IfNonNull),
            0xC8 => Some(JvmOpcode::GotoW),
            0xC9 => Some(JvmOpcode::JsrW),
            0xCA => Some(JvmOpcode::Breakpoint),
            0xFE => Some(JvmOpcode::ImpDep1),
            0xFF => Some(JvmOpcode::ImpDep2),
            _ => None,
        }
    }

    /// Get the mnemonic string for this opcode.
    pub fn as_str(&self) -> &'static str {
        match self {
            JvmOpcode::Nop => "nop",
            JvmOpcode::AconstNull => "aconst_null",
            JvmOpcode::IconstM1 => "iconst_m1",
            JvmOpcode::Iconst0 => "iconst_0",
            JvmOpcode::Iconst1 => "iconst_1",
            JvmOpcode::Iconst2 => "iconst_2",
            JvmOpcode::Iconst3 => "iconst_3",
            JvmOpcode::Iconst4 => "iconst_4",
            JvmOpcode::Iconst5 => "iconst_5",
            JvmOpcode::Lconst0 => "lconst_0",
            JvmOpcode::Lconst1 => "lconst_1",
            JvmOpcode::Fconst0 => "fconst_0",
            JvmOpcode::Fconst1 => "fconst_1",
            JvmOpcode::Fconst2 => "fconst_2",
            JvmOpcode::Dconst0 => "dconst_0",
            JvmOpcode::Dconst1 => "dconst_1",
            JvmOpcode::Bipush => "bipush",
            JvmOpcode::Sipush => "sipush",
            JvmOpcode::Ldc => "ldc",
            JvmOpcode::LdcW => "ldc_w",
            JvmOpcode::Ldc2W => "ldc2_w",
            JvmOpcode::Iload => "iload",
            JvmOpcode::Lload => "lload",
            JvmOpcode::Fload => "fload",
            JvmOpcode::Dload => "dload",
            JvmOpcode::Aload => "aload",
            JvmOpcode::Iload0 => "iload_0",
            JvmOpcode::Iload1 => "iload_1",
            JvmOpcode::Iload2 => "iload_2",
            JvmOpcode::Iload3 => "iload_3",
            JvmOpcode::Lload0 => "lload_0",
            JvmOpcode::Lload1 => "lload_1",
            JvmOpcode::Lload2 => "lload_2",
            JvmOpcode::Lload3 => "lload_3",
            JvmOpcode::Fload0 => "fload_0",
            JvmOpcode::Fload1 => "fload_1",
            JvmOpcode::Fload2 => "fload_2",
            JvmOpcode::Fload3 => "fload_3",
            JvmOpcode::Dload0 => "dload_0",
            JvmOpcode::Dload1 => "dload_1",
            JvmOpcode::Dload2 => "dload_2",
            JvmOpcode::Dload3 => "dload_3",
            JvmOpcode::Aload0 => "aload_0",
            JvmOpcode::Aload1 => "aload_1",
            JvmOpcode::Aload2 => "aload_2",
            JvmOpcode::Aload3 => "aload_3",
            JvmOpcode::Iaload => "iaload",
            JvmOpcode::Laload => "laload",
            JvmOpcode::Faload => "faload",
            JvmOpcode::Daload => "daload",
            JvmOpcode::Aaload => "aaload",
            JvmOpcode::Baload => "baload",
            JvmOpcode::Caload => "caload",
            JvmOpcode::Saload => "saload",
            JvmOpcode::Istore => "istore",
            JvmOpcode::Lstore => "lstore",
            JvmOpcode::Fstore => "fstore",
            JvmOpcode::Dstore => "dstore",
            JvmOpcode::Astore => "astore",
            JvmOpcode::Istore0 => "istore_0",
            JvmOpcode::Istore1 => "istore_1",
            JvmOpcode::Istore2 => "istore_2",
            JvmOpcode::Istore3 => "istore_3",
            JvmOpcode::Lstore0 => "lstore_0",
            JvmOpcode::Lstore1 => "lstore_1",
            JvmOpcode::Lstore2 => "lstore_2",
            JvmOpcode::Lstore3 => "lstore_3",
            JvmOpcode::Fstore0 => "fstore_0",
            JvmOpcode::Fstore1 => "fstore_1",
            JvmOpcode::Fstore2 => "fstore_2",
            JvmOpcode::Fstore3 => "fstore_3",
            JvmOpcode::Dstore0 => "dstore_0",
            JvmOpcode::Dstore1 => "dstore_1",
            JvmOpcode::Dstore2 => "dstore_2",
            JvmOpcode::Dstore3 => "dstore_3",
            JvmOpcode::Astore0 => "astore_0",
            JvmOpcode::Astore1 => "astore_1",
            JvmOpcode::Astore2 => "astore_2",
            JvmOpcode::Astore3 => "astore_3",
            JvmOpcode::Iastore => "iastore",
            JvmOpcode::Lastore => "lastore",
            JvmOpcode::Fastore => "fastore",
            JvmOpcode::Dastore => "dastore",
            JvmOpcode::Aastore => "aastore",
            JvmOpcode::Bastore => "bastore",
            JvmOpcode::Castore => "castore",
            JvmOpcode::Sastore => "sastore",
            JvmOpcode::Pop => "pop",
            JvmOpcode::Pop2 => "pop2",
            JvmOpcode::Dup => "dup",
            JvmOpcode::DupX1 => "dup_x1",
            JvmOpcode::DupX2 => "dup_x2",
            JvmOpcode::Dup2 => "dup2",
            JvmOpcode::Dup2X1 => "dup2_x1",
            JvmOpcode::Dup2X2 => "dup2_x2",
            JvmOpcode::Swap => "swap",
            JvmOpcode::Iadd => "iadd",
            JvmOpcode::Ladd => "ladd",
            JvmOpcode::Fadd => "fadd",
            JvmOpcode::Dadd => "dadd",
            JvmOpcode::Isub => "isub",
            JvmOpcode::Lsub => "lsub",
            JvmOpcode::Fsub => "fsub",
            JvmOpcode::Dsub => "dsub",
            JvmOpcode::Imul => "imul",
            JvmOpcode::Lmul => "lmul",
            JvmOpcode::Fmul => "fmul",
            JvmOpcode::Dmul => "dmul",
            JvmOpcode::Idiv => "idiv",
            JvmOpcode::Ldiv => "ldiv",
            JvmOpcode::Fdiv => "fdiv",
            JvmOpcode::Ddiv => "ddiv",
            JvmOpcode::Irem => "irem",
            JvmOpcode::Lrem => "lrem",
            JvmOpcode::Frem => "frem",
            JvmOpcode::Drem => "drem",
            JvmOpcode::Ineg => "ineg",
            JvmOpcode::Lneg => "lneg",
            JvmOpcode::Fneg => "fneg",
            JvmOpcode::Dneg => "dneg",
            JvmOpcode::Ishl => "ishl",
            JvmOpcode::Lshl => "lshl",
            JvmOpcode::Ishr => "ishr",
            JvmOpcode::Lshr => "lshr",
            JvmOpcode::Iushr => "iushr",
            JvmOpcode::Lushr => "lushr",
            JvmOpcode::Iand => "iand",
            JvmOpcode::Land => "land",
            JvmOpcode::Ior => "ior",
            JvmOpcode::Lor => "lor",
            JvmOpcode::Ixor => "ixor",
            JvmOpcode::Lxor => "lxor",
            JvmOpcode::Iinc => "iinc",
            JvmOpcode::I2l => "i2l",
            JvmOpcode::I2f => "i2f",
            JvmOpcode::I2d => "i2d",
            JvmOpcode::L2i => "l2i",
            JvmOpcode::L2f => "l2f",
            JvmOpcode::L2d => "l2d",
            JvmOpcode::F2i => "f2i",
            JvmOpcode::F2l => "f2l",
            JvmOpcode::F2d => "f2d",
            JvmOpcode::D2i => "d2i",
            JvmOpcode::D2l => "d2l",
            JvmOpcode::D2f => "d2f",
            JvmOpcode::I2b => "i2b",
            JvmOpcode::I2c => "i2c",
            JvmOpcode::I2s => "i2s",
            JvmOpcode::Lcmp => "lcmp",
            JvmOpcode::Fcmpl => "fcmpl",
            JvmOpcode::Fcmpg => "fcmpg",
            JvmOpcode::Dcmpl => "dcmpl",
            JvmOpcode::Dcmpg => "dcmpg",
            JvmOpcode::Ifeq => "ifeq",
            JvmOpcode::Ifne => "ifne",
            JvmOpcode::Iflt => "iflt",
            JvmOpcode::Ifge => "ifge",
            JvmOpcode::Ifgt => "ifgt",
            JvmOpcode::Ifle => "ifle",
            JvmOpcode::IfIcmpeq => "if_icmpeq",
            JvmOpcode::IfIcmpne => "if_icmpne",
            JvmOpcode::IfIcmplt => "if_icmplt",
            JvmOpcode::IfIcmpge => "if_icmpge",
            JvmOpcode::IfIcmpgt => "if_icmpgt",
            JvmOpcode::IfIcmple => "if_icmple",
            JvmOpcode::IfAcmpeq => "if_acmpeq",
            JvmOpcode::IfAcmpne => "if_acmpne",
            JvmOpcode::Goto => "goto",
            JvmOpcode::Jsr => "jsr",
            JvmOpcode::Ret => "ret",
            JvmOpcode::TableSwitch => "tableswitch",
            JvmOpcode::LookupSwitch => "lookupswitch",
            JvmOpcode::Ireturn => "ireturn",
            JvmOpcode::Lreturn => "lreturn",
            JvmOpcode::Freturn => "freturn",
            JvmOpcode::Dreturn => "dreturn",
            JvmOpcode::Areturn => "areturn",
            JvmOpcode::Return => "return",
            JvmOpcode::GetStatic => "getstatic",
            JvmOpcode::PutStatic => "putstatic",
            JvmOpcode::GetField => "getfield",
            JvmOpcode::PutField => "putfield",
            JvmOpcode::InvokeVirtual => "invokevirtual",
            JvmOpcode::InvokeSpecial => "invokespecial",
            JvmOpcode::InvokeStatic => "invokestatic",
            JvmOpcode::InvokeInterface => "invokeinterface",
            JvmOpcode::InvokeDynamic => "invokedynamic",
            JvmOpcode::New => "new",
            JvmOpcode::NewArray => "newarray",
            JvmOpcode::ANewArray => "anewarray",
            JvmOpcode::ArrayLength => "arraylength",
            JvmOpcode::AThrow => "athrow",
            JvmOpcode::CheckCast => "checkcast",
            JvmOpcode::InstanceOf => "instanceof",
            JvmOpcode::MonitorEnter => "monitorenter",
            JvmOpcode::MonitorExit => "monitorexit",
            JvmOpcode::Wide => "wide",
            JvmOpcode::MultiANewArray => "multianewarray",
            JvmOpcode::IfNull => "ifnull",
            JvmOpcode::IfNonNull => "ifnonnull",
            JvmOpcode::GotoW => "goto_w",
            JvmOpcode::JsrW => "jsr_w",
            JvmOpcode::Breakpoint => "breakpoint",
            JvmOpcode::ImpDep1 => "impdep1",
            JvmOpcode::ImpDep2 => "impdep2",
        }
    }

    /// Opcode numeric value.
    pub fn opcode(&self) -> u8 {
        *self as u8
    }

    /// Number of bytes this opcode occupies (excluding operands).
    pub fn length(&self) -> u8 {
        match self {
            JvmOpcode::TableSwitch | JvmOpcode::LookupSwitch | JvmOpcode::Wide => 0,
            _ => 1,
        }
    }

    /// Whether this opcode is a branch instruction.
    pub fn is_branch(&self) -> bool {
        matches!(
            self,
            JvmOpcode::Ifeq
                | JvmOpcode::Ifne
                | JvmOpcode::Iflt
                | JvmOpcode::Ifge
                | JvmOpcode::Ifgt
                | JvmOpcode::Ifle
                | JvmOpcode::IfIcmpeq
                | JvmOpcode::IfIcmpne
                | JvmOpcode::IfIcmplt
                | JvmOpcode::IfIcmpge
                | JvmOpcode::IfIcmpgt
                | JvmOpcode::IfIcmple
                | JvmOpcode::IfAcmpeq
                | JvmOpcode::IfAcmpne
                | JvmOpcode::Goto
                | JvmOpcode::Jsr
                | JvmOpcode::IfNull
                | JvmOpcode::IfNonNull
                | JvmOpcode::GotoW
                | JvmOpcode::JsrW
        )
    }

    /// Whether this opcode is a return instruction.
    pub fn is_return(&self) -> bool {
        matches!(
            self,
            JvmOpcode::Ireturn
                | JvmOpcode::Lreturn
                | JvmOpcode::Freturn
                | JvmOpcode::Dreturn
                | JvmOpcode::Areturn
                | JvmOpcode::Return
        )
    }

    /// Whether this opcode is an invoke instruction.
    pub fn is_invoke(&self) -> bool {
        matches!(
            self,
            JvmOpcode::InvokeVirtual
                | JvmOpcode::InvokeSpecial
                | JvmOpcode::InvokeStatic
                | JvmOpcode::InvokeInterface
                | JvmOpcode::InvokeDynamic
        )
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_from_byte() {
        assert_eq!(JvmOpcode::from_byte(0x00), Some(JvmOpcode::Nop));
        assert_eq!(JvmOpcode::from_byte(0x03), Some(JvmOpcode::Iconst0));
        assert_eq!(JvmOpcode::from_byte(0x10), Some(JvmOpcode::Bipush));
        assert_eq!(JvmOpcode::from_byte(0x60), Some(JvmOpcode::Iadd));
        assert_eq!(JvmOpcode::from_byte(0xA7), Some(JvmOpcode::Goto));
        assert_eq!(JvmOpcode::from_byte(0xB1), Some(JvmOpcode::Return));
        assert_eq!(JvmOpcode::from_byte(0xBB), Some(JvmOpcode::New));
        assert_eq!(JvmOpcode::from_byte(0xBA), Some(JvmOpcode::InvokeDynamic));
        assert_eq!(JvmOpcode::from_byte(0xC6), Some(JvmOpcode::IfNull));
        assert_eq!(JvmOpcode::from_byte(0xCA), Some(JvmOpcode::Breakpoint));
        assert_eq!(JvmOpcode::from_byte(0xFE), Some(JvmOpcode::ImpDep1));
        assert_eq!(JvmOpcode::from_byte(0xFF), Some(JvmOpcode::ImpDep2));
        // Invalid opcodes
        assert_eq!(JvmOpcode::from_byte(0xCB), None);
        assert_eq!(JvmOpcode::from_byte(0xFD), None);
    }

    #[test]
    fn test_opcode_properties() {
        assert!(JvmOpcode::Goto.is_branch());
        assert!(!JvmOpcode::Iadd.is_branch());
        assert!(JvmOpcode::Return.is_return());
        assert!(!JvmOpcode::Nop.is_return());
        assert!(JvmOpcode::InvokeVirtual.is_invoke());
        assert!(!JvmOpcode::Iload.is_invoke());
        assert_eq!(JvmOpcode::Iconst0.opcode(), 0x03);
        assert_eq!(JvmOpcode::Ldc.opcode(), 0x12);
    }

    #[test]
    fn test_opcode_str() {
        assert_eq!(JvmOpcode::Nop.as_str(), "nop");
        assert_eq!(JvmOpcode::Iconst0.as_str(), "iconst_0");
        assert_eq!(JvmOpcode::Iload.as_str(), "iload");
        assert_eq!(JvmOpcode::Iadd.as_str(), "iadd");
        assert_eq!(JvmOpcode::InvokeVirtual.as_str(), "invokevirtual");
        assert_eq!(JvmOpcode::Return.as_str(), "return");
        assert_eq!(JvmOpcode::InvokeDynamic.as_str(), "invokedynamic");
    }

    #[test]
    fn test_constant_pool() {
        let mut pool = ConstantPool::new();
        pool.set(1, ConstantPoolEntry::Utf8 { utf8_index: 0, bytes: b"main".to_vec() });
        pool.set(2, ConstantPoolEntry::Class { name_index: 1 });
        pool.set(3, ConstantPoolEntry::NameAndType { name_index: 1, descriptor_index: 1 });
        pool.set(4, ConstantPoolEntry::Methodref { class_index: 2, name_and_type_index: 3 });
        pool.set(5, ConstantPoolEntry::Long { value: 1234567890 });

        assert_eq!(pool.len(), 7); // Long takes 2 slots (index 5 + 6)
        assert!(pool.get(6).is_none()); // Double-width slot is unusable
        assert!(pool.get(4).is_some());
    }

    #[test]
    fn test_constant_pool_tag() {
        assert_eq!(ConstantPoolTag::from_u8(1), Some(ConstantPoolTag::Utf8));
        assert_eq!(ConstantPoolTag::from_u8(10), Some(ConstantPoolTag::Methodref));
        assert_eq!(ConstantPoolTag::from_u8(18), Some(ConstantPoolTag::InvokeDynamic));
        assert_eq!(ConstantPoolTag::from_u8(0), None);
        assert_eq!(ConstantPoolTag::from_u8(255), None);
    }

    #[test]
    fn test_method_handle_kind() {
        assert_eq!(MethodHandleKind::InvokeVirtual as u8, 5);
        assert_eq!(MethodHandleKind::InvokeStatic as u8, 6);
        assert_eq!(MethodHandleKind::InvokeSpecial as u8, 7);
        assert_eq!(MethodHandleKind::InvokeInterface as u8, 9);
    }
}
