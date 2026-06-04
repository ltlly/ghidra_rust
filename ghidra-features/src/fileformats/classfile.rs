//! Java .class File Format Parser
//!
//! Complete nom-based parser for Java class files (JVM bytecode).
//!
//! ## Specification Coverage
//! - Magic number detection (0xCAFEBABE)
//! - Major/minor version support: Java 1.0 through Java 21+ (45-65)
//! - Constant pool with all 17 tag types (Utf8=1 through Package=20)
//! - Fields and methods with access flags and attributes
//! - Code attribute: max_stack, max_locals, bytecode[], exception_table, nested attributes
//! - StackMapTable: all frame types (same through full_frame)
//! - Verification type info: Top, Integer, Float, Double, Long, Null, UninitializedThis, Object, Uninitialized
//! - Exceptions, InnerClasses, EnclosingMethod, Signature, Synthetic, Deprecated
//! - LineNumberTable, LocalVariableTable, LocalVariableTypeTable
//! - SourceFile, SourceDebugExtension
//! - RuntimeVisible/Invisible Annotations and ParameterAnnotations
//! - RuntimeVisible/Invisible TypeAnnotations
//! - AnnotationDefault, BootstrapMethods, MethodParameters
//! - Module (Java 9+), ModulePackages, ModuleMainClass
//! - NestHost/NestMembers (Java 11+)
//! - Record (Java 16+), PermittedSubclasses (Java 17+)
//!
//! References:
//! - JVM Specification: <https://docs.oracle.com/javase/specs/jvms/se21/html/>

use nom::bytes::complete::take;
use nom::number::complete::{be_u16, be_u32, be_u8};
use nom::IResult;
use std::collections::HashMap;

// ============================================================================
// Magic Number and Version Constants
// ============================================================================

/// Java class file magic number: 0xCAFEBABE.
pub const CLASS_MAGIC: u32 = 0xCAFE_BABE;

/// Java class major version constants.
pub mod class_version {
    pub const JAVA_1_0: u16 = 45;
    pub const JAVA_1_1: u16 = 45;
    pub const JAVA_1_2: u16 = 46;
    pub const JAVA_1_3: u16 = 47;
    pub const JAVA_1_4: u16 = 48;
    pub const JAVA_5: u16 = 49;
    pub const JAVA_6: u16 = 50;
    pub const JAVA_7: u16 = 51;
    pub const JAVA_8: u16 = 52;
    pub const JAVA_9: u16 = 53;
    pub const JAVA_10: u16 = 54;
    pub const JAVA_11: u16 = 55;
    pub const JAVA_12: u16 = 56;
    pub const JAVA_13: u16 = 57;
    pub const JAVA_14: u16 = 58;
    pub const JAVA_15: u16 = 59;
    pub const JAVA_16: u16 = 60;
    pub const JAVA_17: u16 = 61;
    pub const JAVA_18: u16 = 62;
    pub const JAVA_19: u16 = 63;
    pub const JAVA_20: u16 = 64;
    pub const JAVA_21: u16 = 65;
    pub const JAVA_22: u16 = 66;
    pub const JAVA_23: u16 = 67;
    pub const JAVA_24: u16 = 68;
}

/// Return a human-readable Java version name from a major version number.
pub fn java_version_name(major: u16) -> String {
    match major {
        45 => "Java 1.0/1.1".to_string(),
        46 => "Java 1.2".to_string(),
        47 => "Java 1.3".to_string(),
        48 => "Java 1.4".to_string(),
        49 => "Java 5".to_string(),
        50 => "Java 6".to_string(),
        51 => "Java 7".to_string(),
        52 => "Java 8".to_string(),
        53 => "Java 9".to_string(),
        54 => "Java 10".to_string(),
        55 => "Java 11".to_string(),
        56 => "Java 12".to_string(),
        57 => "Java 13".to_string(),
        58 => "Java 14".to_string(),
        59 => "Java 15".to_string(),
        60 => "Java 16".to_string(),
        61 => "Java 17".to_string(),
        62 => "Java 18".to_string(),
        63 => "Java 19".to_string(),
        64 => "Java 20".to_string(),
        65 => "Java 21".to_string(),
        66 => "Java 22".to_string(),
        67 => "Java 23".to_string(),
        68 => "Java 24".to_string(),
        _ => format!("Java (major version {})", major),
    }
}

// ============================================================================
// Constant Pool Tag Constants
// ============================================================================

pub const CONSTANT_UTF8: u8 = 1;
pub const CONSTANT_INTEGER: u8 = 3;
pub const CONSTANT_FLOAT: u8 = 4;
pub const CONSTANT_LONG: u8 = 5;
pub const CONSTANT_DOUBLE: u8 = 6;
pub const CONSTANT_CLASS: u8 = 7;
pub const CONSTANT_STRING: u8 = 8;
pub const CONSTANT_FIELDREF: u8 = 9;
pub const CONSTANT_METHODREF: u8 = 10;
pub const CONSTANT_INTERFACE_METHODREF: u8 = 11;
pub const CONSTANT_NAME_AND_TYPE: u8 = 12;
pub const CONSTANT_METHOD_HANDLE: u8 = 15;
pub const CONSTANT_METHOD_TYPE: u8 = 16;
pub const CONSTANT_DYNAMIC: u8 = 17;
pub const CONSTANT_INVOKE_DYNAMIC: u8 = 18;
pub const CONSTANT_MODULE: u8 = 19;
pub const CONSTANT_PACKAGE: u8 = 20;

/// Reference kind constants for MethodHandle (JVMS 5.4.3.5).
pub const REF_GET_FIELD: u8 = 1;
pub const REF_GET_STATIC: u8 = 2;
pub const REF_PUT_FIELD: u8 = 3;
pub const REF_PUT_STATIC: u8 = 4;
pub const REF_INVOKE_VIRTUAL: u8 = 5;
pub const REF_INVOKE_STATIC: u8 = 6;
pub const REF_INVOKE_SPECIAL: u8 = 7;
pub const REF_NEW_INVOKE_SPECIAL: u8 = 8;
pub const REF_INVOKE_INTERFACE: u8 = 9;

pub fn reference_kind_name(kind: u8) -> &'static str {
    match kind {
        REF_GET_FIELD => "REF_getField",
        REF_GET_STATIC => "REF_getStatic",
        REF_PUT_FIELD => "REF_putField",
        REF_PUT_STATIC => "REF_putStatic",
        REF_INVOKE_VIRTUAL => "REF_invokeVirtual",
        REF_INVOKE_STATIC => "REF_invokeStatic",
        REF_INVOKE_SPECIAL => "REF_invokeSpecial",
        REF_NEW_INVOKE_SPECIAL => "REF_newInvokeSpecial",
        REF_INVOKE_INTERFACE => "REF_invokeInterface",
        _ => "UNKNOWN",
    }
}

// ============================================================================
// Access Flags (bitflags)
// ============================================================================

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct AccessFlags: u16 {
        const ACC_PUBLIC       = 0x0001;
        const ACC_PRIVATE      = 0x0002;
        const ACC_PROTECTED    = 0x0004;
        const ACC_STATIC       = 0x0008;
        const ACC_FINAL        = 0x0010;
        const ACC_SUPER        = 0x0020;
        const ACC_SYNCHRONIZED = 0x0020;
        const ACC_VOLATILE     = 0x0040;
        const ACC_BRIDGE       = 0x0040;
        const ACC_TRANSIENT    = 0x0080;
        const ACC_VARARGS      = 0x0080;
        const ACC_NATIVE       = 0x0100;
        const ACC_INTERFACE    = 0x0200;
        const ACC_ABSTRACT     = 0x0400;
        const ACC_STRICT       = 0x0800;
        const ACC_SYNTHETIC    = 0x1000;
        const ACC_ANNOTATION   = 0x2000;
        const ACC_ENUM         = 0x4000;
        const ACC_MODULE       = 0x8000;
    }
}

// ============================================================================
// Verification Type Info Tags
// ============================================================================

pub const VERIFY_TOP: u8 = 0;
pub const VERIFY_INTEGER: u8 = 1;
pub const VERIFY_FLOAT: u8 = 2;
pub const VERIFY_DOUBLE: u8 = 3;
pub const VERIFY_LONG: u8 = 4;
pub const VERIFY_NULL: u8 = 5;
pub const VERIFY_UNINITIALIZED_THIS: u8 = 6;
pub const VERIFY_OBJECT: u8 = 7;
pub const VERIFY_UNINITIALIZED: u8 = 8;

// ============================================================================
// StackMapFrame Type Constants
// ============================================================================

pub const FRAME_SAME_MAX: u8 = 63;
pub const FRAME_SAME_LOCALS_1_STACK_MAX: u8 = 127;
pub const FRAME_SAME_LOCALS_1_STACK_EXTENDED: u8 = 247;
pub const FRAME_CHOP_MIN: u8 = 248;
pub const FRAME_CHOP_MAX: u8 = 250;
pub const FRAME_SAME_EXTENDED: u8 = 251;
pub const FRAME_APPEND_MIN: u8 = 252;
pub const FRAME_APPEND_MAX: u8 = 254;
pub const FRAME_FULL: u8 = 255;

// ============================================================================
// Data Structures
// ============================================================================

/// Complete parsed Java .class file.
#[derive(Debug, Clone)]
pub struct JavaClass {
    pub magic: u32,
    pub minor_version: u16,
    pub major_version: u16,
    pub constant_pool: Vec<Option<ConstantPoolEntry>>,
    pub access_flags: AccessFlags,
    pub this_class: u16,
    pub super_class: u16,
    pub interfaces: Vec<u16>,
    pub fields: Vec<FieldInfo>,
    pub methods: Vec<MethodInfo>,
    pub attributes: Vec<Attribute>,
    /// Human-readable class name resolved from constant pool.
    pub class_name: String,
    /// Human-readable superclass name resolved from constant pool.
    pub super_class_name: String,
}

/// A single constant pool entry.
#[derive(Debug, Clone)]
pub enum ConstantPoolEntry {
    Utf8 { value: String },
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

/// A field in the class file.
#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub access_flags: AccessFlags,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub attributes: Vec<Attribute>,
    pub name: String,
    pub descriptor: String,
}

/// A method in the class file.
#[derive(Debug, Clone)]
pub struct MethodInfo {
    pub access_flags: AccessFlags,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub attributes: Vec<Attribute>,
    pub name: String,
    pub descriptor: String,
}

/// All standard JVM class file attributes.
#[derive(Debug, Clone)]
pub enum Attribute {
    Code(Box<CodeAttribute>),
    StackMapTable(Vec<StackMapFrame>),
    Exceptions(Vec<u16>),
    InnerClasses(Vec<InnerClassInfo>),
    EnclosingMethod { class_index: u16, method_index: u16 },
    Synthetic,
    Signature { signature_index: u16 },
    SourceFile { sourcefile_index: u16 },
    SourceDebugExtension { debug_extension: Vec<u8> },
    LineNumberTable(Vec<LineNumberEntry>),
    LocalVariableTable(Vec<LocalVariableEntry>),
    LocalVariableTypeTable(Vec<LocalVariableTypeEntry>),
    Deprecated,
    RuntimeVisibleAnnotations(Vec<Annotation>),
    RuntimeInvisibleAnnotations(Vec<Annotation>),
    RuntimeVisibleParameterAnnotations(Vec<Vec<Annotation>>),
    RuntimeInvisibleParameterAnnotations(Vec<Vec<Annotation>>),
    RuntimeVisibleTypeAnnotations(Vec<TypeAnnotation>),
    RuntimeInvisibleTypeAnnotations(Vec<TypeAnnotation>),
    AnnotationDefault { default_value: ElementValue },
    BootstrapMethods(Vec<BootstrapMethod>),
    MethodParameters(Vec<MethodParameter>),
    Module(ModuleAttribute),
    ModulePackages(Vec<u16>),
    ModuleMainClass { main_class_index: u16 },
    NestHost { host_class_index: u16 },
    NestMembers(Vec<u16>),
    Record(Vec<RecordComponent>),
    PermittedSubclasses(Vec<u16>),
    Unknown { name: String, data: Vec<u8> },
}

/// Code attribute structure (JVMS 4.7.3).
#[derive(Debug, Clone)]
pub struct CodeAttribute {
    pub max_stack: u16,
    pub max_locals: u16,
    pub code: Vec<u8>,
    pub exception_table: Vec<ExceptionTableEntry>,
    pub attributes: Vec<Attribute>,
}

/// Exception table entry.
#[derive(Debug, Clone)]
pub struct ExceptionTableEntry {
    pub start_pc: u16,
    pub end_pc: u16,
    pub handler_pc: u16,
    pub catch_type_index: u16,
}

/// Line number table entry.
#[derive(Debug, Clone)]
pub struct LineNumberEntry {
    pub start_pc: u16,
    pub line_number: u16,
}

/// Local variable table entry.
#[derive(Debug, Clone)]
pub struct LocalVariableEntry {
    pub start_pc: u16,
    pub length: u16,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub index: u16,
}

/// Local variable type table entry.
#[derive(Debug, Clone)]
pub struct LocalVariableTypeEntry {
    pub start_pc: u16,
    pub length: u16,
    pub name_index: u16,
    pub signature_index: u16,
    pub index: u16,
}

/// Inner class information.
#[derive(Debug, Clone)]
pub struct InnerClassInfo {
    pub inner_class_info_index: u16,
    pub outer_class_info_index: u16,
    pub inner_name_index: u16,
    pub inner_class_access_flags: AccessFlags,
}

/// Stack map frame (JVMS 4.7.4).
#[derive(Debug, Clone)]
pub enum StackMapFrame {
    Same { offset_delta: u8 },
    SameLocals1StackItem { offset_delta: u8, stack: VerificationTypeInfo },
    SameLocals1StackItemExtended { offset_delta: u16, stack: VerificationTypeInfo },
    Chop { offset_delta: u16, chopped: u8 },
    SameExtended { offset_delta: u16 },
    Append { offset_delta: u16, locals: Vec<VerificationTypeInfo> },
    Full { offset_delta: u16, locals: Vec<VerificationTypeInfo>, stack: Vec<VerificationTypeInfo> },
}

/// Verification type info (JVMS 4.7.4).
#[derive(Debug, Clone)]
pub enum VerificationTypeInfo {
    Top,
    Integer,
    Float,
    Double,
    Long,
    Null,
    UninitializedThis,
    Object { cpool_index: u16 },
    Uninitialized { offset: u16 },
}

/// Annotation structure (JVMS 4.7.16).
#[derive(Debug, Clone)]
pub struct Annotation {
    pub type_index: u16,
    pub element_value_pairs: Vec<ElementValuePair>,
}

/// Element value pair for annotations.
#[derive(Debug, Clone)]
pub struct ElementValuePair {
    pub element_name_index: u16,
    pub value: ElementValue,
}

/// Element value for annotations.
#[derive(Debug, Clone)]
pub enum ElementValue {
    ConstValue { tag: u8, const_value_index: u16 },
    EnumConstValue { type_name_index: u16, const_name_index: u16 },
    ClassInfo { class_info_index: u16 },
    Annotation(Box<Annotation>),
    Array { values: Vec<ElementValue> },
}

/// Type annotation structure (JVMS 4.7.20).
#[derive(Debug, Clone)]
pub struct TypeAnnotation {
    pub target_type: u8,
    pub target_info: TypeAnnotationTarget,
    pub target_path: Vec<TypePathEntry>,
    pub type_index: u16,
    pub element_value_pairs: Vec<ElementValuePair>,
}

/// Type annotation target info.
#[derive(Debug, Clone)]
pub enum TypeAnnotationTarget {
    TypeParameter { index: u8 },
    Supertype { supertype_index: u16 },
    TypeParameterBound { type_parameter_index: u8, bound_index: u8 },
    Empty,
    FormalParameter { index: u8 },
    Throws { throws_type_index: u16 },
    Localvar { table: Vec<LocalVarTargetEntry> },
    Catch { exception_table_index: u16 },
    Offset { offset: u16 },
    TypeArgument { offset: u16, type_argument_index: u8 },
}

/// Local variable target entry for type annotations.
#[derive(Debug, Clone)]
pub struct LocalVarTargetEntry {
    pub start_pc: u16,
    pub length: u16,
    pub index: u16,
}

/// Type path entry.
#[derive(Debug, Clone)]
pub struct TypePathEntry {
    pub type_path_kind: u8,
    pub type_argument_index: u8,
}

/// Bootstrap method entry (JVMS 4.7.23).
#[derive(Debug, Clone)]
pub struct BootstrapMethod {
    pub bootstrap_method_ref: u16,
    pub bootstrap_arguments: Vec<u16>,
}

/// Method parameter entry (JVMS 4.7.24).
#[derive(Debug, Clone)]
pub struct MethodParameter {
    pub name_index: u16,
    pub access_flags: AccessFlags,
}

// ============================================================================
// Module Structures (Java 9+)
// ============================================================================

/// Module attribute (JVMS 4.7.25).
#[derive(Debug, Clone)]
pub struct ModuleAttribute {
    pub module_name_index: u16,
    pub module_flags: AccessFlags,
    pub module_version_index: u16,
    pub requires: Vec<ModuleRequire>,
    pub exports: Vec<ModuleExport>,
    pub opens: Vec<ModuleOpen>,
    pub uses: Vec<u16>,
    pub provides: Vec<ModuleProvide>,
}

/// Module requires entry.
#[derive(Debug, Clone)]
pub struct ModuleRequire {
    pub requires_index: u16,
    pub requires_flags: AccessFlags,
    pub requires_version_index: u16,
}

/// Module exports entry.
#[derive(Debug, Clone)]
pub struct ModuleExport {
    pub exports_index: u16,
    pub exports_flags: AccessFlags,
    pub exports_to_index: Vec<u16>,
}

/// Module opens entry.
#[derive(Debug, Clone)]
pub struct ModuleOpen {
    pub opens_index: u16,
    pub opens_flags: AccessFlags,
    pub opens_to_index: Vec<u16>,
}

/// Module provides entry.
#[derive(Debug, Clone)]
pub struct ModuleProvide {
    pub provides_index: u16,
    pub provides_with_index: Vec<u16>,
}

/// Record component (JVMS 4.7.30, Java 16+).
#[derive(Debug, Clone)]
pub struct RecordComponent {
    pub name_index: u16,
    pub descriptor_index: u16,
    pub attributes: Vec<Attribute>,
}

// ============================================================================
// Error Type
// ============================================================================

#[derive(Debug, Clone)]
pub enum ClassError {
    InvalidMagic,
    TruncatedData,
    InvalidConstantPool,
    InvalidAttribute,
    InvalidUtf8(String),
    NomError(String),
}

impl std::fmt::Display for ClassError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClassError::InvalidMagic => write!(f, "Invalid Java class magic"),
            ClassError::TruncatedData => write!(f, "Truncated class file data"),
            ClassError::InvalidConstantPool => write!(f, "Invalid constant pool entry"),
            ClassError::InvalidAttribute => write!(f, "Invalid attribute"),
            ClassError::InvalidUtf8(s) => write!(f, "Invalid UTF-8: {}", s),
            ClassError::NomError(s) => write!(f, "Parse error: {}", s),
        }
    }
}

impl std::error::Error for ClassError {}

impl From<nom::Err<nom::error::Error<&[u8]>>> for ClassError {
    fn from(e: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        ClassError::NomError(format!("{:?}", e))
    }
}

pub type ClassResult<T> = Result<T, ClassError>;

// ============================================================================
// Nom Parsers: Constant Pool
// ============================================================================

fn parse_cp_entry_utf8(input: &[u8]) -> IResult<&[u8], ConstantPoolEntry> {
    let (input, len) = be_u16(input)?;
    let (input, bytes) = take(len)(input)?;
    let value = String::from_utf8_lossy(bytes).to_string();
    Ok((input, ConstantPoolEntry::Utf8 { value }))
}

fn parse_cp_entry_integer(input: &[u8]) -> IResult<&[u8], ConstantPoolEntry> {
    let (input, val) = be_u32(input)?;
    Ok((input, ConstantPoolEntry::Integer { value: val as i32 }))
}

fn parse_cp_entry_float(input: &[u8]) -> IResult<&[u8], ConstantPoolEntry> {
    let (input, val) = be_u32(input)?;
    Ok((input, ConstantPoolEntry::Float { value: f32::from_bits(val) }))
}

fn parse_cp_entry_long(input: &[u8]) -> IResult<&[u8], ConstantPoolEntry> {
    let (input, high) = be_u32(input)?;
    let (input, low) = be_u32(input)?;
    Ok((input, ConstantPoolEntry::Long { value: ((high as i64) << 32) | (low as i64) }))
}

fn parse_cp_entry_double(input: &[u8]) -> IResult<&[u8], ConstantPoolEntry> {
    let (input, high) = be_u32(input)?;
    let (input, low) = be_u32(input)?;
    let bits = ((high as u64) << 32) | (low as u64);
    Ok((input, ConstantPoolEntry::Double { value: f64::from_bits(bits) }))
}

fn parse_cp_entry_class(input: &[u8]) -> IResult<&[u8], ConstantPoolEntry> {
    let (input, name_index) = be_u16(input)?;
    Ok((input, ConstantPoolEntry::Class { name_index }))
}

fn parse_cp_entry_string(input: &[u8]) -> IResult<&[u8], ConstantPoolEntry> {
    let (input, string_index) = be_u16(input)?;
    Ok((input, ConstantPoolEntry::String { string_index }))
}

fn parse_cp_entry_ref(input: &[u8], kind: u8) -> IResult<&[u8], ConstantPoolEntry> {
    let (input, class_index) = be_u16(input)?;
    let (input, name_and_type_index) = be_u16(input)?;
    let entry = match kind {
        CONSTANT_FIELDREF => ConstantPoolEntry::Fieldref { class_index, name_and_type_index },
        CONSTANT_METHODREF => ConstantPoolEntry::Methodref { class_index, name_and_type_index },
        CONSTANT_INTERFACE_METHODREF => ConstantPoolEntry::InterfaceMethodref { class_index, name_and_type_index },
        _ => unreachable!(),
    };
    Ok((input, entry))
}

fn parse_cp_entry_name_and_type(input: &[u8]) -> IResult<&[u8], ConstantPoolEntry> {
    let (input, name_index) = be_u16(input)?;
    let (input, descriptor_index) = be_u16(input)?;
    Ok((input, ConstantPoolEntry::NameAndType { name_index, descriptor_index }))
}

fn parse_cp_entry_method_handle(input: &[u8]) -> IResult<&[u8], ConstantPoolEntry> {
    let (input, reference_kind) = be_u8(input)?;
    let (input, reference_index) = be_u16(input)?;
    Ok((input, ConstantPoolEntry::MethodHandle { reference_kind, reference_index }))
}

fn parse_cp_entry_method_type(input: &[u8]) -> IResult<&[u8], ConstantPoolEntry> {
    let (input, descriptor_index) = be_u16(input)?;
    Ok((input, ConstantPoolEntry::MethodType { descriptor_index }))
}

fn parse_cp_entry_invoke_dynamic(input: &[u8], kind: u8) -> IResult<&[u8], ConstantPoolEntry> {
    let (input, bootstrap_method_attr_index) = be_u16(input)?;
    let (input, name_and_type_index) = be_u16(input)?;
    let entry = match kind {
        CONSTANT_DYNAMIC => ConstantPoolEntry::Dynamic { bootstrap_method_attr_index, name_and_type_index },
        CONSTANT_INVOKE_DYNAMIC => ConstantPoolEntry::InvokeDynamic { bootstrap_method_attr_index, name_and_type_index },
        _ => unreachable!(),
    };
    Ok((input, entry))
}

fn parse_cp_entry_module(input: &[u8]) -> IResult<&[u8], ConstantPoolEntry> {
    let (input, name_index) = be_u16(input)?;
    Ok((input, ConstantPoolEntry::Module { name_index }))
}

fn parse_cp_entry_package(input: &[u8]) -> IResult<&[u8], ConstantPoolEntry> {
    let (input, name_index) = be_u16(input)?;
    Ok((input, ConstantPoolEntry::Package { name_index }))
}

fn parse_constant_pool(data: &[u8], pool_count: u16) -> ClassResult<Vec<Option<ConstantPoolEntry>>> {
    if pool_count < 1 {
        return Err(ClassError::InvalidConstantPool);
    }
    let mut pool: Vec<Option<ConstantPoolEntry>> = vec![None; pool_count as usize];
    let mut pos: usize = 0;
    let mut i: usize = 1;
    while i < pool_count as usize {
        if pos >= data.len() {
            return Err(ClassError::TruncatedData);
        }
        let tag = data[pos];
        pos += 1;
        let (entry, takes_two_slots) = match tag {
            CONSTANT_UTF8 => {
                let (_, e) = parse_cp_entry_utf8(&data[pos..]).map_err(|_| ClassError::InvalidConstantPool)?;
                (e, false)
            }
            CONSTANT_INTEGER => {
                let (_, e) = parse_cp_entry_integer(&data[pos..]).map_err(|_| ClassError::InvalidConstantPool)?;
                (e, false)
            }
            CONSTANT_FLOAT => {
                let (_, e) = parse_cp_entry_float(&data[pos..]).map_err(|_| ClassError::InvalidConstantPool)?;
                (e, false)
            }
            CONSTANT_LONG => {
                let (_, e) = parse_cp_entry_long(&data[pos..]).map_err(|_| ClassError::InvalidConstantPool)?;
                (e, true)
            }
            CONSTANT_DOUBLE => {
                let (_, e) = parse_cp_entry_double(&data[pos..]).map_err(|_| ClassError::InvalidConstantPool)?;
                (e, true)
            }
            CONSTANT_CLASS => {
                let (_, e) = parse_cp_entry_class(&data[pos..]).map_err(|_| ClassError::InvalidConstantPool)?;
                (e, false)
            }
            CONSTANT_STRING => {
                let (_, e) = parse_cp_entry_string(&data[pos..]).map_err(|_| ClassError::InvalidConstantPool)?;
                (e, false)
            }
            CONSTANT_FIELDREF | CONSTANT_METHODREF | CONSTANT_INTERFACE_METHODREF => {
                let (_, e) = parse_cp_entry_ref(&data[pos..], tag).map_err(|_| ClassError::InvalidConstantPool)?;
                (e, false)
            }
            CONSTANT_NAME_AND_TYPE => {
                let (_, e) = parse_cp_entry_name_and_type(&data[pos..]).map_err(|_| ClassError::InvalidConstantPool)?;
                (e, false)
            }
            CONSTANT_METHOD_HANDLE => {
                let (_, e) = parse_cp_entry_method_handle(&data[pos..]).map_err(|_| ClassError::InvalidConstantPool)?;
                (e, false)
            }
            CONSTANT_METHOD_TYPE => {
                let (_, e) = parse_cp_entry_method_type(&data[pos..]).map_err(|_| ClassError::InvalidConstantPool)?;
                (e, false)
            }
            CONSTANT_DYNAMIC | CONSTANT_INVOKE_DYNAMIC => {
                let (_, e) = parse_cp_entry_invoke_dynamic(&data[pos..], tag).map_err(|_| ClassError::InvalidConstantPool)?;
                (e, false)
            }
            CONSTANT_MODULE => {
                let (_, e) = parse_cp_entry_module(&data[pos..]).map_err(|_| ClassError::InvalidConstantPool)?;
                (e, false)
            }
            CONSTANT_PACKAGE => {
                let (_, e) = parse_cp_entry_package(&data[pos..]).map_err(|_| ClassError::InvalidConstantPool)?;
                (e, false)
            }
            _ => return Err(ClassError::InvalidConstantPool),
        };

        // Calculate consumed bytes
        let consumed = consumed_bytes_for_tag(tag, &data[pos..]);
        pos += consumed;

        pool[i] = Some(entry.clone());
        i += 1;

        // Long and Double take two slots
        if takes_two_slots {
            if i < pool_count as usize {
                pool[i] = Some(entry);
                i += 1;
            }
        }
    }
    Ok(pool)
}

fn consumed_bytes_for_tag(tag: u8, rest: &[u8]) -> usize {
    if rest.is_empty() { return 0; }
    match tag {
        CONSTANT_UTF8 => {
            if rest.len() < 2 { return 0; }
            let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
            2 + len
        }
        CONSTANT_INTEGER | CONSTANT_FLOAT => 4,
        CONSTANT_LONG | CONSTANT_DOUBLE => 8,
        CONSTANT_CLASS | CONSTANT_STRING => 2,
        CONSTANT_FIELDREF | CONSTANT_METHODREF | CONSTANT_INTERFACE_METHODREF => 4,
        CONSTANT_NAME_AND_TYPE => 4,
        CONSTANT_METHOD_HANDLE => 3,
        CONSTANT_METHOD_TYPE => 2,
        CONSTANT_DYNAMIC | CONSTANT_INVOKE_DYNAMIC => 4,
        CONSTANT_MODULE | CONSTANT_PACKAGE => 2,
        _ => 0,
    }
}

// ============================================================================
// Constant Pool Helpers
// ============================================================================

fn cp_utf8(pool: &[Option<ConstantPoolEntry>], idx: u16) -> Option<&str> {
    match pool.get(idx as usize)? {
        Some(ConstantPoolEntry::Utf8 { value }) => Some(value.as_str()),
        _ => None,
    }
}

fn cp_utf8_cloned(pool: &[Option<ConstantPoolEntry>], idx: u16) -> Option<String> {
    cp_utf8(pool, idx).map(|s| s.to_string())
}

fn cp_class_name<'a>(pool: &'a [Option<ConstantPoolEntry>], idx: u16) -> Option<&'a str> {
    match pool.get(idx as usize)? {
        Some(ConstantPoolEntry::Class { name_index }) => cp_utf8(pool, *name_index),
        _ => None,
    }
}

fn cp_class_name_cloned(pool: &[Option<ConstantPoolEntry>], idx: u16) -> Option<String> {
    cp_class_name(pool, idx).map(|s| s.to_string())
}

// ============================================================================
// Nom Parsers: Attributes
// ============================================================================

fn parse_attributes(
    data: &[u8], pos: &mut usize, pool: &[Option<ConstantPoolEntry>],
) -> ClassResult<Vec<Attribute>> {
    if *pos + 2 > data.len() { return Ok(Vec::new()); }
    let count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
    *pos += 2;
    let mut attrs = Vec::with_capacity(count);
    for _ in 0..count {
        if *pos + 6 > data.len() { break; }
        let name_idx = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        let len = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]) as usize;
        *pos += 4;
        let attr_name = cp_utf8_cloned(pool, name_idx).unwrap_or_default();
        let attr_start = *pos;
        if let Some(attr) = parse_single_attribute(data, pos, pool, &attr_name, len) {
            attrs.push(attr);
        }
        *pos = attr_start + len;
    }
    Ok(attrs)
}

fn parse_single_attribute(
    data: &[u8], pos: &mut usize, pool: &[Option<ConstantPoolEntry>],
    name: &str, len: usize,
) -> Option<Attribute> {
    if *pos + len > data.len() { return None; }
    match name {
        "Code" => {
            if *pos + 12 > data.len() { return None; }
            let max_stack = u16::from_be_bytes([data[*pos], data[*pos + 1]]); *pos += 2;
            let max_locals = u16::from_be_bytes([data[*pos], data[*pos + 1]]); *pos += 2;
            let code_len = u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]]) as usize;
            *pos += 4;
            if *pos + code_len > data.len() { return None; }
            let code = data[*pos..*pos + code_len].to_vec();
            *pos += code_len;
            if *pos + 2 > data.len() { return None; }
            let exc_count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            let mut exception_table = Vec::with_capacity(exc_count);
            for _ in 0..exc_count {
                if *pos + 8 > data.len() { break; }
                exception_table.push(ExceptionTableEntry {
                    start_pc: u16::from_be_bytes([data[*pos], data[*pos + 1]]),
                    end_pc: u16::from_be_bytes([data[*pos + 2], data[*pos + 3]]),
                    handler_pc: u16::from_be_bytes([data[*pos + 4], data[*pos + 5]]),
                    catch_type_index: u16::from_be_bytes([data[*pos + 6], data[*pos + 7]]),
                });
                *pos += 8;
            }
            let attrs = parse_attributes(data, pos, pool).unwrap_or_default();
            Some(Attribute::Code(Box::new(CodeAttribute {
                max_stack, max_locals, code, exception_table, attributes: attrs,
            })))
        }
        "StackMapTable" => {
            if *pos + 2 > data.len() { return None; }
            let frame_count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            let mut frames = Vec::with_capacity(frame_count);
            for _ in 0..frame_count {
                if let Some(frame) = parse_stack_map_frame(data, pos) {
                    frames.push(frame);
                }
            }
            Some(Attribute::StackMapTable(frames))
        }
        "Exceptions" => {
            if *pos + 2 > data.len() { return None; }
            let count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            let mut indices = Vec::with_capacity(count);
            for _ in 0..count {
                if *pos + 2 > data.len() { break; }
                indices.push(u16::from_be_bytes([data[*pos], data[*pos + 1]]));
                *pos += 2;
            }
            Some(Attribute::Exceptions(indices))
        }
        "InnerClasses" => {
            if *pos + 2 > data.len() { return None; }
            let count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            let mut classes = Vec::with_capacity(count);
            for _ in 0..count {
                if *pos + 8 > data.len() { break; }
                classes.push(InnerClassInfo {
                    inner_class_info_index: u16::from_be_bytes([data[*pos], data[*pos + 1]]),
                    outer_class_info_index: u16::from_be_bytes([data[*pos + 2], data[*pos + 3]]),
                    inner_name_index: u16::from_be_bytes([data[*pos + 4], data[*pos + 5]]),
                    inner_class_access_flags: AccessFlags::from_bits_truncate(
                        u16::from_be_bytes([data[*pos + 6], data[*pos + 7]])),
                });
                *pos += 8;
            }
            Some(Attribute::InnerClasses(classes))
        }
        "EnclosingMethod" => {
            if *pos + 4 > data.len() { return None; }
            let class_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            let method_index = u16::from_be_bytes([data[*pos + 2], data[*pos + 3]]);
            *pos += 4;
            Some(Attribute::EnclosingMethod { class_index, method_index })
        }
        "Synthetic" => Some(Attribute::Synthetic),
        "Signature" => {
            if *pos + 2 > data.len() { return None; }
            let signature_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Some(Attribute::Signature { signature_index })
        }
        "SourceFile" => {
            if *pos + 2 > data.len() { return None; }
            let sourcefile_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Some(Attribute::SourceFile { sourcefile_index })
        }
        "SourceDebugExtension" => {
            let debug_extension = if *pos + len <= data.len() {
                data[*pos..*pos + len].to_vec()
            } else { Vec::new() };
            *pos += len;
            Some(Attribute::SourceDebugExtension { debug_extension })
        }
        "LineNumberTable" => {
            if *pos + 2 > data.len() { return None; }
            let count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            let mut table = Vec::with_capacity(count);
            for _ in 0..count {
                if *pos + 4 > data.len() { break; }
                table.push(LineNumberEntry {
                    start_pc: u16::from_be_bytes([data[*pos], data[*pos + 1]]),
                    line_number: u16::from_be_bytes([data[*pos + 2], data[*pos + 3]]),
                });
                *pos += 4;
            }
            Some(Attribute::LineNumberTable(table))
        }
        "LocalVariableTable" => {
            if *pos + 2 > data.len() { return None; }
            let count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            let mut table = Vec::with_capacity(count);
            for _ in 0..count {
                if *pos + 10 > data.len() { break; }
                table.push(LocalVariableEntry {
                    start_pc: u16::from_be_bytes([data[*pos], data[*pos + 1]]),
                    length: u16::from_be_bytes([data[*pos + 2], data[*pos + 3]]),
                    name_index: u16::from_be_bytes([data[*pos + 4], data[*pos + 5]]),
                    descriptor_index: u16::from_be_bytes([data[*pos + 6], data[*pos + 7]]),
                    index: u16::from_be_bytes([data[*pos + 8], data[*pos + 9]]),
                });
                *pos += 10;
            }
            Some(Attribute::LocalVariableTable(table))
        }
        "LocalVariableTypeTable" => {
            if *pos + 2 > data.len() { return None; }
            let count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            let mut table = Vec::with_capacity(count);
            for _ in 0..count {
                if *pos + 10 > data.len() { break; }
                table.push(LocalVariableTypeEntry {
                    start_pc: u16::from_be_bytes([data[*pos], data[*pos + 1]]),
                    length: u16::from_be_bytes([data[*pos + 2], data[*pos + 3]]),
                    name_index: u16::from_be_bytes([data[*pos + 4], data[*pos + 5]]),
                    signature_index: u16::from_be_bytes([data[*pos + 6], data[*pos + 7]]),
                    index: u16::from_be_bytes([data[*pos + 8], data[*pos + 9]]),
                });
                *pos += 10;
            }
            Some(Attribute::LocalVariableTypeTable(table))
        }
        "Deprecated" => Some(Attribute::Deprecated),
        "RuntimeVisibleAnnotations" => {
            let annotations = parse_annotations(data, pos)?;
            Some(Attribute::RuntimeVisibleAnnotations(annotations))
        }
        "RuntimeInvisibleAnnotations" => {
            let annotations = parse_annotations(data, pos)?;
            Some(Attribute::RuntimeInvisibleAnnotations(annotations))
        }
        "RuntimeVisibleParameterAnnotations" => {
            let param_anns = parse_parameter_annotations(data, pos)?;
            Some(Attribute::RuntimeVisibleParameterAnnotations(param_anns))
        }
        "RuntimeInvisibleParameterAnnotations" => {
            let param_anns = parse_parameter_annotations(data, pos)?;
            Some(Attribute::RuntimeInvisibleParameterAnnotations(param_anns))
        }
        "BootstrapMethods" => {
            if *pos + 2 > data.len() { return None; }
            let count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            let mut methods = Vec::with_capacity(count);
            for _ in 0..count {
                if *pos + 4 > data.len() { break; }
                let bootstrap_method_ref = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
                let arg_count = u16::from_be_bytes([data[*pos + 2], data[*pos + 3]]) as usize;
                *pos += 4;
                let mut args = Vec::with_capacity(arg_count);
                for _ in 0..arg_count {
                    if *pos + 2 > data.len() { break; }
                    args.push(u16::from_be_bytes([data[*pos], data[*pos + 1]]));
                    *pos += 2;
                }
                methods.push(BootstrapMethod { bootstrap_method_ref, bootstrap_arguments: args });
            }
            Some(Attribute::BootstrapMethods(methods))
        }
        "MethodParameters" => {
            let count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            let mut params = Vec::with_capacity(count);
            for _ in 0..count {
                if *pos + 4 > data.len() { break; }
                params.push(MethodParameter {
                    name_index: u16::from_be_bytes([data[*pos], data[*pos + 1]]),
                    access_flags: AccessFlags::from_bits_truncate(
                        u16::from_be_bytes([data[*pos + 2], data[*pos + 3]])),
                });
                *pos += 4;
            }
            Some(Attribute::MethodParameters(params))
        }
        "Module" => {
            parse_module_attribute(data, pos).map(Attribute::Module)
        }
        "ModulePackages" => {
            if *pos + 2 > data.len() { return None; }
            let count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            let mut packages = Vec::with_capacity(count);
            for _ in 0..count {
                if *pos + 2 > data.len() { break; }
                packages.push(u16::from_be_bytes([data[*pos], data[*pos + 1]]));
                *pos += 2;
            }
            Some(Attribute::ModulePackages(packages))
        }
        "ModuleMainClass" => {
            if *pos + 2 > data.len() { return None; }
            let main_class_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Some(Attribute::ModuleMainClass { main_class_index })
        }
        "NestHost" => {
            if *pos + 2 > data.len() { return None; }
            let host_class_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Some(Attribute::NestHost { host_class_index })
        }
        "NestMembers" => {
            if *pos + 2 > data.len() { return None; }
            let count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            let mut members = Vec::with_capacity(count);
            for _ in 0..count {
                if *pos + 2 > data.len() { break; }
                members.push(u16::from_be_bytes([data[*pos], data[*pos + 1]]));
                *pos += 2;
            }
            Some(Attribute::NestMembers(members))
        }
        "Record" => {
            if *pos + 2 > data.len() { return None; }
            let count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            let mut components = Vec::with_capacity(count);
            for _ in 0..count {
                if *pos + 4 > data.len() { break; }
                let name_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
                let descriptor_index = u16::from_be_bytes([data[*pos + 2], data[*pos + 3]]);
                *pos += 4;
                let attrs = parse_attributes(data, pos, pool).unwrap_or_default();
                components.push(RecordComponent { name_index, descriptor_index, attributes: attrs });
            }
            Some(Attribute::Record(components))
        }
        "PermittedSubclasses" => {
            if *pos + 2 > data.len() { return None; }
            let count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            let mut classes = Vec::with_capacity(count);
            for _ in 0..count {
                if *pos + 2 > data.len() { break; }
                classes.push(u16::from_be_bytes([data[*pos], data[*pos + 1]]));
                *pos += 2;
            }
            Some(Attribute::PermittedSubclasses(classes))
        }
        "AnnotationDefault" => {
            let default_value = parse_element_value(data, pos)?;
            Some(Attribute::AnnotationDefault { default_value })
        }
        "RuntimeVisibleTypeAnnotations" => {
            let anns = parse_type_annotations(data, pos)?;
            Some(Attribute::RuntimeVisibleTypeAnnotations(anns))
        }
        "RuntimeInvisibleTypeAnnotations" => {
            let anns = parse_type_annotations(data, pos)?;
            Some(Attribute::RuntimeInvisibleTypeAnnotations(anns))
        }
        _ => {
            // Unknown attribute
            let attr_data = if *pos + len <= data.len() {
                data[*pos..*pos + len].to_vec()
            } else { Vec::new() };
            *pos += len;
            Some(Attribute::Unknown { name: name.to_string(), data: attr_data })
        }
    }
}

// ============================================================================
// Nom Parsers: StackMapFrame
// ============================================================================

fn parse_stack_map_frame(data: &[u8], pos: &mut usize) -> Option<StackMapFrame> {
    if *pos >= data.len() { return None; }
    let frame_type = data[*pos];
    *pos += 1;
    if frame_type <= FRAME_SAME_MAX {
        Some(StackMapFrame::Same { offset_delta: frame_type })
    } else if frame_type <= FRAME_SAME_LOCALS_1_STACK_MAX {
        let stack = parse_verification_type(data, pos)?;
        Some(StackMapFrame::SameLocals1StackItem { offset_delta: frame_type - 64, stack })
    } else if frame_type == FRAME_SAME_LOCALS_1_STACK_EXTENDED {
        if *pos + 2 > data.len() { return None; }
        let delta = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        let stack = parse_verification_type(data, pos)?;
        Some(StackMapFrame::SameLocals1StackItemExtended { offset_delta: delta, stack })
    } else if (FRAME_CHOP_MIN..=FRAME_CHOP_MAX).contains(&frame_type) {
        if *pos + 2 > data.len() { return None; }
        let delta = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        Some(StackMapFrame::Chop { offset_delta: delta, chopped: 251 - frame_type })
    } else if frame_type == FRAME_SAME_EXTENDED {
        if *pos + 2 > data.len() { return None; }
        let delta = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        Some(StackMapFrame::SameExtended { offset_delta: delta })
    } else if (FRAME_APPEND_MIN..=FRAME_APPEND_MAX).contains(&frame_type) {
        if *pos + 2 > data.len() { return None; }
        let delta = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        let k = (frame_type - 251) as usize;
        let mut locals = Vec::with_capacity(k);
        for _ in 0..k {
            locals.push(parse_verification_type(data, pos)?);
        }
        Some(StackMapFrame::Append { offset_delta: delta, locals })
    } else if frame_type == FRAME_FULL {
        if *pos + 4 > data.len() { return None; }
        let delta = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        let local_count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
        *pos += 2;
        let mut locals = Vec::with_capacity(local_count);
        for _ in 0..local_count {
            locals.push(parse_verification_type(data, pos)?);
        }
        if *pos + 2 > data.len() { return None; }
        let stack_count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
        *pos += 2;
        let mut stack = Vec::with_capacity(stack_count);
        for _ in 0..stack_count {
            stack.push(parse_verification_type(data, pos)?);
        }
        Some(StackMapFrame::Full { offset_delta: delta, locals, stack })
    } else {
        None
    }
}

fn parse_verification_type(data: &[u8], pos: &mut usize) -> Option<VerificationTypeInfo> {
    if *pos >= data.len() { return None; }
    let tag = data[*pos];
    *pos += 1;
    match tag {
        VERIFY_TOP => Some(VerificationTypeInfo::Top),
        VERIFY_INTEGER => Some(VerificationTypeInfo::Integer),
        VERIFY_FLOAT => Some(VerificationTypeInfo::Float),
        VERIFY_DOUBLE => Some(VerificationTypeInfo::Double),
        VERIFY_LONG => Some(VerificationTypeInfo::Long),
        VERIFY_NULL => Some(VerificationTypeInfo::Null),
        VERIFY_UNINITIALIZED_THIS => Some(VerificationTypeInfo::UninitializedThis),
        VERIFY_OBJECT => {
            if *pos + 2 > data.len() { return None; }
            let cpool_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Some(VerificationTypeInfo::Object { cpool_index })
        }
        VERIFY_UNINITIALIZED => {
            if *pos + 2 > data.len() { return None; }
            let offset = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Some(VerificationTypeInfo::Uninitialized { offset })
        }
        _ => None,
    }
}

// ============================================================================
// Nom Parsers: Annotations
// ============================================================================

fn parse_annotations(data: &[u8], pos: &mut usize) -> Option<Vec<Annotation>> {
    if *pos + 2 > data.len() { return None; }
    let count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
    *pos += 2;
    let mut annotations = Vec::with_capacity(count);
    for _ in 0..count {
        if *pos + 4 > data.len() { return None; }
        let type_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        let pair_count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
        *pos += 2;
        let mut pairs = Vec::with_capacity(pair_count);
        for _ in 0..pair_count {
            if *pos + 2 > data.len() { return None; }
            let element_name_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            let value = parse_element_value(data, pos)?;
            pairs.push(ElementValuePair { element_name_index, value });
        }
        annotations.push(Annotation { type_index, element_value_pairs: pairs });
    }
    Some(annotations)
}

fn parse_parameter_annotations(data: &[u8], pos: &mut usize) -> Option<Vec<Vec<Annotation>>> {
    if *pos + 1 > data.len() { return None; }
    let num_params = data[*pos] as usize;
    *pos += 1;
    let mut param_anns = Vec::with_capacity(num_params);
    for _ in 0..num_params {
        let anns = parse_annotations(data, pos)?;
        param_anns.push(anns);
    }
    Some(param_anns)
}

fn parse_element_value(data: &[u8], pos: &mut usize) -> Option<ElementValue> {
    if *pos >= data.len() { return None; }
    let tag = data[*pos];
    *pos += 1;
    match tag as char {
        'B' | 'C' | 'D' | 'F' | 'I' | 'J' | 'S' | 'Z' | 's' => {
            if *pos + 2 > data.len() { return None; }
            let const_value_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Some(ElementValue::ConstValue { tag, const_value_index })
        }
        'e' => {
            if *pos + 4 > data.len() { return None; }
            let type_name_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            let const_name_index = u16::from_be_bytes([data[*pos + 2], data[*pos + 3]]);
            *pos += 4;
            Some(ElementValue::EnumConstValue { type_name_index, const_name_index })
        }
        'c' => {
            if *pos + 2 > data.len() { return None; }
            let class_info_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Some(ElementValue::ClassInfo { class_info_index })
        }
        '@' => {
            let anns = parse_annotations(data, pos)?;
            anns.into_iter().next().map(|a| ElementValue::Annotation(Box::new(a)))
        }
        '[' => {
            if *pos + 2 > data.len() { return None; }
            let count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                values.push(parse_element_value(data, pos)?);
            }
            Some(ElementValue::Array { values })
        }
        _ => None,
    }
}

fn parse_type_annotations(data: &[u8], pos: &mut usize) -> Option<Vec<TypeAnnotation>> {
    if *pos + 2 > data.len() { return None; }
    let count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
    *pos += 2;
    let mut annotations = Vec::with_capacity(count);
    for _ in 0..count {
        if *pos + 2 > data.len() { return None; }
        let target_type = data[*pos];
        *pos += 1;
        let target_info = parse_type_annotation_target(data, pos, target_type)?;
        let path_len = data[*pos] as usize;
        *pos += 1;
        let mut path = Vec::with_capacity(path_len);
        for _ in 0..path_len {
            if *pos + 2 > data.len() { return None; }
            path.push(TypePathEntry {
                type_path_kind: data[*pos],
                type_argument_index: data[*pos + 1],
            });
            *pos += 2;
        }
        if *pos + 4 > data.len() { return None; }
        let type_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        *pos += 2;
        let pair_count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
        *pos += 2;
        let mut pairs = Vec::with_capacity(pair_count);
        for _ in 0..pair_count {
            if *pos + 2 > data.len() { return None; }
            let element_name_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            pairs.push(ElementValuePair { element_name_index, value: parse_element_value(data, pos)? });
        }
        annotations.push(TypeAnnotation {
            target_type, target_info, target_path: path, type_index, element_value_pairs: pairs,
        });
    }
    Some(annotations)
}

fn parse_type_annotation_target(data: &[u8], pos: &mut usize, target_type: u8) -> Option<TypeAnnotationTarget> {
    match target_type {
        0x00 | 0x01 => {
            let index = data[*pos]; *pos += 1;
            Some(TypeAnnotationTarget::TypeParameter { index })
        }
        0x10 => {
            if *pos + 2 > data.len() { return None; }
            let supertype_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Some(TypeAnnotationTarget::Supertype { supertype_index })
        }
        0x11 | 0x12 => {
            let type_parameter_index = data[*pos]; *pos += 1;
            let bound_index = data[*pos]; *pos += 1;
            Some(TypeAnnotationTarget::TypeParameterBound { type_parameter_index, bound_index })
        }
        0x13 | 0x14 | 0x15 => Some(TypeAnnotationTarget::Empty),
        0x16 => {
            let index = data[*pos]; *pos += 1;
            Some(TypeAnnotationTarget::FormalParameter { index })
        }
        0x17 => {
            if *pos + 2 > data.len() { return None; }
            let throws_type_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Some(TypeAnnotationTarget::Throws { throws_type_index })
        }
        0x40 | 0x41 => {
            if *pos + 2 > data.len() { return None; }
            let count = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
            *pos += 2;
            let mut table = Vec::with_capacity(count);
            for _ in 0..count {
                if *pos + 6 > data.len() { return None; }
                table.push(LocalVarTargetEntry {
                    start_pc: u16::from_be_bytes([data[*pos], data[*pos + 1]]),
                    length: u16::from_be_bytes([data[*pos + 2], data[*pos + 3]]),
                    index: u16::from_be_bytes([data[*pos + 4], data[*pos + 5]]),
                });
                *pos += 6;
            }
            Some(TypeAnnotationTarget::Localvar { table })
        }
        0x42 => {
            if *pos + 2 > data.len() { return None; }
            let exception_table_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Some(TypeAnnotationTarget::Catch { exception_table_index })
        }
        0x43 | 0x44 | 0x45 | 0x46 => {
            if *pos + 2 > data.len() { return None; }
            let offset = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            Some(TypeAnnotationTarget::Offset { offset })
        }
        0x47 | 0x48 | 0x49 | 0x4A | 0x4B => {
            if *pos + 3 > data.len() { return None; }
            let offset = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
            *pos += 2;
            let type_argument_index = data[*pos]; *pos += 1;
            Some(TypeAnnotationTarget::TypeArgument { offset, type_argument_index })
        }
        _ => Some(TypeAnnotationTarget::Empty),
    }
}

// ============================================================================
// Nom Parsers: Module Attribute
// ============================================================================

fn parse_module_attribute(data: &[u8], pos: &mut usize) -> Option<ModuleAttribute> {
    if *pos + 6 > data.len() { return None; }
    let module_name_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    let module_flags = AccessFlags::from_bits_truncate(u16::from_be_bytes([data[*pos + 2], data[*pos + 3]]));
    let module_version_index = u16::from_be_bytes([data[*pos + 4], data[*pos + 5]]);
    *pos += 6;

    // requires
    let req_count = if *pos + 2 > data.len() { return None; } else { u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize };
    *pos += 2;
    let mut requires = Vec::with_capacity(req_count);
    for _ in 0..req_count {
        if *pos + 6 > data.len() { break; }
        requires.push(ModuleRequire {
            requires_index: u16::from_be_bytes([data[*pos], data[*pos + 1]]),
            requires_flags: AccessFlags::from_bits_truncate(u16::from_be_bytes([data[*pos + 2], data[*pos + 3]])),
            requires_version_index: u16::from_be_bytes([data[*pos + 4], data[*pos + 5]]),
        });
        *pos += 6;
    }

    // exports
    let exp_count = if *pos + 2 > data.len() { return None; } else { u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize };
    *pos += 2;
    let mut exports = Vec::with_capacity(exp_count);
    for _ in 0..exp_count {
        if *pos + 6 > data.len() { break; }
        let exports_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        let exports_flags = AccessFlags::from_bits_truncate(u16::from_be_bytes([data[*pos + 2], data[*pos + 3]]));
        let to_count = u16::from_be_bytes([data[*pos + 4], data[*pos + 5]]) as usize;
        *pos += 6;
        let mut exports_to = Vec::with_capacity(to_count);
        for _ in 0..to_count {
            if *pos + 2 > data.len() { break; }
            exports_to.push(u16::from_be_bytes([data[*pos], data[*pos + 1]]));
            *pos += 2;
        }
        exports.push(ModuleExport { exports_index, exports_flags, exports_to_index: exports_to });
    }

    // opens
    let opens_count = if *pos + 2 > data.len() { return None; } else { u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize };
    *pos += 2;
    let mut opens = Vec::with_capacity(opens_count);
    for _ in 0..opens_count {
        if *pos + 6 > data.len() { break; }
        let opens_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        let opens_flags = AccessFlags::from_bits_truncate(u16::from_be_bytes([data[*pos + 2], data[*pos + 3]]));
        let to_count = u16::from_be_bytes([data[*pos + 4], data[*pos + 5]]) as usize;
        *pos += 6;
        let mut opens_to = Vec::with_capacity(to_count);
        for _ in 0..to_count {
            if *pos + 2 > data.len() { break; }
            opens_to.push(u16::from_be_bytes([data[*pos], data[*pos + 1]]));
            *pos += 2;
        }
        opens.push(ModuleOpen { opens_index, opens_flags, opens_to_index: opens_to });
    }

    // uses
    let uses_count = if *pos + 2 > data.len() { return None; } else { u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize };
    *pos += 2;
    let mut uses = Vec::with_capacity(uses_count);
    for _ in 0..uses_count {
        if *pos + 2 > data.len() { break; }
        uses.push(u16::from_be_bytes([data[*pos], data[*pos + 1]]));
        *pos += 2;
    }

    // provides
    let prov_count = if *pos + 2 > data.len() { return None; } else { u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize };
    *pos += 2;
    let mut provides = Vec::with_capacity(prov_count);
    for _ in 0..prov_count {
        if *pos + 4 > data.len() { break; }
        let provides_index = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
        let with_count = u16::from_be_bytes([data[*pos + 2], data[*pos + 3]]) as usize;
        *pos += 4;
        let mut with_indices = Vec::with_capacity(with_count);
        for _ in 0..with_count {
            if *pos + 2 > data.len() { break; }
            with_indices.push(u16::from_be_bytes([data[*pos], data[*pos + 1]]));
            *pos += 2;
        }
        provides.push(ModuleProvide { provides_index, provides_with_index: with_indices });
    }

    Some(ModuleAttribute {
        module_name_index, module_flags, module_version_index,
        requires, exports, opens, uses, provides,
    })
}

// ============================================================================
// Main Parser
// ============================================================================

/// Parse a Java .class file from raw bytes.
pub fn parse_class(data: &[u8]) -> ClassResult<JavaClass> {
    if data.len() < 8 {
        return Err(ClassError::TruncatedData);
    }

    let mut pos: usize = 0;

    // Magic
    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic != CLASS_MAGIC {
        return Err(ClassError::InvalidMagic);
    }
    pos += 4;

    // Version
    if pos + 4 > data.len() { return Err(ClassError::TruncatedData); }
    let minor_version = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let major_version = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    pos += 4;

    // Constant pool
    if pos + 2 > data.len() { return Err(ClassError::TruncatedData); }
    let pool_count = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 2;
    let constant_pool = parse_constant_pool(&data[pos..], pool_count)?;
    // Advance past the constant pool
    let mut cp_pos = pos;
    for _ in 1..pool_count as usize {
        if cp_pos >= data.len() { break; }
        let tag = data[cp_pos];
        cp_pos += 1;
        let consumed = consumed_bytes_for_tag(tag, &data[cp_pos..]);
        cp_pos += consumed;
        // Long/Double take 2 slots - already handled in the loop counter by taking 2 entries
    }
    pos = cp_pos;

    // Access flags
    if pos + 2 > data.len() { return Err(ClassError::TruncatedData); }
    let access_flags = AccessFlags::from_bits_truncate(
        u16::from_be_bytes([data[pos], data[pos + 1]]));
    pos += 2;

    // This class, super class
    if pos + 4 > data.len() { return Err(ClassError::TruncatedData); }
    let this_class = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let super_class = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
    pos += 4;

    // Interfaces
    if pos + 2 > data.len() { return Err(ClassError::TruncatedData); }
    let interfaces_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let mut interfaces = Vec::with_capacity(interfaces_count);
    for _ in 0..interfaces_count {
        if pos + 2 > data.len() { break; }
        interfaces.push(u16::from_be_bytes([data[pos], data[pos + 1]]));
        pos += 2;
    }

    // Fields
    if pos + 2 > data.len() { return Err(ClassError::TruncatedData); }
    let fields_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let mut fields = Vec::with_capacity(fields_count);
    for _ in 0..fields_count {
        if pos + 8 > data.len() { break; }
        let f_access = AccessFlags::from_bits_truncate(
            u16::from_be_bytes([data[pos], data[pos + 1]]));
        let f_name_idx = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        let f_desc_idx = u16::from_be_bytes([data[pos + 4], data[pos + 5]]);
        pos += 6;
        let f_attrs = parse_attributes(data, &mut pos, &constant_pool).unwrap_or_default();
        let name = cp_utf8_cloned(&constant_pool, f_name_idx).unwrap_or_default();
        let descriptor = cp_utf8_cloned(&constant_pool, f_desc_idx).unwrap_or_default();
        fields.push(FieldInfo {
            access_flags: f_access, name_index: f_name_idx, descriptor_index: f_desc_idx,
            attributes: f_attrs, name, descriptor,
        });
    }

    // Methods
    if pos + 2 > data.len() { return Err(ClassError::TruncatedData); }
    let methods_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    let mut methods = Vec::with_capacity(methods_count);
    for _ in 0..methods_count {
        if pos + 6 > data.len() { break; }
        let m_access = AccessFlags::from_bits_truncate(
            u16::from_be_bytes([data[pos], data[pos + 1]]));
        let m_name_idx = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
        let m_desc_idx = u16::from_be_bytes([data[pos + 4], data[pos + 5]]);
        pos += 6;
        let m_attrs = parse_attributes(data, &mut pos, &constant_pool).unwrap_or_default();
        let name = cp_utf8_cloned(&constant_pool, m_name_idx).unwrap_or_default();
        let descriptor = cp_utf8_cloned(&constant_pool, m_desc_idx).unwrap_or_default();
        methods.push(MethodInfo {
            access_flags: m_access, name_index: m_name_idx, descriptor_index: m_desc_idx,
            attributes: m_attrs, name, descriptor,
        });
    }

    // Class-level attributes
    let attributes = parse_attributes(data, &mut pos, &constant_pool).unwrap_or_default();

    let class_name = cp_class_name_cloned(&constant_pool, this_class).unwrap_or_default();
    let super_class_name = cp_class_name_cloned(&constant_pool, super_class).unwrap_or_default();

    Ok(JavaClass {
        magic, minor_version, major_version, constant_pool,
        access_flags, this_class, super_class, interfaces,
        fields, methods, attributes, class_name, super_class_name,
    })
}

/// Check if data looks like a Java class file.
pub fn is_class(data: &[u8]) -> bool {
    if data.len() < 4 { return false; }
    u32::from_be_bytes([data[0], data[1], data[2], data[3]]) == CLASS_MAGIC
}

// ============================================================================
// JVM Bytecode Mnemonic Mapping
// ============================================================================

/// All JVM bytecode mnemonics indexed by opcode value (0x00..=0xFF).
/// Unknown opcodes return "unknown".
pub const JVM_BYTECODE_NAMES: [&str; 256] = [
    // 0x00 - 0x0F
    "nop", "aconst_null", "iconst_m1", "iconst_0",
    "iconst_1", "iconst_2", "iconst_3", "iconst_4",
    "iconst_5", "lconst_0", "lconst_1", "fconst_0",
    "fconst_1", "fconst_2", "dconst_0", "dconst_1",
    // 0x10 - 0x1F
    "bipush", "sipush", "ldc", "ldc_w",
    "ldc2_w", "iload", "lload", "fload",
    "dload", "aload", "iload_0", "iload_1",
    "iload_2", "iload_3", "lload_0", "lload_1",
    // 0x20 - 0x2F
    "lload_2", "lload_3", "fload_0", "fload_1",
    "fload_2", "fload_3", "dload_0", "dload_1",
    "dload_2", "dload_3", "aload_0", "aload_1",
    "aload_2", "aload_3", "iaload", "laload",
    // 0x30 - 0x3F
    "faload", "daload", "aaload", "baload",
    "caload", "saload", "istore", "lstore",
    "fstore", "dstore", "astore", "istore_0",
    "istore_1", "istore_2", "istore_3", "lstore_0",
    // 0x40 - 0x4F
    "lstore_1", "lstore_2", "lstore_3", "fstore_0",
    "fstore_1", "fstore_2", "fstore_3", "dstore_0",
    "dstore_1", "dstore_2", "dstore_3", "astore_0",
    "astore_1", "astore_2", "astore_3", "iastore",
    // 0x50 - 0x5F
    "lastore", "fastore", "dastore", "aastore",
    "bastore", "castore", "sastore", "pop",
    "pop2", "dup", "dup_x1", "dup_x2",
    "dup2", "dup2_x1", "dup2_x2", "swap",
    // 0x60 - 0x6F
    "iadd", "ladd", "fadd", "dadd",
    "isub", "lsub", "fsub", "dsub",
    "imul", "lmul", "fmul", "dmul",
    "idiv", "ldiv", "fdiv", "ddiv",
    // 0x70 - 0x7F
    "irem", "lrem", "frem", "drem",
    "ineg", "lneg", "fneg", "dneg",
    "ishl", "lshl", "ishr", "lshr",
    "iushr", "lushr", "iand", "land",
    // 0x80 - 0x8F
    "ior", "lor", "ixor", "lxor",
    "iinc", "i2l", "i2f", "i2d",
    "l2i", "l2f", "l2d", "f2i",
    "f2l", "f2d", "d2i", "d2l",
    // 0x90 - 0x9F
    "d2f", "i2b", "i2c", "i2s",
    "lcmp", "fcmpl", "fcmpg", "dcmpl",
    "dcmpg", "ifeq", "ifne", "iflt",
    "ifge", "ifgt", "ifle", "if_icmpeq",
    // 0xA0 - 0xAF
    "if_icmpne", "if_icmplt", "if_icmpge", "if_icmpgt",
    "if_icmple", "if_acmpeq", "if_acmpne", "goto",
    "jsr", "ret", "tableswitch", "lookupswitch",
    "ireturn", "lreturn", "freturn", "dreturn",
    // 0xB0 - 0xBF
    "areturn", "return", "getstatic", "putstatic",
    "getfield", "putfield", "invokevirtual", "invokespecial",
    "invokestatic", "invokeinterface", "invokedynamic", "new",
    "newarray", "anewarray", "arraylength", "athrow",
    // 0xC0 - 0xCF
    "checkcast", "instanceof", "monitorenter", "monitorexit",
    "wide", "multianewarray", "ifnull", "ifnonnull",
    "goto_w", "jsr_w", "breakpoint", "unknown",
    "unknown", "unknown", "unknown", "unknown",
    // 0xD0 - 0xDF
    "unknown", "unknown", "unknown", "unknown",
    "unknown", "unknown", "unknown", "unknown",
    "unknown", "unknown", "unknown", "unknown",
    "unknown", "unknown", "unknown", "unknown",
    // 0xE0 - 0xEF
    "unknown", "unknown", "unknown", "unknown",
    "unknown", "unknown", "unknown", "unknown",
    "unknown", "unknown", "unknown", "unknown",
    "unknown", "unknown", "unknown", "unknown",
    // 0xF0 - 0xFF
    "unknown", "unknown", "unknown", "unknown",
    "unknown", "unknown", "unknown", "unknown",
    "unknown", "unknown", "unknown", "unknown",
    "unknown", "unknown", "unknown", "unknown",
];

/// Return the mnemonic for a JVM bytecode opcode.
pub fn bytecode_mnemonic(opcode: u8) -> &'static str {
    JVM_BYTECODE_NAMES[opcode as usize]
}

/// Return the mnemonic for a JVM bytecode opcode, or None for unknown opcodes.
pub fn bytecode_mnemonic_known(opcode: u8) -> Option<&'static str> {
    let name = JVM_BYTECODE_NAMES[opcode as usize];
    if name == "unknown" || name == "breakpoint" { None } else { Some(name) }
}

/// Decode a bytecode instruction at the given position in a code array.
/// Returns the mnemonic, the number of bytes consumed, and an optional operand.
pub fn decode_bytecode(code: &[u8], offset: usize) -> Option<(&'static str, usize, Option<i32>)> {
    if offset >= code.len() { return None; }
    let opcode = code[offset];
    let mnemonic = JVM_BYTECODE_NAMES[opcode as usize];
    let (len, operand) = match opcode {
        // No operand, 1 byte
        0x00 | 0x01 | 0x02 | 0x03 | 0x04 | 0x05 | 0x06 | 0x07
        | 0x08 | 0x09 | 0x0a | 0x0b | 0x0c | 0x0d | 0x0e | 0x0f
        // aload_0..aload_3, etc.
        | 0x1a..=0x2d
        // array loads, stores, stack
        | 0x2e..=0x5f
        // arithmetic
        | 0x60..=0x83
        // conversions, comparisons, returns, array length
        | 0x85..=0x98 | 0xac..=0xb1 | 0xbe | 0xbf
        | 0xc2 | 0xc3 => (1, None),
        // bipush: 1 byte operand
        0x10 => (2, Some(code.get(offset + 1).map(|b| *b as i32).unwrap_or(0))),
        // sipush: 2 byte operand
        0x11 => (3, {
            let b1 = code.get(offset + 1).copied().unwrap_or(0) as u16;
            let b2 = code.get(offset + 2).copied().unwrap_or(0) as u16;
            Some((b1 << 8 | b2) as i16 as i32)
        }),
        // ldc: 1 byte index
        0x12 => (2, Some(code.get(offset + 1).map(|b| *b as i32).unwrap_or(0))),
        // ldc_w, ldc2_w, getstatic, putstatic, getfield, putfield,
        // invokevirtual, invokespecial, invokestatic, new, anewarray,
        // checkcast, instanceof: 2 byte index
        0x13 | 0x14 | 0xb2 | 0xb3 | 0xb4 | 0xb5
        | 0xb6 | 0xb7 | 0xb8 | 0xbb | 0xbd
        | 0xc0 | 0xc1 => (3, {
            let b1 = code.get(offset + 1).copied().unwrap_or(0) as u16;
            let b2 = code.get(offset + 2).copied().unwrap_or(0) as u16;
            Some((b1 << 8 | b2) as i32)
        }),
        // iload, lload, fload, dload, aload: 1 byte index
        0x15..=0x19 => (2, Some(code.get(offset + 1).map(|b| *b as i32).unwrap_or(0))),
        // istore, lstore, fstore, dstore, astore: 1 byte index
        0x36..=0x3a => (2, Some(code.get(offset + 1).map(|b| *b as i32).unwrap_or(0))),
        // iinc: 2 bytes (index, const)
        0x84 => (3, {
            let idx = code.get(offset + 1).copied().unwrap_or(0) as i32;
            let constv = code.get(offset + 2).copied().unwrap_or(0) as i8 as i32;
            Some((idx << 8) | (constv & 0xff))
        }),
        // if*, goto, jsr: 2 byte branch offset
        0x99..=0xa8 => (3, {
            let b1 = code.get(offset + 1).copied().unwrap_or(0) as i16;
            let b2 = code.get(offset + 2).copied().unwrap_or(0) as i16;
            Some((b1 << 8 | b2) as i32)
        }),
        // ret: 1 byte index
        0xa9 => (2, Some(code.get(offset + 1).map(|b| *b as i32).unwrap_or(0))),
        // tableswitch: variable length, padded to 4-byte boundary
        0xaa => {
            let pad = (4 - (offset + 1) % 4) % 4;
            if offset + 1 + pad + 12 > code.len() { return None; }
            let _default = read_be_i32(code, offset + 1 + pad);
            let low = read_be_i32(code, offset + 1 + pad + 4);
            let high = read_be_i32(code, offset + 1 + pad + 8);
            let count = (high - low + 1).max(0) as usize;
            (1 + pad + 12 + count * 4, Some(high - low))
        }
        // lookupswitch: variable length
        0xab => {
            let pad = (4 - (offset + 1) % 4) % 4;
            if offset + 1 + pad + 8 > code.len() { return None; }
            let _default = read_be_i32(code, offset + 1 + pad);
            let npairs = read_be_i32(code, offset + 1 + pad + 4);
            (1 + pad + 8 + npairs as usize * 8, Some(npairs))
        }
        // invokeinterface: 4 bytes (index, count, 0)
        0xb9 => (5, {
            let b1 = code.get(offset + 1).copied().unwrap_or(0) as u16;
            let b2 = code.get(offset + 2).copied().unwrap_or(0) as u16;
            Some((b1 << 8 | b2) as i32)
        }),
        // invokedynamic: 4 bytes
        0xba => (5, {
            let b1 = code.get(offset + 1).copied().unwrap_or(0) as u16;
            let b2 = code.get(offset + 2).copied().unwrap_or(0) as u16;
            Some((b1 << 8 | b2) as i32)
        }),
        // newarray: 1 byte (atype)
        0xbc => (2, Some(code.get(offset + 1).map(|b| *b as i32).unwrap_or(0))),
        // multianewarray: 3 bytes (index, dimensions)
        0xc5 => (4, {
            let b1 = code.get(offset + 1).copied().unwrap_or(0) as u16;
            let b2 = code.get(offset + 2).copied().unwrap_or(0) as u16;
            let dims = code.get(offset + 3).copied().unwrap_or(0) as i32;
            Some(((b1 << 8 | b2) as i32) | (dims << 16))
        }),
        // wide: modifies next instruction
        0xc4 => {
            if offset + 1 >= code.len() { return None; }
            let wide_opcode = code[offset + 1];
            match wide_opcode {
                0x15..=0x19 | 0x36..=0x3a => (4, {
                    let b1 = code.get(offset + 2).copied().unwrap_or(0) as u16;
                    let b2 = code.get(offset + 3).copied().unwrap_or(0) as u16;
                    Some((b1 << 8 | b2) as i32)
                }),
                0x84 => (6, {
                    let b1 = code.get(offset + 2).copied().unwrap_or(0) as u16;
                    let b2 = code.get(offset + 3).copied().unwrap_or(0) as u16;
                    let b3 = code.get(offset + 4).copied().unwrap_or(0) as u16;
                    let b4 = code.get(offset + 5).copied().unwrap_or(0) as u16;
                    Some(((b1 << 8 | b2) as i32) | (((b3 << 8 | b4) as i32) << 16))
                }),
                _ => (2, Some(wide_opcode as i32)),
            }
        }
        // ifnull, ifnonnull: 2 byte branch offset
        0xc6 | 0xc7 => (3, {
            let b1 = code.get(offset + 1).copied().unwrap_or(0) as i16;
            let b2 = code.get(offset + 2).copied().unwrap_or(0) as i16;
            Some((b1 << 8 | b2) as i32)
        }),
        // goto_w, jsr_w: 4 byte branch offset
        0xc8 | 0xc9 => (5, {
            Some(read_be_i32(code, offset + 1))
        }),
        _ => (1, None),
    };
    Some((mnemonic, len, operand))
}

/// Read a big-endian i32 from a byte slice at the given offset.
fn read_be_i32(data: &[u8], offset: usize) -> i32 {
    if offset + 4 > data.len() { return 0; }
    i32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

/// Disassemble a chunk of JVM bytecode into a vector of (offset, mnemonic, operand) tuples.
pub fn disassemble_bytecode(code: &[u8]) -> Vec<(usize, String, Option<i32>)> {
    let mut result = Vec::new();
    let mut pos = 0usize;
    while pos < code.len() {
        if let Some((mnemonic, len, operand)) = decode_bytecode(code, pos) {
            result.push((pos, mnemonic.to_string(), operand));
            pos += len;
        } else {
            result.push((pos, "???".to_string(), None));
            pos += 1;
        }
    }
    result
}

// ============================================================================
// BinaryLoader Implementation
// ============================================================================

/// Java class file loader — loads JVM bytecode `.class` files for analysis.
pub struct JavaClassLoader;

impl crate::BinaryLoader for JavaClassLoader {
    fn name(&self) -> &str {
        "Java Class"
    }

    fn can_load(&self, data: &[u8]) -> bool {
        is_class(data)
    }

    fn load(
        &self,
        data: &[u8],
        options: &crate::LoadOptions,
    ) -> anyhow::Result<crate::base::analyzer::Program> {
        use crate::base::analyzer::{Address, MemoryBlock, Program};

        let class = parse_class(data)?;
        let lang = crate::base::analyzer::Language {
            processor: "JVM".into(),
            variant: "BE".into(),
            size: 32,
        };

        let base = options.base_address;
        let mut program = Program::new(
            &format!("class_{}", class.class_name.replace('/', "_")),
            lang,
        );
        program.image_base = base;

        // Create a single memory block for the class file.
        let block = MemoryBlock {
            name: "CLASS_DATA".into(),
            start: Address::new(base),
            size: data.len() as u64,
            is_read: true,
            is_write: false,
            is_execute: false,
            is_initialized: true,
        };
        program.memory_blocks.push(block);

        Ok(program)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_class() -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes()); // minor
        data.extend_from_slice(&52u16.to_be_bytes()); // major (Java 8)

        // Constant pool count: 17
        data.extend_from_slice(&17u16.to_be_bytes());

        // #1 Methodref (class #3, nat #13)
        data.push(CONSTANT_METHODREF);
        data.extend_from_slice(&3u16.to_be_bytes());
        data.extend_from_slice(&13u16.to_be_bytes());

        // #2 Class (#14)
        data.push(CONSTANT_CLASS); data.extend_from_slice(&14u16.to_be_bytes());
        // #3 Class (#15)
        data.push(CONSTANT_CLASS); data.extend_from_slice(&15u16.to_be_bytes());
        // #4 Class (#16)
        data.push(CONSTANT_CLASS); data.extend_from_slice(&16u16.to_be_bytes());

        let utf8_entries: &[&[u8]] = &[
            b"<init>", b"()V", b"Code", b"LineNumberTable",
            b"main", b"([Ljava/lang/String;)V", b"SourceFile", b"Test.java",
            b"Test", b"java/lang/Object", b"java/lang/System",
        ];
        for s in utf8_entries {
            data.push(CONSTANT_UTF8);
            data.extend_from_slice(&(s.len() as u16).to_be_bytes());
            data.extend_from_slice(s);
        }

        // #13 NameAndType (#5, #6)
        data.push(CONSTANT_NAME_AND_TYPE);
        data.extend_from_slice(&5u16.to_be_bytes());
        data.extend_from_slice(&6u16.to_be_bytes());

        // Access: public super
        data.extend_from_slice(&(0x0001u16 | 0x0020u16).to_be_bytes());
        // this=#2, super=#3
        data.extend_from_slice(&2u16.to_be_bytes());
        data.extend_from_slice(&3u16.to_be_bytes());
        // interfaces: 0
        data.extend_from_slice(&0u16.to_be_bytes());
        // fields: 0
        data.extend_from_slice(&0u16.to_be_bytes());
        // methods: 1
        data.extend_from_slice(&1u16.to_be_bytes());

        // Method: <init> "()V"
        data.extend_from_slice(&0x0001u16.to_be_bytes()); // ACC_PUBLIC
        data.extend_from_slice(&5u16.to_be_bytes());  // name idx "init"
        data.extend_from_slice(&6u16.to_be_bytes());  // desc "()V"
        // Code attribute
        data.extend_from_slice(&1u16.to_be_bytes()); // 1 attribute
        data.extend_from_slice(&7u16.to_be_bytes()); // "Code"
        let code_bytes = vec![0x2au8, 0xb7, 0x00, 0x01, 0xb1]; // aload_0, invokespecial #1, return
        let mut code_attr = Vec::new();
        code_attr.extend_from_slice(&2u16.to_be_bytes()); // max_stack
        code_attr.extend_from_slice(&1u16.to_be_bytes()); // max_locals
        code_attr.extend_from_slice(&(code_bytes.len() as u32).to_be_bytes());
        code_attr.extend_from_slice(&code_bytes);
        code_attr.extend_from_slice(&0u16.to_be_bytes()); // 0 exceptions
        code_attr.extend_from_slice(&0u16.to_be_bytes()); // 0 attributes
        data.extend_from_slice(&(code_attr.len() as u32).to_be_bytes());
        data.extend_from_slice(&code_attr);

        // Class attributes: 1 (SourceFile)
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&11u16.to_be_bytes()); // "SourceFile"
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend_from_slice(&12u16.to_be_bytes()); // "Test.java"

        data
    }

    #[test]
    fn test_is_class() {
        let data = build_minimal_class();
        assert!(is_class(&data));
        assert!(!is_class(b"nope"));
        assert!(!is_class(&[]));
    }

    #[test]
    fn test_parse_minimal_class() {
        let data = build_minimal_class();
        let class = parse_class(&data);
        assert!(class.is_ok());
        let class = class.unwrap();
        assert_eq!(class.magic, CLASS_MAGIC);
        assert_eq!(class.major_version, 52);
        assert_eq!(class.minor_version, 0);
        assert_eq!(class.methods.len(), 1);
        assert_eq!(class.methods[0].name, "<init>");
        assert_eq!(class.fields.len(), 0);
    }

    #[test]
    fn test_invalid_magic() {
        let bad = [0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0];
        assert!(parse_class(&bad).is_err());
    }

    #[test]
    fn test_java_version_name() {
        assert_eq!(java_version_name(52), "Java 8");
        assert_eq!(java_version_name(61), "Java 17");
        assert_eq!(java_version_name(65), "Java 21");
    }

    #[test]
    fn test_reference_kind_name() {
        assert_eq!(reference_kind_name(REF_GET_FIELD), "REF_getField");
        assert_eq!(reference_kind_name(REF_INVOKE_INTERFACE), "REF_invokeInterface");
        assert_eq!(reference_kind_name(99), "UNKNOWN");
    }

    #[test]
    fn test_access_flags() {
        let flags = AccessFlags::ACC_PUBLIC | AccessFlags::ACC_STATIC;
        assert!(flags.contains(AccessFlags::ACC_PUBLIC));
        assert!(flags.contains(AccessFlags::ACC_STATIC));
        assert!(!flags.contains(AccessFlags::ACC_PRIVATE));
    }

    #[test]
    fn test_verification_type_parsing() {
        let data = [VERIFY_INTEGER];
        let mut pos = 0;
        let vt = parse_verification_type(&data, &mut pos).unwrap();
        assert!(matches!(vt, VerificationTypeInfo::Integer));

        let data = [VERIFY_NULL];
        let mut pos = 0;
        let vt = parse_verification_type(&data, &mut pos).unwrap();
        assert!(matches!(vt, VerificationTypeInfo::Null));

        let data = [VERIFY_OBJECT, 0x00, 0x05];
        let mut pos = 0;
        let vt = parse_verification_type(&data, &mut pos).unwrap();
        assert!(matches!(vt, VerificationTypeInfo::Object { cpool_index: 5 }));
    }

    #[test]
    fn test_stack_map_frame_parsing() {
        // Same frame
        let data = [0x03u8];
        let mut pos = 0;
        let frame = parse_stack_map_frame(&data, &mut pos).unwrap();
        match frame {
            StackMapFrame::Same { offset_delta } => assert_eq!(offset_delta, 3),
            _ => panic!("Expected Same frame"),
        }
    }

    #[test]
    fn test_bytecode_mnemonic_basic() {
        assert_eq!(bytecode_mnemonic(0x00), "nop");
        assert_eq!(bytecode_mnemonic(0x01), "aconst_null");
        assert_eq!(bytecode_mnemonic(0x10), "bipush");
        assert_eq!(bytecode_mnemonic(0xb1), "return");
        assert_eq!(bytecode_mnemonic(0xbb), "new");
    }

    #[test]
    fn test_bytecode_mnemonic_known() {
        assert_eq!(bytecode_mnemonic_known(0x00), Some("nop"));
        assert_eq!(bytecode_mnemonic_known(0xca), None); // breakpoint
        assert_eq!(bytecode_mnemonic_known(0xff), None); // unknown
    }

    #[test]
    fn test_decode_simple_bytecode() {
        // nop
        let code = [0x00u8];
        let (name, len, op) = decode_bytecode(&code, 0).unwrap();
        assert_eq!(name, "nop");
        assert_eq!(len, 1);
        assert!(op.is_none());

        // bipush 42
        let code = [0x10, 42];
        let (name, len, op) = decode_bytecode(&code, 0).unwrap();
        assert_eq!(name, "bipush");
        assert_eq!(len, 2);
        assert_eq!(op, Some(42));

        // sipush 0x1234
        let code = [0x11, 0x12, 0x34];
        let (name, len, op) = decode_bytecode(&code, 0).unwrap();
        assert_eq!(name, "sipush");
        assert_eq!(len, 3);
        assert_eq!(op.unwrap() as u16, 0x1234u16);
    }

    #[test]
    fn test_disassemble_bytecode() {
        let code = [0x2a, 0xb7, 0x00, 0x01, 0xb1]; // aload_0, invokespecial #1, return
        let dasm = disassemble_bytecode(&code);
        assert_eq!(dasm.len(), 3);
        assert_eq!(dasm[0].1, "aload_0");
        assert_eq!(dasm[1].1, "invokespecial");
        assert_eq!(dasm[2].1, "return");
    }
}
