//! Common types for processor module definitions.
//!
//! Provides the shared [`Register`], [`RegisterBank`], [`RegisterManager`],
//! [`Language`], [`LanguageID`], [`CompilerSpecID`], [`Processor`],
//! [`ProcessorModule`] trait, and supporting types used by all
//! architecture-specific modules.

use ghidra_core::listing::InstructionMnemonic;
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Register type flags (port of Register.java TYPE_* constants)
// ---------------------------------------------------------------------------

/// Bit-flags describing the role or category of a register.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegisterType(u32);

impl RegisterType {
    pub const NONE: RegisterType = RegisterType(0);
    pub const FP: RegisterType = RegisterType(1 << 0);
    pub const SP: RegisterType = RegisterType(1 << 1);
    pub const PC: RegisterType = RegisterType(1 << 2);
    pub const CONTEXT: RegisterType = RegisterType(1 << 3);
    pub const ZERO: RegisterType = RegisterType(1 << 4);
    pub const HIDDEN: RegisterType = RegisterType(1 << 5);
    pub const DOES_NOT_FOLLOW_FLOW: RegisterType = RegisterType(1 << 6);
    pub const VECTOR: RegisterType = RegisterType(1 << 7);

    pub fn from_bits(bits: u32) -> Self { RegisterType(bits) }
    pub fn bits(self) -> u32 { self.0 }
    pub fn contains(self, other: RegisterType) -> bool { (self.0 & other.0) == other.0 }
    pub fn union(self, other: RegisterType) -> RegisterType { RegisterType(self.0 | other.0) }
    pub fn is_fp(self) -> bool { self.contains(Self::FP) }
    pub fn is_sp(self) -> bool { self.contains(Self::SP) }
    pub fn is_pc(self) -> bool { self.contains(Self::PC) }
    pub fn is_context(self) -> bool { self.contains(Self::CONTEXT) }
    pub fn is_zero(self) -> bool { self.contains(Self::ZERO) }
    pub fn is_hidden(self) -> bool { self.contains(Self::HIDDEN) }
    pub fn is_vector(self) -> bool { self.contains(Self::VECTOR) }
}

impl Default for RegisterType {
    fn default() -> Self { RegisterType::NONE }
}

impl fmt::Display for RegisterType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == 0 { return write!(f, "NONE"); }
        let mut flags = Vec::new();
        if self.is_fp() { flags.push("FP"); }
        if self.is_sp() { flags.push("SP"); }
        if self.is_pc() { flags.push("PC"); }
        if self.is_context() { flags.push("CONTEXT"); }
        if self.is_zero() { flags.push("ZERO"); }
        if self.is_hidden() { flags.push("HIDDEN"); }
        if self.is_vector() { flags.push("VECTOR"); }
        write!(f, "{}", flags.join("|"))
    }
}

// ---------------------------------------------------------------------------
// Register definition (enhanced port of Register.java)
// ---------------------------------------------------------------------------

/// A single processor register definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Register {
    pub name: String,
    pub bit_size: u32,
    pub offset: u64,
    pub parent: Option<String>,
    pub lsb: u32,
    pub type_flags: RegisterType,
    pub big_endian: bool,
    pub description: String,
    pub aliases: Vec<String>,
    pub group: String,
}

impl Register {
    pub fn new(name: &str, bit_size: u32, offset: u64) -> Self {
        Register {
            name: name.to_string(), bit_size, offset, parent: None, lsb: 0,
            type_flags: RegisterType::NONE, big_endian: false,
            description: String::new(), aliases: Vec::new(), group: String::new(),
        }
    }

    pub fn sub_register(name: &str, bit_size: u32, offset: u64, parent: &str, lsb: u32) -> Self {
        Register {
            name: name.to_string(), bit_size, offset, parent: Some(parent.to_string()), lsb,
            type_flags: RegisterType::NONE, big_endian: false,
            description: String::new(), aliases: Vec::new(), group: String::new(),
        }
    }

    pub fn with_type(mut self, flags: RegisterType) -> Self { self.type_flags = flags; self }
    pub fn with_endian(mut self, big_endian: bool) -> Self { self.big_endian = big_endian; self }
    pub fn with_description(mut self, desc: impl Into<String>) -> Self { self.description = desc.into(); self }
    pub fn with_group(mut self, group: impl Into<String>) -> Self { self.group = group.into(); self }
    pub fn with_alias(mut self, alias: impl Into<String>) -> Self { self.aliases.push(alias.into()); self }

    pub fn byte_size(&self) -> u32 { (self.bit_size + 7) / 8 }
    pub fn is_base_register(&self) -> bool { self.parent.is_none() }
    pub fn is_processor_context(&self) -> bool { self.type_flags.is_context() }
    pub fn is_program_counter(&self) -> bool { self.type_flags.is_pc() }
    pub fn is_vector_register(&self) -> bool { self.type_flags.is_vector() }
    pub fn is_big_endian(&self) -> bool { self.big_endian }
}

// ---------------------------------------------------------------------------
// Register bank
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct RegisterBank {
    register_by_name: HashMap<String, Register>,
}

impl RegisterBank {
    pub fn new() -> Self { Self { register_by_name: HashMap::new() } }
    pub fn add(&mut self, reg: Register) { self.register_by_name.insert(reg.name.clone(), reg); }
    pub fn add_all(&mut self, regs: impl IntoIterator<Item = Register>) { for reg in regs { self.add(reg); } }
    pub fn get(&self, name: &str) -> Option<&Register> { self.register_by_name.get(name) }
    pub fn sub_registers_of(&self, parent_name: &str) -> Vec<&Register> {
        self.register_by_name.values().filter(|r| r.parent.as_deref() == Some(parent_name)).collect()
    }
    pub fn top_level_registers(&self) -> Vec<&Register> {
        self.register_by_name.values().filter(|r| r.parent.is_none()).collect()
    }
    pub fn len(&self) -> usize { self.register_by_name.len() }
    pub fn is_empty(&self) -> bool { self.register_by_name.is_empty() }
    pub fn iter(&self) -> impl Iterator<Item = &Register> { self.register_by_name.values() }
    pub fn register_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.register_by_name.keys().cloned().collect();
        names.sort();
        names
    }
    pub fn registers_with_type(&self, flags: RegisterType) -> Vec<&Register> {
        self.register_by_name.values().filter(|r| r.type_flags.contains(flags)).collect()
    }
    pub fn as_map(&self) -> &HashMap<String, Register> { &self.register_by_name }
}

// ---------------------------------------------------------------------------
// Endianness
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endian { Little, Big, Bi }

impl Endian {
    pub fn from_str(s: &str) -> Option<Endian> {
        match s.to_lowercase().as_str() {
            "big" | "be" => Some(Endian::Big),
            "little" | "le" => Some(Endian::Little),
            "bi" => Some(Endian::Bi),
            _ => None,
        }
    }
    pub fn is_little(&self) -> bool { matches!(self, Endian::Little) }
    pub fn is_big(&self) -> bool { matches!(self, Endian::Big) }
    pub fn short_str(&self) -> &'static str { match self { Endian::Little => "LE", Endian::Big => "BE", Endian::Bi => "BI" } }
    pub fn display_name(&self) -> &'static str { match self { Endian::Little => "Little", Endian::Big => "Big", Endian::Bi => "Bi" } }
}

impl std::fmt::Display for Endian {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Endian::Little => write!(f, "LE"), Endian::Big => write!(f, "BE"), Endian::Bi => write!(f, "BI") }
    }
}

// ---------------------------------------------------------------------------
// Language definition (enhanced)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Language {
    pub id: String,
    pub description: String,
    pub version: String,
    pub endian: Endian,
    pub pointer_size: u32,
    pub instruction_alignment: u32,
    pub supports_pcode: bool,
    pub program_counter: String,
}

impl Language {
    pub fn new(id: impl Into<String>, description: impl Into<String>, version: impl Into<String>, endian: Endian, pointer_size: u32) -> Self {
        Language {
            id: id.into(), description: description.into(), version: version.into(), endian, pointer_size,
            instruction_alignment: 1, supports_pcode: true, program_counter: "PC".to_string(),
        }
    }
    pub fn with_instruction_alignment(mut self, alignment: u32) -> Self { self.instruction_alignment = alignment; self }
    pub fn with_pcode(mut self, supports: bool) -> Self { self.supports_pcode = supports; self }
    pub fn with_pc_register(mut self, name: impl Into<String>) -> Self { self.program_counter = name.into(); self }
}

// ---------------------------------------------------------------------------
// ProcessorModule trait (enhanced)
// ---------------------------------------------------------------------------

pub trait ProcessorModule {
    fn name() -> &'static str;
    fn registers() -> RegisterBank;
    fn languages() -> Vec<Language>;
    fn instructions() -> Vec<InstructionMnemonic>;
    fn description() -> &'static str { Self::name() }
    fn family() -> &'static str { "Unknown" }
    fn default_pointer_size() -> u32 { 32 }
    fn default_endian() -> Endian { Endian::Little }
    fn processor() -> Processor { Processor::new(Self::name(), Self::description(), Self::family()) }
}

// ---------------------------------------------------------------------------
// LanguageID (port of LanguageID.java)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LanguageID(String);

impl LanguageID {
    pub fn new(id: impl Into<String>) -> Self { let s = id.into(); assert!(!s.is_empty()); LanguageID(s) }
    pub fn as_str(&self) -> &str { &self.0 }
    pub fn processor(&self) -> &str { self.0.split(':').next().unwrap_or(&self.0) }
    pub fn endian_str(&self) -> &str { self.0.split(':').nth(1).unwrap_or("") }
    pub fn size_str(&self) -> &str { self.0.split(':').nth(2).unwrap_or("") }
    pub fn variant(&self) -> &str { self.0.split(':').nth(3).unwrap_or("") }
}

impl fmt::Display for LanguageID { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) } }

// ---------------------------------------------------------------------------
// CompilerSpecID (port of CompilerSpecID.java)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CompilerSpecID(String);

impl CompilerSpecID {
    pub const DEFAULT: &'static str = "default";
    pub fn new(id: impl Into<String>) -> Self { CompilerSpecID(id.into()) }
    pub fn default_id() -> Self { CompilerSpecID(Self::DEFAULT.to_string()) }
    pub fn as_str(&self) -> &str { &self.0 }
}

impl fmt::Display for CompilerSpecID { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) } }
impl Default for CompilerSpecID { fn default() -> Self { Self::default_id() } }

// ---------------------------------------------------------------------------
// CompilerSpecDescription
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompilerSpecDescription {
    pub id: CompilerSpecID,
    pub description: String,
    pub is_default: bool,
}

impl CompilerSpecDescription {
    pub fn new(id: impl Into<String>, description: impl Into<String>, is_default: bool) -> Self {
        CompilerSpecDescription { id: CompilerSpecID::new(id), description: description.into(), is_default }
    }
    pub fn default_spec(description: impl Into<String>) -> Self {
        CompilerSpecDescription { id: CompilerSpecID::default_id(), description: description.into(), is_default: true }
    }
}

// ---------------------------------------------------------------------------
// Processor (port of Processor.java)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Processor { name: String, description: String, family: String }

impl Processor {
    pub fn new(name: impl Into<String>, description: impl Into<String>, family: impl Into<String>) -> Self {
        Processor { name: name.into(), description: description.into(), family: family.into() }
    }
    pub fn name(&self) -> &str { &self.name }
    pub fn description(&self) -> &str { &self.description }
    pub fn family(&self) -> &str { &self.family }
}

impl fmt::Display for Processor { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.name) } }
impl PartialOrd for Processor { fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> { Some(self.cmp(other)) } }
impl Ord for Processor { fn cmp(&self, other: &Self) -> std::cmp::Ordering { self.name.to_lowercase().cmp(&other.name.to_lowercase()) } }

// ---------------------------------------------------------------------------
// LanguageDescription (port of LanguageDescription.java)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LanguageDescription {
    pub language_id: LanguageID,
    pub processor: Processor,
    pub endian: Endian,
    pub instruction_endian: Endian,
    pub size: u32,
    pub variant: String,
    pub version: u32,
    pub minor_version: u32,
    pub description: String,
    pub deprecated: bool,
    pub compiler_specs: Vec<CompilerSpecDescription>,
    pub external_names: HashMap<String, Vec<String>>,
}

impl LanguageDescription {
    pub fn new(language_id: LanguageID, processor: Processor, endian: Endian, size: u32, variant: impl Into<String>, description: impl Into<String>) -> Self {
        LanguageDescription {
            language_id, processor, endian, instruction_endian: endian, size,
            variant: variant.into(), version: 1, minor_version: 0,
            description: description.into(), deprecated: false,
            compiler_specs: vec![CompilerSpecDescription::default_spec("Default compiler")],
            external_names: HashMap::new(),
        }
    }
    pub fn with_instruction_endian(mut self, endian: Endian) -> Self { self.instruction_endian = endian; self }
    pub fn with_version(mut self, major: u32, minor: u32) -> Self { self.version = major; self.minor_version = minor; self }
    pub fn with_deprecated(mut self, deprecated: bool) -> Self { self.deprecated = deprecated; self }
    pub fn with_compiler_spec(mut self, spec: CompilerSpecDescription) -> Self { self.compiler_specs.push(spec); self }
    pub fn with_external_name(mut self, tool: impl Into<String>, name: impl Into<String>) -> Self {
        self.external_names.entry(tool.into()).or_default().push(name.into()); self
    }
    pub fn default_compiler_spec(&self) -> Option<&CompilerSpecDescription> { self.compiler_specs.iter().find(|s| s.is_default) }
    pub fn compiler_spec_by_id(&self, id: &CompilerSpecID) -> Option<&CompilerSpecDescription> { self.compiler_specs.iter().find(|s| s.id == *id) }
    pub fn external_names_for(&self, tool: &str) -> Option<&Vec<String>> { self.external_names.get(tool) }
}

// ---------------------------------------------------------------------------
// RegisterManager (port of RegisterManager.java)
// ---------------------------------------------------------------------------

/// Manages a collection of registers with advanced lookup capabilities.
#[derive(Debug, Clone)]
pub struct RegisterManager {
    registers: Vec<Register>,
    name_map: HashMap<String, Register>,
    register_names: Vec<String>,
    context_registers: Vec<Register>,
    context_base_register: Option<Register>,
    sorted_vector_registers: Vec<Register>,
    groups: HashMap<String, Vec<Register>>,
}

impl RegisterManager {
    pub fn new(bank: &RegisterBank) -> Self {
        let registers: Vec<Register> = bank.iter().cloned().collect();
        let mut name_map = HashMap::new();
        for reg in &registers {
            name_map.insert(reg.name.to_lowercase(), reg.clone());
            for alias in &reg.aliases { name_map.insert(alias.to_lowercase(), reg.clone()); }
        }
        let mut register_names: Vec<String> = registers.iter().map(|r| r.name.clone()).collect();
        register_names.sort();
        let context_registers: Vec<Register> = registers.iter().filter(|r| r.is_processor_context()).cloned().collect();
        let context_base_register = context_registers.iter().filter(|r| r.is_base_register()).max_by_key(|r| r.bit_size).cloned();
        let mut sorted_vector_registers: Vec<Register> = registers.iter().filter(|r| r.is_vector_register()).cloned().collect();
        sorted_vector_registers.sort_by(|a, b| b.bit_size.cmp(&a.bit_size).then(a.offset.cmp(&b.offset)));
        let mut groups: HashMap<String, Vec<Register>> = HashMap::new();
        for reg in &registers {
            let group = if reg.group.is_empty() { "General".to_string() } else { reg.group.clone() };
            groups.entry(group).or_default().push(reg.clone());
        }
        RegisterManager { registers, name_map, register_names, context_registers, context_base_register, sorted_vector_registers, groups }
    }

    pub fn get_register(&self, name: &str) -> Option<&Register> { self.name_map.get(&name.to_lowercase()) }
    pub fn context_base_register(&self) -> Option<&Register> { self.context_base_register.as_ref() }
    pub fn context_registers(&self) -> &[Register] { &self.context_registers }
    pub fn register_names(&self) -> &[String] { &self.register_names }
    pub fn all_registers(&self) -> &[Register] { &self.registers }
    pub fn sorted_vector_registers(&self) -> &[Register] { &self.sorted_vector_registers }
    pub fn registers_in_group(&self, group: &str) -> Option<&Vec<Register>> { self.groups.get(group) }
    pub fn group_names(&self) -> Vec<&String> { self.groups.keys().collect() }
    pub fn len(&self) -> usize { self.registers.len() }
    pub fn is_empty(&self) -> bool { self.registers.is_empty() }
}

// ---------------------------------------------------------------------------
// ProcessorContext trait (port of ProcessorContext.java)
// ---------------------------------------------------------------------------

pub trait ProcessorContext {
    fn get_register_value(&self, name: &str) -> Option<Vec<u8>>;
    fn set_register_value(&mut self, name: &str, value: &[u8]) -> bool;
    fn get_register_u64(&self, name: &str) -> Option<u64> {
        self.get_register_value(name).map(|v| {
            let mut bytes = [0u8; 8];
            let len = v.len().min(8);
            bytes[..len].copy_from_slice(&v[..len]);
            u64::from_le_bytes(bytes)
        })
    }
    fn set_register_u64(&mut self, name: &str, value: u64) -> bool { self.set_register_value(name, &value.to_le_bytes()) }
    fn get_tracked_register_names(&self) -> Vec<String>;
    fn clear_register(&mut self, name: &str) -> bool;
}
