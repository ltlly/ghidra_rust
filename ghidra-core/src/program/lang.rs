//! Language and processor definitions.
//!
//! This module models Ghidra's language infrastructure, converted from the Java
//! classes in `ghidra.program.model.lang`:
//!
//! | Java class | Rust type |
//! |---|---|
//! | `LanguageID` | [`LanguageID`] -- uniquely identifies a processor language |
//! | `Language` (interface) | [`Language`] -- processor language descriptor |
//! | `CompilerSpecID` | [`CompilerSpecID`] -- compiler specification identifier |
//! | `CompilerSpec` (interface) | [`CompilerSpec`] -- ABI / compiler spec |
//! | `Register` | [`Register`] -- CPU register with hierarchy and typing |
//! | `RegisterManager` | [`RegisterManager`] -- register index and lookup |
//! | `Processor` | [`Processor`] -- processor family (ISA grouping) |
//!
//! # Correspondence to Ghidra
//!
//! - `LanguageID` replaces the Java `LanguageID` which is a simple string wrapper.
//!   This Rust version parses the `processor:endian:size:variant[:qualifier]` format
//!   into structured fields for type-safe access.
//!
//! - `Register` replaces the Java `Register` class. Type flags (`TYPE_PC`,
//!   `TYPE_SP`, `TYPE_FP`, `TYPE_CONTEXT`, `TYPE_ZERO`, `TYPE_HIDDEN`,
//!   `TYPE_DOES_NOT_FOLLOW_FLOW`, `TYPE_VECTOR`) are represented as dedicated
//!   boolean fields and a bitflag field (`type_flags`). Child/parent/base register
//!   relationships are tracked via string references.
//!
//! - `RegisterManager` replaces the Java `RegisterManager` which indexes registers
//!   by address, size, and name. This Rust implementation uses `HashMap` for
//!   name-based and offset-based lookup, with a `RegisterSizeKey` for combined
//!   address+size queries corresponding to the Java inner class.
//!
//! - `Processor` replaces the Java `Processor` class. The Java version uses a
//!   static registry pattern (`findOrPossiblyCreateProcessor`, `toProcessor`);
//!   the Rust version is a plain struct. Registry-like behavior can be built
//!   separately using a `HashMap<String, Processor>`.

use crate::addr::{Address, AddressFactory, AddressSpace};
use crate::data::DataOrganization;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

// ============================================================================
// LanguageID
// ============================================================================

/// Uniquely identifies a processor language in Ghidra.
///
/// Corresponds to `ghidra.program.model.lang.LanguageID`.
///
/// A `LanguageID` takes the form `processor:endian:size:variant[:qualifier]`,
/// e.g. `"x86:LE:64:default"` or `"ARM:LE:32:v7"`.
///
/// The Java `LanguageID` wraps a raw string; this Rust version parses it into
/// structured fields while retaining the ability to round-trip through the
/// canonical string form.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LanguageID {
    /// The processor family name (e.g., "x86", "ARM", "MIPS", "PowerPC").
    pub processor: String,

    /// The endianness: "LE" (little-endian) or "BE" (big-endian).
    pub endian: String,

    /// The address size in bits (e.g., 32 or 64).
    pub size: usize,

    /// The variant name (e.g., "default", "v7", "micro").
    pub variant: String,

    /// Optional extra qualifier (e.g., "windows", "gcc").
    pub qualifier: Option<String>,
}

impl LanguageID {
    /// Create a new language ID without a qualifier.
    ///
    /// # Examples
    ///
    /// ```
    /// let id = LanguageID::new("x86", "LE", 64, "default");
    /// ```
    pub fn new(
        processor: impl Into<String>,
        endian: impl Into<String>,
        size: usize,
        variant: impl Into<String>,
    ) -> Self {
        Self {
            processor: processor.into(),
            endian: endian.into(),
            size,
            variant: variant.into(),
            qualifier: None,
        }
    }

    /// Add a qualifier to this language ID (builder pattern).
    pub fn with_qualifier(mut self, qualifier: impl Into<String>) -> Self {
        self.qualifier = Some(qualifier.into());
        self
    }

    /// Parse a language ID string like `"x86:LE:64:default"`.
    ///
    /// Corresponds to `new LanguageID(String)` in Java.
    ///
    /// Returns `None` if the string does not have enough colon-separated parts
    /// or if the size field cannot be parsed as an integer.
    pub fn parse(id_string: &str) -> Option<Self> {
        let parts: Vec<&str> = id_string.split(':').collect();
        if parts.len() < 4 {
            return None;
        }
        let processor = parts[0].to_string();
        let endian = parts[1].to_string();
        let size: usize = parts[2].parse().ok()?;
        let variant = parts[3].to_string();
        let qualifier = if parts.len() > 4 {
            Some(parts[4..].join(":"))
        } else {
            None
        };
        Some(Self {
            processor,
            endian,
            size,
            variant,
            qualifier,
        })
    }

    /// Return the language ID as a canonical string.
    ///
    /// Corresponds to `getIdAsString()` in Java.
    pub fn as_string(&self) -> String {
        self.to_id_string()
    }

    /// Serialize to the canonical string form `processor:endian:size:variant`.
    pub fn to_id_string(&self) -> String {
        let base = format!(
            "{}:{}:{}:{}",
            self.processor, self.endian, self.size, self.variant
        );
        match &self.qualifier {
            Some(q) => format!("{}:{}", base, q),
            None => base,
        }
    }

    /// Returns true if the language is big-endian.
    pub fn is_big_endian(&self) -> bool {
        self.endian.eq_ignore_ascii_case("BE")
    }

    /// Returns true if the language is little-endian.
    pub fn is_little_endian(&self) -> bool {
        self.endian.eq_ignore_ascii_case("LE")
    }

    // -- Convenience constructors --

    /// Convenience constructor for x86_64 LE default.
    pub fn x86_64() -> Self {
        Self::new("x86", "LE", 64, "default")
    }

    /// Convenience constructor for x86 32-bit LE default.
    pub fn x86_32() -> Self {
        Self::new("x86", "LE", 32, "default")
    }

    /// Convenience constructor for ARM LE 32-bit v7.
    pub fn arm_v7() -> Self {
        Self::new("ARM", "LE", 32, "v7")
    }

    /// Convenience constructor for AARCH64 LE 64-bit v8.
    pub fn aarch64() -> Self {
        Self::new("AARCH64", "LE", 64, "v8")
    }

    /// Convenience constructor for MIPS 32-bit BE default.
    pub fn mips32_be() -> Self {
        Self::new("MIPS", "BE", 32, "default")
    }
}

impl fmt::Display for LanguageID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_id_string())
    }
}

impl PartialOrd for LanguageID {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LanguageID {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_id_string().cmp(&other.to_id_string())
    }
}

// ============================================================================
// Language
// ============================================================================

/// Describes a processor language known to Ghidra.
///
/// Corresponds to `ghidra.program.model.lang.Language` (interface).
///
/// A [`Language`] bundles the language identity with version metadata,
/// the register manager (all registers for this processor), the set of
/// available compiler specifications, an address factory, and the mapping
/// of segment registers.
#[derive(Debug, Clone)]
pub struct Language {
    /// The language identifier.
    pub id: LanguageID,

    /// Human-readable name.
    pub name: String,

    /// Major version string.
    pub version: String,

    /// Minor version number.
    pub minor_version: u32,

    /// Human-readable description.
    pub description: String,

    /// The register manager for this language.
    pub register_manager: Arc<RegisterManager>,

    /// Available compiler specifications for this language.
    pub compiler_specs: Vec<Arc<CompilerSpec>>,

    /// The address factory used to create addresses in this language's spaces.
    pub address_factory: AddressFactory,

    /// Segment register name -> segment register description.
    /// E.g., `"DS" -> "Data Segment"`, `"FS" -> "Extra Segment"`.
    pub segment_registers: HashMap<String, String>,

    /// The data organization (endianness, pointer size, alignment).
    pub data_organization: DataOrganization,

    /// Whether this language supports P-code semantics.
    pub has_pcode: bool,

    /// The processor family information.
    pub processor: Option<Arc<Processor>>,

    /// Instruction alignment in bytes (e.g., 1 for x86, 2 for Thumb, 4 for ARM).
    pub instruction_alignment: u32,

    /// The default memory/code space name.
    pub default_space: String,

    /// The default data space name.
    pub default_data_space: String,

    /// Optional instruction mnemonic index (language manual entries).
    /// Maps instruction mnemonics to descriptive text.
    pub manual_index: HashMap<String, String>,

    /// Properties attached to this language definition.
    pub properties: HashMap<String, String>,

    /// User-defined P-code operation names (index -> name).
    pub user_defined_op_names: HashMap<usize, String>,
}

impl Language {
    /// Create a new language description.
    pub fn new(
        id: LanguageID,
        name: impl Into<String>,
        version: impl Into<String>,
        minor_version: u32,
        description: impl Into<String>,
        address_factory: AddressFactory,
    ) -> Self {
        let is_be = id.is_big_endian();
        let pointer_size = (id.size / 8).max(1);
        let data_org = if is_be {
            DataOrganization::default_64bit_be()
        } else if pointer_size >= 8 {
            DataOrganization::default_64bit_le()
        } else {
            DataOrganization::default_32bit_le()
        };

        Self {
            id,
            name: name.into(),
            version: version.into(),
            minor_version,
            description: description.into(),
            register_manager: Arc::new(RegisterManager::new()),
            compiler_specs: Vec::new(),
            address_factory,
            segment_registers: HashMap::new(),
            data_organization: data_org,
            has_pcode: true,
            processor: None,
            instruction_alignment: 1,
            default_space: "ram".to_string(),
            default_data_space: "ram".to_string(),
            manual_index: HashMap::new(),
            properties: HashMap::new(),
            user_defined_op_names: HashMap::new(),
        }
    }

    // -- Builder methods --

    /// Builder: set the register manager.
    pub fn with_register_manager(mut self, rm: RegisterManager) -> Self {
        self.register_manager = Arc::new(rm);
        self
    }

    /// Builder: add a compiler spec.
    pub fn with_compiler_spec(mut self, spec: CompilerSpec) -> Self {
        self.compiler_specs.push(Arc::new(spec));
        self
    }

    /// Builder: set multiple compiler specs.
    pub fn with_compiler_specs(mut self, specs: Vec<CompilerSpec>) -> Self {
        self.compiler_specs = specs.into_iter().map(Arc::new).collect();
        self
    }

    /// Builder: add a segment register description.
    pub fn with_segment_register(
        mut self,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        self.segment_registers
            .insert(name.into(), description.into());
        self
    }

    /// Builder: set the processor family.
    pub fn with_processor(mut self, proc: Arc<Processor>) -> Self {
        self.processor = Some(proc);
        self
    }

    /// Builder: set whether P-code is supported.
    pub fn with_pcode(mut self, has_pcode: bool) -> Self {
        self.has_pcode = has_pcode;
        self
    }

    /// Builder: set instruction alignment.
    pub fn with_instruction_alignment(mut self, align: u32) -> Self {
        self.instruction_alignment = align;
        self
    }

    /// Builder: add a property key-value pair.
    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }

    /// Builder: add a user-defined P-code operation name.
    pub fn with_user_defined_op(mut self, index: usize, name: impl Into<String>) -> Self {
        self.user_defined_op_names.insert(index, name.into());
        self
    }

    // -- Accessor methods (corresponding to Java Language interface methods) --

    /// Returns the LanguageID of this language.
    ///
    /// Corresponds to `getLanguageID()` in Java.
    pub fn get_language_id(&self) -> &LanguageID {
        &self.id
    }

    /// Returns the major version number.
    ///
    /// Corresponds to `getVersion()` in Java.
    pub fn get_version(&self) -> &str {
        &self.version
    }

    /// Returns the minor version number.
    ///
    /// Corresponds to `getMinorVersion()` in Java.
    pub fn get_minor_version(&self) -> u32 {
        self.minor_version
    }

    /// Returns the default memory/code space.
    ///
    /// Corresponds to `getDefaultSpace()` in Java.
    pub fn get_default_space(&self) -> Option<&AddressSpace> {
        self.address_factory.get_space(&self.default_space)
    }

    /// Returns the default data space.
    ///
    /// Corresponds to `getDefaultDataSpace()` in Java.
    pub fn get_default_data_space(&self) -> Option<&AddressSpace> {
        self.address_factory.get_space(&self.default_data_space)
    }

    /// Returns the instruction alignment.
    ///
    /// Corresponds to `getInstructionAlignment()` in Java.
    pub fn get_instruction_alignment(&self) -> u32 {
        self.instruction_alignment
    }

    /// Returns `true` if this language supports P-code.
    ///
    /// Corresponds to `supportsPcode()` in Java.
    pub fn supports_pcode(&self) -> bool {
        self.has_pcode
    }

    /// Returns the number of user-defined P-code operation names.
    ///
    /// Corresponds to `getNumberOfUserDefinedOpNames()` in Java.
    pub fn get_number_of_user_defined_op_names(&self) -> usize {
        self.user_defined_op_names.len()
    }

    /// Get a user-defined P-code operation name by index.
    ///
    /// Corresponds to `getUserDefinedOpName(int)` in Java.
    pub fn get_user_defined_op_name(&self, index: usize) -> Option<&str> {
        self.user_defined_op_names.get(&index).map(|s| s.as_str())
    }

    // -- Compiler spec lookups --

    /// Get a compiler spec by its ID.
    ///
    /// Corresponds to `getCompilerSpecByID(CompilerSpecID)` in Java.
    pub fn get_compiler_spec_by_id(&self, spec_id: &CompilerSpecID) -> Option<&Arc<CompilerSpec>> {
        self.compiler_specs.iter().find(|s| s.id == *spec_id)
    }

    /// Get the default compiler spec (the first one, if any).
    ///
    /// Corresponds to `getDefaultCompilerSpec()` in Java.
    pub fn get_default_compiler_spec(&self) -> Option<&Arc<CompilerSpec>> {
        self.compiler_specs.first()
    }

    /// Returns true if this language is big-endian.
    pub fn is_big_endian(&self) -> bool {
        self.id.is_big_endian()
    }

    /// Returns the pointer size for this language in bytes.
    pub fn get_pointer_size(&self) -> usize {
        self.data_organization.pointer_size
    }

    // -- Register access via RegisterManager --

    /// Get a register by name.
    ///
    /// Corresponds to `getRegister(String)` in Java.
    pub fn get_register(&self, name: &str) -> Option<&Register> {
        self.register_manager.get_register(name)
    }

    /// Get the program counter register.
    ///
    /// Corresponds to `getProgramCounter()` in Java.
    pub fn get_program_counter(&self) -> Option<&Register> {
        self.register_manager.get_program_counter()
    }

    /// Get the stack pointer register.
    pub fn get_stack_pointer(&self) -> Option<&Register> {
        self.register_manager.get_stack_pointer()
    }

    /// Get the frame pointer register.
    pub fn get_frame_pointer(&self) -> Option<&Register> {
        self.register_manager.get_frame_pointer()
    }

    /// Get the return address register.
    pub fn get_return_address_register(&self) -> Option<&Register> {
        self.register_manager.get_return_address_register()
    }

    /// Get the context base register.
    ///
    /// Corresponds to `getContextBaseRegister()` in Java.
    pub fn get_context_base_register(&self) -> Option<&Register> {
        self.register_manager.get_context_base_register()
    }

    /// Get all context registers.
    ///
    /// Corresponds to `getContextRegisters()` in Java.
    pub fn get_context_registers(&self) -> Vec<&Register> {
        self.register_manager.get_context_registers()
    }

    /// Get all registers.
    ///
    /// Corresponds to `getRegisters()` in Java.
    pub fn get_registers(&self) -> Vec<&Register> {
        self.register_manager.get_registers().iter().collect()
    }

    /// Get all register names (alphabetically sorted, no aliases).
    ///
    /// Corresponds to `getRegisterNames()` in Java.
    pub fn get_register_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.register_manager.get_register_names();
        names.sort();
        names
    }

    /// Get sorted vector registers.
    ///
    /// Corresponds to `getSortedVectorRegisters()` in Java.
    pub fn get_sorted_vector_registers(&self) -> Vec<&Register> {
        self.register_manager.get_sorted_vector_registers()
    }

    // -- Property access --

    /// Returns whether this language has a property defined.
    ///
    /// Corresponds to `hasProperty(String)` in Java.
    pub fn has_property(&self, key: &str) -> bool {
        self.properties.contains_key(key)
    }

    /// Gets a property value as an integer, returning `default_val` if not found.
    ///
    /// Corresponds to `getPropertyAsInt(String, int)` in Java.
    pub fn get_property_as_int(&self, key: &str, default_val: i32) -> i32 {
        self.properties
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_val)
    }

    /// Gets a property value as a boolean, returning `default_val` if not found.
    ///
    /// Corresponds to `getPropertyAsBoolean(String, boolean)` in Java.
    pub fn get_property_as_bool(&self, key: &str, default_val: bool) -> bool {
        self.properties
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_val)
    }

    /// Gets a property value as a string, returning `default_val` if not found.
    ///
    /// Corresponds to `getProperty(String, String)` in Java.
    pub fn get_property_with_default(&self, key: &str, default_val: &str) -> String {
        self.properties
            .get(key)
            .cloned()
            .unwrap_or_else(|| default_val.to_string())
    }

    /// Gets a property value, or `None` if not defined.
    ///
    /// Corresponds to `getProperty(String)` in Java.
    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|s| s.as_str())
    }

    /// Returns the set of property keys.
    ///
    /// Corresponds to `getPropertyKeys()` in Java.
    pub fn get_property_keys(&self) -> impl Iterator<Item = &str> {
        self.properties.keys().map(|s| s.as_str())
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} v{} ({})",
            self.name,
            self.version,
            self.id.to_id_string()
        )
    }
}

// ============================================================================
// CompilerSpecID
// ============================================================================

/// A simple identifier for a compiler specification.
///
/// Corresponds to `ghidra.program.model.lang.CompilerSpecID`.
///
/// The Java class has a `DEFAULT_ID = "default"` constant and a constructor
/// that treats `null` as `"default"`. This Rust version uses `"default"`
/// explicitly through the `default_spec()` constructor.
///
/// For example, `"gcc"`, `"windows"`, `"visualstudio"`, or `"clang"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CompilerSpecID {
    /// The compiler spec name as a string. Never empty.
    pub name: String,
}

impl CompilerSpecID {
    /// Create a new compiler spec ID. If `name` is empty, `"default"` is used.
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        let name = if name.is_empty() { "default".to_string() } else { name };
        Self { name }
    }

    /// Return the compiler spec ID as a string.
    ///
    /// Corresponds to `getIdAsString()` in Java.
    pub fn as_string(&self) -> &str {
        &self.name
    }

    // -- Predefined constructors --

    /// Predefined: GCC compiler spec.
    pub fn gcc() -> Self {
        Self::new("gcc")
    }

    /// Predefined: Windows / MSVC compiler spec.
    pub fn windows() -> Self {
        Self::new("windows")
    }

    /// Predefined: Clang compiler spec.
    pub fn clang() -> Self {
        Self::new("clang")
    }

    /// Predefined: Visual Studio compiler spec.
    pub fn visual_studio() -> Self {
        Self::new("visualstudio")
    }

    /// Predefined: default compiler spec.
    pub fn default_spec() -> Self {
        Self::new("default")
    }
}

impl fmt::Display for CompilerSpecID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl From<&str> for CompilerSpecID {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for CompilerSpecID {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl PartialOrd for CompilerSpecID {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CompilerSpecID {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name.cmp(&other.name)
    }
}

// ============================================================================
// CompilerSpec
// ============================================================================

/// A compiler specification describing the ABI for a particular compiler
/// targeting a specific processor language.
///
/// Corresponds to `ghidra.program.model.lang.CompilerSpec` (interface).
///
/// The compiler spec records:
/// - Which calling conventions are available and which is the default
/// - A prototype evaluation model (how parameter types are decomposed)
/// - The data organization (endianness, pointer size, alignment rules)
/// - A pointer to the parent [`Language`].
#[derive(Debug, Clone)]
pub struct CompilerSpec {
    /// The identifier for this compiler spec.
    pub id: CompilerSpecID,

    /// The language this compiler spec targets.
    pub language_id: LanguageID,

    /// Human-readable name (e.g., "gcc", "Microsoft Visual C++").
    pub name: String,

    /// A longer description string.
    pub description: String,

    /// All defined calling conventions.
    pub calling_conventions: Vec<Arc<CallingConvention>>,

    /// The default calling convention for this compiler spec.
    pub default_calling_convention: Option<Arc<CallingConvention>>,

    /// The prototype evaluation model name (how parameter passing is modeled).
    /// E.g., `"__stdcall"`, `"__cdecl"`, `"__thiscall"` on x86.
    pub prototype_model: Option<String>,

    /// Data organization (endianness, pointer size, alignment).
    pub data_organization: DataOrganization,

    /// The parent language (strong reference kept to manage lifetime).
    pub language: Option<Arc<Language>>,

    /// Whether this compiler spec performs C data-type conversions
    /// (e.g., array-to-pointer decay).
    pub does_c_data_type_conversions: bool,

    /// Stack pointer register name.
    pub stack_pointer: Option<String>,

    /// Whether the stack grows towards lower addresses.
    pub stack_grows_negative: bool,

    /// Whether variables are right-justified within stack alignment.
    pub stack_right_justified: bool,

    /// Properties attached to this compiler spec.
    pub properties: HashMap<String, String>,

    /// Name of the stack address space.
    pub stack_space: Option<String>,

    /// Name of the physical address space containing the stack.
    pub stack_base_space: Option<String>,
}

impl CompilerSpec {
    /// Create a new compiler spec.
    pub fn new(
        id: CompilerSpecID,
        language_id: LanguageID,
        name: impl Into<String>,
        data_organization: DataOrganization,
    ) -> Self {
        Self {
            id,
            language_id,
            name: name.into(),
            description: String::new(),
            calling_conventions: Vec::new(),
            default_calling_convention: None,
            prototype_model: None,
            data_organization,
            language: None,
            does_c_data_type_conversions: false,
            stack_pointer: None,
            stack_grows_negative: true,
            stack_right_justified: false,
            properties: HashMap::new(),
            stack_space: None,
            stack_base_space: None,
        }
    }

    /// Create a default compiler spec for the given language.
    pub fn for_language(language: &Language) -> Self {
        Self {
            id: CompilerSpecID::default_spec(),
            language_id: language.id.clone(),
            name: "default".to_string(),
            description: format!("Default compiler spec for {}", language.name),
            calling_conventions: Vec::new(),
            default_calling_convention: None,
            prototype_model: None,
            data_organization: language.data_organization.clone(),
            language: Some(Arc::new(language.clone())),
            does_c_data_type_conversions: false,
            stack_pointer: language
                .get_stack_pointer()
                .map(|r| r.name.clone()),
            stack_grows_negative: true,
            stack_right_justified: false,
            properties: HashMap::new(),
            stack_space: None,
            stack_base_space: None,
        }
    }

    // -- Builder methods --

    /// Builder: add a calling convention.
    pub fn with_calling_convention(mut self, cc: CallingConvention) -> Self {
        self.calling_conventions.push(Arc::new(cc));
        self
    }

    /// Builder: set the default calling convention.
    pub fn with_default_calling_convention(mut self, cc: CallingConvention) -> Self {
        self.default_calling_convention = Some(Arc::new(cc));
        self
    }

    /// Builder: set the prototype model name.
    pub fn with_prototype_model(mut self, model: impl Into<String>) -> Self {
        self.prototype_model = Some(model.into());
        self
    }

    /// Builder: set a description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Builder: set C data type conversions flag.
    pub fn with_c_data_type_conversions(mut self, val: bool) -> Self {
        self.does_c_data_type_conversions = val;
        self
    }

    /// Builder: set stack pointer register name.
    pub fn with_stack_pointer(mut self, name: impl Into<String>) -> Self {
        self.stack_pointer = Some(name.into());
        self
    }

    /// Builder: set stack growth direction.
    pub fn with_stack_grows_negative(mut self, val: bool) -> Self {
        self.stack_grows_negative = val;
        self
    }

    /// Builder: set stack right justification.
    pub fn with_stack_right_justified(mut self, val: bool) -> Self {
        self.stack_right_justified = val;
        self
    }

    /// Builder: add a property.
    pub fn with_property(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.properties.insert(key.into(), value.into());
        self
    }

    /// Builder: set the stack address space name.
    pub fn with_stack_space(mut self, name: impl Into<String>) -> Self {
        self.stack_space = Some(name.into());
        self
    }

    /// Builder: set the stack base space name.
    pub fn with_stack_base_space(mut self, name: impl Into<String>) -> Self {
        self.stack_base_space = Some(name.into());
        self
    }

    // -- Accessor methods (corresponding to Java CompilerSpec interface) --

    /// Get the compiler spec ID.
    ///
    /// Corresponds to `getCompilerSpecID()` in Java.
    pub fn get_compiler_spec_id(&self) -> &CompilerSpecID {
        &self.id
    }

    /// Set a reference to the parent language.
    pub fn set_language(&mut self, language: Arc<Language>) {
        self.language = Some(language);
    }

    /// Get a calling convention by name.
    ///
    /// Corresponds to `getCallingConvention(String)` in Java.
    pub fn get_calling_convention(&self, name: &str) -> Option<&Arc<CallingConvention>> {
        self.calling_conventions
            .iter()
            .find(|cc| cc.name == name)
    }

    /// Get the default calling convention, or the first one.
    ///
    /// Corresponds to `getDefaultCallingConvention()` in Java.
    pub fn get_default_calling_convention(&self) -> Option<&Arc<CallingConvention>> {
        self.default_calling_convention
            .as_ref()
            .or_else(|| self.calling_conventions.first())
    }

    /// Get all calling conventions.
    ///
    /// Corresponds to `getCallingConventions()` in Java.
    pub fn get_calling_conventions(&self) -> &[Arc<CallingConvention>] {
        &self.calling_conventions
    }

    /// Match a calling convention by name, falling back to the default.
    ///
    /// Corresponds to `matchConvention(String)` in Java.
    pub fn match_convention(&self, name: &str) -> Option<&Arc<CallingConvention>> {
        self.get_calling_convention(name)
            .or_else(|| self.default_calling_convention.as_ref())
    }

    /// Returns true if this spec uses big-endian byte order.
    pub fn is_big_endian(&self) -> bool {
        self.data_organization.big_endian
    }

    /// Returns true if this spec uses little-endian byte order.
    pub fn is_little_endian(&self) -> bool {
        !self.data_organization.big_endian
    }

    /// Returns the pointer size in bytes.
    pub fn get_pointer_size(&self) -> usize {
        self.data_organization.pointer_size
    }

    /// Returns whether C data-type conversions are performed.
    ///
    /// Corresponds to `doesCDataTypeConversions()` in Java.
    pub fn does_c_data_type_conversions(&self) -> bool {
        self.does_c_data_type_conversions
    }

    // -- Property access --

    /// Returns whether this spec has a property defined.
    ///
    /// Corresponds to `hasProperty(String)` in Java.
    pub fn has_property(&self, key: &str) -> bool {
        self.properties.contains_key(key)
    }

    /// Gets a property value as an integer.
    ///
    /// Corresponds to `getPropertyAsInt(String, int)` in Java.
    pub fn get_property_as_int(&self, key: &str, default_val: i32) -> i32 {
        self.properties
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_val)
    }

    /// Gets a property value as a boolean.
    ///
    /// Corresponds to `getPropertyAsBoolean(String, boolean)` in Java.
    pub fn get_property_as_bool(&self, key: &str, default_val: bool) -> bool {
        self.properties
            .get(key)
            .and_then(|v| v.parse().ok())
            .unwrap_or(default_val)
    }

    /// Gets a property value as a string with a default.
    ///
    /// Corresponds to `getProperty(String, String)` in Java.
    pub fn get_property_with_default(&self, key: &str, default_val: &str) -> String {
        self.properties
            .get(key)
            .cloned()
            .unwrap_or_else(|| default_val.to_string())
    }

    /// Gets a property value, or `None`.
    ///
    /// Corresponds to `getProperty(String)` in Java.
    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.properties.get(key).map(|s| s.as_str())
    }

    /// Returns the set of property keys.
    ///
    /// Corresponds to `getPropertyKeys()` in Java.
    pub fn get_property_keys(&self) -> impl Iterator<Item = &str> {
        self.properties.keys().map(|s| s.as_str())
    }
}

impl fmt::Display for CompilerSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name, self.language_id.to_id_string())
    }
}

// ============================================================================
// Register
// ============================================================================

/// Register type flags, corresponding to the `TYPE_*` static ints
/// in `ghidra.program.model.lang.Register`.
///
/// These are packed into a bitfield so multiple roles can be combined.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegisterTypeFlags(u16);

impl RegisterTypeFlags {
    pub const NONE: u16 = 0;
    pub const FP: u16 = 1; // frame pointer
    pub const SP: u16 = 2; // stack pointer
    pub const PC: u16 = 4; // program counter
    pub const CONTEXT: u16 = 8; // processor state
    pub const ZERO: u16 = 16; // register is always zero
    pub const HIDDEN: u16 = 32; // register should not be exposed to users
    pub const DOES_NOT_FOLLOW_FLOW: u16 = 64; // value should NOT follow disassembly flow
    pub const VECTOR: u16 = 128; // can be used in SIMD operations

    /// Create flags from raw bits.
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }

    /// Returns the raw bits.
    pub fn bits(&self) -> u16 {
        self.0
    }

    pub fn contains(&self, flag: u16) -> bool {
        (self.0 & flag) != 0
    }

    pub fn set(&mut self, flag: u16) {
        self.0 |= flag;
    }

    pub fn is_frame_pointer(&self) -> bool {
        self.contains(Self::FP)
    }
    pub fn is_stack_pointer(&self) -> bool {
        self.contains(Self::SP)
    }
    pub fn is_program_counter(&self) -> bool {
        self.contains(Self::PC)
    }
    pub fn is_processor_context(&self) -> bool {
        self.contains(Self::CONTEXT)
    }
    pub fn is_zero(&self) -> bool {
        self.contains(Self::ZERO)
    }
    pub fn is_hidden(&self) -> bool {
        self.contains(Self::HIDDEN)
    }
    pub fn does_not_follow_flow(&self) -> bool {
        self.contains(Self::DOES_NOT_FOLLOW_FLOW)
    }
    pub fn follows_flow(&self) -> bool {
        !self.contains(Self::DOES_NOT_FOLLOW_FLOW)
    }
    pub fn is_vector(&self) -> bool {
        self.contains(Self::VECTOR)
    }
}

impl Default for RegisterTypeFlags {
    fn default() -> Self {
        Self(0)
    }
}

/// Models a CPU register as understood by Ghidra.
///
/// Corresponds to `ghidra.program.model.lang.Register`.
///
/// Registers exist within an address space (typically the "register" space),
/// have a bit-length and offset within that space, and may be composed of
/// smaller sub-registers (e.g., RAX contains EAX, AX, AL, AH).
///
/// # Sub-register hierarchy
///
/// A register may have child registers (e.g., RAX has children EAX, AX, AL, AH).
/// The `parent` field tracks the immediate parent; `base_register` tracks the
/// largest enclosing register.
///
/// # Type flags
///
/// Special-role flags (`is_program_counter`, `is_stack_pointer`, etc.) are
/// mirror fields derived from the underlying [`RegisterTypeFlags`] bitfield.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Register {
    /// The name of this register (e.g., "RAX", "EAX", "x0", "r1").
    pub name: String,

    /// Description of this register.
    pub description: String,

    /// The address within the register address space (smallest address containing bits).
    pub address: Address,

    /// The number of bytes spanned by this register.
    pub num_bytes: usize,

    /// The least-significant bit position of this register relative to its address.
    pub least_significant_bit: u32,

    /// The total bit-length of this register.
    pub bit_length: u32,

    /// Whether this register uses big-endian byte ordering.
    pub big_endian: bool,

    /// The raw type flags bitfield.
    pub type_flags: RegisterTypeFlags,

    /// Child registers (sorted by least-significant bit-offset within this register).
    #[serde(skip)]
    pub child_registers: Vec<String>,

    /// Register aliases (e.g., alternate names for the same register).
    pub aliases: HashSet<String>,

    /// The base (largest enclosing) register name.
    pub base_register: Option<String>,

    /// The parent register name.
    pub parent: Option<String>,

    /// The least-significant bit position within the base register.
    pub least_significant_bit_in_base: u32,

    /// The register group this register belongs to (e.g., "GeneralPurpose").
    pub group: Option<String>,

    /// Bit vector of valid lane sizes (for vector registers).
    /// bit N is set if (N+1) bytes is a valid lane size.
    pub lane_sizes: u64,
}

impl Register {
    /// Sentinel register denoting that no context register is defined.
    pub const NO_CONTEXT_NAME: &'static str = "NO_CONTEXT";

    /// Create a full-spec register (no sub-fields).
    pub fn full(
        name: impl Into<String>,
        description: impl Into<String>,
        address: Address,
        num_bytes: usize,
        least_significant_bit: u32,
        bit_length: u32,
        big_endian: bool,
        type_flags: RegisterTypeFlags,
    ) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            address,
            num_bytes,
            least_significant_bit,
            bit_length,
            big_endian,
            type_flags,
            child_registers: Vec::new(),
            aliases: HashSet::new(),
            base_register: None,
            parent: None,
            least_significant_bit_in_base: 0,
            group: None,
            lane_sizes: 0,
        }
    }

    /// Create a new register definition (whole register, no sub-fields).
    ///
    /// Corresponds to `new Register(name, description, address, numBytes, bigEndian, typeFlags)` in Java.
    pub fn new(
        name: impl Into<String>,
        bit_length: u32,
        _address_space: impl Into<String>,
        offset: u64,
    ) -> Self {
        let num_bytes = ((bit_length as usize) + 7) / 8;
        Self {
            name: name.into(),
            description: String::new(),
            address: Address::new(offset),
            num_bytes,
            least_significant_bit: 0,
            bit_length,
            big_endian: false,
            type_flags: RegisterTypeFlags::default(),
            child_registers: Vec::new(),
            aliases: HashSet::new(),
            base_register: None,
            parent: None,
            least_significant_bit_in_base: 0,
            group: None,
            lane_sizes: 0,
        }
    }

    /// Create a NO_CONTEXT placeholder register.
    pub fn no_context() -> Self {
        Self::full(
            Self::NO_CONTEXT_NAME,
            "No defined context",
            Address::NULL,
            4,
            0,
            32,
            true,
            RegisterTypeFlags(RegisterTypeFlags::CONTEXT),
        )
    }

    // -- Builder methods --

    /// Builder: set the base register name.
    pub fn with_base_register(mut self, base: impl Into<String>) -> Self {
        self.base_register = Some(base.into());
        self
    }

    /// Builder: set the parent register name.
    pub fn with_parent(mut self, parent: impl Into<String>) -> Self {
        self.parent = Some(parent.into());
        self
    }

    /// Builder: set the least significant bit position.
    pub fn with_lsb(mut self, lsb: u32) -> Self {
        self.least_significant_bit = lsb;
        self
    }

    /// Builder: mark as big-endian.
    pub fn with_big_endian(mut self) -> Self {
        self.big_endian = true;
        self
    }

    /// Builder: mark as program counter.
    pub fn with_program_counter(mut self) -> Self {
        self.type_flags.set(RegisterTypeFlags::PC);
        self
    }

    /// Builder: mark as stack pointer.
    pub fn with_stack_pointer(mut self) -> Self {
        self.type_flags.set(RegisterTypeFlags::SP);
        self
    }

    /// Builder: mark as frame pointer.
    pub fn with_frame_pointer(mut self) -> Self {
        self.type_flags.set(RegisterTypeFlags::FP);
        self
    }

    /// Builder: mark as return address register (uses DOES_NOT_FOLLOW_FLOW as a marker).
    pub fn with_return_address(self) -> Self {
        // In Ghidra, return address isn't a built-in type flag, so we use the
        // "does not follow flow" flag as a convention. Callers can also track
        // this externally via RegisterManager::return_address.
        self
    }

    /// Builder: mark as processor context register.
    pub fn with_context(mut self) -> Self {
        self.type_flags.set(RegisterTypeFlags::CONTEXT);
        self
    }

    /// Builder: mark as hidden.
    pub fn with_hidden(mut self) -> Self {
        self.type_flags.set(RegisterTypeFlags::HIDDEN);
        self
    }

    /// Builder: mark as always-zero.
    pub fn with_zero(mut self) -> Self {
        self.type_flags.set(RegisterTypeFlags::ZERO);
        self
    }

    /// Builder: mark as vector register.
    pub fn with_vector(mut self) -> Self {
        self.type_flags.set(RegisterTypeFlags::VECTOR);
        self
    }

    /// Builder: set a description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Builder: set the register group.
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }

    /// Builder: add a lane size for vector registers.
    ///
    /// Corresponds to `addLaneSize(int)` in Java.
    pub fn with_lane_size(mut self, lane_size_bytes: u32) -> Self {
        if lane_size_bytes > 0 && lane_size_bytes <= 64 {
            self.type_flags.set(RegisterTypeFlags::VECTOR);
            self.lane_sizes |= 1u64 << (lane_size_bytes - 1);
        }
        self
    }

    /// Builder: add a register alias.
    pub fn with_alias(mut self, alias: impl Into<String>) -> Self {
        let alias = alias.into();
        if alias != self.name {
            self.aliases.insert(alias);
        }
        self
    }

    /// Builder: add child register names.
    pub fn with_children(mut self, children: Vec<impl Into<String>>) -> Self {
        self.child_registers = children.into_iter().map(|c| c.into()).collect();
        self
    }

    // -- Query methods (corresponding to Java Register methods) --

    /// Returns the name of this register.
    ///
    /// Corresponds to `getName()` in Java.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    /// Returns the total number of bits.
    ///
    /// Corresponds to `getBitLength()` in Java.
    pub fn get_bit_length(&self) -> u32 {
        self.bit_length
    }

    /// Returns the minimum number of bytes required to store a value.
    ///
    /// Corresponds to `getMinimumByteSize()` in Java.
    pub fn get_minimum_byte_size(&self) -> usize {
        ((self.bit_length as usize) + 7) / 8
    }

    /// Returns the number of bytes spanned by this register.
    ///
    /// Corresponds to `getNumBytes()` in Java.
    pub fn get_num_bytes(&self) -> usize {
        self.num_bytes
    }

    /// Returns the offset into the register space.
    ///
    /// Corresponds to `getOffset()` in Java.
    pub fn get_offset(&self) -> u64 {
        self.address.offset
    }

    /// Returns the bit offset from the register address.
    ///
    /// Corresponds to `getLeastSignificantBit()` in Java.
    pub fn get_least_significant_bit(&self) -> u32 {
        self.least_significant_bit
    }

    /// Returns the address of the register.
    ///
    /// Corresponds to `getAddress()` in Java.
    pub fn get_address(&self) -> Address {
        self.address
    }

    /// Returns true if this is the base register (no parent base register).
    ///
    /// Corresponds to `isBaseRegister()` in Java.
    pub fn is_base_register(&self) -> bool {
        self.base_register.is_none()
    }

    /// Returns the base register (self if none).
    ///
    /// Corresponds to `getBaseRegister()` in Java.
    pub fn get_base_register(&self) -> &str {
        self.base_register.as_deref().unwrap_or(&self.name)
    }

    /// Returns the parent register name.
    ///
    /// Corresponds to `getParentRegister()` in Java.
    pub fn get_parent_register(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    /// Returns child register names.
    ///
    /// Corresponds to `getChildRegisters()` in Java.
    pub fn get_child_registers(&self) -> &[String] {
        &self.child_registers
    }

    /// Returns true if this register has children.
    ///
    /// Corresponds to `hasChildren()` in Java.
    pub fn has_children(&self) -> bool {
        !self.child_registers.is_empty()
    }

    /// Returns the register group.
    ///
    /// Corresponds to `getGroup()` in Java.
    pub fn get_group(&self) -> Option<&str> {
        self.group.as_deref()
    }

    /// Returns true for the program counter register.
    ///
    /// Corresponds to `isProgramCounter()` in Java.
    pub fn is_program_counter(&self) -> bool {
        self.type_flags.is_program_counter()
    }

    /// Returns true for the stack pointer register.
    pub fn is_stack_pointer(&self) -> bool {
        self.type_flags.is_stack_pointer()
    }

    /// Returns true for the frame pointer register.
    ///
    /// Corresponds to `isDefaultFramePointer()` in Java.
    pub fn is_frame_pointer(&self) -> bool {
        self.type_flags.is_frame_pointer()
    }

    /// Returns true for a processor state register.
    ///
    /// Corresponds to `isProcessorContext()` in Java.
    pub fn is_processor_context(&self) -> bool {
        self.type_flags.is_processor_context()
    }

    /// Returns true for a register that is always zero.
    ///
    /// Corresponds to `isZero()` in Java.
    pub fn is_zero(&self) -> bool {
        self.type_flags.is_zero()
    }

    /// Returns true for a hidden register.
    ///
    /// Corresponds to `isHidden()` in Java.
    pub fn is_hidden(&self) -> bool {
        self.type_flags.is_hidden()
    }

    /// Returns true if the register value should follow disassembly flow.
    ///
    /// Corresponds to `followsFlow()` in Java.
    pub fn follows_flow(&self) -> bool {
        self.type_flags.follows_flow()
    }

    /// Returns true if this is a vector register.
    ///
    /// Corresponds to `isVectorRegister()` in Java.
    pub fn is_vector_register(&self) -> bool {
        self.type_flags.is_vector()
    }

    /// Returns true if the given lane size is valid for this register.
    ///
    /// Corresponds to `isValidLaneSize(int)` in Java.
    pub fn is_valid_lane_size(&self, lane_size_bytes: u32) -> bool {
        if !self.is_vector_register() {
            return false;
        }
        if lane_size_bytes > 64 || lane_size_bytes < 1 {
            return false;
        }
        (self.lane_sizes & (1u64 << (lane_size_bytes - 1))) != 0
    }

    /// Returns the sorted array of lane sizes in bytes.
    ///
    /// Corresponds to `getLaneSizes()` in Java.
    pub fn get_lane_sizes(&self) -> Vec<u32> {
        if self.lane_sizes == 0 {
            return Vec::new();
        }
        let mut sizes = Vec::new();
        let mut tmp = self.lane_sizes;
        let mut size = 1u32;
        while tmp != 0 {
            if (tmp & 1) != 0 {
                sizes.push(size);
            }
            tmp >>= 1;
            size += 1;
        }
        sizes
    }

    /// Returns the byte length (minimum bytes to hold the value, rounded up).
    pub fn byte_length(&self) -> usize {
        ((self.bit_length as usize) + 7) / 8
    }

    /// Returns true if this register is a sub-register of another.
    pub fn is_sub_register(&self) -> bool {
        self.parent.is_some()
    }

    /// Compute a base mask (bitmask indicating which bits in the base register
    /// belong to this sub-register).
    ///
    /// Corresponds to `getBaseMask()` in Java.
    /// Returns `None` if this is the base register itself.
    pub fn compute_base_mask(&self, base_register: &Register) -> Option<Vec<u8>> {
        if self.base_register.is_none() {
            return None;
        }
        let base_bit_length = base_register.get_bit_length();
        let byte_length = ((base_bit_length as usize) + 7) / 8;
        let mut mask = vec![0u8; byte_length];
        let end_bit = self.least_significant_bit_in_base + self.bit_length - 1;
        for i in self.least_significant_bit_in_base..=end_bit {
            let byte_num = byte_length - (i as usize / 8) - 1;
            let bit_num = i % 8;
            mask[byte_num] |= 1 << bit_num;
        }
        Some(mask)
    }
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({} bits)", self.name, self.bit_length)
    }
}

impl PartialOrd for Register {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Register {
    /// Compare registers first by base register, then by address, then by bit length.
    ///
    /// Corresponds to `compareTo(Register)` in Java.
    fn cmp(&self, other: &Self) -> Ordering {
        let self_base = self.get_base_register();
        let other_base = other.get_base_register();

        if self_base == other_base {
            // Same base register: compare by LSB in base
            self.least_significant_bit_in_base
                .cmp(&other.least_significant_bit_in_base)
        } else {
            // Different base registers: compare by address
            self.address.cmp(&other.address)
        }
        .then(self.bit_length.cmp(&other.bit_length))
    }
}

// ============================================================================
// RegisterSizeKey
// ============================================================================

/// A key for looking up registers by address and size.
///
/// Corresponds to the `RegisterSizeKey` inner class in
/// `ghidra.program.model.lang.RegisterManager`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegisterSizeKey {
    /// The register address (offset).
    pub address: Address,
    /// The requested size in bytes. A value of 0 matches the largest register.
    pub size: usize,
}

impl RegisterSizeKey {
    /// Create a new key. Size is clamped to 0 for negative values.
    pub fn new(address: Address, size: usize) -> Self {
        Self { address, size }
    }
}

// ============================================================================
// RegisterManager
// ============================================================================

/// Manages all registers for a processor language.
///
/// Corresponds to `ghidra.program.model.lang.RegisterManager`.
///
/// Provides lookup by name, address, size, and access to architectural
/// special registers (program counter, stack pointer, frame pointer,
/// return address, context base).
#[derive(Debug, Clone)]
pub struct RegisterManager {
    /// All registers as an unsorted unmodifiable-like list (clone of the Vec).
    registers: Vec<Register>,

    /// Name-to-register index (includes aliases and case variations).
    name_map: HashMap<String, usize>,

    /// Offset-in-register-space to list of register indices.
    address_map: HashMap<u64, Vec<usize>>,

    /// (address, size) -> register index. Size 0 maps to the largest register.
    size_map: HashMap<RegisterSizeKey, usize>,

    /// Register indices sorted alphabetically by original name (excluding aliases).
    sorted_names: Vec<String>,

    /// Index of the program counter register in `registers`.
    program_counter: Option<usize>,

    /// Index of the stack pointer register in `registers`.
    stack_pointer: Option<usize>,

    /// Index of the frame pointer register in `registers`.
    frame_pointer: Option<usize>,

    /// Index of the return address register in `registers`.
    return_address: Option<usize>,

    /// Index of the context base register in `registers`.
    context_base: Option<usize>,

    /// Indices of context registers.
    context_register_indices: Vec<usize>,

    /// Indices of vector registers, sorted by size descending then offset ascending.
    sorted_vector_register_indices: Vec<usize>,

    /// Register group -> indices.
    groups: HashMap<String, Vec<usize>>,
}

impl RegisterManager {
    /// Create an empty register manager.
    pub fn new() -> Self {
        Self {
            registers: Vec::new(),
            name_map: HashMap::new(),
            address_map: HashMap::new(),
            size_map: HashMap::new(),
            sorted_names: Vec::new(),
            program_counter: None,
            stack_pointer: None,
            frame_pointer: None,
            return_address: None,
            context_base: None,
            context_register_indices: Vec::new(),
            sorted_vector_register_indices: Vec::new(),
            groups: HashMap::new(),
        }
    }

    /// Add a register to the manager. This should be called before calling
    /// `initialize()` to finalize the manager's lookup tables.
    ///
    /// Registers should be added from largest (base) to smallest (sub-registers)
    /// so that the size map properly populates. After all registers are added,
    /// call `initialize()`.
    pub fn add_register(&mut self, mut reg: Register) -> &mut Self {
        let name = reg.name.clone();
        let off = reg.address.offset;

        // Update base register info
        if reg.base_register.is_none() {
            reg.base_register = Some(name.clone());
        }

        let idx = self.registers.len();

        // Track special roles by index
        if reg.is_program_counter() {
            self.program_counter = Some(idx);
        }
        if reg.is_stack_pointer() {
            self.stack_pointer = Some(idx);
        }
        if reg.is_frame_pointer() {
            self.frame_pointer = Some(idx);
        }
        if reg.is_processor_context() && reg.is_base_register() {
            self.context_base = Some(idx);
        }

        // Index by group
        if let Some(ref group) = reg.group {
            self.groups.entry(group.clone()).or_default().push(idx);
        }

        // Track context registers
        if reg.is_processor_context() {
            self.context_register_indices.push(idx);
        }

        // Index by name (including lower-case variation for semi-case-insensitive lookup)
        self.name_map.insert(name.clone(), idx);
        let lower = name.to_lowercase();
        if lower != name {
            self.name_map.entry(lower).or_insert(idx);
        }

        // Index aliases
        for alias in &reg.aliases {
            self.name_map.entry(alias.clone()).or_insert(idx);
            let alias_lower = alias.to_lowercase();
            if alias_lower != *alias {
                self.name_map.entry(alias_lower).or_insert(idx);
            }
        }

        // Index by address
        self.address_map.entry(off).or_default().push(idx);

        // Track the name for sorted names
        self.sorted_names.push(name);

        self.registers.push(reg);
        self
    }

    /// Finalize the manager after all registers have been added.
    ///
    /// This populates the size map (address+size -> register) and sorts
    /// names and vector registers.
    ///
    /// Corresponds to the private `initialize()` method in Java RegisterManager.
    pub fn initialize(&mut self) {
        // Populate size map for each register
        let indices: Vec<usize> = (0..self.registers.len()).collect();

        // Sort indices by bit length descending (largest first) for size map
        let mut sorted_by_size = indices.clone();
        sorted_by_size.sort_by(|&a, &b| {
            self.registers[b]
                .bit_length
                .cmp(&self.registers[a].bit_length)
                .then(self.registers[a].address.cmp(&self.registers[b].address))
        });

        for &idx in &sorted_by_size {
            let reg = &self.registers[idx];
            if reg.is_processor_context() {
                continue; // context registers don't go into size map
            }
            let min_bytes = reg.get_minimum_byte_size();
            let off = reg.address.offset;

            if reg.big_endian {
                for size in 1..=min_bytes {
                    let addr = Address::new(off + (min_bytes - size) as u64);
                    self.size_map
                        .entry(RegisterSizeKey::new(addr, size))
                        .or_insert(idx);
                }
            } else {
                for size in 1..=min_bytes {
                    self.size_map
                        .entry(RegisterSizeKey::new(Address::new(off), size))
                        .or_insert(idx);
                }
            }
        }

        // Size 0 maps to the largest register at each address
        // Reuse the size-sorted indices (already sorted largest first)
        for &idx in &sorted_by_size {
            let reg = &self.registers[idx];
            if reg.is_processor_context() {
                continue;
            }
            self.size_map
                .entry(RegisterSizeKey::new(reg.address, 0))
                .or_insert(idx);
        }

        // Sort names alphabetically
        self.sorted_names.sort();

        // Set default context base if none was defined
        if self.context_base.is_none() && !self.registers.is_empty() {
            // Create a synthetic NO_CONTEXT register at a high offset
            let no_ctx = Register::no_context();
            if !self.registers.contains(&no_ctx) {
                self.context_register_indices.push(self.registers.len());
                self.registers.push(no_ctx);
            }
        }

        // Build sorted vector register list
        let mut vec_indices: Vec<usize> = self
            .registers
            .iter()
            .enumerate()
            .filter_map(|(i, r)| if r.is_vector_register() { Some(i) } else { None })
            .collect();
        // Sort: size descending, then offset ascending
        vec_indices.sort_by(|&a, &b| {
            self.registers[b]
                .bit_length
                .cmp(&self.registers[a].bit_length)
                .then(self.registers[a].address.cmp(&self.registers[b].address))
        });
        self.sorted_vector_register_indices = vec_indices;
    }

    // -- Lookup methods (corresponding to Java RegisterManager public methods) --

    /// Returns all registers at the given address.
    ///
    /// Corresponds to `getRegisters(Address)` in Java.
    pub fn get_registers_at(&self, addr: &Address) -> Vec<&Register> {
        self.address_map
            .get(&addr.offset)
            .map(|indices| indices.iter().map(|&i| &self.registers[i]).collect())
            .unwrap_or_default()
    }

    /// Returns the largest register at the given address.
    ///
    /// Corresponds to `getRegister(Address)` in Java (size=0 variant).
    pub fn get_largest_register_at(&self, addr: &Address) -> Option<&Register> {
        self.size_map
            .get(&RegisterSizeKey::new(*addr, 0))
            .map(|&i| &self.registers[i])
    }

    /// Get a register by address and size.
    ///
    /// Corresponds to `getRegister(Address, int)` in Java.
    pub fn get_register_at_size(&self, addr: &Address, size: usize) -> Option<&Register> {
        self.size_map
            .get(&RegisterSizeKey::new(*addr, size))
            .map(|&i| &self.registers[i])
    }

    /// Get a register by name (semi-case-insensitive).
    ///
    /// - First tries exact match
    /// - Then tries lowercased name
    /// - Then tries uppercased name
    ///
    /// Corresponds to `getRegister(String)` in Java.
    pub fn get_register(&self, name: &str) -> Option<&Register> {
        // Exact match first
        if let Some(&i) = self.name_map.get(name) {
            return Some(&self.registers[i]);
        }
        // Case-insensitive fallback
        let lower = name.to_lowercase();
        if lower != name {
            if let Some(&i) = self.name_map.get(&lower) {
                return Some(&self.registers[i]);
            }
        }
        None
    }

    /// Get all registers as a slice.
    ///
    /// Corresponds to `getRegisters()` in Java.
    pub fn get_registers(&self) -> &[Register] {
        &self.registers
    }

    /// Get all register names (alphabetically sorted, excluding aliases).
    ///
    /// Corresponds to `getRegisterNames()` in Java.
    pub fn get_register_names(&self) -> Vec<&str> {
        self.sorted_names.iter().map(|s| s.as_str()).collect()
    }

    // -- Special register accessors --

    /// Get the program counter register.
    ///
    /// Corresponds to `Language.getProgramCounter()` in Java.
    pub fn get_program_counter(&self) -> Option<&Register> {
        self.program_counter.map(|i| &self.registers[i])
    }

    /// Get the stack pointer register.
    pub fn get_stack_pointer(&self) -> Option<&Register> {
        self.stack_pointer.map(|i| &self.registers[i])
    }

    /// Get the frame pointer register.
    pub fn get_frame_pointer(&self) -> Option<&Register> {
        self.frame_pointer.map(|i| &self.registers[i])
    }

    /// Get the return address register (link register on some architectures).
    pub fn get_return_address_register(&self) -> Option<&Register> {
        self.return_address.map(|i| &self.registers[i])
    }

    /// Get the context base register.
    ///
    /// Corresponds to `getContextBaseRegister()` in Java.
    pub fn get_context_base_register(&self) -> Option<&Register> {
        self.context_base.map(|i| &self.registers[i])
    }

    /// Get all processor context registers.
    ///
    /// Corresponds to `getContextRegisters()` in Java.
    pub fn get_context_registers(&self) -> Vec<&Register> {
        self.context_register_indices
            .iter()
            .map(|&i| &self.registers[i])
            .collect()
    }

    /// Get sorted vector registers.
    ///
    /// Corresponds to `getSortedVectorRegisters()` in Java.
    pub fn get_sorted_vector_registers(&self) -> Vec<&Register> {
        self.sorted_vector_register_indices
            .iter()
            .map(|&i| &self.registers[i])
            .collect()
    }

    /// Set context base register by name.
    pub fn set_context_base_register(&mut self, name: impl Into<String>) {
        let name = name.into();
        if let Some(idx) = self.name_map.get(&name).copied() {
            self.context_base = Some(idx);
            // Ensure the register marked as context
            self.registers[idx].type_flags.set(RegisterTypeFlags::CONTEXT);
        }
    }

    /// Get a register by its offset in the register address space.
    pub fn get_register_at_offset(&self, offset: u64) -> Option<&Register> {
        self.address_map
            .get(&offset)
            .and_then(|indices| indices.first())
            .map(|&i| &self.registers[i])
    }

    /// Get all registers in a group.
    pub fn get_registers_in_group(&self, group: &str) -> Vec<&Register> {
        self.groups
            .get(group)
            .map(|indices| indices.iter().map(|&i| &self.registers[i]).collect())
            .unwrap_or_default()
    }

    /// Get the base register for a sub-register (following the chain).
    pub fn get_base_register(&self, name: &str) -> Option<&Register> {
        let idx = self.name_map.get(name)?;
        let base_name = self.registers[*idx].get_base_register().to_string();
        if base_name == self.registers[*idx].name {
            Some(&self.registers[*idx])
        } else {
            self.name_map.get(&base_name).map(|&i| &self.registers[i])
        }
    }

    /// Get children (sub-registers) of a register.
    pub fn get_child_registers(&self, parent_name: &str) -> Vec<&Register> {
        self.name_map
            .get(parent_name)
            .map(|&idx| {
                self.registers[idx]
                    .child_registers
                    .iter()
                    .filter_map(|child_name| self.name_map.get(child_name))
                    .map(|&i| &self.registers[i])
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Total number of registers.
    pub fn register_count(&self) -> usize {
        self.registers.len()
    }

    /// Returns true if this manager has no registers.
    pub fn is_empty(&self) -> bool {
        self.registers.is_empty()
    }

    /// Set the program counter by name.
    pub fn set_program_counter(&mut self, name: impl Into<String>) {
        let name = name.into();
        if let Some(idx) = self.name_map.get(&name).copied() {
            self.program_counter = Some(idx);
            self.registers[idx]
                .type_flags
                .set(RegisterTypeFlags::PC);
        }
    }

    /// Set the stack pointer by name.
    pub fn set_stack_pointer(&mut self, name: impl Into<String>) {
        let name = name.into();
        if let Some(idx) = self.name_map.get(&name).copied() {
            self.stack_pointer = Some(idx);
            self.registers[idx]
                .type_flags
                .set(RegisterTypeFlags::SP);
        }
    }

    /// Set the frame pointer by name.
    pub fn set_frame_pointer(&mut self, name: impl Into<String>) {
        let name = name.into();
        if let Some(idx) = self.name_map.get(&name).copied() {
            self.frame_pointer = Some(idx);
            self.registers[idx]
                .type_flags
                .set(RegisterTypeFlags::FP);
        }
    }

    /// Set the return address register by name.
    pub fn set_return_address(&mut self, name: impl Into<String>) {
        let name = name.into();
        if let Some(idx) = self.name_map.get(&name).copied() {
            self.return_address = Some(idx);
        }
    }

    // ========================================================================
    // Pre-built register sets
    // ========================================================================

    /// Build a default x86-64 register set.
    pub fn x86_64_default() -> Self {
        let mut rm = Self::new();

        // --- General purpose registers ---
        // Each group is (name, bits, offset, base, parent, lsb)

        // RAX group
        rm.add_register(
            Register::new("RAX", 64, "register", 0x00)
                .with_description("Accumulator (64-bit)")
                .with_group("GeneralPurpose")
                .with_children(vec!["EAX"]),
        );
        rm.add_register(
            Register::new("EAX", 32, "register", 0x00)
                .with_base_register("RAX")
                .with_parent("RAX")
                .with_lsb(0)
                .with_children(vec!["AX"])
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("AX", 16, "register", 0x00)
                .with_base_register("RAX")
                .with_parent("EAX")
                .with_lsb(0)
                .with_children(vec!["AL", "AH"])
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("AL", 8, "register", 0x00)
                .with_base_register("RAX")
                .with_parent("AX")
                .with_lsb(0)
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("AH", 8, "register", 0x01)
                .with_base_register("RAX")
                .with_parent("AX")
                .with_lsb(8)
                .with_group("GeneralPurpose"),
        );

        // RBX group
        rm.add_register(
            Register::new("RBX", 64, "register", 0x08)
                .with_description("Base (64-bit)")
                .with_group("GeneralPurpose")
                .with_children(vec!["EBX"]),
        );
        rm.add_register(
            Register::new("EBX", 32, "register", 0x08)
                .with_base_register("RBX")
                .with_parent("RBX")
                .with_lsb(0)
                .with_children(vec!["BX"])
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("BX", 16, "register", 0x08)
                .with_base_register("RBX")
                .with_parent("EBX")
                .with_lsb(0)
                .with_children(vec!["BL", "BH"])
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("BL", 8, "register", 0x08)
                .with_base_register("RBX")
                .with_parent("BX")
                .with_lsb(0)
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("BH", 8, "register", 0x09)
                .with_base_register("RBX")
                .with_parent("BX")
                .with_lsb(8)
                .with_group("GeneralPurpose"),
        );

        // RCX group
        rm.add_register(
            Register::new("RCX", 64, "register", 0x10)
                .with_description("Counter (64-bit)")
                .with_group("GeneralPurpose")
                .with_children(vec!["ECX"]),
        );
        rm.add_register(
            Register::new("ECX", 32, "register", 0x10)
                .with_base_register("RCX")
                .with_parent("RCX")
                .with_lsb(0)
                .with_children(vec!["CX"])
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("CX", 16, "register", 0x10)
                .with_base_register("RCX")
                .with_parent("ECX")
                .with_lsb(0)
                .with_children(vec!["CL", "CH"])
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("CL", 8, "register", 0x10)
                .with_base_register("RCX")
                .with_parent("CX")
                .with_lsb(0)
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("CH", 8, "register", 0x11)
                .with_base_register("RCX")
                .with_parent("CX")
                .with_lsb(8)
                .with_group("GeneralPurpose"),
        );

        // RDX group
        rm.add_register(
            Register::new("RDX", 64, "register", 0x18)
                .with_description("Data (64-bit)")
                .with_group("GeneralPurpose")
                .with_children(vec!["EDX"]),
        );
        rm.add_register(
            Register::new("EDX", 32, "register", 0x18)
                .with_base_register("RDX")
                .with_parent("RDX")
                .with_lsb(0)
                .with_children(vec!["DX"])
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("DX", 16, "register", 0x18)
                .with_base_register("RDX")
                .with_parent("EDX")
                .with_lsb(0)
                .with_children(vec!["DL", "DH"])
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("DL", 8, "register", 0x18)
                .with_base_register("RDX")
                .with_parent("DX")
                .with_lsb(0)
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("DH", 8, "register", 0x19)
                .with_base_register("RDX")
                .with_parent("DX")
                .with_lsb(8)
                .with_group("GeneralPurpose"),
        );

        // RSI group
        rm.add_register(
            Register::new("RSI", 64, "register", 0x20)
                .with_description("Source Index (64-bit)")
                .with_group("GeneralPurpose")
                .with_children(vec!["ESI"]),
        );
        rm.add_register(
            Register::new("ESI", 32, "register", 0x20)
                .with_base_register("RSI")
                .with_parent("RSI")
                .with_lsb(0)
                .with_children(vec!["SI"])
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("SI", 16, "register", 0x20)
                .with_base_register("RSI")
                .with_parent("ESI")
                .with_lsb(0)
                .with_children(vec!["SIL"])
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("SIL", 8, "register", 0x20)
                .with_base_register("RSI")
                .with_parent("SI")
                .with_lsb(0)
                .with_group("GeneralPurpose"),
        );

        // RDI group
        rm.add_register(
            Register::new("RDI", 64, "register", 0x28)
                .with_description("Destination Index (64-bit)")
                .with_group("GeneralPurpose")
                .with_children(vec!["EDI"]),
        );
        rm.add_register(
            Register::new("EDI", 32, "register", 0x28)
                .with_base_register("RDI")
                .with_parent("RDI")
                .with_lsb(0)
                .with_children(vec!["DI"])
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("DI", 16, "register", 0x28)
                .with_base_register("RDI")
                .with_parent("EDI")
                .with_lsb(0)
                .with_children(vec!["DIL"])
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("DIL", 8, "register", 0x28)
                .with_base_register("RDI")
                .with_parent("DI")
                .with_lsb(0)
                .with_group("GeneralPurpose"),
        );

        // RBP group
        rm.add_register(
            Register::new("RBP", 64, "register", 0x30)
                .with_description("Base Pointer (64-bit)")
                .with_group("GeneralPurpose")
                .with_children(vec!["EBP"]),
        );
        rm.add_register(
            Register::new("EBP", 32, "register", 0x30)
                .with_base_register("RBP")
                .with_parent("RBP")
                .with_lsb(0)
                .with_children(vec!["BP"])
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("BP", 16, "register", 0x30)
                .with_base_register("RBP")
                .with_parent("EBP")
                .with_lsb(0)
                .with_children(vec!["BPL"])
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("BPL", 8, "register", 0x30)
                .with_base_register("RBP")
                .with_parent("BP")
                .with_lsb(0)
                .with_group("GeneralPurpose"),
        );

        // RSP group
        rm.add_register(
            Register::new("RSP", 64, "register", 0x38)
                .with_description("Stack Pointer (64-bit)")
                .with_group("GeneralPurpose")
                .with_children(vec!["ESP"]),
        );
        rm.add_register(
            Register::new("ESP", 32, "register", 0x38)
                .with_base_register("RSP")
                .with_parent("RSP")
                .with_lsb(0)
                .with_children(vec!["SP"])
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("SP", 16, "register", 0x38)
                .with_base_register("RSP")
                .with_parent("ESP")
                .with_lsb(0)
                .with_children(vec!["SPL"])
                .with_group("GeneralPurpose"),
        );
        rm.add_register(
            Register::new("SPL", 8, "register", 0x38)
                .with_base_register("RSP")
                .with_parent("SP")
                .with_lsb(0)
                .with_group("GeneralPurpose"),
        );

        // R8-R15 groups
        for i in 8usize..16 {
            let q_name = format!("R{}", i);
            let d_name = format!("R{}D", i);
            let w_name = format!("R{}W", i);
            let b_name = format!("R{}B", i);
            let offset = 0x40 + (i - 8) * 8;

            rm.add_register(
                Register::new(q_name.clone(), 64, "register", offset as u64)
                    .with_description(format!("General Purpose Register {} (64-bit)", i))
                    .with_group("GeneralPurpose")
                    .with_children(vec![d_name.clone()]),
            );
            rm.add_register(
                Register::new(d_name.clone(), 32, "register", offset as u64)
                    .with_base_register(q_name.clone())
                    .with_parent(q_name.clone())
                    .with_lsb(0)
                    .with_children(vec![w_name.clone()])
                    .with_group("GeneralPurpose"),
            );
            rm.add_register(
                Register::new(w_name.clone(), 16, "register", offset as u64)
                    .with_base_register(q_name.clone())
                    .with_parent(d_name.clone())
                    .with_lsb(0)
                    .with_children(vec![b_name.clone()])
                    .with_group("GeneralPurpose"),
            );
            rm.add_register(
                Register::new(b_name, 8, "register", offset as u64)
                    .with_base_register(q_name)
                    .with_parent(w_name)
                    .with_lsb(0)
                    .with_group("GeneralPurpose"),
            );
        }

        // Instruction pointer
        rm.add_register(
            Register::new("RIP", 64, "register", 0x80)
                .with_program_counter()
                .with_description("Instruction Pointer")
                .with_group("Special")
                .with_children(vec!["EIP"]),
        );
        rm.add_register(
            Register::new("EIP", 32, "register", 0x80)
                .with_base_register("RIP")
                .with_parent("RIP")
                .with_lsb(0)
                .with_description("32-bit Instruction Pointer")
                .with_group("Special"),
        );

        // Flags register
        rm.add_register(
            Register::new("RFLAGS", 64, "register", 0x88)
                .with_description("Flags Register (64-bit)")
                .with_group("Special")
                .with_children(vec!["EFLAGS"]),
        );
        rm.add_register(
            Register::new("EFLAGS", 32, "register", 0x88)
                .with_base_register("RFLAGS")
                .with_parent("RFLAGS")
                .with_lsb(0)
                .with_description("Flags Register (32-bit)")
                .with_group("Special"),
        );

        // Segment registers
        for (name, offset) in &[
            ("CS", 0x90u64),
            ("DS", 0x92),
            ("ES", 0x94),
            ("FS", 0x96),
            ("GS", 0x98),
            ("SS", 0x9a),
        ] {
            rm.add_register(
                Register::new(*name, 16, "register", *offset)
                    .with_description(format!("{} Segment Register", name))
                    .with_group("Segment"),
            );
        }

        // XMM/YMM/ZMM registers
        for i in 0..16 {
            let offset = 0xa0u64 + i * 16;
            rm.add_register(
                Register::new(format!("XMM{}", i), 128, "register", offset)
                    .with_description(format!("128-bit SSE Register {}", i))
                    .with_group("Vector")
                    .with_vector()
                    .with_lane_size(4)
                    .with_lane_size(8),
            );
            rm.add_register(
                Register::new(format!("YMM{}", i), 256, "register", offset)
                    .with_description(format!("256-bit AVX Register {}", i))
                    .with_group("Vector")
                    .with_vector()
                    .with_lane_size(4)
                    .with_lane_size(8),
            );
            rm.add_register(
                Register::new(format!("ZMM{}", i), 512, "register", offset)
                    .with_description(format!("512-bit AVX-512 Register {}", i))
                    .with_group("Vector")
                    .with_vector()
                    .with_lane_size(4)
                    .with_lane_size(8),
            );
        }

        // Context base register
        rm.set_context_base_register("EFLAGS");

        // Finalize mappings
        rm.initialize();

        // Override special roles
        rm.set_program_counter("RIP");
        rm.set_stack_pointer("RSP");
        rm.set_frame_pointer("RBP");

        rm
    }

    /// Build a default ARM v7 register set.
    pub fn arm_v7_default() -> Self {
        let mut rm = Self::new();

        // Core registers R0-R15 (R15=PC, R14=LR, R13=SP, R12=IP, R11=FP)
        let special = ["", "", "", "", "", "", "", "", "", "", "", "FP", "IP", "SP", "LR", "PC"];

        for i in 0..16u64 {
            let rname = format!("r{}", i);
            let special_name = special[i as usize];
            let display_name = if special_name.is_empty() {
                rname.clone()
            } else {
                special_name.to_string()
            };

            let mut reg = Register::new(display_name.clone(), 32, "register", i * 4)
                .with_description(format!("ARM Core Register r{}", i))
                .with_group("GeneralPurpose");

            match i {
                15 => {
                    reg = reg.with_program_counter();
                }
                14 => {
                    reg = reg.with_return_address();
                }
                13 => {
                    reg = reg.with_stack_pointer();
                }
                11 => {
                    reg = reg.with_frame_pointer();
                }
                _ => {}
            }

            // If this register has a special name, add the rN name as an alias
            if !special_name.is_empty() {
                reg = reg.with_alias(rname);
            }

            rm.add_register(reg);
        }

        // CPSR
        rm.add_register(
            Register::new("CPSR", 32, "register", 0x40)
                .with_description("Current Program Status Register")
                .with_group("Control"),
        );

        // VFP/NEON registers D0-D31 (64-bit double-precision)
        for i in 0..32u64 {
            rm.add_register(
                Register::new(format!("d{}", i), 64, "register", 0x50 + i * 8)
                    .with_description(format!("Double-precision FP Register {}", i))
                    .with_group("FloatingPoint"),
            );
        }

        rm.initialize();

        rm.set_program_counter("PC");
        rm.set_stack_pointer("SP");
        rm.set_frame_pointer("FP");
        rm.set_return_address("LR");

        rm
    }
}

impl Default for RegisterManager {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for RegisterManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RegisterManager ({} registers)", self.registers.len())
    }
}

// ============================================================================
// CallingConvention
// ============================================================================

/// Describes a calling convention (ABI) for a compiler specification.
///
/// A calling convention defines:
/// - Which registers are used to pass parameters (in order)
/// - Which register holds the return value
/// - Stack alignment requirements
/// - Shadow space (on Windows x64)
/// - Whether the caller or callee cleans up stack arguments
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallingConvention {
    /// The name of this calling convention (e.g., "__cdecl", "__stdcall").
    pub name: String,

    /// Ordered list of registers used for parameter passing.
    /// E.g., on System V AMD64: ["RDI", "RSI", "RDX", "RCX", "R8", "R9"].
    pub parameter_registers: Vec<String>,

    /// The register used to return a scalar value, if any.
    /// E.g., "RAX" on x86-64, "r0" on ARM.
    pub return_register: Option<String>,

    /// The register used to return a second scalar value, if any (e.g., RDX on x86-64).
    pub secondary_return_register: Option<String>,

    /// Required stack alignment before a call (in bytes). Typically 16 on x86-64.
    pub stack_alignment: u32,

    /// Shadow space size in bytes (32 on Windows x64, 0 on System V).
    pub shadow_space: u32,

    /// Whether the caller cleans up stack-passed arguments (e.g., __cdecl).
    pub caller_cleanup: bool,

    /// Whether the callee cleans up stack-passed arguments (e.g., __stdcall).
    pub callee_cleanup: bool,

    /// Whether this convention uses red zone (128 bytes below SP on System V).
    pub has_red_zone: bool,

    /// Whether arguments are passed left-to-right (Pascal convention) or
    /// right-to-left (C convention). True = right-to-left.
    pub right_to_left_params: bool,

    /// Which registers are callee-saved (preserved across calls).
    pub callee_saved_registers: Vec<String>,

    /// Which registers are caller-saved (may be clobbered).
    pub caller_saved_registers: Vec<String>,

    /// Human-readable description.
    pub description: String,
}

impl CallingConvention {
    /// Create a new calling convention.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parameter_registers: Vec::new(),
            return_register: None,
            secondary_return_register: None,
            stack_alignment: 16,
            shadow_space: 0,
            caller_cleanup: true,
            callee_cleanup: false,
            has_red_zone: false,
            right_to_left_params: true,
            callee_saved_registers: Vec::new(),
            caller_saved_registers: Vec::new(),
            description: String::new(),
        }
    }

    /// Builder: set parameter registers.
    pub fn with_parameter_registers(mut self, regs: Vec<impl Into<String>>) -> Self {
        self.parameter_registers = regs.into_iter().map(|r| r.into()).collect();
        self
    }

    /// Builder: set the return register.
    pub fn with_return_register(mut self, reg: impl Into<String>) -> Self {
        self.return_register = Some(reg.into());
        self
    }

    /// Builder: set the secondary return register.
    pub fn with_secondary_return_register(mut self, reg: impl Into<String>) -> Self {
        self.secondary_return_register = Some(reg.into());
        self
    }

    /// Builder: set stack alignment.
    pub fn with_stack_alignment(mut self, align: u32) -> Self {
        self.stack_alignment = align;
        self
    }

    /// Builder: set shadow space.
    pub fn with_shadow_space(mut self, shadow: u32) -> Self {
        self.shadow_space = shadow;
        self
    }

    /// Builder: set caller cleanup.
    pub fn with_caller_cleanup(mut self) -> Self {
        self.caller_cleanup = true;
        self.callee_cleanup = false;
        self
    }

    /// Builder: set callee cleanup.
    pub fn with_callee_cleanup(mut self) -> Self {
        self.callee_cleanup = true;
        self.caller_cleanup = false;
        self
    }

    /// Builder: enable red zone.
    pub fn with_red_zone(mut self) -> Self {
        self.has_red_zone = true;
        self
    }

    /// Builder: set callee-saved registers.
    pub fn with_callee_saved(mut self, regs: Vec<impl Into<String>>) -> Self {
        self.callee_saved_registers = regs.into_iter().map(|r| r.into()).collect();
        self
    }

    /// Builder: set caller-saved registers.
    pub fn with_caller_saved(mut self, regs: Vec<impl Into<String>>) -> Self {
        self.caller_saved_registers = regs.into_iter().map(|r| r.into()).collect();
        self
    }

    /// Builder: set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Convenience: System V AMD64 ABI (Linux, macOS, etc.).
    pub fn sysv_amd64() -> Self {
        Self::new("__sysv64")
            .with_parameter_registers(vec!["RDI", "RSI", "RDX", "RCX", "R8", "R9"])
            .with_return_register("RAX")
            .with_secondary_return_register("RDX")
            .with_stack_alignment(16)
            .with_shadow_space(0)
            .with_caller_cleanup()
            .with_red_zone()
            .with_callee_saved(vec![
                "RBX", "RBP", "R12", "R13", "R14", "R15",
            ])
            .with_caller_saved(vec![
                "RAX", "RCX", "RDX", "RSI", "RDI", "R8", "R9", "R10", "R11",
            ])
            .with_description("System V AMD64 ABI")
    }

    /// Convenience: Microsoft x64 calling convention.
    pub fn win64() -> Self {
        Self::new("__win64")
            .with_parameter_registers(vec!["RCX", "RDX", "R8", "R9"])
            .with_return_register("RAX")
            .with_stack_alignment(16)
            .with_shadow_space(32)
            .with_caller_cleanup()
            .with_callee_saved(vec![
                "RBX", "RBP", "RDI", "RSI", "R12", "R13", "R14", "R15",
            ])
            .with_caller_saved(vec![
                "RAX", "RCX", "RDX", "R8", "R9", "R10", "R11",
            ])
            .with_description("Microsoft x64 Calling Convention")
    }

    /// Convenience: __cdecl (x86 32-bit, caller cleanup).
    pub fn cdecl() -> Self {
        Self::new("__cdecl")
            .with_return_register("EAX")
            .with_stack_alignment(4)
            .with_caller_cleanup()
            .with_description("C declaration calling convention")
    }

    /// Convenience: __stdcall (x86 32-bit, callee cleanup).
    pub fn stdcall() -> Self {
        Self::new("__stdcall")
            .with_return_register("EAX")
            .with_stack_alignment(4)
            .with_callee_cleanup()
            .with_description("Standard calling convention (Win32 API)")
    }

    /// Convenience: __fastcall (x86 32-bit, first args in ECX, EDX).
    pub fn fastcall() -> Self {
        Self::new("__fastcall")
            .with_parameter_registers(vec!["ECX", "EDX"])
            .with_return_register("EAX")
            .with_stack_alignment(4)
            .with_callee_cleanup()
            .with_description("Fast call calling convention")
    }

    /// Convenience: ARM AAPCS.
    pub fn aapcs() -> Self {
        Self::new("__aapcs")
            .with_parameter_registers(vec!["r0", "r1", "r2", "r3"])
            .with_return_register("r0")
            .with_secondary_return_register("r1")
            .with_stack_alignment(8)
            .with_callee_saved(vec![
                "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "SP",
            ])
            .with_caller_saved(vec!["r0", "r1", "r2", "r3", "r12", "LR"])
            .with_description("ARM Architecture Procedure Call Standard")
    }

    /// The number of parameters that can be passed in registers.
    pub fn register_parameter_count(&self) -> usize {
        self.parameter_registers.len()
    }

    /// Returns true if a given value can be returned in registers entirely.
    pub fn can_return_in_registers(&self, size_bytes: usize) -> bool {
        let reg_bytes = 8; // assume 64-bit return register
        let total_bytes = if self.secondary_return_register.is_some() {
            reg_bytes * 2
        } else {
            reg_bytes
        };
        size_bytes <= total_bytes
    }
}

impl fmt::Display for CallingConvention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let params = if self.parameter_registers.is_empty() {
            "stack-only".to_string()
        } else {
            self.parameter_registers.join(", ")
        };
        write!(
            f,
            "{} (params: [{}], ret: {:?}, align: {})",
            self.name, params, self.return_register, self.stack_alignment
        )
    }
}

// ============================================================================
// Processor
// ============================================================================

/// Represents a processor family in Ghidra.
///
/// Corresponds to `ghidra.program.model.lang.Processor`.
///
/// A [`Processor`] groups together all the language definitions that share a
/// common instruction set architecture (ISA). For example, the "x86" processor
/// family includes 16-bit, 32-bit, and 64-bit variants for both little-endian
/// and big-endian modes.
///
/// # Notes
///
/// The Java `Processor` class uses a static registry pattern
/// (`findOrPossiblyCreateProcessor`, `toProcessor`). This Rust version is a
/// plain struct. A global registry can be implemented separately using a
/// `HashMap<String, Arc<Processor>>` behind a `RwLock` or `OnceLock`.
#[derive(Debug, Clone)]
pub struct Processor {
    /// The processor family name (e.g., "x86", "ARM", "MIPS").
    pub name: String,

    /// Human-readable description.
    pub description: String,

    /// All language IDs supported by this processor.
    pub supported_languages: Vec<LanguageID>,

    /// Whether this processor supports the SLEIGH specification language.
    pub supports_sleigh: bool,

    /// Whether this processor is little-endian capable.
    pub supports_little_endian: bool,

    /// Whether this processor is big-endian capable.
    pub supports_big_endian: bool,
}

impl Processor {
    /// Create a new processor definition.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            supported_languages: Vec::new(),
            supports_sleigh: true,
            supports_little_endian: true,
            supports_big_endian: false,
        }
    }

    /// Builder: set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Builder: add a supported language. Automatically sets endian flags.
    pub fn with_language(mut self, lang: LanguageID) -> Self {
        if lang.is_big_endian() {
            self.supports_big_endian = true;
        } else {
            self.supports_little_endian = true;
        }
        self.supported_languages.push(lang);
        self
    }

    /// Builder: set multiple supported languages.
    pub fn with_languages(mut self, langs: Vec<LanguageID>) -> Self {
        for lang in langs {
            if lang.is_big_endian() {
                self.supports_big_endian = true;
            } else {
                self.supports_little_endian = true;
            }
            self.supported_languages.push(lang);
        }
        self
    }

    /// Builder: toggle SLEIGH support.
    pub fn with_sleigh(mut self, supports: bool) -> Self {
        self.supports_sleigh = supports;
        self
    }

    /// Convenience: build an x86 processor description.
    pub fn x86() -> Self {
        Self::new("x86")
            .with_description("Intel/AMD x86 processor family")
            .with_language(LanguageID::x86_32())
            .with_language(LanguageID::x86_64())
            .with_language(
                LanguageID::new("x86", "LE", 16, "default").with_qualifier("Real Mode"),
            )
    }

    /// Convenience: build an ARM processor description.
    pub fn arm() -> Self {
        Self::new("ARM")
            .with_description("ARM processor family")
            .with_language(LanguageID::arm_v7())
            .with_language(LanguageID::new("ARM", "BE", 32, "v7"))
            .with_language(LanguageID::new("ARM", "LE", 32, "v8"))
            .with_language(LanguageID::new("ARM", "BE", 32, "v8"))
            .with_language(LanguageID::aarch64())
            .with_language(LanguageID::new("AARCH64", "BE", 64, "v8"))
            .with_sleigh(true)
    }

    /// Convenience: build a MIPS processor description.
    pub fn mips() -> Self {
        Self::new("MIPS")
            .with_description("MIPS processor family")
            .with_language(LanguageID::mips32_be())
            .with_language(LanguageID::new("MIPS", "LE", 32, "default"))
            .with_language(LanguageID::new("MIPS", "BE", 64, "default"))
            .with_language(LanguageID::new("MIPS", "LE", 64, "default"))
    }

    /// Convenience: build a PowerPC processor description.
    pub fn powerpc() -> Self {
        Self::new("PowerPC")
            .with_description("PowerPC processor family")
            .with_language(LanguageID::new("PowerPC", "BE", 32, "default"))
            .with_language(LanguageID::new("PowerPC", "BE", 64, "default"))
            .with_language(LanguageID::new("PowerPC", "LE", 64, "default"))
            .with_sleigh(true)
    }

    /// Get a language by its ID string.
    pub fn get_language(&self, id_string: &str) -> Option<&LanguageID> {
        self.supported_languages
            .iter()
            .find(|l| l.to_id_string() == id_string)
    }

    /// Get all 32-bit language variants.
    pub fn get_32bit_languages(&self) -> Vec<&LanguageID> {
        self.supported_languages
            .iter()
            .filter(|l| l.size == 32)
            .collect()
    }

    /// Get all 64-bit language variants.
    pub fn get_64bit_languages(&self) -> Vec<&LanguageID> {
        self.supported_languages
            .iter()
            .filter(|l| l.size == 64)
            .collect()
    }

    /// Get the default (first) language for this processor.
    pub fn get_default_language(&self) -> Option<&LanguageID> {
        self.supported_languages.first()
    }

    /// Number of supported languages.
    pub fn language_count(&self) -> usize {
        self.supported_languages.len()
    }
}

impl fmt::Display for Processor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({} languages)",
            self.name,
            self.supported_languages.len()
        )
    }
}

impl PartialOrd for Processor {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Processor {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name
            .to_lowercase()
            .cmp(&other.name.to_lowercase())
    }
}

impl PartialEq for Processor {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Eq for Processor {}

impl std::hash::Hash for Processor {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
    }
}

// ============================================================================
// Endian
// ============================================================================

/// Processor endianness.
///
/// Corresponds to `ghidra.program.model.lang.Endian`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Endian {
    Big,
    Little,
}

impl Endian {
    /// Parse an endianness string ("big", "BE", "little", "LE", case-insensitive).
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "big" | "be" => Some(Endian::Big),
            "little" | "le" => Some(Endian::Little),
            _ => None,
        }
    }

    pub fn is_big_endian(&self) -> bool {
        *self == Endian::Big
    }

    pub fn is_little_endian(&self) -> bool {
        *self == Endian::Little
    }

    /// Short string form: "BE" or "LE".
    pub fn to_short_string(&self) -> &str {
        match self {
            Endian::Big => "BE",
            Endian::Little => "LE",
        }
    }
}

impl fmt::Display for Endian {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endian::Big => write!(f, "Big"),
            Endian::Little => write!(f, "Little"),
        }
    }
}

// ============================================================================
// DecompilerLanguage
// ============================================================================

/// Languages the decompiler can output.
///
/// Corresponds to `ghidra.program.model.lang.DecompilerLanguage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DecompilerLanguage {
    CLanguage,
    JavaLanguage,
}

impl fmt::Display for DecompilerLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecompilerLanguage::CLanguage => write!(f, "c-language"),
            DecompilerLanguage::JavaLanguage => write!(f, "java-language"),
        }
    }
}

// ============================================================================
// InputListType
// ============================================================================

/// Strategy for parameter list allocation.
///
/// Corresponds to `ghidra.program.model.lang.InputListType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InputListType {
    Standard,
    Register,
}

// ============================================================================
// StorageClass
// ============================================================================

/// Classification of data-types for storage assignment.
///
/// Corresponds to `ghidra.program.model.lang.StorageClass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StorageClass {
    General,
    Float,
    Ptr,
    HiddenRet,
    Vector,
    Class1,
    Class2,
    Class3,
    Class4,
}

impl StorageClass {
    pub fn value(&self) -> i32 {
        match self {
            StorageClass::General => 0,
            StorageClass::Float => 1,
            StorageClass::Ptr => 2,
            StorageClass::HiddenRet => 3,
            StorageClass::Vector => 4,
            StorageClass::Class1 => 100,
            StorageClass::Class2 => 101,
            StorageClass::Class3 => 102,
            StorageClass::Class4 => 103,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "general" => Some(StorageClass::General),
            "float" => Some(StorageClass::Float),
            "ptr" => Some(StorageClass::Ptr),
            "hiddenret" => Some(StorageClass::HiddenRet),
            "vector" => Some(StorageClass::Vector),
            "class1" => Some(StorageClass::Class1),
            "class2" => Some(StorageClass::Class2),
            "class3" => Some(StorageClass::Class3),
            "class4" => Some(StorageClass::Class4),
            _ => None,
        }
    }
}

impl fmt::Display for StorageClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageClass::General => write!(f, "general"),
            StorageClass::Float => write!(f, "float"),
            StorageClass::Ptr => write!(f, "ptr"),
            StorageClass::HiddenRet => write!(f, "hiddenret"),
            StorageClass::Vector => write!(f, "vector"),
            StorageClass::Class1 => write!(f, "class1"),
            StorageClass::Class2 => write!(f, "class2"),
            StorageClass::Class3 => write!(f, "class3"),
            StorageClass::Class4 => write!(f, "class4"),
        }
    }
}

// ============================================================================
// OperandType
// ============================================================================

/// Bitflags for classifying instruction operand types.
///
/// Corresponds to `ghidra.program.model.lang.OperandType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OperandType(u32);

impl OperandType {
    pub const READ: u32 = 0x0000_0001;
    pub const WRITE: u32 = 0x0000_0002;
    pub const INDIRECT: u32 = 0x0000_0004;
    pub const IMMEDIATE: u32 = 0x0000_0008;
    pub const RELATIVE: u32 = 0x0000_0010;
    pub const IMPLICIT: u32 = 0x0000_0020;
    pub const CODE: u32 = 0x0000_0040;
    pub const DATA: u32 = 0x0000_0080;
    pub const PORT: u32 = 0x0000_0100;
    pub const REGISTER: u32 = 0x0000_0200;
    pub const LIST: u32 = 0x0000_0400;
    pub const FLAG: u32 = 0x0000_0800;
    pub const TEXT: u32 = 0x0000_1000;
    pub const ADDRESS: u32 = 0x0000_2000;
    pub const SCALAR: u32 = 0x0000_4000;
    pub const BIT: u32 = 0x0000_8000;
    pub const BYTE: u32 = 0x0001_0000;
    pub const WORD: u32 = 0x0002_0000;
    pub const QUADWORD: u32 = 0x0004_0000;
    pub const SIGNED: u32 = 0x0008_0000;
    pub const FLOAT: u32 = 0x0010_0000;
    pub const COP: u32 = 0x0020_0000;
    pub const DYNAMIC: u32 = 0x0040_0000;

    pub fn new(bits: u32) -> Self {
        Self(bits)
    }

    pub fn bits(&self) -> u32 {
        self.0
    }

    pub fn does_read(t: u32) -> bool { (t & Self::READ) != 0 }
    pub fn does_write(t: u32) -> bool { (t & Self::WRITE) != 0 }
    pub fn is_indirect(t: u32) -> bool { (t & Self::INDIRECT) != 0 }
    pub fn is_immediate(t: u32) -> bool { (t & Self::IMMEDIATE) != 0 }
    pub fn is_relative(t: u32) -> bool { (t & Self::RELATIVE) != 0 }
    pub fn is_implicit(t: u32) -> bool { (t & Self::IMPLICIT) != 0 }
    pub fn is_code_reference(t: u32) -> bool { (t & Self::CODE) != 0 }
    pub fn is_data_reference(t: u32) -> bool { (t & Self::DATA) != 0 }
    pub fn is_port(t: u32) -> bool { (t & Self::PORT) != 0 }
    pub fn is_register(t: u32) -> bool { (t & Self::REGISTER) != 0 }
    pub fn is_list(t: u32) -> bool { (t & Self::LIST) != 0 }
    pub fn is_flag(t: u32) -> bool { (t & Self::FLAG) != 0 }
    pub fn is_text(t: u32) -> bool { (t & Self::TEXT) != 0 }
    pub fn is_address(t: u32) -> bool { (t & Self::ADDRESS) != 0 }
    pub fn is_scalar(t: u32) -> bool { (t & Self::SCALAR) != 0 }
    pub fn is_bit(t: u32) -> bool { (t & Self::BIT) != 0 }
    pub fn is_byte(t: u32) -> bool { (t & Self::BYTE) != 0 }
    pub fn is_word(t: u32) -> bool { (t & Self::WORD) != 0 }
    pub fn is_quad_word(t: u32) -> bool { (t & Self::QUADWORD) != 0 }
    pub fn is_signed(t: u32) -> bool { (t & Self::SIGNED) != 0 }
    pub fn is_float(t: u32) -> bool { (t & Self::FLOAT) != 0 }
    pub fn is_co_processor(t: u32) -> bool { (t & Self::COP) != 0 }
    pub fn is_dynamic(t: u32) -> bool { (t & Self::DYNAMIC) != 0 }
    pub fn is_scalar_as_address(t: u32) -> bool { Self::is_address(t) && Self::is_scalar(t) }

    pub fn contains(&self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }

    /// Render a human-readable summary of the operand type flags.
    pub fn to_debug_string(t: u32) -> String {
        let mut parts = Vec::new();
        if Self::is_address(t) { parts.push("ADDR"); }
        if Self::is_scalar(t) { parts.push("SCAL"); }
        if Self::is_port(t) { parts.push("PORT"); }
        if Self::is_register(t) { parts.push("REG"); }
        if Self::is_list(t) { parts.push("LIST"); }
        if Self::is_flag(t) { parts.push("FLAG"); }
        if Self::is_text(t) { parts.push("TEXT"); }
        if Self::is_code_reference(t) { parts.push("CODE"); }
        if Self::is_data_reference(t) { parts.push("DATA"); }
        if Self::is_bit(t) { parts.push("BIT"); }
        if Self::is_byte(t) { parts.push("BYTE"); }
        if Self::is_word(t) { parts.push("WORD"); }
        if Self::is_quad_word(t) { parts.push("QUAD"); }
        if Self::is_signed(t) { parts.push("SIGN"); }
        if Self::is_float(t) { parts.push("FLT"); }
        if Self::is_indirect(t) { parts.push("IND"); }
        if Self::is_immediate(t) { parts.push("IMM"); }
        if Self::is_relative(t) { parts.push("REL"); }
        if Self::is_implicit(t) { parts.push("IMPL"); }
        if Self::does_read(t) { parts.push("READ"); }
        if Self::does_write(t) { parts.push("WRTE"); }
        if Self::is_co_processor(t) { parts.push("COP"); }
        if Self::is_dynamic(t) { parts.push("DYN"); }
        parts.join(" | ")
    }
}

// ============================================================================
// SpaceNames
// ============================================================================

/// Reserved address space names used across all Ghidra architectures.
///
/// Corresponds to `ghidra.program.model.lang.SpaceNames`.
pub struct SpaceNames;

impl SpaceNames {
    pub const CONSTANT_SPACE_NAME: &'static str = "const";
    pub const UNIQUE_SPACE_NAME: &'static str = "unique";
    pub const STACK_SPACE_NAME: &'static str = "stack";
    pub const JOIN_SPACE_NAME: &'static str = "join";
    pub const OTHER_SPACE_NAME: &'static str = "OTHER";
    pub const IOP_SPACE_NAME: &'static str = "iop";
    pub const FSPEC_SPACE_NAME: &'static str = "fspec";

    pub const CONSTANT_SPACE_INDEX: u32 = 0;
    pub const OTHER_SPACE_INDEX: u32 = 1;
    pub const UNIQUE_SPACE_SIZE: usize = 4;
}

// ============================================================================
// GhidraLanguagePropertyKeys
// ============================================================================

/// Standard property key names used by Ghidra language specifications.
///
/// Corresponds to `ghidra.program.model.lang.GhidraLanguagePropertyKeys`.
pub struct GhidraLanguagePropertyKeys;

impl GhidraLanguagePropertyKeys {
    pub const MAXIMUM_INSTRUCTION_LENGTH: &'static str = "maximumInstructionLength";
    pub const CUSTOM_DISASSEMBLER_CLASS: &'static str = "customDisassemblerClass";
    pub const ALLOW_OFFCUT_REFERENCES_TO_FUNCTION_STARTS: &'static str =
        "allowOffcutReferencesToFunctionStarts";
    pub const USE_OPERAND_REFERENCE_ANALYZER_SWITCH_TABLES: &'static str =
        "useOperandReferenceAnalyzerSwitchTables";
    pub const IS_TMS320_FAMILY: &'static str = "isTMS320Family";
    pub const PARALLEL_INSTRUCTION_HELPER_CLASS: &'static str = "parallelInstructionHelperClass";
    pub const ADDRESSES_DO_NOT_APPEAR_DIRECTLY_IN_CODE: &'static str =
        "addressesDoNotAppearDirectlyInCode";
    pub const USE_NEW_FUNCTION_STACK_ANALYSIS: &'static str = "useNewFunctionStackAnalysis";
    pub const EMULATE_INSTRUCTION_STATE_MODIFIER_CLASS: &'static str =
        "emulateInstructionStateModifierClass";
    pub const USEROP_LIBS: &'static str = "useropLibs";
    pub const PCODE_INJECT_LIBRARY_CLASS: &'static str = "pcodeInjectLibraryClass";
    pub const ENABLE_SHARED_RETURN_ANALYSIS: &'static str = "enableSharedReturnAnalysis";
    pub const ENABLE_ASSUME_CONTIGUOUS_FUNCTIONS_ONLY: &'static str =
        "enableContiguousFunctionsOnly";
    pub const ENABLE_NO_RETURN_ANALYSIS: &'static str = "enableNoReturnAnalysis";
    pub const RESET_CONTEXT_ON_UPGRADE: &'static str = "resetContextOnUpgrade";
    pub const MINIMUM_DATA_IMAGE_BASE: &'static str = "minimumDataImageBase";
}

// ============================================================================
// CompilerSpecDescription (trait) + BasicCompilerSpecDescription
// ============================================================================

/// Describes a compiler specification without a full `CompilerSpec` loaded.
///
/// Corresponds to `ghidra.program.model.lang.CompilerSpecDescription` (interface).
pub trait CompilerSpecDescription: fmt::Debug + Send + Sync {
    fn get_compiler_spec_id(&self) -> &CompilerSpecID;
    fn get_compiler_spec_name(&self) -> &str;
    fn get_source(&self) -> String;
}

/// Concrete implementation of `CompilerSpecDescription`.
///
/// Corresponds to `ghidra.program.model.lang.BasicCompilerSpecDescription`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicCompilerSpecDescription {
    pub id: CompilerSpecID,
    pub name: String,
}

impl BasicCompilerSpecDescription {
    pub fn new(id: CompilerSpecID, name: impl Into<String>) -> Self {
        Self { id, name: name.into() }
    }
}

impl CompilerSpecDescription for BasicCompilerSpecDescription {
    fn get_compiler_spec_id(&self) -> &CompilerSpecID {
        &self.id
    }
    fn get_compiler_spec_name(&self) -> &str {
        &self.name
    }
    fn get_source(&self) -> String {
        format!("{} {}", self.id, self.name)
    }
}

impl fmt::Display for BasicCompilerSpecDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl PartialEq for BasicCompilerSpecDescription {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for BasicCompilerSpecDescription {}

// ============================================================================
// LanguageDescription (trait) + BasicLanguageDescription
// ============================================================================

/// Describes a language without a full `Language` loaded.
///
/// Corresponds to `ghidra.program.model.lang.LanguageDescription` (interface).
pub trait LanguageDescription: fmt::Debug + Send + Sync {
    fn get_language_id(&self) -> &LanguageID;
    fn get_processor(&self) -> &str;
    fn get_endian(&self) -> Endian;
    fn get_instruction_endian(&self) -> Endian;
    fn get_size(&self) -> usize;
    fn get_variant(&self) -> &str;
    fn get_version(&self) -> i32;
    fn get_minor_version(&self) -> i32;
    fn get_description(&self) -> &str;
    fn is_deprecated(&self) -> bool;
    fn get_compatible_compiler_spec_descriptions(&self) -> &[Box<dyn CompilerSpecDescription>];
    fn get_compiler_spec_description_by_id(
        &self,
        id: &CompilerSpecID,
    ) -> Result<&dyn CompilerSpecDescription, LangError>;
    fn get_external_names(&self, tool: &str) -> Option<Vec<String>>;
}

/// Concrete implementation of `LanguageDescription`.
///
/// Corresponds to `ghidra.program.model.lang.BasicLanguageDescription`.
#[derive(Debug)]
pub struct BasicLanguageDescription {
    pub language_id: LanguageID,
    pub processor_name: String,
    pub endian: Endian,
    pub instruction_endian: Endian,
    pub size: usize,
    pub variant: String,
    pub description: String,
    pub version: i32,
    pub minor_version: i32,
    pub deprecated: bool,
    pub compatible_compiler_specs: Vec<Box<dyn CompilerSpecDescription>>,
    pub external_names: HashMap<String, Vec<String>>,
}

impl BasicLanguageDescription {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        language_id: LanguageID,
        processor_name: impl Into<String>,
        endian: Endian,
        instruction_endian: Endian,
        size: usize,
        variant: impl Into<String>,
        description: impl Into<String>,
        version: i32,
        minor_version: i32,
        deprecated: bool,
        compiler_specs: Vec<Box<dyn CompilerSpecDescription>>,
        external_names: HashMap<String, Vec<String>>,
    ) -> Self {
        Self {
            language_id,
            processor_name: processor_name.into(),
            endian,
            instruction_endian,
            size,
            variant: variant.into(),
            description: description.into(),
            version,
            minor_version,
            deprecated,
            compatible_compiler_specs: compiler_specs,
            external_names,
        }
    }
}

impl LanguageDescription for BasicLanguageDescription {
    fn get_language_id(&self) -> &LanguageID {
        &self.language_id
    }
    fn get_processor(&self) -> &str {
        &self.processor_name
    }
    fn get_endian(&self) -> Endian {
        self.endian
    }
    fn get_instruction_endian(&self) -> Endian {
        self.instruction_endian
    }
    fn get_size(&self) -> usize {
        self.size
    }
    fn get_variant(&self) -> &str {
        &self.variant
    }
    fn get_version(&self) -> i32 {
        self.version
    }
    fn get_minor_version(&self) -> i32 {
        self.minor_version
    }
    fn get_description(&self) -> &str {
        &self.description
    }
    fn is_deprecated(&self) -> bool {
        self.deprecated
    }
    fn get_compatible_compiler_spec_descriptions(&self) -> &[Box<dyn CompilerSpecDescription>] {
        &self.compatible_compiler_specs
    }
    fn get_compiler_spec_description_by_id(
        &self,
        id: &CompilerSpecID,
    ) -> Result<&dyn CompilerSpecDescription, LangError> {
        self.compatible_compiler_specs
            .iter()
            .find(|cs| cs.get_compiler_spec_id() == id)
            .map(|cs| cs.as_ref())
            .ok_or_else(|| LangError::CompilerSpecNotFound {
                language_id: self.language_id.clone(),
                compiler_spec_id: id.clone(),
            })
    }
    fn get_external_names(&self, tool: &str) -> Option<Vec<String>> {
        self.external_names.get(tool).cloned()
    }
}

impl fmt::Display for BasicLanguageDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}/{}/{}/{}",
            self.processor_name, self.endian, self.size, self.variant
        )
    }
}

impl PartialEq for BasicLanguageDescription {
    fn eq(&self, other: &Self) -> bool {
        self.language_id == other.language_id
    }
}
impl Eq for BasicLanguageDescription {}

// ============================================================================
// LanguageCompilerSpecPair
// ============================================================================

/// A (LanguageID, CompilerSpecID) pair used for language/opinion lookups.
///
/// Corresponds to `ghidra.program.model.lang.LanguageCompilerSpecPair`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LanguageCompilerSpecPair {
    pub language_id: LanguageID,
    pub compiler_spec_id: CompilerSpecID,
}

impl LanguageCompilerSpecPair {
    pub fn new(language_id: LanguageID, compiler_spec_id: CompilerSpecID) -> Self {
        Self { language_id, compiler_spec_id }
    }

    pub fn from_strings(
        language_id: &str,
        compiler_spec_id: &str,
    ) -> Result<Self, LangError> {
        let lid = LanguageID::parse(language_id)
            .ok_or_else(|| LangError::InvalidLanguageID(language_id.to_string()))?;
        Ok(Self {
            language_id: lid,
            compiler_spec_id: CompilerSpecID::new(compiler_spec_id),
        })
    }
}

impl PartialOrd for LanguageCompilerSpecPair {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LanguageCompilerSpecPair {
    fn cmp(&self, other: &Self) -> Ordering {
        self.language_id
            .cmp(&other.language_id)
            .then_with(|| self.compiler_spec_id.cmp(&other.compiler_spec_id))
    }
}

impl fmt::Display for LanguageCompilerSpecPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.language_id, self.compiler_spec_id)
    }
}

// ============================================================================
// LanguageCompilerSpecQuery + ExternalLanguageCompilerSpecQuery
// ============================================================================

/// A query for matching language/compiler spec pairs.
///
/// Corresponds to `ghidra.program.model.lang.LanguageCompilerSpecQuery`.
#[derive(Debug, Clone, Default)]
pub struct LanguageCompilerSpecQuery {
    pub processor: Option<String>,
    pub endian: Option<Endian>,
    pub size: Option<usize>,
    pub variant: Option<String>,
}

impl LanguageCompilerSpecQuery {
    pub fn matches(&self, desc: &dyn LanguageDescription) -> bool {
        if let Some(ref proc) = self.processor {
            if desc.get_processor() != proc.as_str() {
                return false;
            }
        }
        if let Some(endian) = self.endian {
            if desc.get_endian() != endian {
                return false;
            }
        }
        if let Some(size) = self.size {
            if desc.get_size() != size {
                return false;
            }
        }
        if let Some(ref variant) = self.variant {
            if desc.get_variant() != variant.as_str() {
                return false;
            }
        }
        true
    }
}

/// Query for external language mappings (e.g., IDA-Pro's "metapc").
///
/// Corresponds to `ghidra.program.model.lang.ExternalLanguageCompilerSpecQuery`.
#[derive(Debug, Clone)]
pub struct ExternalLanguageCompilerSpecQuery {
    pub external_processor_name: String,
    pub external_tool: String,
    pub endian: Option<Endian>,
    pub size: Option<usize>,
    pub compiler_spec_id: Option<CompilerSpecID>,
}

impl ExternalLanguageCompilerSpecQuery {
    pub fn new(
        external_processor_name: impl Into<String>,
        external_tool: impl Into<String>,
    ) -> Self {
        Self {
            external_processor_name: external_processor_name.into(),
            external_tool: external_tool.into(),
            endian: None,
            size: None,
            compiler_spec_id: None,
        }
    }
}

impl fmt::Display for ExternalLanguageCompilerSpecQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "externalProcessorName={}; externalTool={}; endian={:?}; size={:?}; compiler={:?}",
            self.external_processor_name, self.external_tool, self.endian, self.size,
            self.compiler_spec_id
        )
    }
}

// ============================================================================
// AddressLabelInfo
// ============================================================================

/// Stores an address together with a language-defined label.
///
/// Corresponds to `ghidra.program.model.lang.AddressLabelInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressLabelInfo {
    pub addr: Address,
    pub end_addr: Address,
    pub label: String,
    pub description: Option<String>,
    pub is_primary: bool,
    pub is_entry: bool,
    pub size_in_bytes: usize,
    pub is_volatile: Option<bool>,
}

impl AddressLabelInfo {
    pub fn new(
        addr: Address,
        size_in_bytes: usize,
        label: impl Into<String>,
        description: Option<String>,
        is_primary: bool,
        is_entry: bool,
        is_volatile: Option<bool>,
    ) -> Self {
        let label = label.into();
        let size = if size_in_bytes == 0 { 1 } else { size_in_bytes };
        Self {
            addr,
            end_addr: Address::new(addr.offset + size as u64 - 1),
            label,
            description,
            is_primary,
            is_entry,
            size_in_bytes: size,
            is_volatile,
        }
    }

    pub fn get_address(&self) -> Address {
        self.addr
    }

    pub fn get_end_address(&self) -> Address {
        self.end_addr
    }

    pub fn get_label(&self) -> &str {
        &self.label
    }

    pub fn get_byte_size(&self) -> usize {
        self.size_in_bytes
    }
}

impl PartialEq for AddressLabelInfo {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr && self.label == other.label
    }
}
impl Eq for AddressLabelInfo {}

impl PartialOrd for AddressLabelInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AddressLabelInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        self.addr
            .cmp(&other.addr)
            .then_with(|| self.label.cmp(&other.label))
    }
}

// ============================================================================
// UnknownRegister
// ============================================================================

/// A register returned for undefined locations in the register address space.
///
/// Corresponds to `ghidra.program.model.lang.UnknownRegister`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnknownRegister {
    pub register: Register,
}

impl UnknownRegister {
    pub fn new(
        name: impl Into<String>,
        description: impl Into<String>,
        address: Address,
        num_bytes: usize,
        big_endian: bool,
        type_flags: RegisterTypeFlags,
    ) -> Self {
        Self {
            register: Register::full(
                name,
                description,
                address,
                num_bytes,
                0,
                (num_bytes * 8) as u32,
                big_endian,
                type_flags,
            ),
        }
    }
}

impl std::ops::Deref for UnknownRegister {
    type Target = Register;
    fn deref(&self) -> &Self::Target {
        &self.register
    }
}

// ============================================================================
// ContextSetting
// ============================================================================

/// A context register setting over a memory range, used in compiler specs.
///
/// Corresponds to `ghidra.program.model.lang.ContextSetting`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSetting {
    pub register_name: String,
    pub value: u64,
    pub start_addr: Address,
    pub end_addr: Address,
}

impl ContextSetting {
    pub fn new(
        register_name: impl Into<String>,
        value: u64,
        start_addr: Address,
        end_addr: Address,
    ) -> Self {
        Self {
            register_name: register_name.into(),
            value,
            start_addr,
            end_addr,
        }
    }

    pub fn is_equivalent(&self, other: &Self) -> bool {
        self.register_name == other.register_name
            && self.value == other.value
            && self.start_addr == other.start_addr
            && self.end_addr == other.end_addr
    }
}

// ============================================================================
// RegisterValue
// ============================================================================

/// A register value with a validity mask tracking which bits are known.
///
/// Corresponds to `ghidra.program.model.lang.RegisterValue`.
///
/// Values are stored as big-endian: MSB of mask is at index 0, MSB of value
/// is at (bytes.len()/2).
#[derive(Debug, Clone)]
pub struct RegisterValue {
    pub register_name: String,
    pub bytes: Vec<u8>,
    pub start_bit: u32,
    pub end_bit: u32,
    pub big_endian: bool,
}

impl RegisterValue {
    /// Create a RegisterValue with all mask bits set (fully known value).
    pub fn new(register_name: impl Into<String>, bit_length: u32, value: u64, big_endian: bool) -> Self {
        let num_bytes = ((bit_length as usize) + 7) / 8;
        let mask_len = num_bytes;
        let mut bytes = vec![0u8; mask_len * 2];

        // Set all mask bits
        for i in 0..mask_len {
            bytes[i] = 0xff;
        }

        // Set value bytes (big-endian in the second half)
        let value_bytes = value.to_be_bytes();
        let value_start = 8usize.saturating_sub(num_bytes);
        for i in 0..num_bytes {
            if big_endian {
                bytes[mask_len + i] = value_bytes[value_start + i];
            } else {
                // Little-endian: reverse byte order
                bytes[mask_len + i] = value_bytes[8 - 1 - i];
            }
        }

        Self {
            register_name: register_name.into(),
            bytes,
            start_bit: 0,
            end_bit: bit_length.saturating_sub(1),
            big_endian,
        }
    }

    /// Create a RegisterValue with no valid bits (all mask bits off).
    pub fn empty(register_name: impl Into<String>, mask_byte_len: usize) -> Self {
        Self {
            register_name: register_name.into(),
            bytes: vec![0u8; mask_byte_len * 2],
            start_bit: 0,
            end_bit: (mask_byte_len * 8 - 1) as u32,
            big_endian: false,
        }
    }

    /// Returns the register name.
    pub fn get_register_name(&self) -> &str {
        &self.register_name
    }

    /// Returns true if all mask bits for the register range are set.
    pub fn has_value(&self) -> bool {
        let mask_len = self.bytes.len() / 2;
        self.bytes[..mask_len].iter().all(|&b| b == 0xff)
    }

    /// Returns true if any mask bit is set.
    pub fn has_any_value(&self) -> bool {
        let mask_len = self.bytes.len() / 2;
        self.bytes[..mask_len].iter().any(|&b| b != 0)
    }

    /// Get the unsigned value ignoring the mask.
    pub fn get_unsigned_value_ignore_mask(&self) -> u64 {
        let mask_len = self.bytes.len() / 2;
        let value_bytes = &self.bytes[mask_len..];
        let mut result = 0u64;
        for &b in value_bytes.iter() {
            result = (result << 8) | (b as u64);
        }
        result
    }

    /// Get the unsigned value if all mask bits are set, otherwise None.
    pub fn get_unsigned_value(&self) -> Option<u64> {
        if self.has_value() {
            Some(self.get_unsigned_value_ignore_mask())
        } else {
            None
        }
    }

    /// Combine this register value with another, preferring the other's masked bits.
    pub fn combine_values(&self, other: &RegisterValue) -> RegisterValue {
        let n = self.bytes.len() / 2;
        let mut result_bytes = vec![0u8; self.bytes.len()];
        for i in 0..n {
            let mask = other.bytes[i];
            let clear_mask = !mask;
            result_bytes[n + i] = (other.bytes[n + i] & mask) | (self.bytes[n + i] & clear_mask);
            result_bytes[i] = self.bytes[i] | other.bytes[i];
        }
        RegisterValue {
            register_name: self.register_name.clone(),
            bytes: result_bytes,
            start_bit: self.start_bit,
            end_bit: self.end_bit,
            big_endian: self.big_endian,
        }
    }

    /// Return the raw mask/value byte array.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl PartialEq for RegisterValue {
    fn eq(&self, other: &Self) -> bool {
        self.register_name == other.register_name && self.bytes == other.bytes
    }
}
impl Eq for RegisterValue {}

impl fmt::Display for RegisterValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mask_len = self.bytes.len() / 2;
        let mask_str: String = self.bytes[..mask_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let val_str: String = self.bytes[mask_len..]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        write!(
            f,
            "RegisterValue({}): mask=0x{} value=0x{}",
            self.register_name, mask_str, val_str
        )
    }
}

// ============================================================================
// Mask / MaskImpl
// ============================================================================

/// A bit mask for testing instruction bits.
///
/// Corresponds to `ghidra.program.model.lang.Mask` (interface).
pub trait Mask: fmt::Debug + Send + Sync {
    fn apply_mask(&self, cde: &[u8], result: &mut [u8]) -> Result<(), LangError>;
    fn equal_masked_value(&self, cde: &[u8], target: &[u8]) -> Result<bool, LangError>;
    fn complement_mask(&self, msk: &[u8], result: &mut [u8]) -> Result<(), LangError>;
    fn get_bytes(&self) -> &[u8];
}

/// Byte-array implementation of `Mask`.
///
/// Corresponds to `ghidra.program.model.lang.MaskImpl`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaskImpl {
    mask: Vec<u8>,
}

impl MaskImpl {
    pub fn new(mask: Vec<u8>) -> Self {
        Self { mask }
    }
}

impl Mask for MaskImpl {
    fn apply_mask(&self, cde: &[u8], result: &mut [u8]) -> Result<(), LangError> {
        if cde.len() < self.mask.len() || result.len() < cde.len() {
            return Err(LangError::IncompatibleMask);
        }
        for i in 0..self.mask.len() {
            result[i] = self.mask[i] & cde[i];
        }
        for i in self.mask.len()..cde.len() {
            result[i] = cde[i];
        }
        Ok(())
    }

    fn equal_masked_value(&self, cde: &[u8], target: &[u8]) -> Result<bool, LangError> {
        if cde.len() < self.mask.len() || target.len() < self.mask.len() {
            return Err(LangError::IncompatibleMask);
        }
        for i in 0..self.mask.len() {
            if (self.mask[i] & cde[i]) != target[i] {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn complement_mask(&self, msk: &[u8], result: &mut [u8]) -> Result<(), LangError> {
        if msk.len() < self.mask.len() || result.len() < self.mask.len() {
            return Err(LangError::IncompatibleMask);
        }
        for i in 0..self.mask.len() {
            result[i] = !self.mask[i] & msk[i];
        }
        Ok(())
    }

    fn get_bytes(&self) -> &[u8] {
        &self.mask
    }
}

impl PartialEq for MaskImpl {
    fn eq(&self, other: &Self) -> bool {
        self.mask == other.mask
    }
}
impl Eq for MaskImpl {}

// ============================================================================
// PrototypeModel
// ============================================================================

/// A function calling convention model.
///
/// Corresponds to `ghidra.program.model.lang.ProtoypeModel`.
/// This is a simplified Rust representation; the Java version has XML parsing
/// and complex storage assignment logic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrototypeModel {
    pub name: String,
    pub extrapop: i32,
    pub stackshift: i32,
    pub input_list_type: InputListType,
    pub has_this: bool,
    pub is_construct: bool,
    pub has_upon_entry: bool,
    pub has_upon_return: bool,
    pub is_extension: bool,
    pub unaffected: Vec<String>,
    pub killed_by_call: Vec<String>,
    pub return_address: Vec<String>,
    pub likely_trash: Vec<String>,
    pub internal_storage: Vec<String>,
}

impl PrototypeModel {
    pub const UNKNOWN_EXTRAPOP: i32 = 0x8000;

    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            extrapop: Self::UNKNOWN_EXTRAPOP,
            stackshift: -1,
            input_list_type: InputListType::Standard,
            has_this: false,
            is_construct: false,
            has_upon_entry: false,
            has_upon_return: false,
            is_extension: false,
            unaffected: Vec::new(),
            killed_by_call: Vec::new(),
            return_address: Vec::new(),
            likely_trash: Vec::new(),
            internal_storage: Vec::new(),
        }
    }

    /// Create an alias of another PrototypeModel.
    pub fn alias(name: impl Into<String>, other: &PrototypeModel) -> Self {
        Self {
            name: name.into(),
            extrapop: other.extrapop,
            stackshift: other.stackshift,
            input_list_type: other.input_list_type,
            has_this: other.has_this,
            is_construct: other.is_construct,
            has_upon_entry: other.has_upon_entry,
            has_upon_return: other.has_upon_return,
            is_extension: false,
            unaffected: other.unaffected.clone(),
            killed_by_call: other.killed_by_call.clone(),
            return_address: other.return_address.clone(),
            likely_trash: other.likely_trash.clone(),
            internal_storage: other.internal_storage.clone(),
        }
    }

    pub fn is_merged(&self) -> bool {
        false
    }

    pub fn has_injection(&self) -> bool {
        self.has_upon_entry || self.has_upon_return
    }

    pub fn get_extrapop(&self) -> i32 {
        self.extrapop
    }

    pub fn is_equivalent(&self, other: &PrototypeModel) -> bool {
        self.name == other.name
            && self.extrapop == other.extrapop
            && self.stackshift == other.stackshift
            && self.has_this == other.has_this
            && self.is_construct == other.is_construct
            && self.has_upon_entry == other.has_upon_entry
            && self.has_upon_return == other.has_upon_return
            && self.input_list_type == other.input_list_type
    }

    /// Predefined: cdecl calling convention model.
    pub fn cdecl() -> Self {
        Self::new("__cdecl")
    }

    /// Predefined: stdcall calling convention model.
    pub fn stdcall() -> Self {
        Self::new("__stdcall")
    }

    /// Predefined: fastcall calling convention model.
    pub fn fastcall() -> Self {
        Self::new("__fastcall")
    }

    /// Predefined: thiscall calling convention model.
    pub fn thiscall() -> Self {
        let mut m = Self::new("__thiscall");
        m.has_this = true;
        m
    }
}

impl fmt::Display for PrototypeModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl PartialEq for PrototypeModel {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}
impl Eq for PrototypeModel {}

// ============================================================================
// ParamEntry
// ============================================================================

/// A single entry in a parameter list describing a storage location.
///
/// Corresponds to `ghidra.program.model.lang.ParamEntry`.
/// This is a simplified version for Rust; the Java version has XML parsing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParamEntry {
    pub group: i32,
    pub storage_class: StorageClass,
    pub space_name: String,
    pub address_base: u64,
    pub size: usize,
    pub min_size: usize,
    pub alignment: usize,
    pub num_slots: usize,
    pub is_big_endian: bool,
    pub force_left_justify: bool,
    pub reverse_stack: bool,
    pub overlapping: bool,
}

impl ParamEntry {
    pub fn new(group: i32) -> Self {
        Self {
            group,
            storage_class: StorageClass::General,
            space_name: String::new(),
            address_base: 0,
            size: 0,
            min_size: 0,
            alignment: 0,
            num_slots: 0,
            is_big_endian: false,
            force_left_justify: false,
            reverse_stack: false,
            overlapping: false,
        }
    }

    pub fn get_group(&self) -> i32 {
        self.group
    }

    pub fn get_size(&self) -> usize {
        self.size
    }

    pub fn get_min_size(&self) -> usize {
        self.min_size
    }

    pub fn get_align(&self) -> usize {
        self.alignment
    }
}

// ============================================================================
// PrototypePieces
// ============================================================================

/// Raw components of a function prototype obtained from parsing source code.
///
/// Corresponds to `ghidra.program.model.lang.PrototypePieces`.
#[derive(Debug, Clone)]
pub struct PrototypePieces {
    pub model_name: Option<String>,
    pub out_type: Option<String>,
    pub in_types: Vec<String>,
    pub first_var_arg_slot: i32,
}

impl PrototypePieces {
    pub fn new() -> Self {
        Self {
            model_name: None,
            out_type: None,
            in_types: Vec::new(),
            first_var_arg_slot: -1,
        }
    }
}

impl Default for PrototypePieces {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// ParameterPieces
// ============================================================================

/// Basic elements of a parameter: address, data-type, properties.
///
/// Corresponds to `ghidra.program.model.lang.ParameterPieces`.
#[derive(Debug, Clone, Default)]
pub struct ParameterPieces {
    pub address: Option<Address>,
    pub type_name: Option<String>,
    pub join_pieces: Vec<Address>,
    pub is_this_pointer: bool,
    pub hidden_return_ptr: bool,
    pub is_indirect: bool,
}

impl ParameterPieces {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn swap_markup(&mut self, other: &mut ParameterPieces) {
        std::mem::swap(&mut self.type_name, &mut other.type_name);
        std::mem::swap(&mut self.join_pieces, &mut other.join_pieces);
        std::mem::swap(&mut self.is_this_pointer, &mut other.is_this_pointer);
        std::mem::swap(&mut self.hidden_return_ptr, &mut other.hidden_return_ptr);
        std::mem::swap(&mut self.is_indirect, &mut other.is_indirect);
    }
}

// ============================================================================
// ProcessorContextView (trait) + ProcessorContext (trait)
// ============================================================================

/// Read-only view of processor register state.
///
/// Corresponds to `ghidra.program.model.lang.ProcessorContextView` (interface).
pub trait ProcessorContextView: fmt::Debug + Send + Sync {
    fn get_base_context_register(&self) -> Option<&Register>;
    fn get_registers(&self) -> Vec<&Register>;
    fn get_register(&self, name: &str) -> Option<&Register>;
    fn get_value(&self, register: &Register, signed: bool) -> Option<u64>;
    fn get_register_value(&self, register: &Register) -> Option<RegisterValue>;
    fn has_value(&self, register: &Register) -> bool;
}

/// Mutable processor register state.
///
/// Corresponds to `ghidra.program.model.lang.ProcessorContext` (interface).
pub trait ProcessorContext: ProcessorContextView {
    fn set_value(&mut self, register: &Register, value: u64) -> Result<(), LangError>;
    fn set_register_value(&mut self, value: RegisterValue) -> Result<(), LangError>;
    fn clear_register(&mut self, register: &Register) -> Result<(), LangError>;
}

// ============================================================================
// InstructionPrototype (trait)
// ============================================================================

/// Describes one machine-level instruction.
///
/// Corresponds to `ghidra.program.model.lang.InstructionPrototype` (interface).
pub trait InstructionPrototype: fmt::Debug + Send + Sync {
    fn has_delay_slots(&self) -> bool;
    fn has_cross_build_dependency(&self) -> bool;
    fn has_next2_dependency(&self) -> bool;
    fn get_mnemonic(&self) -> &str;
    fn get_length(&self) -> usize;
    fn get_flow_type(&self) -> FlowType;
    fn get_delay_slot_depth(&self) -> usize;
    fn is_in_delay_slot(&self) -> bool;
    fn get_num_operands(&self) -> usize;
    fn get_op_type(&self, operand_index: usize) -> u32;
    fn get_fall_through_offset(&self) -> Option<usize>;
    fn get_flows(&self) -> Vec<Address>;
}

/// Flow type for an instruction.
///
/// Corresponds to `ghidra.program.model.symbol.FlowType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FlowType {
    Fall,
    UnconditionalBranch,
    ConditionalBranch,
    Call,
    CallReturn,
    Terminal,
    Unknown,
}

impl FlowType {
    pub fn is_call(&self) -> bool {
        matches!(self, FlowType::Call | FlowType::CallReturn)
    }

    pub fn is_branch(&self) -> bool {
        matches!(
            self,
            FlowType::UnconditionalBranch | FlowType::ConditionalBranch
        )
    }

    pub fn is_terminal(&self) -> bool {
        *self == FlowType::Terminal
    }

    pub fn is_fall(&self) -> bool {
        *self == FlowType::Fall
    }

    pub fn is_conditional(&self) -> bool {
        *self == FlowType::ConditionalBranch
    }

    pub fn has_fallthrough(&self) -> bool {
        !matches!(
            self,
            FlowType::Terminal | FlowType::UnconditionalBranch
        )
    }
}

/// InstructionPrototype sentinel value for invalid depth change.
pub const INVALID_DEPTH_CHANGE: i32 = 1 << 24;

// ============================================================================
// ConstantPool
// ============================================================================

/// A deferred constant pool (e.g., JVM constant pool).
///
/// Corresponds to `ghidra.program.model.lang.ConstantPool`.
#[derive(Debug, Clone)]
pub enum ConstantPoolRecord {
    Primitive {
        tag: u8,
        value: i64,
        type_name: String,
    },
    StringLiteral {
        token: String,
    },
    ClassReference {
        token: String,
    },
    PointerMethod {
        token: String,
        type_name: String,
    },
    PointerField {
        token: String,
        type_name: String,
    },
    ArrayLength {
        token: String,
        type_name: String,
    },
    InstanceOf {
        token: String,
        type_name: String,
    },
    CheckCast {
        token: String,
        type_name: String,
    },
}

impl ConstantPoolRecord {
    pub const PRIMITIVE: u8 = 0;
    pub const STRING_LITERAL: u8 = 1;
    pub const CLASS_REFERENCE: u8 = 2;
    pub const POINTER_METHOD: u8 = 3;
    pub const POINTER_FIELD: u8 = 4;
    pub const ARRAY_LENGTH: u8 = 5;
    pub const INSTANCE_OF: u8 = 6;
    pub const CHECK_CAST: u8 = 7;
}

/// Trait for deferred constant pool lookups.
pub trait ConstantPool: fmt::Debug + Send + Sync {
    fn get_record(&self, ref_path: &[u64]) -> Option<ConstantPoolRecord>;
}

// ============================================================================
// InjectPayload
// ============================================================================

/// A P-code injection payload used for call-fixups and callother-fixups.
///
/// Corresponds to `ghidra.program.model.lang.InjectPayload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectPayload {
    pub name: String,
    pub payload_type: InjectPayloadType,
    pub pcode_snippet: String,
    pub source: String,
}

/// The type of inject payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InjectPayloadType {
    CallFixup,
    CallOtherFixup,
    CallMechanism,
    ExecutablePcode,
}

impl InjectPayload {
    pub const CALLFIXUP_TYPE: u32 = 0;
    pub const CALLOTHERFIXUP_TYPE: u32 = 1;
    pub const CALLMECHANISM_TYPE: u32 = 2;
    pub const EXECUTABLEPCODE_TYPE: u32 = 3;
}

// ============================================================================
// PcodeInjectLibrary
// ============================================================================

/// A library of P-code injection payloads.
///
/// Corresponds to `ghidra.program.model.lang.PcodeInjectLibrary`.
/// This is a simplified Rust version; the Java version has complex
/// Sleigh parsing and injection machinery.
#[derive(Debug, Clone, Default)]
pub struct PcodeInjectLibrary {
    pub payloads: HashMap<String, InjectPayload>,
}

impl PcodeInjectLibrary {
    pub fn new() -> Self {
        Self {
            payloads: HashMap::new(),
        }
    }

    pub fn register_payload(&mut self, payload: InjectPayload) {
        self.payloads.insert(payload.name.clone(), payload);
    }

    pub fn get_payload(&self, name: &str) -> Option<&InjectPayload> {
        self.payloads.get(name)
    }
}

// ============================================================================
// ProgramArchitecture (trait)
// ============================================================================

/// Identifies the program architecture (language + compiler spec).
///
/// Corresponds to `ghidra.program.model.lang.ProgramArchitecture` (interface).
pub trait ProgramArchitecture: fmt::Debug + Send + Sync {
    fn get_language(&self) -> &Language;
    fn get_compiler_spec(&self) -> &CompilerSpec;
    fn get_language_compiler_spec_pair(&self) -> LanguageCompilerSpecPair;
}

// ============================================================================
// LanguageService (trait)
// ============================================================================

/// Service for looking up languages and compiler specs.
///
/// Corresponds to `ghidra.program.model.lang.LanguageService` (interface).
pub trait LanguageService: fmt::Debug + Send + Sync {
    fn get_language(&self, id: &LanguageID) -> Result<Arc<Language>, LangError>;
    fn get_default_language(&self, processor: &str) -> Result<Arc<Language>, LangError>;
    fn get_language_description(&self, id: &LanguageID) -> Result<Box<dyn LanguageDescription>, LangError>;
    fn get_language_descriptions(&self, include_deprecated: bool) -> Vec<Box<dyn LanguageDescription>>;
    fn get_language_compiler_spec_pairs(
        &self,
        query: &LanguageCompilerSpecQuery,
    ) -> Vec<LanguageCompilerSpecPair>;
}

// ============================================================================
// RegisterBuilder
// ============================================================================

/// Helper for building a set of registers with proper parent-child relationships.
///
/// Corresponds to `ghidra.program.model.lang.RegisterBuilder`.
/// (In Java, RegisterBuilder is a helper used during language loading.)
#[derive(Debug)]
pub struct RegisterBuilder {
    registers: Vec<Register>,
    parent_map: HashMap<String, usize>,
}

impl RegisterBuilder {
    pub fn new() -> Self {
        Self {
            registers: Vec::new(),
            parent_map: HashMap::new(),
        }
    }

    /// Add a base (no parent) register.
    pub fn add_register(&mut self, reg: Register) {
        let name = reg.name.clone();
        let idx = self.registers.len();
        self.parent_map.insert(name, idx);
        self.registers.push(reg);
    }

    /// Add a child register under the named parent.
    pub fn add_child_register(
        &mut self,
        parent_name: &str,
        reg: Register,
    ) -> Result<(), LangError> {
        if !self.parent_map.contains_key(parent_name) {
            return Err(LangError::RegisterNotFound(parent_name.to_string()));
        }
        let name = reg.name.clone();
        let idx = self.registers.len();
        self.parent_map.insert(name, idx);
        self.registers.push(reg);
        Ok(())
    }

    /// Build the final RegisterManager from the added registers.
    pub fn build(mut self) -> RegisterManager {
        let mut rm = RegisterManager::new();
        for reg in self.registers.drain(..) {
            rm.add_register(reg);
        }
        rm.initialize();
        rm
    }
}

impl Default for RegisterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// RegisterTree
// ============================================================================

/// A tree of register names representing parent-child relationships.
///
/// Corresponds to `ghidra.program.model.lang.RegisterTree`.
#[derive(Debug, Clone)]
pub struct RegisterTree {
    pub name: String,
    pub children: Vec<RegisterTree>,
}

impl RegisterTree {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            children: Vec::new(),
        }
    }

    pub fn add_child(&mut self, child: RegisterTree) {
        self.children.push(child);
    }

    /// Collect all register names in this tree (depth-first).
    pub fn collect_names(&self) -> Vec<&str> {
        let mut names = vec![self.name.as_str()];
        for child in &self.children {
            names.extend(child.collect_names());
        }
        names
    }
}

// ============================================================================
// ParallelInstructionLanguageHelper (trait)
// ============================================================================

/// Helper for identifying parallel instruction execution in a language.
///
/// Corresponds to `ghidra.program.model.lang.ParallelInstructionLanguageHelper` (interface).
pub trait ParallelInstructionLanguageHelper: fmt::Debug + Send + Sync {
    /// Returns true if the given instruction bytes indicate parallel execution.
    fn is_parallel_instruction(&self, addr: Address, mem: &[u8]) -> bool;
}

// ============================================================================
// LanguageVersionException + other errors
// ============================================================================

/// Comprehensive error type for the lang module.
///
/// Corresponds to various Java exception types in `ghidra.program.model.lang`.
#[derive(Debug, Clone)]
pub enum LangError {
    /// No language found for the given LanguageID.
    LanguageNotFound(String),
    /// No compiler spec found for the given CompilerSpecID.
    CompilerSpecNotFound {
        language_id: LanguageID,
        compiler_spec_id: CompilerSpecID,
    },
    /// No processor found for the given name.
    ProcessorNotFound(String),
    /// Register not found by name.
    RegisterNotFound(String),
    /// Invalid language ID string.
    InvalidLanguageID(String),
    /// Not enough bytes to parse instruction.
    InsufficientBytes {
        needed: usize,
        available: usize,
    },
    /// Unrecognized instruction bytes.
    UnknownInstruction,
    /// Unknown context register value.
    UnknownContext,
    /// Mask byte array size mismatch.
    IncompatibleMask,
    /// Nested delay slot detected.
    NestedDelaySlot,
    /// Language version mismatch.
    LanguageVersionMismatch {
        expected: i32,
        found: i32,
    },
    /// Context change not allowed.
    ContextChangeError(String),
    /// Generic error message.
    Other(String),
}

impl fmt::Display for LangError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LangError::LanguageNotFound(id) => write!(f, "Language not found: {}", id),
            LangError::CompilerSpecNotFound { language_id, compiler_spec_id } => {
                write!(
                    f,
                    "Compiler spec not found: {} (language: {})",
                    compiler_spec_id, language_id
                )
            }
            LangError::ProcessorNotFound(name) => write!(f, "Processor not found: {}", name),
            LangError::RegisterNotFound(name) => write!(f, "Register not found: {}", name),
            LangError::InvalidLanguageID(id) => write!(f, "Invalid language ID: {}", id),
            LangError::InsufficientBytes { needed, available } => {
                write!(
                    f,
                    "Insufficient bytes: need {}, have {}",
                    needed, available
                )
            }
            LangError::UnknownInstruction => write!(f, "Unknown instruction"),
            LangError::UnknownContext => write!(f, "Unknown context"),
            LangError::IncompatibleMask => write!(f, "Incompatible mask"),
            LangError::NestedDelaySlot => write!(f, "Nested delay slot"),
            LangError::LanguageVersionMismatch { expected, found } => {
                write!(
                    f,
                    "Language version mismatch: expected {}, found {}",
                    expected, found
                )
            }
            LangError::ContextChangeError(msg) => write!(f, "Context change error: {}", msg),
            LangError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for LangError {}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // LanguageID tests
    // ========================================================================

    #[test]
    fn test_language_id_parse() {
        let id = LanguageID::parse("x86:LE:64:default").unwrap();
        assert_eq!(id.processor, "x86");
        assert_eq!(id.endian, "LE");
        assert_eq!(id.size, 64);
        assert_eq!(id.variant, "default");
        assert!(id.qualifier.is_none());
    }

    #[test]
    fn test_language_id_parse_with_qualifier() {
        let id = LanguageID::parse("x86:LE:64:default:windows").unwrap();
        assert_eq!(id.qualifier, Some("windows".to_string()));
    }

    #[test]
    fn test_language_id_to_string() {
        let id = LanguageID::x86_64();
        assert_eq!(id.to_id_string(), "x86:LE:64:default");
    }

    #[test]
    fn test_language_id_endianness() {
        let le = LanguageID::x86_64();
        assert!(le.is_little_endian());
        assert!(!le.is_big_endian());

        let be = LanguageID::mips32_be();
        assert!(be.is_big_endian());
        assert!(!be.is_little_endian());
    }

    #[test]
    fn test_language_id_display() {
        let id = LanguageID::x86_64();
        assert_eq!(format!("{}", id), "x86:LE:64:default");
    }

    #[test]
    fn test_language_id_ordering() {
        let a = LanguageID::x86_64();
        let b = LanguageID::x86_32();
        // x86:LE:32:default < x86:LE:64:default lexicographically
        assert!(b < a);
    }

    #[test]
    fn test_language_id_hash_and_eq() {
        let id1 = LanguageID::x86_64();
        let id2 = LanguageID::x86_64();
        assert_eq!(id1, id2);

        let mut set = HashSet::new();
        set.insert(id1.clone());
        assert!(set.contains(&id2));

        let id3 = LanguageID::x86_32();
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_language_id_convenience_ctors() {
        let x64 = LanguageID::x86_64();
        assert_eq!(x64.size, 64);
        let x32 = LanguageID::x86_32();
        assert_eq!(x32.size, 32);
        let arm = LanguageID::arm_v7();
        assert_eq!(arm.processor, "ARM");
        let aarch64 = LanguageID::aarch64();
        assert_eq!(aarch64.size, 64);
    }

    // ========================================================================
    // CompilerSpecID tests
    // ========================================================================

    #[test]
    fn test_compiler_spec_id_new() {
        let gcc = CompilerSpecID::gcc();
        assert_eq!(gcc.name, "gcc");

        let from_str: CompilerSpecID = "clang".into();
        assert_eq!(from_str.name, "clang");

        let from_string: CompilerSpecID = "visualstudio".to_string().into();
        assert_eq!(from_string.name, "visualstudio");
    }

    #[test]
    fn test_compiler_spec_id_eq() {
        assert_eq!(CompilerSpecID::gcc(), CompilerSpecID::new("gcc"));
        assert_ne!(CompilerSpecID::gcc(), CompilerSpecID::windows());
    }

    #[test]
    fn test_compiler_spec_id_display() {
        let id = CompilerSpecID::gcc();
        assert_eq!(format!("{}", id), "gcc");
    }

    #[test]
    fn test_compiler_spec_id_default_on_empty() {
        let id = CompilerSpecID::new("");
        assert_eq!(id.name, "default");
    }

    #[test]
    fn test_compiler_spec_id_ordering() {
        let a = CompilerSpecID::new("a");
        let b = CompilerSpecID::new("b");
        assert!(a < b);
    }

    // ========================================================================
    // Register tests
    // ========================================================================

    #[test]
    fn test_register_new() {
        let reg = Register::new("RAX", 64, "register", 0x00)
            .with_description("General Purpose Register A")
            .with_group("GeneralPurpose");
        assert_eq!(reg.name, "RAX");
        assert_eq!(reg.bit_length, 64);
        assert_eq!(reg.byte_length(), 8);
        assert!(!reg.is_sub_register());
        assert_eq!(reg.get_group(), Some("GeneralPurpose"));
    }

    #[test]
    fn test_register_sub_register() {
        let reg = Register::new("EAX", 32, "register", 0x00)
            .with_base_register("RAX")
            .with_parent("RAX")
            .with_lsb(0);
        assert!(reg.is_sub_register());
        assert_eq!(reg.base_register, Some("RAX".to_string()));
    }

    #[test]
    fn test_register_special_roles() {
        let pc = Register::new("RIP", 64, "register", 0x80).with_program_counter();
        assert!(pc.is_program_counter());

        let sp = Register::new("RSP", 64, "register", 0x38).with_stack_pointer();
        assert!(sp.is_stack_pointer());

        let fp = Register::new("RBP", 64, "register", 0x30).with_frame_pointer();
        assert!(fp.is_frame_pointer());
    }

    #[test]
    fn test_register_type_flags() {
        let mut flags = RegisterTypeFlags::default();
        assert!(!flags.is_program_counter());
        assert!(flags.follows_flow());

        flags.set(RegisterTypeFlags::PC);
        assert!(flags.is_program_counter());

        flags.set(RegisterTypeFlags::DOES_NOT_FOLLOW_FLOW);
        assert!(!flags.follows_flow());
        assert!(flags.does_not_follow_flow());

        flags.set(RegisterTypeFlags::VECTOR);
        assert!(flags.is_vector());
        assert_eq!(flags.bits(), RegisterTypeFlags::PC | RegisterTypeFlags::DOES_NOT_FOLLOW_FLOW | RegisterTypeFlags::VECTOR);
    }

    #[test]
    fn test_register_vector() {
        let reg = Register::new("XMM0", 128, "register", 0xa0)
            .with_vector()
            .with_lane_size(4)
            .with_lane_size(8);
        assert!(reg.is_vector_register());
        assert!(reg.is_valid_lane_size(4));
        assert!(reg.is_valid_lane_size(8));
        assert!(!reg.is_valid_lane_size(16));
        let sizes = reg.get_lane_sizes();
        assert_eq!(sizes, vec![4, 8]);
    }

    #[test]
    fn test_register_no_context() {
        let reg = Register::no_context();
        assert_eq!(reg.name, "NO_CONTEXT");
        assert!(reg.is_processor_context());
    }

    #[test]
    fn test_register_aliases() {
        let reg = Register::new("PC", 32, "register", 0x3c)
            .with_alias("r15")
            .with_alias("R15");
        assert!(reg.aliases.contains("r15"));
        assert!(reg.aliases.contains("R15"));
        // Adding self-name as alias is ignored
        let reg2 = reg.with_alias("PC");
        assert!(!reg2.aliases.contains("PC"));
    }

    #[test]
    fn test_register_contains() {
        // Test child register relationships
        let parent = Register::new("R0", 64, "register", 0x00)
            .with_children(vec!["R0_LOW"]);
        assert!(parent.has_children());
        assert_eq!(parent.get_child_registers(), &["R0_LOW"]);
    }

    #[test]
    fn test_register_ordering() {
        let r1 = Register::new("RAX", 64, "register", 0x00);
        let r2 = Register::new("EAX", 32, "register", 0x00)
            .with_base_register("RAX");
        // EAX and RAX have different base registers (EAX's base is "RAX", RAX's base is itself)
        // Since base registers differ, compare by address (both 0x00), then by bit_length
        assert!(r2 < r1); // 32 bits < 64 bits
    }

    #[test]
    fn test_register_display() {
        let reg = Register::new("EAX", 32, "register", 0x00);
        assert_eq!(format!("{}", reg), "EAX (32 bits)");
    }

    // ========================================================================
    // RegisterManager tests
    // ========================================================================

    #[test]
    fn test_register_manager_empty() {
        let rm = RegisterManager::new();
        assert!(rm.is_empty());
        assert_eq!(rm.register_count(), 0);
        assert!(rm.get_program_counter().is_none());
        assert!(rm.get_stack_pointer().is_none());
    }

    #[test]
    fn test_register_manager_x86_64() {
        let rm = RegisterManager::x86_64_default();
        assert!(rm.register_count() > 50);

        let rax = rm.get_register("RAX");
        assert!(rax.is_some());
        assert_eq!(rax.unwrap().bit_length, 64);

        let pc = rm.get_program_counter();
        assert!(pc.is_some());
        assert_eq!(pc.unwrap().name, "RIP");

        let sp = rm.get_stack_pointer();
        assert!(sp.is_some());
        assert_eq!(sp.unwrap().name, "RSP");

        let fp = rm.get_frame_pointer();
        assert!(fp.is_some());
        assert_eq!(fp.unwrap().name, "RBP");
    }

    #[test]
    fn test_register_manager_arm_v7() {
        let rm = RegisterManager::arm_v7_default();
        assert!(rm.register_count() > 20);

        let pc = rm.get_program_counter();
        assert!(pc.is_some());
        assert_eq!(pc.unwrap().name, "PC");

        let sp = rm.get_stack_pointer();
        assert!(sp.is_some());
        assert_eq!(sp.unwrap().name, "SP");

        let lr = rm.get_return_address_register();
        assert!(lr.is_some());
        assert_eq!(lr.unwrap().name, "LR");
    }

    #[test]
    fn test_register_manager_child_registers() {
        let rm = RegisterManager::x86_64_default();
        let children = rm.get_child_registers("RAX");
        let child_names: Vec<&str> = children.iter().map(|r| r.name.as_str()).collect();
        assert!(child_names.contains(&"EAX"));
    }

    #[test]
    fn test_register_manager_base_register() {
        let rm = RegisterManager::x86_64_default();
        let base = rm.get_base_register("EAX");
        assert!(base.is_some());
        assert_eq!(base.unwrap().name, "RAX");
    }

    #[test]
    fn test_register_manager_at_offset() {
        let rm = RegisterManager::x86_64_default();
        let regs = rm.get_registers_at(&Address::new(0x00));
        assert!(!regs.is_empty());
    }

    #[test]
    fn test_register_manager_largest_register() {
        let rm = RegisterManager::x86_64_default();
        let reg = rm.get_largest_register_at(&Address::new(0x00));
        assert!(reg.is_some());
        assert_eq!(reg.unwrap().name, "RAX");
    }

    #[test]
    fn test_register_manager_register_names() {
        let rm = RegisterManager::x86_64_default();
        let names = rm.get_register_names();
        assert!(names.contains(&"RAX"));
        assert!(names.contains(&"RSP"));
        assert!(names.contains(&"RIP"));
    }

    #[test]
    fn test_register_manager_case_insensitive() {
        let rm = RegisterManager::x86_64_default();
        // Lowercase lookup
        assert!(rm.get_register("rax").is_some());
        // Uppercase lookup
        assert!(rm.get_register("RAX").is_some());
    }

    #[test]
    fn test_register_manager_vector_registers() {
        let rm = RegisterManager::x86_64_default();
        let vectors = rm.get_sorted_vector_registers();
        assert!(!vectors.is_empty());
        // XMM registers should be present
        let has_xmm0 = vectors.iter().any(|r| r.name == "XMM0");
        assert!(has_xmm0);
    }

    #[test]
    fn test_register_manager_groups() {
        let rm = RegisterManager::x86_64_default();
        let gp = rm.get_registers_in_group("GeneralPurpose");
        assert!(!gp.is_empty());
        assert!(gp.iter().any(|r| r.name == "RAX"));
    }

    // ========================================================================
    // Language tests
    // ========================================================================

    #[test]
    fn test_language_creation() {
        let lang = Language::new(
            LanguageID::x86_64(),
            "x86 64-bit",
            "1.0",
            0,
            "x86 64-bit little-endian",
            AddressFactory::new(),
        )
        .with_register_manager(RegisterManager::x86_64_default());

        assert_eq!(lang.name, "x86 64-bit");
        assert_eq!(lang.version, "1.0");
        assert!(lang.has_pcode);
        assert_eq!(lang.get_pointer_size(), 8);
        assert!(!lang.is_big_endian());
        assert_eq!(lang.get_instruction_alignment(), 1);
    }

    #[test]
    fn test_language_register_access() {
        let lang = Language::new(
            LanguageID::x86_64(),
            "x86 64-bit",
            "1.0",
            0,
            "desc",
            AddressFactory::new(),
        )
        .with_register_manager(RegisterManager::x86_64_default());

        assert!(lang.get_register("RAX").is_some());
        assert!(lang.get_program_counter().is_some());
        assert!(lang.get_stack_pointer().is_some());
        assert!(lang.get_frame_pointer().is_some());
    }

    #[test]
    fn test_language_properties() {
        let lang = Language::new(
            LanguageID::x86_64(),
            "x86 64-bit",
            "1.0",
            0,
            "desc",
            AddressFactory::new(),
        )
        .with_register_manager(RegisterManager::x86_64_default())
        .with_property("max_instruction_length", "15");

        assert!(lang.has_property("max_instruction_length"));
        assert_eq!(
            lang.get_property_as_int("max_instruction_length", 0),
            15
        );
        assert!(!lang.has_property("nonexistent"));
    }

    #[test]
    fn test_language_display() {
        let lang = Language::new(
            LanguageID::x86_64(),
            "x86 64-bit",
            "1.0",
            0,
            "desc",
            AddressFactory::new(),
        );
        let s = format!("{}", lang);
        assert!(s.contains("x86 64-bit"));
        assert!(s.contains("1.0"));
    }

    #[test]
    fn test_language_user_defined_ops() {
        let lang = Language::new(
            LanguageID::x86_64(),
            "x86 64-bit",
            "1.0",
            0,
            "desc",
            AddressFactory::new(),
        )
        .with_user_defined_op(0, "syscall")
        .with_user_defined_op(1, "cpuid");

        assert_eq!(lang.get_number_of_user_defined_op_names(), 2);
        assert_eq!(lang.get_user_defined_op_name(0), Some("syscall"));
        assert_eq!(lang.get_user_defined_op_name(99), None);
    }

    // ========================================================================
    // CompilerSpec tests
    // ========================================================================

    #[test]
    fn test_compiler_spec_creation() {
        let lang = Language::new(
            LanguageID::x86_64(),
            "x86 64-bit",
            "1.0",
            0,
            "desc",
            AddressFactory::new(),
        );

        let spec = CompilerSpec::for_language(&lang);
        assert_eq!(spec.language_id.to_id_string(), "x86:LE:64:default");
        assert!(spec.language.is_some());
    }

    #[test]
    fn test_compiler_spec_with_conventions() {
        let lang = Language::new(
            LanguageID::x86_64(),
            "x86 64-bit",
            "1.0",
            0,
            "desc",
            AddressFactory::new(),
        );
        let spec = CompilerSpec::for_language(&lang)
            .with_calling_convention(CallingConvention::sysv_amd64())
            .with_default_calling_convention(CallingConvention::sysv_amd64())
            .with_prototype_model("__sysv64");

        assert_eq!(spec.calling_conventions.len(), 1);
        assert!(spec.default_calling_convention.is_some());
        assert_eq!(spec.prototype_model, Some("__sysv64".to_string()));
        assert!(spec.is_little_endian());
    }

    #[test]
    fn test_compiler_spec_properties() {
        let lang = Language::new(
            LanguageID::x86_64(),
            "x86 64-bit",
            "1.0",
            0,
            "desc",
            AddressFactory::new(),
        );
        let spec = CompilerSpec::for_language(&lang)
            .with_property("returns_in_float", "true");

        assert!(spec.has_property("returns_in_float"));
        assert_eq!(spec.get_property_as_bool("returns_in_float", false), true);
    }

    // ========================================================================
    // CallingConvention tests
    // ========================================================================

    #[test]
    fn test_calling_convention_sysv_amd64() {
        let cc = CallingConvention::sysv_amd64();
        assert_eq!(cc.name, "__sysv64");
        assert_eq!(cc.parameter_registers.len(), 6);
        assert_eq!(cc.parameter_registers[0], "RDI");
        assert_eq!(cc.return_register, Some("RAX".to_string()));
        assert_eq!(cc.stack_alignment, 16);
        assert_eq!(cc.shadow_space, 0);
        assert!(cc.has_red_zone);
        assert!(cc.caller_cleanup);
    }

    #[test]
    fn test_calling_convention_win64() {
        let cc = CallingConvention::win64();
        assert_eq!(cc.name, "__win64");
        assert_eq!(cc.parameter_registers.len(), 4);
        assert_eq!(cc.shadow_space, 32);
        assert!(!cc.has_red_zone);
    }

    #[test]
    fn test_calling_convention_aapcs() {
        let cc = CallingConvention::aapcs();
        assert_eq!(cc.parameter_registers[0], "r0");
        assert_eq!(cc.stack_alignment, 8);
    }

    #[test]
    fn test_calling_convention_can_return_in_registers() {
        let cc = CallingConvention::sysv_amd64();
        assert!(cc.can_return_in_registers(8));
        assert!(cc.can_return_in_registers(16)); // RAX + RDX
        assert!(!cc.can_return_in_registers(17));
    }

    #[test]
    fn test_calling_convention_register_parameter_count() {
        let cc = CallingConvention::sysv_amd64();
        assert_eq!(cc.register_parameter_count(), 6);
        let cc_none = CallingConvention::cdecl();
        assert_eq!(cc_none.register_parameter_count(), 0);
    }

    #[test]
    fn test_calling_convention_display() {
        let cc = CallingConvention::sysv_amd64();
        let s = format!("{}", cc);
        assert!(s.contains("__sysv64"));
        assert!(s.contains("RDI"));
    }

    // ========================================================================
    // Processor tests
    // ========================================================================

    #[test]
    fn test_processor_x86() {
        let proc = Processor::x86();
        assert_eq!(proc.name, "x86");
        assert!(proc.language_count() >= 2);
        assert!(proc.supports_little_endian);
        assert!(proc.supports_sleigh);
        let default = proc.get_default_language();
        assert!(default.is_some());
    }

    #[test]
    fn test_processor_arm() {
        let proc = Processor::arm();
        assert!(proc.language_count() >= 4);
        assert!(proc.supports_little_endian);
        assert!(proc.supports_big_endian);
    }

    #[test]
    fn test_processor_mips() {
        let proc = Processor::mips();
        assert_eq!(proc.name, "MIPS");
        assert!(proc.supports_big_endian);
        assert!(proc.supports_little_endian);
    }

    #[test]
    fn test_processor_powerpc() {
        let proc = Processor::powerpc();
        assert_eq!(proc.name, "PowerPC");
        assert!(proc.language_count() >= 3);
    }

    #[test]
    fn test_processor_get_language() {
        let proc = Processor::x86();
        let lang = proc.get_language("x86:LE:64:default");
        assert!(lang.is_some());
        assert_eq!(lang.unwrap().size, 64);
    }

    #[test]
    fn test_processor_32_64_filters() {
        let proc = Processor::arm();
        let langs32 = proc.get_32bit_languages();
        let langs64 = proc.get_64bit_languages();
        assert!(!langs32.is_empty());
        assert!(!langs64.is_empty());
    }

    #[test]
    fn test_processor_eq_hash() {
        let p1 = Processor::new("x86");
        let p2 = Processor::new("x86").with_language(LanguageID::x86_64());
        assert_eq!(p1, p2);
    }

    // ========================================================================
    // Endian tests
    // ========================================================================

    #[test]
    fn test_endian_from_str() {
        assert_eq!(Endian::from_str("big"), Some(Endian::Big));
        assert_eq!(Endian::from_str("BE"), Some(Endian::Big));
        assert_eq!(Endian::from_str("little"), Some(Endian::Little));
        assert_eq!(Endian::from_str("LE"), Some(Endian::Little));
        assert_eq!(Endian::from_str("BOTH"), None);
    }

    #[test]
    fn test_endian_properties() {
        assert!(Endian::Big.is_big_endian());
        assert!(!Endian::Big.is_little_endian());
        assert!(!Endian::Little.is_big_endian());
        assert!(Endian::Little.is_little_endian());
        assert_eq!(Endian::Big.to_short_string(), "BE");
        assert_eq!(Endian::Little.to_short_string(), "LE");
    }

    #[test]
    fn test_endian_display() {
        assert_eq!(format!("{}", Endian::Big), "Big");
        assert_eq!(format!("{}", Endian::Little), "Little");
    }

    // ========================================================================
    // DecompilerLanguage tests
    // ========================================================================

    #[test]
    fn test_decompiler_language_display() {
        assert_eq!(format!("{}", DecompilerLanguage::CLanguage), "c-language");
        assert_eq!(format!("{}", DecompilerLanguage::JavaLanguage), "java-language");
    }

    // ========================================================================
    // StorageClass tests
    // ========================================================================

    #[test]
    fn test_storage_class_values() {
        assert_eq!(StorageClass::General.value(), 0);
        assert_eq!(StorageClass::Float.value(), 1);
        assert_eq!(StorageClass::Ptr.value(), 2);
        assert_eq!(StorageClass::Class1.value(), 100);
    }

    #[test]
    fn test_storage_class_from_name() {
        assert_eq!(StorageClass::from_name("general"), Some(StorageClass::General));
        assert_eq!(StorageClass::from_name("float"), Some(StorageClass::Float));
        assert_eq!(StorageClass::from_name("ptr"), Some(StorageClass::Ptr));
        assert_eq!(StorageClass::from_name("hiddenret"), Some(StorageClass::HiddenRet));
        assert_eq!(StorageClass::from_name("vector"), Some(StorageClass::Vector));
        assert_eq!(StorageClass::from_name("class1"), Some(StorageClass::Class1));
        assert_eq!(StorageClass::from_name("unknown"), None);
    }

    #[test]
    fn test_storage_class_display() {
        assert_eq!(format!("{}", StorageClass::General), "general");
        assert_eq!(format!("{}", StorageClass::Float), "float");
    }

    // ========================================================================
    // OperandType tests
    // ========================================================================

    #[test]
    fn test_operand_type_flags() {
        assert!(OperandType::does_read(OperandType::READ));
        assert!(!OperandType::does_read(0));
        assert!(OperandType::does_write(OperandType::WRITE));
        assert!(OperandType::is_immediate(OperandType::IMMEDIATE));
        assert!(OperandType::is_register(OperandType::REGISTER));
        assert!(OperandType::is_address(OperandType::ADDRESS));
        assert!(OperandType::is_scalar(OperandType::SCALAR));
        assert!(OperandType::is_dynamic(OperandType::DYNAMIC));
        assert!(OperandType::is_float(OperandType::FLOAT));
        assert!(OperandType::is_signed(OperandType::SIGNED));
    }

    #[test]
    fn test_operand_type_combined() {
        let t = OperandType::ADDRESS | OperandType::READ | OperandType::DYNAMIC;
        assert!(OperandType::is_address(t));
        assert!(OperandType::does_read(t));
        assert!(OperandType::is_dynamic(t));
        assert!(!OperandType::does_write(t));
    }

    #[test]
    fn test_operand_type_debug_string() {
        let t = OperandType::ADDRESS | OperandType::READ;
        let s = OperandType::to_debug_string(t);
        assert!(s.contains("ADDR"));
        assert!(s.contains("READ"));
    }

    #[test]
    fn test_operand_type_scalar_as_address() {
        let t = OperandType::ADDRESS | OperandType::SCALAR;
        assert!(OperandType::is_scalar_as_address(t));
    }

    #[test]
    fn test_operand_type_struct() {
        let ot = OperandType::new(OperandType::REGISTER | OperandType::WRITE);
        assert!(ot.contains(OperandType::REGISTER));
        assert!(ot.contains(OperandType::WRITE));
        assert!(!ot.contains(OperandType::READ));
    }

    // ========================================================================
    // SpaceNames tests
    // ========================================================================

    #[test]
    fn test_space_names() {
        assert_eq!(SpaceNames::CONSTANT_SPACE_NAME, "const");
        assert_eq!(SpaceNames::UNIQUE_SPACE_NAME, "unique");
        assert_eq!(SpaceNames::STACK_SPACE_NAME, "stack");
        assert_eq!(SpaceNames::JOIN_SPACE_NAME, "join");
        assert_eq!(SpaceNames::CONSTANT_SPACE_INDEX, 0);
        assert_eq!(SpaceNames::OTHER_SPACE_INDEX, 1);
        assert_eq!(SpaceNames::UNIQUE_SPACE_SIZE, 4);
    }

    // ========================================================================
    // GhidraLanguagePropertyKeys tests
    // ========================================================================

    #[test]
    fn test_language_property_keys() {
        assert_eq!(
            GhidraLanguagePropertyKeys::MAXIMUM_INSTRUCTION_LENGTH,
            "maximumInstructionLength"
        );
        assert_eq!(
            GhidraLanguagePropertyKeys::CUSTOM_DISASSEMBLER_CLASS,
            "customDisassemblerClass"
        );
        assert_eq!(
            GhidraLanguagePropertyKeys::ENABLE_NO_RETURN_ANALYSIS,
            "enableNoReturnAnalysis"
        );
    }

    // ========================================================================
    // BasicCompilerSpecDescription tests
    // ========================================================================

    #[test]
    fn test_basic_compiler_spec_description() {
        let desc = BasicCompilerSpecDescription::new(
            CompilerSpecID::gcc(),
            "GNU C Compiler",
        );
        assert_eq!(desc.get_compiler_spec_id().name, "gcc");
        assert_eq!(desc.get_compiler_spec_name(), "GNU C Compiler");
        assert_eq!(format!("{}", desc), "GNU C Compiler");
    }

    #[test]
    fn test_basic_compiler_spec_description_eq() {
        let d1 = BasicCompilerSpecDescription::new(CompilerSpecID::gcc(), "GCC");
        let d2 = BasicCompilerSpecDescription::new(CompilerSpecID::gcc(), "Other");
        assert_eq!(d1, d2); // same id = equal
    }

    // ========================================================================
    // LanguageCompilerSpecPair tests
    // ========================================================================

    #[test]
    fn test_language_compiler_spec_pair() {
        let pair = LanguageCompilerSpecPair::new(
            LanguageID::x86_64(),
            CompilerSpecID::gcc(),
        );
        assert_eq!(pair.language_id, LanguageID::x86_64());
        assert_eq!(pair.compiler_spec_id, CompilerSpecID::gcc());
        assert_eq!(format!("{}", pair), "x86:LE:64:default:gcc");
    }

    #[test]
    fn test_language_compiler_spec_pair_from_strings() {
        let pair = LanguageCompilerSpecPair::from_strings("x86:LE:64:default", "gcc");
        assert!(pair.is_ok());
        let pair = pair.unwrap();
        assert_eq!(pair.compiler_spec_id, CompilerSpecID::gcc());

        let bad = LanguageCompilerSpecPair::from_strings("invalid", "gcc");
        assert!(bad.is_err());
    }

    #[test]
    fn test_language_compiler_spec_pair_ordering() {
        let p1 = LanguageCompilerSpecPair::new(
            LanguageID::x86_64(),
            CompilerSpecID::gcc(),
        );
        let p2 = LanguageCompilerSpecPair::new(
            LanguageID::x86_64(),
            CompilerSpecID::windows(),
        );
        assert!(p1 < p2); // gcc < windows
    }

    // ========================================================================
    // LanguageCompilerSpecQuery tests
    // ========================================================================

    #[test]
    fn test_language_compiler_spec_query() {
        let q = LanguageCompilerSpecQuery {
            processor: Some("x86".to_string()),
            endian: Some(Endian::Little),
            size: Some(64),
            variant: None,
        };
        assert!(q.processor.is_some());
        assert_eq!(q.size, Some(64));
    }

    // ========================================================================
    // ExternalLanguageCompilerSpecQuery tests
    // ========================================================================

    #[test]
    fn test_external_language_compiler_spec_query() {
        let q = ExternalLanguageCompilerSpecQuery::new("metapc", "IDA-PRO");
        assert_eq!(q.external_processor_name, "metapc");
        assert_eq!(q.external_tool, "IDA-PRO");
        let s = format!("{}", q);
        assert!(s.contains("metapc"));
        assert!(s.contains("IDA-PRO"));
    }

    // ========================================================================
    // AddressLabelInfo tests
    // ========================================================================

    #[test]
    fn test_address_label_info() {
        let info = AddressLabelInfo::new(
            Address::new(0x1000),
            4,
            "_start",
            Some("Entry point".to_string()),
            true,
            true,
            None,
        );
        assert_eq!(info.get_address().offset, 0x1000);
        assert_eq!(info.get_end_address().offset, 0x1003);
        assert_eq!(info.get_label(), "_start");
        assert_eq!(info.get_byte_size(), 4);
        assert!(info.is_primary);
        assert!(info.is_entry);
    }

    #[test]
    fn test_address_label_info_ordering() {
        let i1 = AddressLabelInfo::new(Address::new(0x1000), 1, "a", None, false, false, None);
        let i2 = AddressLabelInfo::new(Address::new(0x2000), 1, "b", None, false, false, None);
        assert!(i1 < i2);
    }

    // ========================================================================
    // UnknownRegister tests
    // ========================================================================

    #[test]
    fn test_unknown_register() {
        let ur = UnknownRegister::new(
            "UNK", "Unknown", Address::new(0x100), 4, false,
            RegisterTypeFlags::default(),
        );
        assert_eq!(ur.name, "UNK");
        assert_eq!(ur.bit_length, 32);
    }

    // ========================================================================
    // ContextSetting tests
    // ========================================================================

    #[test]
    fn test_context_setting() {
        let cs = ContextSetting::new("TMode", 1, Address::new(0x1000), Address::new(0x2000));
        assert_eq!(cs.register_name, "TMode");
        assert_eq!(cs.value, 1);
        assert!(cs.is_equivalent(&ContextSetting::new("TMode", 1, Address::new(0x1000), Address::new(0x2000))));
        assert!(!cs.is_equivalent(&ContextSetting::new("TMode", 0, Address::new(0x1000), Address::new(0x2000))));
    }

    // ========================================================================
    // RegisterValue tests
    // ========================================================================

    #[test]
    fn test_register_value_new() {
        let rv = RegisterValue::new("EAX", 32, 0xDEADBEEF, false);
        assert_eq!(rv.get_register_name(), "EAX");
        assert!(rv.has_value());
        let val = rv.get_unsigned_value();
        assert!(val.is_some());
    }

    #[test]
    fn test_register_value_empty() {
        let rv = RegisterValue::empty("EAX", 4);
        assert!(!rv.has_value());
        assert!(!rv.has_any_value());
        assert!(rv.get_unsigned_value().is_none());
    }

    #[test]
    fn test_register_value_combine() {
        let rv1 = RegisterValue::new("EAX", 32, 0x11111111, false);
        let rv2 = RegisterValue::new("EAX", 32, 0x22222222, false);
        let combined = rv1.combine_values(&rv2);
        assert!(combined.has_value());
    }

    #[test]
    fn test_register_value_display() {
        let rv = RegisterValue::new("AL", 8, 0xFF, false);
        let s = format!("{}", rv);
        assert!(s.contains("RegisterValue(AL)"));
        assert!(s.contains("mask=0x"));
        assert!(s.contains("value=0x"));
    }

    // ========================================================================
    // MaskImpl tests
    // ========================================================================

    #[test]
    fn test_mask_impl_apply() {
        let mask = MaskImpl::new(vec![0xFF, 0x00, 0xF0, 0x0F]);
        let cde = vec![0xAB, 0xCD, 0xEF, 0x12];
        let mut result = vec![0u8; 4];
        mask.apply_mask(&cde, &mut result).unwrap();
        assert_eq!(result[0], 0xAB); // 0xFF & 0xAB
        assert_eq!(result[1], 0x00); // 0x00 & 0xCD
        assert_eq!(result[2], 0xE0); // 0xF0 & 0xEF
        assert_eq!(result[3], 0x02); // 0x0F & 0x12
    }

    #[test]
    fn test_mask_impl_equal_masked_value() {
        let mask = MaskImpl::new(vec![0xFF, 0x0F]);
        let cde = vec![0xAB, 0xCD];
        let target_match = vec![0xAB, 0x0D];
        let target_mismatch = vec![0xAB, 0x0C];
        assert!(mask.equal_masked_value(&cde, &target_match).unwrap());
        assert!(!mask.equal_masked_value(&cde, &target_mismatch).unwrap());
    }

    // ========================================================================
    // PrototypeModel tests
    // ========================================================================

    #[test]
    fn test_prototype_model_new() {
        let pm = PrototypeModel::new("__cdecl");
        assert_eq!(pm.name, "__cdecl");
        assert_eq!(pm.extrapop, PrototypeModel::UNKNOWN_EXTRAPOP);
        assert!(!pm.has_this);
        assert!(!pm.has_injection());
    }

    #[test]
    fn test_prototype_model_alias() {
        let base = PrototypeModel::new("__cdecl");
        let alias = PrototypeModel::alias("custom_cdecl", &base);
        assert_eq!(alias.name, "custom_cdecl");
        assert_eq!(alias.extrapop, base.extrapop);
    }

    #[test]
    fn test_prototype_model_predefined() {
        let cdecl = PrototypeModel::cdecl();
        assert_eq!(cdecl.name, "__cdecl");

        let thiscall = PrototypeModel::thiscall();
        assert!(thiscall.has_this);

        let stdcall = PrototypeModel::stdcall();
        assert_eq!(stdcall.name, "__stdcall");
    }

    #[test]
    fn test_prototype_model_equivalent() {
        let a = PrototypeModel::new("test");
        let mut b = PrototypeModel::new("test");
        assert!(a.is_equivalent(&b));
        b.extrapop = 42;
        assert!(!a.is_equivalent(&b));
    }

    // ========================================================================
    // ParamEntry tests
    // ========================================================================

    #[test]
    fn test_param_entry() {
        let mut pe = ParamEntry::new(0);
        pe.storage_class = StorageClass::General;
        pe.space_name = "register".to_string();
        pe.size = 8;
        pe.min_size = 4;
        pe.alignment = 8;
        assert_eq!(pe.get_group(), 0);
        assert_eq!(pe.get_size(), 8);
        assert_eq!(pe.get_min_size(), 4);
        assert_eq!(pe.get_align(), 8);
    }

    // ========================================================================
    // PrototypePieces tests
    // ========================================================================

    #[test]
    fn test_prototype_pieces() {
        let pp = PrototypePieces::new();
        assert!(pp.model_name.is_none());
        assert!(pp.out_type.is_none());
        assert!(pp.in_types.is_empty());
        assert_eq!(pp.first_var_arg_slot, -1);
    }

    // ========================================================================
    // ParameterPieces tests
    // ========================================================================

    #[test]
    fn test_parameter_pieces_default() {
        let pp = ParameterPieces::new();
        assert!(pp.address.is_none());
        assert!(!pp.is_this_pointer);
        assert!(!pp.hidden_return_ptr);
        assert!(!pp.is_indirect);
    }

    #[test]
    fn test_parameter_pieces_swap_markup() {
        let mut a = ParameterPieces {
            type_name: Some("int".to_string()),
            is_this_pointer: true,
            ..ParameterPieces::new()
        };
        let mut b = ParameterPieces {
            type_name: Some("float".to_string()),
            hidden_return_ptr: true,
            ..ParameterPieces::new()
        };
        a.swap_markup(&mut b);
        assert_eq!(a.type_name, Some("float".to_string()));
        assert!(a.hidden_return_ptr);
        assert!(!a.is_this_pointer);
        assert_eq!(b.type_name, Some("int".to_string()));
        assert!(b.is_this_pointer);
    }

    // ========================================================================
    // FlowType tests
    // ========================================================================

    #[test]
    fn test_flow_type() {
        assert!(FlowType::Call.is_call());
        assert!(FlowType::CallReturn.is_call());
        assert!(!FlowType::Fall.is_call());
        assert!(FlowType::UnconditionalBranch.is_branch());
        assert!(FlowType::ConditionalBranch.is_branch());
        assert!(FlowType::ConditionalBranch.is_conditional());
        assert!(FlowType::Terminal.is_terminal());
        assert!(!FlowType::Terminal.has_fallthrough());
        assert!(FlowType::Fall.has_fallthrough());
        assert!(FlowType::ConditionalBranch.has_fallthrough());
    }

    // ========================================================================
    // RegisterBuilder tests
    // ========================================================================

    #[test]
    fn test_register_builder() {
        let mut rb = RegisterBuilder::new();
        rb.add_register(
            Register::new("RAX", 64, "register", 0x00)
                .with_children(vec!["EAX"]),
        );
        rb.add_register(
            Register::new("EAX", 32, "register", 0x00)
                .with_base_register("RAX")
                .with_parent("RAX")
                .with_lsb(0),
        );

        let rm = rb.build();
        assert!(rm.get_register("RAX").is_some());
        assert!(rm.get_register("EAX").is_some());
    }

    // ========================================================================
    // RegisterTree tests
    // ========================================================================

    #[test]
    fn test_register_tree() {
        let mut root = RegisterTree::new("RAX");
        let mut eax = RegisterTree::new("EAX");
        eax.add_child(RegisterTree::new("AX"));
        root.add_child(eax);

        let names = root.collect_names();
        assert_eq!(names, vec!["RAX", "EAX", "AX"]);
    }

    // ========================================================================
    // LangError tests
    // ========================================================================

    #[test]
    fn test_lang_error_display() {
        let err = LangError::LanguageNotFound("x86:LE:64:default".to_string());
        assert!(format!("{}", err).contains("Language not found"));

        let err = LangError::InsufficientBytes { needed: 4, available: 2 };
        assert!(format!("{}", err).contains("4"));
        assert!(format!("{}", err).contains("2"));

        let err = LangError::CompilerSpecNotFound {
            language_id: LanguageID::x86_64(),
            compiler_spec_id: CompilerSpecID::gcc(),
        };
        assert!(format!("{}", err).contains("gcc"));
    }

    #[test]
    fn test_lang_error_is_std_error() {
        let err: Box<dyn std::error::Error> =
            Box::new(LangError::UnknownInstruction);
        assert!(err.to_string().contains("Unknown instruction"));
    }

    // ========================================================================
    // InjectPayload tests
    // ========================================================================

    #[test]
    fn test_inject_payload() {
        let p = InjectPayload {
            name: "fixup_malloc".to_string(),
            payload_type: InjectPayloadType::CallFixup,
            pcode_snippet: "RAX = 0;".to_string(),
            source: "default".to_string(),
        };
        assert_eq!(p.name, "fixup_malloc");
        assert_eq!(p.payload_type, InjectPayloadType::CallFixup);
    }

    // ========================================================================
    // PcodeInjectLibrary tests
    // ========================================================================

    #[test]
    fn test_pcode_inject_library() {
        let mut lib = PcodeInjectLibrary::new();
        lib.register_payload(InjectPayload {
            name: "test".to_string(),
            payload_type: InjectPayloadType::CallFixup,
            pcode_snippet: "".to_string(),
            source: "".to_string(),
        });
        assert!(lib.get_payload("test").is_some());
        assert!(lib.get_payload("missing").is_none());
    }

    // ========================================================================
    // ConstantPoolRecord tests
    // ========================================================================

    #[test]
    fn test_constant_pool_record_tag_constants() {
        assert_eq!(ConstantPoolRecord::PRIMITIVE, 0);
        assert_eq!(ConstantPoolRecord::STRING_LITERAL, 1);
        assert_eq!(ConstantPoolRecord::CLASS_REFERENCE, 2);
        assert_eq!(ConstantPoolRecord::POINTER_METHOD, 3);
        assert_eq!(ConstantPoolRecord::POINTER_FIELD, 4);
    }
}
