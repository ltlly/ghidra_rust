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
}
