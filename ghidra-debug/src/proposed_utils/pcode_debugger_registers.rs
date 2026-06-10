//! Pcode debugger register utilities.
//!
//! Ported from Ghidra's proposed `PcodeDebuggerRegisters` utilities.
//! Provides register bank abstraction, register mapping between language
//! registers and target connectors, register grouping, and register
//! value transformation helpers for pcode-based debugging.
//!
//! Key types:
//! - `PcodeRegisterBank`: A bank of registers for a pcode debug session.
//! - `RegisterMapping`: Maps between language register names and connector names.
//! - `RegisterGroup`: Logical grouping of registers for display.
//! - `RegisterValueTransformer`: Transformations on register values
//!   (endianness swap, sign extension, etc.).
//! - `RegisterConvention`: Register calling convention description.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// A bank of registers for a pcode debug session.
///
/// Ported from Ghidra's proposed `PcodeDebuggerRegisters`. Manages
/// register definitions, their values, and the relationships between
/// registers (parent/child, aliases).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PcodeRegisterBank {
    /// Register definitions by name.
    definitions: BTreeMap<String, RegisterDefinition>,
    /// Current register values by name.
    values: BTreeMap<String, Vec<u8>>,
    /// Alias mappings (alias_name -> canonical_name).
    aliases: BTreeMap<String, String>,
    /// Parent-child relationships (child_name -> parent_name).
    children_of: BTreeMap<String, String>,
    /// Groups for display organization.
    groups: Vec<RegisterGroup>,
}

impl PcodeRegisterBank {
    /// Create a new empty register bank.
    pub fn new() -> Self {
        Self::default()
    }

    /// Define a register.
    pub fn define_register(&mut self, def: RegisterDefinition) {
        let name = def.name.clone();
        self.definitions.insert(name, def);
    }

    /// Define a register with basic parameters.
    pub fn define(
        &mut self,
        name: impl Into<String>,
        bit_length: u32,
        group: impl Into<String>,
    ) {
        let name = name.into();
        self.define_register(RegisterDefinition {
            name: name.clone(),
            bit_length,
            group: group.into(),
            ..Default::default()
        });
    }

    /// Add an alias for a register.
    pub fn add_alias(&mut self, alias: impl Into<String>, canonical: impl Into<String>) {
        self.aliases.insert(alias.into(), canonical.into());
    }

    /// Set a parent-child relationship between registers.
    pub fn set_parent(&mut self, child: impl Into<String>, parent: impl Into<String>) {
        self.children_of.insert(child.into(), parent.into());
    }

    /// Write a register value by name.
    pub fn write_register(&mut self, name: &str, value: &[u8]) {
        let canonical = self.resolve_name(name);
        self.values.insert(canonical.to_string(), value.to_vec());
    }

    /// Read a register value by name.
    pub fn read_register(&self, name: &str) -> Option<Vec<u8>> {
        let canonical = self.resolve_name(name);
        self.values.get(canonical).cloned()
    }

    /// Resolve a name through aliases to the canonical name.
    pub fn resolve_name<'a>(&'a self, name: &'a str) -> &'a str {
        self.aliases
            .get(name)
            .map(|s| s.as_str())
            .unwrap_or(name)
    }

    /// Get a register definition by name.
    pub fn get_definition(&self, name: &str) -> Option<&RegisterDefinition> {
        let canonical = self.resolve_name(name);
        self.definitions.get(canonical)
    }

    /// Get all register names (canonical, excluding aliases).
    pub fn register_names(&self) -> Vec<&str> {
        self.definitions.keys().map(|s| s.as_str()).collect()
    }

    /// Get the parent register name for a child register.
    pub fn parent_of(&self, name: &str) -> Option<&str> {
        let canonical = self.resolve_name(name);
        self.children_of.get(canonical).map(|s| s.as_str())
    }

    /// Get all child register names of a parent.
    pub fn children_of(&self, parent: &str) -> Vec<String> {
        let canonical = self.resolve_name(parent);
        self.children_of
            .iter()
            .filter(|(_, p)| p.as_str() == canonical)
            .map(|(c, _)| c.clone())
            .collect()
    }

    /// Get all register names in a group.
    pub fn registers_in_group(&self, group_name: &str) -> Vec<String> {
        self.definitions
            .values()
            .filter(|d| d.group == group_name)
            .map(|d| d.name.clone())
            .collect()
    }

    /// Get all group names.
    pub fn group_names(&self) -> Vec<String> {
        let mut names: BTreeSet<String> = self
            .definitions
            .values()
            .map(|d| d.group.clone())
            .collect();
        for g in &self.groups {
            names.insert(g.name.clone());
        }
        names.into_iter().collect()
    }

    /// Get all defined groups.
    pub fn groups(&self) -> &[RegisterGroup] {
        &self.groups
    }

    /// Add a register group.
    pub fn add_group(&mut self, group: RegisterGroup) {
        self.groups.push(group);
    }

    /// Get all known register names (those with values).
    pub fn known_registers(&self) -> Vec<String> {
        self.values.keys().cloned().collect()
    }

    /// The number of register definitions.
    pub fn num_definitions(&self) -> usize {
        self.definitions.len()
    }

    /// The number of registers with values.
    pub fn num_known(&self) -> usize {
        self.values.len()
    }

    /// Whether the bank is empty (no definitions).
    pub fn is_empty(&self) -> bool {
        self.definitions.is_empty()
    }

    /// Clear all values (but keep definitions).
    pub fn clear_values(&mut self) {
        self.values.clear();
    }

    /// Read the value of a sub-register (extract bytes from a parent).
    ///
    /// Given a child register that occupies `bit_offset` bits within
    /// its parent, extracts the corresponding bytes.
    pub fn read_sub_register(&self, child_name: &str) -> Option<Vec<u8>> {
        let parent_name = self.parent_of(child_name)?;
        let parent_value = self.values.get(parent_name)?;
        let child_def = self.definitions.get(child_name)?;

        let byte_start = (child_def.bit_offset / 8) as usize;
        let byte_len = ((child_def.bit_length + 7) / 8) as usize;

        if byte_start + byte_len > parent_value.len() {
            return None;
        }

        Some(parent_value[byte_start..byte_start + byte_len].to_vec())
    }

    /// Write the value of a sub-register (merge bytes into a parent).
    pub fn write_sub_register(&mut self, child_name: &str, value: &[u8]) -> Result<(), String> {
        let parent_name = self
            .parent_of(child_name)
            .ok_or_else(|| format!("no parent for {}", child_name))?
            .to_string();
        let child_def = self
            .definitions
            .get(child_name)
            .ok_or_else(|| format!("no definition for {}", child_name))?
            .clone();

        let byte_start = (child_def.bit_offset / 8) as usize;
        let byte_len = ((child_def.bit_length + 7) / 8) as usize;

        // Ensure parent value exists with sufficient length
        let parent = self
            .values
            .entry(parent_name)
            .or_insert_with(|| vec![0u8; byte_start + byte_len]);

        while parent.len() < byte_start + byte_len {
            parent.push(0);
        }

        for (i, &b) in value.iter().enumerate().take(byte_len) {
            parent[byte_start + i] = b;
        }

        Ok(())
    }
}

// ============================================================================
// RegisterDefinition
// ============================================================================

/// A register definition in a pcode debug session.
///
/// Describes a register's name, size, position within its parent,
/// display group, and type flags.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDefinition {
    /// The register name (e.g., "RAX", "XMM0").
    pub name: String,
    /// The bit length of the register.
    pub bit_length: u32,
    /// The bit offset within the parent register (0 for base registers).
    pub bit_offset: u32,
    /// The logical group this register belongs to.
    pub group: String,
    /// Type flags (processor-specific).
    pub type_flags: RegisterTypeFlags,
    /// Whether this is a big-endian register.
    pub big_endian: bool,
    /// Description string.
    pub description: String,
    /// Connector-specific name (if different from language name).
    pub connector_name: Option<String>,
}

impl Default for RegisterDefinition {
    fn default() -> Self {
        Self {
            name: String::new(),
            bit_length: 0,
            bit_offset: 0,
            group: String::new(),
            type_flags: RegisterTypeFlags::empty(),
            big_endian: false,
            description: String::new(),
            connector_name: None,
        }
    }
}

impl RegisterDefinition {
    /// Create a new register definition.
    pub fn new(
        name: impl Into<String>,
        bit_length: u32,
    ) -> Self {
        Self {
            name: name.into(),
            bit_length,
            ..Default::default()
        }
    }

    /// Set the bit offset within the parent register.
    pub fn with_bit_offset(mut self, offset: u32) -> Self {
        self.bit_offset = offset;
        self
    }

    /// Set the group.
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = group.into();
        self
    }

    /// Set type flags.
    pub fn with_type_flags(mut self, flags: RegisterTypeFlags) -> Self {
        self.type_flags = flags;
        self
    }

    /// Set big-endian flag.
    pub fn with_big_endian(mut self, big_endian: bool) -> Self {
        self.big_endian = big_endian;
        self
    }

    /// Set description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    /// Set the connector-specific name.
    pub fn with_connector_name(mut self, name: impl Into<String>) -> Self {
        self.connector_name = Some(name.into());
        self
    }

    /// Get the byte length of the register.
    pub fn byte_length(&self) -> u32 {
        (self.bit_length + 7) / 8
    }

    /// Whether this is a sub-register (has a parent).
    ///
    /// Returns true when the register has a non-zero bit offset within
    /// its parent, or when the `CHILD` flag is explicitly set.
    pub fn is_sub_register(&self) -> bool {
        self.bit_offset > 0 || self.type_flags.contains(RegisterTypeFlags::CHILD)
    }
}

// ============================================================================
// RegisterTypeFlags
// ============================================================================

bitflags::bitflags! {
    /// Type flags for register definitions.
    ///
    /// Ported from Ghidra's register type flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct RegisterTypeFlags: u32 {
        /// No special type.
        const NONE = 0;
        /// The register is a frame pointer.
        const FP = 1 << 0;
        /// The register is a stack pointer.
        const SP = 1 << 1;
        /// The register is the program counter.
        const PC = 1 << 2;
        /// The register is the processor context register.
        const CONTEXT = 1 << 3;
        /// The register is always zero.
        const ZERO = 1 << 4;
        /// The register should not be displayed to users.
        const HIDDEN = 1 << 5;
        /// The register value should not follow disassembly flow.
        const DOES_NOT_FOLLOW_FLOW = 1 << 6;
        /// The register supports SIMD operations.
        const VECTOR = 1 << 7;
        /// The register is a sub-register (child of a base register).
        const CHILD = 1 << 8;
        /// The register is an instruction pointer.
        const IP = Self::PC.bits();
    }
}

impl Serialize for RegisterTypeFlags {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.bits())
    }
}

impl<'de> Deserialize<'de> for RegisterTypeFlags {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bits = u32::deserialize(deserializer)?;
        RegisterTypeFlags::from_bits(bits)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid RegisterTypeFlags: {:#x}", bits)))
    }
}

// ============================================================================
// RegisterGroup
// ============================================================================

/// A logical grouping of registers for display.
///
/// Ported from Ghidra's register group concept.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterGroup {
    /// The group name (e.g., "General Purpose", "Floating Point", "Vector").
    pub name: String,
    /// Display order (lower values appear first).
    pub display_order: u32,
    /// Whether the group is expanded by default.
    pub expanded_by_default: bool,
    /// Registers belonging to this group.
    pub members: Vec<String>,
}

impl RegisterGroup {
    /// Create a new register group.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            display_order: 0,
            expanded_by_default: true,
            members: Vec::new(),
        }
    }

    /// Set display order.
    pub fn with_display_order(mut self, order: u32) -> Self {
        self.display_order = order;
        self
    }

    /// Set whether expanded by default.
    pub fn with_expanded_by_default(mut self, expanded: bool) -> Self {
        self.expanded_by_default = expanded;
        self
    }

    /// Add a member register name.
    pub fn add_member(&mut self, name: impl Into<String>) {
        self.members.push(name.into());
    }

    /// The number of members.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Whether the group is empty.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

// ============================================================================
// RegisterMapping -- language <-> connector register name mapping
// ============================================================================

/// Maps between language register names and connector register names.
///
/// Ported from Ghidra's register mapping utilities. Different debug
/// connectors (GDB, LLDB, etc.) may use different names for the same
/// register. This type provides bidirectional mapping.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterMapping {
    /// Language name -> connector name.
    lang_to_conn: BTreeMap<String, String>,
    /// Connector name -> language name.
    conn_to_lang: BTreeMap<String, String>,
}

impl RegisterMapping {
    /// Create a new empty mapping.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a mapping between language and connector names.
    pub fn insert(
        &mut self,
        lang_name: impl Into<String>,
        conn_name: impl Into<String>,
    ) {
        let lang = lang_name.into();
        let conn = conn_name.into();
        self.lang_to_conn.insert(lang.clone(), conn.clone());
        self.conn_to_lang.insert(conn, lang);
    }

    /// Get the connector name for a language register name.
    pub fn to_connector(&self, lang_name: &str) -> Option<&str> {
        self.lang_to_conn.get(lang_name).map(|s| s.as_str())
    }

    /// Get the language name for a connector register name.
    pub fn to_language(&self, conn_name: &str) -> Option<&str> {
        self.conn_to_lang.get(conn_name).map(|s| s.as_str())
    }

    /// Get the connector name, falling back to the language name itself.
    pub fn to_connector_or_self(&self, lang_name: &str) -> String {
        self.to_connector(lang_name)
            .unwrap_or(lang_name)
            .to_string()
    }

    /// Get the language name, falling back to the connector name itself.
    pub fn to_language_or_self(&self, conn_name: &str) -> String {
        self.to_language(conn_name)
            .unwrap_or(conn_name)
            .to_string()
    }

    /// The number of mappings.
    pub fn len(&self) -> usize {
        self.lang_to_conn.len()
    }

    /// Whether the mapping is empty.
    pub fn is_empty(&self) -> bool {
        self.lang_to_conn.is_empty()
    }
}

// ============================================================================
// RegisterValueTransformer -- value transformation helpers
// ============================================================================

/// Helper for transforming register values.
///
/// Ported from Ghidra's register value transformation utilities.
pub struct RegisterValueTransformer;

impl RegisterValueTransformer {
    /// Swap the byte order of a value (endianness conversion).
    pub fn swap_endian(bytes: &[u8]) -> Vec<u8> {
        bytes.iter().rev().cloned().collect()
    }

    /// Sign-extend a value from `from_bits` to `to_bits`.
    ///
    /// The input is assumed to be in little-endian byte order.
    pub fn sign_extend(bytes: &[u8], from_bits: u32, to_bits: u32) -> Vec<u8> {
        assert!(to_bits >= from_bits);
        let to_bytes = ((to_bits + 7) / 8) as usize;
        let from_bytes = ((from_bits + 7) / 8) as usize;

        let mut result = vec![0u8; to_bytes];

        // Copy existing bytes
        for i in 0..from_bytes.min(bytes.len()).min(to_bytes) {
            result[i] = bytes[i];
        }

        // Sign-extend
        if from_bits < to_bits && from_bytes > 0 {
            let sign_bit = (from_bits - 1) % 8;
            let sign_byte = bytes[from_bytes - 1];
            let sign = (sign_byte >> sign_bit) & 1;
            let fill = if sign == 1 { 0xFF } else { 0x00 };

            // Fill partial last byte
            let partial_bits = from_bits % 8;
            if partial_bits != 0 && from_bytes <= to_bytes {
                let mask = (1u8 << partial_bits) - 1;
                result[from_bytes - 1] =
                    (result[from_bytes - 1] & mask) | (fill & !mask);
            }

            // Fill remaining bytes
            for i in from_bytes..to_bytes {
                result[i] = fill;
            }
        }

        result
    }

    /// Zero-extend a value from `from_bits` to `to_bits`.
    pub fn zero_extend(bytes: &[u8], from_bits: u32, to_bits: u32) -> Vec<u8> {
        assert!(to_bits >= from_bits);
        let to_bytes = ((to_bits + 7) / 8) as usize;
        let from_bytes = ((from_bits + 7) / 8) as usize;

        let mut result = vec![0u8; to_bytes];
        for i in 0..from_bytes.min(bytes.len()) {
            result[i] = bytes[i];
        }
        result
    }

    /// Truncate a value to the given number of bits.
    pub fn truncate(bytes: &[u8], to_bits: u32) -> Vec<u8> {
        let to_bytes = ((to_bits + 7) / 8) as usize;
        let mut result: Vec<u8> = bytes.iter().take(to_bytes).cloned().collect();
        let partial_bits = to_bits % 8;
        if partial_bits != 0 && !result.is_empty() {
            let last = result.len() - 1;
            result[last] &= (1u8 << partial_bits) - 1;
        }
        result
    }

    /// Mask a register value to only include the bits at `bit_offset`
    /// with `bit_length` from the full parent value.
    pub fn extract_bits(bytes: &[u8], bit_offset: u32, bit_length: u32) -> Vec<u8> {
        let out_bytes = ((bit_length + 7) / 8) as usize;
        let mut result = vec![0u8; out_bytes];

        for i in 0..bit_length {
            let src_bit = bit_offset + i;
            let src_byte = (src_bit / 8) as usize;
            let src_idx = src_bit % 8;

            let dst_byte = (i / 8) as usize;
            let dst_idx = i % 8;

            if src_byte < bytes.len() && dst_byte < result.len() {
                let bit = (bytes[src_byte] >> src_idx) & 1;
                result[dst_byte] |= bit << dst_idx;
            }
        }

        result
    }

    /// Merge `overlay_bytes` into `base_bytes` at the given bit position.
    pub fn merge_bits(
        base: &mut [u8],
        overlay: &[u8],
        bit_offset: u32,
        bit_length: u32,
    ) {
        for i in 0..bit_length {
            let src_byte = (i / 8) as usize;
            let src_idx = i % 8;

            let dst_bit = bit_offset + i;
            let dst_byte = (dst_bit / 8) as usize;
            let dst_idx = dst_bit % 8;

            if src_byte < overlay.len() && dst_byte < base.len() {
                let bit = (overlay[src_byte] >> src_idx) & 1;
                if bit != 0 {
                    base[dst_byte] |= 1 << dst_idx;
                } else {
                    base[dst_byte] &= !(1 << dst_idx);
                }
            }
        }
    }

    /// Read a big-endian unsigned integer from a byte slice.
    pub fn read_u64_be(bytes: &[u8]) -> u64 {
        let mut val: u64 = 0;
        for &b in bytes.iter().take(8) {
            val = (val << 8) | b as u64;
        }
        val
    }

    /// Read a little-endian unsigned integer from a byte slice.
    pub fn read_u64_le(bytes: &[u8]) -> u64 {
        let mut val: u64 = 0;
        for (i, &b) in bytes.iter().take(8).enumerate() {
            val |= (b as u64) << (i * 8);
        }
        val
    }

    /// Write an unsigned integer as a little-endian byte vector of given size.
    pub fn write_u64_le(val: u64, byte_size: usize) -> Vec<u8> {
        (0..byte_size).map(|i| ((val >> (i * 8)) & 0xFF) as u8).collect()
    }

    /// Write an unsigned integer as a big-endian byte vector of given size.
    pub fn write_u64_be(val: u64, byte_size: usize) -> Vec<u8> {
        (0..byte_size)
            .rev()
            .map(|i| ((val >> (i * 8)) & 0xFF) as u8)
            .collect()
    }
}

// ============================================================================
// RegisterConvention -- calling convention
// ============================================================================

/// A register calling convention description.
///
/// Ported from Ghidra's calling convention register mapping. Describes
/// which registers are used for arguments, return values, and which
/// are callee-saved.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterConvention {
    /// The convention name (e.g., "System V AMD64 ABI").
    pub name: String,
    /// Registers used for integer arguments, in order.
    pub integer_arg_registers: Vec<String>,
    /// Registers used for floating-point arguments, in order.
    pub float_arg_registers: Vec<String>,
    /// Register(s) used for the return value.
    pub return_registers: Vec<String>,
    /// Callee-saved (non-volatile) registers.
    pub callee_saved: Vec<String>,
    /// Caller-saved (volatile) registers.
    pub caller_saved: Vec<String>,
    /// The stack pointer register name.
    pub stack_pointer: String,
    /// The frame pointer register name.
    pub frame_pointer: String,
    /// The link register name (if applicable, e.g., ARM).
    pub link_register: Option<String>,
}

impl RegisterConvention {
    /// Create a new calling convention with the given name.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Check if a register is callee-saved.
    pub fn is_callee_saved(&self, reg_name: &str) -> bool {
        self.callee_saved.iter().any(|r| r == reg_name)
    }

    /// Check if a register is caller-saved.
    pub fn is_caller_saved(&self, reg_name: &str) -> bool {
        self.caller_saved.iter().any(|r| r == reg_name)
    }

    /// Check if a register is used for argument passing.
    pub fn is_argument_register(&self, reg_name: &str) -> bool {
        self.integer_arg_registers.iter().any(|r| r == reg_name)
            || self.float_arg_registers.iter().any(|r| r == reg_name)
    }

    /// Check if a register is used for return values.
    pub fn is_return_register(&self, reg_name: &str) -> bool {
        self.return_registers.iter().any(|r| r == reg_name)
    }

    /// Build the System V AMD64 ABI convention.
    pub fn system_v_amd64() -> Self {
        Self {
            name: "System V AMD64 ABI".into(),
            integer_arg_registers: vec![
                "RDI".into(), "RSI".into(), "RDX".into(),
                "RCX".into(), "R8".into(), "R9".into(),
            ],
            float_arg_registers: vec![
                "XMM0".into(), "XMM1".into(), "XMM2".into(),
                "XMM3".into(), "XMM4".into(), "XMM5".into(),
                "XMM6".into(), "XMM7".into(),
            ],
            return_registers: vec!["RAX".into(), "RDX".into()],
            callee_saved: vec![
                "RBX".into(), "RBP".into(), "R12".into(),
                "R13".into(), "R14".into(), "R15".into(),
                "RSP".into(),
            ],
            caller_saved: vec![
                "RAX".into(), "RCX".into(), "RDX".into(),
                "RSI".into(), "RDI".into(), "R8".into(),
                "R9".into(), "R10".into(), "R11".into(),
            ],
            stack_pointer: "RSP".into(),
            frame_pointer: "RBP".into(),
            link_register: None,
        }
    }

    /// Build the Microsoft x64 calling convention.
    pub fn ms_x64() -> Self {
        Self {
            name: "Microsoft x64".into(),
            integer_arg_registers: vec![
                "RCX".into(), "RDX".into(), "R8".into(), "R9".into(),
            ],
            float_arg_registers: vec![
                "XMM0".into(), "XMM1".into(), "XMM2".into(), "XMM3".into(),
            ],
            return_registers: vec!["RAX".into()],
            callee_saved: vec![
                "RBX".into(), "RBP".into(), "RDI".into(),
                "RSI".into(), "R12".into(), "R13".into(),
                "R14".into(), "R15".into(), "RSP".into(),
            ],
            caller_saved: vec![
                "RAX".into(), "RCX".into(), "RDX".into(),
                "R8".into(), "R9".into(), "R10".into(), "R11".into(),
            ],
            stack_pointer: "RSP".into(),
            frame_pointer: "RBP".into(),
            link_register: None,
        }
    }

    /// Build the ARM AAPCS convention.
    pub fn arm_aapcs() -> Self {
        Self {
            name: "ARM AAPCS".into(),
            integer_arg_registers: vec![
                "R0".into(), "R1".into(), "R2".into(), "R3".into(),
            ],
            float_arg_registers: vec![
                "S0".into(), "S1".into(), "S2".into(), "S3".into(),
                "D0".into(), "D1".into(), "D2".into(), "D3".into(),
            ],
            return_registers: vec!["R0".into(), "R1".into()],
            callee_saved: vec![
                "R4".into(), "R5".into(), "R6".into(), "R7".into(),
                "R8".into(), "R10".into(), "R11".into(), "SP".into(),
            ],
            caller_saved: vec![
                "R0".into(), "R1".into(), "R2".into(), "R3".into(),
                "R12".into(), "LR".into(),
            ],
            stack_pointer: "SP".into(),
            frame_pointer: "R11".into(),
            link_register: Some("LR".into()),
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- PcodeRegisterBank --

    #[test]
    fn test_register_bank_basic() {
        let mut bank = PcodeRegisterBank::new();
        assert!(bank.is_empty());

        bank.define("RAX", 64, "General Purpose");
        bank.define("RBX", 64, "General Purpose");
        assert_eq!(bank.num_definitions(), 2);
        assert!(bank.register_names().contains(&"RAX"));
    }

    #[test]
    fn test_register_bank_read_write() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "General Purpose");
        bank.write_register("RAX", &[0x78, 0x56, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE]);

        let val = bank.read_register("RAX");
        assert_eq!(val, Some(vec![0x78, 0x56, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE]));
        assert_eq!(bank.num_known(), 1);
    }

    #[test]
    fn test_register_bank_alias() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "General Purpose");
        bank.add_alias("EAX", "RAX");

        bank.write_register("EAX", &[0x78, 0x56, 0x34, 0x12]);
        let val = bank.read_register("RAX");
        assert_eq!(val, Some(vec![0x78, 0x56, 0x34, 0x12]));
    }

    #[test]
    fn test_register_bank_parent_child() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "General Purpose");
        bank.define("EAX", 32, "General Purpose");

        bank.set_parent("EAX", "RAX");
        assert_eq!(bank.parent_of("EAX"), Some("RAX"));
        assert_eq!(bank.children_of("RAX"), vec!["EAX"]);
    }

    #[test]
    fn test_register_bank_sub_register_read() {
        let mut bank = PcodeRegisterBank::new();
        bank.define_register(RegisterDefinition::new("RAX", 64).with_group("GPR"));
        bank.define_register(
            RegisterDefinition::new("EAX", 32)
                .with_bit_offset(0)
                .with_group("GPR"),
        );
        bank.set_parent("EAX", "RAX");
        bank.write_register("RAX", &[0x78, 0x56, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE]);

        let eax = bank.read_sub_register("EAX");
        assert_eq!(eax, Some(vec![0x78, 0x56, 0x34, 0x12]));
    }

    #[test]
    fn test_register_bank_sub_register_write() {
        let mut bank = PcodeRegisterBank::new();
        bank.define_register(RegisterDefinition::new("RAX", 64).with_group("GPR"));
        bank.define_register(
            RegisterDefinition::new("EAX", 32)
                .with_bit_offset(0)
                .with_group("GPR"),
        );
        bank.set_parent("EAX", "RAX");

        // Pre-initialize RAX to 8 bytes so the upper bytes are preserved
        bank.write_register("RAX", &[0x00, 0x00, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44]);

        bank.write_sub_register("EAX", &[0xFF, 0xEE, 0xDD, 0xCC]).unwrap();
        let rax = bank.read_register("RAX").unwrap();
        assert_eq!(&rax[..4], &[0xFF, 0xEE, 0xDD, 0xCC]);
        assert_eq!(&rax[4..], &[0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn test_register_bank_groups() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "General Purpose");
        bank.define("RBX", 64, "General Purpose");
        bank.define("XMM0", 128, "Vector");

        let gpr = bank.registers_in_group("General Purpose");
        assert_eq!(gpr.len(), 2);
        assert!(gpr.contains(&"RAX".to_string()));
        assert!(gpr.contains(&"RBX".to_string()));

        let groups = bank.group_names();
        assert!(groups.contains(&"General Purpose".to_string()));
        assert!(groups.contains(&"Vector".to_string()));
    }

    #[test]
    fn test_register_bank_clear_values() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.write_register("RAX", &[1, 2, 3, 4, 5, 6, 7, 8]);

        bank.clear_values();
        assert_eq!(bank.num_known(), 0);
        assert_eq!(bank.num_definitions(), 1);
        assert!(bank.read_register("RAX").is_none());
    }

    // -- RegisterDefinition --

    #[test]
    fn test_register_definition_builder() {
        let def = RegisterDefinition::new("XMM0", 128)
            .with_group("Vector")
            .with_big_endian(false)
            .with_type_flags(RegisterTypeFlags::VECTOR)
            .with_description("128-bit SIMD register")
            .with_connector_name("xmm0");

        assert_eq!(def.name, "XMM0");
        assert_eq!(def.bit_length, 128);
        assert_eq!(def.byte_length(), 16);
        assert!(def.type_flags.contains(RegisterTypeFlags::VECTOR));
        assert_eq!(def.connector_name, Some("xmm0".to_string()));
    }

    #[test]
    fn test_register_definition_sub_register() {
        // EAX is the low 32 bits of RAX; marking it as CHILD
        let def = RegisterDefinition::new("EAX", 32)
            .with_bit_offset(0)
            .with_type_flags(RegisterTypeFlags::CHILD);
        assert!(def.is_sub_register());

        // AH is at bit offset 8 within RAX
        let ah = RegisterDefinition::new("AH", 8)
            .with_bit_offset(8);
        assert!(ah.is_sub_register());

        // A base register (RAX) is not a sub-register
        let base = RegisterDefinition::new("RAX", 64);
        assert!(!base.is_sub_register());
    }

    // -- RegisterTypeFlags --

    #[test]
    fn test_register_type_flags() {
        let flags = RegisterTypeFlags::PC | RegisterTypeFlags::CONTEXT;
        assert!(flags.contains(RegisterTypeFlags::PC));
        assert!(flags.contains(RegisterTypeFlags::CONTEXT));
        assert!(!flags.contains(RegisterTypeFlags::FP));
    }

    // -- RegisterGroup --

    #[test]
    fn test_register_group() {
        let mut group = RegisterGroup::new("General Purpose")
            .with_display_order(0)
            .with_expanded_by_default(true);
        group.add_member("RAX");
        group.add_member("RBX");

        assert_eq!(group.len(), 2);
        assert!(!group.is_empty());
    }

    // -- RegisterMapping --

    #[test]
    fn test_register_mapping() {
        let mut mapping = RegisterMapping::new();
        mapping.insert("RAX", "rax");
        mapping.insert("EFLAGS", "eflags");

        assert_eq!(mapping.to_connector("RAX"), Some("rax"));
        assert_eq!(mapping.to_language("rax"), Some("RAX"));
        assert_eq!(mapping.to_connector("MISSING"), None);
        assert_eq!(mapping.to_connector_or_self("RAX"), "rax");
        assert_eq!(mapping.to_connector_or_self("RBX"), "RBX");
        assert_eq!(mapping.to_language_or_self("rax"), "RAX");
        assert_eq!(mapping.to_language_or_self("unknown"), "unknown");
    }

    // -- RegisterValueTransformer --

    #[test]
    fn test_swap_endian() {
        let val = vec![0x01, 0x02, 0x03, 0x04];
        let swapped = RegisterValueTransformer::swap_endian(&val);
        assert_eq!(swapped, vec![0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_sign_extend_positive() {
        // 0x01 as 8-bit -> 16-bit should be 0x0001
        let result = RegisterValueTransformer::sign_extend(&[0x01], 8, 16);
        assert_eq!(result, vec![0x01, 0x00]);
    }

    #[test]
    fn test_sign_extend_negative() {
        // 0xFF as 8-bit (-1) -> 16-bit should be 0xFFFF
        let result = RegisterValueTransformer::sign_extend(&[0xFF], 8, 16);
        assert_eq!(result, vec![0xFF, 0xFF]);
    }

    #[test]
    fn test_sign_extend_12bit() {
        // 0x800 as 12-bit (negative) -> 16-bit should be 0xF800
        // 12 bits: 0x800 = 0b1000_0000_0000, sign bit is bit 11
        let result = RegisterValueTransformer::sign_extend(&[0x00, 0x08], 12, 16);
        assert_eq!(result, vec![0x00, 0xF8]);
    }

    #[test]
    fn test_zero_extend() {
        let result = RegisterValueTransformer::zero_extend(&[0xFF], 8, 32);
        assert_eq!(result, vec![0xFF, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_truncate() {
        let result = RegisterValueTransformer::truncate(&[0xFF, 0xFF, 0xFF, 0xFF], 12);
        assert_eq!(result, vec![0xFF, 0x0F]);
    }

    #[test]
    fn test_extract_bits() {
        // Extract bits 8..16 from [0xAA, 0xBB, 0xCC]
        let result = RegisterValueTransformer::extract_bits(&[0xAA, 0xBB, 0xCC], 8, 8);
        assert_eq!(result, vec![0xBB]);
    }

    #[test]
    fn test_merge_bits() {
        let mut base = vec![0x00, 0x00, 0x00, 0x00];
        let overlay = vec![0xFF, 0xFF];
        RegisterValueTransformer::merge_bits(&mut base, &overlay, 8, 16);
        // bits 8..24 should be set
        assert_eq!(base, vec![0x00, 0xFF, 0xFF, 0x00]);
    }

    #[test]
    fn test_read_write_u64_le() {
        let val: u64 = 0xDEADBEEFCAFEBABE;
        let bytes = RegisterValueTransformer::write_u64_le(val, 8);
        let back = RegisterValueTransformer::read_u64_le(&bytes);
        assert_eq!(back, val);
    }

    #[test]
    fn test_read_write_u64_be() {
        let val: u64 = 0xDEADBEEFCAFEBABE;
        let bytes = RegisterValueTransformer::write_u64_be(val, 8);
        let back = RegisterValueTransformer::read_u64_be(&bytes);
        assert_eq!(back, val);
    }

    #[test]
    fn test_read_u64_le_partial() {
        let val = RegisterValueTransformer::read_u64_le(&[0x78, 0x56, 0x34, 0x12]);
        assert_eq!(val, 0x12345678);
    }

    #[test]
    fn test_write_u64_le_4byte() {
        let bytes = RegisterValueTransformer::write_u64_le(0x12345678, 4);
        assert_eq!(bytes, vec![0x78, 0x56, 0x34, 0x12]);
    }

    // -- RegisterConvention --

    #[test]
    fn test_convention_system_v_amd64() {
        let conv = RegisterConvention::system_v_amd64();
        assert_eq!(conv.name, "System V AMD64 ABI");
        assert!(conv.is_argument_register("RDI"));
        assert!(conv.is_argument_register("XMM0"));
        assert!(!conv.is_argument_register("RBX"));
        assert!(conv.is_callee_saved("RBX"));
        assert!(!conv.is_callee_saved("RAX"));
        assert!(conv.is_return_register("RAX"));
        assert_eq!(conv.stack_pointer, "RSP");
        assert!(conv.link_register.is_none());
    }

    #[test]
    fn test_convention_ms_x64() {
        let conv = RegisterConvention::ms_x64();
        assert!(conv.is_argument_register("RCX"));
        assert!(!conv.is_argument_register("RDI"));
        assert!(conv.is_return_register("RAX"));
    }

    #[test]
    fn test_convention_arm_aapcs() {
        let conv = RegisterConvention::arm_aapcs();
        assert!(conv.is_argument_register("R0"));
        assert!(conv.is_callee_saved("R4"));
        assert!(conv.link_register.is_some());
        assert_eq!(conv.link_register.unwrap(), "LR");
        assert_eq!(conv.frame_pointer, "R11");
    }

    #[test]
    fn test_convention_caller_saved() {
        let conv = RegisterConvention::system_v_amd64();
        assert!(conv.is_caller_saved("RAX"));
        assert!(conv.is_caller_saved("RCX"));
        assert!(!conv.is_caller_saved("RBX"));
    }
}
