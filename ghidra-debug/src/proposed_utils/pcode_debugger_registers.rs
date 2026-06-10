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
// RegisterSnapshot -- full register state at a point in time
// ============================================================================

/// A snapshot of all register values at a specific point in time.
///
/// Ported from Ghidra's proposed register snapshot utilities. Captures
/// the full state of a register bank so it can be compared, restored,
/// or serialized for later analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSnapshot {
    /// Human-readable label (e.g., "before syscall", "at breakpoint 3").
    pub label: String,
    /// Timestamp or snap value when the snapshot was taken.
    pub snap: i64,
    /// Register name -> value bytes.
    pub values: BTreeMap<String, Vec<u8>>,
    /// Register name -> state.
    pub states: BTreeMap<String, RegisterSnapshotState>,
}

/// The state of a register within a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegisterSnapshotState {
    /// Register has a known value.
    Known,
    /// Register value was unknown at snapshot time.
    Unknown,
    /// Register value was not requested (not included in snapshot).
    Omitted,
}

impl RegisterSnapshot {
    /// Create a new empty snapshot.
    pub fn new(label: impl Into<String>, snap: i64) -> Self {
        Self {
            label: label.into(),
            snap,
            values: BTreeMap::new(),
            states: BTreeMap::new(),
        }
    }

    /// Capture a snapshot from a register bank.
    pub fn capture_from_bank(label: impl Into<String>, snap: i64, bank: &PcodeRegisterBank) -> Self {
        let mut snapshot = Self::new(label, snap);
        for name in bank.register_names() {
            if let Some(val) = bank.read_register(name) {
                snapshot.values.insert(name.to_string(), val);
                snapshot.states.insert(name.to_string(), RegisterSnapshotState::Known);
            }
        }
        snapshot
    }

    /// Record a register value in the snapshot.
    pub fn record(&mut self, name: impl Into<String>, value: Vec<u8>) {
        let name = name.into();
        self.values.insert(name.clone(), value);
        self.states.insert(name, RegisterSnapshotState::Known);
    }

    /// Mark a register as unknown in the snapshot.
    pub fn record_unknown(&mut self, name: impl Into<String>) {
        let name = name.into();
        self.states.insert(name, RegisterSnapshotState::Unknown);
    }

    /// Get a register value from the snapshot.
    pub fn get(&self, name: &str) -> Option<&Vec<u8>> {
        self.values.get(name)
    }

    /// Get the state of a register in the snapshot.
    pub fn get_state(&self, name: &str) -> RegisterSnapshotState {
        self.states.get(name).copied().unwrap_or(RegisterSnapshotState::Omitted)
    }

    /// All register names included in this snapshot.
    pub fn register_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.states.keys().map(|s| s.as_str()).collect();
        names.sort();
        names
    }

    /// The number of registers with known values.
    pub fn num_known(&self) -> usize {
        self.values.len()
    }
}

// ============================================================================
// RegisterBankDiff -- compare two snapshots
// ============================================================================

/// The result of comparing two register snapshots.
///
/// Ported from Ghidra's register comparison utilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterBankDiff {
    /// Registers that changed value between the two snapshots.
    pub changed: Vec<RegisterChange>,
    /// Registers that were present in `after` but not in `before`.
    pub appeared: Vec<String>,
    /// Registers that were present in `before` but not in `after`.
    pub disappeared: Vec<String>,
}

/// A single register change between two snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterChange {
    /// The register name.
    pub name: String,
    /// The value in the "before" snapshot.
    pub before: Vec<u8>,
    /// The value in the "after" snapshot.
    pub after: Vec<u8>,
}

impl RegisterBankDiff {
    /// Compute the diff between two snapshots.
    pub fn compute(before: &RegisterSnapshot, after: &RegisterSnapshot) -> Self {
        let mut changed = Vec::new();
        let mut appeared = Vec::new();
        let mut disappeared = Vec::new();

        // Find changed and disappeared registers
        for name in before.register_names() {
            let bstate = before.get_state(name);
            let astate = after.get_state(name);

            if astate == RegisterSnapshotState::Omitted {
                disappeared.push(name.to_string());
                continue;
            }

            if bstate == RegisterSnapshotState::Unknown && astate == RegisterSnapshotState::Known {
                // Register became known -- treat as change
                if let Some(val) = after.get(name) {
                    changed.push(RegisterChange {
                        name: name.to_string(),
                        before: Vec::new(),
                        after: val.clone(),
                    });
                }
                continue;
            }

            if let (Some(bval), Some(aval)) = (before.get(name), after.get(name)) {
                if bval != aval {
                    changed.push(RegisterChange {
                        name: name.to_string(),
                        before: bval.clone(),
                        after: aval.clone(),
                    });
                }
            }
        }

        // Find appeared registers
        for name in after.register_names() {
            if before.get_state(name) == RegisterSnapshotState::Omitted {
                appeared.push(name.to_string());
            }
        }

        Self {
            changed,
            appeared,
            disappeared,
        }
    }

    /// Whether there are any differences.
    pub fn is_empty(&self) -> bool {
        self.changed.is_empty() && self.appeared.is_empty() && self.disappeared.is_empty()
    }

    /// The total number of differences.
    pub fn num_changes(&self) -> usize {
        self.changed.len() + self.appeared.len() + self.disappeared.len()
    }
}

// ============================================================================
// RegisterWatchpoint -- watch for register value changes
// ============================================================================

/// A watchpoint that triggers when a register's value changes.
///
/// Ported from Ghidra's proposed register watchpoint utilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterWatchpoint {
    /// Unique watchpoint ID.
    pub id: u64,
    /// The register name to watch.
    pub register_name: String,
    /// Optional condition: if set, only triggers if the new value matches.
    pub condition_value: Option<Vec<u8>>,
    /// Whether the watchpoint is enabled.
    pub enabled: bool,
    /// How many times this watchpoint has fired.
    pub hit_count: u64,
    /// Optional user note.
    pub note: String,
}

impl RegisterWatchpoint {
    /// Create a new register watchpoint.
    pub fn new(id: u64, register_name: impl Into<String>) -> Self {
        Self {
            id,
            register_name: register_name.into(),
            condition_value: None,
            enabled: true,
            hit_count: 0,
            note: String::new(),
        }
    }

    /// Set a condition value.
    pub fn with_condition(mut self, value: Vec<u8>) -> Self {
        self.condition_value = Some(value);
        self
    }

    /// Set a note.
    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = note.into();
        self
    }

    /// Check whether this watchpoint should fire given a new value.
    pub fn should_fire(&self, new_value: &[u8]) -> bool {
        if !self.enabled {
            return false;
        }
        match &self.condition_value {
            Some(cond) => cond.as_slice() == new_value,
            None => true, // Any change fires
        }
    }
}

/// A manager for register watchpoints.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterWatchpointManager {
    watchpoints: BTreeMap<u64, RegisterWatchpoint>,
    next_id: u64,
}

impl RegisterWatchpointManager {
    /// Create a new empty manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a watchpoint for a register.
    pub fn add_watchpoint(&mut self, register_name: impl Into<String>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.watchpoints
            .insert(id, RegisterWatchpoint::new(id, register_name));
        id
    }

    /// Remove a watchpoint.
    pub fn remove_watchpoint(&mut self, id: u64) -> Option<RegisterWatchpoint> {
        self.watchpoints.remove(&id)
    }

    /// Enable or disable a watchpoint.
    pub fn set_enabled(&mut self, id: u64, enabled: bool) {
        if let Some(wp) = self.watchpoints.get_mut(&id) {
            wp.enabled = enabled;
        }
    }

    /// Check all enabled watchpoints against a register name and new value.
    /// Returns the IDs of watchpoints that fired.
    pub fn check(&mut self, register_name: &str, new_value: &[u8]) -> Vec<u64> {
        let mut hits = Vec::new();
        for wp in self.watchpoints.values_mut() {
            if wp.register_name == register_name && wp.should_fire(new_value) {
                wp.hit_count += 1;
                hits.push(wp.id);
            }
        }
        hits
    }

    /// Get a watchpoint by ID.
    pub fn get(&self, id: u64) -> Option<&RegisterWatchpoint> {
        self.watchpoints.get(&id)
    }

    /// Get all watchpoints.
    pub fn all(&self) -> &BTreeMap<u64, RegisterWatchpoint> {
        &self.watchpoints
    }

    /// The number of watchpoints.
    pub fn len(&self) -> usize {
        self.watchpoints.len()
    }

    /// Whether there are no watchpoints.
    pub fn is_empty(&self) -> bool {
        self.watchpoints.is_empty()
    }

    /// Clear all watchpoints.
    pub fn clear(&mut self) {
        self.watchpoints.clear();
    }
}

// ============================================================================
// CallingConventionMapper -- translate register names between conventions
// ============================================================================

/// Translates register arguments between two calling conventions.
///
/// Ported from Ghidra's proposed calling convention mapping utilities.
/// Useful for cross-ABI debugging where the caller uses one convention
/// and the callee uses another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallingConventionMapper {
    /// The source convention (caller's convention).
    pub source: RegisterConvention,
    /// The target convention (callee's convention).
    pub target: RegisterConvention,
}

impl CallingConventionMapper {
    /// Create a new mapper.
    pub fn new(source: RegisterConvention, target: RegisterConvention) -> Self {
        Self { source, target }
    }

    /// Map integer argument registers from source to target.
    ///
    /// Returns a list of (source_register, target_register) pairs for
    /// the overlapping number of argument slots.
    pub fn map_integer_args(&self) -> Vec<(&str, &str)> {
        self.source
            .integer_arg_registers
            .iter()
            .zip(self.target.integer_arg_registers.iter())
            .map(|(s, t)| (s.as_str(), t.as_str()))
            .collect()
    }

    /// Map float argument registers from source to target.
    pub fn map_float_args(&self) -> Vec<(&str, &str)> {
        self.source
            .float_arg_registers
            .iter()
            .zip(self.target.float_arg_registers.iter())
            .map(|(s, t)| (s.as_str(), t.as_str()))
            .collect()
    }

    /// The number of integer argument slots that can be mapped.
    pub fn num_integer_arg_slots(&self) -> usize {
        self.source
            .integer_arg_registers
            .len()
            .min(self.target.integer_arg_registers.len())
    }

    /// The number of float argument slots that can be mapped.
    pub fn num_float_arg_slots(&self) -> usize {
        self.source
            .float_arg_registers
            .len()
            .min(self.target.float_arg_registers.len())
    }

    /// Whether the two conventions use the same stack pointer.
    pub fn same_stack_pointer(&self) -> bool {
        self.source.stack_pointer == self.target.stack_pointer
    }

    /// Whether the two conventions use the same frame pointer.
    pub fn same_frame_pointer(&self) -> bool {
        self.source.frame_pointer == self.target.frame_pointer
    }
}

// ============================================================================
// RegisterAliasChain -- resolve chains of register aliases
// ============================================================================

/// Resolves chains of register aliases to find the ultimate canonical name.
///
/// Ported from Ghidra's proposed alias resolution utilities. Some registers
/// have multi-level aliasing (e.g., AL -> AX -> EAX -> RAX).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterAliasChain {
    /// child -> parent mapping (same as RegisterMapping but for aliases).
    aliases: BTreeMap<String, String>,
}

impl RegisterAliasChain {
    /// Create a new empty alias chain.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an alias mapping.
    pub fn add_alias(&mut self, alias: impl Into<String>, canonical: impl Into<String>) {
        self.aliases.insert(alias.into(), canonical.into());
    }

    /// Resolve a register name to its ultimate canonical name by following
    /// the alias chain.
    pub fn resolve(&self, name: &str) -> String {
        let mut current = name.to_string();
        let mut seen = std::collections::HashSet::new();
        seen.insert(current.clone());
        while let Some(next) = self.aliases.get(&current) {
            if !seen.insert(next.clone()) {
                // Cycle detected -- break
                break;
            }
            current = next.clone();
        }
        current
    }

    /// Get the full alias chain from a name to its canonical form.
    pub fn chain(&self, name: &str) -> Vec<String> {
        let mut result = vec![name.to_string()];
        let mut current = name.to_string();
        let mut seen = std::collections::HashSet::new();
        seen.insert(current.clone());
        while let Some(next) = self.aliases.get(&current) {
            if !seen.insert(next.clone()) {
                break;
            }
            result.push(next.clone());
            current = next.clone();
        }
        result
    }

    /// Check if two names resolve to the same canonical register.
    pub fn is_same_register(&self, a: &str, b: &str) -> bool {
        self.resolve(a) == self.resolve(b)
    }

    /// The number of alias entries.
    pub fn len(&self) -> usize {
        self.aliases.len()
    }

    /// Whether there are no aliases.
    pub fn is_empty(&self) -> bool {
        self.aliases.is_empty()
    }
}

// ============================================================================
// RegisterFileLayout -- physical layout of registers within a file
// ============================================================================

/// Describes the physical layout of a register file, mapping register names
/// to their position and size within a contiguous byte buffer.
///
/// Ported from Ghidra's register file layout concept used in trace-based
/// register storage. Each register occupies a fixed slice within a flat
/// byte array indexed by (space_name, offset).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterFileLayout {
    /// The address space name for this register file (typically "register").
    pub space_name: String,
    /// Register name -> (offset, size) within the register file.
    entries: BTreeMap<String, RegisterLayoutEntry>,
}

/// A single register's position within the register file.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RegisterLayoutEntry {
    /// Byte offset within the register file.
    pub offset: u64,
    /// Size in bytes.
    pub size: u32,
}

impl RegisterFileLayout {
    /// Create a new empty register file layout.
    pub fn new(space_name: impl Into<String>) -> Self {
        Self {
            space_name: space_name.into(),
            entries: BTreeMap::new(),
        }
    }

    /// Add a register entry.
    pub fn add_register(&mut self, name: impl Into<String>, offset: u64, size: u32) {
        self.entries.insert(
            name.into(),
            RegisterLayoutEntry { offset, size },
        );
    }

    /// Get the layout entry for a register.
    pub fn get_entry(&self, name: &str) -> Option<&RegisterLayoutEntry> {
        self.entries.get(name)
    }

    /// Get the byte range (offset, offset+size) for a register.
    pub fn byte_range(&self, name: &str) -> Option<(u64, u64)> {
        self.entries
            .get(name)
            .map(|e| (e.offset, e.offset + e.size as u64))
    }

    /// Extract a register value from a flat byte buffer.
    pub fn extract_value(&self, name: &str, buffer: &[u8]) -> Option<Vec<u8>> {
        let entry = self.entries.get(name)?;
        let start = entry.offset as usize;
        let end = start + entry.size as usize;
        if end > buffer.len() {
            return None;
        }
        Some(buffer[start..end].to_vec())
    }

    /// Write a register value into a flat byte buffer.
    pub fn inject_value(
        &self,
        name: &str,
        buffer: &mut [u8],
        value: &[u8],
    ) -> Result<(), String> {
        let entry = self
            .entries
            .get(name)
            .ok_or_else(|| format!("register '{}' not in layout", name))?;
        let start = entry.offset as usize;
        let end = start + entry.size as usize;
        if end > buffer.len() {
            return Err(format!(
                "buffer too small: need {} bytes, have {}",
                end,
                buffer.len()
            ));
        }
        let copy_len = value.len().min(entry.size as usize);
        buffer[start..start + copy_len].copy_from_slice(&value[..copy_len]);
        Ok(())
    }

    /// All register names in this layout.
    pub fn register_names(&self) -> Vec<&str> {
        self.entries.keys().map(|s| s.as_str()).collect()
    }

    /// The number of registers.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the layout is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The total byte size of the register file (max offset + size).
    pub fn total_size(&self) -> u64 {
        self.entries
            .values()
            .map(|e| e.offset + e.size as u64)
            .max()
            .unwrap_or(0)
    }
}

// ============================================================================
// RegisterValueSource -- track where a register value originated
// ============================================================================

/// Describes the source of a register value.
///
/// Ported from Ghidra's value-source tracking in emulation and debugging.
/// When a register is read from a debug target, the source indicates how
/// the value was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegisterValueSource {
    /// Value was read from the live target.
    Target,
    /// Value was read from the trace database.
    Trace,
    /// Value was read from a static image (program database).
    StaticImage,
    /// Value was set by the user or a script.
    User,
    /// Value was computed by the emulator.
    Emulated,
    /// Value was loaded from a core dump.
    CoreDump,
    /// Source is unknown.
    Unknown,
}

/// A register value paired with its source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourcedRegisterValue {
    /// The register name.
    pub name: String,
    /// The value bytes.
    pub value: Vec<u8>,
    /// Where the value came from.
    pub source: RegisterValueSource,
    /// The snap at which the value was obtained.
    pub snap: i64,
}

impl SourcedRegisterValue {
    /// Create a new sourced value.
    pub fn new(
        name: impl Into<String>,
        value: Vec<u8>,
        source: RegisterValueSource,
        snap: i64,
    ) -> Self {
        Self {
            name: name.into(),
            value,
            source,
            snap,
        }
    }

    /// Whether this value came from the live target.
    pub fn is_live(&self) -> bool {
        self.source == RegisterValueSource::Target
    }
}

// ============================================================================
// RegisterBankOverlay -- apply partial updates to a bank
// ============================================================================

/// An overlay of register values that can be applied on top of a base bank.
///
/// Ported from Ghidra's register overlay concept used when the emulated
/// state differs from the trace state. Only registers present in the
/// overlay are affected; base values for other registers are preserved.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterBankOverlay {
    /// Register name -> overlay value (None means "use base").
    overrides: BTreeMap<String, Option<Vec<u8>>>,
    /// Registers explicitly cleared (marked unknown) by the overlay.
    cleared: BTreeSet<String>,
}

impl RegisterBankOverlay {
    /// Create a new empty overlay.
    pub fn new() -> Self {
        Self::default()
    }

    /// Override a register value in the overlay.
    pub fn set(&mut self, name: impl Into<String>, value: Vec<u8>) {
        let name = name.into();
        self.cleared.remove(&name);
        self.overrides.insert(name, Some(value));
    }

    /// Mark a register as explicitly unknown in the overlay.
    pub fn clear(&mut self, name: impl Into<String>) {
        let name = name.into();
        self.overrides.remove(&name);
        self.cleared.insert(name);
    }

    /// Remove a register from the overlay (revert to base).
    pub fn remove_override(&mut self, name: &str) {
        self.overrides.remove(name);
        self.cleared.remove(name);
    }

    /// Check if the overlay has an entry for the given register.
    pub fn has_override(&self, name: &str) -> bool {
        self.overrides.contains_key(name) || self.cleared.contains(name)
    }

    /// Get the overridden value for a register, if any.
    pub fn get_override(&self, name: &str) -> Option<Option<&Vec<u8>>> {
        if self.cleared.contains(name) {
            return Some(None); // Explicitly cleared
        }
        self.overrides.get(name).map(|v| v.as_ref())
    }

    /// Read a register, checking the overlay first, then falling back to the base bank.
    pub fn read(&self, name: &str, base: &PcodeRegisterBank) -> Option<Vec<u8>> {
        if self.cleared.contains(name) {
            return None;
        }
        if let Some(Some(val)) = self.overrides.get(name) {
            return Some(val.clone());
        }
        base.read_register(name)
    }

    /// Apply all overlay changes into a bank.
    pub fn apply_to(&self, bank: &mut PcodeRegisterBank) {
        for (name, value) in &self.overrides {
            if let Some(val) = value {
                bank.write_register(name, val);
            }
        }
        for name in &self.cleared {
            bank.values.remove(name);
        }
    }

    /// The number of overridden registers.
    pub fn len(&self) -> usize {
        self.overrides.len() + self.cleared.len()
    }

    /// Whether the overlay is empty (no overrides).
    pub fn is_empty(&self) -> bool {
        self.overrides.is_empty() && self.cleared.is_empty()
    }

    /// All register names that have overrides.
    pub fn overridden_names(&self) -> Vec<&str> {
        self.overrides
            .keys()
            .chain(self.cleared.iter())
            .map(|s| s.as_str())
            .collect()
    }
}

// ============================================================================
// RegisterTracer -- record register read/write history
// ============================================================================

/// An entry in the register trace log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterTraceEntry {
    /// The register name.
    pub name: String,
    /// Whether this was a read or write.
    pub access: RegisterAccessKind,
    /// The value (for writes, this is the value written; for reads, the value read).
    pub value: Option<Vec<u8>>,
    /// Monotonic sequence number.
    pub seq: u64,
    /// The snap at which this occurred.
    pub snap: i64,
}

/// Kind of register access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegisterAccessKind {
    /// A register read.
    Read,
    /// A register write.
    Write,
}

/// Records a history of register reads and writes.
///
/// Ported from Ghidra's register tracing facilities used for debugging
/// emulation and recording register access patterns.
#[derive(Debug, Clone, Default)]
pub struct RegisterTracer {
    entries: Vec<RegisterTraceEntry>,
    next_seq: u64,
    /// Maximum number of entries to keep (0 = unlimited).
    max_entries: usize,
}

impl RegisterTracer {
    /// Create a new register tracer.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum number of trace entries. Old entries are evicted FIFO.
    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = max;
        self
    }

    /// Record a register read.
    pub fn record_read(&mut self, name: &str, value: &[u8], snap: i64) {
        self.push_entry(RegisterTraceEntry {
            name: name.to_string(),
            access: RegisterAccessKind::Read,
            value: Some(value.to_vec()),
            seq: self.next_seq,
            snap,
        });
        self.next_seq += 1;
    }

    /// Record a register write.
    pub fn record_write(&mut self, name: &str, value: &[u8], snap: i64) {
        self.push_entry(RegisterTraceEntry {
            name: name.to_string(),
            access: RegisterAccessKind::Write,
            value: Some(value.to_vec()),
            seq: self.next_seq,
            snap,
        });
        self.next_seq += 1;
    }

    fn push_entry(&mut self, entry: RegisterTraceEntry) {
        if self.max_entries > 0 && self.entries.len() >= self.max_entries {
            self.entries.remove(0);
        }
        self.entries.push(entry);
    }

    /// Get all trace entries.
    pub fn entries(&self) -> &[RegisterTraceEntry] {
        &self.entries
    }

    /// Get entries for a specific register.
    pub fn entries_for(&self, name: &str) -> Vec<&RegisterTraceEntry> {
        self.entries
            .iter()
            .filter(|e| e.name == name)
            .collect()
    }

    /// Get entries of a specific kind.
    pub fn entries_of_kind(&self, kind: RegisterAccessKind) -> Vec<&RegisterTraceEntry> {
        self.entries.iter().filter(|e| e.access == kind).collect()
    }

    /// The number of recorded entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no entries have been recorded.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.next_seq = 0;
    }

    /// The last (most recent) entry.
    pub fn last(&self) -> Option<&RegisterTraceEntry> {
        self.entries.last()
    }
}

// ============================================================================
// RegisterBankFork -- snapshot and fork register state
// ============================================================================

/// A forkable register bank that supports snapshot-and-restore semantics.
///
/// Ported from Ghidra's register state forking used in emulation where
/// speculative execution needs to save and restore register state.
#[derive(Debug, Clone)]
pub struct RegisterBankFork {
    /// The current (working) state.
    current: PcodeRegisterBank,
    /// Stack of saved snapshots.
    saved_stack: Vec<PcodeRegisterBank>,
}

impl RegisterBankFork {
    /// Create a new forkable bank.
    pub fn new(bank: PcodeRegisterBank) -> Self {
        Self {
            current: bank,
            saved_stack: Vec::new(),
        }
    }

    /// Save the current state and begin modifying.
    pub fn fork(&mut self) {
        self.saved_stack.push(self.current.clone());
    }

    /// Discard the current state and restore the most recently saved snapshot.
    pub fn restore(&mut self) -> Result<(), String> {
        self.current = self
            .saved_stack
            .pop()
            .ok_or_else(|| "no saved state to restore".to_string())?;
        Ok(())
    }

    /// Accept the current state (discard the saved snapshot).
    pub fn commit(&mut self) -> Result<(), String> {
        self.saved_stack
            .pop()
            .ok_or_else(|| "no saved state to commit".to_string())?;
        Ok(())
    }

    /// Get the current bank.
    pub fn current(&self) -> &PcodeRegisterBank {
        &self.current
    }

    /// Get a mutable reference to the current bank.
    pub fn current_mut(&mut self) -> &mut PcodeRegisterBank {
        &mut self.current
    }

    /// How many snapshots are saved.
    pub fn depth(&self) -> usize {
        self.saved_stack.len()
    }
}

// ============================================================================
// RegisterDependencyGraph -- track register read/write dependencies
// ============================================================================

/// Tracks dependencies between registers for data-flow analysis.
///
/// Ported from Ghidra's register dependency tracking used in pcode
/// emulation to determine which registers affect which other registers.
#[derive(Debug, Clone, Default)]
pub struct RegisterDependencyGraph {
    /// register -> set of registers it depends on (reads from).
    depends_on: BTreeMap<String, BTreeSet<String>>,
    /// register -> set of registers that depend on it (read by).
    depended_by: BTreeMap<String, BTreeSet<String>>,
}

impl RegisterDependencyGraph {
    /// Create a new empty dependency graph.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `target` depends on `source` (target reads from source).
    pub fn add_dependency(&mut self, target: &str, source: &str) {
        self.depends_on
            .entry(target.to_string())
            .or_default()
            .insert(source.to_string());
        self.depended_by
            .entry(source.to_string())
            .or_default()
            .insert(target.to_string());
    }

    /// Get the set of registers that `name` depends on.
    pub fn depends_on(&self, name: &str) -> Vec<String> {
        self.depends_on
            .get(name)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get the set of registers that depend on `name`.
    pub fn depended_by(&self, name: &str) -> Vec<String> {
        self.depended_by
            .get(name)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Transitively compute all registers affected if `name` changes.
    pub fn transitive_dependents(&self, name: &str) -> BTreeSet<String> {
        let mut result = BTreeSet::new();
        let mut queue = std::collections::VecDeque::new();
        if let Some(direct) = self.depended_by.get(name) {
            for d in direct {
                if result.insert(d.clone()) {
                    queue.push_back(d.clone());
                }
            }
        }
        while let Some(current) = queue.pop_front() {
            if let Some(dependents) = self.depended_by.get(&current) {
                for d in dependents {
                    if result.insert(d.clone()) {
                        queue.push_back(d.clone());
                    }
                }
            }
        }
        result
    }

    /// The number of dependency edges.
    pub fn num_edges(&self) -> usize {
        self.depends_on.values().map(|s| s.len()).sum()
    }

    /// Whether the graph has no dependencies.
    pub fn is_empty(&self) -> bool {
        self.depends_on.is_empty()
    }

    /// Clear the graph.
    pub fn clear(&mut self) {
        self.depends_on.clear();
        self.depended_by.clear();
    }
}

// ============================================================================
// RegisterWriteGate -- conditional writes with guard predicates
// ============================================================================

/// A guard that conditionally allows register writes.
///
/// Ported from Ghidra's conditional write gating used in trace-based
/// emulation where writes should only proceed if a condition is met
/// (e.g., the value has actually changed, or a permission flag is set).
#[derive(Debug, Clone)]
pub struct RegisterWriteGate {
    /// Registers that are currently gated (writes blocked).
    gated: BTreeSet<String>,
    /// Registers that are locked (writes permanently blocked until explicitly unlocked).
    locked: BTreeSet<String>,
}

impl RegisterWriteGate {
    /// Create a new write gate with no restrictions.
    pub fn new() -> Self {
        Self {
            gated: BTreeSet::new(),
            locked: BTreeSet::new(),
        }
    }

    /// Gate a register (temporarily block writes).
    pub fn gate(&mut self, name: impl Into<String>) {
        self.gated.insert(name.into());
    }

    /// Ungate a register.
    pub fn ungate(&mut self, name: &str) {
        self.gated.remove(name);
    }

    /// Lock a register (block writes until unlocked).
    pub fn lock(&mut self, name: impl Into<String>) {
        self.locked.insert(name.into());
    }

    /// Unlock a register.
    pub fn unlock(&mut self, name: &str) {
        self.locked.remove(name);
    }

    /// Check if a write to the given register is allowed.
    pub fn is_write_allowed(&self, name: &str) -> bool {
        !self.gated.contains(name) && !self.locked.contains(name)
    }

    /// Attempt a gated write. Returns `Err` if gated or locked.
    pub fn attempt_write(
        &self,
        bank: &mut PcodeRegisterBank,
        name: &str,
        value: &[u8],
    ) -> Result<(), String> {
        if self.locked.contains(name) {
            return Err(format!("register '{}' is locked", name));
        }
        if self.gated.contains(name) {
            return Err(format!("register '{}' is gated", name));
        }
        bank.write_register(name, value);
        Ok(())
    }

    /// Gate all registers in a group.
    pub fn gate_group(&mut self, bank: &PcodeRegisterBank, group_name: &str) {
        for name in bank.registers_in_group(group_name) {
            self.gated.insert(name);
        }
    }

    /// Ungate all registers in a group.
    pub fn ungate_group(&mut self, bank: &PcodeRegisterBank, group_name: &str) {
        for name in bank.registers_in_group(group_name) {
            self.gated.remove(&name);
        }
    }

    /// The number of gated registers.
    pub fn num_gated(&self) -> usize {
        self.gated.len()
    }

    /// The number of locked registers.
    pub fn num_locked(&self) -> usize {
        self.locked.len()
    }

    /// Clear all gates and locks.
    pub fn clear(&mut self) {
        self.gated.clear();
        self.locked.clear();
    }
}

// ============================================================================
// RegisterReadPolicy -- control read behavior
// ============================================================================

/// Policy controlling how register reads are handled.
///
/// Ported from Ghidra's register read policy used in pcode emulation to
/// determine what happens when a register is read with unknown state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegisterReadPolicy {
    /// Return None for unknown registers.
    Strict,
    /// Return zero-filled bytes for unknown registers.
    ZeroFill,
    /// Return a pattern-filled byte (0xCC) for unknown registers.
    PatternFill(u8),
    /// Raise an error for unknown registers.
    Error,
}

impl Default for RegisterReadPolicy {
    fn default() -> Self {
        Self::ZeroFill
    }
}

impl RegisterReadPolicy {
    /// Read a register value, applying the policy for unknown registers.
    pub fn read_with_policy(
        &self,
        bank: &PcodeRegisterBank,
        name: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        match bank.read_register(name) {
            some @ Some(_) => Ok(some),
            None => match self {
                Self::Strict => Ok(None),
                Self::ZeroFill => {
                    let def = bank.get_definition(name);
                    let size = def.map(|d| d.byte_length() as usize).unwrap_or(8);
                    Ok(Some(vec![0u8; size]))
                }
                Self::PatternFill(byte) => {
                    let def = bank.get_definition(name);
                    let size = def.map(|d| d.byte_length() as usize).unwrap_or(8);
                    Ok(Some(vec![*byte; size]))
                }
                Self::Error => Err(format!("register '{}' has no value", name)),
            },
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

    // -- RegisterSnapshot --

    #[test]
    fn test_register_snapshot_capture() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("RBX", 64, "GPR");
        bank.write_register("RAX", &[0x78, 0x56, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE]);
        bank.write_register("RBX", &[0x11; 8]);

        let snap = RegisterSnapshot::capture_from_bank("test", 0, &bank);
        assert_eq!(snap.num_known(), 2);
        assert_eq!(snap.get_state("RAX"), RegisterSnapshotState::Known);
        assert_eq!(snap.get_state("RCX"), RegisterSnapshotState::Omitted);
    }

    #[test]
    fn test_register_snapshot_manual_record() {
        let mut snap = RegisterSnapshot::new("manual", 5);
        snap.record("RAX", vec![1, 2, 3, 4]);
        snap.record_unknown("RBX");

        assert_eq!(snap.get_state("RAX"), RegisterSnapshotState::Known);
        assert_eq!(snap.get_state("RBX"), RegisterSnapshotState::Unknown);
        assert_eq!(snap.get("RAX"), Some(&vec![1, 2, 3, 4]));
    }

    // -- RegisterBankDiff --

    #[test]
    fn test_register_bank_diff_no_changes() {
        let mut before = RegisterSnapshot::new("b", 0);
        before.record("RAX", vec![1, 2, 3, 4]);
        let mut after = RegisterSnapshot::new("a", 1);
        after.record("RAX", vec![1, 2, 3, 4]);

        let diff = RegisterBankDiff::compute(&before, &after);
        assert!(diff.is_empty());
    }

    #[test]
    fn test_register_bank_diff_changed() {
        let mut before = RegisterSnapshot::new("b", 0);
        before.record("RAX", vec![1, 2, 3, 4]);
        before.record("RBX", vec![5, 6, 7, 8]);
        let mut after = RegisterSnapshot::new("a", 1);
        after.record("RAX", vec![0xFF, 2, 3, 4]);
        after.record("RBX", vec![5, 6, 7, 8]);

        let diff = RegisterBankDiff::compute(&before, &after);
        assert_eq!(diff.changed.len(), 1);
        assert_eq!(diff.changed[0].name, "RAX");
        assert_eq!(diff.changed[0].before, vec![1, 2, 3, 4]);
        assert_eq!(diff.changed[0].after, vec![0xFF, 2, 3, 4]);
    }

    #[test]
    fn test_register_bank_diff_appeared_disappeared() {
        let mut before = RegisterSnapshot::new("b", 0);
        before.record("RAX", vec![1, 2, 3, 4]);
        let mut after = RegisterSnapshot::new("a", 1);
        after.record("RAX", vec![1, 2, 3, 4]);
        after.record("RCX", vec![9, 9, 9, 9]);

        let diff = RegisterBankDiff::compute(&before, &after);
        assert!(diff.changed.is_empty());
        assert_eq!(diff.appeared, vec!["RCX"]);
        assert_eq!(diff.disappeared, vec!["RAX"]); // RAX in before but not in after states
    }

    // -- RegisterWatchpoint --

    #[test]
    fn test_register_watchpoint_unconditional() {
        let wp = RegisterWatchpoint::new(1, "RAX");
        assert!(wp.should_fire(&[1, 2, 3]));
    }

    #[test]
    fn test_register_watchpoint_conditional() {
        let wp = RegisterWatchpoint::new(1, "RAX").with_condition(vec![0xFF]);
        assert!(wp.should_fire(&[0xFF]));
        assert!(!wp.should_fire(&[0x00]));
    }

    #[test]
    fn test_register_watchpoint_disabled() {
        let mut wp = RegisterWatchpoint::new(1, "RAX");
        wp.enabled = false;
        assert!(!wp.should_fire(&[1, 2, 3]));
    }

    #[test]
    fn test_register_watchpoint_manager() {
        let mut mgr = RegisterWatchpointManager::new();
        let id1 = mgr.add_watchpoint("RAX");
        let id2 = mgr.add_watchpoint("RBX");
        assert_eq!(mgr.len(), 2);

        let hits = mgr.check("RAX", &[0x42]);
        assert_eq!(hits, vec![id1]);
        assert_eq!(mgr.get(id1).unwrap().hit_count, 1);

        let hits2 = mgr.check("RCX", &[0x42]);
        assert!(hits2.is_empty());

        mgr.set_enabled(id2, false);
        let hits3 = mgr.check("RBX", &[0x99]);
        assert!(hits3.is_empty());

        mgr.remove_watchpoint(id1);
        assert_eq!(mgr.len(), 1);
    }

    // -- CallingConventionMapper --

    #[test]
    fn test_convention_mapper_sysv_to_ms() {
        let mapper = CallingConventionMapper::new(
            RegisterConvention::system_v_amd64(),
            RegisterConvention::ms_x64(),
        );
        let int_args = mapper.map_integer_args();
        assert_eq!(int_args.len(), 4); // min(6, 4)
        assert_eq!(int_args[0], ("RDI", "RCX"));
        assert_eq!(int_args[1], ("RSI", "RDX"));
        assert!(mapper.same_stack_pointer());
        assert!(mapper.same_frame_pointer());
    }

    #[test]
    fn test_convention_mapper_to_arm() {
        let mapper = CallingConventionMapper::new(
            RegisterConvention::system_v_amd64(),
            RegisterConvention::arm_aapcs(),
        );
        assert_eq!(mapper.num_integer_arg_slots(), 4); // min(6, 4)
        assert!(!mapper.same_stack_pointer()); // RSP vs SP
    }

    // -- RegisterAliasChain --

    #[test]
    fn test_alias_chain_simple() {
        let mut chain = RegisterAliasChain::new();
        chain.add_alias("AL", "AX");
        chain.add_alias("AX", "EAX");
        chain.add_alias("EAX", "RAX");

        assert_eq!(chain.resolve("AL"), "RAX");
        assert_eq!(chain.resolve("EAX"), "RAX");
        assert_eq!(chain.resolve("RAX"), "RAX");
    }

    #[test]
    fn test_alias_chain_chain() {
        let mut chain = RegisterAliasChain::new();
        chain.add_alias("AL", "AX");
        chain.add_alias("AX", "EAX");
        chain.add_alias("EAX", "RAX");

        let c = chain.chain("AL");
        assert_eq!(c, vec!["AL", "AX", "EAX", "RAX"]);
    }

    #[test]
    fn test_alias_chain_same_register() {
        let mut chain = RegisterAliasChain::new();
        chain.add_alias("AL", "AX");
        chain.add_alias("AX", "EAX");

        assert!(chain.is_same_register("AL", "EAX"));
        assert!(!chain.is_same_register("AL", "RBX"));
    }

    #[test]
    fn test_alias_chain_cycle_detection() {
        let mut chain = RegisterAliasChain::new();
        chain.add_alias("A", "B");
        chain.add_alias("B", "A");

        // Should not infinite loop; resolves to one of them
        let resolved = chain.resolve("A");
        assert!(resolved == "A" || resolved == "B");
    }

    // -- RegisterFileLayout --

    #[test]
    fn test_register_file_layout_basic() {
        let mut layout = RegisterFileLayout::new("register");
        layout.add_register("RAX", 0, 8);
        layout.add_register("RBX", 8, 8);
        layout.add_register("RCX", 16, 8);

        assert_eq!(layout.len(), 3);
        assert_eq!(layout.total_size(), 24);
        assert_eq!(layout.byte_range("RAX"), Some((0, 8)));
        assert_eq!(layout.byte_range("RBX"), Some((8, 16)));
    }

    #[test]
    fn test_register_file_layout_extract_inject() {
        let mut layout = RegisterFileLayout::new("register");
        layout.add_register("RAX", 0, 8);
        layout.add_register("RBX", 8, 8);

        let buffer = vec![0x78, 0x56, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

        let rax = layout.extract_value("RAX", &buffer).unwrap();
        assert_eq!(rax, vec![0x78, 0x56, 0x34, 0x12, 0xEF, 0xBE, 0xAD, 0xDE]);

        let rbx = layout.extract_value("RBX", &buffer).unwrap();
        assert_eq!(rbx, vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

        // Inject into a new buffer
        let mut buf = vec![0u8; 16];
        layout.inject_value("RBX", &mut buf, &[0xAA, 0xBB]).unwrap();
        assert_eq!(&buf[8..10], &[0xAA, 0xBB]);
    }

    #[test]
    fn test_register_file_layout_missing() {
        let layout = RegisterFileLayout::new("register");
        assert!(layout.get_entry("RAX").is_none());
        assert!(layout.is_empty());
    }

    // -- SourcedRegisterValue --

    #[test]
    fn test_sourced_register_value() {
        let srv = SourcedRegisterValue::new("RAX", vec![1, 2, 3, 4], RegisterValueSource::Target, 10);
        assert!(srv.is_live());
        assert_eq!(srv.name, "RAX");

        let srv2 = SourcedRegisterValue::new("RBX", vec![5, 6], RegisterValueSource::Trace, 10);
        assert!(!srv2.is_live());
    }

    // -- RegisterBankOverlay --

    #[test]
    fn test_register_bank_overlay() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("RBX", 64, "GPR");
        bank.write_register("RAX", &[1, 2, 3, 4, 5, 6, 7, 8]);
        bank.write_register("RBX", &[0xAA; 8]);

        let mut overlay = RegisterBankOverlay::new();
        overlay.set("RAX", vec![0xFF; 8]);

        // RAX from overlay, RBX from base
        assert_eq!(overlay.read("RAX", &bank), Some(vec![0xFF; 8]));
        assert_eq!(overlay.read("RBX", &bank), Some(vec![0xAA; 8]));

        // Clear RAX
        overlay.clear("RAX");
        assert_eq!(overlay.read("RAX", &bank), None);
        assert!(overlay.has_override("RAX"));

        // Remove override reverts to base
        overlay.remove_override("RAX");
        assert_eq!(overlay.read("RAX", &bank), Some(vec![1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn test_register_bank_overlay_apply() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.write_register("RAX", &[0; 8]);

        let mut overlay = RegisterBankOverlay::new();
        overlay.set("RAX", vec![0xFF; 8]);

        overlay.apply_to(&mut bank);
        assert_eq!(bank.read_register("RAX"), Some(vec![0xFF; 8]));
    }

    // -- RegisterTracer --

    #[test]
    fn test_register_tracer_basic() {
        let mut tracer = RegisterTracer::new();
        tracer.record_read("RAX", &[1, 2, 3, 4], 0);
        tracer.record_write("RAX", &[5, 6, 7, 8], 1);
        tracer.record_read("RBX", &[0xAA; 4], 2);

        assert_eq!(tracer.len(), 3);
        assert_eq!(tracer.entries_for("RAX").len(), 2);
        assert_eq!(tracer.entries_of_kind(RegisterAccessKind::Read).len(), 2);
        assert_eq!(tracer.last().unwrap().name, "RBX");
    }

    #[test]
    fn test_register_tracer_max_entries() {
        let mut tracer = RegisterTracer::new().with_max_entries(2);
        tracer.record_read("A", &[1], 0);
        tracer.record_read("B", &[2], 1);
        tracer.record_read("C", &[3], 2);

        assert_eq!(tracer.len(), 2);
        assert_eq!(tracer.entries()[0].name, "B");
        assert_eq!(tracer.entries()[1].name, "C");
    }

    // -- RegisterBankFork --

    #[test]
    fn test_register_bank_fork() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.write_register("RAX", &[1, 2, 3, 4, 5, 6, 7, 8]);

        let mut fork = RegisterBankFork::new(bank);
        assert_eq!(fork.depth(), 0);

        fork.fork();
        assert_eq!(fork.depth(), 1);
        fork.current_mut().write_register("RAX", &[0xFF; 8]);
        assert_eq!(fork.current().read_register("RAX"), Some(vec![0xFF; 8]));

        fork.restore().unwrap();
        assert_eq!(fork.depth(), 0);
        assert_eq!(fork.current().read_register("RAX"), Some(vec![1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn test_register_bank_fork_commit() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.write_register("RAX", &[1, 2, 3, 4, 5, 6, 7, 8]);

        let mut fork = RegisterBankFork::new(bank);
        fork.fork();
        fork.current_mut().write_register("RAX", &[0xFF; 8]);
        fork.commit().unwrap();

        assert_eq!(fork.depth(), 0);
        assert_eq!(fork.current().read_register("RAX"), Some(vec![0xFF; 8]));
    }

    // -- RegisterDependencyGraph --

    #[test]
    fn test_register_dependency_graph() {
        let mut graph = RegisterDependencyGraph::new();
        graph.add_dependency("RCX", "RAX"); // RCX reads RAX
        graph.add_dependency("RDX", "RAX"); // RDX reads RAX
        graph.add_dependency("RSI", "RCX"); // RSI reads RCX

        assert_eq!(graph.depends_on("RCX"), vec!["RAX"]);
        assert_eq!(graph.depended_by("RAX").len(), 2);

        let transitive = graph.transitive_dependents("RAX");
        assert!(transitive.contains("RCX"));
        assert!(transitive.contains("RDX"));
        assert!(transitive.contains("RSI")); // transitively via RCX
    }

    // -- RegisterWriteGate --

    #[test]
    fn test_register_write_gate() {
        let mut gate = RegisterWriteGate::new();
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");

        assert!(gate.is_write_allowed("RAX"));

        gate.gate("RAX");
        assert!(!gate.is_write_allowed("RAX"));
        assert!(gate.attempt_write(&mut bank, "RAX", &[1, 2]).is_err());

        gate.ungate("RAX");
        assert!(gate.is_write_allowed("RAX"));
        assert!(gate.attempt_write(&mut bank, "RAX", &[1, 2]).is_ok());
    }

    #[test]
    fn test_register_write_gate_lock() {
        let mut gate = RegisterWriteGate::new();
        gate.lock("RAX");
        assert!(!gate.is_write_allowed("RAX"));

        // Ungating doesn't help with locks
        gate.ungate("RAX");
        assert!(!gate.is_write_allowed("RAX"));

        gate.unlock("RAX");
        assert!(gate.is_write_allowed("RAX"));
    }

    // -- RegisterReadPolicy --

    #[test]
    fn test_register_read_policy_strict() {
        let bank = PcodeRegisterBank::new();
        let policy = RegisterReadPolicy::Strict;
        assert!(policy.read_with_policy(&bank, "RAX").unwrap().is_none());
    }

    #[test]
    fn test_register_read_policy_zero_fill() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        let policy = RegisterReadPolicy::ZeroFill;
        let val = policy.read_with_policy(&bank, "RAX").unwrap().unwrap();
        assert_eq!(val, vec![0u8; 8]);
    }

    #[test]
    fn test_register_read_policy_pattern() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        let policy = RegisterReadPolicy::PatternFill(0xCC);
        let val = policy.read_with_policy(&bank, "RAX").unwrap().unwrap();
        assert_eq!(val, vec![0xCCu8; 8]);
    }

    #[test]
    fn test_register_read_policy_error() {
        let bank = PcodeRegisterBank::new();
        let policy = RegisterReadPolicy::Error;
        assert!(policy.read_with_policy(&bank, "RAX").is_err());
    }

    #[test]
    fn test_register_read_policy_existing() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.write_register("RAX", &[0x42; 8]);

        // All policies should return the existing value
        for policy in [
            RegisterReadPolicy::Strict,
            RegisterReadPolicy::ZeroFill,
            RegisterReadPolicy::PatternFill(0xCC),
            RegisterReadPolicy::Error,
        ] {
            let val = policy.read_with_policy(&bank, "RAX").unwrap().unwrap();
            assert_eq!(val, vec![0x42; 8]);
        }
    }
}
