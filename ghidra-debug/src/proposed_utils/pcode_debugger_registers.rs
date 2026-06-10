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
//! - `RegisterBankSnapshot`: Serializable snapshot of an entire bank.
//! - `RegisterBankMergeResult` / `RegisterMergeConflict`: Merge conflict tracking.
//! - `PcodeDebuggerRegistersAccess`: Trait for target-synchronized register access.

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

    /// Iterate over all register definitions (name, definition).
    pub fn definitions(&self) -> impl Iterator<Item = (&String, &RegisterDefinition)> {
        self.definitions.iter()
    }

    /// Compute the nesting depth of a register (0 = top-level).
    pub fn compute_depth(&self, name: &str) -> u32 {
        let mut depth = 0u32;
        let mut current = name.to_string();
        while let Some(parent_name) = self.parent_of(&current) {
            depth += 1;
            current = parent_name.to_string();
            if depth > 32 {
                break; // safety limit
            }
        }
        depth
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

    /// Iterate over all mapping entries.
    pub fn iter(&self) -> impl Iterator<Item = RegisterMappingEntry<'_>> {
        self.lang_to_conn.iter().map(|(lang, conn)| RegisterMappingEntry {
            lang_name: lang.as_str(),
            connector_name: conn.as_str(),
        })
    }
}

/// A borrowed entry from a `RegisterMapping`.
#[derive(Debug, Clone)]
pub struct RegisterMappingEntry<'a> {
    /// The language register name.
    pub lang_name: &'a str,
    /// The connector register name.
    pub connector_name: &'a str,
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
// RegisterContextTracker -- track context register changes over time
// ============================================================================

/// Tracks changes to context registers over a sequence of snaps.
///
/// Ported from Ghidra's context register tracking used in pcode emulation
/// where the processor context (e.g., ARM Thumb mode, x86 address size)
/// changes as execution progresses. Maintains a history of context values
/// so that emulators can rewind or diff context state.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterContextTracker {
    /// History entries: (snap, context_field_name, value).
    history: Vec<(i64, String, u64)>,
    /// Current context values by field name.
    current: BTreeMap<String, u64>,
    /// Maximum history depth (0 = unlimited).
    max_depth: usize,
}

impl RegisterContextTracker {
    /// Create a new context tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the maximum history depth.
    pub fn with_max_depth(mut self, max: usize) -> Self {
        self.max_depth = max;
        self
    }

    /// Record a context register change at the given snap.
    pub fn record(&mut self, snap: i64, field: impl Into<String>, value: u64) {
        let field = field.into();
        self.current.insert(field.clone(), value);
        if self.max_depth > 0 && self.history.len() >= self.max_depth {
            self.history.remove(0);
        }
        self.history.push((snap, field, value));
    }

    /// Get the current value of a context field.
    pub fn get(&self, field: &str) -> Option<u64> {
        self.current.get(field).copied()
    }

    /// Get the value of a context field at a specific snap.
    /// Returns the most recent value at or before the given snap.
    pub fn get_at_snap(&self, field: &str, snap: i64) -> Option<u64> {
        self.history
            .iter()
            .rev()
            .find(|(s, f, _)| *s <= snap && f == field)
            .map(|(_, _, v)| *v)
    }

    /// Get the full history for a context field.
    pub fn history_for(&self, field: &str) -> Vec<(i64, u64)> {
        self.history
            .iter()
            .filter(|(_, f, _)| f == field)
            .map(|(s, _, v)| (*s, *v))
            .collect()
    }

    /// Get all context field names currently tracked.
    pub fn fields(&self) -> Vec<&str> {
        self.current.keys().map(|s| s.as_str()).collect()
    }

    /// The total number of history entries.
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Clear all history and current values.
    pub fn clear(&mut self) {
        self.history.clear();
        self.current.clear();
    }

    /// Diff the current context against a previous snap, returning fields
    /// that have changed.
    pub fn diff_since_snap(&self, snap: i64) -> BTreeMap<String, (Option<u64>, Option<u64>)> {
        let mut diffs = BTreeMap::new();
        for (field, &current_val) in &self.current {
            let old_val = self.get_at_snap(field, snap);
            if old_val != Some(current_val) {
                diffs.insert(field.clone(), (old_val, Some(current_val)));
            }
        }
        diffs
    }

    /// Restore context state to the values at a given snap.
    pub fn restore_to_snap(&mut self, snap: i64) {
        for (field, _) in self.current.clone().iter() {
            if let Some(old_val) = self.get_at_snap(field, snap) {
                self.current.insert(field.clone(), old_val);
            }
        }
    }
}

// ============================================================================
// RegisterBankValidator -- validate register values against constraints
// ============================================================================

/// A validation rule for register values.
///
/// Ported from Ghidra's register validation used to check register
/// invariants during emulation (e.g., alignment constraints, range
/// checks, or value-invariant relationships).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegisterValidationRule {
    /// The register value must be within [min, max] as unsigned.
    Range { min: u128, max: u128 },
    /// The register value must be aligned to the given byte boundary.
    Alignment { bytes: u32 },
    /// The register value must not be zero.
    NonZero,
    /// The register value must equal one of the given values.
    OneOf { values: Vec<Vec<u8>> },
    /// A custom rule with a description and a check function result.
    Custom { description: String },
}

/// A validation result for a single register.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterValidationResult {
    /// The register name.
    pub name: String,
    /// Whether the validation passed.
    pub valid: bool,
    /// The rule that failed (if any).
    pub failed_rule: Option<String>,
    /// The actual value (if available).
    pub actual_value: Option<Vec<u8>>,
}

/// Validates register values against a set of rules.
///
/// Ported from Ghidra's register validation framework used during
/// emulation to ensure register state invariants are maintained.
#[derive(Debug, Clone, Default)]
pub struct RegisterBankValidator {
    /// Validation rules keyed by register name.
    rules: BTreeMap<String, Vec<RegisterValidationRule>>,
}

impl RegisterBankValidator {
    /// Create a new empty validator.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a validation rule for a register.
    pub fn add_rule(&mut self, name: impl Into<String>, rule: RegisterValidationRule) {
        self.rules.entry(name.into()).or_default().push(rule);
    }

    /// Add a range rule for a register.
    pub fn add_range_rule(&mut self, name: impl Into<String>, min: u128, max: u128) {
        self.add_rule(name, RegisterValidationRule::Range { min, max });
    }

    /// Add an alignment rule for a register.
    pub fn add_alignment_rule(&mut self, name: impl Into<String>, bytes: u32) {
        self.add_rule(name, RegisterValidationRule::Alignment { bytes });
    }

    /// Add a non-zero rule for a register.
    pub fn add_nonzero_rule(&mut self, name: impl Into<String>) {
        self.add_rule(name, RegisterValidationRule::NonZero);
    }

    /// Validate all registers that have rules against the given bank.
    pub fn validate(&self, bank: &PcodeRegisterBank) -> Vec<RegisterValidationResult> {
        let mut results = Vec::new();
        for (name, rules) in &self.rules {
            let value = bank.read_register(name);
            for rule in rules {
                let result = Self::check_rule(name, rule, value.as_deref());
                if !result.valid {
                    results.push(result);
                }
            }
        }
        results
    }

    /// Validate a single register.
    pub fn validate_register(
        &self,
        bank: &PcodeRegisterBank,
        name: &str,
    ) -> Vec<RegisterValidationResult> {
        let value = bank.read_register(name);
        self.rules
            .get(name)
            .map(|rules| {
                rules
                    .iter()
                    .map(|rule| Self::check_rule(name, rule, value.as_deref()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Check if all registers pass validation.
    pub fn is_valid(&self, bank: &PcodeRegisterBank) -> bool {
        self.validate(bank).is_empty()
    }

    fn check_rule(
        name: &str,
        rule: &RegisterValidationRule,
        value: Option<&[u8]>,
    ) -> RegisterValidationResult {
        let valid = match (rule, value) {
            (_, None) => false,
            (RegisterValidationRule::Range { min, max }, Some(bytes)) => {
                let val = bytes_to_u128(bytes);
                val >= *min && val <= *max
            }
            (RegisterValidationRule::Alignment { bytes }, Some(bv)) => {
                let val = bytes_to_u128(bv);
                val % (*bytes as u128) == 0
            }
            (RegisterValidationRule::NonZero, Some(bytes)) => bytes.iter().any(|&b| b != 0),
            (RegisterValidationRule::OneOf { values }, Some(bytes)) => {
                values.iter().any(|v| v.as_slice() == bytes)
            }
            (RegisterValidationRule::Custom { .. }, _) => true, // Custom rules need external eval
        };
        RegisterValidationResult {
            name: name.to_string(),
            valid,
            failed_rule: if valid {
                None
            } else {
                Some(format!("{:?}", rule))
            },
            actual_value: value.map(|v| v.to_vec()),
        }
    }

    /// Remove all rules for a register.
    pub fn clear_rules(&mut self, name: &str) {
        self.rules.remove(name);
    }

    /// Remove all rules.
    pub fn clear_all(&mut self) {
        self.rules.clear();
    }

    /// The number of registers with rules.
    pub fn num_registers(&self) -> usize {
        self.rules.len()
    }

    /// The total number of rules across all registers.
    pub fn num_rules(&self) -> usize {
        self.rules.values().map(|v| v.len()).sum()
    }
}

/// Helper to convert a byte slice to a u128 value (little-endian).
fn bytes_to_u128(bytes: &[u8]) -> u128 {
    let mut val: u128 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        val |= (b as u128) << (i * 8);
    }
    val
}

// ============================================================================
// RegisterValueCache -- caching layer for register reads
// ============================================================================

/// A cache for register values that avoids repeated reads from the bank.
///
/// Ported from Ghidra's register caching used in pcode emulation where
/// the same registers are read multiple times within a single step.
/// Provides dirty tracking so that only modified registers need to be
/// written back.
#[derive(Debug, Clone, Default)]
pub struct RegisterValueCache {
    /// Cached values by register name.
    cache: BTreeMap<String, Vec<u8>>,
    /// Registers that have been modified since last sync.
    dirty: BTreeSet<String>,
    /// Registers that are pinned (always fetched fresh from bank).
    pinned: BTreeSet<String>,
}

impl RegisterValueCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Read a register, using cache if available.
    pub fn read(&mut self, bank: &PcodeRegisterBank, name: &str) -> Option<Vec<u8>> {
        if self.pinned.contains(name) {
            return bank.read_register(name);
        }
        if let Some(val) = self.cache.get(name) {
            return Some(val.clone());
        }
        let val = bank.read_register(name);
        if let Some(ref v) = val {
            self.cache.insert(name.to_string(), v.clone());
        }
        val
    }

    /// Write a register value into the cache (not written to bank yet).
    pub fn write(&mut self, name: impl Into<String>, value: Vec<u8>) {
        let name = name.into();
        self.cache.insert(name.clone(), value);
        self.dirty.insert(name);
    }

    /// Flush all dirty values back to the bank.
    pub fn flush(&mut self, bank: &mut PcodeRegisterBank) {
        for name in &self.dirty {
            if let Some(val) = self.cache.get(name) {
                bank.write_register(name, val);
            }
        }
        self.dirty.clear();
    }

    /// Flush a specific register back to the bank.
    pub fn flush_register(&mut self, bank: &mut PcodeRegisterBank, name: &str) {
        if let Some(val) = self.cache.get(name) {
            bank.write_register(name, val);
            self.dirty.remove(name);
        }
    }

    /// Invalidate a specific cache entry.
    pub fn invalidate(&mut self, name: &str) {
        self.cache.remove(name);
        self.dirty.remove(name);
    }

    /// Invalidate all cache entries.
    pub fn invalidate_all(&mut self) {
        self.cache.clear();
        self.dirty.clear();
    }

    /// Pin a register (always fetch fresh from bank, bypass cache).
    pub fn pin(&mut self, name: impl Into<String>) {
        self.pinned.insert(name.into());
    }

    /// Unpin a register.
    pub fn unpin(&mut self, name: &str) {
        self.pinned.remove(name);
    }

    /// Get the set of dirty register names.
    pub fn dirty_registers(&self) -> &BTreeSet<String> {
        &self.dirty
    }

    /// Whether the cache has any dirty entries.
    pub fn has_dirty(&self) -> bool {
        !self.dirty.is_empty()
    }

    /// The number of cached entries.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Sync the cache with the bank: update cached values for registers
    /// that have changed in the bank but are not dirty in the cache.
    pub fn sync_from_bank(&mut self, bank: &PcodeRegisterBank) {
        for name in bank.register_names() {
            if !self.dirty.contains(name) {
                if let Some(val) = bank.read_register(name) {
                    self.cache.insert(name.to_string(), val);
                }
            }
        }
    }
}

// ============================================================================
// RegisterBankSnapshot -- serializable bank state capture
// ============================================================================

/// A serializable snapshot of an entire register bank.
///
/// Ported from Ghidra's register bank snapshot concept used by
/// `PcodeDebuggerRegistersAccess`. Captures all definitions,
/// values, aliases, and parent-child relationships so the bank
/// state can be serialized, transmitted, and restored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterBankSnapshot {
    /// The snapshot identifier.
    pub id: String,
    /// The snap (time) at which this snapshot was taken.
    pub snap: i64,
    /// All register definitions.
    pub definitions: BTreeMap<String, RegisterDefinition>,
    /// All register values.
    pub values: BTreeMap<String, Vec<u8>>,
    /// Alias mappings.
    pub aliases: BTreeMap<String, String>,
    /// Parent-child relationships.
    pub children_of: BTreeMap<String, String>,
}

impl RegisterBankSnapshot {
    /// Capture a snapshot from a register bank.
    pub fn capture(id: impl Into<String>, snap: i64, bank: &PcodeRegisterBank) -> Self {
        Self {
            id: id.into(),
            snap,
            definitions: bank.definitions.clone(),
            values: bank.values.clone(),
            aliases: bank.aliases.clone(),
            children_of: bank.children_of.clone(),
        }
    }

    /// Restore the snapshot into a register bank.
    pub fn restore(&self) -> PcodeRegisterBank {
        PcodeRegisterBank {
            definitions: self.definitions.clone(),
            values: self.values.clone(),
            aliases: self.aliases.clone(),
            children_of: self.children_of.clone(),
            groups: Vec::new(),
        }
    }

    /// The number of registers with values in this snapshot.
    pub fn num_values(&self) -> usize {
        self.values.len()
    }

    /// The number of register definitions in this snapshot.
    pub fn num_definitions(&self) -> usize {
        self.definitions.len()
    }
}

// ============================================================================
// RegisterBankMergeResult -- merge conflict tracking
// ============================================================================

/// The result of merging two register bank states.
///
/// Ported from Ghidra's merge logic used when combining register
/// state from multiple sources (e.g., target read + trace data).
#[derive(Debug, Clone, Default)]
pub struct RegisterBankMergeResult {
    /// Registers that were successfully merged (no conflict).
    pub merged: Vec<String>,
    /// Registers where the two sources had different values.
    pub conflicts: Vec<RegisterMergeConflict>,
}

/// A register merge conflict.
#[derive(Debug, Clone)]
pub struct RegisterMergeConflict {
    /// The register name.
    pub name: String,
    /// The value from the first source.
    pub value_a: Vec<u8>,
    /// The value from the second source.
    pub value_b: Vec<u8>,
}

impl RegisterBankMergeResult {
    /// Whether the merge had any conflicts.
    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty()
    }

    /// The total number of registers processed.
    pub fn total(&self) -> usize {
        self.merged.len() + self.conflicts.len()
    }
}

/// Merge two register banks, recording conflicts.
///
/// For each register present in both banks, if the values differ
/// a conflict is recorded; otherwise the value is accepted.
/// The `prefer_first` flag controls which value wins on conflict.
pub fn merge_register_banks(
    a: &PcodeRegisterBank,
    b: &PcodeRegisterBank,
    _prefer_first: bool,
) -> RegisterBankMergeResult {
    let mut result = RegisterBankMergeResult::default();
    let all_names: BTreeSet<String> = a
        .register_names()
        .into_iter()
        .chain(b.register_names().into_iter())
        .map(|s| s.to_string())
        .collect();

    for name in &all_names {
        let val_a = a.read_register(name);
        let val_b = b.read_register(name);

        match (val_a, val_b) {
            (Some(va), Some(vb)) => {
                if va == vb {
                    result.merged.push(name.clone());
                } else {
                    result.conflicts.push(RegisterMergeConflict {
                        name: name.clone(),
                        value_a: va,
                        value_b: vb,
                    });
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                // One side has it, the other doesn't -- take whichever exists
                result.merged.push(name.clone());
            }
            (None, None) => {}
        }
    }

    result
}

// ============================================================================
// PcodeDebuggerRegistersAccess -- trait for register access with target sync
// ============================================================================

/// Access errors specific to debugger register operations.
#[derive(Debug, Clone)]
pub enum RegisterAccessError {
    /// No target is connected.
    NoTarget,
    /// The target is not in a state that permits reads.
    NotReadable,
    /// The target is not in a state that permits writes.
    NotWritable,
    /// The specified register was not found.
    RegisterNotFound(String),
    /// A generic error message.
    Other(String),
}

impl std::fmt::Display for RegisterAccessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoTarget => write!(f, "no target connected"),
            Self::NotReadable => write!(f, "target not readable"),
            Self::NotWritable => write!(f, "target not writable"),
            Self::RegisterNotFound(n) => write!(f, "register not found: {}", n),
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for RegisterAccessError {}

/// A trait for accessing trace registers through a debugger.
///
/// Ported from Ghidra's `PcodeDebuggerRegistersAccess` interface.
/// Extends basic register access with the ability to read unknown
/// registers from the live target and to write registers back.
pub trait PcodeDebuggerRegistersAccess {
    /// Read registers whose state is unknown from the target.
    ///
    /// The `unknown` set identifies which registers need to be read.
    /// Returns `true` if any data was successfully read from the target.
    fn read_from_target_registers(
        &mut self,
        unknown: &[String],
    ) -> Result<bool, RegisterAccessError>;

    /// Write a register value to the target.
    ///
    /// Returns `true` if the target was successfully written.
    fn write_target_register(
        &mut self,
        name: &str,
        data: &[u8],
    ) -> Result<bool, RegisterAccessError>;

    /// Check if the associated session is live (has a connected target).
    fn is_live(&self) -> bool;

    /// Initialize a thread's context register from the trace.
    ///
    /// Called during thread construction after the program counter is
    /// set. Ensures the instruction decoder starts in the correct mode.
    fn initialize_thread_context(&mut self, thread_key: i64);
}

// ============================================================================
// RegisterBankIterator -- iterate over bank entries with metadata
// ============================================================================

/// An iterator entry over a register bank's definitions and values.
///
/// Ported from Ghidra's register bank iteration utilities used by
/// the register window and serialization code to enumerate all registers
/// along with their definitions and current values.
#[derive(Debug, Clone)]
pub struct RegisterBankEntry<'a> {
    /// The register name.
    pub name: &'a str,
    /// The register definition.
    pub definition: &'a RegisterDefinition,
    /// The current value (if known).
    pub value: Option<&'a Vec<u8>>,
    /// The parent register name (if any).
    pub parent: Option<&'a str>,
    /// The register group name.
    pub group: &'a str,
}

/// An iterator over a `PcodeRegisterBank` that yields entries with
/// full metadata including definitions, values, and parent relationships.
///
/// Ported from Ghidra's register bank enumeration patterns. Yields
/// entries in definition order (BTreeMap sorted by name).
pub struct RegisterBankIterator<'a> {
    bank: &'a PcodeRegisterBank,
    names: Vec<&'a str>,
    pos: usize,
}

impl<'a> RegisterBankIterator<'a> {
    /// Create a new iterator over the register bank.
    pub fn new(bank: &'a PcodeRegisterBank) -> Self {
        let names = bank.register_names();
        Self {
            bank,
            names,
            pos: 0,
        }
    }

    /// Collect all remaining entries into a vector.
    pub fn collect_entries(&mut self) -> Vec<RegisterBankEntry<'a>> {
        let mut result = Vec::new();
        while let Some(entry) = self.next() {
            result.push(entry);
        }
        result
    }

    /// Filter iterator to only registers in the given group.
    pub fn filter_group(mut self, group_name: &str) -> Vec<RegisterBankEntry<'a>> {
        self.names.retain(|n| {
            self.bank
                .definitions
                .get(*n)
                .map(|d| d.group == group_name)
                .unwrap_or(false)
        });
        self.pos = 0;
        self.collect_entries()
    }

    /// Filter iterator to only registers with known values.
    pub fn filter_known(mut self) -> Vec<RegisterBankEntry<'a>> {
        self.names
            .retain(|n| self.bank.values.contains_key(*n));
        self.pos = 0;
        self.collect_entries()
    }
}

impl<'a> Iterator for RegisterBankIterator<'a> {
    type Item = RegisterBankEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.names.len() {
            let name = self.names[self.pos];
            self.pos += 1;
            if let Some(definition) = self.bank.definitions.get(name) {
                let value = self.bank.values.get(name);
                let parent = self.bank.children_of.get(name).map(|s| s.as_str());
                return Some(RegisterBankEntry {
                    name,
                    definition,
                    value,
                    parent,
                    group: &definition.group,
                });
            }
        }
        None
    }
}

/// An iterator over only register values (name -> value pairs).
///
/// Simpler than `RegisterBankIterator`, this only yields registers
/// that have known values.
pub struct RegisterValueIterator<'a> {
    iter: std::collections::btree_map::Iter<'a, String, Vec<u8>>,
}

impl<'a> RegisterValueIterator<'a> {
    /// Create a new value iterator from a register bank.
    pub fn new(bank: &'a PcodeRegisterBank) -> Self {
        Self {
            iter: bank.values.iter(),
        }
    }
}

impl<'a> Iterator for RegisterValueIterator<'a> {
    type Item = (&'a str, &'a Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next().map(|(k, v)| (k.as_str(), v))
    }
}

// ============================================================================
// RegisterChangeTracker -- incremental change tracking
// ============================================================================

/// Tracks incremental changes to a register bank over time.
///
/// Ported from Ghidra's register change tracking used by the
/// `PcodeDebuggerRegistersAccess` to efficiently determine which
/// registers have been modified since the last sync. Maintains a
/// delta of changed values and supports rolling back individual
/// changes.
#[derive(Debug, Clone, Default)]
pub struct RegisterChangeTracker {
    /// Snapshot of values at the last checkpoint.
    checkpoint_values: BTreeMap<String, Vec<u8>>,
    /// Changes since the last checkpoint: register_name -> new_value.
    /// `None` means the register was deleted/unknowned.
    deltas: BTreeMap<String, Option<Vec<u8>>>,
    /// Whether any changes have been tracked.
    dirty: bool,
}

impl RegisterChangeTracker {
    /// Create a new change tracker from a register bank's current values.
    pub fn from_bank(bank: &PcodeRegisterBank) -> Self {
        Self {
            checkpoint_values: bank.values.clone(),
            deltas: BTreeMap::new(),
            dirty: false,
        }
    }

    /// Record a write to a register.
    pub fn record_write(&mut self, name: impl Into<String>, value: Vec<u8>) {
        let name = name.into();
        self.deltas.insert(name, Some(value));
        self.dirty = true;
    }

    /// Record that a register was cleared/unknowned.
    pub fn record_clear(&mut self, name: impl Into<String>) {
        let name = name.into();
        self.deltas.insert(name, None);
        self.dirty = true;
    }

    /// Get the names of all changed registers.
    pub fn changed_names(&self) -> Vec<&str> {
        self.deltas.keys().map(|s| s.as_str()).collect()
    }

    /// Whether there are any pending changes.
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// The number of pending changes.
    pub fn num_changes(&self) -> usize {
        self.deltas.len()
    }

    /// Apply the tracked deltas to a register bank and reset the tracker.
    pub fn apply_to(&mut self, bank: &mut PcodeRegisterBank) {
        for (name, value) in &self.deltas {
            match value {
                Some(val) => bank.write_register(name, val),
                None => { bank.values.remove(name); }
            }
        }
        // Update checkpoint to the new state
        self.checkpoint_values = bank.values.clone();
        self.deltas.clear();
        self.dirty = false;
    }

    /// Roll back all tracked changes by restoring the checkpoint values
    /// into the given bank.
    pub fn rollback(&mut self, bank: &mut PcodeRegisterBank) {
        // Restore checkpoint values
        for (name, val) in &self.checkpoint_values {
            bank.values.insert(name.clone(), val.clone());
        }
        // Remove any registers that were added since checkpoint
        let checkpoint_names: BTreeSet<String> =
            self.checkpoint_values.keys().cloned().collect();
        let current_names: Vec<String> = bank.values.keys().cloned().collect();
        for name in current_names {
            if !checkpoint_names.contains(&name) && self.deltas.contains_key(&name) {
                bank.values.remove(&name);
            }
        }
        self.deltas.clear();
        self.dirty = false;
    }

    /// Create a new checkpoint from the current bank state, discarding
    /// the current deltas.
    pub fn checkpoint(&mut self, bank: &PcodeRegisterBank) {
        self.checkpoint_values = bank.values.clone();
        self.deltas.clear();
        self.dirty = false;
    }

    /// Get the checkpoint value for a register (the value before changes).
    pub fn checkpoint_value(&self, name: &str) -> Option<&Vec<u8>> {
        self.checkpoint_values.get(name)
    }

    /// Diff the current bank state against the checkpoint, returning
    /// registers that differ.
    pub fn diff_against_checkpoint(
        &self,
        bank: &PcodeRegisterBank,
    ) -> Vec<(String, Option<Vec<u8>>, Option<Vec<u8>>)> {
        let mut result = Vec::new();
        let all_names: BTreeSet<String> = self
            .checkpoint_values
            .keys()
            .chain(bank.values.keys())
            .cloned()
            .collect();

        for name in &all_names {
            let old = self.checkpoint_values.get(name);
            let new = bank.values.get(name);
            if old != new {
                result.push((name.clone(), old.cloned(), new.cloned()));
            }
        }
        result
    }
}

// ============================================================================
// RegisterBankMerger -- 3-way merge support
// ============================================================================

/// The strategy for resolving register merge conflicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MergeStrategy {
    /// Prefer values from the "ours" side.
    PreferOurs,
    /// Prefer values from the "theirs" side.
    PreferTheirs,
    /// Keep the base value on conflict (effectively reject both changes).
    KeepBase,
    /// Mark conflicting registers as unknown.
    MarkUnknown,
}

/// The result of a 3-way register bank merge.
#[derive(Debug, Clone, Default)]
pub struct RegisterBankMerge3Result {
    /// Registers that were the same in both branches (auto-merged).
    pub unchanged: Vec<String>,
    /// Registers changed only in "ours" (auto-merged).
    pub ours_only: Vec<String>,
    /// Registers changed only in "theirs" (auto-merged).
    pub theirs_only: Vec<String>,
    /// Registers changed in both branches (conflict).
    pub conflicts: Vec<RegisterMerge3Conflict>,
    /// Registers added in either branch.
    pub added: Vec<String>,
    /// Registers removed in either branch.
    pub removed: Vec<String>,
}

/// A conflict in a 3-way merge.
#[derive(Debug, Clone)]
pub struct RegisterMerge3Conflict {
    /// The register name.
    pub name: String,
    /// The base value.
    pub base: Option<Vec<u8>>,
    /// The "ours" value.
    pub ours: Option<Vec<u8>>,
    /// The "theirs" value.
    pub theirs: Option<Vec<u8>>,
}

impl RegisterBankMerge3Result {
    /// Whether there are any conflicts.
    pub fn has_conflicts(&self) -> bool {
        !self.conflicts.is_empty()
    }

    /// The total number of registers processed.
    pub fn total(&self) -> usize {
        self.unchanged.len()
            + self.ours_only.len()
            + self.theirs_only.len()
            + self.conflicts.len()
            + self.added.len()
            + self.removed.len()
    }
}

/// Perform a 3-way merge of register banks.
///
/// Given a `base` bank and two derived banks (`ours` and `theirs`),
/// determines which registers changed independently vs. in conflict.
/// Returns a result describing the merge without modifying any bank.
///
/// Ported from Ghidra's register merge logic used in trace merge/undo.
pub fn merge_register_banks_3way(
    base: &PcodeRegisterBank,
    ours: &PcodeRegisterBank,
    theirs: &PcodeRegisterBank,
) -> RegisterBankMerge3Result {
    let mut result = RegisterBankMerge3Result::default();

    let all_names: BTreeSet<String> = base
        .register_names()
        .into_iter()
        .chain(ours.register_names().into_iter())
        .chain(theirs.register_names().into_iter())
        .map(|s| s.to_string())
        .collect();

    for name in &all_names {
        let base_val = base.read_register(name);
        let ours_val = ours.read_register(name);
        let theirs_val = theirs.read_register(name);

        let ours_changed = ours_val != base_val;
        let theirs_changed = theirs_val != base_val;

        if !ours_changed && !theirs_changed {
            if base_val.is_some() {
                result.unchanged.push(name.clone());
            }
        } else if ours_changed && !theirs_changed {
            result.ours_only.push(name.clone());
        } else if !ours_changed && theirs_changed {
            result.theirs_only.push(name.clone());
        } else {
            // Both changed
            if ours_val == theirs_val {
                // Both changed to the same value -- no conflict
                result.ours_only.push(name.clone());
            } else {
                result.conflicts.push(RegisterMerge3Conflict {
                    name: name.clone(),
                    base: base_val.clone(),
                    ours: ours_val.clone(),
                    theirs: theirs_val.clone(),
                });
            }
        }

        // Track adds and removes
        if base_val.is_none() && (ours_val.is_some() || theirs_val.is_some()) {
            result.added.push(name.clone());
        }
        if base_val.is_some() && ours_val.is_none() && theirs_val.is_none() {
            result.removed.push(name.clone());
        }
    }

    result
}

/// Apply a 3-way merge result with the given strategy, writing
/// resolved values into the `output` bank.
pub fn apply_merge_3way(
    base: &PcodeRegisterBank,
    ours: &PcodeRegisterBank,
    theirs: &PcodeRegisterBank,
    result: &RegisterBankMerge3Result,
    strategy: MergeStrategy,
    output: &mut PcodeRegisterBank,
) {
    // Apply unchanged (keep base value)
    for name in &result.unchanged {
        if let Some(val) = base.read_register(name) {
            output.write_register(name, &val);
        }
    }

    // Apply ours-only changes
    for name in &result.ours_only {
        if let Some(val) = ours.read_register(name) {
            output.write_register(name, &val);
        }
    }

    // Apply theirs-only changes
    for name in &result.theirs_only {
        if let Some(val) = theirs.read_register(name) {
            output.write_register(name, &val);
        }
    }

    // Apply conflicts per strategy
    for conflict in &result.conflicts {
        let resolved = match strategy {
            MergeStrategy::PreferOurs => conflict.ours.as_ref(),
            MergeStrategy::PreferTheirs => conflict.theirs.as_ref(),
            MergeStrategy::KeepBase => conflict.base.as_ref(),
            MergeStrategy::MarkUnknown => None,
        };
        if let Some(val) = resolved {
            output.write_register(&conflict.name, val);
        }
    }

    // Apply additions (prefer ours if both added)
    for name in &result.added {
        let val = ours
            .read_register(name)
            .or_else(|| theirs.read_register(name));
        if let Some(val) = val {
            output.write_register(name, &val);
        }
    }
}

// ============================================================================
// RegisterSerializationUtils -- serialization helpers
// ============================================================================

/// Utilities for serializing and deserializing register data.
///
/// Ported from Ghidra's register serialization utilities used for
/// trace persistence and network transfer.
pub struct RegisterSerializationUtils;

impl RegisterSerializationUtils {
    /// Encode a register value as a hex string (little-endian byte order).
    pub fn encode_value_hex(value: &[u8]) -> String {
        value.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Decode a hex string into a register value (little-endian byte order).
    pub fn decode_value_hex(hex: &str) -> Result<Vec<u8>, String> {
        if hex.len() % 2 != 0 {
            return Err("hex string must have even length".into());
        }
        (0..hex.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&hex[i..i + 2], 16)
                    .map_err(|e| format!("invalid hex at position {}: {}", i, e))
            })
            .collect()
    }

    /// Encode all register values from a bank as a map of name -> hex string.
    pub fn encode_bank_values(bank: &PcodeRegisterBank) -> BTreeMap<String, String> {
        bank.values
            .iter()
            .map(|(name, value)| (name.clone(), Self::encode_value_hex(value)))
            .collect()
    }

    /// Decode a map of name -> hex string into register values and write
    /// them into a bank.
    pub fn decode_bank_values(
        encoded: &BTreeMap<String, String>,
        bank: &mut PcodeRegisterBank,
    ) -> Result<(), String> {
        for (name, hex) in encoded {
            let value = Self::decode_value_hex(hex)?;
            bank.write_register(name, &value);
        }
        Ok(())
    }

    /// Encode a register definition as a portable map.
    pub fn encode_definition(def: &RegisterDefinition) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        map.insert("name".to_string(), def.name.clone());
        map.insert("bit_length".to_string(), def.bit_length.to_string());
        map.insert("bit_offset".to_string(), def.bit_offset.to_string());
        map.insert("group".to_string(), def.group.clone());
        map.insert("big_endian".to_string(), def.big_endian.to_string());
        map.insert("description".to_string(), def.description.clone());
        if let Some(ref cn) = def.connector_name {
            map.insert("connector_name".to_string(), cn.clone());
        }
        map
    }
}

// ============================================================================
// RegisterBankCompression -- compress/decompress register bank data
// ============================================================================

/// Compression format for register bank data.
///
/// Ported from Ghidra's register data serialization used for network
/// transfer and trace persistence. Supports run-length encoding for
/// sparse register banks and delta encoding for incremental updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionFormat {
    /// No compression (raw bytes).
    None,
    /// Run-length encoding for sparse banks.
    RunLength,
    /// Delta encoding relative to a base bank.
    Delta,
}

/// A compressed representation of register bank values.
///
/// Ported from Ghidra's proposed register data compression utilities
/// used when transferring register state between the debugger target
/// and the trace recording infrastructure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressedRegisterBank {
    /// The compression format used.
    pub format: CompressionFormat,
    /// The register names included (in order).
    pub names: Vec<String>,
    /// The compressed data payload.
    pub data: Vec<u8>,
    /// Original total byte count (before compression).
    pub original_size: usize,
}

impl CompressedRegisterBank {
    /// Create a new compressed bank with raw format.
    pub fn new(format: CompressionFormat) -> Self {
        Self {
            format,
            names: Vec::new(),
            data: Vec::new(),
            original_size: 0,
        }
    }

    /// The compression ratio (compressed / original).
    pub fn compression_ratio(&self) -> f64 {
        if self.original_size == 0 {
            return 0.0;
        }
        self.data.len() as f64 / self.original_size as f64
    }

    /// The number of registers in the compressed bank.
    pub fn num_registers(&self) -> usize {
        self.names.len()
    }

    /// Whether the compressed bank is empty.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

/// Utilities for compressing and decompressing register bank data.
///
/// Ported from Ghidra's proposed register data transfer utilities.
pub struct RegisterBankCompression;

impl RegisterBankCompression {
    /// Compress a register bank using the specified format.
    ///
    /// For `CompressionFormat::None`, produces raw bytes.
    /// For `CompressionFormat::RunLength`, uses run-length encoding
    /// for sequences of identical bytes.
    /// For `CompressionFormat::Delta`, stores only differences from
    /// the given base bank.
    pub fn compress(
        bank: &PcodeRegisterBank,
        format: CompressionFormat,
    ) -> CompressedRegisterBank {
        let mut names = Vec::new();
        let mut raw_data = Vec::new();
        for (name, value) in &bank.values {
            names.push(name.clone());
            // 4-byte little-endian length prefix + value bytes
            let len = value.len() as u32;
            raw_data.extend_from_slice(&len.to_le_bytes());
            raw_data.extend_from_slice(value);
        }
        let original_size = raw_data.len();

        let data = match format {
            CompressionFormat::None => raw_data,
            CompressionFormat::RunLength => Self::rle_encode(&raw_data),
            CompressionFormat::Delta => raw_data, // Delta requires base; use raw for now
        };

        CompressedRegisterBank {
            format,
            names,
            data,
            original_size,
        }
    }

    /// Decompress a compressed register bank into a `PcodeRegisterBank`.
    pub fn decompress(
        compressed: &CompressedRegisterBank,
    ) -> Result<PcodeRegisterBank, String> {
        let raw_data = match compressed.format {
            CompressionFormat::None => compressed.data.clone(),
            CompressionFormat::RunLength => Self::rle_decode(&compressed.data)?,
            CompressionFormat::Delta => compressed.data.clone(),
        };

        let mut bank = PcodeRegisterBank::new();
        let mut offset = 0;
        for name in &compressed.names {
            if offset + 4 > raw_data.len() {
                return Err("truncated compressed data".into());
            }
            let len = u32::from_le_bytes([
                raw_data[offset],
                raw_data[offset + 1],
                raw_data[offset + 2],
                raw_data[offset + 3],
            ]) as usize;
            offset += 4;
            if offset + len > raw_data.len() {
                return Err("truncated compressed data".into());
            }
            bank.write_register(name, &raw_data[offset..offset + len]);
            offset += len;
        }
        Ok(bank)
    }

    /// Compress using delta encoding relative to a base bank.
    ///
    /// Only stores registers that differ from the base.
    pub fn compress_delta(
        bank: &PcodeRegisterBank,
        base: &PcodeRegisterBank,
    ) -> CompressedRegisterBank {
        let mut names = Vec::new();
        let mut raw_data = Vec::new();

        for (name, value) in &bank.values {
            let base_val = base.values.get(name);
            if base_val != Some(value) {
                names.push(name.clone());
                let len = value.len() as u32;
                raw_data.extend_from_slice(&len.to_le_bytes());
                raw_data.extend_from_slice(value);
            }
        }
        let original_size = raw_data.len();

        CompressedRegisterBank {
            format: CompressionFormat::Delta,
            names,
            data: raw_data,
            original_size,
        }
    }

    /// Apply a delta-compressed bank on top of a base bank.
    pub fn apply_delta(
        base: &PcodeRegisterBank,
        delta: &CompressedRegisterBank,
    ) -> Result<PcodeRegisterBank, String> {
        if delta.format != CompressionFormat::Delta {
            return Err("expected delta format".into());
        }
        let mut result = base.clone();
        let decompressed = Self::decompress(delta)?;
        // Decompressed bank has values but no definitions, so iterate
        // over the delta names directly
        for name in &delta.names {
            if let Some(val) = decompressed.read_register(name) {
                result.write_register(name, &val);
            }
        }
        Ok(result)
    }

    fn rle_encode(data: &[u8]) -> Vec<u8> {
        if data.is_empty() {
            return Vec::new();
        }
        let mut result = Vec::new();
        let mut i = 0;
        while i < data.len() {
            let byte = data[i];
            let mut count: u8 = 1;
            while i + (count as usize) < data.len()
                && data[i + count as usize] == byte
                && count < 255
            {
                count += 1;
            }
            result.push(count);
            result.push(byte);
            i += count as usize;
        }
        result
    }

    fn rle_decode(data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() % 2 != 0 {
            return Err("invalid RLE data: odd length".into());
        }
        let mut result = Vec::new();
        for chunk in data.chunks(2) {
            let count = chunk[0];
            let byte = chunk[1];
            for _ in 0..count {
                result.push(byte);
            }
        }
        Ok(result)
    }
}

// ============================================================================
// RegisterGroupLayout -- layout algorithm for register group display
// ============================================================================

/// Layout mode for register group display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GroupLayoutMode {
    /// Display registers in a single column.
    SingleColumn,
    /// Display registers in a multi-column grid.
    Grid { columns: usize },
    /// Display registers in a tree hierarchy (parent/child).
    Tree,
}

/// Describes the layout of a register group for display in a UI.
///
/// Ported from Ghidra's proposed register display layout utilities
/// used by the Registers window to organize register groups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterGroupLayout {
    /// The group name.
    pub group_name: String,
    /// The layout mode.
    pub mode: GroupLayoutMode,
    /// The ordered list of register names to display.
    pub entries: Vec<LayoutEntry>,
    /// Whether the group is expanded by default.
    pub expanded: bool,
    /// Display order priority (lower = shown first).
    pub display_order: u32,
}

/// A single entry in a register group layout.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayoutEntry {
    /// The register name.
    pub name: String,
    /// Nesting depth (0 = top-level, 1 = child, etc.).
    pub depth: u32,
    /// Whether this entry has children.
    pub has_children: bool,
    /// The display label (may differ from register name for aliases).
    pub label: String,
}

impl RegisterGroupLayout {
    /// Create a new layout for a group.
    pub fn new(group_name: impl Into<String>) -> Self {
        Self {
            group_name: group_name.into(),
            mode: GroupLayoutMode::SingleColumn,
            entries: Vec::new(),
            expanded: true,
            display_order: 0,
        }
    }

    /// Set the layout mode.
    pub fn with_mode(mut self, mode: GroupLayoutMode) -> Self {
        self.mode = mode;
        self
    }

    /// Set whether expanded by default.
    pub fn with_expanded(mut self, expanded: bool) -> Self {
        self.expanded = expanded;
        self
    }

    /// Set the display order.
    pub fn with_display_order(mut self, order: u32) -> Self {
        self.display_order = order;
        self
    }

    /// Build a layout from a register bank's group and parent/child info.
    pub fn from_bank(bank: &PcodeRegisterBank, group_name: &str) -> Self {
        let mut layout = Self::new(group_name);
        let registers = bank.registers_in_group(group_name);

        for name in &registers {
            let depth = Self::compute_depth(bank, name);
            let children = bank.children_of(name);
            layout.entries.push(LayoutEntry {
                name: name.clone(),
                depth,
                has_children: !children.is_empty(),
                label: name.clone(),
            });
        }

        // Sort: top-level first, then by name within each depth
        layout.entries.sort_by(|a, b| {
            a.depth.cmp(&b.depth).then_with(|| a.name.cmp(&b.name))
        });

        layout
    }

    fn compute_depth(bank: &PcodeRegisterBank, name: &str) -> u32 {
        let mut depth = 0;
        let mut current = name.to_string();
        while let Some(parent) = bank.parent_of(&current) {
            depth += 1;
            current = parent.to_string();
            if depth > 32 {
                break; // safety limit
            }
        }
        depth
    }

    /// The number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the layout has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get only top-level entries (depth 0).
    pub fn top_level_entries(&self) -> Vec<&LayoutEntry> {
        self.entries.iter().filter(|e| e.depth == 0).collect()
    }
}

// ============================================================================
// RegisterAliasResolver -- resolve multi-level alias chains
// ============================================================================

/// Resolves register alias chains to their canonical form.
///
/// Ported from Ghidra's register alias resolution used by
/// `PcodeDebuggerRegistersAccess` to map between target register
/// names, language register names, and alias chains (e.g.,
/// "EAX" -> "RAX" -> "a").
///
/// Unlike the simple alias map in `PcodeRegisterBank`, this supports
/// multi-level chains, transitive resolution, and conflict detection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterAliasResolver {
    /// alias -> canonical mapping (direct aliases).
    aliases: BTreeMap<String, String>,
    /// Reverse mapping: canonical -> all known aliases.
    reverse: BTreeMap<String, Vec<String>>,
}

impl RegisterAliasResolver {
    /// Create a new empty resolver.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an alias mapping. `alias` is an alternative name for `canonical`.
    pub fn add_alias(&mut self, alias: impl Into<String>, canonical: impl Into<String>) {
        let alias = alias.into();
        let canonical = canonical.into();
        self.reverse
            .entry(canonical.clone())
            .or_default()
            .push(alias.clone());
        self.aliases.insert(alias, canonical);
    }

    /// Add aliases from a register bank.
    pub fn add_from_bank(&mut self, bank: &PcodeRegisterBank) {
        for (alias, canonical) in &bank.aliases {
            self.add_alias(alias, canonical);
        }
    }

    /// Resolve a name to its canonical form, following the full chain.
    ///
    /// Returns the canonical name as a `String`, or `None` if a cycle
    /// is detected.
    pub fn resolve(&self, name: &str) -> Option<String> {
        // Follow the chain until we reach a name with no further alias
        let mut current = name.to_string();
        let mut visited = std::collections::HashSet::new();
        visited.insert(name.to_string());
        while let Some(next) = self.aliases.get(&current) {
            if !visited.insert(next.clone()) {
                // Cycle detected
                return None;
            }
            current = next.clone();
        }
        Some(current)
    }

    /// Get all aliases for a canonical name.
    pub fn aliases_of(&self, canonical: &str) -> &[String] {
        self.reverse
            .get(canonical)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Whether the given name is an alias (not a canonical name).
    pub fn is_alias(&self, name: &str) -> bool {
        self.aliases.contains_key(name)
    }

    /// Whether the given name is a canonical name (has aliases).
    pub fn is_canonical(&self, name: &str) -> bool {
        self.reverse.contains_key(name)
    }

    /// The total number of alias mappings.
    pub fn num_aliases(&self) -> usize {
        self.aliases.len()
    }

    /// Check for cycles in the alias graph.
    pub fn has_cycle(&self) -> bool {
        for name in self.aliases.keys() {
            let mut visited = std::collections::HashSet::new();
            visited.insert(name.clone());
            let mut current = name.as_str();
            while let Some(next) = self.aliases.get(current) {
                if !visited.insert(next.clone()) {
                    return true;
                }
                current = next;
            }
        }
        false
    }

    /// Build an alias resolver from a `RegisterMapping`.
    ///
    /// Adds each mapping pair as an alias from the connector name
    /// to the language register name.
    pub fn from_mapping(mapping: &RegisterMapping) -> Self {
        let mut resolver = Self::new();
        for entry in mapping.iter() {
            resolver.add_alias(entry.connector_name.to_string(), entry.lang_name.to_string());
        }
        resolver
    }

    /// Clear all aliases.
    pub fn clear(&mut self) {
        self.aliases.clear();
        self.reverse.clear();
    }
}

// ============================================================================
// Saved Register Map (ported from SavedRegisterMap.java)
// ============================================================================

/// A range mapping from register space to a stack address.
///
/// Ported from Ghidra's `SavedRegisterMap.SavedEntry`. Used when a
/// register's value was saved to the stack by a caller frame, so
/// register reads must be redirected to stack reads during unwinding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedEntry {
    /// The range in register space (start_offset, end_offset inclusive).
    pub from: (u64, u64),
    /// The target address in the stack segment.
    pub to: u64,
}

impl SavedEntry {
    /// Create a new saved entry.
    pub fn new(from_min: u64, from_max: u64, to: u64) -> Self {
        Self {
            from: (from_min, from_max),
            to,
        }
    }

    /// The length of the mapped range.
    pub fn size(&self) -> u64 {
        self.from.1 - self.from.0 + 1
    }

    /// Check if an address falls within the "from" range.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.from.0 && addr <= self.from.1
    }

    /// Truncate the entry to a sub-range (must be enclosed by current range).
    pub fn truncate(&self, range_min: u64, range_max: u64) -> Self {
        let left_offset = range_min - self.from.0;
        Self {
            from: (range_min, range_max),
            to: self.to + left_offset,
        }
    }

    /// Intersect with another range, returning None if no overlap.
    pub fn intersect(&self, other_min: u64, other_max: u64) -> Option<Self> {
        let int_min = self.from.0.max(other_min);
        let int_max = self.from.1.min(other_max);
        if int_min <= int_max {
            Some(self.truncate(int_min, int_max))
        } else {
            None
        }
    }

    /// Truncate to exclude addresses beyond the given max.
    pub fn truncate_max(&self, max: u64) -> Option<Self> {
        if self.from.1 <= max {
            return Some(self.clone());
        }
        if self.from.0 <= max {
            Some(self.truncate(self.from.0, max))
        } else {
            None
        }
    }

    /// Truncate to exclude addresses before the given min.
    pub fn truncate_min(&self, min: u64) -> Option<Self> {
        if self.from.0 >= min {
            return Some(self.clone());
        }
        if self.from.1 >= min {
            Some(self.truncate(min, self.from.1))
        } else {
            None
        }
    }
}

/// A map from registers to physical stack addresses.
///
/// Ported from Ghidra's `SavedRegisterMap`. Used by an unwound frame
/// to ensure that register reads are translated to stack reads when
/// the register's value was saved to the stack by some inner frame.
/// If a register is not saved to the stack, its value is read from
/// the register bank directly.
#[derive(Debug, Clone, Default)]
pub struct SavedRegisterMap {
    /// Mappings keyed by the minimum address of the "from" range.
    entries: BTreeMap<u64, SavedEntry>,
}

impl SavedRegisterMap {
    /// Create a new empty (identity) register map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Map a register range to a stack address range.
    ///
    /// The `from` and `to` ranges must have equal lengths.
    pub fn put_range(&mut self, from_min: u64, from_max: u64, to_min: u64) {
        let entry = SavedEntry::new(from_min, from_max, to_min);
        // Remove any overlapping entries first
        self.remove_overlapping(from_min, from_max);
        self.entries.insert(from_min, entry);
    }

    /// Map a register (by offset and size) to a stack varnode.
    pub fn put_register(&mut self, reg_offset: u64, reg_size: u64, stack_offset: u64) {
        self.put_range(reg_offset, reg_offset + reg_size - 1, stack_offset);
    }

    fn remove_overlapping(&mut self, min: u64, max: u64) {
        let overlapping: Vec<u64> = self
            .entries
            .range(..=max)
            .filter(|(_, e)| e.from.1 >= min)
            .map(|(k, _)| *k)
            .collect();
        for key in overlapping {
            self.entries.remove(&key);
        }
    }

    /// Look up whether an address should be redirected and return
    /// (stack_address, size) if so.
    pub fn lookup(&self, addr: u64) -> Option<(u64, u64)> {
        // Find the entry whose range contains addr
        for (_, entry) in self.entries.range(..=addr).rev() {
            if entry.contains(addr) {
                let offset = addr - entry.from.0;
                let remaining = entry.from.1 - addr + 1;
                return Some((entry.to + offset, remaining));
            }
            break;
        }
        None
    }

    /// Check if a register address is saved to the stack.
    pub fn is_saved(&self, addr: u64) -> bool {
        self.lookup(addr).is_some()
    }

    /// Fork (copy) this register map.
    pub fn fork(&self) -> Self {
        Self {
            entries: self.entries.clone(),
        }
    }

    /// The number of entries in the map.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the map is empty (identity mapping).
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate over all saved entries.
    pub fn iter(&self) -> impl Iterator<Item = &SavedEntry> {
        self.entries.values()
    }
}

// ============================================================================
// Register Mapper (ported from RegisterMapper.java / DefaultRegisterMapper)
// ============================================================================

/// A trait for mapping register names and values between language
/// and connector conventions.
///
/// Ported from Ghidra's `RegisterMapper` interface. Implementations
/// translate register names and values between the Ghidra language
/// model and a target connector (e.g., GDB remote protocol).
pub trait RegisterMapper {
    /// Map a language register name to a connector register name.
    fn map_name(&self, name: &str) -> String;

    /// Map a connector register name back to a language register name.
    fn map_name_back(&self, name: &str) -> String;

    /// Map a register value from language format to connector format.
    ///
    /// The default implementation returns the value unchanged.
    fn map_value(&self, _name: &str, value: &[u8]) -> Vec<u8> {
        value.to_vec()
    }

    /// Map a register value from connector format back to language format.
    ///
    /// The default implementation returns the value unchanged.
    fn map_value_back(&self, _name: &str, value: &[u8]) -> Vec<u8> {
        value.to_vec()
    }
}

/// The default (identity) register mapper.
///
/// Ported from Ghidra's `DefaultRegisterMapper`. Performs no
/// translation -- names and values pass through unchanged.
#[derive(Debug, Clone)]
pub struct DefaultRegisterMapper {
    /// The language ID for context (unused in identity mapping).
    pub language_id: String,
}

impl DefaultRegisterMapper {
    /// Create a new identity register mapper.
    pub fn new(language_id: impl Into<String>) -> Self {
        Self {
            language_id: language_id.into(),
        }
    }
}

impl RegisterMapper for DefaultRegisterMapper {
    fn map_name(&self, name: &str) -> String {
        name.to_string()
    }

    fn map_name_back(&self, name: &str) -> String {
        name.to_string()
    }
}

// ============================================================================
// Register Row (ported from RegisterRow.java)
// ============================================================================

/// A single row in a register display table.
///
/// Ported from Ghidra's `RegisterRow`. Represents one register
/// for display in a debugger register panel, including its name,
/// current value, and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRow {
    /// The register name (canonical).
    pub name: String,
    /// The display name (may include alias or group prefix).
    pub display_name: String,
    /// The register bit length.
    pub bit_length: u32,
    /// The current value as raw bytes (big-endian).
    pub value: Option<Vec<u8>>,
    /// The group this register belongs to.
    pub group: String,
    /// The nesting depth (for sub-registers).
    pub depth: u32,
    /// Whether this register's value has changed since last stop.
    pub changed: bool,
    /// Whether this row is currently visible/expanded.
    pub visible: bool,
}

impl RegisterRow {
    /// Create a new register row.
    pub fn new(
        name: impl Into<String>,
        display_name: impl Into<String>,
        bit_length: u32,
        group: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            display_name: display_name.into(),
            bit_length,
            value: None,
            group: group.into(),
            depth: 0,
            changed: false,
            visible: true,
        }
    }

    /// Set the value.
    pub fn with_value(mut self, value: Vec<u8>) -> Self {
        self.value = Some(value);
        self
    }

    /// Set the depth.
    pub fn with_depth(mut self, depth: u32) -> Self {
        self.depth = depth;
        self
    }

    /// Mark this register as changed.
    pub fn mark_changed(&mut self) {
        self.changed = true;
    }

    /// Clear the changed flag.
    pub fn clear_changed(&mut self) {
        self.changed = false;
    }

    /// Get the value as a hex string.
    pub fn value_hex(&self) -> String {
        match &self.value {
            Some(v) => v.iter().map(|b| format!("{:02x}", b)).collect(),
            None => "??".to_string(),
        }
    }

    /// The byte length of the register.
    pub fn byte_length(&self) -> u32 {
        (self.bit_length + 7) / 8
    }
}

/// Build a set of `RegisterRow` entries from a `PcodeRegisterBank`.
///
/// This produces the display rows for a register panel, organized
/// by group and respecting parent/child relationships.
pub fn build_register_rows(bank: &PcodeRegisterBank, group_name: &str) -> Vec<RegisterRow> {
    let mut rows = Vec::new();
    for (name, def) in bank.definitions() {
        if def.group != group_name {
            continue;
        }
        let depth = bank.compute_depth(name);
        let value = bank.read_register(name);
        let display_name = if depth > 0 {
            format!("{}{}", "  ".repeat(depth as usize), name)
        } else {
            name.clone()
        };
        let mut row = RegisterRow::new(name.as_str(), display_name, def.bit_length, def.group.as_str())
            .with_depth(depth);
        if let Some(v) = value {
            row = row.with_value(v);
        }
        rows.push(row);
    }
    rows
}

/// A snapshot of all register values at a point in time.
///
/// Ported from Ghidra's register snapshot concept in the debug framework.
/// Captures the complete register state for comparison or restoration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegisterStateSnapshot {
    /// Register name -> value bytes.
    pub values: BTreeMap<String, Vec<u8>>,
    /// The snap (time) at which this snapshot was taken.
    pub snap: i64,
    /// The thread key this snapshot belongs to.
    pub thread_key: Option<i64>,
}

impl RegisterStateSnapshot {
    /// Create a new empty snapshot at the given snap.
    pub fn new(snap: i64) -> Self {
        Self {
            snap,
            ..Default::default()
        }
    }

    /// Capture the current state of a register bank.
    pub fn capture(bank: &PcodeRegisterBank, snap: i64) -> Self {
        let mut snapshot = Self::new(snap);
        for (name, _) in bank.definitions() {
            if let Some(value) = bank.read_register(name) {
                snapshot.values.insert(name.clone(), value);
            }
        }
        snapshot
    }

    /// Set the thread key.
    pub fn with_thread_key(mut self, key: i64) -> Self {
        self.thread_key = Some(key);
        self
    }

    /// Get a register value.
    pub fn get(&self, name: &str) -> Option<&Vec<u8>> {
        self.values.get(name)
    }

    /// Compute a diff between this snapshot and another.
    pub fn diff(&self, other: &RegisterStateSnapshot) -> RegisterSnapshotDiff {
        let mut changes = BTreeMap::new();
        for (name, val) in &self.values {
            match other.values.get(name) {
                Some(other_val) if val != other_val => {
                    changes.insert(
                        name.clone(),
                        RegisterDiffEntry {
                            old_value: Some(val.clone()),
                            new_value: Some(other_val.clone()),
                        },
                    );
                }
                None => {
                    changes.insert(
                        name.clone(),
                        RegisterDiffEntry {
                            old_value: Some(val.clone()),
                            new_value: None,
                        },
                    );
                }
                _ => {}
            }
        }
        for name in other.values.keys() {
            if !self.values.contains_key(name) {
                changes.insert(
                    name.clone(),
                    RegisterDiffEntry {
                        old_value: None,
                        new_value: other.values.get(name).cloned(),
                    },
                );
            }
        }
        RegisterSnapshotDiff {
            from_snap: self.snap,
            to_snap: other.snap,
            changes,
        }
    }
}

/// A single entry in a register snapshot diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterDiffEntry {
    /// The old value (None if register didn't exist before).
    pub old_value: Option<Vec<u8>>,
    /// The new value (None if register was removed).
    pub new_value: Option<Vec<u8>>,
}

/// A diff between two register state snapshots.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSnapshotDiff {
    /// The snap of the "from" snapshot.
    pub from_snap: i64,
    /// The snap of the "to" snapshot.
    pub to_snap: i64,
    /// Map of register name -> changed entry.
    pub changes: BTreeMap<String, RegisterDiffEntry>,
}

impl RegisterSnapshotDiff {
    /// Whether there are any changes.
    pub fn has_changes(&self) -> bool {
        !self.changes.is_empty()
    }

    /// The number of changed registers.
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// Whether the diff is empty (no changes).
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
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
        before.record("RBX", vec![5, 6, 7, 8]);
        let mut after = RegisterSnapshot::new("a", 1);
        after.record("RBX", vec![5, 6, 7, 8]);
        after.record("RCX", vec![9, 9, 9, 9]);

        let diff = RegisterBankDiff::compute(&before, &after);
        assert!(diff.changed.is_empty());
        assert_eq!(diff.appeared, vec!["RCX"]);
        assert_eq!(diff.disappeared, vec!["RAX"]); // RAX in before but not in after
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

    // -- RegisterContextTracker --

    #[test]
    fn test_context_tracker_basic() {
        let mut tracker = RegisterContextTracker::new();
        tracker.record(0, "TMode", 0);
        tracker.record(10, "TMode", 1);
        tracker.record(20, "TMode", 0);

        assert_eq!(tracker.get("TMode"), Some(0));
        assert_eq!(tracker.get_at_snap("TMode", 5), Some(0));
        assert_eq!(tracker.get_at_snap("TMode", 15), Some(1));
        assert_eq!(tracker.get_at_snap("TMode", 25), Some(0));
    }

    #[test]
    fn test_context_tracker_history() {
        let mut tracker = RegisterContextTracker::new();
        tracker.record(0, "TMode", 0);
        tracker.record(10, "TMode", 1);
        tracker.record(20, "AddrSize", 32);

        assert_eq!(tracker.history_for("TMode").len(), 2);
        assert_eq!(tracker.fields().len(), 2);
    }

    #[test]
    fn test_context_tracker_diff() {
        let mut tracker = RegisterContextTracker::new();
        tracker.record(0, "TMode", 0);
        tracker.record(10, "TMode", 1);

        let diffs = tracker.diff_since_snap(0);
        assert!(diffs.contains_key("TMode"));
        assert_eq!(diffs["TMode"], (Some(0), Some(1)));
    }

    #[test]
    fn test_context_tracker_max_depth() {
        let mut tracker = RegisterContextTracker::new().with_max_depth(2);
        tracker.record(0, "X", 1);
        tracker.record(1, "X", 2);
        tracker.record(2, "X", 3);

        assert_eq!(tracker.history_len(), 2);
        // Snap 0 was evicted
        assert_eq!(tracker.get_at_snap("X", 0), None);
        assert_eq!(tracker.get_at_snap("X", 1), Some(2));
    }

    // -- RegisterBankValidator --

    #[test]
    fn test_validator_range() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.write_register("RAX", &100u64.to_le_bytes());

        let mut validator = RegisterBankValidator::new();
        validator.add_range_rule("RAX", 0, 200);
        assert!(validator.is_valid(&bank));

        validator.add_range_rule("RAX", 0, 50);
        assert!(!validator.is_valid(&bank));
    }

    #[test]
    fn test_validator_alignment() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RSP", 64, "GPR");
        bank.write_register("RSP", &0x1000u64.to_le_bytes());

        let mut validator = RegisterBankValidator::new();
        validator.add_alignment_rule("RSP", 16);
        assert!(validator.is_valid(&bank));

        bank.write_register("RSP", &0x1001u64.to_le_bytes());
        assert!(!validator.is_valid(&bank));
    }

    #[test]
    fn test_validator_nonzero() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RCX", 64, "GPR");

        let mut validator = RegisterBankValidator::new();
        validator.add_nonzero_rule("RCX");

        // No value = not valid
        assert!(!validator.is_valid(&bank));

        bank.write_register("RCX", &[0; 8]);
        assert!(!validator.is_valid(&bank));

        bank.write_register("RCX", &1u64.to_le_bytes());
        assert!(validator.is_valid(&bank));
    }

    #[test]
    fn test_validator_one_of() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("FLAGS", 32, "GPR");
        bank.write_register("FLAGS", &0x200u32.to_le_bytes());

        let mut validator = RegisterBankValidator::new();
        validator.add_rule(
            "FLAGS",
            RegisterValidationRule::OneOf {
                values: vec![0x200u32.to_le_bytes().to_vec(), 0x202u32.to_le_bytes().to_vec()],
            },
        );
        assert!(validator.is_valid(&bank));

        bank.write_register("FLAGS", &0x100u32.to_le_bytes());
        assert!(!validator.is_valid(&bank));
    }

    // -- RegisterValueCache --

    #[test]
    fn test_cache_basic() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.write_register("RAX", &[0x42; 8]);

        let mut cache = RegisterValueCache::new();
        assert_eq!(cache.read(&bank, "RAX"), Some(vec![0x42; 8]));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_cache_write_flush() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.write_register("RAX", &[0x42; 8]);

        let mut cache = RegisterValueCache::new();
        cache.read(&bank, "RAX"); // prime cache

        cache.write("RAX", vec![0xFF; 8]);
        assert!(cache.has_dirty());
        assert_eq!(cache.dirty_registers().len(), 1);

        // Bank still has old value
        assert_eq!(bank.read_register("RAX"), Some(vec![0x42; 8]));

        cache.flush(&mut bank);
        assert_eq!(bank.read_register("RAX"), Some(vec![0xFF; 8]));
        assert!(!cache.has_dirty());
    }

    #[test]
    fn test_cache_pin() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.write_register("RAX", &[0x42; 8]);

        let mut cache = RegisterValueCache::new();
        cache.pin("RAX");

        // Pinned registers are always fetched fresh
        cache.read(&bank, "RAX");
        assert_eq!(cache.len(), 0); // not cached
    }

    #[test]
    fn test_cache_invalidate() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.write_register("RAX", &[0x42; 8]);

        let mut cache = RegisterValueCache::new();
        cache.read(&bank, "RAX");
        assert_eq!(cache.len(), 1);

        cache.invalidate("RAX");
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_sync_from_bank() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("RBX", 64, "GPR");
        bank.write_register("RAX", &[0x42; 8]);
        bank.write_register("RBX", &[0xAA; 8]);

        let mut cache = RegisterValueCache::new();
        cache.read(&bank, "RAX"); // cache RAX

        // Modify bank directly
        bank.write_register("RAX", &[0xFF; 8]);

        // Dirty cache entries should not be overwritten
        cache.write("RAX", vec![0x99; 8]);
        cache.sync_from_bank(&bank);

        // RAX is dirty, so sync shouldn't overwrite it
        assert_eq!(cache.read(&bank, "RAX"), Some(vec![0x99; 8]));
        // RBX should be synced from bank
        assert_eq!(cache.read(&bank, "RBX"), Some(vec![0xAA; 8]));
    }

    // -- RegisterBankSnapshot --

    #[test]
    fn test_bank_snapshot_capture_restore() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("RBX", 64, "GPR");
        bank.write_register("RAX", &[0x42; 8]);
        bank.write_register("RBX", &[0xAA; 8]);
        bank.add_alias("EAX", "RAX");

        let snap = RegisterBankSnapshot::capture("test_snap", 10, &bank);
        assert_eq!(snap.num_values(), 2);
        assert_eq!(snap.num_definitions(), 2);
        assert_eq!(snap.snap, 10);

        let restored = snap.restore();
        assert_eq!(restored.read_register("RAX"), Some(vec![0x42; 8]));
        assert_eq!(restored.read_register("EAX"), Some(vec![0x42; 8]));
    }

    // -- merge_register_banks --

    #[test]
    fn test_merge_register_banks_no_conflict() {
        let mut a = PcodeRegisterBank::new();
        a.define("RAX", 64, "GPR");
        a.write_register("RAX", &[0x42; 8]);

        let mut b = PcodeRegisterBank::new();
        b.define("RAX", 64, "GPR");
        b.write_register("RAX", &[0x42; 8]);

        let result = merge_register_banks(&a, &b, true);
        assert!(!result.has_conflicts());
        assert_eq!(result.merged.len(), 1);
    }

    #[test]
    fn test_merge_register_banks_with_conflict() {
        let mut a = PcodeRegisterBank::new();
        a.define("RAX", 64, "GPR");
        a.write_register("RAX", &[0x42; 8]);

        let mut b = PcodeRegisterBank::new();
        b.define("RAX", 64, "GPR");
        b.write_register("RAX", &[0xFF; 8]);

        let result = merge_register_banks(&a, &b, true);
        assert!(result.has_conflicts());
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].name, "RAX");
    }

    #[test]
    fn test_merge_register_banks_disjoint() {
        let mut a = PcodeRegisterBank::new();
        a.define("RAX", 64, "GPR");
        a.write_register("RAX", &[0x42; 8]);

        let mut b = PcodeRegisterBank::new();
        b.define("RBX", 64, "GPR");
        b.write_register("RBX", &[0xAA; 8]);

        let result = merge_register_banks(&a, &b, true);
        assert!(!result.has_conflicts());
        assert_eq!(result.merged.len(), 2);
    }

    // -- RegisterAccessError --

    #[test]
    fn test_register_access_error_display() {
        let e = RegisterAccessError::NoTarget;
        assert_eq!(format!("{}", e), "no target connected");

        let e2 = RegisterAccessError::RegisterNotFound("RAX".into());
        assert!(format!("{}", e2).contains("RAX"));
    }

    // -- RegisterBankIterator --

    #[test]
    fn test_register_bank_iterator() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("RBX", 64, "GPR");
        bank.define("XMM0", 128, "Vector");
        bank.write_register("RAX", &[0x42; 8]);

        let mut iter = RegisterBankIterator::new(&bank);
        let mut count = 0;
        while let Some(entry) = iter.next() {
            if entry.name == "RAX" {
                assert!(entry.value.is_some());
            } else {
                assert!(entry.value.is_none());
            }
            count += 1;
        }
        assert_eq!(count, 3);
    }

    #[test]
    fn test_register_bank_iterator_filter_group() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("RBX", 64, "GPR");
        bank.define("XMM0", 128, "Vector");

        let iter = RegisterBankIterator::new(&bank);
        let gpr_entries = iter.filter_group("GPR");
        assert_eq!(gpr_entries.len(), 2);
    }

    #[test]
    fn test_register_bank_iterator_filter_known() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("RBX", 64, "GPR");
        bank.write_register("RAX", &[0x42; 8]);

        let iter = RegisterBankIterator::new(&bank);
        let known = iter.filter_known();
        assert_eq!(known.len(), 1);
        assert_eq!(known[0].name, "RAX");
    }

    #[test]
    fn test_register_value_iterator() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("RBX", 64, "GPR");
        bank.write_register("RAX", &[0x42; 8]);
        bank.write_register("RBX", &[0xAA; 8]);

        let vals: Vec<_> = RegisterValueIterator::new(&bank).collect();
        assert_eq!(vals.len(), 2);
    }

    // -- RegisterChangeTracker --

    #[test]
    fn test_change_tracker_basic() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("RBX", 64, "GPR");
        bank.write_register("RAX", &[0x42; 8]);

        let mut tracker = RegisterChangeTracker::from_bank(&bank);
        assert!(!tracker.is_dirty());

        bank.write_register("RAX", &[0xFF; 8]);
        tracker.record_write("RAX", vec![0xFF; 8]);

        assert!(tracker.is_dirty());
        assert_eq!(tracker.num_changes(), 1);
        assert_eq!(tracker.changed_names(), vec!["RAX"]);
    }

    #[test]
    fn test_change_tracker_apply() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.write_register("RAX", &[0x42; 8]);

        let mut tracker = RegisterChangeTracker::from_bank(&bank);
        bank.write_register("RAX", &[0xFF; 8]);
        tracker.record_write("RAX", vec![0xFF; 8]);

        // Apply deltas
        tracker.apply_to(&mut bank);
        assert!(!tracker.is_dirty());
        assert_eq!(bank.read_register("RAX"), Some(vec![0xFF; 8]));
    }

    #[test]
    fn test_change_tracker_rollback() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.write_register("RAX", &[0x42; 8]);

        let mut tracker = RegisterChangeTracker::from_bank(&bank);
        bank.write_register("RAX", &[0xFF; 8]);
        tracker.record_write("RAX", vec![0xFF; 8]);

        // Rollback should restore original value
        tracker.rollback(&mut bank);
        assert!(!tracker.is_dirty());
        assert_eq!(bank.read_register("RAX"), Some(vec![0x42; 8]));
    }

    #[test]
    fn test_change_tracker_diff_against_checkpoint() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("RBX", 64, "GPR");
        bank.write_register("RAX", &[0x42; 8]);
        bank.write_register("RBX", &[0xAA; 8]);

        let mut tracker = RegisterChangeTracker::from_bank(&bank);
        bank.write_register("RAX", &[0xFF; 8]);

        let diffs = tracker.diff_against_checkpoint(&bank);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].0, "RAX");
        assert_eq!(diffs[0].1, Some(vec![0x42; 8]));
        assert_eq!(diffs[0].2, Some(vec![0xFF; 8]));
    }

    #[test]
    fn test_change_tracker_checkpoint() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.write_register("RAX", &[0x42; 8]);

        let mut tracker = RegisterChangeTracker::from_bank(&bank);
        tracker.record_write("RAX", vec![0xFF; 8]);

        // Create new checkpoint -- clears deltas
        tracker.checkpoint(&bank);
        assert!(!tracker.is_dirty());
        assert_eq!(tracker.num_changes(), 0);
    }

    // -- merge_register_banks_3way --

    #[test]
    fn test_3way_merge_no_changes() {
        let mut base = PcodeRegisterBank::new();
        base.define("RAX", 64, "GPR");
        base.write_register("RAX", &[0x42; 8]);

        let result = merge_register_banks_3way(&base, &base, &base);
        assert!(!result.has_conflicts());
        assert_eq!(result.unchanged.len(), 1);
    }

    #[test]
    fn test_3way_merge_ours_only() {
        let mut base = PcodeRegisterBank::new();
        base.define("RAX", 64, "GPR");
        base.write_register("RAX", &[0x42; 8]);

        let mut ours = PcodeRegisterBank::new();
        ours.define("RAX", 64, "GPR");
        ours.write_register("RAX", &[0xFF; 8]);

        let result = merge_register_banks_3way(&base, &ours, &base);
        assert!(!result.has_conflicts());
        assert_eq!(result.ours_only.len(), 1);
    }

    #[test]
    fn test_3way_merge_conflict() {
        let mut base = PcodeRegisterBank::new();
        base.define("RAX", 64, "GPR");
        base.write_register("RAX", &[0x42; 8]);

        let mut ours = PcodeRegisterBank::new();
        ours.define("RAX", 64, "GPR");
        ours.write_register("RAX", &[0xAA; 8]);

        let mut theirs = PcodeRegisterBank::new();
        theirs.define("RAX", 64, "GPR");
        theirs.write_register("RAX", &[0xBB; 8]);

        let result = merge_register_banks_3way(&base, &ours, &theirs);
        assert!(result.has_conflicts());
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].name, "RAX");
    }

    #[test]
    fn test_3way_merge_same_change() {
        let mut base = PcodeRegisterBank::new();
        base.define("RAX", 64, "GPR");
        base.write_register("RAX", &[0x42; 8]);

        let mut ours = PcodeRegisterBank::new();
        ours.define("RAX", 64, "GPR");
        ours.write_register("RAX", &[0xFF; 8]);

        // Both changed to the same value -- no conflict
        let result = merge_register_banks_3way(&base, &ours, &ours);
        assert!(!result.has_conflicts());
        assert_eq!(result.ours_only.len(), 1);
    }

    #[test]
    fn test_apply_merge_3way_prefer_ours() {
        let mut base = PcodeRegisterBank::new();
        base.define("RAX", 64, "GPR");
        base.write_register("RAX", &[0x42; 8]);

        let mut ours = PcodeRegisterBank::new();
        ours.define("RAX", 64, "GPR");
        ours.write_register("RAX", &[0xAA; 8]);

        let mut theirs = PcodeRegisterBank::new();
        theirs.define("RAX", 64, "GPR");
        theirs.write_register("RAX", &[0xBB; 8]);

        let result = merge_register_banks_3way(&base, &ours, &theirs);
        let mut output = PcodeRegisterBank::new();
        output.define("RAX", 64, "GPR");
        apply_merge_3way(&base, &ours, &theirs, &result, MergeStrategy::PreferOurs, &mut output);

        assert_eq!(output.read_register("RAX"), Some(vec![0xAA; 8]));
    }

    #[test]
    fn test_apply_merge_3way_mark_unknown() {
        let mut base = PcodeRegisterBank::new();
        base.define("RAX", 64, "GPR");
        base.write_register("RAX", &[0x42; 8]);

        let mut ours = PcodeRegisterBank::new();
        ours.define("RAX", 64, "GPR");
        ours.write_register("RAX", &[0xAA; 8]);

        let mut theirs = PcodeRegisterBank::new();
        theirs.define("RAX", 64, "GPR");
        theirs.write_register("RAX", &[0xBB; 8]);

        let result = merge_register_banks_3way(&base, &ours, &theirs);
        let mut output = PcodeRegisterBank::new();
        output.define("RAX", 64, "GPR");
        apply_merge_3way(&base, &ours, &theirs, &result, MergeStrategy::MarkUnknown, &mut output);

        // MarkUnknown doesn't write the conflicting value
        assert!(output.read_register("RAX").is_none());
    }

    // -- RegisterSerializationUtils --

    #[test]
    fn test_serialization_encode_decode_hex() {
        let value = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let hex = RegisterSerializationUtils::encode_value_hex(&value);
        assert_eq!(hex, "deadbeef");

        let decoded = RegisterSerializationUtils::decode_value_hex(&hex).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_serialization_decode_invalid_hex() {
        assert!(RegisterSerializationUtils::decode_value_hex("xyz").is_err());
        assert!(RegisterSerializationUtils::decode_value_hex("123").is_err());
    }

    #[test]
    fn test_serialization_bank_round_trip() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("RBX", 64, "GPR");
        bank.write_register("RAX", &[0x42; 8]);
        bank.write_register("RBX", &[0xAA; 8]);

        let encoded = RegisterSerializationUtils::encode_bank_values(&bank);
        assert_eq!(encoded.len(), 2);

        let mut restored = PcodeRegisterBank::new();
        RegisterSerializationUtils::decode_bank_values(&encoded, &mut restored).unwrap();

        assert_eq!(restored.read_register("RAX"), Some(vec![0x42; 8]));
        assert_eq!(restored.read_register("RBX"), Some(vec![0xAA; 8]));
    }

    #[test]
    fn test_serialization_encode_definition() {
        let def = RegisterDefinition::new("RAX", 64)
            .with_group("GPR")
            .with_connector_name("rax");

        let encoded = RegisterSerializationUtils::encode_definition(&def);
        assert_eq!(encoded.get("name").unwrap(), "RAX");
        assert_eq!(encoded.get("bit_length").unwrap(), "64");
        assert_eq!(encoded.get("connector_name").unwrap(), "rax");
    }

    // -- RegisterBankCompression --

    #[test]
    fn test_compression_none_round_trip() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("RBX", 64, "GPR");
        bank.write_register("RAX", &[0x42; 8]);
        bank.write_register("RBX", &[0xAA; 8]);

        let compressed = RegisterBankCompression::compress(&bank, CompressionFormat::None);
        assert_eq!(compressed.num_registers(), 2);
        assert!(!compressed.is_empty());

        let restored = RegisterBankCompression::decompress(&compressed).unwrap();
        assert_eq!(restored.read_register("RAX"), Some(vec![0x42; 8]));
        assert_eq!(restored.read_register("RBX"), Some(vec![0xAA; 8]));
    }

    #[test]
    fn test_compression_rle_round_trip() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.write_register("RAX", &[0x00; 8]); // Repeated bytes compress well

        let compressed = RegisterBankCompression::compress(&bank, CompressionFormat::RunLength);
        assert_eq!(compressed.format, CompressionFormat::RunLength);

        let restored = RegisterBankCompression::decompress(&compressed).unwrap();
        assert_eq!(restored.read_register("RAX"), Some(vec![0x00; 8]));
    }

    #[test]
    fn test_compression_delta() {
        let mut base = PcodeRegisterBank::new();
        base.define("RAX", 64, "GPR");
        base.define("RBX", 64, "GPR");
        base.write_register("RAX", &[0x42; 8]);
        base.write_register("RBX", &[0xAA; 8]);

        let mut modified = PcodeRegisterBank::new();
        modified.define("RAX", 64, "GPR");
        modified.define("RBX", 64, "GPR");
        modified.write_register("RAX", &[0xFF; 8]); // Changed
        modified.write_register("RBX", &[0xAA; 8]); // Same as base

        let delta = RegisterBankCompression::compress_delta(&modified, &base);
        assert_eq!(delta.format, CompressionFormat::Delta);
        assert_eq!(delta.num_registers(), 1); // Only RAX changed
        assert!(delta.names.contains(&"RAX".to_string()));

        let restored = RegisterBankCompression::apply_delta(&base, &delta).unwrap();
        assert_eq!(restored.read_register("RAX"), Some(vec![0xFF; 8]));
    }

    #[test]
    fn test_compression_ratio() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.write_register("RAX", &[0x00; 8]);

        let compressed = RegisterBankCompression::compress(&bank, CompressionFormat::RunLength);
        // RLE on 8 zero bytes: 2 bytes (count + value) vs 12 bytes (4 len + 8 data)
        assert!(compressed.compression_ratio() < 1.0);
    }

    // -- RegisterGroupLayout --

    #[test]
    fn test_group_layout_from_bank() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("EAX", 32, "GPR");
        bank.define("RBX", 64, "GPR");
        bank.set_parent("EAX", "RAX");

        let layout = RegisterGroupLayout::from_bank(&bank, "GPR");
        assert_eq!(layout.len(), 3);
        assert!(!layout.is_empty());
        assert_eq!(layout.group_name, "GPR");
    }

    #[test]
    fn test_group_layout_top_level() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("EAX", 32, "GPR");
        bank.define("RBX", 64, "GPR");
        bank.set_parent("EAX", "RAX");

        let layout = RegisterGroupLayout::from_bank(&bank, "GPR");
        let top = layout.top_level_entries();
        // RAX (depth 0) and RBX (depth 0) are top-level; EAX (depth 1) is not
        assert_eq!(top.len(), 2);
        // RAX has EAX as a child
        let rax_entry = top.iter().find(|e| e.name == "RAX").unwrap();
        assert!(rax_entry.has_children);
        // RBX has no children
        let rbx_entry = top.iter().find(|e| e.name == "RBX").unwrap();
        assert!(!rbx_entry.has_children);
    }

    #[test]
    fn test_group_layout_builder() {
        let layout = RegisterGroupLayout::new("Vector")
            .with_mode(GroupLayoutMode::Grid { columns: 4 })
            .with_expanded(false)
            .with_display_order(5);

        assert_eq!(layout.group_name, "Vector");
        assert!(!layout.expanded);
        assert_eq!(layout.display_order, 5);
    }

    // -- RegisterAliasResolver --

    #[test]
    fn test_alias_resolver_basic() {
        let mut resolver = RegisterAliasResolver::new();
        resolver.add_alias("EAX", "RAX");
        resolver.add_alias("a", "RAX");

        assert_eq!(resolver.resolve("EAX"), Some("RAX".to_string()));
        assert_eq!(resolver.resolve("a"), Some("RAX".to_string()));
        assert_eq!(resolver.resolve("RAX"), Some("RAX".to_string()));
        assert_eq!(resolver.resolve("MISSING"), Some("MISSING".to_string()));
    }

    #[test]
    fn test_alias_resolver_chain() {
        let mut resolver = RegisterAliasResolver::new();
        resolver.add_alias("EAX", "RAX");
        resolver.add_alias("a", "EAX");

        // "a" -> "EAX" -> "RAX" (transitive resolution)
        assert_eq!(resolver.resolve("a"), Some("RAX".to_string()));
    }

    #[test]
    fn test_alias_resolver_reverse() {
        let mut resolver = RegisterAliasResolver::new();
        resolver.add_alias("EAX", "RAX");
        resolver.add_alias("a", "RAX");

        let aliases = resolver.aliases_of("RAX");
        assert_eq!(aliases.len(), 2);
        assert!(aliases.contains(&"EAX".to_string()));
        assert!(aliases.contains(&"a".to_string()));
    }

    #[test]
    fn test_alias_resolver_from_bank() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.add_alias("EAX", "RAX");

        let mut resolver = RegisterAliasResolver::new();
        resolver.add_from_bank(&bank);
        assert_eq!(resolver.resolve("EAX"), Some("RAX".to_string()));
    }

    #[test]
    fn test_alias_resolver_cycle_detection() {
        let mut resolver = RegisterAliasResolver::new();
        resolver.add_alias("A", "B");
        resolver.add_alias("B", "A");
        assert!(resolver.has_cycle());
    }

    #[test]
    fn test_alias_resolver_no_cycle() {
        let mut resolver = RegisterAliasResolver::new();
        resolver.add_alias("EAX", "RAX");
        assert!(!resolver.has_cycle());
    }

    // -- SavedRegisterMap --

    #[test]
    fn test_saved_entry_basic() {
        let entry = SavedEntry::new(0x100, 0x107, 0x7FFF_0000);
        assert_eq!(entry.size(), 8);
        assert!(entry.contains(0x100));
        assert!(entry.contains(0x107));
        assert!(!entry.contains(0x108));
    }

    #[test]
    fn test_saved_entry_truncate() {
        let entry = SavedEntry::new(0x100, 0x107, 0x7FFF_0000);
        let truncated = entry.truncate(0x102, 0x105);
        assert_eq!(truncated.from, (0x102, 0x105));
        assert_eq!(truncated.to, 0x7FFF_0002);
    }

    #[test]
    fn test_saved_entry_intersect() {
        let entry = SavedEntry::new(0x100, 0x107, 0x7FFF_0000);
        let inter = entry.intersect(0x105, 0x110).unwrap();
        assert_eq!(inter.from, (0x105, 0x107));
        assert_eq!(inter.to, 0x7FFF_0005);

        assert!(entry.intersect(0x200, 0x300).is_none());
    }

    #[test]
    fn test_saved_entry_truncate_max() {
        let entry = SavedEntry::new(0x100, 0x107, 0x7FFF_0000);
        let truncated = entry.truncate_max(0x103).unwrap();
        assert_eq!(truncated.from, (0x100, 0x103));
        assert!(entry.truncate_max(0x107).is_some());
    }

    #[test]
    fn test_saved_entry_truncate_min() {
        let entry = SavedEntry::new(0x100, 0x107, 0x7FFF_0000);
        let truncated = entry.truncate_min(0x104).unwrap();
        assert_eq!(truncated.from, (0x104, 0x107));
        assert!(entry.truncate_min(0x100).is_some());
    }

    #[test]
    fn test_saved_register_map() {
        let mut map = SavedRegisterMap::new();
        assert!(map.is_empty());

        map.put_register(0x100, 8, 0x7FFF_0000);
        assert_eq!(map.len(), 1);
        assert!(map.is_saved(0x100));
        assert!(map.is_saved(0x107));
        assert!(!map.is_saved(0x108));

        let (stack_addr, size) = map.lookup(0x102).unwrap();
        assert_eq!(stack_addr, 0x7FFF_0002);
        assert_eq!(size, 6);
    }

    #[test]
    fn test_saved_register_map_overwrite() {
        let mut map = SavedRegisterMap::new();
        map.put_register(0x100, 8, 0x7FFF_0000);
        // Overwrite with a smaller range
        map.put_register(0x100, 4, 0x7FFF_1000);
        assert!(map.is_saved(0x100));
        assert!(!map.is_saved(0x104));
    }

    #[test]
    fn test_saved_register_map_fork() {
        let mut map = SavedRegisterMap::new();
        map.put_register(0x100, 8, 0x7FFF_0000);
        let forked = map.fork();
        assert!(forked.is_saved(0x100));
        assert_eq!(forked.len(), 1);
    }

    // -- RegisterMapper / DefaultRegisterMapper --

    #[test]
    fn test_default_register_mapper() {
        let mapper = DefaultRegisterMapper::new("x86:LE:64:default");
        assert_eq!(mapper.map_name("RAX"), "RAX");
        assert_eq!(mapper.map_name_back("RAX"), "RAX");
        assert_eq!(mapper.map_value("RAX", &[1, 2, 3]), vec![1, 2, 3]);
        assert_eq!(mapper.map_value_back("RAX", &[1, 2, 3]), vec![1, 2, 3]);
    }

    // -- RegisterRow --

    #[test]
    fn test_register_row() {
        let row = RegisterRow::new("RAX", "RAX", 64, "GPR")
            .with_value(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(row.name, "RAX");
        assert_eq!(row.bit_length, 64);
        assert_eq!(row.byte_length(), 8);
        assert_eq!(row.value_hex(), "0102030405060708");
    }

    #[test]
    fn test_register_row_changed() {
        let mut row = RegisterRow::new("RAX", "RAX", 64, "GPR");
        assert!(!row.changed);
        row.mark_changed();
        assert!(row.changed);
        row.clear_changed();
        assert!(!row.changed);
    }

    #[test]
    fn test_register_row_no_value() {
        let row = RegisterRow::new("RAX", "RAX", 64, "GPR");
        assert_eq!(row.value_hex(), "??");
    }

    #[test]
    fn test_build_register_rows() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("RBX", 64, "GPR");
        bank.write_register("RAX", &[0xAA; 8]);

        let rows = build_register_rows(&bank, "GPR");
        assert_eq!(rows.len(), 2);
        let rax_row = rows.iter().find(|r| r.name == "RAX").unwrap();
        assert!(rax_row.value.is_some());
    }

    // -- RegisterStateSnapshot / diff --

    #[test]
    fn test_register_state_snapshot() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("RBX", 64, "GPR");
        bank.write_register("RAX", &[0x01; 8]);
        bank.write_register("RBX", &[0x02; 8]);

        let snapshot = RegisterStateSnapshot::capture(&bank, 0);
        assert_eq!(snapshot.snap, 0);
        assert_eq!(snapshot.get("RAX"), Some(&vec![0x01; 8]));
        assert_eq!(snapshot.get("RBX"), Some(&vec![0x02; 8]));
    }

    #[test]
    fn test_register_state_snapshot_diff() {
        let mut snap1 = RegisterStateSnapshot::new(0);
        snap1.values.insert("RAX".to_string(), vec![0x01; 8]);
        snap1.values.insert("RBX".to_string(), vec![0x02; 8]);

        let mut snap2 = RegisterStateSnapshot::new(1);
        snap2.values.insert("RAX".to_string(), vec![0xFF; 8]);
        snap2.values.insert("RBX".to_string(), vec![0x02; 8]);
        snap2.values.insert("RCX".to_string(), vec![0x03; 8]);

        let diff = snap1.diff(&snap2);
        assert!(diff.has_changes());
        assert_eq!(diff.len(), 2); // RAX changed, RCX added

        let rax_change = diff.changes.get("RAX").unwrap();
        assert_eq!(rax_change.old_value, Some(vec![0x01; 8]));
        assert_eq!(rax_change.new_value, Some(vec![0xFF; 8]));

        let rcx_change = diff.changes.get("RCX").unwrap();
        assert!(rcx_change.old_value.is_none());
        assert_eq!(rcx_change.new_value, Some(vec![0x03; 8]));
    }

    #[test]
    fn test_register_state_snapshot_no_diff() {
        let snap1 = RegisterStateSnapshot::new(0);
        let snap2 = RegisterStateSnapshot::new(1);
        let diff = snap1.diff(&snap2);
        assert!(diff.is_empty());
    }

    #[test]
    fn test_compute_depth() {
        let mut bank = PcodeRegisterBank::new();
        bank.define("RAX", 64, "GPR");
        bank.define("EAX", 32, "GPR");
        bank.define("AX", 16, "GPR");
        bank.set_parent("EAX", "RAX");
        bank.set_parent("AX", "EAX");

        assert_eq!(bank.compute_depth("RAX"), 0);
        assert_eq!(bank.compute_depth("EAX"), 1);
        assert_eq!(bank.compute_depth("AX"), 2);
    }
}
