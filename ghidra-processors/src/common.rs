//! Common types for processor module definitions.
//!
//! Provides the shared [`Register`], [`RegisterBank`], [`Language`], and
//! [`ProcessorModule`] trait used by all architecture-specific modules.

use ghidra_core::listing::InstructionMnemonic;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Register definition
// ---------------------------------------------------------------------------

/// A single processor register definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Register {
    /// Human-readable name (e.g., "RAX", "R0", "D0", "PC").
    pub name: String,
    /// Width of the register in bits.
    pub bit_size: u32,
    /// Offset into the register space (unique address for this register).
    pub offset: u64,
    /// For sub-registers, the name of the parent register.
    pub parent: Option<String>,
    /// Least significant bit offset within the parent register (0 for full-width).
    pub lsb: u32,
}

impl Register {
    /// Create a new top-level (non-sub-register) register.
    pub fn new(name: &str, bit_size: u32, offset: u64) -> Self {
        Register {
            name: name.to_string(),
            bit_size,
            offset,
            parent: None,
            lsb: 0,
        }
    }

    /// Create a new sub-register that aliases a portion of a parent register.
    pub fn sub_register(name: &str, bit_size: u32, offset: u64, parent: &str, lsb: u32) -> Self {
        Register {
            name: name.to_string(),
            bit_size,
            offset,
            parent: Some(parent.to_string()),
            lsb,
        }
    }

    /// Size of this register in bytes.
    pub fn byte_size(&self) -> u32 {
        (self.bit_size + 7) / 8
    }
}

// ---------------------------------------------------------------------------
// Register bank
// ---------------------------------------------------------------------------

/// A processor register bank containing all register definitions for an
/// architecture, indexed by name for fast lookup.
#[derive(Debug, Clone, Default)]
pub struct RegisterBank {
    /// All registers indexed by name.
    register_by_name: HashMap<String, Register>,
}

impl RegisterBank {
    /// Create an empty register bank.
    pub fn new() -> Self {
        Self {
            register_by_name: HashMap::new(),
        }
    }

    /// Add a register to the bank.
    pub fn add(&mut self, reg: Register) {
        self.register_by_name.insert(reg.name.clone(), reg);
    }

    /// Add all registers from an iterator.
    pub fn add_all(&mut self, regs: impl IntoIterator<Item = Register>) {
        for reg in regs {
            self.add(reg);
        }
    }

    /// Look up a register by its name (case-sensitive).
    pub fn get(&self, name: &str) -> Option<&Register> {
        self.register_by_name.get(name)
    }

    /// Return all registers that alias (are sub-registers of) the given parent.
    pub fn sub_registers_of(&self, parent_name: &str) -> Vec<&Register> {
        self.register_by_name
            .values()
            .filter(|r| r.parent.as_deref() == Some(parent_name))
            .collect()
    }

    /// Return all top-level registers (those without a parent).
    pub fn top_level_registers(&self) -> Vec<&Register> {
        self.register_by_name
            .values()
            .filter(|r| r.parent.is_none())
            .collect()
    }

    /// Return the total number of defined registers.
    pub fn len(&self) -> usize {
        self.register_by_name.len()
    }

    /// Returns true if the register bank is empty.
    pub fn is_empty(&self) -> bool {
        self.register_by_name.is_empty()
    }

    /// Iterate over all registered registers.
    pub fn iter(&self) -> impl Iterator<Item = &Register> {
        self.register_by_name.values()
    }
}

// ---------------------------------------------------------------------------
// Endianness
// ---------------------------------------------------------------------------

/// Processor endianness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endian {
    /// Little-endian byte order.
    Little,
    /// Big-endian byte order.
    Big,
    /// Bi-endian (configurable at runtime).
    Bi,
}

impl Endian {
    /// Returns true if this is a little-endian variant.
    pub fn is_little(&self) -> bool {
        matches!(self, Endian::Little)
    }

    /// Returns true if this is a big-endian variant.
    pub fn is_big(&self) -> bool {
        matches!(self, Endian::Big)
    }
}

impl std::fmt::Display for Endian {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endian::Little => write!(f, "LE"),
            Endian::Big => write!(f, "BE"),
            Endian::Bi => write!(f, "BI"),
        }
    }
}

// ---------------------------------------------------------------------------
// Language definition
// ---------------------------------------------------------------------------

/// A language/compiler variant for a processor.
///
/// Each processor typically supports multiple languages, corresponding to
/// different variants (32/64-bit, endianness, ISA revisions, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Language {
    /// Unique language ID (e.g., "hexagon:LE:32:V5").
    pub id: String,
    /// Human-readable description.
    pub description: String,
    /// ISA version string.
    pub version: String,
    /// Endianness for this language variant.
    pub endian: Endian,
    /// Pointer size in bits (32 or 64).
    pub pointer_size: u32,
}

impl Language {
    /// Create a new language definition.
    pub fn new(
        id: impl Into<String>,
        description: impl Into<String>,
        version: impl Into<String>,
        endian: Endian,
        pointer_size: u32,
    ) -> Self {
        Language {
            id: id.into(),
            description: description.into(),
            version: version.into(),
            endian,
            pointer_size,
        }
    }
}

// ---------------------------------------------------------------------------
// ProcessorModule trait
// ---------------------------------------------------------------------------

/// The core trait that every processor module must implement.
///
/// Provides the register set, supported language variants, and instruction
/// mnemonics for a given architecture.
pub trait ProcessorModule {
    /// The human-readable name of this processor.
    fn name() -> &'static str;

    /// The complete register bank for this processor.
    fn registers() -> RegisterBank;

    /// The list of supported language/compiler variants.
    fn languages() -> Vec<Language>;

    /// The list of instruction mnemonics supported by this processor.
    fn instructions() -> Vec<InstructionMnemonic>;
}
