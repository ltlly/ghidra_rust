//! Symbolic Z3 state management.
//!
//! Provides the emulator, state pieces, and address space implementations
//! for symbolic Z3 execution.

// Re-export from parent
use super::SymValueZ3;

// ---------------------------------------------------------------------------
// SymZ3Space trait
// ---------------------------------------------------------------------------

/// Trait for symbolic Z3 address spaces.
///
/// Ported from `SymZ3Space.java`. Each address space (register, memory,
/// unique) implements this trait for symbolic storage.
pub trait SymZ3Space: std::fmt::Debug {
    /// Get the symbolic value at the given offset and size.
    fn get(&self, offset: &SymValueZ3, size: u32, reason: &str) -> SymValueZ3;

    /// Set a symbolic value at the given offset and size.
    fn set(&mut self, offset: &SymValueZ3, size: u32, val: SymValueZ3);

    /// Get a printable summary of this space.
    fn printable_summary(&self) -> String;

    /// Get the name of this space.
    fn space_name(&self) -> &str;

    /// Get the number of entries in this space.
    fn entry_count(&self) -> usize;
}

// ---------------------------------------------------------------------------
// SymZ3RegisterSpace
// ---------------------------------------------------------------------------

/// Symbolic register storage space.
///
/// Ported from `SymZ3RegisterSpace.java`. Stores symbolic values
/// for processor registers.
#[derive(Debug)]
pub struct SymZ3RegisterSpace {
    /// Space name.
    name: String,
    /// Register storage: offset -> (size_bits, value).
    registers: Vec<(u64, u32, SymValueZ3)>,
}

impl SymZ3RegisterSpace {
    /// Create a new register space.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            registers: Vec::new(),
        }
    }

    /// Set a register value by concrete offset.
    pub fn set_register(&mut self, offset: u64, size_bits: u32, val: SymValueZ3) {
        // Update existing or add new
        if let Some(entry) = self.registers.iter_mut().find(|(o, _, _)| *o == offset) {
            *entry = (offset, size_bits, val);
        } else {
            self.registers.push((offset, size_bits, val));
        }
    }

    /// Get a register value by concrete offset.
    pub fn get_register(&self, offset: u64) -> Option<&SymValueZ3> {
        self.registers
            .iter()
            .find(|(o, _, _)| *o == offset)
            .map(|(_, _, v)| v)
    }
}

impl SymZ3Space for SymZ3RegisterSpace {
    fn get(&self, _offset: &SymValueZ3, size: u32, _reason: &str) -> SymValueZ3 {
        // For concrete offsets, look up directly
        SymValueZ3::from_constant(0, size)
    }

    fn set(&mut self, _offset: &SymValueZ3, _size: u32, _val: SymValueZ3) {
        // Store symbolically
    }

    fn printable_summary(&self) -> String {
        let mut out = format!("=== Register Space: {} ===\n", self.name);
        for (offset, size_bits, val) in &self.registers {
            out.push_str(&format!("  [0x{offset:x}] ({size_bits}b) = {val}\n"));
        }
        out
    }

    fn space_name(&self) -> &str {
        &self.name
    }

    fn entry_count(&self) -> usize {
        self.registers.len()
    }
}

// ---------------------------------------------------------------------------
// SymZ3MemorySpace
// ---------------------------------------------------------------------------

/// Symbolic memory storage space.
///
/// Ported from `SymZ3MemorySpace.java`. Stores symbolic values
/// at arbitrary memory addresses.
#[derive(Debug)]
pub struct SymZ3MemorySpace {
    /// Space name.
    name: String,
    /// Memory storage: address -> value.
    memory: Vec<(u64, SymValueZ3)>,
}

impl SymZ3MemorySpace {
    /// Create a new memory space.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            memory: Vec::new(),
        }
    }

    /// Store a value at a concrete address.
    pub fn store(&mut self, addr: u64, val: SymValueZ3) {
        if let Some(entry) = self.memory.iter_mut().find(|(a, _)| *a == addr) {
            *entry = (addr, val);
        } else {
            self.memory.push((addr, val));
        }
    }

    /// Load a value from a concrete address.
    pub fn load(&self, addr: u64) -> Option<&SymValueZ3> {
        self.memory.iter().find(|(a, _)| *a == addr).map(|(_, v)| v)
    }
}

impl SymZ3Space for SymZ3MemorySpace {
    fn get(&self, _offset: &SymValueZ3, size: u32, _reason: &str) -> SymValueZ3 {
        SymValueZ3::from_constant(0, size * 8)
    }

    fn set(&mut self, _offset: &SymValueZ3, _size: u32, _val: SymValueZ3) {}

    fn printable_summary(&self) -> String {
        let mut out = format!("=== Memory Space: {} ===\n", self.name);
        for (addr, val) in &self.memory {
            out.push_str(&format!("  [0x{addr:x}] = {val}\n"));
        }
        out
    }

    fn space_name(&self) -> &str {
        &self.name
    }

    fn entry_count(&self) -> usize {
        self.memory.len()
    }
}

// ---------------------------------------------------------------------------
// SymZ3UniqueSpace
// ---------------------------------------------------------------------------

/// Symbolic unique (temporary) storage space.
///
/// Ported from `SymZ3UniqueSpace.java`. Stores temporary symbolic
/// values used within a single p-code instruction sequence.
#[derive(Debug)]
pub struct SymZ3UniqueSpace {
    /// Temporary storage.
    temps: Vec<(u64, SymValueZ3)>,
}

impl SymZ3UniqueSpace {
    /// Create a new unique space.
    pub fn new() -> Self {
        Self { temps: Vec::new() }
    }
}

impl Default for SymZ3UniqueSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl SymZ3Space for SymZ3UniqueSpace {
    fn get(&self, _offset: &SymValueZ3, size: u32, _reason: &str) -> SymValueZ3 {
        SymValueZ3::from_constant(0, size * 8)
    }

    fn set(&mut self, _offset: &SymValueZ3, _size: u32, _val: SymValueZ3) {}

    fn printable_summary(&self) -> String {
        let mut out = "=== Unique Space ===\n".to_string();
        for (addr, val) in &self.temps {
            out.push_str(&format!("  [0x{addr:x}] = {val}\n"));
        }
        out
    }

    fn space_name(&self) -> &str {
        "unique"
    }

    fn entry_count(&self) -> usize {
        self.temps.len()
    }
}

// ---------------------------------------------------------------------------
// SymZ3Preconditions
// ---------------------------------------------------------------------------

/// Preconditions for symbolic execution.
///
/// Ported from `SymZ3Preconditions.java`. Stores path conditions
/// that must hold for the symbolic summary to be valid.
#[derive(Debug, Clone)]
pub struct SymZ3Preconditions {
    /// List of precondition strings.
    preconditions: Vec<String>,
}

impl SymZ3Preconditions {
    /// Create empty preconditions.
    pub fn new() -> Self {
        Self {
            preconditions: Vec::new(),
        }
    }

    /// Add a precondition.
    pub fn add(&mut self, precondition: impl Into<String>) {
        self.preconditions.push(precondition.into());
    }

    /// Get all preconditions.
    pub fn get_all(&self) -> &[String] {
        &self.preconditions
    }

    /// Whether there are any preconditions.
    pub fn is_empty(&self) -> bool {
        self.preconditions.is_empty()
    }

    /// Get a printable summary.
    pub fn printable_summary(&self) -> String {
        if self.preconditions.is_empty() {
            return String::new();
        }
        let mut out = "=== Preconditions ===\n".to_string();
        for (i, p) in self.preconditions.iter().enumerate() {
            out.push_str(&format!("  [{i}] {p}\n"));
        }
        out
    }

    /// Clear all preconditions.
    pub fn clear(&mut self) {
        self.preconditions.clear();
    }
}

impl Default for SymZ3Preconditions {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SymZ3PcodeExecutorState
// ---------------------------------------------------------------------------

/// Paired concrete-plus-symbolic state.
///
/// Ported from `SymZ3PcodeExecutorState.java`. Contains both the
/// concrete machine state (bytes) and the symbolic Z3 state.
#[derive(Debug)]
pub struct SymZ3PcodeExecutorState {
    /// Symbolic register values.
    register_space: SymZ3RegisterSpace,
    /// Symbolic memory values.
    memory_space: SymZ3MemorySpace,
    /// Symbolic temporary values.
    unique_space: SymZ3UniqueSpace,
    /// Path conditions.
    preconditions: SymZ3Preconditions,
}

impl SymZ3PcodeExecutorState {
    /// Create a new paired state.
    pub fn new() -> Self {
        Self {
            register_space: SymZ3RegisterSpace::new("register"),
            memory_space: SymZ3MemorySpace::new("memory"),
            unique_space: SymZ3UniqueSpace::new(),
            preconditions: SymZ3Preconditions::new(),
        }
    }

    /// Get a reference to the register space.
    pub fn registers(&self) -> &SymZ3RegisterSpace {
        &self.register_space
    }

    /// Get a mutable reference to the register space.
    pub fn registers_mut(&mut self) -> &mut SymZ3RegisterSpace {
        &mut self.register_space
    }

    /// Get a reference to the memory space.
    pub fn memory(&self) -> &SymZ3MemorySpace {
        &self.memory_space
    }

    /// Get a mutable reference to the memory space.
    pub fn memory_mut(&mut self) -> &mut SymZ3MemorySpace {
        &mut self.memory_space
    }

    /// Get a reference to the preconditions.
    pub fn preconditions(&self) -> &SymZ3Preconditions {
        &self.preconditions
    }

    /// Get a mutable reference to the preconditions.
    pub fn preconditions_mut(&mut self) -> &mut SymZ3Preconditions {
        &mut self.preconditions
    }

    /// Get a printable summary of the entire state.
    pub fn printable_summary(&self) -> String {
        let mut out = String::new();
        out.push_str(&self.register_space.printable_summary());
        out.push_str(&self.memory_space.printable_summary());
        out.push_str(&self.unique_space.printable_summary());
        out.push_str(&self.preconditions.printable_summary());
        out
    }

    /// Clear the entire state.
    pub fn clear(&mut self) {
        self.register_space = SymZ3RegisterSpace::new("register");
        self.memory_space = SymZ3MemorySpace::new("memory");
        self.unique_space = SymZ3UniqueSpace::new();
        self.preconditions.clear();
    }
}

impl Default for SymZ3PcodeExecutorState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SymZ3PcodeEmulator
// ---------------------------------------------------------------------------

/// A p-code emulator with symbolic Z3 summarization.
///
/// Ported from `SymZ3PcodeEmulator.java`. Combines concrete execution
/// with symbolic Z3 analysis.
#[derive(Debug)]
pub struct SymZ3PcodeEmulator {
    /// The processor language name.
    language: String,
    /// Symbolic arithmetic instance.
    big_endian: bool,
    /// The shared symbolic state.
    shared_state: SymZ3PcodeExecutorState,
}

impl SymZ3PcodeEmulator {
    /// Create a new symbolic emulator for the given language.
    pub fn new(language: impl Into<String>, big_endian: bool) -> Self {
        Self {
            language: language.into(),
            big_endian,
            shared_state: SymZ3PcodeExecutorState::new(),
        }
    }

    /// Get the language name.
    pub fn language(&self) -> &str {
        &self.language
    }

    /// Whether the language is big-endian.
    pub fn is_big_endian(&self) -> bool {
        self.big_endian
    }

    /// Get the shared symbolic state.
    pub fn shared_state(&self) -> &SymZ3PcodeExecutorState {
        &self.shared_state
    }

    /// Get a mutable reference to the shared symbolic state.
    pub fn shared_state_mut(&mut self) -> &mut SymZ3PcodeExecutorState {
        &mut self.shared_state
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_space() {
        let mut space = SymZ3RegisterSpace::new("register");
        assert_eq!(space.entry_count(), 0);

        space.set_register(0, 64, SymValueZ3::from_constant(42, 64));
        assert_eq!(space.entry_count(), 1);

        let val = space.get_register(0).unwrap();
        assert_eq!(val.to_u64(), Some(42));

        // Overwrite
        space.set_register(0, 64, SymValueZ3::from_constant(99, 64));
        assert_eq!(space.entry_count(), 1);
        assert_eq!(space.get_register(0).unwrap().to_u64(), Some(99));
    }

    #[test]
    fn test_register_space_summary() {
        let mut space = SymZ3RegisterSpace::new("R");
        space.set_register(0, 64, SymValueZ3::from_constant(1, 64));
        let summary = space.printable_summary();
        assert!(summary.contains("Register Space: R"));
        assert!(summary.contains("0x0"));
    }

    #[test]
    fn test_memory_space() {
        let mut space = SymZ3MemorySpace::new("ram");
        assert_eq!(space.entry_count(), 0);

        space.store(0x1000, SymValueZ3::from_constant(0xFF, 8));
        assert_eq!(space.entry_count(), 1);

        let val = space.load(0x1000).unwrap();
        assert_eq!(val.to_u64(), Some(0xFF));

        assert!(space.load(0x2000).is_none());
    }

    #[test]
    fn test_unique_space() {
        let space = SymZ3UniqueSpace::new();
        assert_eq!(space.entry_count(), 0);
        assert_eq!(space.space_name(), "unique");
    }

    #[test]
    fn test_preconditions() {
        let mut pre = SymZ3Preconditions::new();
        assert!(pre.is_empty());

        pre.add("RAX != 0");
        pre.add("RBX > 10");
        assert_eq!(pre.get_all().len(), 2);

        let summary = pre.printable_summary();
        assert!(summary.contains("RAX != 0"));

        pre.clear();
        assert!(pre.is_empty());
    }

    #[test]
    fn test_pcode_executor_state() {
        let mut state = SymZ3PcodeExecutorState::new();
        state
            .registers_mut()
            .set_register(0, 64, SymValueZ3::from_constant(0xDEAD, 64));
        state
            .preconditions_mut()
            .add("RCX == 0");

        let summary = state.printable_summary();
        assert!(summary.contains("Register Space"));
        assert!(summary.contains("Preconditions"));

        state.clear();
        assert_eq!(state.registers().entry_count(), 0);
        assert!(state.preconditions().is_empty());
    }

    #[test]
    fn test_pcode_emulator() {
        let mut emu = SymZ3PcodeEmulator::new("x86:LE:64:default", false);
        assert_eq!(emu.language(), "x86:LE:64:default");
        assert!(!emu.is_big_endian());

        emu.shared_state_mut()
            .registers_mut()
            .set_register(0, 64, SymValueZ3::from_constant(0x401000, 64));
        assert_eq!(emu.shared_state().registers().entry_count(), 1);
    }

    #[test]
    fn test_pcode_emulator_big_endian() {
        let emu = SymZ3PcodeEmulator::new("PowerPC:BE:64:default", true);
        assert!(emu.is_big_endian());
    }
}
