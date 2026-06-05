//! TraceRegister and TraceRegisterContainer.
//!
//! Ported from Ghidra's `ghidra.trace.model.memory.TraceRegister` and
//! `TraceRegisterContainer` interfaces.
//!
//! Registers are represented in two ways:
//! 1. In the TraceMemoryManager via register spaces.
//! 2. In the TraceObjectManager as objects in the target tree.
//!
//! This module defines the target-tree representation.

use serde::{Deserialize, Serialize};

use super::memory::TraceMemoryState;
use super::target_iface::keys;
use super::Lifespan;

/// Well-known keys for register objects.
pub mod register_keys {
    /// The bit length of the register.
    pub const BIT_LENGTH: &str = "_length";
    /// The state of the register value (known/unknown/error).
    pub const STATE: &str = "_state";
    /// The register value bytes.
    pub const VALUE: &str = super::keys::VALUE;
}

/// A register in the target tree.
///
/// Registers are presented as objects in the target tree, organized under
/// a `TraceRegisterContainer`. The name is taken from the object key,
/// the bit length from `_length`, and the value from `_value`.
///
/// When the connector does not know a register's name in Ghidra's slaspec,
/// it uses the `DATA` processor and presents registers as primitive children
/// of the container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRegister {
    /// The register name (e.g., "RAX", "EIP", "XMM0").
    pub name: String,
    /// The thread this register belongs to.
    pub thread_key: i64,
    /// The bit length of the register.
    pub bit_length: u32,
    /// The current value of the register, if known.
    pub value: Option<Vec<u8>>,
    /// The observation state of the register.
    pub state: TraceMemoryState,
    /// The lifespan during which this register definition is valid.
    pub lifespan: Lifespan,
}

impl TraceRegister {
    /// Well-known key for bit length.
    pub const KEY_BITLENGTH: &'static str = register_keys::BIT_LENGTH;
    /// Well-known key for state.
    pub const KEY_STATE: &'static str = register_keys::STATE;

    /// Create a new register.
    pub fn new(
        name: impl Into<String>,
        thread_key: i64,
        bit_length: u32,
        lifespan: Lifespan,
    ) -> Self {
        Self {
            name: name.into(),
            thread_key,
            bit_length,
            value: None,
            state: TraceMemoryState::Unknown,
            lifespan,
        }
    }

    /// Get the byte length of the register.
    pub fn byte_length(&self) -> u32 {
        (self.bit_length + 7) / 8
    }

    /// Set the register value.
    pub fn set_value(&mut self, value: Vec<u8>, lifespan: Lifespan) {
        self.value = Some(value);
        self.state = TraceMemoryState::Known;
        self.lifespan = lifespan;
    }

    /// Get the register value at a given snap.
    pub fn get_value(&self, snap: i64) -> Option<&[u8]> {
        if self.lifespan.contains(snap) {
            self.value.as_deref()
        } else {
            None
        }
    }

    /// Set the observation state of this register.
    pub fn set_state(&mut self, state: TraceMemoryState, lifespan: Lifespan) {
        self.state = state;
        self.lifespan = lifespan;
    }

    /// Get the observation state at a given snap.
    pub fn get_state(&self, snap: i64) -> TraceMemoryState {
        if self.lifespan.contains(snap) {
            self.state
        } else {
            TraceMemoryState::Unknown
        }
    }

    /// Check if the register value is known at a given snap.
    pub fn is_known(&self, snap: i64) -> bool {
        self.get_state(snap) == TraceMemoryState::Known
    }
}

/// A container of registers in the target tree.
///
/// This is a special marker for the root container of a set of registers.
/// The container need not be the immediate parent of each register -- registers
/// may be organized into groups under the container.
///
/// The register container is typically associated with a thread or a stack frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRegisterContainer {
    /// The schema name for this container.
    pub schema_name: String,
    /// The thread this container belongs to.
    pub thread_key: i64,
    /// The frame level (0 = current frame).
    pub frame_level: u32,
    /// The lifespan of this container.
    pub lifespan: Lifespan,
}

impl TraceRegisterContainer {
    /// Create a new register container.
    pub fn new(thread_key: i64, frame_level: u32, lifespan: Lifespan) -> Self {
        Self {
            schema_name: "RegisterContainer".to_string(),
            thread_key,
            frame_level,
            lifespan,
        }
    }

    /// Whether this container is valid at the given snap.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }
}

/// A group of registers presented together (e.g., general purpose, FPU, SSE).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRegisterGroup {
    /// The name of this group (e.g., "General Purpose", "SSE").
    pub name: String,
    /// The registers in this group.
    pub registers: Vec<TraceRegister>,
    /// The lifespan of this group.
    pub lifespan: Lifespan,
}

impl TraceRegisterGroup {
    /// Create a new register group.
    pub fn new(name: impl Into<String>, lifespan: Lifespan) -> Self {
        Self {
            name: name.into(),
            registers: Vec::new(),
            lifespan,
        }
    }

    /// Add a register to this group.
    pub fn add_register(&mut self, register: TraceRegister) {
        self.registers.push(register);
    }

    /// Find a register by name.
    pub fn find_register(&self, name: &str) -> Option<&TraceRegister> {
        self.registers.iter().find(|r| r.name == name)
    }

    /// Get all register names in this group.
    pub fn register_names(&self) -> Vec<&str> {
        self.registers.iter().map(|r| r.name.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trace_register_new() {
        let reg = TraceRegister::new("RAX", 1, 64, Lifespan::ALL);
        assert_eq!(reg.name, "RAX");
        assert_eq!(reg.bit_length, 64);
        assert_eq!(reg.byte_length(), 8);
        assert_eq!(reg.thread_key, 1);
        assert!(reg.value.is_none());
        assert_eq!(reg.get_state(0), TraceMemoryState::Unknown);
    }

    #[test]
    fn test_trace_register_value() {
        let mut reg = TraceRegister::new("RAX", 1, 64, Lifespan::ALL);
        assert!(!reg.is_known(0));

        reg.set_value(vec![0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0], Lifespan::ALL);
        assert!(reg.is_known(0));
        assert_eq!(
            reg.get_value(0),
            Some([0xef, 0xbe, 0xad, 0xde, 0, 0, 0, 0].as_slice())
        );
    }

    #[test]
    fn test_trace_register_lifespan() {
        let mut reg = TraceRegister::new("EAX", 1, 32, Lifespan::span(0, 10));
        reg.set_value(vec![0x78, 0x56, 0x34, 0x12], Lifespan::span(0, 10));

        assert!(reg.is_known(5));
        assert!(!reg.is_known(15));
        assert!(reg.get_value(5).is_some());
        assert!(reg.get_value(15).is_none());
    }

    #[test]
    fn test_trace_register_byte_length() {
        let r8 = TraceRegister::new("AL", 1, 8, Lifespan::ALL);
        assert_eq!(r8.byte_length(), 1);

        let r32 = TraceRegister::new("EAX", 1, 32, Lifespan::ALL);
        assert_eq!(r32.byte_length(), 4);

        let r64 = TraceRegister::new("RAX", 1, 64, Lifespan::ALL);
        assert_eq!(r64.byte_length(), 8);

        // Odd bit length
        let r5 = TraceRegister::new("FLAGS5", 1, 5, Lifespan::ALL);
        assert_eq!(r5.byte_length(), 1); // ceil(5/8) = 1

        let r13 = TraceRegister::new("X13", 1, 13, Lifespan::ALL);
        assert_eq!(r13.byte_length(), 2); // ceil(13/8) = 2
    }

    #[test]
    fn test_register_container() {
        let container = TraceRegisterContainer::new(1, 0, Lifespan::ALL);
        assert_eq!(container.thread_key, 1);
        assert_eq!(container.frame_level, 0);
        assert!(container.is_valid_at(0));
        assert!(container.is_valid_at(i64::MAX));
    }

    #[test]
    fn test_register_container_lifespan() {
        let container = TraceRegisterContainer::new(1, 0, Lifespan::span(0, 5));
        assert!(container.is_valid_at(3));
        assert!(!container.is_valid_at(10));
    }

    #[test]
    fn test_register_group() {
        let mut group = TraceRegisterGroup::new("General Purpose", Lifespan::ALL);
        group.add_register(TraceRegister::new("RAX", 1, 64, Lifespan::ALL));
        group.add_register(TraceRegister::new("RBX", 1, 64, Lifespan::ALL));
        group.add_register(TraceRegister::new("RCX", 1, 64, Lifespan::ALL));

        assert_eq!(group.register_names(), vec!["RAX", "RBX", "RCX"]);
        assert!(group.find_register("RAX").is_some());
        assert!(group.find_register("RDX").is_none());
    }

    #[test]
    fn test_register_keys() {
        assert_eq!(TraceRegister::KEY_BITLENGTH, "_length");
        assert_eq!(TraceRegister::KEY_STATE, "_state");
        assert_eq!(register_keys::BIT_LENGTH, "_length");
        assert_eq!(register_keys::VALUE, "_value");
    }

    #[test]
    fn test_register_serde() {
        let reg = TraceRegister::new("RIP", 1, 64, Lifespan::ALL);
        let json = serde_json::to_string(&reg).unwrap();
        let back: TraceRegister = serde_json::from_str(&json).unwrap();
        assert_eq!(back.name, "RIP");
        assert_eq!(back.bit_length, 64);
    }
}
