//! Debugger utility types.
//!
//! Ported from Ghidra's `ghidra.app.plugin.core.debug.utils` package.

use serde::{Deserialize, Serialize};

use crate::model::Lifespan;

/// A range of memory for reading or writing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MemoryRange {
    /// Start address.
    pub start: u64,
    /// Length in bytes.
    pub length: u64,
}

impl MemoryRange {
    /// Create a new memory range.
    pub fn new(start: u64, length: u64) -> Self {
        Self { start, length }
    }

    /// Create a range from start and end (inclusive).
    pub fn from_to(start: u64, end: u64) -> Self {
        Self {
            start,
            length: end - start + 1,
        }
    }

    /// The end address (exclusive).
    pub fn end(&self) -> u64 {
        self.start + self.length
    }

    /// Whether this range contains the given address.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end()
    }

    /// Whether this range overlaps another range.
    pub fn overlaps(&self, other: &MemoryRange) -> bool {
        self.start < other.end() && other.start < self.end()
    }
}

/// A register value pair (name + bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterValue {
    /// The register name.
    pub name: String,
    /// The register value as bytes (big-endian).
    pub value: Vec<u8>,
}

impl RegisterValue {
    /// Create a new register value.
    pub fn new(name: impl Into<String>, value: Vec<u8>) -> Self {
        Self {
            name: name.into(),
            value,
        }
    }

    /// Create from a 64-bit value.
    pub fn from_u64(name: impl Into<String>, val: u64) -> Self {
        Self {
            name: name.into(),
            value: val.to_le_bytes().to_vec(),
        }
    }

    /// Create from a 32-bit value.
    pub fn from_u32(name: impl Into<String>, val: u32) -> Self {
        Self {
            name: name.into(),
            value: val.to_le_bytes().to_vec(),
        }
    }

    /// Interpret as a u64 (little-endian).
    pub fn as_u64(&self) -> Option<u64> {
        if self.value.len() >= 8 {
            let mut bytes = [0u8; 8];
            bytes.copy_from_slice(&self.value[..8]);
            Some(u64::from_le_bytes(bytes))
        } else {
            None
        }
    }

    /// Interpret as a u32 (little-endian).
    pub fn as_u32(&self) -> Option<u32> {
        if self.value.len() >= 4 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&self.value[..4]);
            Some(u32::from_le_bytes(bytes))
        } else {
            None
        }
    }
}

/// A snapshot of all register values for a thread at a given snap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterSnapshot {
    /// The thread key.
    pub thread_key: i64,
    /// The snap.
    pub snap: i64,
    /// The register values.
    pub registers: Vec<RegisterValue>,
}

impl RegisterSnapshot {
    /// Create a new snapshot.
    pub fn new(thread_key: i64, snap: i64) -> Self {
        Self {
            thread_key,
            snap,
            registers: Vec::new(),
        }
    }

    /// Add a register value.
    pub fn add_register(&mut self, reg: RegisterValue) {
        self.registers.push(reg);
    }

    /// Find a register value by name.
    pub fn get_register(&self, name: &str) -> Option<&RegisterValue> {
        self.registers.iter().find(|r| r.name == name)
    }

    /// Get the PC value.
    pub fn pc(&self) -> Option<u64> {
        self.get_register("PC")
            .or_else(|| self.get_register("RIP"))
            .or_else(|| self.get_register("rip"))
            .and_then(|r| r.as_u64())
    }

    /// Get the SP value.
    pub fn sp(&self) -> Option<u64> {
        self.get_register("SP")
            .or_else(|| self.get_register("RSP"))
            .or_else(|| self.get_register("rsp"))
            .and_then(|r| r.as_u64())
    }
}

/// An overlay memory region type (used when trace has overlay address spaces).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayRegion {
    /// The overlay space name.
    pub overlay_space: String,
    /// The underlying space name.
    pub underlying_space: String,
    /// The overlay range start.
    pub start: u64,
    /// The overlay range length.
    pub length: u64,
}

impl OverlayRegion {
    /// Create a new overlay region.
    pub fn new(
        overlay_space: impl Into<String>,
        underlying_space: impl Into<String>,
        start: u64,
        length: u64,
    ) -> Self {
        Self {
            overlay_space: overlay_space.into(),
            underlying_space: underlying_space.into(),
            start,
            length,
        }
    }
}

/// Utility: check whether two lifespans overlap.
pub fn lifespans_overlap(a: &Lifespan, b: &Lifespan) -> bool {
    a.intersects(b)
}

/// Utility: clamp a value to a range.
pub fn clamp_to_range(value: u64, min: u64, max: u64) -> u64 {
    value.max(min).min(max)
}

/// Utility: align an address upward to the given alignment.
pub fn align_up(addr: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        return addr;
    }
    (addr + alignment - 1) & !(alignment - 1)
}

/// Utility: align an address downward.
pub fn align_down(addr: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        return addr;
    }
    addr & !(alignment - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_range() {
        let r = MemoryRange::new(0x400000, 0x1000);
        assert_eq!(r.end(), 0x401000);
        assert!(r.contains(0x400500));
        assert!(!r.contains(0x402000));
    }

    #[test]
    fn test_memory_range_from_to() {
        let r = MemoryRange::from_to(0x400000, 0x400fff);
        assert_eq!(r.length, 0x1000);
        assert!(r.contains(0x400fff));
    }

    #[test]
    fn test_memory_range_overlaps() {
        let a = MemoryRange::new(0x1000, 0x1000);
        let b = MemoryRange::new(0x1800, 0x1000);
        let c = MemoryRange::new(0x3000, 0x1000);

        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c));
    }

    #[test]
    fn test_register_value() {
        let rv = RegisterValue::from_u64("RAX", 0x42);
        assert_eq!(rv.as_u64(), Some(0x42));

        let rv = RegisterValue::from_u32("EAX", 0x42);
        assert_eq!(rv.as_u32(), Some(0x42));
    }

    #[test]
    fn test_register_snapshot() {
        let mut snap = RegisterSnapshot::new(1, 0);
        snap.add_register(RegisterValue::from_u64("RIP", 0x400000));
        snap.add_register(RegisterValue::from_u64("RSP", 0x7fff0000));

        assert_eq!(snap.pc(), Some(0x400000));
        assert_eq!(snap.sp(), Some(0x7fff0000));
        assert!(snap.get_register("RAX").is_none());
    }

    #[test]
    fn test_register_snapshot_pc_aliases() {
        let mut snap = RegisterSnapshot::new(1, 0);
        snap.add_register(RegisterValue::from_u64("PC", 0x8000));
        assert_eq!(snap.pc(), Some(0x8000));
    }

    #[test]
    fn test_overlay_region() {
        let overlay = OverlayRegion::new("OVL1", "ram", 0x10000000, 0x1000);
        assert_eq!(overlay.overlay_space, "OVL1");
        assert_eq!(overlay.underlying_space, "ram");
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0, 0x1000), 0);
    }

    #[test]
    fn test_align_down() {
        assert_eq!(align_down(0x1fff, 0x1000), 0x1000);
        assert_eq!(align_down(0x1000, 0x1000), 0x1000);
    }

    #[test]
    fn test_clamp_to_range() {
        assert_eq!(clamp_to_range(5, 0, 10), 5);
        assert_eq!(clamp_to_range(15, 0, 10), 10);
        assert_eq!(clamp_to_range(0, 5, 10), 5);
    }

    #[test]
    fn test_memory_range_serde() {
        let r = MemoryRange::new(0x400000, 0x1000);
        let json = serde_json::to_string(&r).unwrap();
        let back: MemoryRange = serde_json::from_str(&json).unwrap();
        assert_eq!(back.start, 0x400000);
    }

    #[test]
    fn test_register_value_empty() {
        let rv = RegisterValue::new("FLAGS", vec![]);
        assert!(rv.as_u64().is_none());
        assert!(rv.as_u32().is_none());
    }
}
