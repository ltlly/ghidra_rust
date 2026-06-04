//! TraceRegisterContext - register values in a trace.
//!
//! Ported from Ghidra's `ghidra.trace.model.context` package.
//! Tracks register values across time for threads in a trace.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::Lifespan;

/// A register value observed at a given lifespan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceRegisterValue {
    /// The register name (e.g., "RAX", "EFLAGS").
    pub name: String,
    /// The byte value of the register.
    pub value: Vec<u8>,
    /// The lifespan during which this value is valid.
    pub lifespan: Lifespan,
}

impl TraceRegisterValue {
    /// Create a new register value.
    pub fn new(name: impl Into<String>, value: Vec<u8>, lifespan: Lifespan) -> Self {
        Self {
            name: name.into(),
            value,
            lifespan,
        }
    }

    /// Interpret the value as a u64 (little-endian).
    pub fn as_u64_le(&self) -> Option<u64> {
        if self.value.len() >= 8 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&self.value[..8]);
            Some(u64::from_le_bytes(buf))
        } else if self.value.len() >= 4 {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&self.value[..4]);
            Some(u32::from_le_bytes(buf) as u64)
        } else if self.value.len() >= 2 {
            let mut buf = [0u8; 2];
            buf.copy_from_slice(&self.value[..2]);
            Some(u16::from_le_bytes(buf) as u64)
        } else if self.value.len() >= 1 {
            Some(self.value[0] as u64)
        } else {
            None
        }
    }

    /// Whether this value is valid at the given snap.
    pub fn is_valid_at(&self, snap: i64) -> bool {
        self.lifespan.contains(snap)
    }
}

/// Whether a register is defined at a given snap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RegisterDefinedState {
    /// The register value is known/defined.
    Defined,
    /// The register value is unknown/undefined.
    Undefined,
}

/// Manages register context for a trace.
///
/// Stores register values per (thread, frame, snap) and tracks which
/// registers are defined vs. undefined.
#[derive(Debug, Clone, Default)]
pub struct TraceRegisterContextManager {
    /// Register values keyed by (thread_key, frame_level, register_name).
    values: BTreeMap<(i64, i32, String), Vec<TraceRegisterValue>>,
    /// Whether registers are defined, keyed by (thread_key, frame_level, register_name, snap).
    defined: BTreeMap<(i64, i32, String), Vec<(Lifespan, RegisterDefinedState)>>,
}

impl Serialize for TraceRegisterContextManager {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("TraceRegisterContextManager", 2)?;
        // Serialize values as a Vec of ((thread, frame, name), values) pairs
        let values_vec: Vec<(&(i64, i32, String), &Vec<TraceRegisterValue>)> =
            self.values.iter().collect();
        state.serialize_field("values", &values_vec)?;
        let defined_vec: Vec<(&(i64, i32, String), &Vec<(Lifespan, RegisterDefinedState)>)> =
            self.defined.iter().collect();
        state.serialize_field("defined", &defined_vec)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for TraceRegisterContextManager {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Helper {
            values: Vec<((i64, i32, String), Vec<TraceRegisterValue>)>,
            defined: Vec<((i64, i32, String), Vec<(Lifespan, RegisterDefinedState)>)>,
        }
        let helper = Helper::deserialize(deserializer)?;
        Ok(Self {
            values: helper.values.into_iter().collect(),
            defined: helper.defined.into_iter().collect(),
        })
    }
}

impl TraceRegisterContextManager {
    /// Create a new register context manager.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a register value for a thread/frame over a lifespan.
    pub fn set_register(
        &mut self,
        thread_key: i64,
        frame_level: i32,
        name: impl Into<String>,
        value: Vec<u8>,
        lifespan: Lifespan,
    ) {
        let name = name.into();
        let entry = TraceRegisterValue::new(&name, value, lifespan);
        self.values
            .entry((thread_key, frame_level, name))
            .or_default()
            .push(entry);
    }

    /// Get the register value at a given snap.
    pub fn get_register(
        &self,
        thread_key: i64,
        frame_level: i32,
        name: &str,
        snap: i64,
    ) -> Option<&TraceRegisterValue> {
        self.values
            .get(&(thread_key, frame_level, name.to_string()))
            .and_then(|entries| {
                entries
                    .iter()
                    .filter(|e| e.lifespan.contains(snap))
                    .max_by_key(|e| e.lifespan.lmin())
            })
    }

    /// Set whether a register is defined.
    pub fn set_register_defined(
        &mut self,
        thread_key: i64,
        frame_level: i32,
        name: impl Into<String>,
        state: RegisterDefinedState,
        lifespan: Lifespan,
    ) {
        let name = name.into();
        self.defined
            .entry((thread_key, frame_level, name))
            .or_default()
            .push((lifespan, state));
    }

    /// Check if a register is defined at a given snap.
    pub fn is_register_defined(
        &self,
        thread_key: i64,
        frame_level: i32,
        name: &str,
        snap: i64,
    ) -> bool {
        self.defined
            .get(&(thread_key, frame_level, name.to_string()))
            .and_then(|entries| {
                entries
                    .iter()
                    .filter(|(l, _)| l.contains(snap))
                    .max_by_key(|(l, _)| l.lmin())
                    .map(|(_, s)| *s == RegisterDefinedState::Defined)
            })
            .unwrap_or(false)
    }

    /// Get all register names for a thread/frame at a given snap.
    pub fn register_names(
        &self,
        thread_key: i64,
        frame_level: i32,
        snap: i64,
    ) -> Vec<String> {
        self.values
            .iter()
            .filter(|((t, f, _), entries)| {
                *t == thread_key
                    && *f == frame_level
                    && entries.iter().any(|e| e.lifespan.contains(snap))
            })
            .map(|((_, _, name), _)| name.clone())
            .collect()
    }

    /// Clear all register values for a thread.
    pub fn clear_thread(&mut self, thread_key: i64) {
        self.values.retain(|(t, _, _), _| *t != thread_key);
        self.defined.retain(|(t, _, _), _| *t != thread_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_value_as_u64_le() {
        let rv = TraceRegisterValue::new("RAX", vec![0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00], Lifespan::at(0));
        assert_eq!(rv.as_u64_le(), Some(0x12345678));

        let rv32 = TraceRegisterValue::new("EAX", vec![0x78, 0x56, 0x34, 0x12], Lifespan::at(0));
        assert_eq!(rv32.as_u64_le(), Some(0x12345678));

        let rv16 = TraceRegisterValue::new("AX", vec![0x34, 0x12], Lifespan::at(0));
        assert_eq!(rv16.as_u64_le(), Some(0x1234));

        let rv8 = TraceRegisterValue::new("AL", vec![0x42], Lifespan::at(0));
        assert_eq!(rv8.as_u64_le(), Some(0x42));

        let rv_empty = TraceRegisterValue::new("empty", vec![], Lifespan::at(0));
        assert_eq!(rv_empty.as_u64_le(), None);
    }

    #[test]
    fn test_register_context_set_and_get() {
        let mut mgr = TraceRegisterContextManager::new();
        mgr.set_register(1, 0, "RAX", vec![0x42; 8], Lifespan::now_on(0));
        mgr.set_register(1, 0, "RBX", vec![0x99; 8], Lifespan::now_on(0));

        let rax = mgr.get_register(1, 0, "RAX", 5);
        assert!(rax.is_some());
        assert_eq!(rax.unwrap().value, vec![0x42; 8]);

        assert!(mgr.get_register(1, 0, "RCX", 5).is_none());
        assert!(mgr.get_register(2, 0, "RAX", 5).is_none());
    }

    #[test]
    fn test_register_context_overwrite() {
        let mut mgr = TraceRegisterContextManager::new();
        mgr.set_register(1, 0, "RAX", vec![0x01; 8], Lifespan::span(0, 5));
        mgr.set_register(1, 0, "RAX", vec![0x02; 8], Lifespan::now_on(6));

        let v5 = mgr.get_register(1, 0, "RAX", 5).unwrap();
        assert_eq!(v5.value, vec![0x01; 8]);

        let v10 = mgr.get_register(1, 0, "RAX", 10).unwrap();
        assert_eq!(v10.value, vec![0x02; 8]);
    }

    #[test]
    fn test_register_defined_state() {
        let mut mgr = TraceRegisterContextManager::new();
        mgr.set_register_defined(
            1, 0, "RAX",
            RegisterDefinedState::Defined,
            Lifespan::now_on(0),
        );

        assert!(mgr.is_register_defined(1, 0, "RAX", 5));
        assert!(!mgr.is_register_defined(1, 0, "RBX", 5));
        assert!(!mgr.is_register_defined(2, 0, "RAX", 5));
    }

    #[test]
    fn test_register_names() {
        let mut mgr = TraceRegisterContextManager::new();
        mgr.set_register(1, 0, "RAX", vec![0; 8], Lifespan::now_on(0));
        mgr.set_register(1, 0, "RBX", vec![0; 8], Lifespan::now_on(0));
        mgr.set_register(1, 1, "RBP", vec![0; 8], Lifespan::now_on(0));

        let names = mgr.register_names(1, 0, 5);
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"RAX".to_string()));
        assert!(names.contains(&"RBX".to_string()));
    }

    #[test]
    fn test_clear_thread() {
        let mut mgr = TraceRegisterContextManager::new();
        mgr.set_register(1, 0, "RAX", vec![0; 8], Lifespan::now_on(0));
        mgr.set_register(2, 0, "RAX", vec![0; 8], Lifespan::now_on(0));

        mgr.clear_thread(1);
        assert!(mgr.get_register(1, 0, "RAX", 5).is_none());
        assert!(mgr.get_register(2, 0, "RAX", 5).is_some());
    }

    #[test]
    fn test_register_context_serde() {
        let mut mgr = TraceRegisterContextManager::new();
        mgr.set_register(1, 0, "RAX", vec![0x42; 8], Lifespan::now_on(0));
        let json = serde_json::to_string(&mgr).unwrap();
        let back: TraceRegisterContextManager = serde_json::from_str(&json).unwrap();
        let rax = back.get_register(1, 0, "RAX", 5).unwrap();
        assert_eq!(rax.value, vec![0x42; 8]);
    }
}
